"""Network Time Machine 1.52.0: the state, compare and export routes.

Through the real write paths of ``tm_index_kit`` / ``test_tm_clients_v1510``
(fake coordinators, the real fleet tracker, the real Network Intelligence
and Client Stability for the client sessions) and the HTTP views of
``tm_views`` with users of ``core_testkit``. The route clock is the
world's clock (``tm_views.time``).
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import contextlib
import json
import logging
import time as real_time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_client_engine import M1, M2, disk  # noqa: F401 - fixture
from test_tm_clients_v1510 import TMC1, clients_world, step
from tm_index_kit import KEY, RID, SECRETS, T0, iface, poll_data, world

from custom_components.openwrt_router import net_engine, tm_export, tm_state, tm_views
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.tm_engine import async_forget_client
from custom_components.openwrt_router.tm_export import EXPORT_MAX_MARKS
from custom_components.openwrt_router.topology_panel import _PANEL_VIEW_DISABLED_KEY

R1, R2 = RID["r1"], RID["r2"]
TMC2 = "tmc_" + pseudonymise_identifier("client", M2, KEY)[4:]
PANEL_ACCESS = "openwrt_router_panel_access"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _auth(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
        return await handler(request)

    return middleware


class Client:
    def __init__(self, w: Any, test_client: TestClient) -> None:
        self.w = w
        self.client = test_client
        self.bodies: list[bytes] = []

    async def get(
        self, path: str, user: str | None = ADMIN_ID, params: Any = None
    ) -> Any:
        headers = {"X-Test-User": user} if user else {}
        resp = await self.client.get(
            tm_views.BASE_URL + path, headers=headers, params=params
        )
        raw = await resp.read()
        self.bodies.append(raw)
        data = json.loads(raw) if raw[:1] == b"{" else None
        return SimpleNamespace(
            status=resp.status, headers=resp.headers, data=data, raw=raw
        )


@contextlib.asynccontextmanager
async def http(w: Any) -> Any:
    add_users(w.hass)
    w.hass.is_stopping = False
    app = web.Application(middlewares=[_auth(w.hass)])
    app[KEY_HASS] = w.hass
    for view_class in tm_views.TIME_MACHINE_VIEWS:
        view_class().register(w.hass, app, app.router)
    clock = SimpleNamespace(time=w.clock, monotonic=real_time.monotonic)
    with patch.object(tm_views, "time", clock):
        async with TestClient(TestServer(app)) as test_client:
            yield Client(w, test_client)


def tick(w: Any, on1: list[str] | None, on2: list[str] | None, **radios: Any) -> None:
    """One minute: both routers polled (radios), then their client lists."""
    for entry_id, coord in w.coords.items():
        coord.poll(poll_data(*radios.get(entry_id, [iface("phy1", 36)])))
    step(w, on1, on2)


def roam(w: Any) -> dict[str, float]:
    """M1 on r1, then on r2; M2 on r1 the whole time."""
    for _ in range(3):
        tick(w, [M1, M2], [])
    roamed = w.t
    for _ in range(3):
        tick(w, [M2], [M1])
    return {"r1": T0 + 90, "r2": roamed + 30}


# --- state ---------------------------------------------------------------------------------


async def test_state_route_clients_for_admins_with_paging(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        moments = roam(w)
        got = await h.get("/state", params={"at": str(moments["r1"])})
        body = got.data
        assert got.status == 200 and got.headers["Cache-Control"] == "no-store"
        assert body["v"] == 1 and body["status"] == "ok" and body["known"] is True
        clients = body["clients"]
        assert clients["state"] == "ok" and clients["total"] == 2
        assert {(c["client"], c["router_id"]) for c in clients["items"]} == {
            (TMC1, R1),
            (TMC2, R1),
        }
        assert clients["per_router"] == [
            {"router_id": R1, "router_name": "Router 1", "clients": 2}
        ]
        later = (await h.get("/state", params={"at": str(moments["r2"])})).data
        where = {c["client"]: c["router_id"] for c in later["clients"]["items"]}
        assert where == {TMC1: R2, TMC2: R1}
        # paging with the cursor: two pages, nothing lost, nothing twice
        seen: list[str] = []
        params = {"at": str(moments["r2"]), "clients_limit": "1"}
        for _ in range(3):
            page = (await h.get("/state", params=params)).data["clients"]
            seen += [c["client"] for c in page["items"]]
            if page["next_cursor"] is None:
                break
            assert page["truncated"] is True
            params = {**params, "clients_cursor": page["next_cursor"]}
        assert sorted(seen) == sorted([TMC1, TMC2])
        print("\n[state example]", json.dumps(later, indent=1)[:3000])


async def test_state_route_rights_and_errors_reveal_nothing(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        moments = roam(w)
        at = {"at": str(moments["r2"])}
        assert (await h.get("/state", None, at)).status == 401  # no login
        assert (await h.get("/state", USER_ID, at)).status == 403  # panel closed
        w.hass.data[PANEL_ACCESS] = {"r1": True}
        user = await h.get("/state", USER_ID, at)
        assert user.status == 200
        clients = user.data["clients"]
        assert (clients["state"], clients["reason"]) == ("off", "admin_only")
        assert clients["items"] == clients["per_router"] == [] and clients["total"] == 0
        assert user.data["config"]["state"] == "off"
        assert b"tmc_" not in user.raw and b"laptop" not in user.raw
        # a client key from a non-admin: refused before its value is read
        for key in ("clients_limit", "clients_cursor"):
            bad = await h.get("/state", USER_ID, {**at, key: M1})
            assert (bad.status, bad.data["details"]) == (
                400,
                {"field": key, "reason": "admin_only"},
            )
            assert M1.encode() not in bad.raw
        for params, field, reason in (
            ({"at": M1}, "at", "invalid"),
            ({"at": str(w.t + 3600)}, "at", "out_of_range"),
            ({"x": "1"}, "query", "unknown_key"),
            ({**at, "clients_cursor": "zz" + M1}, "clients_cursor", "invalid"),
            ({**at, "router_id": M1}, "router_id", "invalid"),
            ({**at, "clients_limit": "0"}, "clients_limit", "out_of_range"),
        ):
            bad = await h.get("/state", ADMIN_ID, params)
            assert bad.status == 400, params
            assert bad.data["details"] == {"field": field, "reason": reason}, params
            assert M1.encode() not in bad.raw
        w.hass.data[_PANEL_VIEW_DISABLED_KEY] = True
        assert (await h.get("/state", ADMIN_ID, at)).status == 410
        w.hass.data.pop(_PANEL_VIEW_DISABLED_KEY)
        # the client switch off: the list says so, the rest stays
        await w.engine.async_set_clients(False)
        off = (await h.get("/state", ADMIN_ID, at)).data
        assert (off["clients"]["state"], off["clients"]["reason"]) == (
            "off",
            "clients_off",
        )
        for body in h.bodies:
            for needle in SECRETS:
                assert needle.encode() not in body, needle


async def test_off_and_not_running_read_nothing(disks) -> None:
    with world(disks) as w:
        async with http(w) as h:
            body = (await h.get("/state")).data
            assert (body["status"], body["routers"], body["clients"]) == (
                "off",
                [],
                None,
            )
            assert (await h.get("/compare", params={"t1": "1", "t2": "2"})).data[
                "status"
            ] == "off"
            assert (await h.get("/export")).data["status"] == "off"
            w.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = True
            body = (await h.get("/state")).data
            assert (body["status"], body["reason"]) == ("unavailable", "not_running")


async def test_forget_removes_the_client_from_every_answer(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        moments = roam(w)
        await async_forget_client(w.hass, M1)
        state = (await h.get("/state", params={"at": str(moments["r2"])})).data
        assert {c["client"] for c in state["clients"]["items"]} == {TMC2}
        export = await h.get("/export", params={"from": str(int(T0 - 60))})
        assert TMC1.encode() not in export.raw and TMC2.encode() not in export.raw


# --- compare -------------------------------------------------------------------------------


async def test_compare_route_names_only_the_differences(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        moments = roam(w)
        tick(w, [M2], [M1], r1=[iface("phy1", 44)])
        tick(w, [M2], [M1], r1=[iface("phy1", 44)])
        t1, t2 = moments["r1"], w.clock.t - 1
        got = await h.get("/compare", params={"t1": str(t1), "t2": str(t2)})
        assert got.status == 200
        body = got.data
        assert (body["t1"], body["t2"]) == (t1, t2)
        changes = {c["router_id"]: c for c in body["changes"]["routers"]}
        radios = changes[R1]["radios"]
        assert radios == [
            {
                "key": "5g0",
                "band": "5g",
                "from": {"channel": 36, "width": 80, "state": "up"},
                "to": {"channel": 44, "width": 80, "state": "up"},
                "state": "changed",
                "reason": None,
            }
        ]
        assert changes[R1]["clients"] == {"from": 2, "to": 1, "delta": -1}
        assert changes[R2]["clients"] == {"from": 0, "to": 1, "delta": 1}
        marks = body["changes"]["marks"]
        assert marks["by_group"]["clients"] >= 2 and marks["by_group"]["radio"] == 1
        # NI is not running here: "off" as in the state, not "unreadable"
        assert body["changes"]["incidents"]["state"] == "off"
        assert body["before"]["incidents"]["state"] == "off"
        print("\n[compare example]", json.dumps(body["changes"], indent=1)[:2500])
        for params, reason in (
            ({"t1": str(t2), "t2": str(t1)}, ("window", "empty")),
            ({"t1": str(t1)}, ("t2", "missing")),
            ({"t1": "1", "t2": str(t2)}, ("window", "too_large")),
        ):
            bad = await h.get("/compare", params=params)
            assert bad.status == 400
            assert (
                bad.data["details"]["field"],
                bad.data["details"]["reason"],
            ) == reason
        # a non-admin with the open panel: no client count, no client group
        w.hass.data[PANEL_ACCESS] = {"r1": True}
        user = (await h.get("/compare", USER_ID, {"t1": str(t1), "t2": str(t2)})).data
        assert all(c["clients"] is None for c in user["changes"]["routers"])
        assert "clients" not in user["changes"]["marks"]["by_group"]
        assert user["before"]["clients"]["reason"] == "admin_only"


# --- export --------------------------------------------------------------------------------


async def test_export_is_audited_nameless_and_for_admins_only(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        roam(w)
        w.down("r2")
        tick(w, [M2], None)
        window = {"from": str(int(T0 - 60))}
        w.hass.data[PANEL_ACCESS] = {"r1": True}
        assert (await h.get("/export", USER_ID, window)).status == 403
        assert (await h.get("/export", None, window)).status == 401
        before = len(w.api.emitted)
        got = await h.get("/export", ADMIN_ID, window)
        assert got.status == 200
        assert got.headers["Content-Disposition"].startswith("attachment;")
        assert got.headers["Cache-Control"] == "no-store"
        body = got.data
        assert body["kind"] == "openwrt_router.time_machine.export"
        assert body["v"] == 1 and body["limit"] == EXPORT_MAX_MARKS
        client_marks = [m for m in w.engine.index if m.client is not None]
        assert len(client_marks) >= 4
        assert body["marks"] and body["omitted_client_marks"] == len(client_marks)
        for mark in (*body["marks"], *body["spanning"]):
            assert mark["client"] is None and mark["client_name"] is None
            assert mark["router_name"] is None and mark["text"] is None
        [down] = [m for m in body["marks"] if m["kind"] == "router_down"]
        assert down["router_id"] == R2
        assert b"Router 1" not in got.raw and b"Router 2" not in got.raw
        assert b"tmc_" not in got.raw
        for needle in SECRETS:
            assert needle.encode() not in got.raw, needle
        # the audit entry: counts only, the user as actor, on the security ring
        [(event_type, kw)] = w.api.emitted[before:]
        assert event_type == "time_machine.exported"
        assert kw["security_relevant"] is True and kw["actor"].user_id == ADMIN_ID
        assert kw["data"]["marks"] == len(body["marks"])
        assert set(kw["data"]) == {
            "marks",
            "spanning",
            "omitted_client_marks",
            "truncated",
            "window_s",
        }

        # the audit log refuses: no export
        def refuse(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("disk full")

        w.api.emit = refuse
        bad = await h.get("/export", ADMIN_ID, window)
        assert bad.status == 503
        assert bad.data["details"] == {"reason": "audit_unavailable"}
        assert b"marks" not in bad.raw
        assert (
            await h.get("/export", ADMIN_ID, {**window, "limit": "5"})
        ).status == 400
        assert (
            await h.get("/export", ADMIN_ID, {**window, "client": TMC1})
        ).status == 400


async def test_export_limit_pages_with_the_cursor(disks) -> None:
    with world(disks) as w, patch.object(tm_export, "EXPORT_MAX_MARKS", 1000):
        w.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = True
        engine = await w.start()
        total = 2700
        for i in range(total):
            engine.index.add(
                ts=T0 + 1 + i * 0.5,
                kind="channel_changed",
                router=R1,
                code="channel",
                params={"band": 5, "channel_from": 36, "channel_to": 44},
            )
        w.clock.t = T0 + total
        async with http(w) as h:
            params = {"from": str(int(T0 - 60)), "until": str(int(w.clock.t))}
            ids: list[str] = []
            pages = 0
            while True:
                body = (await h.get("/export", params=params)).data
                pages += 1
                assert len(body["marks"]) <= 1000 == body["limit"]
                ids += [m["id"] for m in body["marks"]]
                if body["next_cursor"] is None:
                    break
                assert body["truncated"] is True
                params = {**params, "cursor": body["next_cursor"]}
            assert pages == 3
            assert len(ids) == len(set(ids)) == total + 1  # + tm_started


# --- privacy of the logs ----------------------------------------------------------------


async def test_no_identifier_reaches_the_log(disks, disk, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    async with clients_world(disks, disk) as w, http(w) as h:
        moments = roam(w)
        for path, params in (
            ("/state", {"at": str(moments["r2"])}),
            ("/state", {"at": M1}),
            ("/compare", {"t1": str(T0), "t2": str(w.t - 1)}),
            ("/export", {"from": str(int(T0 - 60))}),
        ):
            await h.get(path, params=params)
        with patch.object(tm_state, "router_state", side_effect=RuntimeError(M1)):
            assert (await h.get("/state", params={"at": str(T0)})).status == 500
        text = caplog.text
        for needle in (*SECRETS, M1, M2, M1.upper()):
            assert needle not in text, needle


# --- NI incidents at a moment (real Network Intelligence) -------------------------------


async def test_incidents_open_at_a_moment(disks, disk) -> None:
    async with clients_world(disks, disk) as w, http(w) as h:
        clock = SimpleNamespace(time=w.clock, monotonic=real_time.monotonic)
        w.stack.enter_context(patch.object(net_engine, "time", clock))
        w.stack.enter_context(
            patch.object(net_engine, "async_get_engine", lambda _h: w.ni)
        )
        roam(w)
        w.down("r1")
        for _ in range(5):
            step(w, None, [M1])
        during = w.t - 30
        w.up("r1")
        for _ in range(3):
            tick(w, [M2], [M1])
        body = (await h.get("/state", params={"at": str(during)})).data
        incidents = body["incidents"]
        assert incidents["state"] == "ok"
        [item] = [i for i in incidents["items"] if i["type"] == "router_unreachable"]
        assert (item["router_id"], item["state"], item["fleet"]) == (R1, "open", False)
        assert item["ref"]["module"] == "network_intelligence"
        assert item["target"] is None  # no Enterprise tab shows NI incidents
        [row] = [r for r in body["routers"] if r["router_id"] == R1]
        assert row["reachable"]["value"] is False
        after = (await h.get("/state", params={"at": str(w.t - 1)})).data
        assert not [
            i for i in after["incidents"]["items"] if i["type"] == "router_unreachable"
        ]
        compare = (
            await h.get("/compare", params={"t1": str(during), "t2": str(w.t - 1)})
        ).data
        resolved = compare["changes"]["incidents"]["resolved"]
        assert [i["type"] for i in resolved] == ["router_unreachable"]
