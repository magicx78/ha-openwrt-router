"""Network Time Machine, Phase C (1.51.0): client sessions.

Real write path: the Network Intelligence engine ingests polls, the real
Client Stability books its transitions and the Time Machine observes them
(``ClientStability.add_transition_listener``). Store on
``core_testkit.FakeDisks``; NI and Client Stability on the fake disks of
``test_client_engine``. Routers ``r1`` / ``r2`` map to contract router ids
through the kit's fake registry. MACs locally administered.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import contextlib
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import full_router_kit as kit
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.http import KEY_AUTHENTICATED, KEY_HASS
from test_client_engine import M1, M2, client, data, disk, setup  # noqa: F401
from tm_index_kit import KEY, RID, SECRETS, T0, world

from custom_components.openwrt_router import tm_sources, tm_views
from custom_components.openwrt_router.client_history import ClientHistory
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.tm_engine import (
    async_apply_time_machine_options,
    async_clear_history,
    async_forget_client,
    async_get_time_machine,
    async_purge_clients,
)

R1, R2 = RID["r1"], RID["r2"]
TMC1 = "tmc_" + pseudonymise_identifier("client", M1, KEY)[4:]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


@contextlib.asynccontextmanager
async def clients_world(disks: Any, disk: Any, *, clients: bool = True) -> Any:
    with world(disks, routers=2) as w:
        for entry in w.entries:
            entry.options[OPTION_TIME_MACHINE_ENABLED] = True
        w.ni, w.cs = await setup(w.hass, "r1", "r2")
        await w.start(clients=clients)
        w.t = T0
        yield w


def step(w: Any, r1: list[str] | None, r2: list[str] | None) -> None:
    """One poll of both routers (``None``: no fresh client list)."""
    for router, macs in (("r1", r1), ("r2", r2)):
        listed = None if macs is None else [client(m) for m in macs]
        w.ni.ingest(router, data(listed), w.t, interval=60.0)
    w.t += 60
    w.clock.t = w.t


def sessions(w: Any) -> list[Any]:
    return w.marks("client_session")


# --- sessions, roaming, disconnects --------------------------------------------------


async def test_session_roam_and_disconnect_across_routers(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        for _ in range(2):
            step(w, [], [M1])
        for _ in range(12):
            step(w, [], [])
        first, second = sessions(w)
        assert (first.router, first.end_state) == (R1, "closed")
        assert first.params["band"] == 5 and "roam" not in first.params
        assert (second.router, second.params) == (R2, {"band": 5, "roam": 1})
        assert second.end_state == "closed" and second.ts == first.end
        [roam] = w.marks("client_roam")
        assert roam.peers == (R1, R2) and roam.client == TMC1[4:]
        [gone] = w.marks("client_disconnect")
        assert gone.ts == second.end and gone.params == {"timed": 1}
        assert gone.code == "unknown" and gone.router == R2


async def test_unreachable_router_invents_no_disconnect(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(2):
            step(w, [M1], [])
        w.down("r1")
        for _ in range(20):
            step(w, None, [])  # r1 delivers no client list
        assert not w.marks("client_disconnect")
        [session] = sessions(w)
        assert session.is_open and session.params.get("gaps", 0) >= 1
        assert w.marks("router_down")[0].is_open


async def test_restart_mid_session_ends_unknown_and_resumes(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        await w.ha_stop_and_write()
        w.engine.recorder.detach()
        stopped = w.stored["saved_at"]
        w.clock.advance(600)
        await w.start(clients=True)
        old, new = sessions(w)
        assert (old.end_state, old.end) == ("unknown", pytest.approx(stopped))
        assert new.is_open and new.params["resumed"] == 1 and new.derived is True
        assert new.ts == pytest.approx(w.clock.t) and new.router == R1


async def test_a_flapping_client_never_fills_the_store(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        w.down("r2")  # an infrastructure mark that must survive
        infra = len(w.marks("router_down"))
        # 130 cycles of seven polls fit into the UTC day of T0
        for _ in range(130):
            step(w, [M1], [])
            for _ in range(6):
                step(w, [], [])
        client_marks = [m for m in w.engine.index if m.client is not None]
        [flap] = w.marks("client_flapping")
        assert len(client_marks) == 201  # 200 a day + the summary
        assert flap.params["suppressed"] > 0 and flap.params["cap"] == 200
        assert len(w.marks("router_down")) == infra
        assert w.engine.index.count("infrastructure") >= 1


# --- forgetting and switching off -------------------------------------------------------


async def test_forget_action_and_client_stability_exclusion(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1, M2], [])
        answer = await async_forget_client(w.hass, M1.lower())
        assert answer["deleted"] == 1
        assert "client_stability" in answer["not_deleted_in"]
        assert {m.client for m in sessions(w)} == {
            pseudonymise_identifier("client", M2, KEY)[4:]
        }
        [forgot] = w.marks("tm_forgot_client")
        assert forgot.client is None and forgot.params == {"deleted": 1}
        assert w.api.emitted[-1][0] == "time_machine.client_forgotten"
        # written at once, even though a delayed write was already pending
        assert w.disk.delayed[-1][1] == 0
        w.flush()
        gone = pseudonymise_identifier("client", M1, KEY)[4:]
        assert not [row for row in w.stored["marks"] if gone in row]
        # Client Stability forgets M2 (exclusion): the Time Machine follows
        w.ni.settings["exclusions"] = {"macs": [M2.lower()]}
        step(w, [M1, M2], [])
        assert all(
            m.client != pseudonymise_identifier("client", M2, KEY)[4:]
            for m in w.engine.index
        )
        with pytest.raises(ServiceValidationError) as err:
            await async_forget_client(w.hass, "not a mac")
        assert err.value.translation_key == "time_machine_invalid_mac"


async def test_client_switch_off_deletes_the_client_history(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        w.down("r2")
        await async_apply_time_machine_options(w.hass, on=True, clients=False)
        assert not [m for m in w.engine.index if m.client is not None]
        assert w.marks("router_down")
        w.flush()
        assert not [r for r in w.stored["marks"] if "|client_" in r]
        step(w, [M1], [])  # nothing recorded while off
        assert not sessions(w)
        assert w.engine.recorder is None and w.cs._transition_listeners == []


async def test_time_machine_off_deletes_clients_and_purge_when_already_off(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        await async_apply_time_machine_options(w.hass, on=False, clients=True)
        assert async_get_time_machine(w.hass) is None
        assert not [r for r in w.stored["marks"] if "|client_" in r]
    # a store left with client marks (e.g. written by a crash) and the
    # client switch is turned off while the Time Machine is off
    with world(disks) as w2:
        engine = await w2.start(clients=False)
        engine.index.add(
            ts=T0, kind="client_roam", router=R1, client="ab" * 8, code="roam"
        )
        await engine.async_stop("unloaded")
        assert any("|client_roam|" in r for r in w2.stored["marks"])
        assert await async_purge_clients(w2.hass) == 1
        assert not any("|client_roam|" in r for r in w2.stored["marks"])


async def test_clear_history_action(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        w.down("r2")
        assert (await async_clear_history(w.hass, True))["deleted"] == 1
        assert w.marks("router_down") and not sessions(w)
        await async_clear_history(w.hass, False)
        assert [m.kind for m in w.engine.index] == ["tm_cleared"]


# --- privacy and rights --------------------------------------------------------------


async def test_store_holds_pseudonyms_only(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(2):
            step(w, [M1, M2], [])
        w.cs.history._clients[M1].host = "laptop"  # what DHCP gave it
        await w.ha_stop_and_write()
        text = json.dumps(w.stored)
        for needle in (*SECRETS, M1, M1.lower(), M2.lower()):
            assert needle not in text, needle
        assert TMC1[4:] in text


async def test_client_marks_and_names_for_admins_only(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(2):
            step(w, [M1], [])
        w.cs.history._clients[M1].host = "laptop"
        routers = tm_sources.RouterMap({"r1": R1}, {R1: "Router 1"})
        since, until = T0 - 60, T0 + 3600
        admin = tm_sources.ReadRequest(since, until, True, until)
        user = tm_sources.ReadRequest(since, until, False, until)
        got = await tm_sources.async_read_source(w.hass, "tm_clients", admin, routers)
        [mark] = got.marks
        assert (mark["client"], mark["client_name"]) == (TMC1, "laptop")
        assert (
            mark["end_state"] == "open"
            and mark["title_key"] == "tm_clients.client_session"
        )
        off = await tm_sources.async_read_source(w.hass, "tm_clients", user, routers)
        assert (off.state, off.reason, off.marks) == ("off", "admin_only", [])
        # forgotten by Client Stability: the pseudonym stays, the name goes
        w.cs.history._clients.pop(M1)
        got = await tm_sources.async_read_source(w.hass, "tm_clients", admin, routers)
        assert got.marks[0]["client_name"] is None
        # the client switch off: the source says so
        await w.engine.async_set_clients(False)
        off = await tm_sources.async_read_source(w.hass, "tm_clients", admin, routers)
        assert (off.state, off.reason) == ("off", "clients_off")


def _auth(hass: Any) -> Any:
    @web.middleware
    async def middleware(request: web.Request, handler: Any) -> Any:
        user_id = request.headers.get("X-Test-User")
        if user_id:
            request[KEY_AUTHENTICATED] = True
            request[KEY_HASS_USER] = hass.users.get(user_id)
        return await handler(request)

    return middleware


async def get(hass: Any, path: str, user: str, params: Any = None) -> Any:
    app = web.Application(middlewares=[_auth(hass)])
    app[KEY_HASS] = hass
    for view_class in tm_views.TIME_MACHINE_VIEWS:
        view_class().register(hass, app, app.router)
    async with TestClient(TestServer(app)) as c:
        resp = await c.get(
            tm_views.BASE_URL + path, headers={"X-Test-User": user}, params=params
        )
        return resp.status, await resp.json()


async def test_sessions_route_rights_errors_and_paging(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        add_users(w.hass)
        w.hass.is_stopping = False
        w.hass.data["openwrt_router_panel_access"] = {"r1": True}
        for _ in range(3):
            step(w, [M1, M2], [])
        for _ in range(2):
            step(w, [], [M1, M2])
        window = {"from": str(int(T0 - 60)), "until": str(int(w.t + 60))}
        status, body = await get(w.hass, "/sessions", USER_ID, window)
        assert status == 403 and "sessions" not in body
        status, body = await get(w.hass, "/sessions", ADMIN_ID, {**window, "x": "1"})
        assert (status, body["details"]) == (
            400,
            {"field": "query", "reason": "unknown_key"},
        )
        status, body = await get(w.hass, "/sessions", ADMIN_ID, {"client": M1})
        assert status == 400 and M1 not in json.dumps(body)
        status, body = await get(
            w.hass, "/sessions", ADMIN_ID, {**window, "limit": "2"}
        )
        assert status == 200 and body["status"] == "ok" and body["recording"] is True
        # two sessions start at the same moment (the roam): one page keeps them
        assert len(body["sessions"]) == 2 and body["truncated"] is True
        assert {s["router_id"] for s in body["sessions"]} == {R2}
        page2 = {**window, "until": str(body["next_until"]), "limit": "2"}
        status, body2 = await get(w.hass, "/sessions", ADMIN_ID, page2)
        assert {s["router_id"] for s in body2["sessions"]} == {R1}
        assert body2["sessions"][0]["end_state"] == "closed"
        one = {**window, "client": TMC1}
        status, body3 = await get(w.hass, "/sessions", ADMIN_ID, one)
        assert {s["client"] for s in body3["sessions"]} == {TMC1}
        assert set(body3["sessions"][0]) == {
            "id",
            "client",
            "client_name",
            "router_id",
            "router_name",
            "start",
            "end",
            "end_state",
            "band",
            "params",
            "derived",
        }
        # the timeline: a non-admin with the open panel sees no client mark
        status, tl = await get(w.hass, "/timeline", USER_ID, window)
        assert status == 200
        assert not [m for m in tl["marks"] if m["group"] == "clients"]
        by_id = {s["id"]: s for s in tl["sources"]}
        assert by_id["tm_clients"]["reason"] == "admin_only"
        assert tl["omitted_client_marks"] == 0
        await w.engine.async_set_clients(False)
        status, off = await get(w.hass, "/sessions", ADMIN_ID, window)
        assert off["status"] == "clients_off" and off["sessions"] == []


# --- the source module behaves as before ---------------------------------------------


class _Seen:
    def __init__(self, seen: list[Any]) -> None:
        self.seen = seen

    def __call__(self, *args: Any) -> None:
        self.seen.append(args)


async def test_client_stability_books_the_same_with_a_listener(disk) -> None:
    from core_testkit import make_hass

    runs = []
    for listen in (False, True):
        hass = make_hass()
        ni, cs = await setup(hass, "r1", "r2")
        seen: list[Any] = []
        if listen:
            cs.add_transition_listener(
                SimpleNamespace(transition=lambda *a: None, forgot=lambda m: None)
            )
            cs.add_transition_listener(
                SimpleNamespace(transition=_Seen(seen), forgot=lambda m: None)
            )
        t = T0
        for macs1, macs2 in [([M1], [])] * 3 + [([], [M1, M2])] * 2 + [([], [])] * 12:
            ni.ingest("r1", data([client(m) for m in macs1]), t, interval=60.0)
            ni.ingest("r2", data([client(m) for m in macs2]), t + 1, interval=60.0)
            t += 60
        runs.append(cs.history.to_dict())
        if listen:
            assert len(seen) >= 4
    assert runs[0] == runs[1]
    # a failing listener never reaches the history
    hist = ClientHistory()
    hist.on_transition = MagicMock(side_effect=RuntimeError("boom"))
    hist.on_forget = MagicMock(side_effect=RuntimeError("boom"))
    assert hist.forget(M1) is False


# --- no router call ---------------------------------------------------------------------


async def test_two_polls_make_the_same_router_calls_with_everything_on(
    disks, disk
) -> None:
    """Hard requirement 2: the call list of two polls, all on vs all off."""
    off_calls: list[Any] = []
    off = kit.make_coordinator(MagicMock(), kit.make_api(off_calls))
    await kit.full_polls(off, on_poll=lambda d, n: None)
    async with clients_world(disks, disk) as w:
        on_calls: list[Any] = []
        coordinator = kit.make_coordinator(w.hass, kit.make_api(on_calls))
        w.engine.add_entry("r1", coordinator)
        assert w.engine.recorder is not None and w.engine.recorder.attached

        def after_poll(result: Any, _n: int) -> None:
            coordinator.data = result
            coordinator.async_update_listeners()  # the Time Machine runs here

        await kit.full_polls(coordinator, on_poll=after_poll)
        assert on_calls == off_calls
        assert w.engine.store.state.get(R1)  # it did see both polls
