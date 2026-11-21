"""1.51.0: the sample answers of the tab's B/C parts are real route answers.

The frontend tests read ``tmFixtureClients.json`` for the own index
(outages as intervals, one that reaches into the window), the client
histories (sessions, a roam with its peers, a disconnect, a client name
from Client Stability) and the sessions view. It is not written by hand:
this test builds three routers with the real outage tracker, the real
Network Intelligence and Client Stability and the Time Machine with its
client switch on (``tm_index_kit``, ``test_tm_clients_v1510``), asks the
real routes ``GET .../timemachine/timeline`` and ``.../sessions`` as an
administrator and as a user, with a small page, a client filter, a refused
query, an empty window, with the client switch off, while not running and
while switched off, and compares the answers with the checked-in file.

The route's clock is the test clock; mark ids and pseudonyms are
repeatable (fixed module key). All values are invented: locally
administered MACs (never in an answer, checked), the routers "Router 1" to
"Router 3", the client name "tablet-kueche".

Regenerate after a deliberate change of the answer::

    TM_WRITE_FIXTURE=1 python -m pytest tests/test_tm_panel_fixture_v1510.py
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import contextlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users
from test_client_engine import M1, M2, client, data, disk, setup  # noqa: F401
from test_tm_views import http
from tm_index_kit import SECRETS, T0, world

from custom_components.openwrt_router import tm_views
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_ENGINE,
    OPTION_TIME_MACHINE_ENABLED,
)
from custom_components.openwrt_router.topology_panel import _PANEL_ACCESS_KEY

FIXTURE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/timemachine"
    / "tmFixtureClients.json"
)
INDEX = "tm_index,tm_refs,tm_clients"
NAME = "tablet-kueche"


@pytest.fixture
def disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def poll(w: Any, **lists: list[str] | None) -> None:
    """One poll of every router (missing: no client; ``None``: no list)."""
    for entry in ("r1", "r2", "r3"):
        macs = lists.get(entry, [])
        listed = None if macs is None else [client(m) for m in macs]
        w.ni.ingest(entry, data(listed), w.t, interval=60.0)
    w.t += 60
    w.clock.t = w.t


@contextlib.asynccontextmanager
async def three_routers(disks: Any) -> Any:
    with world(disks, routers=3) as w:
        for entry in w.entries:
            entry.options[OPTION_TIME_MACHINE_ENABLED] = True
        w.ni, w.cs = await setup(w.hass, "r1", "r2", "r3")
        await w.start(clients=True)
        w.t = T0
        yield w


async def fetch(h: Any, path: str, user: str, params: dict[str, str]) -> Any:
    resp = await h.client.get(
        tm_views.BASE_URL + path, headers={"X-Test-User": user}, params=params
    )
    body = await resp.read()
    h.bodies.append(body)
    return {"status": resp.status, "body": json.loads(body)}


async def build(disks: Any) -> tuple[dict[str, Any], list[bytes]]:
    async with three_routers(disks) as w:
        add_users(w.hass)
        # r3 goes down early and stays down: it reaches into the window
        poll(w, r1=[M2])
        w.down("r3")
        for _ in range(9):
            poll(w, r1=[M2], r3=None)
        w.cs.history._clients[M2].host = NAME  # what Client Stability knows
        since = w.t  # the window starts here: M2's session reaches into it
        # M1: connected to r1, roams to r2, leaves
        for _ in range(3):
            poll(w, r1=[M2, M1], r3=None)
        for _ in range(2):
            poll(w, r1=[M2], r2=[M1], r3=None)
        for _ in range(12):
            poll(w, r1=[M2], r3=None)
        # r2: a short outage inside the window
        w.down("r2")
        for _ in range(5):
            poll(w, r1=[M2], r2=None, r3=None)
        w.up("r2")
        w.coords["r2"].poll()
        for _ in range(3):
            poll(w, r1=[M2], r3=None)
        now = w.t
        window = {"from": str(int(since)), "until": str(int(now + 1))}
        past = {"from": str(int(T0 - 3 * 86_400)), "until": str(int(T0 - 86_400))}
        tl = {**window, "source": INDEX}
        out: dict[str, Any] = {}
        with patch.object(tm_views.time, "time", return_value=now):
            async with http(w.hass) as h:
                out["timeline"] = await fetch(h, "/timeline", ADMIN_ID, tl)
                out["timeline_page1"] = await fetch(
                    h, "/timeline", ADMIN_ID, {**tl, "limit": "4"}
                )
                w.hass.data[_PANEL_ACCESS_KEY] = {"r1": True}
                out["timeline_user"] = await fetch(h, "/timeline", USER_ID, tl)
                out["sessions_user"] = await fetch(h, "/sessions", USER_ID, window)
                w.hass.data.pop(_PANEL_ACCESS_KEY)
                out["sessions"] = await fetch(h, "/sessions", ADMIN_ID, window)
                page = {**window, "limit": "2"}
                first = await fetch(h, "/sessions", ADMIN_ID, page)
                out["sessions_page1"] = first
                until = first["body"]["next_until"]
                assert until is not None
                out["sessions_page2"] = await fetch(
                    h, "/sessions", ADMIN_ID, {**page, "until": str(until)}
                )
                one = out["sessions"]["body"]["sessions"][0]["client"]
                out["sessions_client"] = await fetch(
                    h, "/sessions", ADMIN_ID, {**window, "client": one}
                )
                out["sessions_empty"] = await fetch(h, "/sessions", ADMIN_ID, past)
                out["sessions_bad_request"] = await fetch(
                    h, "/sessions", ADMIN_ID, {"client": "nope"}
                )
                engine = w.hass.data.pop(DATA_TIME_MACHINE_ENGINE)
                out["sessions_unavailable"] = await fetch(
                    h, "/sessions", ADMIN_ID, window
                )
                w.hass.data[DATA_TIME_MACHINE_ENGINE] = engine
                await engine.async_set_clients(False)
                out["sessions_clients_off"] = await fetch(
                    h, "/sessions", ADMIN_ID, window
                )
                out["timeline_clients_off"] = await fetch(h, "/timeline", ADMIN_ID, tl)
                for entry in w.entries:
                    entry.options[OPTION_TIME_MACHINE_ENABLED] = False
                out["sessions_off"] = await fetch(h, "/sessions", ADMIN_ID, window)
                bodies = list(h.bodies)
        return out, bodies


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


async def test_the_clients_fixture_is_the_real_route_answer(disks, disk) -> None:
    doc, bodies = await build(disks)
    for body in bodies:
        for needle in (*SECRETS, M1, M2, M1.lower(), M2.lower()):
            assert needle.encode() not in body, needle
    tl = doc["timeline"]["body"]
    marks = tl["marks"]
    kinds = {m["kind"] for m in marks}
    # the scenarios the frontend tests rely on
    assert {"client_session", "client_roam", "client_disconnect"} <= kinds
    assert {"router_down", "router_up"} <= kinds
    spans = [m for m in marks if m["spans_in"]]
    assert {m["kind"] for m in spans} == {"router_down", "client_session"}
    assert {m["end_state"] for m in marks if m["end_state"]} >= {"open", "closed"}
    roam = next(m for m in marks if m["kind"] == "client_roam")
    assert roam["peers"]["before"]["router_name"] == "Router 1"
    assert roam["peers"]["after"]["router_name"] == "Router 2"
    assert NAME in {m["client_name"] for m in marks}
    assert None in {m["client_name"] for m in marks if m["client"]}
    assert doc["timeline_page1"]["body"]["next_until"] is not None
    assert not [m for m in doc["timeline_page1"]["body"]["marks"] if m["spans_in"]]
    user = {s["id"]: s for s in doc["timeline_user"]["body"]["sources"]}
    assert user["tm_clients"]["reason"] == user["tm_refs"]["reason"] == "admin_only"
    assert doc["sessions_user"]["status"] == 403
    sessions = doc["sessions"]["body"]
    assert sessions["status"] == "ok" and sessions["recording"] is True
    assert {s["end_state"] for s in sessions["sessions"]} == {"open", "closed"}
    assert any(s["params"].get("roam") for s in sessions["sessions"])
    assert doc["sessions_page1"]["body"]["truncated"] is True
    assert doc["sessions_empty"]["body"]["sessions"] == []
    assert doc["sessions_bad_request"]["status"] == 400
    assert doc["sessions_unavailable"]["body"]["status"] == "unavailable"
    assert doc["sessions_clients_off"]["body"]["status"] == "clients_off"
    off = {s["id"]: s for s in doc["timeline_clients_off"]["body"]["sources"]}
    assert (off["tm_clients"]["state"], off["tm_clients"]["reason"]) == (
        "off",
        "clients_off",
    )
    assert doc["sessions_off"]["body"]["status"] == "off"
    text = _dump(doc)
    if os.environ.get("TM_WRITE_FIXTURE") == "1":
        FIXTURE.write_text(text, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == text, (
        "tmFixtureClients.json differs from the route's answer; regenerate it "
        "with TM_WRITE_FIXTURE=1 (see the module docstring)"
    )
