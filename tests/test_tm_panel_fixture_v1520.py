"""1.52.0: the sample answers of the tab's views "Zustand" and "Vergleich"
and of its export are real route answers.

The frontend tests read ``tmFixtureState.json``. It is not written by hand:
this test builds two routers with the real write paths of
``test_tm_routes_v1520`` (``clients_world``: the real fleet tracker, Network
Intelligence, Client Stability and the Time Machine with its client switch
on), lets a client roam, a channel change and an outage happen, and asks the
real routes ``GET .../timemachine/state``, ``.../compare``, ``.../export``
and ``.../timeline`` (client filter) as an administrator and as a user:

* state: known (with an outage, clients, intervals), the client list in two
  pages (``clients_limit=1``, ``clients_cursor``), a user, a moment before
  the recording (``not_recorded``), one beyond the retention, the client
  switch off, the Time Machine off and not running, a refused moment;
* the three other global reasons (``ha_gap``, ``observation_gap``,
  ``evicted``) with ``tm_state.Snapshot.global_reason`` patched to return
  them: the shape of the answer is the route's, only the reason is chosen
  (their write paths are covered by ``test_tm_state_v1520``);
* compare: changes (a channel, the outage, clients), a quiet pair, one side
  unknown, a user, two refused pairs; ``other_sources`` ok with nothing,
  ok with one audit entry (``compare_other``) and unreadable (the audit
  API without ``events``, ``compare_unreadable``);
* export: one page, a page cut by a lowered limit (``EXPORT_MAX_MARKS`` 1,
  with ``next_cursor``), the audit log refusing (503), and the answers
  without a mark (1.52.0 browser check: the panel saves no file for them):
  a window before the recording with the readable sources
  (``export_empty``, status ``ok``) and with all of them
  (``export_empty_partial``: the modules of the world are not running), the
  Time Machine not running (``export_unavailable``, reason ``not_running``)
  and off (``export_off``);
* timeline: the client filter of an administrator.

The route's clock is the test clock; mark ids and pseudonyms are
repeatable (fixed module key). All values are invented (locally
administered MACs, never in an answer, checked; "Router 1", "Router 2").

Regenerate after a deliberate change of the answer::

    TM_WRITE_FIXTURE=1 python -m pytest tests/test_tm_panel_fixture_v1520.py
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import ADMIN_ID, USER_ID, FakeDisks
from test_client_engine import M1, M2, disk  # noqa: F401 - fixture
from test_tm_clients_v1510 import TMC1, clients_world
from test_tm_routes_v1520 import PANEL_ACCESS, R1, http, roam, tick
from tm_index_kit import SECRETS, T0, iface

from custom_components.openwrt_router import tm_export, tm_state
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_ENGINE,
    OPTION_TIME_MACHINE_ENABLED,
)
from custom_components.openwrt_router.core_models import CoreEvent

FIXTURE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/timemachine"
    / "tmFixtureState.json"
)
PATCHED_REASONS = ("ha_gap", "observation_gap", "evicted")


@pytest.fixture
def disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def _answer(got: Any) -> dict[str, Any]:
    return {"status": got.status, "body": got.data}


async def build(disks: Any, disk: Any) -> tuple[dict[str, Any], list[bytes]]:
    out: dict[str, Any] = {}
    async with clients_world(disks, disk) as w, http(w) as h:
        # The audit log of the test world: empty (the source reads ok with
        # nothing in the window), one entry for ``compare_other`` and none
        # at all (``events`` missing: unreadable) for ``compare_unreadable``.
        w.api.events = lambda **_k: []
        moments = roam(w)
        # r1 changes its channel, then r2 goes down and stays down
        tick(w, [M2], [M1], r1=[iface("phy1", 44)])
        tick(w, [M2], [M1], r1=[iface("phy1", 44)])
        changed = w.clock.t
        w.down("r2")
        tick(w, [M2], None, r1=[iface("phy1", 44)])
        tick(w, [M2], None, r1=[iface("phy1", 44)])
        now = w.clock.t
        at = str(now - 1)

        async def get(path: str, params: dict[str, str], user: str = ADMIN_ID) -> Any:
            return _answer(await h.get(path, user, params))

        # -- state ----------------------------------------------------------------------
        out["state"] = await get("/state", {"at": at})
        page1 = await get("/state", {"at": at, "clients_limit": "1"})
        out["state_clients_page1"] = page1
        cursor = page1["body"]["clients"]["next_cursor"]
        assert cursor is not None
        out["state_clients_page2"] = await get(
            "/state", {"at": at, "clients_limit": "1", "clients_cursor": cursor}
        )
        out["state_before"] = await get("/state", {"at": str(moments["r1"])})
        out["state_not_recorded"] = await get("/state", {"at": str(T0 - 600)})
        out["state_beyond_retention"] = await get(
            "/state", {"at": str(now - 15 * 86_400)}
        )
        for reason in PATCHED_REASONS:
            with patch.object(
                tm_state.Snapshot, "global_reason", lambda _s, _at, r=reason: r
            ):
                out[f"state_{reason}"] = await get("/state", {"at": at})
        out["state_bad_at"] = await get("/state", {"at": str(now + 3600)})
        # -- compare --------------------------------------------------------------------
        out["compare"] = await get("/compare", {"t1": str(moments["r1"]), "t2": at})
        out["compare_quiet"] = await get(
            "/compare", {"t1": str(changed + 1), "t2": str(changed + 30)}
        )
        out["compare_one_unknown"] = await get(
            "/compare", {"t1": str(T0 - 600), "t2": at}
        )
        audit = CoreEvent(
            event_id="evt_" + "1" * 32,
            ts=datetime.fromtimestamp(moments["r1"] + 10, UTC),
            type="configuration.drift_detected",
            source="config_manager",
            router_id=R1,
        )
        w.api.events = lambda **_k: [audit]
        out["compare_other"] = await get(
            "/compare", {"t1": str(moments["r1"]), "t2": at}
        )
        del w.api.events
        out["compare_unreadable"] = await get(
            "/compare", {"t1": str(moments["r1"]), "t2": at}
        )
        w.api.events = lambda **_k: []
        out["compare_empty"] = await get(
            "/compare", {"t1": at, "t2": str(moments["r1"])}
        )
        out["compare_too_large"] = await get("/compare", {"t1": "1", "t2": at})
        # -- export ---------------------------------------------------------------------
        window = {"from": str(int(T0 - 60)), "until": str(int(now))}
        out["export"] = await get("/export", window)
        with patch.object(tm_export, "EXPORT_MAX_MARKS", 1):
            out["export_cut"] = await get("/export", window)

        def refuse(*_a: Any, **_k: Any) -> None:
            raise RuntimeError("disk full")

        emit = w.api.emit
        w.api.emit = refuse
        out["export_refused"] = await get("/export", window)
        w.api.emit = emit
        # -- timeline: the client filter of an administrator ---------------------------
        out["timeline_client"] = await get(
            "/timeline", {**window, "client": TMC1, "spans": "1"}
        )
        # -- a user with the open panel ---------------------------------------------------
        w.hass.data[PANEL_ACCESS] = {"r1": True}
        out["state_user"] = await get("/state", {"at": at}, USER_ID)
        out["compare_user"] = await get(
            "/compare", {"t1": str(moments["r1"]), "t2": at}, USER_ID
        )
        out["export_user"] = await get("/export", window, USER_ID)
        w.hass.data.pop(PANEL_ACCESS)
        # -- an export window without a mark (before the recording) --------------------
        before = {"from": str(int(T0 - 3600)), "until": str(int(T0 - 1800))}
        out["export_empty"] = await get(
            "/export", {**before, "source": "core_audit,tm_index,tm_refs"}
        )
        out["export_empty_partial"] = await get("/export", before)
        # -- the client switch off, the Time Machine not running and off ---------------
        await w.engine.async_set_clients(False)
        out["state_clients_off"] = await get("/state", {"at": at})
        engine = w.hass.data.pop(DATA_TIME_MACHINE_ENGINE)
        out["state_unavailable"] = await get("/state", {"at": at})
        out["export_unavailable"] = await get("/export", window)
        w.hass.data[DATA_TIME_MACHINE_ENGINE] = engine
        for entry in w.entries:
            entry.options[OPTION_TIME_MACHINE_ENABLED] = False
        out["state_off"] = await get("/state", {"at": at})
        out["compare_off"] = await get("/compare", {"t1": str(moments["r1"]), "t2": at})
        out["export_off"] = await get("/export", window)
        bodies = list(h.bodies)
    return out, bodies


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


async def test_the_state_fixture_is_the_real_route_answer(disks, disk) -> None:
    doc, bodies = await build(disks, disk)
    for body in bodies:
        for needle in (*SECRETS, M1, M2, M1.lower(), M2.lower()):
            assert needle.encode() not in body, needle
    # the scenarios the frontend tests rely on
    state = doc["state"]["body"]
    assert state["status"] == "ok" and state["known"] is True
    reach = {r["router_name"]: r["reachable"] for r in state["routers"]}
    assert reach["Router 1"]["value"] is True and reach["Router 2"]["value"] is False
    assert any(r["role"]["reason"] for r in state["routers"])  # an unknown value
    assert state["intervals"] and state["clients"]["state"] == "ok"
    assert state["clients"]["total"] >= 1
    page1 = doc["state_clients_page1"]["body"]["clients"]
    page2 = doc["state_clients_page2"]["body"]["clients"]
    assert page1["truncated"] is True and page2["next_cursor"] is None
    for name in ("not_recorded", "beyond_retention", *PATCHED_REASONS):
        body = doc[f"state_{name}"]["body"]
        assert (body["known"], body["unknown_reason"]) == (False, name), name
    assert doc["state_bad_at"]["status"] == 400
    user = doc["state_user"]["body"]
    assert user["clients"]["reason"] == "admin_only"
    assert user["config"]["reason"] == "admin_only"
    assert doc["state_clients_off"]["body"]["clients"]["reason"] == "clients_off"
    assert doc["state_unavailable"]["body"]["status"] == "unavailable"
    assert doc["state_off"]["body"]["status"] == "off"
    changes = doc["compare"]["body"]["changes"]
    states = {r["reachable"]["state"] for r in changes["routers"]} | {
        x["state"] for r in changes["routers"] for x in r["radios"]
    }
    assert "changed" in states
    assert changes["marks"]["count"] > 0
    quiet = doc["compare_quiet"]["body"]["changes"]
    assert not [
        r
        for r in quiet["routers"]
        if "changed"
        in {r["reachable"]["state"], r["role"]["state"], r["uplink"]["state"]}
        | {x["state"] for x in r["radios"]}
    ]
    others = {
        name: doc[name]["body"]["changes"]["other_sources"]
        for name in ("compare", "compare_other", "compare_unreadable")
    }
    assert (others["compare"]["state"], others["compare"]["count"]) == ("ok", 0)
    assert (others["compare_other"]["state"], others["compare_other"]["count"]) == (
        "ok",
        1,
    )
    assert others["compare_unreadable"]["state"] == "unreadable"
    assert others["compare_unreadable"]["unreadable"] == ["core_audit"]
    one = doc["compare_one_unknown"]["body"]
    assert one["before"]["known"] is False and one["after"]["known"] is True
    assert doc["compare_empty"]["body"]["details"]["reason"] == "empty"
    assert doc["compare_too_large"]["body"]["details"]["reason"] == "too_large"
    assert all(
        r["clients"] is None for r in doc["compare_user"]["body"]["changes"]["routers"]
    )
    export = doc["export"]["body"]
    assert export["kind"] == "openwrt_router.time_machine.export"
    assert export["marks"] and export["truncated"] is False
    cut = doc["export_cut"]["body"]
    assert cut["truncated"] is True and cut["next_cursor"] is not None
    assert doc["export_refused"]["status"] == 503
    assert doc["export_user"]["status"] == 403
    # the answers without a mark: the panel saves nothing and says why
    empty = doc["export_empty"]["body"]
    assert (empty["status"], empty["reason"]) == ("ok", None)
    assert empty["marks"] == [] and empty["spanning"] == []
    partial = doc["export_empty_partial"]["body"]
    assert (partial["status"], partial["marks"], partial["spanning"]) == (
        "partial",
        [],
        [],
    )
    unavailable = doc["export_unavailable"]["body"]
    assert (unavailable["status"], unavailable["reason"]) == (
        "unavailable",
        "not_running",
    )
    assert unavailable["marks"] == [] and unavailable["spanning"] == []
    off = doc["export_off"]["body"]
    assert (off["status"], off["marks"], off["spanning"]) == ("off", [], [])
    timeline = doc["timeline_client"]["body"]
    assert timeline["marks"] and {m["client"] for m in timeline["marks"]} == {TMC1}
    text = _dump(doc)
    if os.environ.get("TM_WRITE_FIXTURE") == "1":
        FIXTURE.write_text(text, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == text, (
        "tmFixtureState.json differs from the route's answer; regenerate it "
        "with TM_WRITE_FIXTURE=1 (see the module docstring)"
    )
