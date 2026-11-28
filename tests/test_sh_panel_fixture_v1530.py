"""1.53.0 (package J): the sample answers of the "Self-Healing" tab are real
route answers.

The frontend tests (``frontend/topology/src/enterprise/selfhealing``) and the
dev mock (``?selfhealingmock``) read ``shFixture.json``. It is not written by
hand: this test builds the world of ``test_heal_engine_v1530`` with the
production decider (``PolicyDecider()``, as ``async_setup_self_healing``
wires it), asks the five real GET routes of ``heal_views`` and compares the
answers with the checked-in file:

* nothing observed yet (overview, list, plans);
* one record closed by Network Intelligence (WAN, router 2), one open record
  with a cause (router 1) and one more root incident waiting on router 1;
  list, both details, the plans, the settings;
* a plan whose facts source names a candidate (a stand-in for packages E/F,
  not wired in 1.53.0): the candidate appears only in the explanation;
* a non-administrator with the panel open to all (counts only) and closed
  (403);
* a router hold, a paused fleet and a router configured for Auto-Heal;
* the module switched off in the store, an unknown record (404) and the
  engine stopped (503).

Ids are made repeatable (``uuid.uuid4`` counts; router ids are the test's
``rtr_1…1`` / ``rtr_2…2``), the routes' clock is the test clock. Everything
else is what the routes answer. No address, host or client name is in any
answer (checked below).

Regenerate after a deliberate change of an answer::

    SH_WRITE_FIXTURE=1 python -m pytest tests/test_sh_panel_fixture_v1530.py
"""

from __future__ import annotations

import itertools
import json
import os
import re
import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, add_users
from test_heal_engine_v1530 import (
    E1,
    E2,
    R1,
    R2,
    Clock,
    FakeNI,
    Registry,
    World,
    heal_hass,
    make_entries,
    patched,
)
from test_heal_store_v1530 import disks
from test_heal_views_v1530 import _auth_middleware
from test_heal_x_engine_v1530 import Favourable

from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_views as hv
from custom_components.openwrt_router import net_rules
from custom_components.openwrt_router.const import DATA_SELF_HEALING_ENGINE
from custom_components.openwrt_router.topology_panel import _PANEL_ACCESS_KEY

__all__ = ["disks"]

FIXTURE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/selfhealing"
    / "shFixture.json"
)
B = hv.BASE_URL
# an address, a MAC or an interface name would be private data in a sample
_PRIVATE = re.compile(
    r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|\b\d{1,3}(?:\.\d{1,3}){3}\b"
    r"|\b(?:wlan|phy|eth|br-|lan\d)",
    re.IGNORECASE,
)


async def build() -> dict[str, Any]:
    """Every answer the tab's tests need, from the real routes."""
    hass = heal_hass(make_entries(E1, E2))
    add_users(hass)
    clock = Clock()
    w = World(hass, clock, FakeNI(), Registry({E1: R1, E2: R2}))
    out: dict[str, Any] = {}
    seq = itertools.count(1)
    fake_time = SimpleNamespace(time=lambda: clock.now)
    with (
        patch("uuid.uuid4", side_effect=lambda: uuid.UUID(int=next(seq))),
        patched(w.ni, w.registry, w.ticks),
        patch.object(hv, "time", fake_time),
        # NI's own reading of the incident: two source families, cause likely
        patch.object(
            net_rules, "cause_families", lambda inc, events: frozenset({"log", "poll"})
        ),
        patch.object(
            net_rules,
            "incident_cause_level",
            lambda inc, events: SimpleNamespace(value="likely"),
        ),
    ):
        engine = await w.start(decider=he.PolicyDecider())
        hass.is_stopping = False
        app = web.Application(middlewares=[_auth_middleware(hass)])
        app[hv.KEY_HASS] = hass
        for view_class in hv.SELF_HEALING_VIEWS:
            view_class().register(hass, app, app.router)
        async with TestClient(TestServer(app)) as client:

            async def get(
                url: str, user: str | None = ADMIN_ID, **params: str
            ) -> dict[str, Any]:
                headers = {"X-Test-User": user} if user else {}
                resp = await client.get(url, headers=headers, params=params or None)
                return {"status": resp.status, "body": json.loads(await resp.text())}

            # 1. nothing observed yet
            out["empty_overview"] = await get(f"{B}/overview")
            out["empty_actions"] = await get(f"{B}/actions", limit="200")
            out["empty_plans"] = await get(f"{B}/plans")

            # 2. one closed record (WAN, resolved by NI), one open with a
            #    cause, one more root waiting on the same router
            w.open(
                "inc-2",
                router=E2,
                type="wan_down",
                cause="wan_down",
                cause_status="confirmed",
            )
            clock.now += 600
            w.resolve("inc-2")
            clock.now += 1200
            w.open(
                "inc-1",
                router=E1,
                type="system_service_restart",
                cause="dns_resolution",
                cause_status="hypothesis",
            )
            clock.now += 30
            w.open("inc-3", router=E1, type="dhcp_pool_full")
            clock.now += 90
            open_rec = w.of("inc-1")
            closed_rec = w.of("inc-2")
            out["overview"] = await get(f"{B}/overview")
            out["actions"] = await get(f"{B}/actions", limit="200")
            out["detail_open"] = await get(f"{B}/actions/{open_rec.action_id}")
            out["detail_closed"] = await get(f"{B}/actions/{closed_rec.action_id}")
            out["plans"] = await get(f"{B}/plans")
            out["plan_open"] = await get(f"{B}/plans", action_id=open_rec.action_id)
            out["plan_closed"] = await get(f"{B}/plans", action_id=closed_rec.action_id)
            out["settings"] = await get(f"{B}/settings")
            # a facts source that names a candidate (stand-in for packages
            # E/F, not wired in 1.53.0): shown only in the explanation
            engine.decider = he.PolicyDecider(Favourable())
            out["plan_candidate"] = await get(
                f"{B}/plans", action_id=open_rec.action_id
            )
            engine.decider = he.PolicyDecider()

            # 3. a non-admin while the panel is open to all: counts only
            hass.data[_PANEL_ACCESS_KEY] = {E1: True}
            out["user_overview"] = await get(f"{B}/overview", user=USER_ID)
            out["user_actions"] = await get(f"{B}/actions", user=USER_ID)
            hass.data[_PANEL_ACCESS_KEY] = {E1: False}
            out["user_overview_closed_panel"] = await get(f"{B}/overview", user=USER_ID)

            # 4. a router hold, a paused fleet, a router set to Auto-Heal
            store = engine.store
            store.set_settings(
                hm.HealSettings(
                    routers={R2: hm.RouterSettings(mode=hm.HealMode.AUTO_HEAL)}
                )
            )
            safe = store.now()
            store.loop.place_hold(
                hm.RouterHold(
                    router_id=R1,
                    reason=hm.HoldReason.OUTCOME_UNKNOWN,
                    since=safe,
                    until=None,
                )
            )
            store.loop.fleet = hm.FleetPause(
                paused_until=safe + 3600, since=safe, reason="store_lost"
            )
            out["held_overview"] = await get(f"{B}/overview")
            out["held_detail"] = await get(f"{B}/actions/{open_rec.action_id}")
            out["held_plan"] = await get(f"{B}/plans", action_id=open_rec.action_id)

            # 5. the module switched off in the store
            store.set_settings(hm.HealSettings(enabled=False))
            store.loop.holds.clear()
            store.loop.fleet = hm.FleetPause()
            out["disabled_overview"] = await get(f"{B}/overview")

            # 6. errors: an unknown record, the engine stopped
            out["unknown_action"] = await get(f"{B}/actions/rem_{'f' * 32}")
            await engine.async_stop()
            out["not_running"] = await get(f"{B}/overview")
            hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
    return out


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


async def test_the_tab_fixture_is_the_real_route_answer(disks: FakeDisks) -> None:
    doc = await build()
    # the scenarios the frontend tests rely on
    assert doc["empty_actions"]["body"]["actions"] == []
    assert doc["overview"]["body"]["status"] == "on"
    assert doc["overview"]["body"]["release_mode"] == "observe_only"
    assert doc["overview"]["body"]["write_path"] is False
    assert doc["overview"]["body"]["pending_incidents"] == 1
    states = sorted(a["state"] for a in doc["actions"]["body"]["actions"])
    assert states == ["cancelled", "proposed"]
    assert doc["detail_open"]["body"]["action"]["preflight"] == []
    assert "candidate" not in doc["plan_open"]["body"]["plans"][0]["explanation"]
    candidate = doc["plan_candidate"]["body"]["plans"][0]["explanation"]["candidate"]
    assert candidate["label"] == "candidate"
    assert candidate["note"] == "not_the_record_decision"
    assert "routers" not in doc["user_overview"]["body"]
    assert doc["user_actions"]["status"] == 403
    assert doc["user_overview_closed_panel"]["status"] == 403
    held = doc["held_overview"]["body"]
    assert held["fleet"]["paused"] is True
    assert held["fleet"]["pause_reason"] == "store_lost"
    assert [r["held"] for r in held["routers"]] == [True, False]
    assert held["routers"][1]["configured_mode"] == "auto_heal"
    assert held["routers"][1]["effective_mode"] == "observe"
    assert doc["disabled_overview"]["body"]["status"] == "module_disabled"
    assert doc["unknown_action"]["status"] == 404
    assert doc["unknown_action"]["body"]["code"] == "unknown_action"
    assert doc["not_running"]["status"] == 503
    assert doc["not_running"]["body"]["code"] == "not_running"
    text = _dump(doc)
    assert not _PRIVATE.search(text), _PRIVATE.search(text)
    if os.environ.get("SH_WRITE_FIXTURE") == "1":
        FIXTURE.write_text(text, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == text, (
        "shFixture.json differs from the routes' answers; regenerate it with "
        "SH_WRITE_FIXTURE=1 (see the module docstring)"
    )
