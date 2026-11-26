"""1.52.0 review fixes A to J of the Time Machine backend.

Every test runs through the real write paths (``tm_index_kit``: the real
engine, store, fleet tracker; the client tests the real Network Intelligence
and Client Stability of ``test_tm_clients_v1510``) and fails without its fix.
The answers are read as the routes read them (``tm_state.async_snapshot`` /
``router_state``, ``async_state``, ``async_compare``, ``async_timeline``,
``async_export``). A value is either the truth of the polls or unknown.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import json
import logging
import random
import time
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import FakeDisks
from test_client_engine import M1, M2, disk  # noqa: F401 - fixture
from test_tm_clients_v1510 import clients_world, step
from test_tm_modules_v1520 import BLOCK_CALLS_MAX, GROWTH_MAX, count_work
from tm_index_kit import RID, T0, iface, poll_data, world

from custom_components.openwrt_router import (
    net_engine,
    rf_center,
    tm_export,
    tm_query,
    tm_sources,
    tm_state,
    traffic_correlate,
)
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.core_models import CoreEvent
from custom_components.openwrt_router.net_rules import Topology, Uplink
from custom_components.openwrt_router.tm_engine import (
    GAP_MIN_S,
    async_clear_history,
    async_forget_client,
    async_remove_router,
)
from custom_components.openwrt_router.tm_export import async_export
from custom_components.openwrt_router.tm_marks import QUOTA_INFRA
from custom_components.openwrt_router.tm_sources import RouterMap
from custom_components.openwrt_router.tm_store import Segment, pack_radios

R1, R2, R3 = RID["r1"], RID["r2"], RID["r3"]
ROUTERS = RouterMap(
    {"r1": R1, "r2": R2, "r3": R3}, {R1: "Router 1", R2: "Router 2", R3: "Router 3"}
)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def tree(r3_parent: str = "r1") -> Topology:
    return Topology(
        uplinks={"r3": Uplink(r3_parent), "r2": Uplink("r1")},
        gateways=frozenset({"r1"}),
    )


def enable(w: Any) -> None:
    for entry in w.entries:
        entry.options[OPTION_TIME_MACHINE_ENABLED] = True


def poll_all(
    w: Any,
    radios: dict[str, list[dict[str, Any]]] | None = None,
    *,
    step_s: float = 60.0,
    fail: tuple[str, ...] = (),
) -> None:
    """One poll of every router (``fail``: these polls fail)."""
    radios = radios or {}
    for entry_id, coord in w.coords.items():
        if entry_id in fail:
            coord.poll(ok=False)
        else:
            coord.poll(poll_data(*radios.get(entry_id, [iface("phy1", 36)])))
    w.clock.advance(step_s)


async def snap(w: Any, now: float | None = None) -> tm_state.Snapshot:
    return await tm_state.async_snapshot(w.engine, w.clock.t if now is None else now)


def at(s: tm_state.Snapshot, rid: str, ts: float) -> dict[str, Any]:
    item, _n = tm_state.router_state(s, rid, ts, ROUTERS)
    return item


def value(part: dict[str, Any]) -> Any:
    return part["value"] if part["reason"] is None else ("?", part["reason"])


def channels(s: tm_state.Snapshot, rid: str, ts: float) -> Any:
    radios = at(s, rid, ts)["radios"]
    if radios["state"] == "unknown":
        return ("?", radios["reason"])
    return {i["key"]: (i["channel"], i["state"]) for i in radios["items"]}


def every_part_unknown(s: tm_state.Snapshot, rid: str, ts: float) -> set[str]:
    """The reasons of every part of one router (all must be unknown)."""
    item = at(s, rid, ts)
    reasons = {item[name]["reason"] for name in ("reachable", "role", "uplink")}
    assert item["radios"]["state"] == "unknown", item["radios"]
    reasons.add(item["radios"]["reason"])
    assert None not in reasons, item
    return reasons


# --- A: the wall clock jumps -----------------------------------------------------------


async def test_a_clock_jump_back_at_a_tick_leaves_the_doubled_time_unknown(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        enable(w)
        await w.start()
        w.topology = Topology(uplinks={}, gateways=frozenset({"r1"}))
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(5):
            poll_all(w, radios)
        w.engine.tick()
        before = w.clock.t
        # the wall clock goes back an hour; real (monotonic) time goes on
        w.clock.t -= 3600
        w.clock.mono += 60
        w.engine.tick()
        jumped = w.clock.t
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(80):  # past the old wall time
            poll_all(w, radios)
        [shift] = w.marks("clock_shift")
        assert shift.params == {"shift_s": -3660, "lead_s": 60}
        s = await snap(w)
        # the wall time between the jump and the old wall clock: occupied
        # twice (channel 36 before, channel 44 after) -> never a value
        for ts in (jumped + 1, jumped + 1800, before - 1, before + 30):
            assert s.global_reason(ts) == "clock_shift", ts
            assert every_part_unknown(s, R1, ts) == {"clock_shift"}
        state = await tm_state.async_state(
            w.hass, tm_state.StateQuery(jumped + 1800), admin=True, now=w.clock.t
        )
        assert (state["known"], state["unknown_reason"]) == (False, "clock_shift")
        # the time before the jump: here before the index ran (second
        # review, A: a time lived once stays known, see test_tm_review_k_v1520)
        assert s.global_reason(jumped - 600) == "not_recorded"
        # later than the doubled window: the truth (channel 44)
        late = w.clock.t - 30
        assert s.global_reason(late) is None
        assert channels(s, R1, late) == {"5g0": (44, "up")}
        assert value(at(s, R1, late)["reachable"]) is True


async def test_a_clock_jump_back_across_a_restart(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(5):
            poll_all(w, radios)
        await w.ha_stop_and_write()
        saved = w.stored["saved_at"]
        w.clock.t -= 7200  # HA comes back with a clock two hours behind
        await w.start()
        started = w.clock.t
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(150):
            poll_all(w, radios)
        [shift] = w.marks("clock_shift")
        assert shift.code == "backwards" and shift.ts == started
        s = await snap(w)
        # from the new wall clock up to the old one: occupied twice
        for ts in (started + 1, saved - 1):
            assert s.global_reason(ts) == "clock_shift", ts
        assert s.global_reason(started - 60) == "not_recorded"  # before T0
        assert s.global_reason(saved + 60) is None
        late = w.clock.t - 30
        assert channels(s, R1, late) == {"5g0": (44, "up")}


async def test_a_clock_jump_ahead_leaves_no_doubled_time(disks) -> None:
    """DECIDED: a jump ahead occupies no wall time twice; nothing unknown."""
    with world(disks, routers=1) as w:
        await w.start()
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(5):
            poll_all(w, radios)
        w.engine.tick()
        w.clock.t += 3600
        w.clock.mono += 60
        w.engine.tick()
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(5):
            poll_all(w, radios)
        [shift] = w.marks("clock_shift")
        assert shift.code == "forwards"
        s = await snap(w)
        assert s.global_reason(shift.ts + 1) is None
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}
        assert channels(s, R1, shift.ts - 3600 - 30) == {"5g0": (36, "up")}


# --- B: topology debounce across failed polls -------------------------------------------


async def test_b_uplink_candidate_failed_polls_then_confirm(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        w.topology = tree("r1")
        for _ in range(5):
            poll_all(w)
        w.topology = tree("r2")
        first = w.clock.t  # the candidate's first poll
        poll_all(w)
        # the engine holds an unconfirmed candidate: "now" is settling
        s = await snap(w)
        assert value(at(s, R3, w.clock.t - 1)["uplink"]) == ("?", "settling")
        assert value(at(s, R2, w.clock.t - 1)["uplink"])["router_id"] == R1
        for _ in range(20):  # r3's polls fail for 20 min, nothing reported
            poll_all(w, fail=("r3",))
        poll_all(w)  # confirms
        for _ in range(5):
            poll_all(w)
        [change] = [m for m in w.marks("uplink_changed") if m.router == R3]
        assert change.params["since"] == first and change.ts > first + 20 * 60
        s = await snap(w)
        for dt in (0.0, 30.0, 59.0, 600.0):
            got = value(at(s, R3, first + dt)["uplink"])
            # never the old uplink once the new one was first seen
            assert isinstance(got, tuple) or got["router_id"] == R2, (dt, got)
            if dt < 60:
                assert got == ("?", "settling"), (dt, got)
        # settling counts from the first sight, not from the confirmation
        assert value(at(s, R3, first - 120)["uplink"]) == ("?", "settling")
        assert value(at(s, R3, w.clock.t - 1)["uplink"])["router_id"] == R2


# --- C: "Verlauf löschen" and reloads while a router is down ----------------------------


async def test_c_clear_while_a_router_is_reported_down(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        since = w.clock.t
        for _ in range(3):
            poll_all(w, fail=("r2",))
        w.tracker.report_down("r2", "timeout", datetime.fromtimestamp(since, UTC))
        w.tracker._evaluate()
        poll_all(w, fail=("r2",))
        await async_clear_history(w.hass, clients_only=False)
        cleared = w.clock.t
        for _ in range(4):
            poll_all(w, fail=("r2",))
        s = await snap(w)
        assert value(at(s, R2, cleared + 30)["reachable"]) is False
        [down] = w.marks("router_down")
        assert down.ts == cleared and down.is_open and down.derived is True


async def test_c_clear_during_a_gap_keeps_the_gap(disks) -> None:
    """Polls fail (no report yet), the history is cleared, they go on failing:
    the gap reopened at the clear is not dropped as short (oracle seed 32)."""
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        for _ in range(3):
            poll_all(w, fail=("r2",))
        await async_clear_history(w.hass, clients_only=False)
        cleared = w.clock.t
        poll_all(w, step_s=GAP_MIN_S / 3, fail=("r2",))
        poll_all(w)  # back, less than GAP_MIN_S after the clear
        s = await snap(w)
        got = value(at(s, R2, cleared + 1)["reachable"])
        assert got is not True, got
        [gap] = [m for m in w.marks("observation_gap") if m.router == R2]
        assert gap.ts == cleared and not gap.is_open


async def test_c_clear_during_a_fleet_outage_keeps_lan_down(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        utc = w.clock.utc()
        w.tracker.report_down("r1", "timeout", utc)
        w.tracker.report_down("r2", "timeout", utc)
        w.tracker._evaluate()  # every router down: the LAN from HA
        assert w.marks("lan_down")
        await async_clear_history(w.hass, clients_only=False)
        cleared = w.clock.t
        for _ in range(3):
            poll_all(w, fail=("r1", "r2"))
        [lan] = w.marks("lan_down")
        assert lan.ts == cleared and lan.is_open
        s = await snap(w)
        assert value(at(s, R1, cleared + 30)["reachable"]) is False


async def test_c_reload_of_a_down_router_keeps_its_outage(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        w.down("r2")
        poll_all(w, fail=("r2",))
        w.engine.remove_entry("r2")  # the entry reloads, still down
        w.engine.add_entry("r2", w.coords["r2"])
        reloaded = w.clock.t
        for _ in range(3):
            poll_all(w, fail=("r2",))
        old, new = w.marks("router_down")
        # the outage goes on at once (its start from the fleet tracker)
        assert not old.is_open and new.is_open and new.ts <= reloaded
        s = await snap(w)
        assert value(at(s, R2, reloaded + 30)["reachable"]) is False


async def test_c_restart_while_down_and_clients_only_clear(disks) -> None:
    """Load after a restart and a clients-only clear keep the outage too."""
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        w.down("r2")
        poll_all(w, fail=("r2",))
        await async_clear_history(w.hass, clients_only=True)
        [down] = w.marks("router_down")
        assert down.is_open
        await w.ha_stop_and_write()
        w.clock.advance(120)
        await w.start()
        started = w.clock.t
        for _ in range(3):
            poll_all(w, fail=("r2",))
        s = await snap(w)
        assert value(at(s, R2, started + 30)["reachable"]) is False


# --- D: an open interval evicted while open ----------------------------------------------


async def test_d_evicted_open_outage_stays_unknown_until_its_end(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        w.engine.index.quotas = {**w.engine.index.quotas, QUOTA_INFRA: 2}
        for _ in range(3):
            poll_all(w)
        since = w.clock.t
        for _ in range(3):
            poll_all(w, fail=("r2", "r3"))
        w.tracker.report_down("r2", "timeout", datetime.fromtimestamp(since, UTC))
        w.tracker._evaluate()
        w.clock.advance(10)
        w.tracker.report_down("r3", "timeout", datetime.fromtimestamp(since + 5, UTC))
        w.tracker._evaluate()
        poll_all(w, fail=("r2", "r3"))
        radios = {"r1": [iface("phy1", 44)]}  # a third mark evicts r2's outage
        for _ in range(13):
            poll_all(w, radios, fail=("r2", "r3"))
        s = await snap(w)
        q = w.clock.t - 30
        assert value(at(s, R2, q)["reachable"]) is not True
        assert value(at(s, R3, q)["reachable"]) is not True
        assert w.engine.index.lost_open  # the evicted outage is still running
        # the saved file says the same (``lost`` up to now while it runs)
        assert w.engine.store._build()["lost"][QUOTA_INFRA] >= w.clock.t - 1
        w.up("r2")
        ended = w.clock.t
        poll_all(w, radios, fail=("r3",))
        assert not w.engine.index.lost_open
        assert w.engine.index.lost[QUOTA_INFRA] >= ended


# --- E: a radio off across a restart ------------------------------------------------------


async def test_e_radio_off_across_a_restart_is_not_ok(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        both = {"r1": [iface("phy1", 36), iface("phy0", 6, "2.4g", "HT20")]}
        for _ in range(3):
            poll_all(w, both)
        five = {"r1": [iface("phy1", 36)]}
        for _ in range(4):
            poll_all(w, five)
        s = await snap(w)
        before = at(s, R1, w.clock.t - 30)["radios"]
        assert before["state"] == "ok"
        assert {i["key"]: i["state"] for i in before["items"]} == {
            "5g0": "up",
            "2.4g0": "down",
        }
        await w.ha_stop_and_write()
        w.clock.advance(120)
        await w.start()
        for _ in range(5):
            poll_all(w, five)
        s = await snap(w)
        after = at(s, R1, w.clock.t - 30)["radios"]
        # the 2.4 GHz radio is off and not in the list: the block is partial
        assert after["state"] == "partial" and after["reason"] == "not_observed"
        assert [i["key"] for i in after["items"]] == ["5g0"]
        for _ in range(2):  # it comes back: complete again
            poll_all(w, both)
        s = await snap(w)
        assert at(s, R1, w.clock.t - 30)["radios"]["state"] == "ok"


# --- F: compare counts the timeline's window ----------------------------------------------


async def test_f_compare_counts_like_the_timeline_and_names_other_sources(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        enable(w)
        await w.start()
        for _ in range(3):
            poll_all(w)
        poll_all(w, {"r1": [iface("phy1", 44)]})
        poll_all(w, {"r1": [iface("phy1", 44)]})
        [change] = w.marks("channel_changed")
        now = w.clock.t
        t1, t2 = change.ts, now - 1
        audit = CoreEvent(
            event_id="evt_" + "1" * 32,
            ts=datetime.fromtimestamp(t1 + 10, UTC),
            type="configuration.drift_detected",
            source="config_manager",
            router_id=R1,
        )
        w.api.events = lambda **_k: [audit]
        timeline = await tm_query.async_timeline(
            w.hass,
            tm_query.Query(t1, t2, sources=(tm_sources.SOURCE_TM_INDEX,)),
            admin=True,
            now=now,
        )
        body = await tm_state.async_compare(
            w.hass, tm_state.CompareQuery(t1, t2), admin=True, now=now
        )
        marks = body["changes"]["marks"]
        # [t1, t2): the mark at t1 counts, as in the timeline from=t1
        assert marks["count"] == len(timeline["marks"]) >= 1
        other = body["changes"]["other_sources"]
        assert other == {
            "state": "ok",
            "reason": None,
            "count": 1,  # the audit entry; not in ``marks.count``
            "truncated": False,
            "unreadable": [],
        }
        # exactly the other sources' entries the timeline lists
        others = tuple(
            x
            for x in tm_sources.ALL_SOURCE_IDS
            if x not in (tm_sources.SOURCE_TM_INDEX, tm_sources.SOURCE_TM_CLIENTS)
        )
        listed = await tm_query.async_timeline(
            w.hass, tm_query.Query(t1, t2, sources=others), admin=True, now=now
        )
        assert other["count"] == len(listed["marks"]) == 1
        # the mark exactly at t2 does not count; a failing source is named
        del w.api.events
        body = await tm_state.async_compare(
            w.hass, tm_state.CompareQuery(t1 - 60, t1), admin=True, now=now
        )
        assert body["changes"]["marks"]["count"] == 0
        other = body["changes"]["other_sources"]
        assert (other["state"], other["unreadable"]) == ("unreadable", ["core_audit"])


async def test_f_other_sources_count_ni_events_without_their_doubles(
    disks, disk
) -> None:
    """The real NI writes ``router_unreachable`` / ``router_reachable`` for
    the outage the Time Machine holds itself: the timeline drops them as
    doubles, ``other_sources`` counts exactly what the timeline lists."""
    async with clients_world(disks, disk) as w:
        clock = SimpleNamespace(time=w.clock, monotonic=time.monotonic)
        w.stack.enter_context(patch.object(net_engine, "time", clock))
        w.stack.enter_context(
            patch.object(net_engine, "async_get_engine", lambda _h: w.ni)
        )
        w.api.events = lambda **_k: []
        for _ in range(3):
            step(w, [M1], [M2])
        w.down("r1")
        for _ in range(5):
            step(w, None, [M2])
        w.up("r1")
        for _ in range(3):
            step(w, [M1], [M2])
        assert "system.router_unreachable" in [e.kind for e in w.ni.ring]
        t1, t2 = T0 - 60, w.t
        everything = tuple(
            x for x in tm_sources.ALL_SOURCE_IDS if x != tm_sources.SOURCE_TM_CLIENTS
        )
        for admin in (True, False):
            listed = await tm_query.async_timeline(
                w.hass,
                tm_query.Query(t1, t2, sources=everything, no_clients=not admin),
                admin=admin,
                now=w.t,
            )
            by_id = {x["id"]: x for x in listed["sources"]}
            assert by_id["ni_events"]["duplicates"] == 2
            body = await tm_state.async_compare(
                w.hass, tm_state.CompareQuery(t1, t2), admin=admin, now=w.t
            )
            other = body["changes"]["other_sources"]
            want = [m for m in listed["marks"] if m["source"] != "tm_index"]
            assert not listed["truncated"] and other["truncated"] is False
            assert other["count"] == len(want), (admin, other, want)


# --- G: the client day cap across midnight ------------------------------------------------


async def test_g_a_capped_client_keeps_the_list_partial_past_midnight(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        midnight = (T0 // 86_400 + 1) * 86_400
        for _ in range(130):  # over the cap on the day of T0
            step(w, [M1], [])
            for _ in range(6):
                step(w, [], [])
        assert w.marks("client_flapping")
        while w.t < midnight + 1800:  # connected, no session (capped)
            step(w, [M1], [])
        s = await snap(w)
        assert s.clients_reason(midnight + 900) == ("partial", "flapping")
        assert s.clients_reason(w.t - 30) == ("partial", "flapping")


# --- H: a failing module makes its part unreadable ----------------------------------------


async def test_h_failing_traffic_and_rf_reads_make_parts_unreadable(
    disks, caplog
) -> None:
    class Broken:
        status = "ready"

        def __getattr__(self, _name: str) -> Any:
            def fail(*_a: Any, **_k: Any) -> Any:
                raise RuntimeError("secret detail rtr_9")

            return fail

    with world(disks, routers=1) as w:
        enable(w)
        await w.start()
        for _ in range(3):
            poll_all(w)
        now = w.clock.t
        caplog.set_level(logging.DEBUG)
        with (
            patch.object(
                traffic_correlate, "async_get_traffic_read_api", lambda _h: Broken()
            ),
            patch.object(rf_center, "async_get_rf_center", lambda _h: Broken()),
        ):
            body = await tm_state.async_state(
                w.hass, tm_state.StateQuery(now - 30), admin=True, now=now
            )
        assert body["status"] == "partial"
        [router] = body["routers"]
        assert router["traffic"]["state"] == "unreadable"
        assert router["utilization"]["state"] == "unreadable"
        assert router["reachable"]["value"] is True  # the rest is answered
        assert "RuntimeError" in caplog.text
        assert "secret detail" not in caplog.text


# --- I: export pages are full, blocks short -----------------------------------------------

RIDS = [f"rtr_{i:032x}" for i in range(1, 65)]


def _fill_fleet(engine: Any, now: float, routers: int, share: float = 1.0) -> None:
    """15000 marks (5000 without a client) over 13 days and ``routers`` (a
    ``share`` of them)."""
    rnd = random.Random(7)
    span = 13 * 86_400
    rids = RIDS[:routers]
    for i in range(int(3000 * share)):
        ts = now - span + rnd.random() * span
        engine.index.add(
            ts=ts,
            kind="channel_changed",
            router=rids[i % routers],
            code="channel",
            params={"band": 5, "channel_from": 36, "channel_to": 100},
        )
    for i in range(int(2000 * share)):
        ts = now - span + rnd.random() * span
        engine.index.add(
            ts=ts,
            kind="config_drift",
            router=rids[i % routers],
            code="configuration.drift_detected",
            ref=("audit", f"evt_{i:032x}"),
        )
    for i in range(int(10_000 * share)):
        ts = now - span + rnd.random() * span
        engine.index.add(
            ts=ts,
            kind="client_session",
            router=rids[i % routers],
            client=f"{i:016x}",
            end=ts + 600,
            end_state="closed",
            params={"band": 5},
        )
    radios = {"5g0": (100, 160), "2.4g0": (11, 40)}
    for n, rid in enumerate(rids):
        engine.store.seen[rid] = [
            Segment(
                start=now - span,
                end=None,
                radios_at=now - span + 1,
                radios=dict(radios),
                topo_at=now - span + 120,
                parent=rids[(n + 1) % routers],
                role="n",
            )
        ]
        engine.store.state[rid] = "a" * 16 + "|" + pack_radios(radios) + "||n"


async def _export_work(disks: Any, routers: int, share: float) -> tuple[Any, Any]:
    with world(disks) as w:
        w.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = True
        now = T0 + 14 * 86_400
        w.clock.t = now - 14 * 86_400 + 5
        engine = await w.start(clients=False)
        w.clock.t = now
        engine.clients_wanted = True
        engine.recorder = SimpleNamespace(name_of=lambda _c: None, attached=True)
        _fill_fleet(engine, now, routers, share)
        query = tm_query.Query(now - 14 * 86_400 + 60, now)
        return await count_work(
            lambda: async_export(w.hass, query, now=now, user_id="u")
        )


@pytest.mark.parametrize("routers", [1, 64])
async def test_i_export_pages_fill_and_the_loop_yields(disks, routers) -> None:
    """Counted work, not time (see ``test_tm_modules_v1520.Work``)."""
    _small, small = await _export_work(disks, routers, 0.25)
    body, work = await _export_work(disks, routers, 1.0)
    # every mark without a client fits one page (5000): none is pushed
    # out by client marks that are left out anyway
    assert len(body["marks"]) == 5000 and body["truncated"] is False
    assert body["omitted_client_marks"] == 10_000
    assert body["sources"] and len(json.dumps(body)) < 16_000_000
    print(
        f"\n[time machine] export {routers} router(s): calls {small.calls} -> "
        f"{work.calls}, longest block {small.longest} -> {work.longest} calls, "
        f"yields {small.yields} -> {work.yields}"
    )
    # the export's own loop yields every 1000 marks
    assert work.by_module[tm_export.__name__] >= len(body["marks"]) // 1000
    assert work.calls <= GROWTH_MAX * small.calls  # nothing quadratic
    assert work.longest <= BLOCK_CALLS_MAX  # no long block


# --- J: forgetting a router spoils only the routers that named it --------------------------


async def test_j_forget_router_raises_lost_for_the_peers_only(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        w.topology = tree("r1")
        for _ in range(4):
            poll_all(w)
        w.topology = tree("r2")
        for _ in range(4):
            poll_all(w)
        [change] = [m for m in w.marks("uplink_changed") if m.router == R3]
        assert R2 in change.peers
        for _ in range(3):
            poll_all(w)
        early = T0 + 90
        s = await snap(w)
        assert value(at(s, R1, early)["reachable"]) is True
        w.engine.remove_entry("r2")
        await async_remove_router(w.hass, R2)
        index = w.engine.index
        assert QUOTA_INFRA not in index.lost  # no fleet-wide loss
        assert index.lost_router[R3] >= change.ts
        s = await snap(w)
        # r1 never named r2 in a removed mark: still known before
        assert value(at(s, R1, early)["reachable"]) is True
        assert channels(s, R1, early) == {"5g0": (36, "up")}
        # r3 lost its uplink change: unknown up to it
        assert at(s, R3, early)["radios"]["reason"] == "evicted"
        assert value(at(s, R3, w.clock.t - 1)["reachable"]) is True
        # and the file keeps it (``lost_routers``, only when not empty)
        assert R3 in w.engine.store._build()["lost_routers"]


async def test_j_forget_client_lowers_past_counts_without_a_mark(disks, disk) -> None:
    """DECIDED (as requested): "Client vergessen" lowers the client counts of
    the past and nothing marks the moment as unknown or partial."""
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1, M2], [])
        past = w.t - 90
        s = await snap(w)
        assert len(s.sessions_at(past)) == 2
        await async_forget_client(w.hass, M1.lower())
        s = await snap(w)
        assert len(s.sessions_at(past)) == 1
        assert s.clients_reason(past) == ("ok", None)
        assert s.global_reason(past) is None
