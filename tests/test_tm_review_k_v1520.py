"""1.52.0 second review of the Time Machine backend: K, E, L, G and A.

K  a LAN outage starts when the last router failed, not at the first single
   outage (also for a backdated mark of 1.51.0);
E  "Verlauf löschen" keeps the radios off it deletes the marks of;
L  after a restart a router is reachable only from its first successful poll;
G  a capped client that is gone ends the partial client list;
A  a jump back of the wall clock leaves only the doubly occupied time unknown.

Every test runs the real write paths (``tm_index_kit``) and fails without
its fix; the answers are read as the routes read them.
"""

# ruff: noqa: F811  (pytest fixtures imported from other test modules)
from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_client_engine import M1, M2, disk  # noqa: F401 - fixture
from test_tm_clients_v1510 import clients_world, step
from test_tm_review_v1520 import (  # noqa: F401 - fixture
    R1,
    R2,
    R3,
    at,
    disks,
    poll_all,
    snap,
    value,
)
from tm_index_kit import T0, iface, world

from custom_components.openwrt_router import net_engine, tm_query, tm_sources
from custom_components.openwrt_router.tm_engine import async_clear_history
from custom_components.openwrt_router.tm_marks import END_OPEN

# --- K: a LAN outage starts when the last router failed ----------------------------------


async def _staggered_fleet_outage(w: Any) -> tuple[float, float]:
    """r2 fails 30 min before r1 and r3 (then all three are down)."""
    await w.start()
    for _ in range(3):
        poll_all(w)
    r2_down = w.clock.t
    w.down("r2")
    for _ in range(30):  # r1 and r3 answer every poll
        poll_all(w, fail=("r2",))
    all_down = w.clock.t
    w.down("r1")
    w.down("r3")
    for _ in range(5):
        poll_all(w, fail=("r1", "r2", "r3"))
    return r2_down, all_down


def _reach(s: Any, ts: float) -> dict[str, Any]:
    return {rid: value(at(s, rid, ts)["reachable"]) for rid in (R1, R2, R3)}


async def test_k_lan_outage_starts_when_the_last_router_failed(disks) -> None:
    with world(disks, routers=3) as w:
        r2_down, all_down = await _staggered_fleet_outage(w)
        [lan] = w.marks("lan_down")
        assert (lan.ts, lan.is_open, lan.derived) == (all_down, True, False)
        # r2's own outage stays its own interval
        assert [m.ts for m in w.marks("router_down") if m.router == R2] == [r2_down]
        s = await snap(w)
        # r1 and r3 answered every poll while only r2 was down
        assert _reach(s, r2_down + 600) == {R1: True, R2: False, R3: True}
        assert _reach(s, all_down + 120) == {R1: False, R2: False, R3: False}
        assert at(s, R3, all_down + 120)["radios"]["reason"] == "lan_down"
        assert at(s, R3, all_down - 30)["radios"]["state"] == "ok"


async def test_k_a_backdated_1510_lan_mark_covers_each_router_from_its_failure(
    disks,
) -> None:
    """1.51.0 dated ``lan_down`` back to the first single outage; such a
    stored mark covers a router only from its own first failed poll."""
    with world(disks, routers=3) as w:
        r2_down, all_down = await _staggered_fleet_outage(w)
        index = w.engine.index
        [lan] = w.marks("lan_down")
        index.remove_where(lambda m: m.seq != lan.seq)
        old = index.add(
            ts=r2_down,
            kind="lan_down",
            router=None,
            severity="critical",
            code="lan_unreachable",
            end_state=END_OPEN,
        )
        w.engine._lan_seq = old.seq
        s = await snap(w)
        assert _reach(s, r2_down + 600) == {R1: True, R2: False, R3: True}
        assert _reach(s, all_down - 30) == {R1: True, R2: False, R3: True}
        assert _reach(s, all_down + 120) == {R1: False, R2: False, R3: False}


async def test_k_ni_lan_events_stay_doubles_of_the_later_lan_mark(disks, disk) -> None:
    """The NI writes ``lan_unreachable`` when the fleet outage begins; the
    own ``lan_down`` (now from the last failure) still holds it."""
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
        for _ in range(20):
            step(w, None, [M2])
        w.down("r2")
        for _ in range(5):
            step(w, None, None)
        w.up("r2")
        w.up("r1")
        for _ in range(3):
            step(w, [M1], [M2])
        kinds = [e.kind for e in w.ni.ring]
        assert "system.lan_unreachable" in kinds, kinds
        [lan] = w.marks("lan_down")
        assert lan.ts == T0 + 23 * 60  # when r2 failed, not when r1 did
        everything = tuple(
            x for x in tm_sources.ALL_SOURCE_IDS if x != tm_sources.SOURCE_TM_CLIENTS
        )
        listed = await tm_query.async_timeline(
            w.hass,
            tm_query.Query(T0 - 60, w.t, sources=everything),
            admin=True,
            now=w.t,
        )
        ni = [m["kind"] for m in listed["marks"] if m["source"] == "ni_events"]
        assert not [k for k in ni if k.startswith("lan_")], ni
        own = [m["kind"] for m in listed["marks"] if m["source"] == "tm_index"]
        assert own.count("lan_down") == 1 and own.count("lan_up") == 1, own


async def test_k_a_router_reported_before_the_lan_outage_ends_its_outage(
    disks,
) -> None:
    """The fleet issue takes the single reports over: a router that comes
    back after the LAN outage fires no event of the tracker. Its own outage
    ends at its first successful poll all the same."""
    with world(disks, routers=3) as w:
        r2_down, _all_down = await _staggered_fleet_outage(w)
        w.up("r1")  # the LAN outage ends
        for _ in range(2):
            poll_all(w, fail=("r2", "r3"))
        w.up("r3")
        w.up("r2")  # no event: neither is reported any more
        back = w.clock.t
        for _ in range(3):
            poll_all(w)
        [down] = [m for m in w.marks("router_down") if m.router == R2]
        assert (down.ts, down.end_state, down.end) == (r2_down, "closed", back)
        s = await snap(w)
        assert _reach(s, w.clock.t - 30) == {R1: True, R2: True, R3: True}
        assert _reach(s, back - 30)[R2] is False


# --- E: "Verlauf löschen" while a radio is off ----------------------------------------------

BOTH = {"r1": [iface("phy1", 36), iface("phy0", 6, "2.4g", "HT20")]}
FIVE = {"r1": [iface("phy1", 36)]}


async def _radio_off_then(w: Any, how: str) -> None:
    await w.start()
    for _ in range(3):
        poll_all(w, BOTH)
    for _ in range(3):
        poll_all(w, FIVE)  # 2.4 GHz off: an open radio_down
    assert w.marks("radio_down")
    if how == "clear":
        await async_clear_history(w.hass, clients_only=False)
    elif how == "clients":
        await async_clear_history(w.hass, clients_only=True)
    elif how == "restart":
        await w.ha_stop_and_write()
        w.clock.advance(120)
        await w.start()
    else:
        w.engine.remove_entry("r1")
        w.engine.add_entry("r1", w.coords["r1"])
    for _ in range(4):
        poll_all(w, FIVE)


@pytest.mark.parametrize("how", ["clear", "clients", "restart", "reload"])
async def test_e_a_radio_off_stays_noted_across_clear_restart_and_reload(
    disks, how
) -> None:
    with world(disks, routers=1) as w:
        await _radio_off_then(w, how)
        s = await snap(w)
        radios = at(s, R1, w.clock.t - 30)["radios"]
        if how == "clients":  # the radio_down mark itself is still there
            assert radios["state"] == "ok"
            assert {i["key"]: i["state"] for i in radios["items"]} == {
                "5g0": "up",
                "2.4g0": "down",
            }
        else:  # the 2.4 GHz radio is off and not in the list
            assert (radios["state"], radios["reason"]) == ("partial", "not_observed")
            assert [i["key"] for i in radios["items"]] == ["5g0"]
        for _ in range(2):  # it comes back: complete again
            poll_all(w, BOTH)
        s = await snap(w)
        assert at(s, R1, w.clock.t - 30)["radios"]["state"] == "ok"


# --- L: a gap across a restart -------------------------------------------------------------


@pytest.mark.parametrize("failed_before", [True, False])
async def test_l_after_a_restart_a_router_is_reachable_from_its_first_good_poll(
    disks, failed_before
) -> None:
    """A router failing before the restart (not reported) or not: after the
    restart its first poll fails and the next one 40 s later answers. Until
    that answer its state is unknown, never "reachable"."""
    with world(disks, routers=2) as w:
        await w.start()
        for _ in range(3):
            poll_all(w)
        last_ok = w.clock.t - 60
        if failed_before:
            poll_all(w, fail=("r2",))
        await w.ha_stop_and_write()
        stopped = w.stored["saved_at"]
        w.clock.advance(45)
        await w.start()
        started = w.clock.t
        w.clock.advance(5)
        poll_all(w, fail=("r2",), step_s=40)
        failed = started + 5
        answered = w.clock.t
        for _ in range(3):
            poll_all(w)
        s = await snap(w)
        r2 = [value(at(s, R2, ts)["reachable"]) for ts in (failed, answered - 1)]
        assert True not in r2, r2
        assert [x[1] for x in r2] == ["observation_gap"] * 2
        assert value(at(s, R2, answered + 1)["reachable"]) is True
        assert value(at(s, R1, answered - 1)["reachable"]) is True
        # before the restart: unknown from the failed poll on, the HA gap after
        if failed_before:
            assert value(at(s, R2, last_ok + 61)["reachable"]) == (
                "?",
                "observation_gap",
            )
        assert value(at(s, R2, stopped + 1)["reachable"]) == ("?", "ha_gap")


# --- G: a capped client that is gone ---------------------------------------------------------


async def test_g_a_capped_client_that_is_gone_ends_the_partial_list(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(130):  # over the day cap, the last capped mark an end
            step(w, [M1], [])
            for _ in range(6):
                step(w, [], [])
        [flap] = w.marks("client_flapping")
        assert flap.params["gone"] == 1
        flapped = flap.end
        for i in range(25 * 60):  # M1 gone for good, M2 comes and goes
            step(w, [M2] if (i // 120) % 2 == 0 else [], [])
        s = await snap(w)
        assert s.clients_reason(flapped) == ("partial", "flapping")
        for hours in (1, 6, 24):
            assert s.clients_reason(flapped + hours * 3600) == ("ok", None), hours


async def test_g_a_capped_client_still_there_ends_at_its_disconnect(
    disks, disk
) -> None:
    """The last capped mark is a session start: the list stays partial until
    the recorder sees the client go (here after midnight, not capped)."""
    async with clients_world(disks, disk) as w:
        midnight = (T0 // 86_400 + 1) * 86_400
        for _ in range(130):
            step(w, [M1], [])
            for _ in range(6):
                step(w, [], [])
        while w.t < midnight + 1800:  # connected, no session (capped)
            step(w, [M1], [])
        [flap] = w.marks("client_flapping")
        assert "gone" not in flap.params
        for _ in range(30):
            step(w, [], [])
        [gone] = [m for m in w.marks("client_disconnect") if m.ts > midnight]
        for _ in range(6 * 60):
            step(w, [], [])
        s = await snap(w)
        assert s.clients_reason(midnight + 900) == ("partial", "flapping")
        assert s.clients_reason(gone.ts - 1) == ("partial", "flapping")
        for hours in (1, 6):
            assert s.clients_reason(gone.ts + hours * 3600) == ("ok", None), hours


# --- A: a jump back of the wall clock ------------------------------------------------------


def _channels(s: Any, ts: float) -> Any:
    radios = at(s, R1, ts)["radios"]
    if radios["state"] == "unknown":
        return ("?", radios["reason"])
    return {i["key"]: (i["channel"], i["state"]) for i in radios["items"]}


def _all_unknown(s: Any, ts: float) -> set[str]:
    item = at(s, R1, ts)
    reasons = {item[name]["reason"] for name in ("reachable", "role", "uplink")}
    reasons.add(
        item["radios"]["reason"] if item["radios"]["state"] == "unknown" else None
    )
    return reasons


async def test_a_a_jump_back_at_a_poll_keeps_the_time_before_it_known(disks) -> None:
    """Only the doubly occupied wall time is unknown: what lies before the
    new wall clock was seen once (channel 36) and stays known; after the
    old wall clock the second occupant (channel 44) holds."""
    with world(disks, routers=1) as w:
        await w.start()
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(90):
            poll_all(w, radios)
        w.engine.tick()
        before = w.clock.t
        w.clock.t -= 3600  # the wall clock goes back an hour, real time on
        w.clock.mono += 60
        jumped = w.clock.t
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(80):  # past the old wall clock
            poll_all(w, radios)
        [shift] = w.marks("clock_shift")
        assert (shift.ts, shift.code) == (jumped, "backwards")
        assert shift.params == {"shift_s": -3660, "lead_s": 60}
        s = await snap(w)
        for ts in (jumped - 62, jumped - 600, jumped - 1500):
            assert s.global_reason(ts) is None, ts
            assert _channels(s, ts) == {"5g0": (36, "up")}, ts
            assert value(at(s, R1, ts)["reachable"]) is True, ts
        for ts in (jumped + 1, jumped + 1800, before - 1, before + 30):
            assert _all_unknown(s, ts) == {"clock_shift"}, ts
        late = w.clock.t - 30
        assert s.global_reason(late) is None
        assert _channels(s, late) == {"5g0": (44, "up")}
        assert value(at(s, R1, late)["reachable"]) is True


async def test_a_a_jump_back_across_a_restart_keeps_the_time_before_it_known(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(60):
            poll_all(w, radios)
        await w.ha_stop_and_write()
        saved = w.stored["saved_at"]
        w.clock.t -= 1800  # HA comes back with its clock half an hour behind
        await w.start()
        started = w.clock.t
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(40):  # 2400 s: past the old wall clock
            poll_all(w, radios)
        [shift] = w.marks("clock_shift")
        assert shift.ts == started
        assert shift.params == {"shift_s": round(started - saved), "lead_s": 0}
        s = await snap(w)
        for ts in (started - 60, started - 1200):
            assert s.global_reason(ts) is None, ts
            assert _channels(s, ts) == {"5g0": (36, "up")}, ts
            assert value(at(s, R1, ts)["reachable"]) is True, ts
        for ts in (started + 1, saved - 1):
            assert _all_unknown(s, ts) == {"clock_shift"}, ts
        late = w.clock.t - 30
        assert _channels(s, late) == {"5g0": (44, "up")}
        assert value(at(s, R1, late)["reachable"]) is True


async def test_a_a_failed_stretch_before_a_jump_back_stays_a_gap(disks) -> None:
    """The router fails for 7 polls (420 s), the wall clock goes back 310 s,
    the next poll answers 110 wall seconds after the first failure: the gap
    is no short one (it lasted 450 s) and is kept, so the time before the
    doubled wall time is never "reachable"."""
    with world(disks, routers=1) as w:
        await w.start()
        for _ in range(30):
            poll_all(w)
        w.engine.tick()
        failed = w.clock.t
        for _ in range(7):
            poll_all(w, fail=("r1",))
        w.clock.t -= 310
        for _ in range(20):
            poll_all(w)
        [gap] = w.marks("observation_gap")
        assert gap.ts == failed and gap.end is not None and gap.end >= gap.ts
        assert gap.params["gap_s"] >= 0
        s = await snap(w)
        # the doubled time begins at most ``lead_s`` (60 s, and 1 s for the
        # rounding) before the poll that saw the jump (failed + 110)
        assert value(at(s, R1, failed + 30)["reachable"]) == ("?", "observation_gap")
        assert value(at(s, R1, failed + 51)["reachable"]) == ("?", "clock_shift")
        assert value(at(s, R1, failed - 30)["reachable"]) is True
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True


async def test_a_a_restart_inside_the_doubled_time_still_waits_for_the_old_clock(
    disks,
) -> None:
    """A jump back, then a restart before the wall clock is past the old one
    (no jump against ``saved_at``): the marks of the first occupant there
    must not enter the new stretch either (channel 100 at the old time)."""
    with world(disks, routers=1) as w:
        await w.start()
        radios = {"r1": [iface("phy1", 36)]}
        for _ in range(60):
            poll_all(w, radios)
        radios["r1"] = [iface("phy1", 100)]  # a change shortly before the jump
        for _ in range(5):
            poll_all(w, radios)
        old_wall = w.clock.t
        w.clock.t -= 1800
        radios["r1"] = [iface("phy1", 36)]
        for _ in range(5):
            poll_all(w, radios)
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        radios["r1"] = [iface("phy1", 44)]
        for _ in range(40):
            poll_all(w, radios)
        assert w.clock.t > old_wall + 600
        s = await snap(w)
        late = w.clock.t - 30
        assert _channels(s, late) == {"5g0": (44, "up")}
        assert _all_unknown(s, old_wall - 120) == {"clock_shift"}
