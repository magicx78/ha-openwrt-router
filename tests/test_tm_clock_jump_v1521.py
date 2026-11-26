"""1.52.1: a jump back of the wall clock survives a restart and is bounded.

Review of 1.52.0 (two findings, both through the real write paths of
``tm_index_kit``: the real engine, store and fleet tracker, the answers read
as the routes read them):

* **Gap 1** (a wrong answer): the wait after a jump back (``_follow_from``)
  was rebuilt at start only from the ``clock_shift`` mark, a point mark
  pruned 14 days after it was written, while the marks of the first
  occupant of the doubled wall time are dated later and stay longer. A
  restart after that, or simply the 14 days, let them back in as known
  values.
* **Gap 2** (an unbounded "unknown"): the wait had no upper limit (a clock
  400 days ahead for a moment stopped every stretch for 400 days), and
  "Verlauf löschen" did not end it.

1.52.1: a jump back mark is kept as long as the doubled time it names is
inside the retention; the wait ends at the old wall clock or, once the
clock stayed behind it for ``CLOCK_WAIT_MAX_S`` (a day), by dropping every
mark, stretch and coverage dated after now (only the first occupant can
have written them) and recording on; the mark keeps how long its doubled
time is (``wait_s``). "Verlauf löschen" ends any wait.

The two store files in ``fixtures/`` were written by the unchanged code of
1.52.0 and 1.51.0 (``git archive v1.52.0`` / ``v1.51.0``, their own
``tm_index_kit``): one router on channel 36, the wall clock 20 days ahead
for two hours (channel 100), corrected, half an hour on channel 36, a clean
HA stop.
"""

# ruff: noqa: F811  (pytest fixture imported from test_tm_review_v1520)
from __future__ import annotations

import json
import math
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core_testkit import FakeDisks
from test_tm_oracle_review_v1520 import EXTENDED_MODES, run_extended
from test_tm_review_v1520 import (  # noqa: F401 - fixture
    R1,
    at,
    channels,
    disks,
    poll_all,
    snap,
    value,
)
from tm_index_kit import T0, iface, world

from custom_components.openwrt_router import tm_engine
from custom_components.openwrt_router.tm_engine import (
    CLOCK_WAIT_MAX_S,
    async_clear_history,
)
from custom_components.openwrt_router.tm_marks import QUOTA_INFRA, RETENTION_S

DAY = 86_400.0
HOUR = 3600.0
FIXTURES = Path(__file__).parent / "fixtures"
FIX_1520 = FIXTURES / "tm_store_v1520_clock_back.json"
FIX_1510 = FIXTURES / "tm_store_v1510_clock_back.json"


def rounds(
    w: Any,
    radios: dict[str, list[dict[str, Any]]],
    n: int,
    *,
    step_s: float = 60.0,
    tick_every: int = 1,
    fail: tuple[str, ...] = (),
) -> None:
    """``n`` poll rounds, a tick after every ``tick_every``-th."""
    for i in range(n):
        poll_all(w, radios, step_s=step_s, fail=fail)
        if i % tick_every == 0:
            w.engine.tick()


def ch(chan: int) -> dict[str, list[dict[str, Any]]]:
    return {"r1": [iface("phy1", chan)]}


def back_mark(w: Any) -> Any:
    [mark] = [m for m in w.marks("clock_shift") if m.code == "backwards"]
    return mark


def ahead_of(w: Any) -> list[Any]:
    """Marks, stretches and coverage dated after now (none may survive a
    capped wait)."""
    now = w.clock.t
    store = w.engine.store
    out: list[Any] = [m for m in w.engine.index if m.ts > now]
    out += [
        s
        for segs in store.seen.values()
        for s in segs
        if s.start > now or (s.end or 0) > now
    ]
    out += [p for p in store.coverage if p[0] > now or (p[1] or 0) > now]
    return out


async def far_ahead_then_back(w: Any, ahead_s: float, minutes: int) -> float:
    """Channel 36; the wall clock ``ahead_s`` ahead for ``minutes`` (channel
    100), then corrected (a tick sees it); returns the first wall time of
    the first occupant."""
    rounds(w, ch(36), 30)
    w.engine.tick()
    w.clock.t += ahead_s
    w.engine.tick()
    ahead = w.clock.t
    rounds(w, ch(100), minutes, tick_every=5)
    w.clock.t -= ahead_s + minutes * 60
    w.clock.mono += 60
    w.engine.tick()
    return ahead


# --- gap 1: the first occupant never comes back ------------------------------------


async def test_gap1_jump_back_20_days_then_restart_after_the_retention(disks) -> None:
    """The reviewer's scenario: 20 days ahead for two hours (36 -> 100),
    corrected; 15 days later HA restarts and runs 10 more days. The time the
    first occupant had (channel 100) is now lived again on channel 36."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 20 * DAY, 120)
        jumped = w.clock.t
        rounds(w, ch(36), 2 * 144, step_s=600)
        # the wait was capped a day after the jump: the first occupant's
        # marks (dated 20 days ahead) are gone, its doubled time is one day
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert w.engine.counters["clock_waits_capped"] == 1
        assert not [m for m in w.marks("channel_changed") if m.ts >= ahead]
        assert not ahead_of(w)
        rounds(w, ch(36), 13 * 144, step_s=600)
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from < w.clock.t
        rounds(w, ch(36), 10 * 144, step_s=600)
        s = await snap(w)
        probe = ahead + 20
        assert probe >= w.clock.t - RETENTION_S
        assert s.global_reason(probe) is None
        assert channels(s, R1, probe) == {"5g0": (36, "up")}
        assert value(at(s, R1, probe)["reachable"]) is True
        assert w.clock.t - jumped > 25 * DAY - HOUR


async def test_gap1_short_jump_back_stays_unknown_while_its_marks_are_kept(
    disks,
) -> None:
    """A jump back under the cap (six hours): the first occupant's outage
    in the doubled time outlives the 14 days of the jump mark itself; the
    doubled time must stay unknown as long as such a mark is kept."""
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 30)
        w.engine.tick()
        w.clock.t += 6 * HOUR
        w.engine.tick()
        rounds(w, ch(36), 10)
        down_at = w.clock.t
        w.down("r1")
        rounds(w, ch(36), 30, fail=("r1",))
        w.up("r1")
        rounds(w, ch(36), 20)
        w.clock.t -= 6 * HOUR  # corrected (now the real time again)
        w.clock.mono += 60
        w.engine.tick()
        [down] = w.marks("router_down")
        assert down.ts <= down_at + 60 < down.end
        # 14 days and 4 hours, the router up all the time
        rounds(w, ch(36), 14 * 144 + 24, step_s=600)
        back = back_mark(w)  # kept: its doubled time is inside the retention
        assert "wait_s" not in back.params  # under the cap: no drop
        assert w.engine.index.get(down.seq) is not None
        s = await snap(w)
        probe = down_at + 300
        assert probe >= w.clock.t - RETENTION_S
        assert back.ts < w.clock.t - RETENTION_S < probe
        assert s.global_reason(probe) == "clock_shift"
        assert value(at(s, R1, probe)["reachable"]) == ("?", "clock_shift")
        # once the whole doubled time is past the retention the mark goes
        rounds(w, ch(36), 6, step_s=600)
        assert back_mark(w) is back
        rounds(w, ch(36), 24, step_s=600)
        assert not [m for m in w.marks("clock_shift") if m.code == "backwards"]


# --- gap 2: the wait is bounded ----------------------------------------------------


async def test_gap2_far_ahead_then_back_records_again_after_a_day(disks) -> None:
    """The clock 400 days ahead for a moment (bad NTP), then corrected: one
    day unknown, then recording goes on (also after a restart)."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 400 * DAY, 1)
        jumped = w.clock.t
        assert w.engine._follow_from - jumped > 399 * DAY
        rounds(w, ch(36), 600, tick_every=5)
        assert w.engine._follow_from > w.clock.t  # still waiting (10 h)
        rounds(w, ch(44), 26 * 60 - 600, tick_every=5)
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 120
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.engine._follow_from <= w.clock.t
        assert not ahead_of(w)
        s = await snap(w)
        late = w.clock.t - 120
        assert value(at(s, R1, late)["reachable"]) is True
        assert channels(s, R1, late) == {"5g0": (44, "up")}
        # the doubled time is the first day after the jump, not 400 days
        assert s.global_reason(jumped + HOUR) == "clock_shift"
        assert s.global_reason(jumped + DAY + 300) is None
        assert max(hi for _lo, hi in s.shifts) <= jumped + DAY + 120
        # the file keeps the capped wait: a restart does not wait 400 days
        w.flush()
        [row] = [r for r in w.stored["marks"] if "|backwards|" in r]
        assert f"wait_s={back.params['wait_s']}" in row
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from < w.clock.t
        rounds(w, ch(44), 3)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}


async def test_a_jump_back_of_an_hour_still_waits_about_an_hour(disks) -> None:
    """As documented in 1.52.0: an hour back, about an hour unknown and not
    followed; nothing is dropped and the mark is unchanged."""
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 5)
        w.engine.tick()
        before = w.clock.t
        w.clock.t -= HOUR
        w.clock.mono += 60
        w.engine.tick()
        jumped = w.clock.t
        rounds(w, ch(44), 50)
        assert w.engine._follow_from > w.clock.t
        rounds(w, ch(44), 30)
        assert back_mark(w).params == {"shift_s": -3660, "lead_s": 60}
        assert w.engine.counters["clock_waits_capped"] == 0
        # the first occupant's stretch is kept, the next begins past the
        # old wall clock
        segs = w.engine.store.seen[R1]
        assert segs[0].start == T0 and segs[-1].start > before + 60
        s = await snap(w)
        [(lo, hi)] = s.shifts
        assert 3600 <= hi - jumped <= 3700 and jumped - lo <= 61
        assert s.global_reason(before - 1) == "clock_shift"
        assert s.global_reason(before + 120) is None
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}


async def test_a_jump_ahead_neither_waits_nor_drops(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 5)
        w.engine.tick()
        w.clock.t += 2 * DAY
        w.clock.mono += 60
        w.engine.tick()
        rounds(w, ch(44), 5)
        [shift] = w.marks("clock_shift")
        assert shift.code == "forwards" and "wait_s" not in shift.params
        assert w.engine._follow_from == -math.inf
        assert w.engine.counters["clock_waits_capped"] == 0
        assert w.marks("tm_started")
        s = await snap(w)
        assert s.global_reason(w.clock.t - 30) is None
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}


async def test_a_wrong_jump_back_corrected_ahead_keeps_the_history(disks) -> None:
    """The other way round: the clock was right and goes 30 days back by
    mistake, then NTP sets it ahead again within minutes. The wait ends at
    the old wall clock; nothing of the true history is dropped."""
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 10)
        rounds(w, ch(44), 20)
        w.engine.tick()
        [changed] = w.marks("channel_changed")
        w.clock.t -= 30 * DAY
        w.clock.mono += 60
        w.engine.tick()
        rounds(w, ch(44), 20)
        w.clock.t += 30 * DAY
        w.clock.mono += 60
        w.engine.tick()
        rounds(w, ch(44), 10)
        assert w.engine.index.get(changed.seq) is changed
        assert "wait_s" not in back_mark(w).params
        assert w.engine.counters["clock_waits_capped"] == 0
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        # the true history lies in the doubled time: unknown, not gone
        assert s.global_reason(changed.ts + 60) == "clock_shift"
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}


# --- restarts and "Verlauf löschen" during a wait ---------------------------------


async def test_a_restart_inside_the_wait_keeps_it_and_the_cap_counts_from_the_jump(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        rounds(w, ch(36), 60)
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from > w.clock.t + 19 * DAY  # restored
        rounds(w, ch(36), 2)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        rounds(w, ch(36), 2 * 144, step_s=600)
        back = back_mark(w)
        # a day from the jump, not from the restart (an hour later)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert back.ts == jumped
        assert not ahead_of(w)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 60)["reachable"]) is True
        assert channels(s, R1, w.clock.t - 60) == {"5g0": (36, "up")}


async def test_ha_off_across_the_cap_drops_at_the_next_start(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        rounds(w, ch(36), 30)
        await w.ha_stop_and_write()
        w.clock.advance(3 * DAY)
        await w.start()
        started = w.clock.t
        assert w.engine.counters["clock_waits_capped"] == 1
        assert not ahead_of(w)
        assert back_mark(w).params["wait_s"] == math.ceil(started - jumped)
        assert w.engine._follow_from <= started + 1
        rounds(w, ch(36), 3)
        s = await snap(w)
        assert s.global_reason(jumped + DAY) == "clock_shift"
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (36, "up")}


@pytest.mark.parametrize("ahead_s", [HOUR, 20 * DAY])
async def test_clearing_the_history_during_a_wait_ends_it(disks, ahead_s) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, ahead_s, 30)
        rounds(w, ch(36), 10)
        assert w.engine._follow_from > w.clock.t
        await async_clear_history(w.hass, clients_only=False)
        assert w.engine._follow_from == -math.inf
        assert all(v <= w.clock.t for v in w.engine.index.lost.values())
        rounds(w, ch(36), 3)
        s = await snap(w)
        assert s.global_reason(w.clock.t - 30) is None
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (36, "up")}
        w.flush()
        assert all(v <= w.clock.t for v in w.stored["lost"].values())


async def test_clearing_only_the_clients_keeps_the_wait(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 30)
        rounds(w, ch(36), 10)
        follow = w.engine._follow_from
        await async_clear_history(w.hass, clients_only=True)
        assert w.engine._follow_from == follow > w.clock.t
        rounds(w, ch(36), 3)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")


async def test_an_evicted_jump_mark_still_ends_its_wait_after_a_restart(
    disks,
) -> None:
    """A full infrastructure quota evicts the jump mark itself during the
    wait: its doubled time counts as lost (never known), and after a
    restart the wait still ends a day later."""
    with world(disks, routers=1) as w:
        await w.start()
        w.engine.index.quotas = {**w.engine.index.quotas, QUOTA_INFRA: 6}
        await far_ahead_then_back(w, 20 * DAY, 10)
        back = back_mark(w)
        for i in range(12):  # flip-flop: one channel mark per poll
            rounds(w, ch(44 if i % 2 else 36), 1)
        assert w.engine.index.get(back.seq) is None
        assert w.engine.index.lost[QUOTA_INFRA] > w.clock.t + 19 * DAY
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        w.engine.index.quotas = {**w.engine.index.quotas, QUOTA_INFRA: 6}
        assert w.engine._follow_from > w.clock.t + 19 * DAY
        rounds(w, ch(36), 2 * 144, step_s=600)
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.engine.index.lost[QUOTA_INFRA] <= w.clock.t
        assert not ahead_of(w)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 60)["reachable"]) is True


async def test_a_jump_back_no_check_saw_before_the_stop_is_found_at_start(
    disks,
) -> None:
    """Found by a stricter oracle run while fixing the two gaps (present in
    1.52.0 too): the clock goes back an hour and HA stops before a poll or
    tick sees it. The file is dated an hour before its own marks; at start
    that is a jump back like any other, so the hour lived twice is unknown
    instead of showing the first occupant's outage."""
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 30)
        down_at = w.clock.t
        w.down("r1")
        rounds(w, ch(36), 10, fail=("r1",))
        w.up("r1")
        [up] = w.marks("router_up")
        rounds(w, ch(36), 20)
        w.clock.t -= HOUR  # no poll, no tick: HA stops at once
        await w.ha_stop_and_write()
        saved = w.stored["saved_at"]
        w.clock.advance(60)
        await w.start()
        back = back_mark(w)
        assert back.ts == saved and back.params["lead_s"] == 600
        # up to the newest thing the first occupant recorded (its stretch
        # was closed at the stop, at the new wall time)
        assert back.params["shift_s"] == round(saved - up.ts)
        rounds(w, ch(36), 70)  # the hour again, the router up
        s = await snap(w)
        assert s.global_reason(down_at + 120) == "clock_shift"
        assert value(at(s, R1, down_at + 120)["reachable"]) == ("?", "clock_shift")
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True


async def test_an_outage_start_from_the_lived_twice_time_never_hides_the_gap(
    disks,
) -> None:
    """Found by the stricter oracle after the drop: the fleet tracker keeps
    an outage start it took in the other time line (a router failing then,
    its coordinator counting on across the jump). Once the clock passes that
    start, the outage took over the open gap and began there, so the
    failure between the gap and that start read as "reachable". A start
    inside the doubled wall time of a jump (all of it, the cap does not
    shorten it) is not trusted: the outage begins at the gap it takes over."""
    with world(disks, routers=1) as w:
        await w.start()
        rounds(w, ch(36), 30)
        w.clock.t -= 2 * DAY  # two days back, a tick sees it
        w.clock.mono += 60
        w.engine.tick()
        jumped = w.clock.t
        rounds(w, ch(36), 150, step_s=600)  # the cap drops a day after it
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.clock.t < jumped + 2 * DAY - HOUR
        fail_from = w.clock.t  # the next poll fails
        rounds(w, ch(36), 20, fail=("r1",))
        [gap] = w.marks("observation_gap")
        assert gap.ts == fail_from
        # the tracker's start: a wall time of the first occupant
        foreign = fail_from + 900
        w.tracker.report_down("r1", "timeout", datetime.fromtimestamp(foreign, UTC))
        w.tracker._evaluate()
        rounds(w, ch(36), 10, fail=("r1",))
        w.up("r1")
        rounds(w, ch(36), 10)
        [down] = w.marks("router_down")
        assert down.ts == fail_from and down.end_state == "closed"
        assert not w.marks("observation_gap")
        s = await snap(w)
        assert value(at(s, R1, fail_from + 300)["reachable"]) is False
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True


# --- store files of 1.52.0 and 1.51.0 ----------------------------------------------


@pytest.mark.parametrize("fixture", [FIX_1520, FIX_1510], ids=["1520", "1510"])
async def test_an_old_file_written_inside_a_wait(disks, fixture) -> None:
    """Loaded without loss (every row and stretch of the file stays), the
    wait goes on from the stored mark, the cap ends it a day after the jump
    and the first occupant's channel 100 never comes back."""
    old = json.loads(fixture.read_text())
    data = old["data"]
    [back_row] = [r for r in data["marks"] if "|backwards|" in r]
    jump_ts = int(back_row.split("|")[1]) / 1000
    shift = -int(back_row.split("shift_s=")[1].split(";")[0].split("|")[0])
    [ahead_row] = [r for r in data["marks"] if "channel_to=100" in r]
    ahead = int(ahead_row.split("|")[1]) / 1000
    with world(disks, routers=1) as w:
        w.disk.data = json.loads(json.dumps(old))
        w.clock.t = data["saved_at"] + 60
        await w.start()
        assert w.engine.index.counters["bad_marks"] == 0
        assert w.engine._follow_from == pytest.approx(jump_ts + shift + 1)
        w.flush()
        assert set(data["marks"]) <= set(w.stored["marks"])
        old_seen = data.get("seen", {})
        for rid, rows in old_seen.items():
            assert set(rows) <= set(w.stored["seen"][rid])
        rounds(w, ch(36), 2 * 144, step_s=600)
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert not [m for m in w.marks("channel_changed") if m.ts >= ahead]
        rounds(w, ch(36), 19 * 144, step_s=600)
        s = await snap(w)
        probe = ahead + 20
        assert probe >= w.clock.t - RETENTION_S
        assert channels(s, R1, probe) == {"5g0": (36, "up")}
        assert value(at(s, R1, probe)["reachable"]) is True


# --- the randomised oracle with a short cap ---------------------------------------


async def test_the_extended_oracle_with_a_short_cap(monkeypatch) -> None:
    """``test_tm_oracle_review_v1520`` with the cap at 600 s, so its jumps
    back of 3000 s end by the drop: every answer stays the truth of one of
    the time lines or unknown, and the drop really ran."""
    monkeypatch.setattr(tm_engine, "CLOCK_WAIT_MAX_S", 600.0)
    capped = Counter()
    real_end = tm_engine.TimeMachine._end_wait

    def counting(self: Any, now: float) -> None:
        capped["calls"] += 1
        real_end(self, now)

    monkeypatch.setattr(tm_engine.TimeMachine, "_end_wait", counting)
    modes = (
        "jumpback",
        "jumpback+restartany",
        EXTENDED_MODES[-1],  # everything at once, ``jumpfwd`` included
    )
    for mode in modes:
        for seed in (1, 2, 3, 4, 8, 10, 22):
            with FakeDisks().patch() as fresh:
                findings, _stats = await run_extended(fresh, mode, seed)
            assert not findings, (mode, seed, {k: len(v) for k, v in findings.items()})
    assert capped["calls"] >= 5, capped
    assert CLOCK_WAIT_MAX_S == DAY  # the shipped cap
