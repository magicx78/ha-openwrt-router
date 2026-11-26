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
inside the retention. A jump ahead while a wait runs ends the doubled time
at the clock time just before it (a boot with a wrong clock that NTP sets
right: the history before the stop is known again at once); if the clock
is still behind the old time, the rest is a new jump back. Nothing is ever
deleted because of a clock jump (owner's decision after the second review
of the PR: a forward jump and a jump back of the same size look the same
whether the line between them was ahead or the lines around it were
behind, so no rule can tell what to delete). The wait goes on up to the
old wall clock, without an upper bound; after a day of it
(``CLOCK_WAIT_LONG_S``, not counting the clock jumps) a counter and one log
line say so. "Verlauf löschen" ends any wait.

Review of the PR (P1-1 to P1-3): the boot scenarios below are the
reviewer's repros (``test_a_boot_*``); the second review's repros A, B and
C and the two cases a stricter rule would still get wrong are
``test_p1_*``.

The two store files in ``fixtures/`` were written by the unchanged code of
1.52.0 and 1.51.0 (``git archive v1.52.0`` / ``v1.51.0``, their own
``tm_index_kit``): one router on channel 36, the wall clock 20 days ahead
for two hours (channel 100), corrected, half an hour on channel 36, a clean
HA stop.
"""

# ruff: noqa: F811  (pytest fixture imported from test_tm_review_v1520)
from __future__ import annotations

import asyncio
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
    CLOCK_WAIT_LONG_S,
    async_clear_history,
)
from custom_components.openwrt_router.tm_marks import (
    END_UNKNOWN,
    QUOTA_INFRA,
    RETENTION_S,
)

DAY = 86_400.0
HOUR = 3600.0
FIXTURES = Path(__file__).parent / "fixtures"
FIX_1520 = FIXTURES / "tm_store_v1520_clock_back.json"
FIX_1510 = FIXTURES / "tm_store_v1510_clock_back.json"


async def settle(w: Any) -> None:
    """Let the engine's tasks run (the drop: the copy first, then the drop)."""
    while pending := [t for t in w.hass.tasks if not t.done()]:
        await asyncio.gather(*pending)


async def rounds(
    w: Any,
    radios: dict[str, list[dict[str, Any]]],
    n: int,
    *,
    step_s: float = 60.0,
    tick_every: int = 1,
    fail: tuple[str, ...] = (),
) -> None:
    """``n`` poll rounds, a tick after every ``tick_every``-th; the tasks the
    engine started run after each round (as in the event loop)."""
    for i in range(n):
        poll_all(w, radios, step_s=step_s, fail=fail)
        if i % tick_every == 0:
            w.engine.tick()
        await settle(w)


def ch(chan: int) -> dict[str, list[dict[str, Any]]]:
    return {"r1": [iface("phy1", chan)]}


def back_mark(w: Any) -> Any:
    [mark] = [m for m in w.marks("clock_shift") if m.code == "backwards"]
    return mark


def backs(w: Any) -> list[Any]:
    return [m for m in w.marks("clock_shift") if m.code == "backwards"]


def tick_jump(w: Any, seconds: float) -> None:
    """The wall clock jumps by ``seconds`` (a tick a minute later sees it)."""
    w.clock.t += seconds
    w.clock.mono += 60
    w.engine.tick()


async def far_ahead_then_back(w: Any, ahead_s: float, minutes: int) -> float:
    """Channel 36; the wall clock ``ahead_s`` ahead for ``minutes`` (channel
    100, a tick sees the jump ahead), then corrected (a tick sees it);
    returns the first wall time of the line ahead."""
    await rounds(w, ch(36), 30)
    w.engine.tick()
    w.clock.t += ahead_s
    w.engine.tick()
    ahead = w.clock.t
    await rounds(w, ch(100), minutes, tick_every=5)
    w.clock.t -= ahead_s + minutes * 60
    w.clock.mono += 60
    w.engine.tick()
    return ahead


async def history(w: Any) -> float:
    """Five days: channel 36, then 44 for the last two days; returns the
    wall time of the stop that follows."""
    await w.start()
    await rounds(w, ch(36), 3 * 24, step_s=HOUR)
    await rounds(w, ch(44), 2 * 24, step_s=HOUR)
    return w.clock.t


async def boot_behind(w: Any, behind_s: float) -> float:
    """HA stops cleanly, is off ten minutes and boots with the clock
    ``behind_s`` behind (no RTC); returns the real time at the boot."""
    stop = w.clock.t
    await w.ha_stop_and_write()
    real = stop + 600
    w.clock.t = real - behind_s
    w.clock.mono += 600
    await w.start()
    return real


def known(s: Any, ts: float, chan: int) -> None:
    """The router at ``ts``: known, reachable, on ``chan``."""
    assert s.global_reason(ts) is None
    assert value(at(s, R1, ts)["reachable"]) is True
    assert channels(s, R1, ts) == {"5g0": (chan, "up")}


def nothing_dropped(w: Any, before: Any = ()) -> None:
    """No ``.bak`` copy of the file was written, and every mark of
    ``before`` (seqs) is still in the index (1.52.1: a clock jump never
    deletes anything)."""
    assert w.disk.backups == 0
    missing = [seq for seq in before if w.engine.index.get(seq) is None]
    assert not missing, missing


def seqs(w: Any) -> set[int]:
    return {m.seq for m in w.engine.index}


def ntp(w: Any, real: float) -> None:
    """NTP sets the wall clock to ``real`` (a tick a minute later sees it)."""
    w.clock.t = real
    w.clock.mono += 60
    w.engine.tick()


# --- gap 1: the first occupant never comes back ------------------------------------


async def test_gap1_a_jump_back_nothing_explains_survives_the_retention(
    disks,
) -> None:
    """HA starts with the clock 20 days ahead (no jump to see), runs two
    hours on channel 100, the clock is corrected. Nothing explains the jump
    back, so nothing is dropped and the wait goes on for 20 days; a restart
    15 days later (the mark itself is older than the 14 days) must not
    forget it, and the doubled time stays unknown once lived again. 1.52.0
    pruned the mark at day 14: the restart forgot the wait and channel 100
    came back as a known value (fails with ``Mark.kept_until`` undone)."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 30)
        await w.ha_stop_and_write()
        w.clock.t += 20 * DAY
        w.clock.mono += 60
        await w.start()
        assert not w.marks("clock_shift")  # nothing saw the clock go ahead
        ahead = w.clock.t
        await rounds(w, ch(100), 120, tick_every=5)
        tick_jump(w, -(20 * DAY + 120 * 60))
        back = back_mark(w)
        await rounds(w, ch(36), 2 * 144, step_s=600)
        nothing_dropped(w)
        assert w.engine.counters["clock_waits_long"] == 1
        assert [m for m in w.marks("channel_changed") if m.ts >= ahead]
        await rounds(w, ch(36), 13 * 144, step_s=600)
        assert back.ts < w.clock.t - RETENTION_S
        assert back_mark(w) is back  # kept: its doubled time is inside
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from > w.clock.t + 4 * DAY  # not forgotten
        await rounds(w, ch(36), 6 * 144, step_s=600)  # past the old time
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        probe = ahead + 20 * 60
        assert probe >= w.clock.t - RETENTION_S
        assert s.global_reason(probe) == "clock_shift"
        assert channels(s, R1, probe) == ("?", "clock_shift")
        known(s, w.clock.t - 60, 36)


async def test_gap1_short_jump_back_stays_unknown_while_its_marks_are_kept(
    disks,
) -> None:
    """A jump back under the limit (six hours): the first occupant's outage
    in the doubled time outlives the 14 days of the jump mark itself; the
    doubled time must stay unknown as long as such a mark is kept."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 30)
        w.engine.tick()
        w.clock.t += 6 * HOUR
        w.engine.tick()
        await rounds(w, ch(36), 10)
        down_at = w.clock.t
        w.down("r1")
        await rounds(w, ch(36), 30, fail=("r1",))
        w.up("r1")
        await rounds(w, ch(36), 20)
        tick_jump(w, -6 * HOUR)  # corrected (now the real time again)
        [down] = w.marks("router_down")
        assert down.ts <= down_at + 60 < down.end
        # 14 days and 4 hours, the router up all the time
        await rounds(w, ch(36), 14 * 144 + 24, step_s=600)
        back = back_mark(w)  # kept: its doubled time is inside the retention
        assert "wait_s" not in back.params  # under the limit: no drop
        assert w.engine.index.get(down.seq) is not None
        s = await snap(w)
        probe = down_at + 300
        assert probe >= w.clock.t - RETENTION_S
        assert back.ts < w.clock.t - RETENTION_S < probe
        assert s.global_reason(probe) == "clock_shift"
        assert value(at(s, R1, probe)["reachable"]) == ("?", "clock_shift")
        # once the whole doubled time is past the retention the mark goes
        await rounds(w, ch(36), 6, step_s=600)
        assert back_mark(w) is back
        await rounds(w, ch(36), 24, step_s=600)
        assert not backs(w)


# --- a wrong clock at boot, set right later (review P1-1 to P1-3) ----------------


async def test_a_boot_far_behind_that_ntp_corrects_in_a_minute_keeps_the_history(
    disks,
) -> None:
    """P1-1: HA boots with the clock 400 days behind, NTP sets it right a
    minute later. The line behind lived one minute, 400 days ago: the
    history before the stop is known again at once, as in 1.52.0, and
    nothing is dropped."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        real = await boot_behind(w, 400 * DAY)
        back = back_mark(w)
        assert back.ts == real - 400 * DAY
        await rounds(w, ch(44), 1)
        w.clock.t = real + 120  # NTP
        w.clock.mono += 60
        w.engine.tick()
        # the doubled time is the minute behind (then pruned: 400 days old)
        assert back.params["wait_s"] <= 180
        assert not backs(w)
        assert w.engine._follow_from < w.clock.t
        await rounds(w, ch(44), 60)
        nothing_dropped(w)
        s = await snap(w)
        known(s, stop - DAY, 44)
        known(s, stop - 4 * DAY, 36)
        known(s, w.clock.t - 30, 44)
        await rounds(w, ch(44), 12 * 24, step_s=HOUR)
        s = await snap(w)
        known(s, stop - DAY, 44)


async def test_a_boot_far_behind_set_to_just_before_the_stop_drops_nothing(
    disks,
) -> None:
    """P1-2: a boot 400 days behind, then the clock is set to 30 minutes
    before the old save time. The forward step is no waited time: nothing is
    dropped on that tick; the half hour up to the old save time is a new
    jump back (lived twice), the rest of the history is known."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        before = {m.seq for m in w.engine.index}
        await boot_behind(w, 400 * DAY)
        await rounds(w, ch(44), 1)
        w.clock.t = stop - 30 * 60
        w.clock.mono += 60
        w.engine.tick()
        nothing_dropped(w)
        [back] = backs(w)  # the one of the boot is pruned (400 days old)
        assert back.ts == w.clock.t
        assert back.params == {"shift_s": -1800, "lead_s": 60}
        assert stop <= w.engine._follow_from <= stop + 1
        assert before <= {m.seq for m in w.engine.index}
        await rounds(w, ch(44), 40)
        nothing_dropped(w)
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        assert s.global_reason(stop - 10 * 60) == "clock_shift"
        known(s, stop - DAY, 44)
        known(s, stop - 4 * DAY, 36)
        known(s, w.clock.t - 30, 44)


async def test_a_boot_far_behind_without_ntp_for_a_day_drops_nothing(disks) -> None:
    """P1-3: a boot 400 days behind and no NTP for 25 hours. No jump ahead
    explains the doubled time, so the day limit drops nothing; once NTP
    sets the clock right the history before the stop is known."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        before = {m.seq for m in w.engine.index}
        segs = sum(len(v) for v in w.engine.store.seen.values())
        real = await boot_behind(w, 400 * DAY)
        await rounds(w, ch(44), 25, step_s=HOUR)
        nothing_dropped(w)
        assert w.engine.counters["clock_waits_long"] == 1
        assert before <= {m.seq for m in w.engine.index}
        assert sum(len(v) for v in w.engine.store.seen.values()) == segs
        assert w.engine._follow_from > w.clock.t  # still waiting
        w.clock.t = real + 25 * HOUR  # NTP
        w.clock.mono += 60
        w.engine.tick()
        await rounds(w, ch(44), 60)
        nothing_dropped(w)
        s = await snap(w)
        known(s, stop - DAY, 44)
        known(s, stop - 4 * DAY, 36)
        known(s, w.clock.t - 30, 44)


async def test_a_boot_two_days_behind_without_ntp_for_a_day(disks) -> None:
    """P1-3: two days behind (a stale RTC), NTP back after 25 hours.
    Nothing dropped (1.52.1 before the review dropped the last day). The 25
    hours lived twice ended inside the last stretch before the stop, whose
    replay would take their marks: the time up to the stop stays unknown,
    the history before is known."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        real = await boot_behind(w, 2 * DAY)
        await rounds(w, ch(44), 25, step_s=HOUR)
        nothing_dropped(w)
        w.clock.t = real + 25 * HOUR
        w.clock.mono += 60
        w.engine.tick()
        await rounds(w, ch(44), 60)
        s = await snap(w)
        assert s.global_reason(stop - 30 * HOUR) == "clock_shift"
        assert s.global_reason(stop - 12 * HOUR) == "clock_shift"
        known(s, stop - 3 * DAY, 36)
        known(s, w.clock.t - 30, 44)


async def test_a_wrong_jump_back_corrected_ahead_keeps_the_history(disks) -> None:
    """The clock was right and goes 30 days back by mistake while HA runs;
    NTP sets it right again 20 minutes later. The doubled time is those 20
    minutes 30 days ago: the true history is known, nothing is dropped."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 10)
        await rounds(w, ch(44), 20)
        w.engine.tick()
        [changed] = w.marks("channel_changed")
        tick_jump(w, -30 * DAY)
        await rounds(w, ch(44), 20)
        tick_jump(w, 30 * DAY)
        await rounds(w, ch(44), 10)
        assert w.engine.index.get(changed.seq) is changed
        assert not backs(w)  # 20 minutes 30 days ago: pruned
        assert w.engine._follow_from < w.clock.t
        nothing_dropped(w)
        s = await snap(w)
        known(s, changed.ts + 60, 44)
        known(s, changed.ts - 120, 36)
        known(s, w.clock.t - 30, 44)


# --- a clock ahead, then corrected: nothing is deleted ---------------------------


async def test_a_clock_ahead_then_corrected_keeps_everything_and_waits(
    disks,
) -> None:
    """The clock two days ahead for two hours (a jump ahead the engine saw:
    channel 100 is recorded, dated two days too late), then set back.

    What the user sees (1.52.1, nothing is deleted because of a clock jump):
    the history before the jump ahead stays known. The two hours the clock
    was ahead stay in the file but read "unknown (clock jump)" for the whole
    retention: their wall time is the doubled time of the jump back, which
    the true clock lives a second time two days later. From the correction
    on, nothing new is recorded until the clock is past the old time (two
    days and two hours; a counter and a log line after one day), and that
    time reads "unknown (clock jump)" too. Then recording goes on, and
    channel 100 is never shown as a known value."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        jumped = w.clock.t
        before = seqs(w)
        late = [m for m in w.engine.index if m.ts >= ahead]
        assert [m for m in late if m.kind == "channel_changed"]
        await rounds(w, ch(36), 23 * 6, step_s=600)
        assert w.engine.counters["clock_waits_long"] == 0
        await rounds(w, ch(36), 2 * 6, step_s=600)
        assert w.engine.counters["clock_waits_long"] == 1
        nothing_dropped(w, before)
        back = back_mark(w)
        assert "wait_s" not in back.params
        assert w.engine._follow_from > w.clock.t  # still waiting
        s = await snap(w)
        known(s, T0 + 10 * 60, 36)
        assert s.global_reason(jumped + HOUR) == "clock_shift"
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        await rounds(w, ch(36), 2 * 144, step_s=600)  # past the old time
        assert w.engine._follow_from < w.clock.t
        nothing_dropped(w, before)
        assert w.engine.counters["clock_waits_long"] == 1  # once per wait
        s = await snap(w)
        for t in (ahead + 60, ahead + HOUR, ahead + 2 * HOUR - 120):
            assert s.global_reason(t) == "clock_shift"
            assert channels(s, R1, t) == ("?", "clock_shift")
        assert s.global_reason(jumped + DAY) == "clock_shift"
        known(s, T0 + 10 * 60, 36)
        known(s, w.clock.t - 30, 36)
        await rounds(w, ch(36), 12 * 144, step_s=600)
        s = await snap(w)
        assert ahead + HOUR >= w.clock.t - RETENTION_S
        assert channels(s, R1, ahead + HOUR) == ("?", "clock_shift")
        nothing_dropped(w)


async def test_gap2_far_ahead_then_back_waits_up_to_the_old_time(disks) -> None:
    """The clock 400 days ahead for a moment (bad NTP), then corrected.
    Nothing is deleted, so nothing new is recorded for 400 days (no upper
    bound, 1.52.1; "Verlauf löschen" ends it, see below). A restart keeps
    the wait, and after a day a counter and one log line say so."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 400 * DAY, 1)
        jumped = w.clock.t
        before = seqs(w)
        assert w.engine._follow_from - jumped > 399 * DAY
        await rounds(w, ch(44), 26 * 60, tick_every=5)
        assert w.engine.counters["clock_waits_long"] == 1
        nothing_dropped(w, before)
        assert "wait_s" not in back_mark(w).params
        assert w.engine._follow_from - jumped > 399 * DAY
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from - jumped > 399 * DAY
        # the wait is a day old: this run counts it once, at its start
        assert w.engine.counters["clock_waits_long"] == 1
        await rounds(w, ch(44), 3)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        nothing_dropped(w, before)


async def test_a_jump_back_of_an_hour_still_waits_about_an_hour(disks) -> None:
    """As documented in 1.52.0: an hour back, about an hour unknown and not
    followed; nothing is dropped and the mark is unchanged."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 5)
        w.engine.tick()
        before = w.clock.t
        tick_jump(w, -HOUR)
        jumped = w.clock.t
        await rounds(w, ch(44), 50)
        assert w.engine._follow_from > w.clock.t
        await rounds(w, ch(44), 30)
        assert back_mark(w).params == {"shift_s": -3660, "lead_s": 60}
        nothing_dropped(w)
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
        await rounds(w, ch(36), 5)
        w.engine.tick()
        tick_jump(w, 2 * DAY)
        await rounds(w, ch(44), 5)
        [shift] = w.marks("clock_shift")
        assert shift.code == "forwards" and shift.params == {"shift_s": 2 * 86_400 - 60}
        assert w.engine._follow_from == -math.inf
        nothing_dropped(w)
        assert w.marks("tm_started")
        s = await snap(w)
        assert s.global_reason(w.clock.t - 30) is None
        assert channels(s, R1, w.clock.t - 30) == {"5g0": (44, "up")}


# --- second review of the PR: nothing is deleted (P1-1) --------------------------
#
# Before the owner's decision a jump back "explained" by a recorded jump ahead
# was dropped after a day. Each case below deleted true, correctly dated
# history that way (A, B, C: the reviewer's repros; the last two: cases a
# stricter rule would still have got wrong). Now nothing is deleted, and once
# the clock is right the history reads as known again.


async def history_with_forward_step(w: Any) -> tuple[float, float]:
    """Five days: three on channel 36, a harmless forward step of ten
    minutes (VM paused, NTP step), two on channel 44; returns (stop, step)."""
    await w.start()
    await rounds(w, ch(36), 3 * 24, step_s=HOUR)
    w.engine.tick()
    w.clock.t += 600  # the wall clock skips what the monotonic one did not
    w.engine.tick()
    step = w.clock.t
    await rounds(w, ch(44), 2 * 24, step_s=HOUR)
    return w.clock.t, step


async def three_days_then_boot_behind(w: Any) -> tuple[float, set[int]]:
    """Three days of true history (a day on channel 36, two on 44), a clean
    stop, a boot 400 days behind and no NTP for 25 hours, then NTP. Returns
    the stop and the marks before the boot."""
    await rounds(w, ch(36), 24, step_s=HOUR)
    await rounds(w, ch(44), 48, step_s=HOUR)
    stop = w.clock.t
    before = seqs(w)
    real = await boot_behind(w, 400 * DAY)
    await rounds(w, ch(44), 25, step_s=HOUR)
    assert w.engine.counters["clock_waits_long"] == 1
    nothing_dropped(w, before)
    ntp(w, real + 25 * HOUR)
    await rounds(w, ch(44), 30)
    return stop, before


def true_history_known(s: Any, stop: float) -> None:
    known(s, stop - 2 * DAY - 12 * HOUR, 36)
    known(s, stop - DAY, 44)
    known(s, stop - 60, 44)


async def test_p1_a_forward_step_then_a_boot_far_behind_deletes_nothing(
    disks,
) -> None:
    """Repro A: a ten-minute forward step two days before the stop, a boot
    400 days behind, no NTP for 25 hours, then NTP. The step does not make
    the jump back "explained": the last two days stay, and read as known."""
    with world(disks, routers=1) as w:
        stop, step = await history_with_forward_step(w)
        before = seqs(w)
        assert [m for m in w.marks("channel_changed") if m.ts >= step]
        real = await boot_behind(w, 400 * DAY)
        await rounds(w, ch(44), 25, step_s=HOUR)
        nothing_dropped(w, before)
        ntp(w, real + 25 * HOUR)
        await rounds(w, ch(44), 30)
        nothing_dropped(w, before)
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        known(s, stop - DAY, 44)
        known(s, stop - 60, 44)
        known(s, step - 2 * DAY, 36)
        known(s, w.clock.t - 30, 44)


async def test_p1_a_with_ntp_while_ha_is_off_stays_unknown_and_deletes_nothing(
    disks,
) -> None:
    """Repro A, but NTP sets the clock while HA is off (a known limit,
    documented): at the start nothing shows that the clock goes on from the
    line before the jump back, and the forward step lies in the doubled
    time, so that time is not cut. The whole history before the stop reads
    "unknown (clock jump)" for the retention; nothing is deleted, and
    recording goes on at once."""
    with world(disks, routers=1) as w:
        stop, _step = await history_with_forward_step(w)
        before = seqs(w)
        real = await boot_behind(w, 400 * DAY)
        await rounds(w, ch(44), 10)
        await w.ha_stop_and_write()
        w.clock.t = real + HOUR  # NTP, HA off
        w.clock.mono += HOUR
        await w.start()
        await rounds(w, ch(44), 10)
        nothing_dropped(w, before)
        assert "wait_s" not in back_mark(w).params
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        for t in (stop - 60, stop - DAY, stop - 4 * DAY):
            assert s.global_reason(t) == "clock_shift"
        known(s, w.clock.t - 30, 44)


async def test_p1_b_a_forward_step_then_a_wrong_jump_back_deletes_nothing(
    disks,
) -> None:
    """Repro B, in one run: a ten-minute forward step, two days later the
    clock goes 30 days back by mistake, NTP fixes it after 25 hours."""
    with world(disks, routers=1) as w:
        stop, _step = await history_with_forward_step(w)
        before = seqs(w)
        w.engine.tick()
        tick_jump(w, -30 * DAY)
        await rounds(w, ch(44), 25, step_s=HOUR)
        nothing_dropped(w, before)
        tick_jump(w, 30 * DAY)
        await rounds(w, ch(44), 30)
        nothing_dropped(w, before)
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        known(s, stop - DAY, 44)
        known(s, stop - 60, 44)
        known(s, w.clock.t - 30, 44)


async def test_p1_c_two_boots_without_a_clock_battery_delete_nothing(disks) -> None:
    """Repro C: boot 1 is 400 days behind and NTP fixes it a minute later
    (a 400-day jump ahead is recorded); three days of true history; boot 2
    is 400 days behind again, no NTP for 25 hours, then NTP."""
    with world(disks, routers=1) as w:
        await history(w)
        real = await boot_behind(w, 400 * DAY)
        await rounds(w, ch(44), 1)
        ntp(w, real + 120)
        assert [m for m in w.marks("clock_shift") if m.code == "forwards"]
        stop, before = await three_days_then_boot_behind(w)
        nothing_dropped(w, before)
        s = await snap(w)
        true_history_known(s, stop)


async def test_p1_a_first_start_with_the_clock_behind_deletes_nothing(disks) -> None:
    """A stricter rule would still fail here: the Time Machine starts for
    the first time (or is switched on) while the clock is 400 days behind;
    no jump back is ever seen, NTP a minute later records only the jump
    ahead. Then as in repro C."""
    with world(disks, routers=1) as w:
        w.clock.t = T0 - 400 * DAY
        await w.start()
        await rounds(w, ch(36), 1)
        ntp(w, T0 + 120)
        assert [m.code for m in w.marks("clock_shift")] == ["forwards"]
        stop, before = await three_days_then_boot_behind(w)
        nothing_dropped(w, before)
        s = await snap(w)
        true_history_known(s, stop)


async def test_p1_clearing_during_a_boot_behind_then_ntp_deletes_nothing(
    disks,
) -> None:
    """A stricter rule would still fail here too: a boot 400 days behind,
    "Verlauf löschen" during the wait (the jump back is gone with the rest),
    NTP a minute later records only the jump ahead. Then as in repro C."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 10)
        real = await boot_behind(w, 400 * DAY)
        await rounds(w, ch(36), 1)
        await async_clear_history(w.hass, clients_only=False)
        await settle(w)
        ntp(w, real + 120)
        assert [m.code for m in w.marks("clock_shift")] == ["forwards"]
        stop, before = await three_days_then_boot_behind(w)
        nothing_dropped(w, before)
        s = await snap(w)
        true_history_known(s, stop)


# --- jumps are not waited time ------------------------------------------------------


async def test_a_forward_step_during_a_wait_is_not_waited_time(disks) -> None:
    """The clock two days ahead for two hours, corrected (a wait of two
    days), 20 hours later a forward step of 30 minutes that does not end the
    wait. The day after which ``clock_waits_long`` counts is a day of real
    time: the step does not shorten it (fails with the shift in
    ``_jumped_ahead`` undone)."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 2 * DAY, 120)
        jumped = w.clock.t
        await rounds(w, ch(36), 20 * 6, step_s=600)
        w.engine.tick()
        tick_jump(w, 1800)
        assert "wait_s" not in back_mark(w).params  # the wait goes on
        assert w.engine._follow_from > w.clock.t
        while w.clock.t - 1800 < jumped + DAY - 900:
            await rounds(w, ch(36), 1, step_s=300)
        assert w.engine.counters["clock_waits_long"] == 0
        while w.clock.t - 1800 < jumped + DAY + 600:
            await rounds(w, ch(36), 1, step_s=300)
        assert w.engine.counters["clock_waits_long"] == 1


async def test_a_second_jump_back_during_a_wait_is_not_waited_time(disks) -> None:
    """A wait after the clock was two days ahead, ten hours later a second
    jump back of three hours: the first wait still counts a day of real
    time from its jump, not a day plus three hours (fails with the shift in
    the backward branch of ``_check_clock`` undone)."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 2 * DAY, 120)
        jumped = w.clock.t
        await rounds(w, ch(36), 10 * 6, step_s=600)
        w.engine.tick()
        tick_jump(w, -3 * HOUR)
        assert len(backs(w)) == 2
        while w.clock.t + 3 * HOUR < jumped + DAY + 600:
            await rounds(w, ch(36), 1, step_s=300)
        assert w.engine.counters["clock_waits_long"] == 1  # the first one


# --- restarts and "Verlauf löschen" during a wait ---------------------------------


async def test_a_restart_inside_the_wait_keeps_it_and_the_day_counts_from_the_jump(
    disks,
) -> None:
    """A restart an hour into the wait keeps it; the day after which the
    counter and the log line say so counts from the jump, not from the
    restart."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        before = seqs(w)
        await rounds(w, ch(36), 60)
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from > w.clock.t + 19 * DAY  # restored
        await rounds(w, ch(36), 2)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        while w.clock.t < jumped + DAY - 900:
            await rounds(w, ch(36), 1, step_s=600)
        assert w.engine.counters["clock_waits_long"] == 0
        await rounds(w, ch(36), 3, step_s=600)
        assert w.engine.counters["clock_waits_long"] == 1
        back = back_mark(w)
        assert back.ts == jumped and "wait_s" not in back.params
        assert w.engine._follow_from > w.clock.t + 18 * DAY
        nothing_dropped(w, before)


async def test_ha_off_across_the_day_keeps_the_wait_at_start(disks) -> None:
    """The clock 20 days ahead for an hour (seen), corrected, then HA off
    for three days: at the next start nothing is deleted and the wait goes
    on (17 more days); the counter says so at once."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        before = seqs(w)
        await rounds(w, ch(36), 30)
        await w.ha_stop_and_write()
        w.clock.advance(3 * DAY)
        await w.start()
        assert w.engine.counters["clock_waits_long"] == 1
        nothing_dropped(w, before)
        assert "wait_s" not in back_mark(w).params
        assert w.engine._follow_from > jumped + 20 * DAY
        await rounds(w, ch(36), 3)
        s = await snap(w)
        assert s.global_reason(jumped + DAY) == "clock_shift"
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")


async def test_ha_off_across_the_day_after_a_boot_behind_keeps_the_wait(
    disks,
) -> None:
    """Four days behind at boot, HA off for two days inside the wait: at the
    next start nothing is dropped and the wait goes on; NTP ends it."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        before = {m.seq for m in w.engine.index}
        real = await boot_behind(w, 4 * DAY)
        await rounds(w, ch(44), 10)
        await w.ha_stop_and_write()
        w.clock.advance(2 * DAY)
        await w.start()
        nothing_dropped(w)
        assert w.engine.counters["clock_waits_long"] == 1
        assert before <= {m.seq for m in w.engine.index}
        assert stop <= w.engine._follow_from <= stop + 1
        w.clock.t = real + 2 * DAY + 20 * 60  # NTP
        w.clock.mono += 60
        w.engine.tick()
        await rounds(w, ch(44), 30)
        nothing_dropped(w)
        s = await snap(w)
        known(s, stop - 12 * HOUR, 44)
        # the line behind ran (HA on or off) over the time three days ago
        assert s.global_reason(stop - 3 * DAY) == "clock_shift"
        known(s, stop - 4 * DAY - 12 * HOUR, 36)


async def test_a_boot_behind_that_ntp_corrects_while_ha_is_off_keeps_the_history(
    disks,
) -> None:
    """P1-1 across a restart: HA boots four days behind, runs ten minutes
    and stops; NTP sets the clock right while HA is off. The line behind
    wrote nothing after its last write: the doubled time ends there, or at
    the end of the stretch of the line before it that held it (its replay
    would take the marks of the line behind). The rest of the history
    before the stop is known at once and the HA gap begins at the stop, not
    four days before it."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        real = await boot_behind(w, 4 * DAY)
        behind = w.clock.t
        [held] = [
            seg.end
            for seg in w.engine.store.seen[R1]
            if seg.end is not None and seg.start < behind + 600 < seg.end
        ]
        assert held < stop - 2 * DAY
        await rounds(w, ch(44), 10)
        await w.ha_stop_and_write()
        w.clock.t = real + HOUR  # NTP, HA off
        w.clock.mono += HOUR
        await w.start()
        back = back_mark(w)
        assert back.params["wait_s"] == math.ceil(held - back.ts)
        assert w.engine._follow_from < w.clock.t
        assert not w.engine._waits
        await rounds(w, ch(44), 5)
        nothing_dropped(w)
        s = await snap(w)
        known(s, stop - DAY, 44)
        known(s, stop - 60, 44)
        known(s, held + HOUR, 36)
        assert s.global_reason(behind + 300) == "clock_shift"
        assert s.global_reason(held - HOUR) == "clock_shift"
        assert s.global_reason(stop + 300) == "ha_gap"
        [gap] = [m for m in w.marks("ha_gap") if m.ts > stop - 2 * DAY]
        assert stop <= gap.ts <= stop + 1
        known(s, w.clock.t - 30, 44)


async def test_a_wrong_jump_back_never_lends_its_values_to_the_stretch_before(
    disks,
) -> None:
    """Two days behind at boot, an hour on channel 100 (a wrong value only
    the line behind saw), then NTP. The stretch of the line before that
    holds that hour is replayed by time: the doubled time ends at its end,
    so channel 100 is never read as known after the hour either."""
    with world(disks, routers=1) as w:
        stop = await history(w)
        real = await boot_behind(w, 2 * DAY)
        behind = w.clock.t
        [held] = [
            seg.end
            for seg in w.engine.store.seen[R1]
            if seg.end is not None and seg.start < behind + HOUR < seg.end
        ]
        await rounds(w, ch(100), 60)
        w.clock.t = real + HOUR  # NTP
        w.clock.mono += 60
        w.engine.tick()
        await rounds(w, ch(44), 10)
        back = back_mark(w)
        assert back.params["wait_s"] == math.ceil(held - back.ts)
        s = await snap(w)
        for t in (behind + 2 * HOUR, behind + 6 * HOUR, held - 60):
            assert s.global_reason(t) == "clock_shift"
            assert channels(s, R1, t) != {"5g0": (100, "up")}
        known(s, held + HOUR, 44)
        known(s, stop - 60, 44)


async def test_a_clock_ahead_corrected_then_off_past_the_old_time_stays_unknown(
    disks,
) -> None:
    """The clock two days ahead for two hours (seen), corrected, then HA off
    for three days: at the start the clock is past the old wall time. The
    doubled time is never cut at the last write (the line ahead wrote in
    it), and the values the line ahead dated stay unknown, never known."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        await rounds(w, ch(36), 30)
        await w.ha_stop_and_write()
        w.clock.advance(3 * DAY)
        await w.start()
        assert "wait_s" not in back_mark(w).params
        await rounds(w, ch(36), 3)
        nothing_dropped(w)
        s = await snap(w)
        assert s.global_reason(ahead + HOUR) == "clock_shift"
        assert s.global_reason(ahead + 2 * HOUR - 120) == "clock_shift"
        known(s, w.clock.t - 30, 36)


@pytest.mark.parametrize("jump_s", [3 * DAY, 2 * DAY + HOUR], ids=["3d", "2d1h"])
async def test_a_jump_ahead_past_a_corrected_clock_ahead_never_shows_its_values(
    disks, jump_s
) -> None:
    """The clock two days ahead for two hours (seen), corrected, and an hour
    later ahead again, by more (three days) or by less (two days and an
    hour) than it went back: the jump ahead does not undo the jump back
    (``_undoes``), so the doubled time is not cut (the first line ahead
    wrote in it); its values stay unknown."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        await rounds(w, ch(36), 60)
        tick_jump(w, jump_s)
        await rounds(w, ch(44), 10)
        assert "wait_s" not in back_mark(w).params
        nothing_dropped(w)
        s = await snap(w)
        assert s.global_reason(ahead + HOUR) == "clock_shift"
        assert channels(s, R1, ahead + HOUR) != {"5g0": (100, "up")}
        known(s, w.clock.t - 30, 44)


async def test_a_clock_set_ahead_again_by_the_same_amount_is_trusted(disks) -> None:
    """A known limit (1.52.1, documented): the clock two days ahead for two
    hours (seen, channel 100), corrected, and an hour later set ahead again
    by exactly what it went back (a bad time source twice). The jump ahead
    undoes the jump back (``_undoes``), so the engine takes the clock it is
    left with as right: the doubled time is cut at the jump ahead and the
    two hours of channel 100 read as known at the wall time they were
    dated, as the values of any clock ahead that is never corrected do.
    Nothing is deleted."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        back = back_mark(w)
        before = seqs(w)
        await rounds(w, ch(36), 60)
        tick_jump(w, -back.params["shift_s"] + 60)
        await rounds(w, ch(36), 10)
        assert "wait_s" in back.params
        nothing_dropped(w, before)
        s = await snap(w)
        assert channels(s, R1, ahead + HOUR) == {"5g0": (100, "up")}
        known(s, w.clock.t - 30, 36)


@pytest.mark.parametrize("factor", [1.0, 3.0, 50.0], ids=["1x", "3x", "50x"])
async def test_a_jump_back_found_at_a_start_trusts_any_larger_jump_ahead(
    disks, factor
) -> None:
    """A known limit (1.52.1, documented), not desired behaviour: the clock
    four hours ahead while HA runs (seen), an hour on channel 100, HA stops;
    the clock is corrected while HA is off for 30 minutes, so the start
    finds a jump back (``lead_s`` 0: the time HA was off is not in it). 20
    minutes into the remaining wait the clock jumps ahead by 1, 3 or 50
    times the jump back (a bad time source again, or a host suspended longer
    than the remaining wait). For a jump back found at a start ``_undoes``
    accepts any jump ahead at least as large, so the doubled time is cut and
    channel 100, a real reading, reads as known at a date four hours too
    late. 1.52.0 showed "unknown" there. Nothing is deleted."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 60)
        w.engine.tick()
        ahead = w.clock.t + 4 * HOUR
        tick_jump(w, 4 * HOUR)
        await rounds(w, ch(100), 60)
        saved = w.clock.t
        await w.ha_stop_and_write()
        w.clock.t = saved - 4 * HOUR + 30 * 60  # corrected while HA was off
        w.clock.mono += 30 * 60
        await w.start()
        back = back_mark(w)
        assert back.params["lead_s"] == 0
        before = seqs(w)
        await rounds(w, ch(36), 20)
        w.engine.tick()
        tick_jump(w, factor * -back.params["shift_s"])
        await rounds(w, ch(36), 60)
        assert "wait_s" in back.params
        nothing_dropped(w, before)
        s = await snap(w)
        assert channels(s, R1, ahead + 30 * 60) == {"5g0": (100, "up")}
        known(s, w.clock.t - 30, 36)


@pytest.mark.parametrize("ahead_s", [HOUR, 20 * DAY])
async def test_clearing_the_history_during_a_wait_ends_it(disks, ahead_s) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, ahead_s, 30)
        await rounds(w, ch(36), 10)
        assert w.engine._follow_from > w.clock.t
        await async_clear_history(w.hass, clients_only=False)
        assert w.engine._follow_from == -math.inf
        assert all(v <= w.clock.t for v in w.engine.index.lost.values())
        await rounds(w, ch(36), 3)
        s = await snap(w)
        known(s, w.clock.t - 30, 36)
        w.flush()
        assert all(v <= w.clock.t for v in w.stored["lost"].values())


async def test_clearing_only_the_clients_keeps_the_wait(disks) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 30)
        await rounds(w, ch(36), 10)
        follow = w.engine._follow_from
        await async_clear_history(w.hass, clients_only=True)
        assert w.engine._follow_from == follow > w.clock.t
        await rounds(w, ch(36), 3)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")


async def test_an_evicted_jump_mark_keeps_its_wait_and_drops_nothing(
    disks,
) -> None:
    """A full infrastructure quota evicts the jump mark itself during the
    wait: its doubled time counts as lost (never known). Nothing can explain
    a gone mark, so nothing is dropped and the wait goes on up to the lost
    time, also after a restart."""
    with world(disks, routers=1) as w:
        await w.start()
        w.engine.index.quotas = {**w.engine.index.quotas, QUOTA_INFRA: 6}
        await far_ahead_then_back(w, 2 * DAY, 10)
        back = back_mark(w)
        for i in range(12):  # flip-flop: one channel mark per poll
            await rounds(w, ch(44 if i % 2 else 36), 1)
        assert w.engine.index.get(back.seq) is None
        lost = w.engine.index.lost[QUOTA_INFRA]
        assert lost > w.clock.t + DAY
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        w.engine.index.quotas = {**w.engine.index.quotas, QUOTA_INFRA: 6}
        assert w.engine._follow_from >= lost
        await rounds(w, ch(36), 36 * 6, step_s=600)
        nothing_dropped(w)
        assert w.engine.counters["clock_waits_long"] == 1
        assert w.engine._follow_from > w.clock.t
        await rounds(w, ch(36), 18 * 6, step_s=600)  # past the lost time
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        known(s, w.clock.t - 60, 36)


async def test_an_evicted_jump_mark_keeps_its_wait_when_a_later_one_is_cut(
    disks,
) -> None:
    """The jump mark of a clock two days ahead is evicted (its doubled time
    counts as lost), a second jump back of an hour follows, HA stops inside
    that hour and starts two hours later: the start cuts the second jump at
    the last write (``_past_at_start``), but the wait for the lost time goes
    on (fails with the floor ``_lost_ahead`` in ``_follow_until`` undone)."""
    with world(disks, routers=1) as w:
        await w.start()
        quotas = w.engine.index.quotas
        w.engine.index.quotas = {**quotas, QUOTA_INFRA: 6}
        await far_ahead_then_back(w, 2 * DAY, 10)
        first = back_mark(w)
        for i in range(12):  # flip-flop: one channel mark per poll
            await rounds(w, ch(44 if i % 2 else 36), 1)
        assert w.engine.index.get(first.seq) is None
        w.engine.index.quotas = quotas
        lost = w.engine.index.lost[QUOTA_INFRA]
        assert lost > w.clock.t + DAY
        w.engine.tick()
        tick_jump(w, -HOUR)
        await rounds(w, ch(36), 10)
        await w.ha_stop_and_write()
        w.clock.advance(2 * HOUR)
        await w.start()
        assert "wait_s" in back_mark(w).params  # the hour was cut
        assert w.engine._follow_from >= lost > w.clock.t
        await rounds(w, ch(36), 3)
        assert w.engine._follow_from >= lost > w.clock.t
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "evicted")


async def test_an_outage_open_at_a_jump_back_ends_at_the_last_check(disks) -> None:
    """A router is down when the clock goes back ten minutes: its outage ends
    at the last check before the jump, end unknown (not at the new, earlier
    wall time, where it would shrink), and a new one begins at the jump."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 30)
        w.down("r1")
        await rounds(w, ch(36), 60, fail=("r1",))
        [down] = w.marks("router_down")
        assert down.is_open
        w.engine.tick()
        last = w.clock.t
        tick_jump(w, -600)
        assert down.end == last and down.end_state == END_UNKNOWN
        await rounds(w, ch(36), 5, fail=("r1",))
        [again] = [m for m in w.marks("router_down") if m.seq != down.seq]
        assert again.is_open and again.ts < last
        s = await snap(w)
        assert value(at(s, R1, down.ts + 30 * 60)["reachable"]) is False


# --- found while fixing -----------------------------------------------------------


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
        await rounds(w, ch(36), 30)
        down_at = w.clock.t
        w.down("r1")
        await rounds(w, ch(36), 10, fail=("r1",))
        w.up("r1")
        [up] = w.marks("router_up")
        await rounds(w, ch(36), 20)
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
        await rounds(w, ch(36), 70)  # the hour again, the router up
        s = await snap(w)
        assert s.global_reason(down_at + 120) == "clock_shift"
        assert value(at(s, R1, down_at + 120)["reachable"]) == ("?", "clock_shift")
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) is True


async def test_an_unseen_jump_back_ends_at_the_newest_mark_of_any_quota(
    disks,
) -> None:
    """Review P2-1: the unseen jump at start is found from the
    infrastructure (Client Stability may date a client mark up to a day
    ahead), but its doubled time ends at the newest mark of any quota: a
    client mark the first occupant dated after its last infrastructure mark
    stays inside the unknown time."""
    with world(disks, routers=1) as w:
        await w.start()
        await rounds(w, ch(36), 30)
        w.down("r1")
        await rounds(w, ch(36), 10, fail=("r1",))
        w.up("r1")
        [up] = w.marks("router_up")
        await rounds(w, ch(36), 5)
        late = up.ts + 40 * 60
        mark = w.engine.index.add(
            ts=late,
            kind="client_disconnect",
            router=R1,
            client="0123456789abcdef",
            code="left",
            params={"timed": True},
        )
        assert mark is not None and mark.quota != QUOTA_INFRA
        w.clock.t -= HOUR
        await w.ha_stop_and_write()
        saved = w.stored["saved_at"]
        w.clock.advance(60)
        await w.start()
        back = back_mark(w)
        assert back.params["shift_s"] == round(saved - late)
        s = await snap(w)
        assert s.global_reason(late - 1) == "clock_shift"


async def test_an_outage_start_from_the_lived_twice_time_never_hides_the_gap(
    disks,
) -> None:
    """Found by the stricter oracle while fixing: the fleet tracker keeps
    an outage start it took in the other time line (a router failing then,
    its coordinator counting on across the jump). Once the clock passes that
    start, the outage took over the open gap and began there, so the
    failure between the gap and that start read as "reachable". A start
    inside the doubled wall time of a jump (all of it, a cut ``wait_s``
    does not shorten it) is not trusted: the outage begins at the gap it
    takes over. Here the failure starts when the wait is over."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 2 * DAY, 10)
        jumped = w.clock.t
        back = back_mark(w)
        # a cut doubled time (as a jump ahead or a restart past it writes)
        w.engine.index.set_param(back.seq, "wait_s", round(DAY))
        w.engine._follow_from = w.engine._follow_until()
        await rounds(w, ch(36), 150, step_s=600)
        assert w.engine._follow_from < w.clock.t < jumped + 2 * DAY - HOUR
        fail_from = w.clock.t  # the next poll fails
        await rounds(w, ch(36), 20, fail=("r1",))
        [gap] = w.marks("observation_gap")
        assert gap.ts == fail_from
        # the tracker's start: a wall time of the first occupant
        foreign = fail_from + 900
        w.tracker.report_down("r1", "timeout", datetime.fromtimestamp(foreign, UTC))
        w.tracker._evaluate()
        await rounds(w, ch(36), 10, fail=("r1",))
        w.up("r1")
        await rounds(w, ch(36), 10)
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
    wait goes on from the stored mark up to the old wall clock (20 days);
    nothing is deleted, and the first occupant's channel 100 never comes
    back as a known value."""
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
        before = seqs(w)
        await rounds(w, ch(36), 2 * 144, step_s=600)
        assert "wait_s" not in back_mark(w).params
        assert w.engine._follow_from > w.clock.t
        nothing_dropped(w, before)
        await rounds(w, ch(36), 19 * 144, step_s=600)
        assert w.engine._follow_from < w.clock.t
        nothing_dropped(w)
        s = await snap(w)
        probe = ahead + 20
        assert probe >= w.clock.t - RETENTION_S
        assert s.global_reason(probe) == "clock_shift"
        assert channels(s, R1, probe) == ("?", "clock_shift")
        known(s, w.clock.t - 60, 36)


# --- the randomised oracle with a short limit -------------------------------------


async def test_the_extended_oracle_with_a_short_day(monkeypatch) -> None:
    """``test_tm_oracle_review_v1520`` with the day at 600 s, so its jumps
    back of 3000 s reach it: every answer stays the truth of one of the time
    lines or unknown, the long wait was counted, and no run wrote a
    ``.bak`` copy or deleted a mark because of a clock jump."""
    monkeypatch.setattr(tm_engine, "CLOCK_WAIT_LONG_S", 600.0)
    counted = Counter()
    real_check = tm_engine.TimeMachine._check_wait

    def checking(self: Any, now: float) -> None:
        before = self.counters["clock_waits_long"]
        real_check(self, now)
        counted["long"] += self.counters["clock_waits_long"] - before

    monkeypatch.setattr(tm_engine.TimeMachine, "_check_wait", checking)
    modes = (
        "jumpback",
        "jumpback+restartany",
        EXTENDED_MODES[-1],  # everything at once, ``jumpfwd`` included
    )
    runs = [(mode, seed) for mode in modes for seed in (1, 2, 3, 4, 8, 10, 22)]
    # a jump ahead, then back before where it went (dropped before the
    # second review of the PR, kept now)
    runs += [
        ("jumpback+jumpfwd", 6),
        ("jumpback+jumpfwd", 44),
        ("jumpback+jumpfwd+restartany", 20),
        ("radiooff+restartany+jumpback+jumpfwd+eval", 15),
        ("radiooff+restartany+jumpback+jumpfwd+eval", 55),
        # found with the jump-ahead shortening (a stretch across a jump
        # ahead, an old line's gap closed by the new one), fixed
        ("jumpback+jumpfwd", 23),
        ("radiooff+restartany+jumpback+jumpfwd+eval", 6),
    ]
    for mode, seed in runs:
        with FakeDisks().patch() as fresh:
            findings, _stats = await run_extended(fresh, mode, seed)
            assert not sum(d.backups for d in fresh.disks.values()), (mode, seed)
        assert not findings, (mode, seed, {k: len(v) for k, v in findings.items()})
    assert counted["long"] >= 5, counted
    assert CLOCK_WAIT_LONG_S == DAY  # the shipped day
