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
is still behind the old time, the rest is a new jump back. After a day of
waiting (``CLOCK_WAIT_MAX_S``, not counting the clock jumps) the engine
drops only what a recorded jump ahead explains: the clock was ahead and was
set back, so what the line ahead dated after now goes, after a ``.bak`` copy
of the file. Without such a jump nothing is dropped and the wait goes on up
to the old wall clock. "Verlauf löschen" ends any wait.

Review of the PR (P1-1 to P1-3): the boot scenarios below are the
reviewer's repros (``test_a_boot_*``).

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
    CLOCK_WAIT_MAX_S,
    async_clear_history,
)
from custom_components.openwrt_router.tm_marks import QUOTA_INFRA, RETENTION_S

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


def ahead_of(w: Any) -> list[Any]:
    """Marks, stretches and coverage dated after now (none may survive a
    drop at now)."""
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


def nothing_dropped(w: Any) -> None:
    c = w.engine.counters
    assert c["clock_waits_capped"] == 0
    assert w.engine.store.counters["backups"] == 0 and w.disk.backups == 0


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
        assert w.engine.counters["clock_waits_unexplained"] == 1
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
        assert w.engine.counters["clock_waits_unexplained"] == 1
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


# --- a clock ahead, then corrected: dropped after a day --------------------------


async def test_a_clock_ahead_then_corrected_drops_only_what_it_dated(disks) -> None:
    """The clock two days ahead for two hours (a jump ahead the engine saw:
    channel 100), then set back. For a day nothing is dropped; then exactly
    what the line ahead dated goes, after one ``.bak`` copy of the file;
    the history before the jump ahead stays."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        jumped = w.clock.t
        early = [m.seq for m in w.engine.index if m.ts < ahead]
        late = [m for m in w.engine.index if m.ts >= ahead]
        assert [m for m in late if m.kind == "channel_changed"]
        await rounds(w, ch(36), 23 * 6, step_s=600)
        nothing_dropped(w)
        await rounds(w, ch(36), 2 * 6, step_s=600)
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.engine.store.counters["backups"] == 1 and w.disk.backups == 1
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert all(w.engine.index.get(m.seq) is None for m in late)
        assert all(w.engine.index.get(seq) is not None for seq in early)
        assert not ahead_of(w)
        await rounds(w, ch(36), 3)
        s = await snap(w)
        known(s, T0 + 10 * 60, 36)
        assert s.global_reason(jumped + HOUR) == "clock_shift"
        known(s, w.clock.t - 30, 36)
        await rounds(w, ch(36), 2 * 144, step_s=600)  # past the old time
        assert w.engine.store.counters["backups"] == 1  # one copy, once
        s = await snap(w)
        known(s, ahead + HOUR, 36)  # the true day, no channel 100


async def test_gap2_far_ahead_then_back_records_again_after_a_day(disks) -> None:
    """The clock 400 days ahead for a moment (bad NTP), then corrected: one
    day unknown, then recording goes on (also after a restart)."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 400 * DAY, 1)
        jumped = w.clock.t
        assert w.engine._follow_from - jumped > 399 * DAY
        await rounds(w, ch(36), 600, tick_every=5)
        assert w.engine._follow_from > w.clock.t  # still waiting (10 h)
        await rounds(w, ch(44), 26 * 60 - 600, tick_every=5)
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 120
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.disk.backups == 1
        assert w.engine._follow_from <= w.clock.t
        assert not ahead_of(w)
        s = await snap(w)
        known(s, w.clock.t - 120, 44)
        # the doubled time is the first day after the jump, not 400 days
        assert s.global_reason(jumped + HOUR) == "clock_shift"
        assert s.global_reason(jumped + DAY + 300) is None
        assert max(hi for _lo, hi in s.shifts) <= jumped + DAY + 120
        # the file keeps the decided wait: a restart does not wait 400 days
        w.flush()
        [row] = [r for r in w.stored["marks"] if "|backwards|" in r]
        assert f"wait_s={back.params['wait_s']}" in row
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from < w.clock.t
        await rounds(w, ch(44), 3)
        s = await snap(w)
        known(s, w.clock.t - 30, 44)


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


# --- restarts and "Verlauf löschen" during a wait ---------------------------------


async def test_a_restart_inside_the_wait_keeps_it_and_the_limit_counts_from_the_jump(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        await rounds(w, ch(36), 60)
        await w.ha_stop_and_write()
        w.clock.advance(60)
        await w.start()
        assert w.engine._follow_from > w.clock.t + 19 * DAY  # restored
        await rounds(w, ch(36), 2)
        s = await snap(w)
        assert value(at(s, R1, w.clock.t - 30)["reachable"]) == ("?", "clock_shift")
        await rounds(w, ch(36), 2 * 144, step_s=600)
        back = back_mark(w)
        # a day from the jump, not from the restart (an hour later)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert back.ts == jumped
        assert w.disk.backups == 1
        assert not ahead_of(w)
        s = await snap(w)
        known(s, w.clock.t - 60, 36)


async def test_ha_off_across_the_limit_drops_an_explained_jump_at_start(
    disks,
) -> None:
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 20 * DAY, 60)
        jumped = w.clock.t
        await rounds(w, ch(36), 30)
        await w.ha_stop_and_write()
        w.clock.advance(3 * DAY)
        await w.start()
        started = w.clock.t
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.disk.backups == 1
        assert not ahead_of(w)
        assert back_mark(w).params["wait_s"] == math.ceil(started - jumped)
        assert w.engine._follow_from <= started + 1
        await rounds(w, ch(36), 3)
        s = await snap(w)
        assert s.global_reason(jumped + DAY) == "clock_shift"
        known(s, w.clock.t - 30, 36)


async def test_ha_off_across_the_limit_drops_nothing_unexplained(disks) -> None:
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
        assert w.engine.counters["clock_waits_unexplained"] == 1
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


async def test_a_jump_ahead_past_a_corrected_clock_ahead_never_shows_its_values(
    disks,
) -> None:
    """The clock two days ahead for two hours (seen), corrected, and an hour
    later three days ahead again: the doubled time is not cut at the jump
    ahead (the first line ahead wrote in it); its values stay unknown."""
    with world(disks, routers=1) as w:
        await w.start()
        ahead = await far_ahead_then_back(w, 2 * DAY, 120)
        await rounds(w, ch(36), 60)
        tick_jump(w, 3 * DAY)
        await rounds(w, ch(44), 10)
        assert "wait_s" not in back_mark(w).params
        nothing_dropped(w)
        s = await snap(w)
        assert s.global_reason(ahead + HOUR) == "clock_shift"
        assert channels(s, R1, ahead + HOUR) != {"5g0": (100, "up")}
        known(s, w.clock.t - 30, 44)


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
        assert w.engine.counters["clock_waits_unexplained"] == 1
        assert w.engine._follow_from > w.clock.t
        await rounds(w, ch(36), 18 * 6, step_s=600)  # past the lost time
        assert w.engine._follow_from < w.clock.t
        s = await snap(w)
        known(s, w.clock.t - 60, 36)


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
    """Found by the stricter oracle after the drop: the fleet tracker keeps
    an outage start it took in the other time line (a router failing then,
    its coordinator counting on across the jump). Once the clock passes that
    start, the outage took over the open gap and began there, so the
    failure between the gap and that start read as "reachable". A start
    inside the doubled wall time of a jump (all of it, a drop does not
    shorten it) is not trusted: the outage begins at the gap it takes over."""
    with world(disks, routers=1) as w:
        await w.start()
        await far_ahead_then_back(w, 2 * DAY, 10)
        jumped = w.clock.t
        await rounds(w, ch(36), 150, step_s=600)  # dropped a day after it
        assert w.engine.counters["clock_waits_capped"] == 1
        assert w.clock.t < jumped + 2 * DAY - HOUR
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
    wait goes on from the stored mark; the jump ahead before it explains
    it, so a day after the jump what the clock ahead dated is dropped and
    the first occupant's channel 100 never comes back."""
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
        await rounds(w, ch(36), 2 * 144, step_s=600)
        back = back_mark(w)
        assert DAY <= back.params["wait_s"] <= DAY + 600 + 60
        assert w.disk.backups == 1
        assert not [m for m in w.marks("channel_changed") if m.ts >= ahead]
        await rounds(w, ch(36), 19 * 144, step_s=600)
        s = await snap(w)
        probe = ahead + 20
        assert probe >= w.clock.t - RETENTION_S
        known(s, probe, 36)


# --- the randomised oracle with a short limit -------------------------------------


async def test_the_extended_oracle_with_a_short_limit(monkeypatch) -> None:
    """``test_tm_oracle_review_v1520`` with the limit at 600 s, so its jumps
    back of 3000 s reach it: every answer stays the truth of one of the time
    lines or unknown, the explained drop really ran and so did the
    unexplained wait."""
    monkeypatch.setattr(tm_engine, "CLOCK_WAIT_MAX_S", 600.0)
    capped = Counter()
    real_end = tm_engine.TimeMachine._end_wait

    def counting(self: Any, now: float, back: Any, at: float) -> None:
        capped["calls"] += 1
        real_end(self, now, back, at)

    monkeypatch.setattr(tm_engine.TimeMachine, "_end_wait", counting)
    real_check = tm_engine.TimeMachine._check_wait

    def checking(self: Any, now: float, *, schedule: bool = True) -> Any:
        before = self.counters["clock_waits_unexplained"]
        due = real_check(self, now, schedule=schedule)
        capped["unexplained"] += self.counters["clock_waits_unexplained"] - before
        return due

    monkeypatch.setattr(tm_engine.TimeMachine, "_check_wait", checking)
    modes = (
        "jumpback",
        "jumpback+restartany",
        EXTENDED_MODES[-1],  # everything at once, ``jumpfwd`` included
    )
    runs = [(mode, seed) for mode in modes for seed in (1, 2, 3, 4, 8, 10, 22)]
    # a jump ahead, then back before where it went: the explained drop
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
        assert not findings, (mode, seed, {k: len(v) for k, v in findings.items()})
    assert capped["calls"] >= 5 and capped["unexplained"] >= 5, capped
    assert CLOCK_WAIT_MAX_S == DAY  # the shipped limit
