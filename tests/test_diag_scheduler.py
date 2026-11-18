"""Tests for diag_scheduler.py: the central diagnostics test scheduler.

Time is virtual: the scheduler gets ``VirtualTime.clock``/``sleep`` injected,
so nothing really waits and nothing depends on the wall clock. Jobs are
scripted fakes; no test does network I/O.
"""

from __future__ import annotations

import ast
import asyncio
import heapq
import logging
import math
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router.diag_scheduler import (
    TASK_NAME_PREFIX,
    DiagJob,
    DiagScheduler,
    MaintenanceWindow,
    Outcome,
    RateLimit,
    RequestStatus,
    RunResult,
    SchedulerConfig,
    Trigger,
)

MODULE_PATH = (
    Path(__file__).resolve().parent.parent
    / "custom_components"
    / "openwrt_router"
    / "diag_scheduler.py"
)
WALL0 = 1_800_000_000.0
T0 = 1000.0
# Hang guards: a broken timeout/stop path must fail a test, never block it.
MAX_VIRTUAL_STEPS = 10_000
STOP_STEPS = 120


class VirtualTime:
    """Monotonic clock plus sleep that only advances when the test says so."""

    def __init__(self) -> None:
        self.now = T0
        self._sleepers: list[tuple[float, int, asyncio.Future[None]]] = []
        self._seq = 0

    def clock(self) -> float:
        return self.now

    def wall(self) -> float:
        return WALL0 + self.now

    async def sleep(self, delay: float) -> None:
        if delay <= 0:
            await asyncio.sleep(0)
            return
        fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._seq += 1
        heapq.heappush(self._sleepers, (self.now + delay, self._seq, fut))
        await fut

    async def settle(self) -> None:
        """Let every ready task run (zero-delay yields only)."""
        for _ in range(100):
            await asyncio.sleep(0)

    async def advance(self, seconds: float) -> None:
        target = self.now + seconds
        await self.settle()
        for _step in range(MAX_VIRTUAL_STEPS):
            live = [s for s in self._sleepers if not s[2].done()]
            heapq.heapify(live)
            self._sleepers = live
            if not live or live[0][0] > target:
                break
            deadline, _seq, fut = heapq.heappop(self._sleepers)
            self.now = max(self.now, deadline)
            fut.set_result(None)
            await self.settle()
        else:
            raise AssertionError("virtual time step limit reached")
        self.now = target
        await self.settle()

    async def run_until_done(self, task: asyncio.Task[Any], steps: int) -> bool:
        """Advance 1 s at a time until ``task`` is done; False after ``steps``."""
        for _ in range(steps):
            if task.done():
                return True
            await self.advance(1.0)
        return task.done()


class Body:
    """Scripted job body: records calls, can hang, wait for a gate or raise."""

    def __init__(self, env: Env, name: str) -> None:
        self.env = env
        self.name = name
        self.calls = 0
        self.active = 0
        self.cancelled = 0
        self.hang = False
        self.gate: asyncio.Event | None = None
        self.fail_with: BaseException | None = None

    async def __call__(self) -> str:
        self.calls += 1
        self.active += 1
        self.env.log.append((self.name, self.env.vt.now))
        try:
            if self.hang:
                await asyncio.Event().wait()
            if self.gate is not None:
                await self.gate.wait()
            if self.fail_with is not None:
                raise self.fail_with
            return f"{self.name}-ok"
        except asyncio.CancelledError:
            self.cancelled += 1
            raise
        finally:
            self.active -= 1


class Stubborn:
    """Job body that swallows every cancellation until ``release`` is set."""

    def __init__(self, env: Env) -> None:
        self.release = asyncio.Event()
        self.cancels = 0
        env.releases.append(self.release)

    async def __call__(self) -> str:
        while not self.release.is_set():
            try:
                await self.release.wait()
            except asyncio.CancelledError:
                self.cancels += 1
        return "late"


class Env:
    """Virtual time, recorded results and a scheduler factory."""

    def __init__(self) -> None:
        self.vt = VirtualTime()
        self.results: list[RunResult] = []
        self.log: list[tuple[str, float]] = []
        self.made: list[DiagScheduler] = []
        self.releases: list[asyncio.Event] = []

    def body(self, name: str) -> Body:
        return Body(self, name)

    def scheduler(
        self,
        *,
        rand: Callable[[], float] = lambda: 0.0,
        on_result: Callable[[RunResult], None] | None = None,
        **cfg: Any,
    ) -> DiagScheduler:
        cfg.setdefault("min_interval", 10.0)
        cfg.setdefault("backoff_jitter", 0.0)
        sched = DiagScheduler(
            SchedulerConfig(**cfg),
            clock=self.vt.clock,
            wall_clock=self.vt.wall,
            sleep=self.vt.sleep,
            rand=rand,
            on_result=on_result or self.results.append,
        )
        self.made.append(sched)
        return sched

    def outcomes(self, job_id: str) -> list[Outcome]:
        return [r.outcome for r in self.results if r.job_id == job_id]

    async def settle(self) -> None:
        await self.vt.settle()


def diag_tasks(*parts: str) -> list[asyncio.Task[Any]]:
    """Unfinished scheduler tasks, optionally only those naming one of ``parts``."""
    found = []
    for task in asyncio.all_tasks():
        name = task.get_name()
        if task.done() or not name.startswith(TASK_NAME_PREFIX):
            continue
        if not parts or any(p in name for p in parts):
            found.append(task)
    return found


@pytest.fixture
async def env() -> AsyncIterator[Env]:
    environment = Env()
    yield environment
    loop = asyncio.get_running_loop()
    stops = [loop.create_task(sched.async_stop()) for sched in environment.made]
    stopped = True
    for stop in stops:
        stopped = await environment.vt.run_until_done(stop, STOP_STEPS) and stopped
    for release in environment.releases:  # let stubborn bodies end either way
        release.set()
    await environment.settle()
    for stop in stops:
        stop.cancel()
    await asyncio.gather(*stops, return_exceptions=True)
    assert stopped, "async_stop did not return within its bound"
    assert diag_tasks() == []


# --- named acceptance tests ---------------------------------------------------


async def test_case_20_scheduler_rate_limiting(env: Env) -> None:
    """Per router key max N runs per window; refusals are typed, not raised."""
    s = env.scheduler(rate_limit=RateLimit(max_runs=2, window=60.0))
    bodies = {n: env.body(n) for n in ("a", "b", "c", "d")}
    for name in ("a", "b", "c"):
        s.add_job(DiagJob(name, "ping", bodies[name], router_key="r1"))
    s.add_job(DiagJob("d", "ping", bodies["d"], router_key="r2"))
    s.start()

    ra, rb, rc, rd = (s.request_run(n) for n in ("a", "b", "c", "d"))
    assert ra.status is RequestStatus.ACCEPTED
    assert rb.status is RequestStatus.ACCEPTED
    assert rc.status is RequestStatus.REFUSED_RATE_LIMIT
    assert rc.completion is None
    assert rc.retry_after == pytest.approx(60.0)
    assert rd.status is RequestStatus.ACCEPTED  # other router key unaffected
    await env.settle()
    assert ra.completion is not None and rb.completion is not None
    assert (await ra.completion).outcome is Outcome.SUCCESS
    assert (await rb.completion).outcome is Outcome.SUCCESS
    assert bodies["c"].calls == 0
    # Event-triggered requests use the same bucket
    refused = s.request_run("c", trigger=Trigger.EVENT)
    assert refused.status is RequestStatus.REFUSED_RATE_LIMIT

    await env.vt.advance(59.0)
    late = s.request_run("c")
    assert late.status is RequestStatus.REFUSED_RATE_LIMIT
    assert late.retry_after == pytest.approx(1.0)
    await env.vt.advance(1.0)
    again = s.request_run("c")
    assert again.status is RequestStatus.ACCEPTED
    await env.settle()
    assert again.completion is not None
    assert (await again.completion).outcome is Outcome.SUCCESS
    assert bodies["c"].calls == 1
    # Refusals never show up as failures
    assert Outcome.FAILURE not in [r.outcome for r in env.results]

    # Long-running runs: the window limits *started* runs, not accepted requests
    s2 = env.scheduler(rate_limit=RateLimit(max_runs=2, window=100.0))
    names = ("A", "B", "C", "D")
    long_bodies = {n: env.body(n) for n in names}
    long_bodies["A"].gate = asyncio.Event()
    for name in names:
        s2.add_job(DiagJob(name, "ping", long_bodies[name], "r9", timeout=1000.0))
    s2.start()
    t0 = env.vt.now
    assert s2.request_run("A").status is RequestStatus.ACCEPTED  # runs 0..150
    await env.vt.advance(99.0)
    rb2 = s2.request_run("B")  # queued behind A
    await env.vt.advance(1.0)
    rc2 = s2.request_run("C")
    assert rb2.status is RequestStatus.ACCEPTED
    assert rc2.status is RequestStatus.ACCEPTED
    await env.vt.advance(50.0)
    long_bodies["A"].gate.set()
    await env.vt.advance(49.0)
    rd2 = s2.request_run("D")  # B and C started at 150: the window is full
    assert rd2.status is RequestStatus.REFUSED_RATE_LIMIT
    assert rd2.retry_after == pytest.approx(51.0)
    starts = [t - t0 for name, t in env.log if name in names]
    assert starts == [0.0, 150.0, 150.0]
    for t in starts:
        assert len([u for u in starts if t <= u < t + 100.0]) <= 2
    for req in (rb2, rc2):
        assert req.completion is not None
        assert req.completion.result().outcome is Outcome.SUCCESS
    await env.vt.advance(51.0)
    assert s2.request_run("D").status is RequestStatus.ACCEPTED


async def test_case_21_test_timeouts(env: Env) -> None:
    """A hanging run is cancelled at its timeout and reported as 'timeout'."""
    s = env.scheduler()
    hang = env.body("hang")
    hang.hang = True
    quick = env.body("quick")
    s.add_job(DiagJob("h", "ping", hang, router_key="r1", timeout=5.0))
    s.add_job(DiagJob("q", "ping", quick, router_key="r2", timeout=5.0))
    s.start()
    rh = s.request_run("h")
    rq = s.request_run("q")
    await env.settle()
    assert rq.completion is not None and rq.completion.done()
    assert rq.completion.result().outcome is Outcome.SUCCESS
    assert rq.completion.result().value == "quick-ok"
    assert len(diag_tasks("timer")) == 1  # only the hanging run's timer is left
    assert rh.completion is not None

    await env.vt.advance(4.9)
    assert not rh.completion.done()
    assert hang.active == 1

    await env.vt.advance(0.1)
    assert rh.completion.done()
    result = rh.completion.result()
    assert result.outcome is Outcome.TIMEOUT
    assert result.finished - result.started == pytest.approx(5.0)
    assert result.error is None
    assert hang.cancelled == 1 and hang.active == 0
    assert diag_tasks("job", "timer", "run") == []  # nothing left behind
    assert s.job_status("h").consecutive_failures == 1  # timeout counts as failure
    # The router key is free again
    second = s.request_run("h")
    assert second.status is RequestStatus.ACCEPTED
    await env.vt.advance(5.0)
    assert second.completion is not None
    assert second.completion.result().outcome is Outcome.TIMEOUT
    assert s.job_status("h").consecutive_failures == 2
    assert s.running


async def test_job_ignoring_cancellation_times_out_and_frees_its_key(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    """A job that swallows CancelledError is orphaned after a bounded grace."""
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    secret = "192.168.77.1"
    s = env.scheduler()  # default cancel grace: 5 s
    stubborn = Stubborn(env)
    after = env.body("after")
    s.add_job(DiagJob("stub", "ping", stubborn, router_key=secret, timeout=5.0))
    s.add_job(DiagJob("after", "ping", after, router_key=secret, timeout=5.0))
    s.start()
    req = s.request_run("stub")
    await env.vt.advance(5.0)
    assert stubborn.cancels == 1
    assert req.completion is not None and not req.completion.done()  # in grace
    await env.vt.advance(5.0)
    assert req.completion.done()
    result = req.completion.result()
    assert result.outcome is Outcome.TIMEOUT
    assert result.error == "CancellationIgnored"
    assert result.finished - result.started == pytest.approx(10.0)
    assert s.orphaned_tasks == 1
    assert s.job_status("stub").running is False
    # The router key is free again
    follow = s.request_run("after")
    assert follow.status is RequestStatus.ACCEPTED
    await env.settle()
    assert follow.completion is not None
    assert follow.completion.result().outcome is Outcome.SUCCESS
    loud = [r for r in caplog.records if r.levelno > logging.DEBUG]
    assert len([r for r in loud if "cancellation" in r.getMessage()]) == 1
    assert all(secret not in r.getMessage() for r in loud)
    # The orphan is tracked until it really ends
    stubborn.release.set()
    await env.settle()
    assert s.orphaned_tasks == 0
    assert diag_tasks("job") == []


async def test_stop_is_bounded_when_a_job_ignores_cancellation(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger="custom_components.openwrt_router")
    s = env.scheduler()  # default stop grace: 10 s
    stubborn = Stubborn(env)
    s.add_job(DiagJob("stub", "ping", stubborn, router_key="r1", timeout=100.0))
    s.start()
    s.request_run("stub")
    await env.settle()
    stop = asyncio.get_running_loop().create_task(s.async_stop())
    assert await env.vt.run_until_done(stop, 30), "async_stop must be bounded"
    assert stop.result() == 1  # the job task that did not stop
    assert s.orphaned_tasks == 1
    assert not s.running
    assert any("did not stop" in r.getMessage() for r in caplog.records)
    assert await s.async_stop() == 1  # idempotent, same answer
    stubborn.release.set()
    await env.settle()
    assert s.orphaned_tasks == 0
    assert diag_tasks() == []


# --- priority, single flight, concurrency ---------------------------------------


async def test_priority_manual_before_event_before_periodic(env: Env) -> None:
    s = env.scheduler(max_concurrent=1)
    blocker = env.body("block")
    blocker.gate = asyncio.Event()
    s.add_job(DiagJob("block", "x", blocker, router_key="k0"))
    s.add_job(
        DiagJob(
            "per",
            "x",
            env.body("per"),
            router_key="k1",
            interval=60.0,
            first_delay=10.0,
        )
    )
    s.add_job(DiagJob("evt", "x", env.body("evt"), router_key="k2"))
    s.add_job(DiagJob("man", "x", env.body("man"), router_key="k3"))
    s.start()
    s.request_run("block")
    await env.settle()
    await env.vt.advance(10.0)  # periodic job is due, but the only slot is taken
    assert s.job_status("per").pending is Trigger.PERIODIC
    assert s.request_run("evt", trigger=Trigger.EVENT).status is RequestStatus.ACCEPTED
    assert s.request_run("man").status is RequestStatus.ACCEPTED
    await env.settle()
    assert [name for name, _ in env.log] == ["block"]
    blocker.gate.set()
    await env.settle()
    assert [name for name, _ in env.log] == ["block", "man", "evt", "per"]


async def test_manual_request_upgrades_a_pending_periodic_run(env: Env) -> None:
    s = env.scheduler(max_concurrent=1)
    blocker = env.body("block")
    blocker.gate = asyncio.Event()
    per = env.body("per")
    s.add_job(DiagJob("block", "x", blocker, router_key="k0"))
    s.add_job(DiagJob("per", "x", per, router_key="k1", interval=60.0))
    s.request_run("block")
    s.start()
    await env.settle()
    assert s.job_status("per").pending is Trigger.PERIODIC
    req = s.request_run("per")
    assert req.status is RequestStatus.ACCEPTED
    assert s.job_status("per").pending is Trigger.MANUAL
    assert s.request_run("per").status is RequestStatus.REFUSED_ALREADY_QUEUED
    blocker.gate.set()
    await env.settle()
    assert per.calls == 1
    assert req.completion is not None
    assert req.completion.result().trigger is Trigger.MANUAL


async def test_single_flight_per_router_key(env: Env) -> None:
    s = env.scheduler(max_concurrent=4)
    gate = asyncio.Event()
    a, b, c = env.body("a"), env.body("b"), env.body("c")
    for body in (a, b, c):
        body.gate = gate
    s.add_job(DiagJob("a", "x", a, router_key="r1"))
    s.add_job(DiagJob("b", "x", b, router_key="r1"))
    s.add_job(DiagJob("c", "x", c, router_key="r2"))
    s.start()
    for name in ("a", "b", "c"):
        assert s.request_run(name).status is RequestStatus.ACCEPTED
    await env.settle()
    assert (a.active, b.active, c.active) == (1, 0, 1)
    assert s.job_status("b").pending is Trigger.MANUAL
    gate.set()
    await env.settle()
    assert (a.calls, b.calls, c.calls) == (1, 1, 1)
    order = [name for name, _ in env.log]
    assert order.index("b") > order.index("a")


async def test_ha_side_jobs_share_one_slot(env: Env) -> None:
    """Jobs without a router key (HA-side) are serialised like one router."""
    s = env.scheduler(max_concurrent=4)
    gate = asyncio.Event()
    a, b = env.body("a"), env.body("b")
    a.gate = b.gate = gate
    s.add_job(DiagJob("a", "x", a))
    s.add_job(DiagJob("b", "x", b))
    s.start()
    s.request_run("a")
    s.request_run("b")
    await env.settle()
    assert (a.active, b.active) == (1, 0)
    gate.set()
    await env.settle()
    assert (a.calls, b.calls) == (1, 1)


async def test_global_concurrency_is_bounded(env: Env) -> None:
    s = env.scheduler(max_concurrent=2)
    gate = asyncio.Event()
    bodies = [env.body(f"j{i}") for i in range(3)]
    for i, body in enumerate(bodies):
        body.gate = gate
        s.add_job(DiagJob(f"j{i}", "x", body, router_key=f"r{i}"))
        s.request_run(f"j{i}")
    s.start()
    await env.settle()
    assert sum(b.active for b in bodies) == 2
    assert len(diag_tasks("run")) == 2
    gate.set()
    await env.settle()
    assert [b.calls for b in bodies] == [1, 1, 1]


# --- rate limit applies to periodic and manual runs alike -----------------------


async def test_manual_run_obeys_the_same_rate_limit_as_periodic(env: Env) -> None:
    s = env.scheduler(rate_limit=RateLimit(max_runs=2, window=300.0))
    per = env.body("per")
    man = env.body("man")
    s.add_job(DiagJob("per", "x", per, router_key="r1", interval=30.0))
    s.add_job(DiagJob("man", "x", man, router_key="r1"))
    s.start()
    await env.settle()
    assert per.calls == 1
    await env.vt.advance(30.0)
    assert per.calls == 2
    refused = s.request_run("man")
    assert refused.status is RequestStatus.REFUSED_RATE_LIMIT
    assert refused.retry_after == pytest.approx(270.0)
    # The next periodic run is deferred until the window frees, not failed
    await env.vt.advance(30.0)
    assert per.calls == 2
    status = s.job_status("per")
    assert status.consecutive_failures == 0
    assert status.next_due == pytest.approx(T0 + 300.0)
    await env.vt.advance(240.0)
    assert per.calls == 3
    assert env.outcomes("per") == [Outcome.SUCCESS] * 3
    assert man.calls == 0


async def test_rate_limit_counts_runs_not_requests_for_periodic(env: Env) -> None:
    """A periodic job alone never exceeds max_runs per window."""
    s = env.scheduler(rate_limit=RateLimit(max_runs=3, window=100.0))
    per = env.body("per")
    s.add_job(DiagJob("per", "x", per, router_key="r1", interval=10.0))
    s.start()
    await env.vt.advance(1000.0)
    starts = [t for name, t in env.log if name == "per"]
    for t in starts:
        in_window = [u for u in starts if t <= u < t + 100.0]
        assert len(in_window) <= 3
    assert len(starts) >= 30


# --- backoff -------------------------------------------------------------------


async def test_backoff_grows_to_the_cap_and_resets_on_success(env: Env) -> None:
    s = env.scheduler(backoff_cap=300.0)
    flaky = env.body("flaky")
    flaky.fail_with = OSError("boom")
    s.add_job(DiagJob("f", "x", flaky, router_key="r1", interval=60.0))
    s.start()
    await env.settle()
    delays = []
    for _ in range(4):
        status = s.job_status("f")
        delays.append(status.next_due - env.vt.now)
        await env.vt.advance(status.next_due - env.vt.now)
    assert delays == [120.0, 240.0, 300.0, 300.0]
    assert s.job_status("f").consecutive_failures == 5
    flaky.fail_with = None
    await env.vt.advance(s.job_status("f").next_due - env.vt.now)
    status = s.job_status("f")
    assert status.consecutive_failures == 0
    assert status.last_outcome is Outcome.SUCCESS
    assert status.next_due - env.vt.now == 60.0


async def test_backoff_jitter_comes_from_the_injected_random(env: Env) -> None:
    s = env.scheduler(backoff_cap=3600.0, backoff_jitter=0.2, rand=lambda: 0.5)
    flaky = env.body("flaky")
    flaky.fail_with = OSError("boom")
    s.add_job(DiagJob("f", "x", flaky, router_key="r1", interval=60.0))
    s.start()
    await env.settle()
    # 120 s backoff, shortened by jitter * rand = 10 %
    assert s.job_status("f").next_due - env.vt.now == pytest.approx(108.0)


async def test_backoff_never_shortens_a_long_interval(env: Env) -> None:
    s = env.scheduler(backoff_cap=300.0)
    flaky = env.body("flaky")
    flaky.fail_with = OSError("boom")
    s.add_job(DiagJob("f", "x", flaky, router_key="r1", interval=3600.0))
    s.start()
    await env.settle()
    assert s.job_status("f").next_due - env.vt.now == 3600.0


# --- adaptive frequency -----------------------------------------------------------


async def test_adaptive_frequency_slows_and_speeds_within_bounds(env: Env) -> None:
    s = env.scheduler(min_interval=60.0, load_multiplier=4.0, problem_speedup=4.0)
    per = env.body("per")
    s.add_job(DiagJob("p", "x", per, router_key="r1", interval=120.0))

    def eff() -> float | None:
        return s.job_status("p").effective_interval

    assert eff() == 120.0
    s.set_router_load("r1", True)
    assert eff() == 480.0
    s.set_problem_tracking("r1", True)
    assert eff() == 480.0  # a degraded router is never sped up
    s.set_router_load("r1", False)
    assert eff() == 60.0  # 120 / 4 = 30, floored at min_interval
    s.set_problem_tracking("r1", False)
    assert eff() == 120.0

    s.start()
    await env.settle()
    assert per.calls == 1
    assert s.job_status("p").next_due == T0 + 120.0
    s.set_problem_tracking("r1", True)
    assert s.job_status("p").next_due == T0 + 60.0
    await env.vt.advance(60.0)
    assert per.calls == 2
    s.set_router_load("r1", True)
    assert s.job_status("p").next_due == T0 + 60.0 + 480.0
    await env.vt.advance(479.0)
    assert per.calls == 2
    await env.vt.advance(1.0)
    assert per.calls == 3


# --- maintenance windows ----------------------------------------------------------


async def test_maintenance_window_skips_periodic_jobs(env: Env) -> None:
    s = env.scheduler()
    p, q = env.body("p"), env.body("q")
    s.add_job(DiagJob("p", "x", p, router_key="r1", interval=60.0))
    s.add_job(DiagJob("q", "x", q, router_key="r2", interval=60.0))
    s.set_router_maintenance("r1", [MaintenanceWindow(WALL0 + T0 - 1, WALL0 + T0 + 90)])
    assert s.in_maintenance("r1") and not s.in_maintenance("r2")
    s.start()
    await env.settle()
    assert (p.calls, q.calls) == (0, 1)
    assert env.outcomes("p") == [Outcome.SKIPPED_MAINTENANCE]
    assert s.job_status("p").consecutive_failures == 0
    # Manual runs are still possible inside the window
    manual = s.request_run("p")
    await env.settle()
    assert manual.completion is not None
    assert manual.completion.result().outcome is Outcome.SUCCESS
    await env.vt.advance(60.0)  # still inside the window
    assert p.calls == 1
    assert env.outcomes("p")[-1] is Outcome.SKIPPED_MAINTENANCE
    await env.vt.advance(60.0)  # window over
    assert p.calls == 2
    assert Outcome.FAILURE not in env.outcomes("p")

    s.set_global_maintenance([MaintenanceWindow(WALL0 + env.vt.now, WALL0 + 1e9)])
    before = (p.calls, q.calls)
    await env.vt.advance(120.0)
    assert (p.calls, q.calls) == before
    s.set_global_maintenance([])
    await env.vt.advance(60.0)
    assert p.calls > before[0] and q.calls > before[1]


async def test_maintenance_window_validation(env: Env) -> None:
    s = env.scheduler()
    with pytest.raises(ValueError):
        MaintenanceWindow(10.0, 5.0)
    with pytest.raises(ValueError):
        MaintenanceWindow(0.0, math.inf)
    with pytest.raises(ValueError):
        s.set_global_maintenance(
            [MaintenanceWindow(float(i), i + 1.0) for i in range(100)]
        )


# --- cancellation and shutdown -----------------------------------------------------


async def test_cancel_single_job(env: Env) -> None:
    s = env.scheduler(max_concurrent=1)
    a, b, c = env.body("a"), env.body("b"), env.body("c")
    a.hang = True
    s.add_job(DiagJob("a", "x", a, router_key="r1"))
    s.add_job(DiagJob("b", "x", b, router_key="r1"))
    s.add_job(DiagJob("c", "x", c, router_key="r2"))
    s.start()
    ra, rb, rc = (s.request_run(n) for n in ("a", "b", "c"))
    await env.settle()
    assert a.active == 1
    assert await s.async_cancel_job("a") is True
    assert ra.completion is not None
    assert ra.completion.result().outcome is Outcome.CANCELLED
    assert a.cancelled == 1
    assert s.job_status("a") is None
    assert s.request_run("a").status is RequestStatus.REFUSED_UNKNOWN_JOB
    await env.settle()
    assert (b.calls, c.calls) == (1, 1)
    for req in (rb, rc):
        assert req.completion is not None
        assert req.completion.result().outcome is Outcome.SUCCESS
    assert await s.async_cancel_job("a") is False
    # Cancelled runs are not failures
    assert Outcome.FAILURE not in env.outcomes("a")


async def test_cancel_all_jobs_of_a_router(env: Env) -> None:
    s = env.scheduler(max_concurrent=4)
    x, y, z = env.body("x"), env.body("y"), env.body("z")
    x.hang = z.hang = True
    s.add_job(DiagJob("x", "x", x, router_key="r3"))
    s.add_job(DiagJob("y", "x", y, router_key="r3", interval=60.0))
    s.add_job(DiagJob("z", "x", z, router_key="r4"))
    s.request_run("x")
    s.request_run("z")
    s.start()
    await env.settle()
    ry = s.request_run("y")  # pending behind x
    assert ry.status is RequestStatus.ACCEPTED
    assert await s.async_cancel_router("r3") == 2
    assert ry.completion is not None
    assert ry.completion.result().outcome is Outcome.CANCELLED
    assert (x.cancelled, y.calls, z.active) == (1, 0, 1)
    assert s.job_status("x") is None and s.job_status("y") is None
    assert s.job_status("z") is not None
    assert await s.async_cancel_router("r3") == 0


async def test_stop_is_clean_idempotent_and_final(env: Env) -> None:
    s = env.scheduler(max_concurrent=1)
    h, p = env.body("h"), env.body("p")
    h.hang = True
    s.add_job(DiagJob("h", "x", h, router_key="r1"))
    s.add_job(DiagJob("p", "x", p, router_key="r2", interval=60.0))
    rh = s.request_run("h")  # accepted before start, runs once started
    s.start()
    await env.settle()
    assert h.active == 1 and s.job_status("p").pending is Trigger.PERIODIC
    assert diag_tasks("loop") and diag_tasks("run")

    await asyncio.gather(s.async_stop(), s.async_stop())
    assert diag_tasks() == []
    assert h.cancelled == 1 and h.active == 0
    assert rh.completion is not None
    assert rh.completion.result().outcome is Outcome.CANCELLED
    others = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    assert [t for t in others if not t.done()] == []
    assert not s.running

    await s.async_stop()  # idempotent
    assert s.request_run("h").status is RequestStatus.REFUSED_STOPPED
    with pytest.raises(RuntimeError):
        s.add_job(DiagJob("new", "x", env.body("new"), router_key="r9"))
    with pytest.raises(RuntimeError):
        s.start()
    s.set_router_load("r2", True)  # harmless after stop
    await env.vt.advance(3600.0)
    assert p.calls == 0
    assert diag_tasks() == []


async def test_stop_before_start_and_start_twice(env: Env) -> None:
    s = env.scheduler()
    await s.async_stop()
    assert not s.running
    t = env.scheduler()
    t.start()
    t.start()  # second start is a no-op
    assert len(diag_tasks("loop")) == 1
    await t.async_stop()


# --- error isolation and logging --------------------------------------------------


async def test_raising_job_does_not_kill_the_loop(env: Env) -> None:
    s = env.scheduler()
    bad = env.body("bad")
    bad.fail_with = RuntimeError("boom")
    good = env.body("good")

    def sync_bad() -> Any:
        raise ValueError("raised before any await")

    s.add_job(DiagJob("bad", "x", bad, router_key="r1", interval=60.0))
    s.add_job(DiagJob("sync", "x", sync_bad, router_key="r2", interval=60.0))
    s.add_job(DiagJob("good", "x", good, router_key="r3", interval=60.0))
    s.start()
    await env.settle()
    by_id = {r.job_id: r for r in env.results}
    assert by_id["bad"].outcome is Outcome.FAILURE
    assert by_id["bad"].error == "RuntimeError"
    assert by_id["sync"].outcome is Outcome.FAILURE
    assert by_id["sync"].error == "ValueError"
    assert by_id["good"].outcome is Outcome.SUCCESS
    assert s.running
    await env.vt.advance(60.0)
    assert good.calls == 2


async def test_failing_result_callback_does_not_kill_the_loop(env: Env) -> None:
    seen: list[str] = []

    def explode(result: RunResult) -> None:
        seen.append(result.job_id)
        raise RuntimeError("callback bug")

    s = env.scheduler(on_result=explode)
    good = env.body("good")
    s.add_job(DiagJob("good", "x", good, router_key="r1", interval=60.0))
    s.start()
    await env.settle()
    await env.vt.advance(60.0)
    assert good.calls == 2 and seen == ["good", "good"]
    assert s.running


async def test_hosts_are_logged_at_debug_only(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    secret = "192.168.77.1"
    s = env.scheduler()
    bad = env.body("bad")
    bad.fail_with = OSError(f"no route to {secret}")
    s.add_job(DiagJob(f"ping-{secret}", "ping", bad, router_key=secret, interval=60.0))
    s.start()
    await env.settle()
    await env.vt.advance(120.0)
    assert bad.calls >= 2
    loud = [r for r in caplog.records if r.levelno > logging.DEBUG]
    assert len(loud) == 1  # one warning per failure streak, not per run
    assert all(secret not in r.getMessage() for r in loud)
    assert any(secret in r.getMessage() for r in caplog.records)  # debug has details


async def test_failed_scheduler_pass_logs_the_type_only(
    env: Env, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    secret = "192.168.77.1"
    s = env.scheduler()
    job = env.body("j")
    s.add_job(DiagJob("j", "ping", job, router_key="r1"))
    real_dispatch = s._dispatch
    passes = 0

    def flaky_dispatch() -> None:
        nonlocal passes
        passes += 1
        if passes == 1:
            raise RuntimeError(f"bad state for {secret}")
        real_dispatch()

    s._dispatch = flaky_dispatch  # type: ignore[method-assign]
    s.request_run("j")
    s.start()
    await env.settle()
    assert job.calls == 0
    await env.vt.advance(10.0)  # retried after min_interval
    assert job.calls == 1 and s.running
    loud = [r for r in caplog.records if r.levelno > logging.DEBUG]
    assert [r.getMessage() for r in loud] == [
        "Diagnostic scheduler pass failed (RuntimeError)"
    ]
    assert all(r.exc_info is None for r in loud)
    debug = [r for r in caplog.records if r.levelno == logging.DEBUG and r.exc_info]
    assert any(secret in str(r.exc_info[1]) for r in debug)


# --- configuration, validation, status ---------------------------------------------


async def test_add_job_validation(env: Env) -> None:
    s = env.scheduler(min_interval=60.0, max_jobs=2)
    body = env.body("j")
    s.add_job(DiagJob("j1", "x", body, router_key="r1", interval=60.0))
    with pytest.raises(ValueError):
        s.add_job(DiagJob("j1", "x", body, router_key="r1"))  # duplicate
    with pytest.raises(ValueError):
        s.add_job(DiagJob("j2", "x", body, router_key="r1", interval=59.0))
    s.add_job(DiagJob("j2", "x", body))
    with pytest.raises(ValueError):
        s.add_job(DiagJob("j3", "x", body))  # max_jobs
    for bad in (
        {"timeout": 0.0},
        {"timeout": -1.0},
        {"timeout": math.nan},
        {"timeout": math.inf},
        {"interval": math.inf},
        {"interval": 0.0},
        {"first_delay": -1.0},
    ):
        with pytest.raises(ValueError):
            DiagJob("x", "x", body, **bad)
    with pytest.raises(ValueError):
        DiagJob("", "x", body)
    with pytest.raises(TypeError):
        DiagJob("x", "x", "not callable")  # type: ignore[arg-type]


async def test_request_validation(env: Env) -> None:
    s = env.scheduler()
    s.add_job(DiagJob("j", "x", env.body("j"), router_key="r1"))
    assert s.request_run("missing").status is RequestStatus.REFUSED_UNKNOWN_JOB
    with pytest.raises(ValueError):
        s.request_run("j", trigger=Trigger.PERIODIC)
    first = s.request_run("j")
    assert first.status is RequestStatus.ACCEPTED
    dup = s.request_run("j", trigger=Trigger.EVENT)
    assert dup.status is RequestStatus.REFUSED_ALREADY_QUEUED
    assert dup.completion is None


async def test_config_validation() -> None:
    for bad in (
        {"max_concurrent": 0},
        {"min_interval": 0.0},
        {"load_multiplier": 0.5},
        {"problem_speedup": 0.5},
        {"backoff_cap": -1.0},
        {"backoff_jitter": 1.5},
        {"max_jobs": 0},
        {"cancel_grace": 0.0},
        {"cancel_grace": math.inf},
        {"stop_grace": -1.0},
        {"stop_grace": math.nan},
    ):
        with pytest.raises(ValueError):
            SchedulerConfig(**bad)
    with pytest.raises(ValueError):
        RateLimit(max_runs=0, window=60.0)
    with pytest.raises(ValueError):
        RateLimit(max_runs=1, window=0.0)


async def test_load_report_documents_runs_per_day(env: Env) -> None:
    s = env.scheduler(
        min_interval=60.0, rate_limit=RateLimit(max_runs=10, window=600.0)
    )
    body = env.body("j")
    s.add_job(DiagJob("a", "x", body, router_key="r1", interval=300.0))
    s.add_job(DiagJob("b", "x", body, router_key="r1", interval=600.0))
    s.add_job(DiagJob("m", "x", body, router_key="r1"))
    s.add_job(DiagJob("ha", "x", body, interval=3600.0))
    report = s.load_report()
    assert set(report) == {"r1", None}
    r1 = report["r1"]
    assert (r1.periodic_jobs, r1.on_demand_jobs) == (2, 1)
    assert r1.runs_per_day == pytest.approx(288 + 144)
    assert r1.effective_runs_per_day == pytest.approx(432)
    assert r1.rate_limit_per_day == pytest.approx(1440)
    assert report[None].runs_per_day == pytest.approx(24)
    s.set_router_load("r1", True)
    slowed = s.load_report()["r1"]
    assert slowed.runs_per_day == pytest.approx(432)
    assert slowed.effective_runs_per_day == pytest.approx(108)


async def test_default_config_is_conservative() -> None:
    cfg = SchedulerConfig()
    assert cfg.max_concurrent <= 2
    assert cfg.rate_limit.max_runs * 86400 / cfg.rate_limit.window <= 1440
    assert cfg.min_interval >= 30.0


def test_module_is_standard_library_only() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no intra-package imports"
            names = [node.module or ""]
        else:
            continue
        for name in names:
            assert not name.startswith(("homeassistant", "aiohttp", "socket"))
