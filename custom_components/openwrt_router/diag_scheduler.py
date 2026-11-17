"""Central scheduler for active network diagnostics (pure asyncio).

Standard library only, no Home Assistant imports. The scheduler never knows
what a test does: a ``DiagJob`` carries an injected async callable. Router
keys are opaque strings (``None`` = a job that runs on the HA side).

Guarantees:

* priority per run request: manual > event-triggered > periodic;
* bounded global concurrency and at most one running job per router key
  (``None`` counts as one key);
* a sliding-window rate limit per router key that applies equally to manual,
  event and periodic runs. Manual/event requests over the limit are refused
  at once with ``RequestStatus.REFUSED_RATE_LIMIT``; a periodic run over the
  limit is deferred until the window frees (not counted as a failure);
* every run has a timeout; a timed-out run is cancelled, awaited and
  reported as ``Outcome.TIMEOUT``. Jobs must honour cancellation;
* exponential backoff (capped, optional jitter from an injected ``rand``)
  after consecutive failures or timeouts, reset on success;
* adaptive intervals: slower while a router key is marked under load, faster
  while a problem is tracked, never below ``min_interval`` (load wins);
* maintenance windows (global and per router key, absolute wall-clock
  ranges) skip periodic runs with ``Outcome.SKIPPED_MAINTENANCE``;
* an exception in a job is a ``FAILURE`` outcome, never a dead loop. Router
  keys, job IDs and exception messages are logged at debug level only;
* ``async_stop`` cancels and awaits every task it created; idempotent.

Clock, wall clock, sleep and random source are injectable, so tests run in
virtual time. A run's ``value`` is whatever the job returned; a measured
problem (e.g. packet loss) is a value, not a failure.
"""

from __future__ import annotations

import asyncio
import logging
import math
import random
import time
from collections import deque
from collections.abc import Awaitable, Callable, Coroutine, Iterable
from dataclasses import dataclass, field
from enum import IntEnum, StrEnum
from typing import Any

_LOGGER = logging.getLogger(__name__)

TASK_NAME_PREFIX = "openwrt_router diag"
SECONDS_PER_DAY = 86400.0
MAX_MAINTENANCE_WINDOWS = 32
# Highest backoff exponent (2**30 times any interval is far beyond any cap).
_MAX_EXPONENT = 30

type JobCallable = Callable[[], Awaitable[Any]]
type TaskFactory = Callable[[Coroutine[Any, Any, None], str], asyncio.Task[None]]


class Trigger(IntEnum):
    """Why a run was started; a higher value is a higher priority."""

    PERIODIC = 0
    EVENT = 1
    MANUAL = 2


class Outcome(StrEnum):
    """Result of one run (or of one skipped periodic run)."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    SKIPPED_MAINTENANCE = "skipped_maintenance"


class RequestStatus(StrEnum):
    """Answer to a manual or event-triggered run request."""

    ACCEPTED = "accepted"
    REFUSED_RATE_LIMIT = "refused_rate_limit"
    REFUSED_ALREADY_QUEUED = "refused_already_queued"
    REFUSED_UNKNOWN_JOB = "refused_unknown_job"
    REFUSED_STOPPED = "refused_stopped"


def _finite(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


@dataclass(frozen=True, slots=True)
class RateLimit:
    """At most ``max_runs`` started runs per router key within ``window`` s."""

    max_runs: int = 10
    window: float = 600.0

    def __post_init__(self) -> None:
        """Validate the limit."""
        if type(self.max_runs) is not int or self.max_runs < 1:
            raise ValueError("max_runs must be a positive int")
        if not _finite(self.window) or self.window <= 0:
            raise ValueError("window must be a positive number")

    @property
    def per_day(self) -> float:
        """Upper bound of runs per router key and day."""
        return self.max_runs * SECONDS_PER_DAY / self.window


@dataclass(frozen=True, slots=True)
class SchedulerConfig:
    """Scheduler limits. Defaults are deliberately conservative."""

    max_concurrent: int = 2
    rate_limit: RateLimit = field(default_factory=RateLimit)
    min_interval: float = 60.0
    load_multiplier: float = 4.0
    problem_speedup: float = 4.0
    backoff_cap: float = 3600.0
    backoff_jitter: float = 0.1
    max_jobs: int = 256

    def __post_init__(self) -> None:
        """Validate the configuration."""
        if type(self.max_concurrent) is not int or self.max_concurrent < 1:
            raise ValueError("max_concurrent must be a positive int")
        if type(self.max_jobs) is not int or self.max_jobs < 1:
            raise ValueError("max_jobs must be a positive int")
        if not isinstance(self.rate_limit, RateLimit):
            raise TypeError("rate_limit must be a RateLimit")
        if not _finite(self.min_interval) or self.min_interval <= 0:
            raise ValueError("min_interval must be positive")
        for name in ("load_multiplier", "problem_speedup"):
            value = getattr(self, name)
            if not _finite(value) or value < 1:
                raise ValueError(f"{name} must be at least 1")
        if not _finite(self.backoff_cap) or self.backoff_cap < 0:
            raise ValueError("backoff_cap must not be negative")
        if not _finite(self.backoff_jitter) or not 0 <= self.backoff_jitter < 1:
            raise ValueError("backoff_jitter must be in [0, 1)")


@dataclass(frozen=True, slots=True)
class DiagJob:
    """One diagnostic job. ``interval`` None = on demand only."""

    job_id: str
    kind: str
    run: JobCallable
    router_key: str | None = None
    interval: float | None = None
    timeout: float = 30.0
    first_delay: float = 0.0

    def __post_init__(self) -> None:
        """Validate the job definition."""
        if not isinstance(self.job_id, str) or not self.job_id:
            raise ValueError("job_id must be a non-empty string")
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("kind must be a non-empty string")
        if not callable(self.run):
            raise TypeError("run must be callable")
        if self.router_key is not None and not isinstance(self.router_key, str):
            raise TypeError("router_key must be a string or None")
        if self.interval is not None and (
            not _finite(self.interval) or self.interval <= 0
        ):
            raise ValueError("interval must be a positive number")
        if not _finite(self.timeout) or self.timeout <= 0:
            raise ValueError("timeout must be a positive number")
        if not _finite(self.first_delay) or self.first_delay < 0:
            raise ValueError("first_delay must not be negative")


@dataclass(frozen=True, slots=True)
class MaintenanceWindow:
    """Absolute wall-clock range ``[start, end)`` in epoch seconds."""

    start: float
    end: float

    def __post_init__(self) -> None:
        """Validate the range."""
        if not _finite(self.start) or not _finite(self.end) or self.end <= self.start:
            raise ValueError("maintenance window needs finite start < end")

    def contains(self, wall: float) -> bool:
        """True if ``wall`` lies inside the window."""
        return self.start <= wall < self.end


@dataclass(frozen=True, slots=True)
class RunResult:
    """Outcome of one run; ``started``/``finished`` use the monotonic clock."""

    job_id: str
    router_key: str | None
    kind: str
    trigger: Trigger
    outcome: Outcome
    started: float
    finished: float
    value: Any = None
    error: str | None = None  # exception type name only, never its message
    consecutive_failures: int = 0


@dataclass(frozen=True, slots=True)
class RunRequest:
    """Answer to ``request_run``; ``completion`` resolves with the RunResult."""

    status: RequestStatus
    completion: asyncio.Future[RunResult] | None = None
    retry_after: float | None = None


@dataclass(frozen=True, slots=True)
class JobStatus:
    """Snapshot of one job's scheduling state."""

    job_id: str
    router_key: str | None
    kind: str
    next_due: float | None
    effective_interval: float | None
    consecutive_failures: int
    last_outcome: Outcome | None
    running: bool
    pending: Trigger | None


@dataclass(frozen=True, slots=True)
class KeyLoad:
    """Configured load of one router key, in runs per day."""

    router_key: str | None
    periodic_jobs: int
    on_demand_jobs: int
    runs_per_day: float  # from the configured intervals
    effective_runs_per_day: float  # with the current load/problem factors
    rate_limit_per_day: float  # hard ceiling from the rate limit


@dataclass(slots=True)
class _JobState:
    next_due: float | None
    failures: int = 0
    last_end: float | None = None
    last_outcome: Outcome | None = None


@dataclass(slots=True)
class _Pending:
    seq: int
    trigger: Trigger
    completion: asyncio.Future[RunResult] | None


async def _invoke(run: JobCallable) -> Any:
    """Call the job inside the task, so synchronous raises are caught too."""
    return await run()


async def _sleep_for(sleep: Callable[[float], Awaitable[Any]], delay: float) -> None:
    await sleep(delay)


class DiagScheduler:
    """Runs ``DiagJob``s under concurrency, rate, timeout and backoff limits.

    Call every method from the event loop. Nothing runs before ``start()``;
    requests accepted before that run once started.
    """

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        rand: Callable[[], float] = random.random,
        on_result: Callable[[RunResult], None] | None = None,
        task_factory: TaskFactory | None = None,
    ) -> None:
        """Set up the scheduler.

        Args:
            config: Limits; ``SchedulerConfig()`` when omitted.
            clock: Monotonic seconds, for intervals, timeouts, rate limit.
            wall_clock: Epoch seconds, for maintenance windows only.
            sleep: Awaitable sleep; used for loop waits and run timeouts.
            rand: Source in [0, 1) for backoff jitter.
            on_result: Called with every RunResult (also skips/cancels).
            task_factory: Creates the long-running loop task (Home Assistant
                passes a background-task factory); run tasks are internal.
        """
        self._cfg = config or SchedulerConfig()
        self._clock = clock
        self._wall_clock = wall_clock
        self._sleep = sleep
        self._rand = rand
        self._on_result = on_result
        self._task_factory = task_factory
        self._jobs: dict[str, DiagJob] = {}
        self._states: dict[str, _JobState] = {}
        self._pending: dict[str, _Pending] = {}
        self._running: dict[str, asyncio.Task[None]] = {}
        self._busy: set[str | None] = set()
        self._charges: dict[str | None, deque[float]] = {}
        self._under_load: set[str | None] = set()
        self._tracking: set[str | None] = set()
        self._global_windows: tuple[MaintenanceWindow, ...] = ()
        self._key_windows: dict[str | None, tuple[MaintenanceWindow, ...]] = {}
        self._tasks: set[asyncio.Task[Any]] = set()
        self._loop_task: asyncio.Task[None] | None = None
        self._wake = asyncio.Event()
        self._seq = 0
        self._stopped = False

    # --- public API ---------------------------------------------------------------

    @property
    def config(self) -> SchedulerConfig:
        """The active configuration."""
        return self._cfg

    @property
    def running(self) -> bool:
        """True while the scheduling loop is alive."""
        task = self._loop_task
        return not self._stopped and task is not None and not task.done()

    def start(self) -> None:
        """Start the scheduling loop (no-op if already running)."""
        if self._stopped:
            raise RuntimeError("diagnostic scheduler was stopped")
        if self._loop_task is not None:
            return
        coro = self._run_loop()
        name = f"{TASK_NAME_PREFIX} loop"
        if self._task_factory is not None:
            task = self._task_factory(coro, name)
        else:
            task = asyncio.get_running_loop().create_task(coro, name=name)
        self._loop_task = task
        self._track(task)

    async def async_stop(self) -> None:
        """Cancel the loop and all runs, await them; idempotent and final."""
        self._stopped = True
        now = self._clock()
        for job_id, pending in list(self._pending.items()):
            job = self._jobs.get(job_id)
            if job is not None:
                self._publish(self._cancelled(job, pending, now), pending.completion)
        self._pending.clear()
        current = asyncio.current_task()
        while True:
            alive = [t for t in self._tasks if not t.done() and t is not current]
            if not alive:
                break
            for task in alive:
                task.cancel()
            await asyncio.gather(*alive, return_exceptions=True)
        self._loop_task = None

    def add_job(self, job: DiagJob) -> None:
        """Register a job; periodic jobs are first due after ``first_delay``."""
        if self._stopped:
            raise RuntimeError("diagnostic scheduler was stopped")
        if not isinstance(job, DiagJob):
            raise TypeError("job must be a DiagJob")
        if job.job_id in self._jobs:
            raise ValueError("duplicate job id")
        if len(self._jobs) >= self._cfg.max_jobs:
            raise ValueError("too many diagnostic jobs")
        if job.interval is not None and job.interval < self._cfg.min_interval:
            raise ValueError("interval below the configured minimum")
        due = self._clock() + job.first_delay if job.interval is not None else None
        self._jobs[job.job_id] = job
        self._states[job.job_id] = _JobState(next_due=due)
        self._wake.set()

    async def async_cancel_job(self, job_id: str) -> bool:
        """Remove a job and cancel its pending or running run."""
        if job_id not in self._jobs:
            return False
        await self._cancel_tasks([self._detach(job_id)])
        return True

    async def async_cancel_router(self, router_key: str | None) -> int:
        """Remove every job of ``router_key``; returns how many were removed."""
        ids = [jid for jid, job in self._jobs.items() if job.router_key == router_key]
        await self._cancel_tasks([self._detach(jid) for jid in ids])
        return len(ids)

    def request_run(
        self, job_id: str, *, trigger: Trigger = Trigger.MANUAL
    ) -> RunRequest:
        """Ask for an extra run now (manual or event-triggered).

        Refusals are returned, never raised. An accepted request takes one
        rate-limit slot at once; a pending periodic run of the same job is
        upgraded instead of duplicated.
        """
        if trigger is Trigger.PERIODIC:
            raise ValueError("periodic runs are scheduled, not requested")
        if self._stopped:
            return RunRequest(RequestStatus.REFUSED_STOPPED)
        job = self._jobs.get(job_id)
        if job is None:
            return RunRequest(RequestStatus.REFUSED_UNKNOWN_JOB)
        current = self._pending.get(job_id)
        if job_id in self._running or (
            current is not None and current.trigger is not Trigger.PERIODIC
        ):
            return RunRequest(RequestStatus.REFUSED_ALREADY_QUEUED)
        now = self._clock()
        wait = self._rate_wait(job.router_key, now)
        if wait is not None:
            _LOGGER.debug("Run of %s refused by rate limit (%.0f s)", job_id, wait)
            return RunRequest(RequestStatus.REFUSED_RATE_LIMIT, retry_after=wait)
        self._charge(job.router_key, now)
        completion: asyncio.Future[RunResult] = (
            asyncio.get_running_loop().create_future()
        )
        seq = current.seq if current is not None else self._next_seq()
        self._pending[job_id] = _Pending(seq, trigger, completion)
        self._wake.set()
        return RunRequest(RequestStatus.ACCEPTED, completion=completion)

    def set_router_load(self, router_key: str | None, under_load: bool) -> None:
        """Mark a router key as under load / degraded management (slows it)."""
        self._set_flag(self._under_load, router_key, under_load)

    def set_problem_tracking(self, router_key: str | None, active: bool) -> None:
        """Mark a problem as tracked on a router key (speeds it up, bounded)."""
        self._set_flag(self._tracking, router_key, active)

    def set_global_maintenance(self, windows: Iterable[MaintenanceWindow]) -> None:
        """Replace the maintenance windows that apply to every job."""
        self._global_windows = _windows(windows)

    def set_router_maintenance(
        self, router_key: str | None, windows: Iterable[MaintenanceWindow]
    ) -> None:
        """Replace the maintenance windows of one router key."""
        found = _windows(windows)
        others = {k: v for k, v in self._key_windows.items() if k != router_key}
        self._key_windows = {**others, router_key: found} if found else others

    def in_maintenance(self, router_key: str | None) -> bool:
        """True if periodic jobs of ``router_key`` are skipped right now."""
        return self._in_window(router_key, self._wall_clock())

    def job_status(self, job_id: str) -> JobStatus | None:
        """Snapshot of one job, or None if unknown."""
        job = self._jobs.get(job_id)
        state = self._states.get(job_id)
        if job is None or state is None:
            return None
        pending = self._pending.get(job_id)
        return JobStatus(
            job_id=job_id,
            router_key=job.router_key,
            kind=job.kind,
            next_due=state.next_due,
            effective_interval=self._effective_interval(job),
            consecutive_failures=state.failures,
            last_outcome=state.last_outcome,
            running=job_id in self._running,
            pending=pending.trigger if pending is not None else None,
        )

    def load_report(self) -> dict[str | None, KeyLoad]:
        """Configured runs per router key and day for the current job set."""
        groups: dict[str | None, list[DiagJob]] = {}
        for job in self._jobs.values():
            groups.setdefault(job.router_key, []).append(job)
        report: dict[str | None, KeyLoad] = {}
        for key, jobs in groups.items():
            periodic = [j for j in jobs if j.interval is not None]
            report[key] = KeyLoad(
                router_key=key,
                periodic_jobs=len(periodic),
                on_demand_jobs=len(jobs) - len(periodic),
                runs_per_day=sum(SECONDS_PER_DAY / j.interval for j in periodic),  # type: ignore[operator]
                effective_runs_per_day=sum(
                    SECONDS_PER_DAY / (self._effective_interval(j) or 1.0)
                    for j in periodic
                ),
                rate_limit_per_day=self._cfg.rate_limit.per_day,
            )
        return report

    # --- scheduling loop ------------------------------------------------------------

    async def _run_loop(self) -> None:
        while not self._stopped:
            self._wake.clear()
            try:
                self._dispatch()
                delay = self._next_delay()
            except Exception:  # a scheduler bug must not end diagnostics for good
                _LOGGER.exception("Diagnostic scheduler pass failed")
                delay = self._cfg.min_interval
            await self._wait(delay)

    async def _wait(self, delay: float | None) -> None:
        loop = asyncio.get_running_loop()
        waiters = {loop.create_task(self._wake.wait(), name=f"{TASK_NAME_PREFIX} wake")}
        if delay is not None:
            sleeper = _sleep_for(self._sleep, delay)
            waiters.add(loop.create_task(sleeper, name=f"{TASK_NAME_PREFIX} sleep"))
        for task in waiters:
            self._track(task)
        try:
            await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in waiters:
                task.cancel()
            await asyncio.gather(*waiters, return_exceptions=True)

    def _dispatch(self) -> None:
        now = self._clock()
        self._enqueue_due(now)
        self._start_ready(now)

    def _enqueue_due(self, now: float) -> None:
        wall: float | None = None
        for job_id, job in list(self._jobs.items()):
            state = self._states.get(job_id)
            if state is None or job.interval is None or state.next_due is None:
                continue
            if (
                state.next_due > now
                or job_id in self._running
                or job_id in self._pending
            ):
                continue
            if wall is None:
                wall = self._wall_clock()
            if self._in_window(job.router_key, wall):
                state.next_due = now + self._effective_interval(job)  # type: ignore[operator]
                skipped = RunResult(
                    job_id,
                    job.router_key,
                    job.kind,
                    Trigger.PERIODIC,
                    Outcome.SKIPPED_MAINTENANCE,
                    now,
                    now,
                    consecutive_failures=state.failures,
                )
                self._publish(skipped, None)
                continue
            self._pending[job_id] = _Pending(self._next_seq(), Trigger.PERIODIC, None)

    def _start_ready(self, now: float) -> None:
        order = sorted(
            self._pending.items(), key=lambda kv: (-kv[1].trigger, kv[1].seq)
        )
        for job_id, pending in order:
            if len(self._running) >= self._cfg.max_concurrent:
                return
            job = self._jobs.get(job_id)
            if job is None or job.router_key in self._busy:
                continue
            if pending.trigger is Trigger.PERIODIC:
                wait = self._rate_wait(job.router_key, now)
                if wait is not None:
                    del self._pending[job_id]
                    self._states[job_id].next_due = now + wait
                    _LOGGER.debug("Periodic run of %s deferred %.0f s", job_id, wait)
                    continue
                self._charge(job.router_key, now)
            self._start(job, pending)

    def _start(self, job: DiagJob, pending: _Pending) -> None:
        del self._pending[job.job_id]
        self._busy.add(job.router_key)
        loop = asyncio.get_running_loop()
        task = loop.create_task(
            self._run_one(job, pending), name=f"{TASK_NAME_PREFIX} run"
        )
        self._running[job.job_id] = task
        self._track(task)

    def _next_delay(self) -> float | None:
        dues = [
            state.next_due
            for job_id, state in self._states.items()
            if state.next_due is not None
            and job_id not in self._running
            and job_id not in self._pending
        ]
        if not dues:
            return None
        return max(0.0, min(dues) - self._clock())

    # --- one run ------------------------------------------------------------------------

    async def _run_one(self, job: DiagJob, pending: _Pending) -> None:
        started = self._clock()
        outcome, value, error = Outcome.CANCELLED, None, None
        try:
            outcome, value, error = await self._attempt(job)
        finally:
            self._complete(job, pending, started, outcome, value, error)

    async def _attempt(self, job: DiagJob) -> tuple[Outcome, Any, str | None]:
        loop = asyncio.get_running_loop()
        work = loop.create_task(_invoke(job.run), name=f"{TASK_NAME_PREFIX} job")
        timer = loop.create_task(
            _sleep_for(self._sleep, job.timeout), name=f"{TASK_NAME_PREFIX} timer"
        )
        self._track(work)
        self._track(timer)
        timed_out = False
        try:
            done, _ = await asyncio.wait(
                (work, timer), return_when=asyncio.FIRST_COMPLETED
            )
            timed_out = work not in done
        finally:
            timer.cancel()
            work.cancel()
            await asyncio.gather(work, timer, return_exceptions=True)
        if timed_out:
            return Outcome.TIMEOUT, None, None
        if work.cancelled():
            return Outcome.FAILURE, None, "CancelledError"
        err = work.exception()
        if err is not None:
            _LOGGER.debug(
                "Diagnostic job %s (router %s) raised",
                job.job_id,
                job.router_key,
                exc_info=err,
            )
            return Outcome.FAILURE, None, type(err).__name__
        return Outcome.SUCCESS, work.result(), None

    def _complete(
        self,
        job: DiagJob,
        pending: _Pending,
        started: float,
        outcome: Outcome,
        value: Any,
        error: str | None,
    ) -> None:
        if self._running.get(job.job_id) is asyncio.current_task():
            del self._running[job.job_id]
        self._busy.discard(job.router_key)
        finished = self._clock()
        state = (
            self._states.get(job.job_id) if self._jobs.get(job.job_id) is job else None
        )
        if state is not None and outcome is not Outcome.CANCELLED:
            self._record(job, state, outcome, finished)
            self._log_outcome(job, outcome, error, state.failures)
        result = RunResult(
            job.job_id,
            job.router_key,
            job.kind,
            pending.trigger,
            outcome,
            started,
            finished,
            value,
            error,
            state.failures if state is not None else 0,
        )
        self._publish(result, pending.completion)
        self._wake.set()

    def _record(
        self, job: DiagJob, state: _JobState, outcome: Outcome, now: float
    ) -> None:
        state.failures = 0 if outcome is Outcome.SUCCESS else state.failures + 1
        state.last_end = now
        state.last_outcome = outcome
        if job.interval is not None:
            state.next_due = now + self._delay_after(job, state.failures)

    def _log_outcome(
        self, job: DiagJob, outcome: Outcome, error: str | None, failures: int
    ) -> None:
        if outcome is Outcome.SUCCESS:
            return
        what = "timed out" if outcome is Outcome.TIMEOUT else f"failed ({error})"
        _LOGGER.debug(
            "Diagnostic job %s (router %s) %s, %d in a row",
            job.job_id,
            job.router_key,
            what,
            failures,
        )
        if failures == 1:
            _LOGGER.warning(
                "A diagnostic job of kind %s %s; retrying with backoff", job.kind, what
            )

    def _publish(
        self, result: RunResult, completion: asyncio.Future[RunResult] | None
    ) -> None:
        if completion is not None and not completion.done():
            completion.set_result(result)
        if self._on_result is None:
            return
        try:
            self._on_result(result)
        except Exception as err:  # a listener bug must not stop scheduling
            _LOGGER.error("Diagnostic result listener failed (%s)", type(err).__name__)
            _LOGGER.debug("Listener failure details", exc_info=err)

    # --- helpers ------------------------------------------------------------------------

    def _detach(self, job_id: str) -> asyncio.Task[None] | None:
        """Forget a job at once; returns its running task (to cancel) if any."""
        job = self._jobs.pop(job_id)
        self._states.pop(job_id, None)
        pending = self._pending.pop(job_id, None)
        if pending is not None:
            self._publish(
                self._cancelled(job, pending, self._clock()), pending.completion
            )
        self._wake.set()
        return self._running.get(job_id)

    async def _cancel_tasks(self, tasks: list[asyncio.Task[None] | None]) -> None:
        alive = [t for t in tasks if t is not None and t is not asyncio.current_task()]
        for task in alive:
            task.cancel()
        if alive:
            await asyncio.gather(*alive, return_exceptions=True)

    def _cancelled(self, job: DiagJob, pending: _Pending, now: float) -> RunResult:
        return RunResult(
            job.job_id,
            job.router_key,
            job.kind,
            pending.trigger,
            Outcome.CANCELLED,
            now,
            now,
        )

    def _track(self, task: asyncio.Task[Any]) -> None:
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _set_flag(self, flags: set[str | None], key: str | None, on: bool) -> None:
        if on:
            flags.add(key)
        else:
            flags.discard(key)
        self._retime(key)
        self._wake.set()

    def _retime(self, key: str | None) -> None:
        """Apply a changed load/problem factor to idle, healthy jobs of ``key``."""
        for job_id, job in self._jobs.items():
            state = self._states[job_id]
            if job.router_key != key or job.interval is None or state.last_end is None:
                continue
            if state.failures or job_id in self._running or job_id in self._pending:
                continue
            state.next_due = state.last_end + self._delay_after(job, 0)

    def _effective_interval(self, job: DiagJob) -> float | None:
        if job.interval is None:
            return None
        interval = job.interval
        if job.router_key in self._under_load:
            interval *= self._cfg.load_multiplier
        elif job.router_key in self._tracking:
            interval /= self._cfg.problem_speedup
        return max(interval, self._cfg.min_interval)

    def _delay_after(self, job: DiagJob, failures: int) -> float:
        base = self._effective_interval(job) or self._cfg.min_interval
        if failures <= 0:
            return base
        cap = max(self._cfg.backoff_cap, base)
        delay = min(base * 2 ** min(failures, _MAX_EXPONENT), cap)
        jitter = self._cfg.backoff_jitter
        if jitter:
            delay *= 1.0 - jitter * min(max(self._rand(), 0.0), 1.0)
        return max(base, delay)

    def _rate_wait(self, key: str | None, now: float) -> float | None:
        """None if a run may start now, else seconds until a slot frees."""
        limit = self._cfg.rate_limit
        charges = self._charges.get(key)
        if charges is None:
            return None
        while charges and now - charges[0] >= limit.window:
            charges.popleft()
        if len(charges) < limit.max_runs:
            return None
        return charges[0] + limit.window - now

    def _charge(self, key: str | None, now: float) -> None:
        self._charges.setdefault(key, deque()).append(now)

    def _in_window(self, key: str | None, wall: float) -> bool:
        windows = (*self._global_windows, *self._key_windows.get(key, ()))
        return any(w.contains(wall) for w in windows)


def _windows(windows: Iterable[MaintenanceWindow]) -> tuple[MaintenanceWindow, ...]:
    found = tuple(windows)
    if len(found) > MAX_MAINTENANCE_WINDOWS:
        raise ValueError("too many maintenance windows")
    if not all(isinstance(w, MaintenanceWindow) for w in found):
        raise TypeError("expected MaintenanceWindow items")
    return found
