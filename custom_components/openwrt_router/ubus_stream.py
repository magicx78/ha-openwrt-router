"""Transport runner for one ubus SSE subscription on one router (RT2).

``UbusSubscription`` keeps ``OpenWrtAPI.async_subscribe(obj)`` running: it
reconnects with exponential backoff and jitter, waits an hour when the
session lacks the ``:subscribe`` right, buffers events in a bounded queue and
stops cleanly. It does no HTTP itself (that stays in api.py) and has no Home
Assistant imports, so it runs in tests without ``hass``; Home Assistant passes
a task factory around ``entry.async_create_background_task``.

RT2 decision: the per-object transport runner lives here; the multi-router
manager (discovery, batching into the engine) follows as ``net_stream.py`` in
RT3 and builds on this class.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import random
import time
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import Any, Protocol

from .api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtStreamNotFoundError,
    OpenWrtStreamPermissionError,
    OpenWrtTimeoutError,
    SseStats,
    validate_stream_object,
)
from .const import (
    STREAM_BACKOFF_INITIAL,
    STREAM_BACKOFF_JITTER,
    STREAM_BACKOFF_MAX,
    STREAM_BACKOFF_RESET_AFTER,
    STREAM_NO_PERMISSION_RETRY,
    STREAM_QUEUE_MAX,
    STREAM_STATE_BACKOFF,
    STREAM_STATE_CONNECTING,
    STREAM_STATE_IDLE,
    STREAM_STATE_NO_PERMISSION,
    STREAM_STATE_NOT_FOUND,
    STREAM_STATE_PAUSED,
    STREAM_STATE_STOPPED,
    STREAM_STATE_UP,
    STREAM_STOP_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)

# Highest exponent used for the backoff (2 * 2**30 is far beyond any cap).
_MAX_ATTEMPT = 30
# Errors a stream normally ends with (logged at debug, not as a warning).
_EXPECTED_ERRORS = (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)

type TaskFactory = Callable[[Coroutine[Any, Any, None], str], asyncio.Task[None]]
type EventFilter = Callable[[str, dict[str, Any]], bool]


class SubscribeApi(Protocol):
    """The part of ``OpenWrtAPI`` a subscription needs."""

    def async_subscribe(
        self,
        obj: str,
        *,
        on_open: Callable[[], None] | None = None,
        stats: SseStats | None = None,
    ) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        """Yield ``(event, data)`` of one ubus object until the stream ends."""


@dataclass(frozen=True, slots=True)
class StreamItem:
    """One received event with its HA receive time (SSE has no timestamp)."""

    ts: float
    obj: str
    event: str
    data: dict[str, Any]


class UbusSubscription:
    """Keep one ubus object of one router subscribed.

    States: ``idle`` (not started), ``connecting``, ``up``, ``backoff``,
    ``no_permission``, ``not_found``, ``paused``, ``stopped``.
    """

    def __init__(
        self,
        api: SubscribeApi,
        obj: str,
        *,
        name: str | None = None,
        queue_max: int = STREAM_QUEUE_MAX,
        event_filter: EventFilter | None = None,
        notify: Callable[[], None] | None = None,
        on_state_change: Callable[[str], None] | None = None,
        backoff_initial: float = STREAM_BACKOFF_INITIAL,
        backoff_max: float = STREAM_BACKOFF_MAX,
        backoff_jitter: float = STREAM_BACKOFF_JITTER,
        backoff_reset_after: float = STREAM_BACKOFF_RESET_AFTER,
        no_permission_retry: float = STREAM_NO_PERMISSION_RETRY,
        stop_timeout: float = STREAM_STOP_TIMEOUT,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        rand: Callable[[], float] = random.random,
    ) -> None:
        """Set up the subscription; nothing runs before ``start()``.

        Args:
            api: Object with ``async_subscribe`` (``OpenWrtAPI``).
            obj: ubus object, validated like ``async_subscribe`` does.
            name: Label for logs and the task name (e.g. host plus object).
            queue_max: Bound of the event queue; the oldest event is dropped.
            event_filter: ``(event, data) -> keep``; applied before queueing.
            notify: Called (synchronously) after each queued event.
            on_state_change: Called with the new state on every change.
            backoff_initial / backoff_max / backoff_jitter /
            backoff_reset_after / no_permission_retry / stop_timeout:
                Timing, defaults from const.py.
            sleep / clock / wall_clock / rand: Injectable for tests.
        """
        if queue_max < 1:
            raise ValueError("queue_max must be at least 1")
        self._api = api
        self._obj = validate_stream_object(obj)
        self._label = name or obj
        self._queue: deque[StreamItem] = deque(maxlen=queue_max)
        self._filter = event_filter
        self._notify = notify
        self._on_state_change = on_state_change
        self._backoff_initial = backoff_initial
        self._backoff_max = backoff_max
        self._backoff_jitter = backoff_jitter
        self._backoff_reset_after = backoff_reset_after
        self._no_permission_retry = no_permission_retry
        self._stop_timeout = stop_timeout
        self._sleep = sleep
        self._clock = clock
        self._wall_clock = wall_clock
        self._rand = rand

        self._task: asyncio.Task[None] | None = None
        self._conn_task: asyncio.Task[None] | None = None
        self._items = asyncio.Event()
        self._resume = asyncio.Event()
        self._resume.set()
        self._wake = asyncio.Event()
        self._paused = False
        self._stopped = False
        self._state = STREAM_STATE_IDLE
        self._attempt = 0
        self._up_since: float | None = None
        self._permission_warned = False
        self._filter_warned = False

        self.stats = SseStats()
        self.connects = 0
        self.disconnects = 0
        self.events = 0
        self.filtered = 0
        self.dropped = 0
        self.overflow = False
        self.last_event_ts: float | None = None
        self.last_error: str | None = None
        # clock() time of the next connect attempt while waiting, else None.
        self.retry_at: float | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def obj(self) -> str:
        """The subscribed ubus object."""
        return self._obj

    @property
    def state(self) -> str:
        """Current state (see class docstring)."""
        return self._state

    @property
    def running(self) -> bool:
        """True while the subscription task exists and has not finished."""
        return self._task is not None and not self._task.done()

    @property
    def paused(self) -> bool:
        """True between ``pause()`` and ``resume()``."""
        return self._paused

    @property
    def oversize(self) -> int:
        """Events dropped by the parser because they were too large."""
        return self.stats.oversize

    @property
    def bad_json(self) -> int:
        """Events dropped by the parser because data was no JSON object."""
        return self.stats.bad_json

    @property
    def queue_len(self) -> int:
        """Events waiting in the queue."""
        return len(self._queue)

    def start(self, task_factory: TaskFactory | None = None) -> None:
        """Start the subscription task (no-op while it already runs).

        Args:
            task_factory: ``(coro, name) -> Task``. Home Assistant passes
                ``lambda c, n: entry.async_create_background_task(hass, c, n)``
                so the task is cancelled on unload and shutdown; default is a
                plain ``loop.create_task``.

        Raises:
            RuntimeError: After ``stop()`` (create a new subscription instead).
        """
        if self._stopped:
            raise RuntimeError(f"stream {self._label} was stopped")
        if self.running:
            return
        name = f"openwrt_router stream {self._label}"
        coro = self._run()
        try:
            if task_factory is None:
                self._task = asyncio.get_running_loop().create_task(coro, name=name)
            else:
                self._task = task_factory(coro, name)
        except BaseException:
            coro.close()
            raise

    async def stop(self) -> None:
        """Stop for good: cancel the task, wait for it, close the response.

        Waits at most ``stop_timeout`` seconds. Idempotent; afterwards
        nothing reconnects and ``start()`` raises.
        """
        self._stopped = True
        self._resume.set()
        self._wake.set()
        task = self._task
        if task is not None and task is not asyncio.current_task():
            if not task.done():
                task.cancel()
            done, _ = await asyncio.wait((task,), timeout=self._stop_timeout)
            if not done:
                _LOGGER.warning(
                    "OpenWrt stream %s did not stop within %ss",
                    self._label,
                    self._stop_timeout,
                )
            elif not task.cancelled() and (exc := task.exception()) is not None:
                _LOGGER.debug("OpenWrt stream %s ended with %r", self._label, exc)
        # Only left over when the runner was cancelled twice while cleaning up.
        conn = self._conn_task
        if conn is not None and not conn.done():
            conn.cancel()
            await asyncio.wait((conn,), timeout=self._stop_timeout)
        self._set_state(STREAM_STATE_STOPPED)

    def pause(self) -> None:
        """Close the stream and stay disconnected until ``resume()``.

        For the coordinator saying the router is unreachable. A running
        backoff wait ends early, except the one-hour ``no_permission`` wait.
        """
        if self._stopped or self._paused:
            return
        self._paused = True
        self._resume.clear()
        conn = self._conn_task
        if conn is not None and not conn.done():
            conn.cancel()
        if self._state != STREAM_STATE_NO_PERMISSION:
            self._wake.set()

    def resume(self) -> None:
        """Reconnect after ``pause()`` (the backoff counter is kept)."""
        if self._stopped or not self._paused:
            return
        self._paused = False
        self._resume.set()
        if self._state != STREAM_STATE_NO_PERMISSION:
            self._wake.set()

    def retry_now(self) -> None:
        """End any backoff wait now, also ``no_permission`` (after ACL deploy)."""
        if not self._stopped:
            self._wake.set()

    def drain(self, max_items: int | None = None) -> list[StreamItem]:
        """Remove and return up to ``max_items`` queued events, oldest first."""
        count = len(self._queue)
        if max_items is not None:
            count = min(count, max(0, max_items))
        items = [self._queue.popleft() for _ in range(count)]
        if not self._queue:
            self._items.clear()
        return items

    def take_overflow(self) -> bool:
        """Return whether events were dropped since the last call, and reset."""
        overflow = self.overflow
        self.overflow = False
        return overflow

    async def wait_for_items(self) -> None:
        """Return as soon as the queue holds at least one event."""
        await self._items.wait()

    def snapshot(self) -> dict[str, Any]:
        """Counters and state for diagnostics and coverage."""
        retry_in: float | None = None
        if self.retry_at is not None:
            retry_in = max(0.0, round(self.retry_at - self._clock(), 1))
        return {
            "obj": self._obj,
            "state": self._state,
            "connects": self.connects,
            "disconnects": self.disconnects,
            "events": self.events,
            "filtered": self.filtered,
            "dropped": self.dropped,
            "oversize": self.stats.oversize,
            "bad_json": self.stats.bad_json,
            "queue_len": len(self._queue),
            "overflow": self.overflow,
            "last_event_ts": self.last_event_ts,
            "last_error": self.last_error,
            "retry_in": retry_in,
        }

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _set_state(self, state: str) -> None:
        """Change the state and tell the listener."""
        if state == self._state:
            return
        _LOGGER.debug("OpenWrt stream %s: %s -> %s", self._label, self._state, state)
        self._state = state
        if self._on_state_change is not None:
            try:
                self._on_state_change(state)
            except Exception:
                # A listener must not kill the stream.
                _LOGGER.exception(
                    "OpenWrt stream %s: state listener failed", self._label
                )

    async def _run(self) -> None:
        """Connect, consume, back off; until stopped or cancelled."""
        loop = asyncio.get_running_loop()
        try:
            while not self._stopped:
                if self._paused:
                    self.retry_at = None
                    self._set_state(STREAM_STATE_PAUSED)
                    await self._resume.wait()
                    continue
                self.retry_at = None
                self._set_state(STREAM_STATE_CONNECTING)
                self._up_since = None
                conn = loop.create_task(
                    self._consume(), name=f"openwrt_router stream {self._label} conn"
                )
                self._conn_task = conn
                try:
                    await asyncio.wait((conn,))
                finally:
                    if not conn.done():
                        # We are being cancelled: end the connection too, so
                        # the HTTP response is closed before the task ends.
                        conn.cancel()
                        await asyncio.wait((conn,))
                    self._conn_task = None
                up_for: float | None = None
                if self._up_since is not None:
                    up_for = self._clock() - self._up_since
                    self.disconnects += 1
                    self._up_since = None
                if conn.cancelled():
                    continue  # pause() or stop(); the loop head decides
                await self._backoff(conn.exception(), up_for)
        finally:
            self._up_since = None
            self.retry_at = None
            self._stopped = True
            self._set_state(STREAM_STATE_STOPPED)

    async def _consume(self) -> None:
        """Run one connection until the router closes it or it fails."""
        stream = self._api.async_subscribe(
            self._obj, on_open=self._on_open, stats=self.stats
        )
        async with contextlib.aclosing(stream):  # type: ignore[type-var]
            async for event, data in stream:
                self._enqueue(event, data)

    def _on_open(self) -> None:
        """The router accepted the subscription."""
        self._up_since = self._clock()
        self.connects += 1
        self._permission_warned = False
        self._set_state(STREAM_STATE_UP)

    def _enqueue(self, event: str, data: dict[str, Any]) -> None:
        """Filter, then queue one event (dropping the oldest when full)."""
        self.events += 1
        if self._filter is not None:
            try:
                keep = self._filter(event, data)
            except Exception:
                # RT2 decision: fail closed. The filter keeps foreign MACs
                # (probes) out of HA; when it breaks, drop instead of store.
                if not self._filter_warned:
                    self._filter_warned = True
                    _LOGGER.exception(
                        "OpenWrt stream %s: event filter failed; dropping events",
                        self._label,
                    )
                keep = False
            if not keep:
                self.filtered += 1
                return
        ts = self._wall_clock()
        if len(self._queue) == self._queue.maxlen:
            self.dropped += 1
            self.overflow = True
        self._queue.append(StreamItem(ts, self._obj, event, data))
        self.last_event_ts = ts
        self._items.set()
        if self._notify is not None:
            try:
                self._notify()
            except Exception:
                # A listener must not kill the stream.
                _LOGGER.exception("OpenWrt stream %s: notify failed", self._label)

    def _next_delay(self) -> float:
        """Exponential delay with downward jitter, capped at backoff_max.

        RT2 decision: jitter only shortens the delay (by up to
        ``backoff_jitter``), so the cap of 300 s is a hard upper bound.
        """
        base = min(self._backoff_max, self._backoff_initial * 2**self._attempt)
        self._attempt = min(self._attempt + 1, _MAX_ATTEMPT)
        return base * (1.0 - self._backoff_jitter * self._rand())

    async def _backoff(self, exc: BaseException | None, up_for: float | None) -> None:
        """Pick state and delay for the end of a connection, then wait."""
        if up_for is not None and up_for >= self._backoff_reset_after:
            self._attempt = 0
        if isinstance(exc, OpenWrtStreamPermissionError):
            state = STREAM_STATE_NO_PERMISSION
            delay = float(self._no_permission_retry)
            if not self._permission_warned:
                self._permission_warned = True
                _LOGGER.warning(
                    "OpenWrt stream %s: the router session lacks the "
                    "':subscribe' ACL right; next try in %d s",
                    self._label,
                    delay,
                )
        elif isinstance(exc, OpenWrtStreamNotFoundError):
            state = STREAM_STATE_NOT_FOUND
            delay = self._next_delay()
        else:
            state = STREAM_STATE_BACKOFF
            delay = self._next_delay()
        if exc is not None:
            self.last_error = f"{type(exc).__name__}: {exc}"[:300]
            if not isinstance(exc, _EXPECTED_ERRORS):
                # Not one of the API's error types: likely a bug, show it.
                _LOGGER.warning(
                    "OpenWrt stream %s failed unexpectedly: %r", self._label, exc
                )
            else:
                _LOGGER.debug("OpenWrt stream %s ended: %s", self._label, exc)
        else:
            _LOGGER.debug("OpenWrt stream %s closed by the router", self._label)
        self.retry_at = self._clock() + delay
        self._set_state(state)
        if self._stopped or (self._paused and state != STREAM_STATE_NO_PERMISSION):
            return
        await self._wait(delay)

    async def _wait(self, delay: float) -> None:
        """Sleep ``delay`` seconds, ending early on ``_wake``."""
        if delay <= 0:
            return
        self._wake.clear()
        loop = asyncio.get_running_loop()
        sleeper = loop.create_task(self._sleep_for(delay))
        waker = loop.create_task(self._wake.wait())
        try:
            await asyncio.wait((sleeper, waker), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (sleeper, waker):
                task.cancel()
            await asyncio.wait((sleeper, waker))
            for task in (sleeper, waker):
                if not task.cancelled():
                    task.exception()  # retrieved, never raised here

    async def _sleep_for(self, delay: float) -> None:
        """Await the injected sleep (wrapped so any awaitable works)."""
        await self._sleep(delay)
