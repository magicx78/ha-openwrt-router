"""Tests for ubus_stream.UbusSubscription (RT2).

A fake API scripts each connection (events, then close / error / block); a
fake clock and sleep make the backoff deterministic. No network.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

import pytest
from test_api_stream import PROBE, FakeResponse, json_body, make_api, sse

from custom_components.openwrt_router.api import (
    OpenWrtConnectionError,
    OpenWrtStreamNotFoundError,
    OpenWrtStreamPermissionError,
    OpenWrtTimeoutError,
    SseStats,
)
from custom_components.openwrt_router.const import (
    STREAM_BACKOFF_MAX,
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
)
from custom_components.openwrt_router.ubus_stream import StreamItem, UbusSubscription

OBJ = "hostapd.phy0-ap0"


# =====================================================================
# Fakes
# =====================================================================


@dataclass
class Conn:
    """One scripted connection: events, optional up time, then how it ends."""

    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    hold: float = 0.0  # fake seconds the connection stays up
    end: BaseException | None = None  # raised after the events
    block: bool = False  # stay open until cancelled


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeSleep:
    """Records delays; returns at once, or waits for release() when gated."""

    def __init__(self, clock: FakeClock, *, gated: bool = False) -> None:
        self.clock = clock
        self.gated = gated
        self.delays: list[float] = []
        self._gate = asyncio.Event()
        self.waiting = 0

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)
        if self.gated:
            self.waiting += 1
            try:
                await self._gate.wait()
            finally:
                self.waiting -= 1
            self._gate.clear()
        else:
            await asyncio.sleep(0)
        self.clock.now += delay

    def release(self) -> None:
        self._gate.set()


class FakeApi:
    """Scripted ``async_subscribe``; tracks open connections."""

    def __init__(self, script: list[Conn | BaseException], clock: FakeClock) -> None:
        self.script = list(script)
        self.clock = clock
        self.calls = 0
        self.active = 0
        self.closed = 0

    async def async_subscribe(
        self,
        obj: str,
        *,
        on_open: Callable[[], None] | None = None,
        stats: SseStats | None = None,
    ) -> AsyncIterator[tuple[str, dict[str, Any]]]:
        self.calls += 1
        step = self.script.pop(0) if self.script else Conn(block=True)
        if isinstance(step, BaseException):
            raise step
        self.active += 1
        try:
            assert on_open is not None
            on_open()
            for item in step.events:
                await asyncio.sleep(0)
                yield item
            self.clock.now += step.hold
            if step.end is not None:
                raise step.end
            if step.block:
                await asyncio.Event().wait()
        finally:
            self.active -= 1
            self.closed += 1


async def until(cond: Callable[[], bool], timeout: float = 2.0) -> None:
    """Let the loop run until ``cond()`` holds."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not cond():
        if loop.time() > deadline:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.001)


def stream_tasks() -> list[asyncio.Task[Any]]:
    return [
        t
        for t in asyncio.all_tasks()
        if t.get_name().startswith("openwrt_router stream") and not t.done()
    ]


def make_sub(
    script: list[Conn | BaseException],
    *,
    gated: bool = False,
    rand: Callable[[], float] = lambda: 0.0,
    **kw: Any,
) -> tuple[UbusSubscription, FakeApi, FakeSleep, list[str]]:
    clock = FakeClock()
    sleep = FakeSleep(clock, gated=gated)
    api = FakeApi(script, clock)
    states: list[str] = []
    sub = UbusSubscription(
        api,
        OBJ,
        name=f"gw {OBJ}",
        sleep=sleep,
        clock=clock,
        wall_clock=lambda: 1_700_000_000.0,
        rand=rand,
        on_state_change=states.append,
        **kw,
    )
    return sub, api, sleep, states


# =====================================================================
# Reconnect and backoff
# =====================================================================


class TestReconnect:
    async def test_stream_abort_then_automatic_reconnect(self) -> None:
        sub, api, sleep, states = make_sub(
            [
                Conn(events=[("assoc", {"a": 1})], end=OpenWrtConnectionError("reset")),
                Conn(events=[("disassoc", {"a": 2})], block=True),
            ]
        )
        sub.start()
        await until(lambda: api.calls == 2 and sub.queue_len == 2)

        assert sub.state == STREAM_STATE_UP
        assert sub.connects == 2
        assert sub.disconnects == 1
        assert sleep.delays == [2.0]
        assert "OpenWrtConnectionError" in (sub.last_error or "")
        assert [i.event for i in sub.drain()] == ["assoc", "disassoc"]
        assert states[:4] == [
            STREAM_STATE_CONNECTING,
            STREAM_STATE_UP,
            STREAM_STATE_BACKOFF,
            STREAM_STATE_CONNECTING,
        ]
        await sub.stop()

    async def test_server_close_reconnects(self) -> None:
        sub, api, sleep, _ = make_sub([Conn(events=[("probe", {})]), Conn(block=True)])
        sub.start()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2.0]
        assert sub.disconnects == 1
        await sub.stop()

    async def test_exponential_backoff_capped_at_300(self) -> None:
        sub, api, sleep, _ = make_sub([OpenWrtConnectionError("down")] * 10)
        sub.start()
        await until(lambda: api.calls == 11 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]
        assert max(sleep.delays) == STREAM_BACKOFF_MAX
        assert sub.connects == 1
        assert sub.disconnects == 0
        await sub.stop()

    @pytest.mark.parametrize("seed", [1, 2, 3])
    async def test_jitter_bounds(self, seed: int) -> None:
        sub, api, sleep, _ = make_sub(
            [OpenWrtTimeoutError("t")] * 10, rand=random.Random(seed).random
        )
        sub.start()
        await until(lambda: api.calls == 11)
        bases = [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]
        for delay, base in zip(sleep.delays, bases, strict=True):
            assert 0.8 * base <= delay <= base
        assert len(set(sleep.delays)) > 1  # jitter actually varies
        await sub.stop()

    async def test_jitter_extremes(self) -> None:
        sub, api, sleep, _ = make_sub(
            [OpenWrtTimeoutError("t")] * 2, rand=lambda: 0.999999
        )
        sub.start()
        await until(lambda: api.calls == 3)
        assert sleep.delays[0] == pytest.approx(1.6, abs=1e-4)
        assert sleep.delays[1] == pytest.approx(3.2, abs=1e-4)
        await sub.stop()

    async def test_backoff_resets_after_stable_120s(self) -> None:
        err = OpenWrtConnectionError
        sub, api, sleep, _ = make_sub(
            [
                err("1"),
                err("2"),
                Conn(hold=130),  # stable >= 120 s -> reset
                err("3"),
                Conn(hold=60),  # short -> keeps growing
                err("4"),
            ]
        )
        sub.start()
        await until(lambda: api.calls == 7 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2, 4, 2, 4, 8, 16]
        await sub.stop()

    async def test_unexpected_exception_backs_off_and_continues(self) -> None:
        sub, api, sleep, _ = make_sub([RuntimeError("bug")])
        sub.start()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2.0]
        assert "RuntimeError" in (sub.last_error or "")
        await sub.stop()


class TestErrorStates:
    async def test_no_permission_waits_3600(self) -> None:
        sub, api, sleep, states = make_sub(
            [OpenWrtStreamPermissionError("-13")], gated=True
        )
        sub.start()
        await until(lambda: sleep.waiting == 1)
        assert sub.state == STREAM_STATE_NO_PERMISSION
        assert sleep.delays == [STREAM_NO_PERMISSION_RETRY]
        assert sub.snapshot()["retry_in"] == STREAM_NO_PERMISSION_RETRY
        # pause/resume must not cut the hour short (no retry storm)
        sub.pause()
        sub.resume()
        await asyncio.sleep(0.01)
        assert api.calls == 1
        sleep.release()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        assert STREAM_STATE_NO_PERMISSION in states
        await sub.stop()

    async def test_no_permission_retry_now_after_acl_deploy(self) -> None:
        sub, api, sleep, _ = make_sub([OpenWrtStreamPermissionError("-13")], gated=True)
        sub.start()
        await until(lambda: sleep.waiting == 1)
        sub.retry_now()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        await sub.stop()

    async def test_no_permission_does_not_grow_backoff(self) -> None:
        sub, api, sleep, _ = make_sub(
            [OpenWrtStreamPermissionError("-13")] * 3 + [OpenWrtConnectionError("x")]
        )
        sub.start()
        await until(lambda: api.calls == 5)
        assert sleep.delays == [3600, 3600, 3600, 2]
        await sub.stop()

    async def test_not_found_backs_off(self) -> None:
        sub, api, sleep, states = make_sub(
            [OpenWrtStreamNotFoundError("404"), OpenWrtStreamNotFoundError("404")]
        )
        sub.start()
        await until(lambda: api.calls == 3 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2, 4]
        assert STREAM_STATE_NOT_FOUND in states
        assert STREAM_STATE_BACKOFF not in states
        await sub.stop()


# =====================================================================
# Queue
# =====================================================================


class TestQueue:
    async def test_bounded_queue_drops_oldest_and_counts(self) -> None:
        events = [("assoc", {"n": n}) for n in range(5)]
        sub, _api, _, _ = make_sub([Conn(events=events, block=True)], queue_max=3)
        sub.start()
        await until(lambda: sub.events == 5)
        assert sub.dropped == 2
        assert sub.overflow is True
        assert sub.take_overflow() is True
        assert sub.take_overflow() is False
        items = sub.drain()
        assert [i.data["n"] for i in items] == [2, 3, 4]
        assert all(isinstance(i, StreamItem) and i.obj == OBJ for i in items)
        assert items[0].ts == 1_700_000_000.0
        assert sub.last_event_ts == 1_700_000_000.0
        assert sub.queue_len == 0
        await sub.stop()

    async def test_default_queue_bound(self) -> None:
        sub, _, _, _ = make_sub([])
        assert sub._queue.maxlen == STREAM_QUEUE_MAX == 512

    async def test_drain_max_items_and_wait_for_items(self) -> None:
        notified: list[int] = []
        sub, _api, _, _ = make_sub(
            [Conn(events=[("a", {}), ("b", {}), ("c", {})], block=True)],
            notify=lambda: notified.append(1),
        )
        waiter = asyncio.create_task(sub.wait_for_items())
        await asyncio.sleep(0)
        assert not waiter.done()
        sub.start()
        await asyncio.wait_for(waiter, 1)
        await until(lambda: sub.queue_len == 3)
        assert len(notified) == 3
        assert [i.event for i in sub.drain(2)] == ["a", "b"]
        assert [i.event for i in sub.drain(5)] == ["c"]
        assert sub.drain() == []
        blocked = asyncio.create_task(sub.wait_for_items())
        await asyncio.sleep(0.01)
        assert not blocked.done()  # event cleared once the queue is empty
        blocked.cancel()
        await sub.stop()

    async def test_filter_drops_events(self) -> None:
        events = [("probe", {}), ("assoc", {}), ("probe", {}), ("disassoc", {})]
        sub, _, _, _ = make_sub(
            [Conn(events=events, block=True)],
            event_filter=lambda event, data: event != "probe",
        )
        sub.start()
        await until(lambda: sub.events == 4)
        assert [i.event for i in sub.drain()] == ["assoc", "disassoc"]
        assert sub.filtered == 2
        assert sub.dropped == 0
        await sub.stop()

    async def test_failing_filter_fails_closed(self) -> None:
        def _bad(event: str, data: dict[str, Any]) -> bool:
            raise KeyError("address")

        sub, _, _, _ = make_sub(
            [Conn(events=[("probe", {}), ("assoc", {})], block=True)], event_filter=_bad
        )
        sub.start()
        await until(lambda: sub.events == 2)
        assert sub.queue_len == 0
        assert sub.filtered == 2
        assert sub.state == STREAM_STATE_UP  # stream keeps running
        await sub.stop()

    async def test_failing_listeners_do_not_kill_stream(self) -> None:
        def _boom(*_a: Any) -> None:
            raise RuntimeError("listener")

        clock = FakeClock()
        api = FakeApi([Conn(events=[("a", {})], block=True)], clock)
        sub = UbusSubscription(
            api, OBJ, notify=_boom, on_state_change=_boom, sleep=FakeSleep(clock)
        )
        sub.start()
        await until(lambda: sub.queue_len == 1)
        assert sub.state == STREAM_STATE_UP
        await sub.stop()


# =====================================================================
# Stop, pause, start
# =====================================================================


class TestLifecycle:
    async def test_stop_cancels_cleanly_and_is_idempotent(self) -> None:
        sub, api, _, states = make_sub([Conn(events=[("a", {})], block=True)])
        sub.start()
        await until(lambda: sub.state == STREAM_STATE_UP)
        assert api.active == 1
        assert stream_tasks()

        await sub.stop()

        assert api.active == 0  # generator finalised -> response closed
        assert sub.state == STREAM_STATE_STOPPED
        assert not sub.running
        assert stream_tasks() == []
        assert states[-1] == STREAM_STATE_STOPPED
        await sub.stop()  # idempotent
        assert sub.state == STREAM_STATE_STOPPED
        calls = api.calls
        await asyncio.sleep(0.02)
        assert api.calls == calls  # nothing reconnects
        with pytest.raises(RuntimeError):
            sub.start()

    async def test_stop_during_backoff(self) -> None:
        sub, api, sleep, _ = make_sub([OpenWrtConnectionError("x")], gated=True)
        sub.start()
        await until(lambda: sleep.waiting == 1)
        await sub.stop()
        assert sub.state == STREAM_STATE_STOPPED
        assert stream_tasks() == []
        assert sleep.waiting == 0
        await asyncio.sleep(0.02)
        assert api.calls == 1

    async def test_stop_before_start(self) -> None:
        sub, api, _, _ = make_sub([])
        assert sub.state == STREAM_STATE_IDLE
        await sub.stop()
        assert sub.state == STREAM_STATE_STOPPED
        assert api.calls == 0

    async def test_stop_right_after_start(self) -> None:
        sub, api, _, _ = make_sub([])
        sub.start()
        await sub.stop()
        assert stream_tasks() == []
        assert api.active == 0

    async def test_stop_timeout_is_bounded(self) -> None:
        """A connection that ignores cancellation cannot hang stop()."""

        class StubbornApi(FakeApi):
            async def async_subscribe(self, obj: str, **kw: Any):  # type: ignore[override]
                kw["on_open"]()
                for _ in range(3):  # ignores two cancels, then gives up
                    try:
                        await asyncio.sleep(0.2)
                    except asyncio.CancelledError:
                        continue
                raise asyncio.CancelledError
                yield ("never", {})  # pragma: no cover

        clock = FakeClock()
        api = StubbornApi([], clock)
        sub = UbusSubscription(api, OBJ, stop_timeout=0.05, sleep=FakeSleep(clock))
        sub.start()
        await until(lambda: sub.state == STREAM_STATE_UP)
        loop = asyncio.get_running_loop()
        started = loop.time()
        await sub.stop()
        assert loop.time() - started < 0.5
        assert sub.state == STREAM_STATE_STOPPED
        # The stubborn connection gives up on its own shortly after.
        await until(lambda: stream_tasks() == [])

    async def test_start_twice_is_noop_and_task_factory(self) -> None:
        names: list[str] = []

        def factory(coro: Any, name: str) -> asyncio.Task[None]:
            names.append(name)
            return asyncio.get_running_loop().create_task(coro, name=name)

        sub, api, _, _ = make_sub([Conn(block=True)])
        sub.start(factory)
        sub.start(factory)
        await until(lambda: sub.state == STREAM_STATE_UP)
        assert names == [f"openwrt_router stream gw {OBJ}"]
        assert api.calls == 1
        await sub.stop()

    async def test_external_cancel_like_ha_unload(self) -> None:
        """HA cancels the background task itself on unload/shutdown."""
        tasks: list[asyncio.Task[None]] = []

        def factory(coro: Any, name: str) -> asyncio.Task[None]:
            task = asyncio.get_running_loop().create_task(coro, name=name)
            tasks.append(task)
            return task

        sub, api, _, _ = make_sub([Conn(block=True)])
        sub.start(factory)
        await until(lambda: sub.state == STREAM_STATE_UP)
        tasks[0].cancel()
        await asyncio.wait(tasks)
        assert api.active == 0
        assert sub.state == STREAM_STATE_STOPPED
        assert stream_tasks() == []
        await sub.stop()  # still fine afterwards

    async def test_pause_and_resume_while_up(self) -> None:
        sub, api, sleep, _states = make_sub([Conn(block=True), Conn(block=True)])
        sub.start()
        await until(lambda: sub.state == STREAM_STATE_UP)
        sub.pause()
        await until(lambda: sub.state == STREAM_STATE_PAUSED)
        assert api.active == 0
        assert sub.disconnects == 1
        await asyncio.sleep(0.02)
        assert api.calls == 1  # no reconnect while paused
        sub.resume()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == []  # pause is no failure: no backoff
        await sub.stop()

    async def test_pause_during_backoff_then_resume_connects_now(self) -> None:
        sub, api, sleep, _ = make_sub([OpenWrtConnectionError("x")], gated=True)
        sub.start()
        await until(lambda: sleep.waiting == 1)
        sub.pause()
        await until(lambda: sub.state == STREAM_STATE_PAUSED)
        assert sleep.waiting == 0
        sub.resume()
        await until(lambda: api.calls == 2 and sub.state == STREAM_STATE_UP)
        await sub.stop()

    async def test_pause_before_start_and_after_stop(self) -> None:
        sub, api, _, _ = make_sub([])
        sub.pause()
        sub.start()
        await until(lambda: sub.state == STREAM_STATE_PAUSED)
        assert api.calls == 0
        await sub.stop()
        sub.resume()  # no effect after stop
        sub.retry_now()
        await asyncio.sleep(0.01)
        assert api.calls == 0

    def test_invalid_arguments(self) -> None:
        clock = FakeClock()
        api = FakeApi([], clock)
        with pytest.raises(ValueError):
            UbusSubscription(api, "hostapd-auth")
        with pytest.raises(ValueError):
            UbusSubscription(api, "a/b")
        with pytest.raises(ValueError):
            UbusSubscription(api, OBJ, queue_max=0)

    async def test_snapshot(self) -> None:
        sub, _, _, _ = make_sub([Conn(events=[("a", {})], block=True)])
        sub.start()
        await until(lambda: sub.queue_len == 1)
        snap = sub.snapshot()
        assert snap["obj"] == OBJ
        assert snap["state"] == STREAM_STATE_UP
        assert snap["connects"] == 1
        assert snap["events"] == 1
        assert snap["queue_len"] == 1
        assert snap["retry_in"] is None
        assert set(snap) >= {"dropped", "oversize", "bad_json", "last_error"}
        await sub.stop()


# =====================================================================
# Together with the real OpenWrtAPI (fake HTTP session)
# =====================================================================


class TestWithRealApi:
    async def test_states_follow_http_answers_and_stop_closes(self) -> None:
        big = b'data: {"x":"' + b"y" * 70000 + b'"}\n\n'
        responses: list[FakeResponse | BaseException] = [
            sse(PROBE, big, b"data: nope\n\n"),  # 1 event, then closed by router
            FakeResponse(status=404),  # object gone (hostapd reload)
            json_body(b'{"code":-13,"message":"Permission denied"}'),
            json_body(b'{"code":-13,"message":"Permission denied"}'),
        ]
        last = sse(PROBE, block=True)
        responses.append(last)
        api, session = make_api(responses)

        async def _login() -> bool:
            api._token = "c" * 32
            return True

        api.login = _login  # type: ignore[method-assign]
        clock = FakeClock()
        sleep = FakeSleep(clock)
        states: list[str] = []
        sub = UbusSubscription(
            api,
            OBJ,
            sleep=sleep,
            clock=clock,
            rand=lambda: 0.0,
            on_state_change=states.append,
        )
        sub.start()
        await until(lambda: len(session.calls) == 5 and sub.state == STREAM_STATE_UP)
        assert sleep.delays == [2, 4, 3600]
        assert STREAM_STATE_NOT_FOUND in states
        assert STREAM_STATE_NO_PERMISSION in states
        assert sub.connects == 2
        assert sub.oversize == 1
        assert sub.bad_json == 1
        assert [i.event for i in sub.drain()] == ["probe", "probe"]
        assert not last.closed
        await sub.stop()
        assert last.closed
        assert stream_tasks() == []
