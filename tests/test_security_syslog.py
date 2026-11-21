"""Syslog receiver of the Security Center (release 1.46.0 part 2).

The receiver binds UDP on loopback only (127.0.0.1, port 0 or a port taken
by the test itself); datagrams come from a local socket or straight through
``receive``. No router, no Home Assistant instance, no foreign network.
Addresses are documentation ranges, MACs locally administered test values.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from config_manager_kit import cm_env, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_client_engine import T0, client, data, setup
from test_net_engine import FakeDisk, make_hass
from test_security_center import (
    M1,
    NO_SCHEDULE,
    RID1,
    RID2,
    _core_center,
    center_for,
    coordinator,
    disks,  # noqa: F401 - fixture
    sec_disk,
    wifi,
)

from custom_components.openwrt_router import security_center, security_syslog
from custom_components.openwrt_router.const import SEC_DEFAULT_SYSLOG_PORT
from custom_components.openwrt_router.log_parser import WIFI_PSK_MISMATCH
from custom_components.openwrt_router.security_center import (
    async_release_security_center,
    async_setup_security_center,
    default_settings,
    merge_settings,
)
from custom_components.openwrt_router.security_logsrc import MAX_LINE_BYTES
from custom_components.openwrt_router.security_syslog import (
    REASON_NOT_STARTED,
    REASON_PORT_IN_USE,
    REASON_STOPPED,
    SyslogLimits,
    SyslogReceiver,
    bind_reason,
    sender_address,
)

LOOP = "127.0.0.1"
OTHER = "192.0.2.77"
NOV18 = datetime(2026, 11, 18, 12, 0, 0, tzinfo=UTC).timestamp()
FORGED = (
    "<4>May 15 11:59:59 OpenWrt kernel: drop lan in: IN=br-lan "
    "SRC=192.168.1.66 DST=192.168.1.1 PROTO=TCP SPT=1 DPT=22"
)
IDENTIFIERS = (OTHER, "203.0.113.", "198.51.100.", "192.168.1.66", "OpenWrt")


def fw_line(i: int, ts: float = NOV18) -> bytes:
    """A firewall drop line (fw4 log prefix) dated ``ts`` in UTC."""
    wall = datetime.fromtimestamp(ts, UTC).strftime("%b %d %H:%M:%S")
    return (
        f"<4>{wall} OpenWrt kernel: drop wan in: IN=wan SRC=203.0.113.{i} "
        "DST=198.51.100.1 PROTO=TCP SPT=1 DPT=22"
    ).encode()


class Clock:
    """A settable receive clock."""

    def __init__(self, now: float = NOV18) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


def receiver(**kw: Any) -> SyslogReceiver:
    kw.setdefault("port", 0)
    kw.setdefault("host", LOOP)
    kw.setdefault("clock", Clock())
    rx = SyslogReceiver(**kw)
    rx.set_senders({LOOP: RID1})
    return rx


def loopback_factory(clock: Clock | None = None, made: list | None = None) -> Any:
    """Center factory: a receiver on 127.0.0.1, port 0 (any free port)."""

    def make(*, port: int, on_backlog: Any = None) -> SyslogReceiver:
        rx = SyslogReceiver(
            port=0, host=LOOP, clock=clock or Clock(), on_backlog=on_backlog
        )
        if made is not None:
            made.append(rx)
        return rx

    return make


async def until(check: Any, timeout: float = 3.0) -> None:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while not check():
        if loop.time() > end:
            raise AssertionError("condition not reached")
        await asyncio.sleep(0.01)


async def syslog_center(hass: Any, *, clock: Clock, made: list) -> Any:
    """An enabled center on the syslog path with a loopback receiver."""
    center = await center_for(hass, "r1", enabled=False)
    center.syslog_factory = loopback_factory(clock, made)
    center.senders_of = lambda: {LOOP: RID1}
    center.settings = merge_settings(
        center.settings, {"enabled": True, "log_path": "syslog"}
    )
    await center.async_activate()
    return center


# --- helpers of the module -------------------------------------------------------------


def test_sender_address_takes_literals_only() -> None:
    assert sender_address("192.0.2.1") == "192.0.2.1"
    assert sender_address("::ffff:192.0.2.1") == "192.0.2.1"
    assert sender_address("[2001:db8::1]") == "2001:db8::1"
    assert sender_address("fe80::1%eth0") == "fe80::1"
    for bad in ("router.lan", "", None, 42, "x" * 80, "192.0.2.300"):
        assert sender_address(bad) is None


def test_bind_reason_maps_windows_and_posix_codes() -> None:
    import errno

    assert bind_reason(OSError(errno.EADDRINUSE, "x")) == REASON_PORT_IN_USE
    win = OSError()
    win.winerror = 10048  # type: ignore[attr-defined]
    assert bind_reason(win) == REASON_PORT_IN_USE
    assert bind_reason(OSError(errno.EACCES, "x")) == "permission_denied"
    assert bind_reason(OSError(errno.EADDRNOTAVAIL, "x")) == "address_not_available"
    assert bind_reason(OSError("no code")) == "bind_failed"


# --- real socket on loopback -------------------------------------------------------------


async def test_real_datagram_on_loopback_is_received_and_closed() -> None:
    rx = receiver()
    assert not rx.listening and rx.reason == REASON_NOT_STARTED
    await rx.async_start()
    try:
        assert rx.listening and rx.reason is None
        port = rx.bound_port
        assert isinstance(port, int) and port > 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(fw_line(1), (LOOP, port))
        await until(lambda: rx.stats().received == 1)
        records = rx.drain(100)
        assert len(records) == 1
        assert records[0].router == RID1  # the allowlist's id, not the HOST field
        assert records[0].kind == "fw.drop"
        assert rx.stats().parsed == 1
    finally:
        rx.close()
    assert not rx.listening and rx.reason == REASON_STOPPED
    assert rx.bound_port is None
    rx.close()  # idempotent
    await rx.async_start()  # a closed receiver never binds again
    assert not rx.listening


async def test_unknown_sender_is_dropped_and_counted_without_state(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    rx = receiver()
    await rx.async_start()
    try:
        rx.set_senders({})  # nobody allowed: the loopback socket is unknown
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(fw_line(1), (LOOP, rx.bound_port))
        await until(lambda: rx.stats().received == 1)
        assert rx.stats().dropped_sender == 1 and rx.drain(10) == []
    finally:
        rx.close()
    rx = receiver()
    for n in range(1000):
        rx.receive(fw_line(n % 250), (f"192.0.2.{n % 250}", 514))
    rx.receive(fw_line(1), ("router.lan", 514))  # names are never resolved
    rx.receive(fw_line(1), None)
    stats = rx.stats()
    assert stats.dropped_sender == 1002 and stats.parsed == 0
    assert rx.footprint() == {"senders": 1, "buckets": 0, "buffered": 0}
    for record in caplog.records:
        text = record.getMessage()
        assert not any(i in text for i in IDENTIFIERS), text


def test_allowlist_leaves_out_ambiguous_and_invalid_entries() -> None:
    rx = receiver()
    rx.set_senders(
        {
            "192.0.2.1": RID1,
            "::ffff:192.0.2.1": RID2,  # same address for two routers
            "192.0.2.2": RID2,
            "router.lan": RID1,
            "192.0.2.3": "not-a-router-id",
        }
    )
    assert rx.router_ids == frozenset({RID2})
    rx.receive(fw_line(1), ("192.0.2.1", 514))
    rx.receive(fw_line(2), ("192.0.2.2", 514))
    assert rx.stats().dropped_sender == 1
    assert [r.router for r in rx.drain(10)] == [RID2]


def test_overlong_line_is_cut_and_counted() -> None:
    rx = receiver()
    line = fw_line(1) + b" " + b"A" * (5 * MAX_LINE_BYTES)
    rx.receive(line, (LOOP, 514))
    stats = rx.stats()
    assert stats.truncated == 1 and stats.received == 1
    records = rx.drain(10)
    assert len(records) <= 1
    text = repr(records) + repr(rx)
    assert "A" * MAX_LINE_BYTES not in text


def test_rate_limits_per_sender_and_in_total() -> None:
    clock = Clock()
    rx = receiver(
        clock=clock,
        limits=SyslogLimits(
            sender_rate=0.0, sender_burst=5, total_rate=0.0, total_burst=8
        ),
    )
    rx.set_senders({LOOP: RID1, "192.0.2.2": RID2})
    for n in range(10):
        rx.receive(fw_line(n), (LOOP, 514))
    assert rx.stats().dropped_rate == 5
    for n in range(10):
        rx.receive(fw_line(100 + n), ("192.0.2.2", 514))
    stats = rx.stats()
    assert stats.dropped_rate == 5 + 7  # the total bucket had three left
    assert len(rx.drain(100)) == 8


def test_rate_refills_with_time_and_ignores_a_clock_going_back() -> None:
    clock = Clock()
    rx = receiver(
        clock=clock,
        limits=SyslogLimits(
            sender_rate=1.0, sender_burst=2, total_rate=100.0, total_burst=100
        ),
    )
    for n in range(3):
        rx.receive(fw_line(n), (LOOP, 514))
    assert rx.stats().dropped_rate == 1
    clock.now -= 3600  # back: no refill, no crash
    rx.receive(fw_line(5), (LOOP, 514))
    assert rx.stats().dropped_rate == 2
    clock.now = NOV18 + 10
    rx.receive(fw_line(6), (LOOP, 514))
    assert rx.stats().dropped_rate == 2


def test_buffer_is_bounded() -> None:
    rx = receiver(
        limits=SyslogLimits(
            sender_burst=1000, total_burst=1000, buffer_max=4, drain_at=4
        )
    )
    for n in range(10):
        rx.receive(fw_line(n), (LOOP, 514))
    assert rx.stats().dropped_buffer == 6
    assert rx.footprint()["buffered"] == 4
    assert len(rx.drain(2)) == 2 and len(rx.drain(100)) == 2


async def test_backlog_wakes_the_drain_once() -> None:
    calls: list[int] = []
    rx = receiver(
        on_backlog=lambda: calls.append(1),
        limits=SyslogLimits(sender_burst=100, total_burst=100, drain_at=3),
    )
    for n in range(6):
        rx.receive(fw_line(n), (LOOP, 514))
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert calls == [1]


def test_a_throwing_parser_never_leaves_the_receiver() -> None:
    rx = receiver()
    with patch.object(
        security_syslog, "parse_remote_line", side_effect=RuntimeError("boom")
    ):
        rx.receive(fw_line(1), (LOOP, 514))
    assert rx.status()["errors"]["errors"] == 1
    rx.receive(b"\xff\xfe\x00 garbage", (LOOP, 514))
    rx.receive(b"", (LOOP, 514))
    assert rx.stats().received == 3


async def test_future_line_cannot_poison_the_marks(disks) -> None:  # noqa: F811
    """A forged line dated into the future moves no mark and no count."""
    hass = make_hass()
    center = await center_for(hass, "r1")
    clock = Clock()
    rx = receiver(clock=clock, tz_offset_of=lambda _rid: 0.0)
    center.syslog = rx
    rx.receive(FORGED.encode(), (LOOP, 514))
    assert rx.stats().ts_future == 1
    center._drain_from(rx)
    hwm = center.deduper.hwm(RID1)
    assert hwm is None or hwm <= NOV18 + center.deduper.max_future_s
    assert center._fw_events.total(NOV18) == 0  # a future line is not counted
    for i in range(1, 6):
        clock.now = NOV18 + i
        rx.receive(fw_line(i, NOV18 + i), (LOOP, 514))
    center._drain_from(rx)
    assert center._fw_events.total(clock.now) == 5  # real lines still pass
    assert center.counters["log_records"] == 6


# --- the center: on/off, bind errors, path switch ---------------------------------------


async def test_default_off_opens_no_socket(disks) -> None:  # noqa: F811
    hass = make_hass()
    factory = MagicMock()
    with patch.object(security_center, "SyslogReceiver", factory):
        entry = SimpleNamespace(entry_id="r1")
        center = await async_setup_security_center(hass, entry, coordinator())
        assert not center.enabled and center.syslog is None
        # syslog chosen, center off: still no socket
        center.settings = merge_settings(center.settings, {"log_path": "syslog"})
        await center.async_sync_log_source()
        # center on, path off: no socket
        center.settings = merge_settings(
            center.settings, {"enabled": True, "log_path": "off"}
        )
        await center.async_activate()
        assert center.active and center.syslog is None
        await async_release_security_center(hass, "r1")
    factory.assert_not_called()


async def test_bind_error_is_not_available_and_setup_goes_on(
    disks,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    blocker.bind((LOOP, 0))
    port = blocker.getsockname()[1]
    try:
        sec_disk(disks).data = {
            "settings": {
                **default_settings(),
                "enabled": True,
                "log_path": "syslog",
                "syslog_port": port,
            }
        }

        def factory(*, port: int, on_backlog: Any = None) -> SyslogReceiver:
            return SyslogReceiver(port=port, host=LOOP, on_backlog=on_backlog)

        hass = make_hass()
        with (
            patch.object(security_center, "SyslogReceiver", factory),
            caplog.at_level(logging.DEBUG),
        ):
            entry = SimpleNamespace(entry_id="r1")
            center = await async_setup_security_center(hass, entry, coordinator())
        assert center.active and center.enabled
        rx = center.syslog
        assert rx is not None and not rx.listening
        assert rx.reason == REASON_PORT_IN_USE
        assert center.counters["syslog_starts"] == 1
        view = center.detections_view(now=NOV18)
        assert view["log_path"]["receiver"]["reason"] == REASON_PORT_IN_USE
        reasons = {
            s["reason"]
            for s in view["log_path"]["status"]
            if s["availability"] == "not_available"
        }
        assert REASON_PORT_IN_USE in reasons
        warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(str(port) in r.getMessage() for r in warnings)
        await async_release_security_center(hass, "r1")
    finally:
        blocker.close()


async def test_path_switch_closes_the_socket_and_sends_nothing_twice(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    clock = Clock()
    made: list[SyslogReceiver] = []
    center = await syslog_center(hass, clock=clock, made=made)
    first = center.syslog
    assert first is not None and first.listening and first.router_ids == {RID1}
    lines = [fw_line(i, NOV18 + i) for i in range(1, 11)]
    for i, line in enumerate(lines, start=1):
        clock.now = NOV18 + i
        first.receive(line, (LOOP, 514))
    center._drain_logs()
    assert center.counters["log_records"] == 10

    center.settings = merge_settings(center.settings, {"log_path": "collector"})
    await center.async_sync_log_source()
    assert center.syslog is None and not first.listening  # socket closed

    center.settings = merge_settings(center.settings, {"log_path": "syslog"})
    await center.async_sync_log_source()
    second = center.syslog
    assert second is not None and second is not first and second.listening
    clock.now = NOV18 + 20
    for line in lines:  # the router re-sends its ring after the switch
        second.receive(line, (LOOP, 514))
    second.receive(fw_line(99, NOV18 + 20), (LOOP, 514))
    center._drain_logs()
    assert center.counters["log_records"] == 11  # only the new line
    assert center.deduper.stats().to_dict()["dup_seen"] >= 10

    # a port change restarts the receiver; turning off closes it
    center.settings = merge_settings(center.settings, {"syslog_port": 15514})
    await center.async_sync_log_source()
    assert not second.listening and center.syslog is not second
    third = center.syslog
    center.settings = merge_settings(center.settings, {"enabled": False})
    center.deactivate()
    assert center.syslog is None and not third.listening
    assert [rx.listening for rx in made] == [False, False, False]


async def test_unload_of_the_last_entry_closes_the_socket(disks) -> None:  # noqa: F811
    sec_disk(disks).data = {
        "settings": {**default_settings(), "enabled": True, "log_path": "syslog"}
    }
    made: list[SyslogReceiver] = []
    hass = make_hass()
    with patch.object(security_center, "SyslogReceiver", loopback_factory(None, made)):
        center = await async_setup_security_center(
            hass, SimpleNamespace(entry_id="r1"), coordinator()
        )
        await async_setup_security_center(
            hass, SimpleNamespace(entry_id="r2"), coordinator()
        )
    assert center.syslog is not None and center.syslog.listening
    assert center.syslog.port == 0 and center._syslog_port == SEC_DEFAULT_SYSLOG_PORT
    await async_release_security_center(hass, "r1")
    assert center.syslog is not None and center.syslog.listening  # one entry left
    await async_release_security_center(hass, "r2")
    assert center.syslog is None and [rx.listening for rx in made] == [False]


async def test_throwing_receiver_or_drain_keeps_the_poll(
    disks,  # noqa: F811
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    clock = Clock()
    center = await syslog_center(hass, clock=clock, made=[])
    broken = MagicMock()
    broken.drain.side_effect = RuntimeError(f"bad {OTHER}")
    broken.listening = True
    broken.router_ids = frozenset({RID1})
    center.syslog.close()
    center.syslog = broken
    with caplog.at_level(logging.DEBUG):
        stored = engine.ingest(
            "r1",
            data([client(M1)], (wifi(WIFI_PSK_MISMATCH, 1),)),
            T0,
            interval=60,
        )
    assert stored == 1  # network intelligence stored its event
    assert cs.history.live(M1) is not None  # client stability got the poll
    assert center.counters["polls"] == 1 and center.counters["errors"] >= 1
    for record in caplog.records:
        if record.levelno >= logging.WARNING:
            assert OTHER not in record.getMessage()
    # a factory that throws: the center stays on without a receiver
    center.syslog = None
    center.syslog_factory = MagicMock(side_effect=OSError("no"))
    await center.async_sync_log_source()
    assert center.active and center.syslog is None
    center.deactivate()


async def test_a_receiver_that_did_not_bind_is_retried_from_the_poll(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    center = await syslog_center(hass, clock=Clock(), made=[])
    rx = center.syslog
    rx.close()  # as if the socket was lost
    assert not rx.listening
    hass.async_create_task = MagicMock(side_effect=lambda coro, **kw: coro.close())
    center._maybe_retry_syslog()
    hass.async_create_task.assert_not_called()  # too early
    center._syslog_tried = -1e9
    center._maybe_retry_syslog()
    hass.async_create_task.assert_called_once()
    await center.async_sync_log_source()  # what the task runs
    assert center.syslog is not rx and center.syslog.listening
    center.deactivate()


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


async def test_allowlist_comes_from_the_router_registry(core_disks, tmp_path) -> None:
    env = await cm_env(core_disks, tmp_path, routers=2, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    senders = center._registry_senders()
    assert senders == {"192.168.1.1": env.rids[0], "192.168.1.2": env.rids[1]}
    center.remove_entry(env.entries[1].entry_id)  # unloaded: no longer allowed
    assert center._registry_senders() == {"192.168.1.1": env.rids[0]}
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)
