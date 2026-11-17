"""Tests for the read-only poll hook of net_engine.py (client stability B2).

``NetIntelligence.add_poll_observer`` hands every ingested poll to observers
as an immutable ``PollFacts``. Observers must never change what the engine
does: errors are logged and swallowed per observer, nothing is re-read.
"""

from __future__ import annotations

import dataclasses
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_net_engine import (
    MAC1,
    MAC2,
    MS0,
    T0,
    FakeDisk,
    FakeStore,
    engine_for,
    make_hass,
    poll,
    wifi,
)

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.log_parser import (
    WIFI_CONNECTED,
    WIFI_DISCONNECTED,
    WIFI_PSK_MISMATCH,
)
from custom_components.openwrt_router.net_engine import PollFacts

IFACES = [{"ifname": "phy1-ap0", "ssid": "Test", "band": "5g", "phy": "phy1"}]


@pytest.fixture
def disk() -> Any:
    store = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(store, *a, **kw)):
        yield store


class Recorder:
    def __init__(self) -> None:
        self.polls: list[PollFacts] = []
        self.shifts: list[float] = []
        self.removed: list[str] = []

    def on_poll(self, facts: PollFacts) -> None:
        self.polls.append(facts)

    def on_clock_shift(self, delta: float) -> None:
        self.shifts.append(delta)

    def on_router_removed(self, router: str) -> None:
        self.removed.append(router)


class Broken(Recorder):
    def on_poll(self, facts: PollFacts) -> None:
        raise RuntimeError("observer bug")


def data_with(events=(), clients=None, **kw) -> SimpleNamespace:
    data = poll(tuple(events), **kw)
    data.ap_interfaces = IFACES
    data.clients = clients
    data.log_status = "ok"
    return data


def client(mac: str, signal: int = -55) -> dict[str, Any]:
    return {"mac": mac, "radio": "phy1-ap0", "signal": signal, "ip": None}


@pytest.mark.asyncio
async def test_observer_gets_the_facts_of_each_new_poll(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    engine.add_poll_observer(rec)
    data = data_with(
        (wifi(WIFI_CONNECTED, 1, MAC2), wifi(WIFI_PSK_MISMATCH, 2)),
        clients=[client(MAC2)],
    )
    engine.ingest("r1", data, T0, interval=60.0)
    engine.ingest("r1", data, T0 + 60)  # same data object: not again
    [facts] = rec.polls
    assert facts.router == "r1"
    assert facts.now == T0
    assert facts.interval == 60.0
    assert facts.fresh_clients
    assert set(facts.context.clients) == {MAC2.upper()}
    assert [line.kind for line in facts.wifi_lines] == [
        WIFI_CONNECTED,
        WIFI_PSK_MISMATCH,
    ]
    assert facts.log_ok
    assert [e.kind for e in facts.stored_events] == ["wifi.psk_mismatch"]
    # the first failure of a client is a new attempt
    assert facts.auth_attempts == frozenset({facts.stored_events[0].id})
    assert facts.down_routers == frozenset()
    assert facts.auth_failed == frozenset()
    assert facts.loc.get(MAC2.upper()) == "r1"
    with pytest.raises(dataclasses.FrozenInstanceError):
        facts.router = "x"  # type: ignore[misc]


@pytest.mark.asyncio
async def test_baseline_read_gives_no_lines_and_no_list_is_not_fresh(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    engine.add_poll_observer(rec)
    engine.ingest("r1", data_with((wifi(WIFI_DISCONNECTED, 1),), baseline=True), T0)
    [facts] = rec.polls
    assert facts.wifi_lines == ()
    assert not facts.fresh_clients
    assert facts.context.clients is None
    assert facts.interval > 0  # default when the caller gives none


@pytest.mark.asyncio
async def test_failing_observer_changes_nothing(
    disk: FakeDisk, caplog: pytest.LogCaptureFixture
) -> None:
    hass = make_hass()
    plain = await engine_for(hass, "r1")
    expected = plain.ingest("r1", data_with((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    await net_engine.async_unload_net_intelligence(hass, "r1")

    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    engine.add_poll_observer(Broken())
    engine.add_poll_observer(rec)
    with caplog.at_level(logging.WARNING, logger=net_engine.__name__):
        stored = engine.ingest("r1", data_with((wifi(WIFI_PSK_MISMATCH, 1),)), T0)
    assert stored == expected
    assert len(rec.polls) == 1  # the next observer still ran
    assert "poll observer" in caplog.text
    assert MAC1 not in caplog.text and MAC1.upper() not in caplog.text


@pytest.mark.asyncio
async def test_unsubscribe_stops_the_calls(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    unsub = engine.add_poll_observer(rec)
    unsub()
    unsub()  # twice is harmless
    engine.ingest("r1", data_with(), T0)
    assert rec.polls == []


@pytest.mark.asyncio
async def test_clock_jump_back_and_router_removal_are_forwarded(
    disk: FakeDisk,
) -> None:
    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    engine.add_poll_observer(rec)
    engine.ingest("r1", data_with(), T0)
    engine.ingest("r1", data_with(), T0 - 86_400)
    assert rec.shifts == [-86_400]
    assert rec.polls[-1].now == T0 - 86_400  # stored times moved instead
    engine.remove_router("r1")
    assert rec.removed == ["r1"]


@pytest.mark.asyncio
async def test_lines_keep_their_router_time(disk: FakeDisk) -> None:
    engine = await engine_for(make_hass(), "r1")
    rec = Recorder()
    engine.add_poll_observer(rec)
    engine.ingest("r1", data_with((wifi(WIFI_DISCONNECTED, 3),)), T0 + 10)
    [line] = rec.polls[0].wifi_lines
    assert line.time_ms == MS0 + 3000
