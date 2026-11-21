"""Fixes from the independent Traffic Analytics review (T1-T8, 2026-11-21).

Mocks only (FakeDisks, FakeCoordinator, synthetic router ids). No Home
Assistant instance, no router, no network.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from core_testkit import FakeDisks, drain
from test_traffic_engine import (
    RID,
    enabled,
    make_hass,
    start,
    two_polls,
)

from custom_components.openwrt_router.traffic_const import OPT_OFFLOAD_PROBE
from custom_components.openwrt_router.traffic_model import Quality, Scope


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# --- T1: a listener call without a new poll keeps the current rates ---------------


async def test_listener_without_new_poll_keeps_rates(disks: FakeDisks) -> None:
    """``async_update_listeners`` without a poll (e.g. after the package-update
    check) hands the same data again: no rate, no bucket, no extra call, no
    signal, and ``latest`` keeps the last valid WAN rate."""
    hass = make_hass()
    enabled(disks, {RID: {OPT_OFFLOAD_PROBE: True}})
    engine, coord = await start(hass)
    coord.api.async_traffic_offload_state = AsyncMock(return_value={})
    await two_polls(engine, coord, hass)
    signals: list[int] = []
    engine._signal = lambda: signals.append(1)  # type: ignore[method-assign]
    wan_pid = engine.wan_point(RID).point_id
    wan_before = engine.latest[wan_pid]
    assert wan_before.quality is Quality.OK
    version = engine.series.version
    quality = dict(engine.quality_counts)
    blocked = dict(engine.blocked_counts)
    processed = engine.counters["processed_snapshots"]

    for _ in range(2):
        engine.clock.t += 5
        coord.poll()  # the listeners again, same data, same sample time
        await drain(hass)

    assert engine.wan_point(RID) is not None  # the WAN sensors keep their value
    wan = engine.latest[wan_pid]
    assert wan is wan_before
    assert wan.rx_bps == 1_000_000.0
    assert engine.series.version == version
    assert dict(engine.quality_counts) == quality
    assert dict(engine.blocked_counts) == blocked
    assert engine.counters["processed_snapshots"] == processed
    assert engine.counters["repeated_snapshots"] == 2
    assert signals == []
    assert all(
        r.quality is not Quality.TIME_NOT_ADVANCING for r in engine.latest.values()
    )


async def test_time_not_advancing_never_overwrites_latest(disks: FakeDisks) -> None:
    """Independent of the repeat guard: a TIME_NOT_ADVANCING rate (poll
    without a usable sample time) neither replaces ``latest`` nor marks the
    series."""
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    await two_polls(engine, coord, hass)
    wan_pid = engine.wan_point(RID).point_id
    before = engine.latest[wan_pid]
    version = engine.series.version
    data = coord.data
    data.counters_sampled_mono = None  # counters without a time: rule 2
    engine.clock.t += 60
    coord.poll(data=data)
    await drain(hass)
    assert engine.latest[wan_pid] is before
    assert engine.wan_point(RID) is not None
    assert engine.series.version == version
    assert engine.quality_counts[Quality.TIME_NOT_ADVANCING.value] > 0
    assert all(
        r.quality is not Quality.TIME_NOT_ADVANCING
        for r in engine.latest.values()
        if r.point.scope is not Scope.STATION
    )
