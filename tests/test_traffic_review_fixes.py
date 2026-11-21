"""Fixes from the independent Traffic Analytics review (T1-T8, 2026-11-21).

Mocks only (FakeDisks, FakeCoordinator, synthetic router ids). No Home
Assistant instance, no router, no network.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest
from core_testkit import FakeDisks, drain
from test_traffic_engine import (
    RID,
    RID2,
    enabled,
    make_hass,
    start,
    two_polls,
)

from custom_components.openwrt_router import traffic_collector as tc
from custom_components.openwrt_router.traffic_const import (
    FEED_COLLECTOR,
    FLOW_STATE_SILENT,
    MAX_FLOW_FEEDS,
    OPT_OFFLOAD_PROBE,
)
from custom_components.openwrt_router.traffic_flows import (
    FlowStore,
    normalise_collector_flow,
)
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


# --- T2: the flow store and the intake stay bounded -----------------------------------

FLOW_NOW = 1_800_000_000.0
FLOW_KEY = bytes(range(32))


def flow_record(router_id: str | None = RID, **over: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "kind": "flow",
        "router_id": router_id,
        "window": {"start": FLOW_NOW - 60, "end": FLOW_NOW},
        "direction": "orig",
        "proto": "tcp",
        "src": "192.0.2.10",
        "dst": "198.51.100.5",
        "src_port": 50000,
        "dst_port": 443,
        "bytes": 1200,
        "packets": 10,
        "observation": "observed",
    }
    raw.update(over)
    return raw


def envelope(*records: dict[str, Any], sent_at: float = FLOW_NOW) -> bytes:
    return json.dumps(
        {
            "schema": tc.SCHEMA_V1,
            "collector": "edge-1",
            "sent_at": sent_at,
            "records": list(records),
        }
    ).encode()


def fake_rid(n: int) -> str:
    return "rtr_" + f"{n:032x}"


def test_flow_store_forgets_feeds_after_the_ttl_and_stays_silent() -> None:
    store = FlowStore(ttl_s=60)
    for n in range(200):
        record = normalise_collector_flow(
            flow_record(fake_rid(n)), now=FLOW_NOW, module_key=FLOW_KEY
        )
        store.add(record, origin=FEED_COLLECTOR, now=FLOW_NOW)
    later = FLOW_NOW + 3600
    store.prune(later)
    assert store._last_seen == {}  # nothing older than the TTL is remembered
    # a source that went quiet is still "silent", never "no source"
    assert store.source_state(later, module_key=FLOW_KEY).state == FLOW_STATE_SILENT


def test_flow_store_bounds_the_feeds_it_remembers() -> None:
    store = FlowStore(ttl_s=3600, max_total=100_000, max_per_feed=10)
    for n in range(MAX_FLOW_FEEDS + 500):
        record = normalise_collector_flow(
            flow_record(fake_rid(n)), now=FLOW_NOW, module_key=FLOW_KEY
        )
        store.add(record, origin=FEED_COLLECTOR, now=FLOW_NOW + n * 0.001)
    assert len(store._last_seen) <= MAX_FLOW_FEEDS
    assert len(store._feeds) <= MAX_FLOW_FEEDS
    assert store.counters["dropped_feeds"] >= 500
    assert len(store) == sum(len(q) for q in store._feeds.values())


def test_intake_refuses_router_ids_of_no_loaded_router() -> None:
    intake, flows = tc.CollectorIntake(), FlowStore()
    known = frozenset({RID})
    with pytest.raises(tc.CollectorRejected) as err:
        intake.ingest(
            envelope(flow_record(RID), flow_record(fake_rid(7))),
            now_wall=FLOW_NOW,
            module_key=FLOW_KEY,
            flows=flows,
            known_routers=known,
        )
    assert err.value.status == 400
    assert err.value.reason == tc.REJECT_RECORDS
    assert err.value.rejected == [(1, tc.REJECT_UNKNOWN_ROUTER)]
    assert len(flows) == 0 and flows._last_seen == {}  # all or nothing
    assert intake.counters[f"rejected_{tc.REJECT_RECORDS}"] == 1
    assert intake.counters["rejected_records_unknown_router"] == 1
    answer = intake.ingest(
        envelope(flow_record(RID), flow_record(None)),
        now_wall=FLOW_NOW,
        module_key=FLOW_KEY,
        flows=flows,
        known_routers=known,
    )
    assert answer["accepted"] == 2  # a record without router id stays allowed


async def test_engine_checks_collector_router_ids_against_routers_on(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    enabled(disks)
    engine, _coord = await start(hass)
    now = engine.wall()
    rec = {**flow_record(RID2), "window": {"start": now - 60, "end": now}}
    with pytest.raises(tc.CollectorRejected) as err:
        engine.ingest_collector(envelope(rec, sent_at=now))
    assert err.value.rejected == [(0, tc.REJECT_UNKNOWN_ROUTER)]
    rec["router_id"] = RID
    assert engine.ingest_collector(envelope(rec, sent_at=now))["accepted"] == 1
