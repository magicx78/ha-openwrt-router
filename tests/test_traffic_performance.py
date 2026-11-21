"""Traffic Analytics performance and resource limits (Phase L, plan 2026-11-20 §18).

What is measured (the figures go to ``docs/traffic-analytics.md``; run with
``-s`` to print them as ``PERF {...}`` lines):

* switched off, a poll makes exactly the router calls of a poll without the
  package (same ubus objects, methods and arguments, in the same order);
  switched on without extra calls, too; and what a poll costs on vs. off;
* the reference fleet of the plan (6 routers, 102 infrastructure points,
  150 clients): one poll round of all six routers;
* the peak sensor (24 h of 5-minute buckets), the flow store at its limit
  of 2000 records, one collector call with 500 records;
* time and size of every read route on the reference fleet;
* memory over many polls: after the bounded rings are full, more polls add
  only the hourly / daily buckets up to their fixed caps.

Limits are deliberately loose (CI runners are slow and shared): each one is
far above the measured value and only catches an order-of-magnitude
regression, never a slow runner. Mocks only; no router, no Home Assistant
instance, no network.
"""

from __future__ import annotations

import gc
import json
import statistics
import time
import tracemalloc
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import test_poll_no_ssh as model
from core_testkit import FakeCoordinator, FakeDisks, FakeEntry, drain, router_data
from core_testkit import make_hass as core_make_hass
from test_traffic_engine import (
    KEY,
    _reset_pending,  # noqa: F401 - autouse fixture
    counters,
    enabled,
    start,
    station,
)
from test_traffic_regression import _api
from test_traffic_views import COLLECTOR_ID, collector_users, envelope, http, users

from custom_components.openwrt_router.const import DATA_TRAFFIC_ANALYTICS
from custom_components.openwrt_router.traffic_collector import (
    BODY_MAX_BYTES,
    MAX_RECORDS,
)
from custom_components.openwrt_router.traffic_const import (
    MAX_FLOWS_PER_FEED,
    MAX_FLOWS_TOTAL,
)
from custom_components.openwrt_router.traffic_engine import (
    TrafficEngine,
    async_release_traffic,
    async_setup_traffic,
)
from custom_components.openwrt_router.traffic_entities import _wan_peak
from custom_components.openwrt_router.traffic_flows import FlowStore
from custom_components.openwrt_router.traffic_model import (
    FlowDirection,
    FlowKind,
    FlowRecord,
    Scope,
    Source,
)

ROUTERS = 6
DEVICES_PER_ROUTER = 17  # 6 x 17 = 102 infrastructure points (plan §5)
CLIENTS_PER_ROUTER = 25  # 6 x 25 = 150 clients
RIDS = ["rtr_" + f"{r + 1:x}" * 32 for r in range(ROUTERS)]
POLL_S = 60.0


def perf(name: str, **values: Any) -> None:
    """One line of measured figures (shown with ``pytest -s``)."""
    print("\nPERF", json.dumps({"measure": name, **values}, sort_keys=True))


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# --- 1. switched off: the same router calls as without the package -------------------------


def _call_list(session: Any) -> list[tuple[Any, ...]]:
    out = []
    for call in session.post.call_args_list:
        params = (call.kwargs.get("json") or {}).get("params") or [None, "", "", {}]
        args = params[3] if len(params) > 3 else None
        out.append((params[1], params[2], json.dumps(args, sort_keys=True)))
    return out


async def _polls(mode: str, polls: int) -> tuple[list[tuple[Any, ...]], float, int]:
    """``polls`` real polls with the package absent / off / on (no extras)."""
    processed = 0
    session = model._ubus_session()
    coord = model._make_coordinator(_api(session))
    hass = core_make_hass()
    with FakeDisks().patch():
        if mode != "absent":
            engine = TrafficEngine(hass)
            hass.data[DATA_TRAFFIC_ANALYTICS] = engine
            engine.router_id_of = {"e1": RIDS[0]}.get
            await async_setup_traffic(
                hass, FakeEntry("e1", options={"traffic_enabled": mode == "on"}), coord
            )
        model._MODE["empty_tables"] = False
        with (
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            started = time.perf_counter()
            for _n in range(polls):
                coord.data = await coord._async_update_data()
                coord.async_update_listeners()
                while hass.tasks:
                    await hass.tasks.pop(0)
            elapsed = time.perf_counter() - started
        if mode != "absent":
            processed = engine.counters.get("processed_snapshots", 0)
            await async_release_traffic(hass, "e1")
    return _call_list(session), elapsed, processed


async def test_off_and_on_make_exactly_the_router_calls_of_no_package() -> None:
    polls = 5
    absent, t_absent, _ = await _polls("absent", polls)
    off, t_off, off_processed = await _polls("off", polls)
    on, t_on, on_processed = await _polls("on", polls)
    assert absent, "the model poll made no call"
    assert (off_processed, on_processed) == (0, polls)  # on really worked
    # the same objects, methods and arguments in the same order
    assert off == absent
    assert on == absent  # stage A-standard: no router call of its own
    per_poll = {
        k: round(v / polls * 1000, 2)
        for k, v in (("absent_ms", t_absent), ("off_ms", t_off), ("on_ms", t_on))
    }
    perf("poll_cost", calls_per_poll=len(absent) // polls, **per_poll)
    # on: the extra work per poll stays far below one second (measured: a
    # few milliseconds); the poll itself is mostly the ubus mock
    assert (t_on - t_absent) / polls < 1.0


# --- 2. the reference fleet ----------------------------------------------------------------


def fleet_poll(router: int, mono: float, step: int) -> Any:
    """One poll of router ``router`` at poll number ``step`` (counters grow)."""
    data = router_data()
    gateway = router == 0
    data.wan_status = {**data.wan_status, "l3_device": "wan" if gateway else None}
    data.uptime = 10_000 + step * int(POLL_S)
    names = ["wan"] if gateway else []
    names += [f"lan{i}" for i in range(1, 5)] + ["eth0", "eth1", "br-lan"]
    names += [f"br-lan.{v}" for v in (10, 20, 30, 40)]
    names += [f"wg{i}" for i in range(DEVICES_PER_ROUTER - len(names))]
    assert len(names) == DEVICES_PER_ROUTER
    load = 5 if (step // 60) % 24 in range(18, 23) else 1
    data.device_counters = {
        name: counters(
            step * load * (2_000_000 + 997 * n), step * load * (400_000 + 13 * n)
        )
        for n, name in enumerate(names)
    }
    data.counters_sampled_mono = mono
    data.clients = [
        station(
            f"02:00:5e:{router:02x}:00:{c:02x}",
            step * load * (50_000 + c),
            step * load * 9_000,
            f"phy{c % 2}-ap0",
        )
        for c in range(CLIENTS_PER_ROUTER)
    ]
    return data


async def fleet(hass: Any) -> tuple[TrafficEngine, list[FakeCoordinator]]:
    """An engine with six routers switched on (no extra calls)."""
    enabled(None)
    mapping = {f"e{r}": RIDS[r] for r in range(ROUTERS)}
    coords = []
    engine = None
    for r in range(ROUTERS):
        engine, coord = await start(
            hass,
            entry_id=f"e{r}",
            coord=FakeCoordinator(fleet_poll(r, 0.0, 0)),
            rids=mapping,
        )
        coords.append(coord)
    assert engine is not None and engine.active
    engine._module_key = KEY  # what the core hands out
    return engine, coords


async def run_rounds(
    engine: TrafficEngine, coords: list[FakeCoordinator], hass: Any, first: int, n: int
) -> list[float]:
    """``n`` poll rounds of every router; the seconds each round took."""
    times = []
    for step in range(first, first + n):
        engine.clock.t = 1_000.0 + step * POLL_S
        started = time.perf_counter()
        for r, coord in enumerate(coords):
            coord.poll(data=fleet_poll(r, engine.clock.t, step))
        await drain(hass)
        times.append(time.perf_counter() - started)
    return times


async def test_reference_fleet_poll_round(disks) -> None:
    hass = users(core_make_hass())
    engine, coords = await fleet(hass)
    await run_rounds(engine, coords, hass, 1, 5)  # warm-up: first samples, bases
    times = await run_rounds(engine, coords, hass, 6, 60)
    points = engine.summary()["points"]
    assert points == {"infra": ROUTERS * DEVICES_PER_ROUTER, "client": 150}
    assert engine.counters["dropped_snapshots"] == 0
    assert all(c.router_calls() == [] for c in coords)  # no router call at all
    median = statistics.median(times)
    perf(
        "fleet_round",
        routers=ROUTERS,
        infra_points=points["infra"],
        clients=points["client"],
        round_median_ms=round(median * 1000, 2),
        round_max_ms=round(max(times) * 1000, 2),
    )
    # a round runs once per poll interval (60 s); measured in the tens of
    # milliseconds, the limit is 50 times that and still 1/30 of the interval
    assert median < 2.0


async def test_peak_sensor_over_24_hours(disks) -> None:
    hass = users(core_make_hass())
    engine, coords = await fleet(hass)
    # 24 h at a 5-minute poll interval fill every 5-minute bucket of the day
    for step in range(1, 24 * 12 + 2):
        engine.clock.t = 1_000.0 + step * 300.0
        for r, coord in enumerate(coords[:1]):
            data = fleet_poll(r, engine.clock.t, step * 5)
            coord.poll(data=data)
        await drain(hass)
    rid = RIDS[0]
    runs = 200
    started = time.perf_counter()
    for _ in range(runs):
        value, attrs = _wan_peak(engine, rid)
    each = (time.perf_counter() - started) / runs
    assert value is not None and value > 0
    assert attrs["buckets"] > 60  # compact keeps 5-minute values 6 h
    perf("peak_sensor", buckets=attrs["buckets"], each_ms=round(each * 1000, 3))
    assert each < 0.25  # measured well below 1 ms


# --- 3. flow store and collector ---------------------------------------------------------


def flow(i: int, now: float, router: str) -> FlowRecord:
    return FlowRecord(
        router_id=router,
        client_ref=f"cli_{i % 150:016x}",
        vlan_id=None,
        proto="tcp" if i % 3 else "udp",
        src=f"192.0.2.{i % 250 + 1}",
        dst=f"198.51.100.{i % 200 + 1}",
        src_port=40_000 + i % 20_000,
        dst_port=(443, 53, 1883, 123)[i % 4],
        start=now - 60,
        end=now,
        bytes=1_000 + i,
        packets=10,
        direction=FlowDirection.ORIG,
        kind=FlowKind.OBSERVED,
        source=Source.COLLECTOR,
        nat_seen=None,
    )


def test_flow_store_at_its_limit_of_2000() -> None:
    store = FlowStore()
    now = 1_800_000_000.0
    started = time.perf_counter()
    kept = sum(
        store.add(flow(i, now, RIDS[i % 4]), origin="collector_flow", now=now)
        for i in range(MAX_FLOWS_TOTAL)
    )
    add_each = (time.perf_counter() - started) / MAX_FLOWS_TOTAL
    assert kept == MAX_FLOWS_TOTAL == len(store) == 2000
    # full: a further record of a new feed is refused, a full feed drops its oldest
    assert not store.add(flow(1, now, RIDS[5]), origin="collector_flow", now=now)
    assert store.add(flow(2, now, RIDS[0]), origin="collector_flow", now=now)
    assert len(store) == 2000
    assert store.counters["dropped_flows_store_full"] == 1
    assert store.counters["dropped_flows_feed_full"] == 1
    assert max(len(q) for q in store._feeds.values()) <= MAX_FLOWS_PER_FEED
    started = time.perf_counter()
    result = store.query(now, module_key=KEY, limit=200)
    query_s = time.perf_counter() - started
    assert len(result.rows) == 200
    perf(
        "flow_store",
        records=len(store),
        add_each_us=round(add_each * 1e6, 1),
        query_200_ms=round(query_s * 1000, 2),
    )
    assert add_each < 0.01 and query_s < 2.0


async def test_collector_call_with_500_records(disks) -> None:
    hass = users(core_make_hass())
    enabled(None)
    engine, _coord = await start(hass)
    collector_users(hass)
    await engine.async_update_settings(
        {"collector": {"enabled": True, "user_id": COLLECTOR_ID}}
    )
    engine._module_key = KEY
    now = engine.wall()
    body = envelope(now)
    one = body["records"][0]
    body["records"] = [
        {
            **one,
            "src_port": 40_000 + i,
            "client_mac": f"02:00:5e:20:{i // 256:02x}:{i % 256:02x}",
        }
        for i in range(MAX_RECORDS)
    ]
    raw = json.dumps(body).encode()
    assert MAX_RECORDS == 500 and len(raw) < BODY_MAX_BYTES
    started = time.perf_counter()
    answer = engine.ingest_collector(raw)
    elapsed = time.perf_counter() - started
    assert answer["accepted"] == 500 and answer["rejected"] == []
    assert len(engine.flows) == 500  # one router: its feed is full
    perf(
        "collector_call",
        records=500,
        body_bytes=len(raw),
        body_limit=BODY_MAX_BYTES,
        ms=round(elapsed * 1000, 2),
    )
    assert elapsed < 5.0


# --- 4. read routes on the reference fleet ----------------------------------------------


ROUTES = (
    ("/overview", None),
    ("/points", None),
    ("/series", "series"),
    ("/talkers", {"window": "24h", "limit": "50"}),
    ("/clients", None),
    ("/vlans", None),
    ("/capacity", None),
    ("/anomalies", None),
    ("/recommendations", None),
    ("/flows", None),
    ("/settings", None),
    ("/collector/users", None),
)


async def test_read_routes_time_and_size_on_the_reference_fleet(disks) -> None:
    hass = users(core_make_hass())
    engine, coords = await fleet(hass)
    await run_rounds(engine, coords, hass, 1, 30)
    wan = next(p for p in engine.series.points() if p.scope is Scope.WAN)
    figures = {}
    async with http(hass) as h:
        for path, params in ROUTES:
            if params == "series":
                params = {"point_id": wan.point_id, "window": "24h"}
            best = None
            for _ in range(3):
                started = time.perf_counter()
                resp = await h.get(path, params=params)
                took = time.perf_counter() - started
                assert resp.status == 200, (path, resp.data)
                best = took if best is None else min(best, took)
            figures[path] = {"ms": round(best * 1000, 1), "bytes": len(resp.body)}
            # every answer stays small enough for a phone (measured: at most
            # a few hundred KiB for the full client list)
            assert len(resp.body) < 1024 * 1024, path
            assert best < 2.0, path
        h.assert_no_secret("02:00:5e:", "phy0-ap0", "phy1-ap0")
    perf("routes", **{k.strip("/"): v for k, v in figures.items()})


# --- 5. memory over many polls ------------------------------------------------------------


def settle(hass: Any) -> None:
    """Forget what the MagicMock hass recorded (test harness, not the engine)."""
    hass.reset_mock()
    hass.fired.clear()
    gc.collect()


async def test_memory_stays_bounded_over_many_polls(disks) -> None:
    hass = users(core_make_hass())
    engine, coords = await fleet(hass)
    coords = coords[:2]  # two routers: 34 infrastructure points, 50 clients
    # 7 h of 60-s polls: the 5-minute ring (6 h in compact) is full
    await run_rounds(engine, coords, hass, 1, 7 * 60)
    settle(hass)
    tracemalloc.start()
    try:
        first = tracemalloc.get_traced_memory()[0]
        fine_before = engine.series.bucket_count("fine", "infra")
        await run_rounds(engine, coords, hass, 7 * 60 + 1, 5 * 60)  # 5 h more
        settle(hass)
        second = tracemalloc.get_traced_memory()[0]
        await run_rounds(engine, coords, hass, 12 * 60 + 1, 5 * 60)  # 5 h more
        settle(hass)
        third = tracemalloc.get_traced_memory()[0]
    finally:
        tracemalloc.stop()
    fine_after = engine.series.bucket_count("fine", "infra")
    assert fine_after == fine_before  # the 5-minute tier is at its fixed size
    assert engine.flows is not None and len(engine.flows) == 0
    grow_1 = second - first
    grow_2 = third - second
    perf(
        "memory",
        polls_per_router=17 * 60,
        growth_5h_kib=round(grow_1 / 1024, 1),
        growth_next_5h_kib=round(grow_2 / 1024, 1),
        fine_buckets_infra=fine_after,
    )
    # only hourly and daily buckets are still being added (bounded by their
    # caps: 14 / 31 days); 5 hours of them are a few hundred KiB at most
    assert grow_1 < 4 * 1024 * 1024 and grow_2 < 4 * 1024 * 1024
    # and it does not speed up (measured: about 1 MiB, then about 0.4 MiB)
    assert grow_2 < 1.5 * grow_1 + 64 * 1024
