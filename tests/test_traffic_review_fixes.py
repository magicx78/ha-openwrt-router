"""Fixes from the independent Traffic Analytics review (T1-T8, 2026-11-21).

Mocks only (FakeDisks, FakeCoordinator, synthetic router ids). No Home
Assistant instance, no router, no network.
"""

from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import AsyncMock

import pytest
import test_traffic_history as th_tests
import test_traffic_views as tv_tests
from core_testkit import USER_ID, FakeDisks, drain
from core_testkit import make_hass as core_make_hass
from test_traffic_engine import (
    RID,
    RID2,
    counters,
    enabled,
    make_hass,
    poll_data,
    start,
    two_polls,
)

from custom_components.openwrt_router import traffic_collector as tc
from custom_components.openwrt_router import traffic_store
from custom_components.openwrt_router.const import (
    TRAFFIC_COARSE_STORE_KEY,
    TRAFFIC_FINE_STORE_KEY,
)
from custom_components.openwrt_router.coordinator import (
    TRAFFIC_MAX_DEVICES,
    traffic_device_counters,
    traffic_devices_omitted,
)
from custom_components.openwrt_router.traffic_const import (
    CAP_NETDEV_COUNTERS,
    FEED_COLLECTOR,
    FLOW_STATE_SILENT,
    MAX_DEVICES_PER_ROUTER,
    MAX_FLOW_FEEDS,
    OPT_OFFLOAD_PROBE,
    REASON_DEVICES_OMITTED,
)
from custom_components.openwrt_router.traffic_engine import async_release_traffic
from custom_components.openwrt_router.traffic_flows import (
    FlowStore,
    normalise_collector_flow,
)
from custom_components.openwrt_router.traffic_history import TrafficHistory
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)


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


# --- T3: over the netdev cap the WAN counter stays ------------------------------------


def many_devices(n: int) -> dict[str, Any]:
    """``network.device status`` with ``n`` netdevs sorted before ``wan``."""
    reply: dict[str, Any] = {
        f"eth{i:02d}": {"statistics": {"rx_bytes": i, "tx_bytes": i}} for i in range(n)
    }
    for name in ("wan", "wan6", "pppoe-wan"):
        reply[name] = {"statistics": {"rx_bytes": 1, "tx_bytes": 2}}
    return reply


def test_coordinator_copy_keeps_wan_and_uplinks_over_the_cap() -> None:
    reply = many_devices(80)
    out = traffic_device_counters(reply, first=("eth79", "wan"))
    assert out is not None and len(out) == TRAFFIC_MAX_DEVICES
    assert {"wan", "wan6", "pppoe-wan", "eth79"} <= set(out)
    assert traffic_devices_omitted(reply) == 83 - TRAFFIC_MAX_DEVICES
    assert traffic_devices_omitted(many_devices(10)) == 0
    # under the cap nothing changes
    assert set(traffic_device_counters(many_devices(10)) or {}) == set(many_devices(10))


async def test_wan_rate_over_the_netdev_cap_and_omitted_is_visible(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)

    def data(mono: float, wan: tuple[int, int]) -> Any:
        d = poll_data(mono, wan)
        d.device_counters = {
            **{f"eth{i:02d}": counters(i, i) for i in range(70)},
            "wan": counters(*wan),
        }
        d.device_counters_omitted = 9  # the coordinator cut nine more
        return d

    coord.poll(data=data(100.0, (1_000, 500)))
    await drain(hass)
    engine.clock.t += 10
    coord.poll(data=data(110.0, (1_251_000, 125_500)))
    await drain(hass)
    wan = engine.wan_point(RID)
    assert wan is not None
    assert engine.latest[wan.point_id].rx_bps == 1_000_000.0
    status = engine.status[RID]
    assert status.devices == MAX_DEVICES_PER_ROUTER
    assert status.devices_omitted == 9 + 71 - MAX_DEVICES_PER_ROUTER
    caps = engine.capabilities(RID)
    assert caps[CAP_NETDEV_COUNTERS] == {
        "state": "available",
        "reason": REASON_DEVICES_OMITTED,
    }
    assert engine.counters["devices_omitted"] == 2 * status.devices_omitted


# --- T4: one noisy user cannot use up the event budget of the others -------------------


def test_event_budget_is_per_reason_and_user() -> None:
    sent: list[dict[str, Any]] = []
    intake = tc.CollectorIntake()
    intake.emit = lambda _event, **kw: sent.append(kw)
    for i in range(30):  # a signed-in non-collector user, again and again
        intake.auth_refused(tc.REJECT_AUTH, FLOW_NOW + i, user_id="user-a")
    assert len(sent) == tc.EVENT_BUDGET_PER_HOUR
    # a real failed attempt of someone else still reaches the Security Center
    intake.auth_refused(tc.REJECT_AUTH, FLOW_NOW + 40, user_id="user-b")
    intake.auth_refused(tc.REJECT_TRANSPORT, FLOW_NOW + 41, user_id="user-a")
    assert len(sent) == tc.EVENT_BUDGET_PER_HOUR + 2
    assert intake.counters["events_over_budget"] == 20
    # no user id in the event or the counters
    assert "user-a" not in repr(sent) and "user-a" not in repr(intake.counters)


def test_event_bookkeeping_is_bounded() -> None:
    intake = tc.CollectorIntake()
    intake.emit = lambda _event, **_kw: None
    for n in range(tc.MAX_EVENT_KEYS + 100):
        intake.auth_refused(tc.REJECT_AUTH, FLOW_NOW, user_id=f"user-{n}")
    assert len(intake._events) <= tc.MAX_EVENT_KEYS
    assert intake.counters["events_keys_full"] == 100
    # an hour later the old keys are gone and new ones fit again
    intake.auth_refused(tc.REJECT_AUTH, FLOW_NOW + 3700, user_id="user-new")
    assert intake.counters["events_published"] == tc.MAX_EVENT_KEYS + 1
    assert len(intake._events) == 1


async def test_route_books_the_budget_per_user(disks: FakeDisks) -> None:
    """Over HTTP: 15 refusals of a plain user, then the collector user over
    plain HTTP: that refusal is still published."""
    hass, engine = await tv_tests.collector_on(disks)
    sent: list[dict[str, Any]] = []
    engine.collector.emit = lambda _event, **kw: sent.append(kw)
    async with tv_tests.http(hass) as h:
        for _ in range(15):
            resp = await tv_tests.ingest(
                h, tv_tests.envelope(engine.wall()), user=USER_ID
            )
            assert resp.status == 403
        assert len(sent) == tc.EVENT_BUDGET_PER_HOUR
        resp = await tv_tests.ingest(h, tv_tests.envelope(engine.wall()), https=False)
        assert resp.data["code"] == "insecure_transport"
    assert len(sent) == tc.EVENT_BUDGET_PER_HOUR + 1
    assert sent[-1]["data"] == {"reason": tc.REJECT_TRANSPORT}


# --- T5: a call sent twice is kept once ------------------------------------------------


def test_repeated_call_is_confirmed_once_and_not_counted_twice() -> None:
    intake, flows = tc.CollectorIntake(), FlowStore()
    raw = envelope(flow_record(RID), flow_record(RID, dst_port=80))
    first = intake.ingest(
        raw, now_wall=FLOW_NOW, module_key=FLOW_KEY, flows=flows, user_id="c"
    )
    # the same call again (e.g. a retry after a timeout), whitespace aside
    again = intake.ingest(
        json.dumps(json.loads(raw), indent=2).encode(),
        now_wall=FLOW_NOW + 30,
        module_key=FLOW_KEY,
        flows=flows,
        user_id="c",
    )
    assert again == first  # idempotent: the same answer
    assert len(flows) == 2
    assert intake.counters["accepted_calls"] == 1
    assert intake.counters["accepted_records"] == 2
    assert intake.counters["duplicate_calls"] == 1
    # another sent_at is another call
    intake.ingest(
        envelope(flow_record(RID), sent_at=FLOW_NOW + 1),
        now_wall=FLOW_NOW + 40,
        module_key=FLOW_KEY,
        flows=flows,
        user_id="c",
    )
    assert len(flows) == 3


def test_refused_call_is_not_remembered() -> None:
    intake = tc.CollectorIntake()
    raw = envelope(flow_record(RID))
    full = FlowStore(max_total=0)
    with pytest.raises(tc.CollectorRejected):
        intake.ingest(raw, now_wall=FLOW_NOW, module_key=FLOW_KEY, flows=full)
    flows = FlowStore()
    answer = intake.ingest(raw, now_wall=FLOW_NOW, module_key=FLOW_KEY, flows=flows)
    assert answer["accepted"] == 1 and len(flows) == 1


def test_call_ids_are_bounded() -> None:
    intake, flows = tc.CollectorIntake(), FlowStore(max_total=100_000)
    for n in range(tc.MAX_CALL_IDS + 50):
        intake.ingest(
            envelope(flow_record(RID), sent_at=FLOW_NOW - n),
            now_wall=FLOW_NOW,
            module_key=FLOW_KEY,
            flows=flows,
        )
    assert len(intake._call_ids) == tc.MAX_CALL_IDS


# --- T6: a coarse store newer than the fine one adds nothing twice --------------------

HDAY = 86400
HT0 = 1_800_000_000 - (1_800_000_000 % HDAY)  # UTC midnight
HWAN = MeasurementPoint(RID, Scope.WAN, device="wan")


def hist_rate(wall: float, rx: int = 6_000, interval: float = 60.0) -> Rate:
    return Rate(
        HWAN,
        Quality.OK,
        interval_s=interval,
        rx_bps=rx * 8 / interval,
        tx_bps=3_000 * 8 / interval,
        rx_delta=rx,
        tx_delta=3_000,
        coverage=Coverage.FULL,
        wall_s=wall,
        mono_s=wall,
    )


def hist_feed(hist: TrafficHistory, start: float, end: float) -> None:
    t = start + 60.0
    while t <= end:
        hist.add_rate(hist_rate(t))
        t += 60.0


def hour_bytes(hist: TrafficHistory, end: float) -> list[int | None]:
    win = hist.window(HWAN.point_id, 4 * 3600, end=end, resolution_s=3600)
    return [b.rx_bytes for b in win.buckets]


def test_coarse_store_newer_than_fine_store_counts_nothing_twice() -> None:
    hist = TrafficHistory()
    hist_feed(hist, HT0, HT0 + 2 * 3600)
    hist.compact(HT0 + 2 * 3600)
    fine_old = json.loads(json.dumps(hist.export_fine()))  # last fine write
    hist_feed(hist, HT0 + 2 * 3600, HT0 + 3 * 3600)
    hist.compact(HT0 + 3 * 3600)
    coarse_new = json.loads(json.dumps(hist.export_coarse()))  # a later coarse write
    # hard crash: the fine store of 2 h, the coarse store of 3 h are on disk
    again = TrafficHistory()
    assert again.import_payload(fine_old, coarse_new) == 0
    end = HT0 + 3 * 3600
    truth = hour_bytes(hist, end)
    # every hour holds at most what really went through, before and after
    # the next roll-up
    for _step in ("on load", "after the next roll-up"):
        got = hour_bytes(again, end)
        for want, have in zip(truth, got, strict=True):
            assert (have or 0) <= (want or 0), (_step, truth, got)
        again.compact(end + 60)
    assert hour_bytes(again, HT0 + 2 * 3600)[:2] == hour_bytes(hist, HT0 + 2 * 3600)[:2]


def test_old_store_files_without_the_coarse_marker_still_load() -> None:
    hist = TrafficHistory()
    hist_feed(hist, HT0, HT0 + 2 * 3600)
    hist.compact(HT0 + 2 * 3600)
    fine = json.loads(json.dumps(hist.export_fine()))
    coarse = json.loads(json.dumps(hist.export_coarse()))
    for entry in coarse["points"].values():
        entry.pop("ru", None)  # a coarse file written before the fix
    again = TrafficHistory()
    assert again.import_payload(fine, coarse) == 0
    assert again.compact(HT0 + 2 * 3600) is False  # nothing rolled twice
    assert hour_bytes(again, HT0 + 2 * 3600) == hour_bytes(hist, HT0 + 2 * 3600)


def test_fine_store_newer_than_coarse_store_loses_no_rolled_bucket() -> None:
    """The other order: the coarse mark tells what the coarse tiers hold, so
    the fine buckets after it are rolled again (nothing lost, nothing twice)."""
    hist = TrafficHistory()
    hist_feed(hist, HT0, HT0 + 2 * 3600)
    hist.compact(HT0 + 2 * 3600)
    coarse_old = json.loads(json.dumps(hist.export_coarse()))
    hist_feed(hist, HT0 + 2 * 3600, HT0 + 3 * 3600)
    hist.compact(HT0 + 3 * 3600)
    fine_new = json.loads(json.dumps(hist.export_fine()))
    again = TrafficHistory()
    assert again.import_payload(fine_new, coarse_old) == 0
    end = HT0 + 3 * 3600
    assert hour_bytes(again, end) == hour_bytes(hist, end)
    again.compact(end)
    assert hour_bytes(again, end) == hour_bytes(hist, end)


# --- T7: the size brake never empties the stored history --------------------------------


async def test_over_size_fine_write_right_after_start_keeps_the_stored_file(
    disks: FakeDisks, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = core_make_hass()
    engine, coord = await th_tests._engine(hass, on=True)
    await th_tests._run_polls(engine, coord, hass, 90)
    disks.flush_delayed()
    stored = json.loads(json.dumps(disks[TRAFFIC_FINE_STORE_KEY].data["data"]))
    assert stored["history"]["points"]
    await async_release_traffic(hass, "e1")
    # restart, and the very first write is over the size limit
    hass2 = core_make_hass()
    engine2, _coord2 = await th_tests._engine(hass2, on=True)
    monkeypatch.setattr(traffic_store, "TRAFFIC_FINE_STORE_MAX_BYTES", 10)
    payload = engine2.store.fine_payload()
    assert payload == stored  # the file on disk, never {}
    assert engine2.store.counters["save_over_size"] == 1


async def test_over_size_coarse_write_right_after_start_keeps_the_stored_history(
    disks: FakeDisks, monkeypatch: pytest.MonkeyPatch
) -> None:
    hass = core_make_hass()
    engine, coord = await th_tests._engine(hass, on=True)
    await th_tests._run_polls(engine, coord, hass, 150)
    disks.flush_delayed()
    await async_release_traffic(hass, "e1")
    stored = json.loads(json.dumps(disks[TRAFFIC_COARSE_STORE_KEY].data["data"]))
    assert stored["history"]["points"]
    hass2 = core_make_hass()
    engine2, _coord2 = await th_tests._engine(hass2, on=True)
    monkeypatch.setattr(traffic_store, "TRAFFIC_COARSE_STORE_MAX_BYTES", 10)
    payload = engine2.store.coarse_payload()
    assert payload["history"] == stored["history"]


# --- T8: a store write rebuilds the export at most twice --------------------------------
# Measured on the reference fleet (6 routers, 102 infrastructure points, 150
# clients, standard profile, 92 days, dev VM): a write without trimming
# 23-42 ms (the export is nearly all of it; the JSON measuring is cheap), the
# first write over a part budget (budgets at 60 %) 61/87 ms fine/coarse with
# 2 builds (before: 118/226 ms with 4-6 builds); the writes after it 23-25 ms.


def test_write_over_budget_rebuilds_the_export_at_most_twice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hist = TrafficHistory(profile="standard")
    th_tests.simulate(hist, 0, 2)
    store = traffic_store.TrafficStore(core_make_hass())
    store.history = hist
    store.baselines = list
    builds = {"n": 0}
    for name in ("export_fine", "export_coarse"):
        original = getattr(hist, name)

        def counted(original: Any = original) -> dict[str, Any]:
            builds["n"] += 1
            return original()

        monkeypatch.setattr(hist, name, counted)
    full = {
        part: traffic_store.store_bytes(
            "fine",
            {
                k: e
                for k, e in hist.export_fine()["points"].items()
                if traffic_store._part_of(e) == part
            },
        )
        for part in ("infra", "client")
    }
    builds["n"] = 0
    tight = {
        "standard": {
            "fine": {"infra": full["infra"] // 2, "client": full["client"] // 2},
            "coarse": {"infra": 10**9, "client": 10**9},
        }
    }
    monkeypatch.setattr(traffic_store, "HISTORY_BUDGETS", tight)
    started = time.perf_counter()
    payload = store.fine_payload()
    elapsed = time.perf_counter() - started
    assert builds["n"] <= 2
    for part in ("infra", "client"):
        size = traffic_store.store_bytes(
            "fine",
            {
                k: e
                for k, e in payload["history"]["points"].items()
                if traffic_store._part_of(e) == part
            },
        )
        assert size <= tight["standard"]["fine"][part]
    builds["n"] = 0
    store.fine_payload()  # the next write: under budget, one build
    assert builds["n"] == 1
    assert elapsed < 2.0  # generous: a small fleet, any machine
