"""Client traffic attribution (plan 2026-11-20, §4): traffic_clients.py.

Test areas of the task (§21): 12 client traffic attribution, 13 Wi-Fi
roaming, 25 high client counts. The client registry is the real
``client_history.ClientHistory`` fed with synthetic poll inputs; the engine
runs on fake coordinators. No router, no network; MACs are locally
administered test values, IPs from the documentation range.
"""

from __future__ import annotations

import json
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from core_testkit import FakeCoordinator, FakeDisks, FakeEntry, drain, router_data
from core_testkit import make_hass as core_make_hass

from custom_components.openwrt_router import client_engine
from custom_components.openwrt_router.client_history import (
    ClientHistory,
    ClientObs,
    PollInput,
    normalize_mac,
)
from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ANALYTICS,
    TRAFFIC_COARSE_STORE_KEY,
)
from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.traffic_clients import (
    ClientTracker,
    NoClientHistory,
    StationFacts,
    WindowTotals,
    identity_of,
    registry_lookup,
    window_values,
)
from custom_components.openwrt_router.traffic_collect import WiredSighting
from custom_components.openwrt_router.traffic_const import (
    CLIENT_VALUE_KIND,
    CLIENT_WINDOWS,
    IDENTITY_MAC_ONLY,
    IDENTITY_REGISTRY,
    IDENTITY_REGISTRY_MISSING,
    IDENTITY_UNCONFIRMED,
    LOCATION_FDB,
    LOCATION_REGISTRY,
    LOCATION_STATION,
    MAX_POINTS_CLIENT,
    MAX_STATIONS_PER_ROUTER,
    MAX_TRACKED_WIFI_CLIENTS,
    MAX_TRACKED_WIRED_CLIENTS,
    MAX_WIRED_PER_ROUTER,
    REASON_HISTORY_NOT_BUILT,
    REASON_NO_RATE_YET,
    REASON_NO_WIFI_VLAN_MAPPING,
    REASON_PORT_VLAN_AMBIGUOUS,
)
from custom_components.openwrt_router.traffic_engine import (
    TrafficEngine,
    async_setup_traffic,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    RegistryFacts,
    Scope,
    Source,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
KEY = bytes(range(32))
MAC_HW = "00:00:5e:00:53:01"  # documentation OUI, universally administered
MAC_RAND1 = "02:00:5e:10:00:01"  # locally administered = randomised
MAC_RAND2 = "02:00:5e:10:00:02"
HOST = "test-device"
TRAFFIC_DIR = Path(__file__).parent.parent / "custom_components" / "openwrt_router"


def ref(mac: str) -> str:
    return pseudonymise_identifier("client", mac, KEY)


class Clock:
    def __init__(self, t: float = 1_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _counters(rx: int, tx: int) -> dict[str, Any]:
    return {
        "rx_bytes": rx,
        "tx_bytes": tx,
        "rx_packets": 0,
        "tx_packets": 0,
        "rx_errors": 0,
        "tx_errors": 0,
        "rx_dropped": 0,
        "tx_dropped": 0,
        "speed": "1000F",
        "up": True,
        "carrier": True,
    }


def poll(
    mono: float,
    step: int,
    stations: list[dict[str, Any]] | None = None,
    *,
    fdb: dict[str, str] | None = None,
    port_vlans: dict[str, list[int]] | None = None,
) -> Any:
    data = router_data()
    data.wan_status = {**data.wan_status, "l3_device": "wan"}
    data.uptime = 5_000 + int(mono)
    data.device_counters = {
        "br-lan": _counters(step * 1000, step * 2000),
        "wan": _counters(step * 100_000, step * 10_000),
    }
    data.port_stats = [
        {"name": "lan1", "speed_mbps": 1000, "duplex": "full"},
        {"name": "lan2", "speed_mbps": 1000, "duplex": "full"},
        {"name": "lan3", "speed_mbps": 1000, "duplex": "full"},
    ]
    data.counters_sampled_mono = mono
    data.clients = list(stations or [])
    data.port_fdb_map = dict(fdb or {})
    data.port_vlan_map = dict(port_vlans or {})
    return data


def station(
    mac: str,
    rx: int | None,
    tx: int | None,
    *,
    radio: str = "phy0-ap0",
    ip: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"mac": mac, "radio": radio, "rx_bytes": rx, "tx_bytes": tx}
    if ip is not None:
        out["ip"] = ip
        out["hostname"] = HOST
    return out


async def start(
    hass: Any, disks: FakeDisks, entries: tuple[str, ...] = ("e1", "e2")
) -> tuple[TrafficEngine, list[FakeCoordinator]]:
    disks[TRAFFIC_COARSE_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": TRAFFIC_COARSE_STORE_KEY,
        "data": {"settings": {"v": 1, "enabled": True, "routers": {}}},
    }
    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    mapping = {f"e{i}": "rtr_" + f"{i:x}" * 32 for i in range(1, 10)}
    engine.router_id_of = mapping.get
    engine.clock = Clock()
    engine.wall = lambda: 1_800_000_000.0 + engine.clock()
    engine.registry_source = lambda: None
    coords = []
    for entry_id in entries:
        coord = FakeCoordinator(poll(100.0, 1))
        coord.update_interval = timedelta(seconds=60)
        coord.poll_running = False
        await async_setup_traffic(
            hass, FakeEntry(entry_id, options={"traffic_enabled": True}), coord
        )
        coords.append(coord)
    engine._module_key = KEY
    return engine, coords


def ingest(history: ClientHistory, router: str, now: float, macs: list[str]) -> None:
    history.ingest(
        PollInput(
            router=router,
            now=now,
            interval=60.0,
            fresh=True,
            clients=tuple(ClientObs(mac=normalize_mac(m) or m) for m in macs),
        )
    )


# --- area 12: client traffic attribution ------------------------------------------------------


def test_registry_lookup_reads_the_client_history_only() -> None:
    history = ClientHistory()
    ingest(history, "e2", 1_000.0, [MAC_HW])
    lookup = registry_lookup(history, {"e2": RID2}.get)
    facts = lookup(MAC_HW)
    assert facts == RegistryFacts(known=True, state="online", router_id=RID2)
    assert lookup(MAC_RAND1) == RegistryFacts(known=False)
    # an AP entry the core does not know gives no location, never an error
    assert registry_lookup(history, {}.get)(MAC_HW).router_id is None

    class Broken:
        def live(self, mac: str) -> Any:
            raise RuntimeError("history gone")

    assert registry_lookup(Broken(), {}.get)(MAC_HW) == RegistryFacts(known=False)


@pytest.mark.parametrize(
    ("private", "registry", "expected"),
    [
        (False, RegistryFacts(True), IDENTITY_REGISTRY),
        (True, RegistryFacts(True), IDENTITY_REGISTRY),
        (True, RegistryFacts(False), IDENTITY_UNCONFIRMED),
        (True, None, IDENTITY_UNCONFIRMED),
        (False, RegistryFacts(False), IDENTITY_MAC_ONLY),
        (False, None, IDENTITY_REGISTRY_MISSING),
    ],
)
def test_identity_classes(private: bool, registry: Any, expected: str) -> None:
    assert identity_of(private, registry) == expected


async def test_changing_ip_keeps_the_same_client(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, _ap) = await start(hass, disks)
    history = ClientHistory()
    engine.registry_source = lambda: history
    for step, ip in enumerate(("192.0.2.10", "192.0.2.11", "192.0.2.12"), start=1):
        ingest(history, "e1", 1_000.0 + step * 60, [MAC_HW])
        gw.poll(
            data=poll(
                40.0 + step * 60,
                step,
                [station(MAC_HW, step * 1000, step * 3000, ip=ip)],
            )
        )
        await drain(hass)
    assert engine.clients.refs() == [ref(MAC_HW)]
    view = engine.client_view(ref(MAC_HW))
    assert view is not None
    assert view.identity == IDENTITY_REGISTRY
    assert view.location_source == LOCATION_REGISTRY
    assert (view.router_id, view.radio_id) == (RID, "phy0-ap0")


async def test_randomised_macs_are_never_merged(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, _ap) = await start(hass, disks)
    history = ClientHistory()  # knows neither MAC
    engine.registry_source = lambda: history
    for step in (1, 2):
        gw.poll(
            data=poll(
                40.0 + step * 60,
                step,
                [
                    station(MAC_RAND1, step * 10, step * 20, ip="192.0.2.20"),
                    station(MAC_RAND2, step * 10, step * 20, ip="192.0.2.20"),
                ],
            )
        )
        await drain(hass)
    views = engine.client_views()
    assert sorted(v.client_ref for v in views) == sorted(
        [ref(MAC_RAND1), ref(MAC_RAND2)]
    )
    assert {v.identity for v in views} == {IDENTITY_UNCONFIRMED}


async def test_client_view_values_and_reasons(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, _ap) = await start(hass, disks)
    gw.poll(data=poll(100.0, 1, [station(MAC_HW, 1_000, 2_000)]))
    await drain(hass)
    first = engine.client_view(ref(MAC_HW))
    assert first is not None
    assert first.down_bps is None and first.down_bytes is None
    assert first.unavailable["down_bps"] == Quality.FIRST_SAMPLE.value
    assert first.unavailable["down_bytes"] == REASON_NO_RATE_YET
    assert first.coverage is Coverage.UNAVAILABLE
    assert first.identity == IDENTITY_REGISTRY_MISSING  # no client engine here

    gw.poll(data=poll(160.0, 2, [station(MAC_HW, 2_000, 8_000)]))
    await drain(hass)
    gw.poll(data=poll(220.0, 3, [station(MAC_HW, 2_600, 9_200)]))
    await drain(hass)
    view = engine.client_view(ref(MAC_HW))
    assert view is not None
    # station counters are the AP's view: TX is what the client downloaded
    assert view.down_bps == 1_200 * 8 / 60 and view.up_bps == 600 * 8 / 60
    assert (view.down_bytes, view.up_bytes) == (7_200, 1_600)
    assert view.covered_s == 120.0
    assert view.avg_down_bps == 7_200 * 8 / 120
    assert view.max_down_bps == 6_000 * 8 / 60
    assert view.max_up_bps == 1_000 * 8 / 60
    assert view.value_kind == CLIENT_VALUE_KIND
    assert view.coverage is Coverage.PARTIAL
    assert view.coverage_reasons == ("station_counters_only",)
    assert view.location_source == LOCATION_STATION
    assert view.vlan_id is None
    assert view.unavailable["vlan_id"] == REASON_NO_WIFI_VLAN_MAPPING
    assert view.wan_attribution.coverage is Coverage.UNAVAILABLE
    assert view.unavailable["wan_attribution"] == "needs_flow_source"
    assert set(view.windows) == set(CLIENT_WINDOWS)
    for window in view.windows.values():
        assert window["down_bytes"] is None and window["up_bytes"] is None
        assert window["coverage"] == "unavailable"
        assert window["reasons"] == [REASON_HISTORY_NOT_BUILT]
    dumped = json.dumps([v.to_dict() for v in engine.client_views()])
    dumped += json.dumps(engine.summary())
    assert MAC_HW not in dumped.lower() and "192.0.2" not in dumped


def test_windows_come_from_the_history_interface() -> None:
    class Source:
        def client_window(self, client_ref: str, window_s: int) -> WindowTotals | None:
            if window_s == 3600:
                return WindowTotals(10, 20, 3600.0, Coverage.FULL)
            return None

    values = window_values(Source(), "cli_" + "a" * 16, wifi=True)
    assert values["1h"]["down_bytes"] == 10
    assert values["1h"]["coverage"] == "partial"  # never "full" for stations
    assert values["1h"]["reasons"] == ["station_counters_only"]
    assert values["24h"]["coverage"] == "unavailable"
    assert values["24h"]["reasons"] == [REASON_HISTORY_NOT_BUILT]
    empty = window_values(NoClientHistory(), "cli_" + "a" * 16, wifi=True)
    assert all(v["down_bytes"] is None for v in empty.values())


async def test_wired_client_has_a_port_but_no_bytes(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, _ap) = await start(hass, disks)
    data = poll(
        100.0,
        1,
        [station(MAC_RAND1, 10, 20)],
        fdb={MAC_HW: "lan2", MAC_RAND2: "lan3", MAC_RAND1: "lan1", "bad": "lan1"},
        port_vlans={"lan2": [10], "lan3": [10, 20]},
    )
    data.trunk_port_map = {"192.0.2.40": "lan1"}  # lan1 leads to another router
    gw.poll(data=data)
    await drain(hass)
    wired = engine.client_view(ref(MAC_HW))
    assert wired is not None and wired.link == "wired"
    assert (wired.router_id, wired.port, wired.location_source) == (
        RID,
        "lan2",
        LOCATION_FDB,
    )
    assert wired.coverage is Coverage.UNAVAILABLE
    assert wired.coverage_reasons == ("no_wired_client_source",)
    assert wired.down_bps is None and wired.down_bytes is None
    assert wired.unavailable["down_bytes"] == "no_wired_client_source"
    assert wired.vlan_id == 10  # the port carries exactly one VLAN
    assert wired.identity == IDENTITY_MAC_ONLY
    assert all(
        w["reasons"] == ["no_wired_client_source"] for w in wired.windows.values()
    )
    ambiguous = engine.client_view(ref(MAC_RAND2))
    assert ambiguous is not None and ambiguous.vlan_id is None
    assert ambiguous.unavailable["vlan_id"] == REASON_PORT_VLAN_AMBIGUOUS
    assert ambiguous.identity == IDENTITY_UNCONFIRMED
    # a Wi-Fi station is never also a wired client; a trunk port gives none
    wifi = engine.client_view(ref(MAC_RAND1))
    assert wifi is not None and wifi.link == "wifi"
    assert engine.clients.wired_count == 2


def test_client_values_never_use_the_wan_wording() -> None:
    forbidden = (
        "internet" + "verbrauch",
        "internet" + " usage",
        "internet" + "_usage",
        "internet" + "usage",
        "internet" + "-usage",
    )
    files = sorted(TRAFFIC_DIR.glob("traffic_*.py"))
    assert len(files) >= 8
    for path in files:
        text = path.read_text(encoding="utf-8").lower()
        for word in forbidden:
            assert word not in text, f"{word!r} in {path.name}"
    tracker = ClientTracker()
    point = MeasurementPoint(
        RID, Scope.STATION, radio_id="phy0-ap0", client_ref=ref(MAC_HW)
    )
    tracker.observe([_ok(point, 1.0)], {}, 1.0)
    view = tracker.view(ref(MAC_HW))
    assert view is not None
    dumped = json.dumps(view.to_dict()).lower()
    assert not any(word in dumped for word in forbidden)
    assert "internet" not in dumped


# --- area 13: Wi-Fi roaming ------------------------------------------------------------------


async def test_roaming_starts_a_new_base_and_shows_the_gap(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, ap) = await start(hass, disks)
    history = ClientHistory()
    engine.registry_source = lambda: history
    me = ref(MAC_HW)
    for step, mono in enumerate((100.0, 160.0, 220.0), start=1):
        ingest(history, "e1", mono, [MAC_HW])
        gw.poll(data=poll(mono, step, [station(MAC_HW, step * 1000, step * 2000)]))
        await drain(hass)
    before = engine.client_view(me)
    assert before is not None
    assert (before.down_bytes, before.up_bytes, before.roaming_gaps) == (
        4_000,
        2_000,
        0,
    )

    # the client roams: the AP lists it with fresh counters, the gateway not
    ingest(history, "e2", 280.0, [MAC_HW])
    ingest(history, "e1", 281.0, [])
    ap.poll(data=poll(280.0, 1, [station(MAC_HW, 100, 200)]))
    gw.poll(data=poll(281.0, 4, []))
    await drain(hass)
    roamed = engine.client_view(me)
    assert roamed is not None
    assert (roamed.router_id, roamed.location_source) == (RID2, LOCATION_REGISTRY)
    assert roamed.roaming_gaps == 1
    assert roamed.down_bps is None
    assert roamed.unavailable["down_bps"] == "roaming_gap"
    assert "roaming_gap" in roamed.coverage_reasons
    assert roamed.coverage is Coverage.PARTIAL
    # no delta across the APs: the totals did not move
    assert (roamed.down_bytes, roamed.up_bytes) == (4_000, 2_000)
    old = MeasurementPoint(RID, Scope.STATION, radio_id="phy0-ap0", client_ref=me)
    assert not engine.book.has(old.point_id)  # the old association's base is gone

    ingest(history, "e2", 340.0, [MAC_HW])
    ap.poll(data=poll(340.0, 2, [station(MAC_HW, 1_100, 2_200)]))
    await drain(hass)
    after = engine.client_view(me)
    assert after is not None
    assert after.down_bps == 2_000 * 8 / 60
    assert (after.down_bytes, after.up_bytes) == (6_000, 3_000)
    assert "roaming_gap" in after.coverage_reasons  # the loss stays visible
    assert engine.summary()["clients"]["roaming_gaps"] == 1


async def test_overlapping_sightings_are_not_counted_twice(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, ap) = await start(hass, disks)
    history = ClientHistory()
    engine.registry_source = lambda: history
    me = ref(MAC_HW)
    for step, mono in enumerate((100.0, 160.0, 220.0, 280.0), start=1):
        # both APs list the client; the registry places it at the AP (e2)
        ingest(history, "e2", mono, [MAC_HW])
        gw.poll(data=poll(mono, step, [station(MAC_HW, step * 5_000, step * 9_000)]))
        ap.poll(data=poll(mono + 2, step, [station(MAC_HW, step * 100, step * 300)]))
        await drain(hass)
    view = engine.client_view(me)
    assert view is not None
    assert view.router_id == RID2
    assert (view.down_bytes, view.up_bytes) == (900, 300)  # the AP's deltas only
    assert view.stale_sightings >= 3
    gw_points = [
        r
        for r in engine.latest.values()
        if r.point.router_id == RID and r.point.scope is Scope.STATION
    ]
    assert all(r.quality is Quality.STALE_SOURCE for r in gw_points)


async def test_return_to_the_old_ap_starts_a_new_base(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, (gw, ap) = await start(hass, disks)
    history = ClientHistory()
    engine.registry_source = lambda: history
    me = ref(MAC_HW)
    for step, mono in enumerate((100.0, 160.0), start=1):
        ingest(history, "e1", mono, [MAC_HW])
        gw.poll(
            data=poll(
                mono,
                step,
                [station(MAC_HW, 49_000 + step * 1_000, 88_000 + step * 2_000)],
            )
        )
        await drain(hass)
    ingest(history, "e2", 220.0, [MAC_HW])
    ingest(history, "e1", 221.0, [])
    ap.poll(data=poll(220.0, 1, [station(MAC_HW, 10, 10)]))
    gw.poll(data=poll(221.0, 3, []))
    await drain(hass)
    # back at the gateway; its counters grew while the client was at the AP
    ingest(history, "e1", 280.0, [MAC_HW])
    ingest(history, "e2", 281.0, [])
    gw.poll(data=poll(280.0, 4, [station(MAC_HW, 60_000, 95_000)]))
    ap.poll(data=poll(281.0, 2, []))
    await drain(hass)
    view = engine.client_view(me)
    assert view is not None
    assert (view.router_id, view.roaming_gaps) == (RID, 2)
    # never a delta across the time at the AP: the totals did not move
    assert (view.down_bytes, view.up_bytes) == (2_000, 1_000)
    assert view.down_bps is None
    assert view.unavailable["down_bps"] == "roaming_gap"


# --- area 25: high client counts -------------------------------------------------------------


def _ok(point: MeasurementPoint, mono: float, rx: int = 600, tx: int = 1_200) -> Rate:
    return Rate(
        point,
        Quality.OK,
        interval_s=60.0,
        rx_bps=rx * 8 / 60,
        tx_bps=tx * 8 / 60,
        rx_delta=rx,
        tx_delta=tx,
        coverage=Coverage.PARTIAL,
        source=Source.HOSTAPD,
        mono_s=mono,
    )


def test_tracker_has_a_hard_cap_with_visible_drops() -> None:
    tracker = ClientTracker(max_wifi=200, max_wired=10)
    points = [
        MeasurementPoint(
            RID, Scope.STATION, radio_id="phy0-ap0", client_ref=f"cli_{i:016x}"
        )
        for i in range(1_000)
    ]
    started = time.perf_counter()
    tracker.observe([_ok(p, 1.0) for p in points], {}, 1.0)
    tracker.observe([_ok(p, 61.0) for p in points], {}, 61.0)
    elapsed = time.perf_counter() - started
    assert tracker.wifi_count == 200
    assert tracker.counters["dropped_wifi_clients"] == 1_600
    assert elapsed < 2.0
    # an active client is never displaced; an idle one makes room
    newcomer = MeasurementPoint(
        RID, Scope.STATION, radio_id="phy0-ap0", client_ref="cli_" + "f" * 16
    )
    tracker.observe([_ok(newcomer, 100.0)], {}, 100.0)
    assert not tracker.is_wifi("cli_" + "f" * 16)
    later = 61.0 + 24 * 3600 + 1
    tracker.observe([_ok(newcomer, later)], {}, later)
    assert tracker.is_wifi("cli_" + "f" * 16)
    assert tracker.counters["replaced_clients"] == 1
    # the wired quota is separate: a full FDB never touches Wi-Fi clients
    tracker.observe_wired(
        RID,
        [WiredSighting(f"cli_{i:016x}", "lan1") for i in range(5_000, 5_050)],
        later,
    )
    assert tracker.wired_count == 10
    assert tracker.counters["dropped_wired_clients"] == 40
    assert tracker.wifi_count == 200
    assert tracker.prune(later + 25 * 3600) == 210
    assert len(tracker) == 0


async def test_engine_with_more_than_a_thousand_stations(disks: FakeDisks) -> None:
    hass = core_make_hass()
    entries = ("e1", "e2", "e3", "e4")
    engine, coords = await start(hass, disks, entries)
    per_router = 300
    macs = {
        entry: [
            f"02:00:5e:{n:02x}:{i // 256:02x}:{i % 256:02x}" for i in range(per_router)
        ]
        for n, entry in enumerate(entries, start=1)
    }
    fdb = {f"02:00:5f:00:{i // 256:02x}:{i % 256:02x}": "lan2" for i in range(400)}
    started = time.perf_counter()
    for step, mono in enumerate((100.0, 160.0, 220.0), start=1):
        for coord, entry in zip(coords, entries, strict=True):
            stations = [station(m, step * 1_000, step * 2_000) for m in macs[entry]]
            coord.poll(data=poll(mono, step, stations, fdb=fdb))
        await drain(hass)
        engine.clock.t += 60
    elapsed = time.perf_counter() - started
    assert elapsed < 10.0  # 3 polls x 4 routers x 300 stations, generous bound
    rids = [engine.router_id_of(e) for e in entries]
    for rid in rids:
        status = engine.status[rid]
        assert status.stations_total == per_router
        assert status.stations_dropped == per_router - MAX_STATIONS_PER_ROUTER
        # the infrastructure points keep their quota and their rates
        infra = {
            r.point.device: r
            for r in engine.rates_of(rid)
            if r.point.scope is not Scope.STATION
        }
        assert infra["wan"].quality is Quality.OK
        assert infra["br-lan"].quality is Quality.OK
    summary = engine.summary()
    assert summary["points"]["client"] <= MAX_POINTS_CLIENT
    assert summary["counters"]["dropped_points_client"] > 0
    assert summary["counters"]["stations_dropped"] > 0
    assert summary["clients"]["wifi"] <= MAX_TRACKED_WIFI_CLIENTS
    assert summary["clients"]["wired"] <= MAX_TRACKED_WIRED_CLIENTS
    assert summary["clients"]["dropped_wired_clients"] > 0
    assert summary["counters"]["wired_dropped"] == 3 * 4 * (400 - MAX_WIRED_PER_ROUTER)
    assert (
        len(engine.client_views())
        == engine.clients.wifi_count + engine.clients.wired_count
    )


# --- registry wiring ------------------------------------------------------------------------


async def test_registry_source_reads_the_running_client_engine(
    disks: FakeDisks,
) -> None:
    hass = core_make_hass()
    engine = TrafficEngine(hass)
    assert engine._client_history() is None  # client engine not running
    history = ClientHistory()
    cs = object.__new__(client_engine.ClientStability)
    cs.settings = {"enabled": True}
    cs.history = history
    hass.data[client_engine._DATA_KEY] = cs
    assert engine._client_history() is history
    cs.settings = {"enabled": False}
    assert engine._client_history() is None
    # without the module key there is no lookup at all
    assert engine._registry_lookup() is None
    engine._module_key = KEY
    cs.settings = {"enabled": True}
    assert engine._registry_lookup() is not None


def test_station_facts_carry_no_identifier() -> None:
    facts = StationFacts(True, RegistryFacts(True, "online", RID, "5g"))
    assert MAC_HW not in repr(facts)
    assert RegistryFacts(True, router_id="not-a-router-id").router_id is None
