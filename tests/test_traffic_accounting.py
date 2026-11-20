"""Traffic accounting (plan 2026-11-20, §3.5): traffic_accounting.py.

Test areas of the task (§21): 9 NAT-related attribution, 10 hardware
offloading, 11 avoiding double counting. Pure functions plus the engine
end to end on fake coordinators. No router, no network; router ids and MACs
are synthetic test values (locally administered MACs).
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import pytest
from core_testkit import FakeCoordinator, FakeDisks, FakeEntry, drain, router_data
from core_testkit import make_hass as core_make_hass

from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ANALYTICS,
    TRAFFIC_COARSE_STORE_KEY,
)
from custom_components.openwrt_router.traffic_accounting import (
    MEASURING_SCOPES,
    SightingBook,
    TrafficAccounting,
    classify,
    direction_map,
    down_up,
    offload_coverage,
    sum_rates,
    wan_client_attribution,
)
from custom_components.openwrt_router.traffic_collect import OffloadState
from custom_components.openwrt_router.traffic_const import (
    DIR_AMBIGUOUS_BRIDGE,
    DIR_PORT_ROLE_UNKNOWN,
    NOTE_DIRECTION_MISSING,
    NOTE_POINTS_OMITTED,
    NOTE_PORT_COUNTERS_UNVERIFIED,
    NOTE_RX_TX_SEPARATE,
    PORT_ROLE_DOWNLINK,
    PORT_ROLE_UPLINK,
    SIGHTING_WINDOW_S,
    SUM_BRIDGE_PLUS_PORTS,
    SUM_CLIENT_PLUS_WAN,
    SUM_DUPLICATE_CLIENT,
    SUM_DUPLICATE_POINT,
    SUM_INTERFACE_PLUS_VLAN,
    SUM_INTERFACES_OVERLAP,
    SUM_MIXED_SCOPES,
    SUM_NEEDS_FLOW_SOURCE,
    SUM_NO_POINTS,
    SUM_PORT_IS_UPLINK,
    SUM_PORTS_OF_SEVERAL_ROUTERS,
    SUM_STATION_PLUS_PORT,
    SUM_UPLINKS_UNKNOWN,
    SUM_VLAN_NETDEVS_OVERLAP,
    SUM_WAN_SAME_ROUTER,
)
from custom_components.openwrt_router.traffic_engine import (
    TrafficEngine,
    async_get_traffic_engine,
    async_setup_traffic,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Perspective,
    Quality,
    Rate,
    Scope,
    Source,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
RID3 = "rtr_" + "3" * 32
CLI = "cli_" + "a" * 16
CLI2 = "cli_" + "b" * 16
KEY = bytes(range(32))
MAC1 = "02:00:5e:10:00:01"
UNKNOWN = OffloadState(None, None)
HW_ON = OffloadState(True, True)
HW_OFF = OffloadState(True, False)


# --- helpers ------------------------------------------------------------------------------


def wan(rid: str = RID, device: str = "wan") -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.WAN, device=device)


def iface(device: str, rid: str = RID) -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.INTERFACE, device=device)


def port(device: str, rid: str = RID) -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.PORT, device=device)


def vlan(device: str, vid: int, rid: str = RID) -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.VLAN, device=device, vlan_id=vid)


def sta(ref: str = CLI, rid: str = RID, radio: str = "phy0-ap0") -> MeasurementPoint:
    return MeasurementPoint(rid, Scope.STATION, radio_id=radio, client_ref=ref)


def client(ref: str = CLI) -> MeasurementPoint:
    return MeasurementPoint(None, Scope.CLIENT, client_ref=ref)


def rate(
    point: MeasurementPoint,
    rx: float | None = 8_000.0,
    tx: float | None = 16_000.0,
    *,
    quality: Quality = Quality.OK,
    mono: float | None = 100.0,
    coverage: Coverage = Coverage.UNKNOWN,
    reason: CoverageReason | None = None,
) -> Rate:
    valid = quality in (Quality.OK, Quality.WRAP_32)
    return Rate(
        point,
        quality,
        interval_s=60.0 if valid else None,
        rx_bps=rx if valid else None,
        tx_bps=tx if valid else None,
        rx_delta=None if rx is None or not valid else int(rx * 60 / 8),
        tx_delta=None if tx is None or not valid else int(tx * 60 / 8),
        coverage=coverage if valid else Coverage.UNAVAILABLE,
        coverage_reason=reason,
        source=Source.HOSTAPD if point.scope is Scope.STATION else Source.NETDEV,
        mono_s=mono,
        wall_s=None if mono is None else 1_800_000_000.0 + mono,
    )


def full(point: MeasurementPoint, rx: float = 8_000.0, tx: float = 16_000.0) -> Rate:
    return rate(point, rx, tx, coverage=Coverage.FULL)


# --- measuring areas and RX/TX semantics -------------------------------------------------


def test_seven_measuring_areas_are_kept_apart() -> None:
    assert set(MEASURING_SCOPES) == set(Scope)
    assert len(MEASURING_SCOPES) == 7


def test_wan_download_is_rx_and_upload_is_tx() -> None:
    mapping = direction_map(wan())
    assert mapping.perspective is Perspective.ROUTER
    assert (mapping.download, mapping.upload) == ("rx", "tx")
    assert down_up(rate(wan(), 1_000.0, 200.0)) == (1_000.0, 200.0)


@pytest.mark.parametrize("point", [sta(), client()])
def test_station_and_client_directions_are_turned(point: MeasurementPoint) -> None:
    mapping = direction_map(point)
    assert mapping.perspective is Perspective.STATION
    assert (mapping.download, mapping.upload) == ("tx", "rx")
    # the AP sent 16 kbit/s to the client: the client's download
    assert down_up(rate(point, 8_000.0, 16_000.0)) == (16_000.0, 8_000.0)


@pytest.mark.parametrize(
    "point", [iface("br-lan"), iface("eth0"), vlan("br-lan.10", 10)]
)
def test_bridge_interface_and_vlan_give_rx_tx_only(point: MeasurementPoint) -> None:
    mapping = direction_map(point)
    assert mapping.download is None and mapping.upload is None
    assert mapping.reason == DIR_AMBIGUOUS_BRIDGE
    assert down_up(rate(point)) == (None, None)


def test_port_download_upload_only_with_a_known_role() -> None:
    assert direction_map(port("lan1")).reason == DIR_PORT_ROLE_UNKNOWN
    assert down_up(rate(port("lan1"), 1.0, 2.0)) == (None, None)
    assert down_up(rate(port("lan1"), 1.0, 2.0), port_role=PORT_ROLE_UPLINK) == (
        1.0,
        2.0,
    )
    assert down_up(rate(port("lan1"), 1.0, 2.0), port_role=PORT_ROLE_DOWNLINK) == (
        2.0,
        1.0,
    )


def test_invalid_rate_has_no_download_or_upload() -> None:
    assert down_up(rate(wan(), quality=Quality.FIRST_SAMPLE)) == (None, None)


def test_direction_map_is_json_safe() -> None:
    dumped = json.dumps(direction_map(sta()).to_dict())
    assert '"perspective": "station"' in dumped


# --- area 9: NAT-related attribution --------------------------------------------------------


def test_nat_wan_traffic_is_not_attributed_to_clients_without_flow_source() -> None:
    attribution = wan_client_attribution()
    assert attribution.coverage is Coverage.UNAVAILABLE
    assert attribution.reason == CoverageReason.NEEDS_FLOW_SOURCE.value
    assert attribution.to_dict() == {
        "coverage": "unavailable",
        "reason": "needs_flow_source",
    }


def test_nat_client_plus_wan_is_refused() -> None:
    result = sum_rates([full(client()), full(wan())])
    assert not result.ok and result.refused == SUM_CLIENT_PLUS_WAN
    assert result.rx_bps is None and result.tx_bps is None
    assert result.coverage is Coverage.UNAVAILABLE
    assert result.omitted == 2 and result.contributing == 0


def test_nat_station_plus_wan_is_a_mixed_refusal() -> None:
    result = sum_rates([full(sta()), full(wan())])
    assert result.refused == SUM_MIXED_SCOPES


def test_nat_flow_scope_needs_a_flow_source() -> None:
    flow = MeasurementPoint(RID, Scope.FLOW)
    accounted = classify(rate(flow), offload=HW_OFF)
    assert accounted.coverage is Coverage.UNAVAILABLE
    assert accounted.coverage_reason is CoverageReason.NEEDS_FLOW_SOURCE
    assert sum_rates([rate(flow)]).refused == SUM_NEEDS_FLOW_SOURCE


def test_nat_wan_values_stay_what_the_line_carried() -> None:
    # the accounting never splits or redistributes WAN bytes to anyone
    accounted = classify(rate(wan(), 5_000.0, 1_000.0), offload=HW_OFF)
    assert (accounted.rx_bps, accounted.tx_bps) == (5_000.0, 1_000.0)
    assert accounted.point.client_ref is None


# --- area 10: hardware offloading ----------------------------------------------------------


@pytest.mark.parametrize(
    ("offload", "coverage", "reason"),
    [
        (None, Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_UNKNOWN),
        (UNKNOWN, Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_UNKNOWN),
        (OffloadState(True, None), Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_UNKNOWN),
        (HW_ON, Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_ON),
        (HW_OFF, Coverage.FULL, None),
        (OffloadState(False, False), Coverage.FULL, None),
    ],
)
@pytest.mark.parametrize(
    "point", [wan(), iface("br-lan"), vlan("br-lan.10", 10), iface("eth0")]
)
def test_offload_state_sets_wan_and_bridge_coverage(
    point: MeasurementPoint,
    offload: OffloadState | None,
    coverage: Coverage,
    reason: CoverageReason | None,
) -> None:
    assert offload_coverage(offload) == (coverage, reason)
    accounted = classify(rate(point), offload=offload)
    assert (accounted.coverage, accounted.coverage_reason) == (coverage, reason)
    assert accounted.rx_bps == 8_000.0  # values are never changed


@pytest.mark.parametrize("offload", [None, HW_ON, HW_OFF])
def test_offload_does_not_touch_ports_and_stations(offload: Any) -> None:
    assert classify(rate(port("lan1")), offload=offload).coverage is Coverage.FULL
    station = classify(rate(sta()), offload=offload)
    assert station.coverage is Coverage.PARTIAL
    assert station.coverage_reason is CoverageReason.STATION_COUNTERS_ONLY


def test_offload_never_makes_an_invalid_rate_valid() -> None:
    gap = rate(wan(), quality=Quality.GAP)
    assert classify(gap, offload=HW_OFF) is gap
    assert gap.coverage is Coverage.UNAVAILABLE


def test_wan_sum_over_gateways_carries_the_offload_reason() -> None:
    a = classify(rate(wan(RID), 1_000.0, 100.0), offload=HW_OFF)
    b = classify(rate(wan(RID2), 2_000.0, 200.0), offload=None)
    result = sum_rates([a, b])
    assert result.ok and result.scope is Scope.WAN
    assert (result.rx_bps, result.tx_bps) == (3_000.0, 300.0)
    assert result.coverage is Coverage.PARTIAL
    assert result.coverage_reasons == ("hw_offload_unknown",)
    assert (result.contributing, result.omitted, result.routers) == (2, 0, 2)
    both_off = sum_rates([a, classify(rate(wan(RID2)), offload=HW_OFF)])
    assert both_off.coverage is Coverage.FULL and both_off.coverage_reasons == ()


# --- area 11: no double counting -------------------------------------------------------------


@pytest.mark.parametrize(
    ("points", "reason"),
    [
        ([sta(), port("lan1")], SUM_STATION_PLUS_PORT),
        ([iface("eth0"), vlan("br-lan.10", 10)], SUM_INTERFACE_PLUS_VLAN),
        ([iface("br-lan"), vlan("br-lan.10", 10)], SUM_INTERFACE_PLUS_VLAN),
        ([client(), wan()], SUM_CLIENT_PLUS_WAN),
        ([iface("br-lan"), port("lan1"), port("lan2")], SUM_BRIDGE_PLUS_PORTS),
        ([iface("eth0"), port("lan1")], SUM_MIXED_SCOPES),
        ([sta(), client()], SUM_MIXED_SCOPES),
        ([wan(), port("lan1")], SUM_MIXED_SCOPES),
    ],
)
def test_sums_across_areas_are_refused_with_a_name(
    points: list[MeasurementPoint], reason: str
) -> None:
    result = sum_rates([full(p) for p in points])
    assert result.refused == reason
    assert result.rx_bps is None and result.rx_bytes is None
    assert result.coverage is Coverage.UNAVAILABLE
    assert result.contributing == 0 and result.omitted == len(points)


@pytest.mark.parametrize(
    ("points", "reason"),
    [
        ([iface("br-lan"), iface("phy0-ap0")], SUM_INTERFACES_OVERLAP),
        ([iface("br-lan", RID), iface("br-lan", RID2)], SUM_INTERFACES_OVERLAP),
        ([vlan("br-lan.10", 10), vlan("lan1.10", 10)], SUM_VLAN_NETDEVS_OVERLAP),
        ([vlan("br-lan.10", 10), vlan("br-lan.20", 20)], SUM_VLAN_NETDEVS_OVERLAP),
        ([wan(RID, "wan"), wan(RID, "pppoe-wan")], SUM_WAN_SAME_ROUTER),
        ([port("lan1", RID), port("lan1", RID2)], SUM_PORTS_OF_SEVERAL_ROUTERS),
    ],
)
def test_overlapping_points_of_one_area_are_refused(
    points: list[MeasurementPoint], reason: str
) -> None:
    uplinks = {RID: frozenset(), RID2: frozenset()}
    assert sum_rates([full(p) for p in points], uplink_ports=uplinks).refused == reason


def test_same_point_twice_is_refused() -> None:
    assert sum_rates([full(wan()), full(wan())]).refused == SUM_DUPLICATE_POINT


def test_empty_sum_is_refused() -> None:
    result = sum_rates([])
    assert result.refused == SUM_NO_POINTS and result.scope is None


def test_port_sum_needs_known_uplinks_and_skips_trunk_ports() -> None:
    ports = [full(port("lan1"), 800.0, 80.0), full(port("lan2"), 200.0, 20.0)]
    assert sum_rates(ports).refused == SUM_UPLINKS_UNKNOWN
    assert sum_rates(ports, uplink_ports={RID: None}).refused == SUM_UPLINKS_UNKNOWN
    trunk = sum_rates(ports, uplink_ports={RID: frozenset({"lan2"})})
    assert trunk.refused == SUM_PORT_IS_UPLINK
    ok = sum_rates(ports, uplink_ports={RID: frozenset({"lan4"})})
    assert ok.ok and (ok.rx_bps, ok.tx_bps) == (1_000.0, 100.0)
    assert ok.coverage is Coverage.FULL
    assert NOTE_PORT_COUNTERS_UNVERIFIED in ok.notes


def test_sum_counts_contributing_and_omitted_points() -> None:
    a = classify(rate(wan(RID), 1_000.0, 100.0), offload=HW_OFF)
    b = rate(wan(RID2), quality=Quality.COUNTER_RESET)
    c = rate(wan(RID3), quality=Quality.GAP)
    result = sum_rates([a, b, c])
    assert result.ok
    assert (result.contributing, result.omitted) == (1, 2)
    assert result.omitted_by_quality == {"counter_reset": 1, "gap": 1}
    assert result.coverage is Coverage.PARTIAL  # omitted points: never "full"
    assert NOTE_POINTS_OMITTED in result.notes
    assert result.rx_bps == 1_000.0


def test_sum_without_any_valid_point_is_unavailable_not_zero() -> None:
    result = sum_rates([rate(wan(), quality=Quality.FIRST_SAMPLE)])
    assert result.ok and result.contributing == 0
    assert result.rx_bps is None and result.tx_bps is None
    assert result.coverage is Coverage.UNAVAILABLE


def test_sum_with_a_missing_direction_is_partial() -> None:
    a = full(wan(RID), 1_000.0, 100.0)
    b = rate(wan(RID2), 500.0, None, coverage=Coverage.FULL)
    result = sum_rates([a, b])
    assert result.rx_bps == 1_500.0 and result.tx_bps == 100.0
    assert result.coverage is Coverage.PARTIAL
    assert NOTE_DIRECTION_MISSING in result.notes


def test_rx_and_tx_are_never_added_together() -> None:
    result = sum_rates([full(wan(RID)), full(wan(RID2))])
    assert NOTE_RX_TX_SEPARATE in result.notes
    keys = set(result.to_dict())
    assert not {k for k in keys if "total" in k or "combined" in k}
    json.dumps(result.to_dict())


def test_station_sum_refuses_the_same_client_twice() -> None:
    two = [full(sta(CLI, RID)), full(sta(CLI, RID2))]
    assert sum_rates(two).refused == SUM_DUPLICATE_CLIENT
    distinct = sum_rates([full(sta(CLI, RID)), full(sta(CLI2, RID2))])
    assert distinct.ok and distinct.contributing == 2


def test_station_sum_skips_a_stale_duplicate() -> None:
    accounting = TrafficAccounting()
    out = accounting.account(
        [rate(sta(CLI, RID), mono=100.0), rate(sta(CLI, RID2), mono=101.0)],
        offload=None,
        registry_router={CLI: RID2},
    )
    result = sum_rates(out)
    assert result.ok and result.contributing == 1 and result.omitted == 1
    assert result.omitted_by_quality == {"stale_source": 1}


def test_duplicate_sighting_counts_only_at_the_registry_ap() -> None:
    accounting = TrafficAccounting()
    out = accounting.account(
        [rate(sta(CLI, RID), mono=100.0), rate(sta(CLI, RID2), mono=100.0)],
        offload=None,
        registry_router={CLI: RID},
    )
    assert out[0].quality is Quality.OK
    assert out[1].quality is Quality.STALE_SOURCE
    assert out[1].rx_bps is None and out[1].rx_delta is None
    assert out[1].coverage is Coverage.UNAVAILABLE
    assert accounting.summary()["duplicate_sightings"] == 1


def test_duplicate_decision_does_not_depend_on_processing_order() -> None:
    for order in ((RID, RID2), (RID2, RID)):
        accounting = TrafficAccounting()
        results = {}
        for i, rid in enumerate(order):
            [out] = accounting.account(
                [rate(sta(CLI, rid), mono=100.0 + i)],
                offload=None,
                registry_router={CLI: RID2},
            )
            results[rid] = out.quality
        assert results == {RID: Quality.STALE_SOURCE, RID2: Quality.OK}


def test_without_registry_the_newest_association_counts() -> None:
    accounting = TrafficAccounting()
    accounting.account([rate(sta(CLI, RID), mono=100.0)], offload=None)
    # the client shows up at a second AP; the first one still lists it
    [new] = accounting.account([rate(sta(CLI, RID2), mono=130.0)], offload=None)
    [old] = accounting.account([rate(sta(CLI, RID), mono=150.0)], offload=None)
    assert new.quality is Quality.OK
    assert old.quality is Quality.STALE_SOURCE


def test_two_radios_of_one_router_count_once() -> None:
    accounting = TrafficAccounting()
    out = accounting.account(
        [
            rate(sta(CLI, RID, "phy1-ap0"), mono=100.0),
            rate(sta(CLI, RID, "phy0-ap0"), mono=100.0),
        ],
        offload=None,
        registry_router={CLI: RID},
    )
    qualities = sorted(r.quality.value for r in out)
    assert qualities == ["ok", "stale_source"]
    # tie: the smallest radio id wins, deterministically
    assert out[1].quality is Quality.OK


def test_sightings_outside_the_window_are_no_duplicate() -> None:
    accounting = TrafficAccounting()
    accounting.account([rate(sta(CLI, RID), mono=100.0)], offload=None)
    later = 100.0 + SIGHTING_WINDOW_S + 1
    [out] = accounting.account([rate(sta(CLI, RID2), mono=later)], offload=None)
    assert out.quality is Quality.OK
    assert accounting.summary()["duplicate_sightings"] == 0


def test_different_clients_are_never_merged() -> None:
    accounting = TrafficAccounting()
    out = accounting.account(
        [rate(sta(CLI, RID), mono=100.0), rate(sta(CLI2, RID2), mono=100.0)],
        offload=None,
    )
    assert [r.quality for r in out] == [Quality.OK, Quality.OK]


def test_sighting_book_is_bounded_and_counts_refusals() -> None:
    book = SightingBook(max_clients=2, max_assoc=2)
    assert book.see("cli_" + "1" * 16, (RID, "a"), 1.0)
    assert book.see("cli_" + "2" * 16, (RID, "a"), 1.0)
    assert not book.see("cli_" + "3" * 16, (RID, "a"), 2.0)
    assert book.counters["untracked_sightings"] == 1
    # an association quota per client: the oldest makes room
    ref = "cli_" + "1" * 16
    book.see(ref, (RID2, "a"), 3.0)
    book.see(ref, (RID3, "a"), 4.0)
    assert book.winner(ref, 4.0) == (RID3, "a")
    # an old entry is pruned, the slot is free again
    later = 10.0 + SIGHTING_WINDOW_S
    assert book.see("cli_" + "3" * 16, (RID, "a"), later)
    book.drop_router(RID)
    book.clear()
    assert len(book) == 0


def test_untracked_sighting_is_counted_but_not_dropped() -> None:
    accounting = TrafficAccounting(SightingBook(max_clients=0))
    [out] = accounting.account([rate(sta(), mono=1.0)], offload=None)
    assert out.quality is Quality.OK
    assert accounting.summary()["untracked_sightings"] == 1


def test_rates_without_time_skip_the_duplicate_rule() -> None:
    accounting = TrafficAccounting()
    out = accounting.account(
        [rate(sta(CLI, RID), mono=None), rate(sta(CLI, RID2), mono=None)],
        offload=None,
    )
    assert [r.quality for r in out] == [Quality.OK, Quality.OK]


# --- engine end to end ------------------------------------------------------------------------


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


def poll(mono: float, step: int, *, wan: bool = True, macs: tuple = ()) -> Any:
    data = router_data()
    data.wan_status = {**data.wan_status, "l3_device": "wan"}
    data.uptime = 5_000 + int(mono)
    devices = {"br-lan": _counters(step * 1000, step * 2000)}
    if wan:
        devices["wan"] = _counters(step * 100_000, step * 10_000)
    data.device_counters = devices
    data.counters_sampled_mono = mono
    data.clients = [
        {
            "mac": mac,
            "radio": "phy0-ap0",
            "rx_bytes": step * 500,
            "tx_bytes": step * 900,
        }
        for mac in macs
    ]
    return data


async def start_two(hass: Any, disks: FakeDisks) -> tuple[TrafficEngine, Any, Any]:
    disks[TRAFFIC_COARSE_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": TRAFFIC_COARSE_STORE_KEY,
        "data": {"settings": {"v": 1, "enabled": True, "routers": {}}},
    }
    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    engine.router_id_of = {"e1": RID, "e2": RID2}.get
    engine.clock = Clock()
    engine.wall = lambda: 1_800_000_000.0 + engine.clock()
    coords = []
    for entry_id in ("e1", "e2"):
        coord = FakeCoordinator(poll(100.0, 1))
        coord.update_interval = timedelta(seconds=60)
        coord.poll_running = False
        await async_setup_traffic(hass, FakeEntry(entry_id), coord)
        coords.append(coord)
    assert async_get_traffic_engine(hass) is engine
    return engine, coords[0], coords[1]


async def test_engine_rates_pass_the_accounting(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, gw, _ap = await start_two(hass, disks)
    gw.poll(data=poll(100.0, 1))
    await drain(hass)
    gw.poll(data=poll(160.0, 2))
    await drain(hass)
    rates = {r.point.device: r for r in engine.rates_of(RID)}
    assert rates["wan"].coverage is Coverage.PARTIAL
    assert rates["wan"].coverage_reason is CoverageReason.HW_OFFLOAD_UNKNOWN
    assert rates["br-lan"].coverage_reason is CoverageReason.HW_OFFLOAD_UNKNOWN
    assert rates["wan"].mono_s == 160.0
    # a known offload state changes the coverage of the next rates
    engine.offload[RID] = OffloadState(True, False)
    gw.poll(data=poll(220.0, 3))
    await drain(hass)
    assert engine.latest[rates["wan"].point.point_id].coverage is Coverage.FULL
    engine.offload[RID] = OffloadState(True, True)
    gw.poll(data=poll(280.0, 4))
    await drain(hass)
    wan_rate = engine.latest[rates["wan"].point.point_id]
    assert wan_rate.coverage_reason is CoverageReason.HW_OFFLOAD_ON
    assert "accounting" in engine.summary()


async def test_engine_counts_a_client_seen_at_two_aps_once(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, gw, ap = await start_two(hass, disks)
    engine._module_key = KEY
    for step, mono in enumerate((100.0, 160.0, 220.0), start=1):
        gw.poll(data=poll(mono, step, macs=(MAC1,)))
        ap.poll(data=poll(mono + 5, step, wan=False, macs=(MAC1,)))
        await drain(hass)
    stations = [r for r in engine.latest.values() if r.point.scope is Scope.STATION]
    assert len(stations) == 2
    qualities = sorted(r.quality.value for r in stations)
    assert qualities == ["ok", "stale_source"]
    result = sum_rates(stations)
    assert result.ok and result.contributing == 1
    assert result.omitted_by_quality == {"stale_source": 1}
    assert engine.summary()["accounting"]["duplicate_sightings"] >= 2
    assert engine.summary()["rates_by_quality"]["stale_source"] >= 2
    dumped = json.dumps(engine.summary()) + json.dumps(
        [r.to_dict() for r in engine.latest.values()]
    )
    assert MAC1 not in dumped.lower()


async def test_engine_sum_latest_uses_the_topology_uplinks(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine, gw, ap = await start_two(hass, disks)
    for step, mono in enumerate((100.0, 160.0), start=1):
        gw.poll(data=poll(mono, step))
        ap.poll(data=poll(mono + 5, step, wan=False))
        await drain(hass)
    wans = [p for p, r in engine.latest.items() if r.point.scope is Scope.WAN]
    result = engine.sum_latest([*wans, "tpt_" + "0" * 16])
    assert result.ok and result.contributing == 1
    assert result.omitted_by_quality == {"source_missing": 1}
    assert result.coverage is Coverage.PARTIAL
    assert NOTE_POINTS_OMITTED in result.notes
    assert engine.uplink_ports() == {RID: frozenset(), RID2: frozenset()}
    bridges = [p for p, r in engine.latest.items() if r.point.device == "br-lan"]
    assert engine.sum_latest(bridges).refused == SUM_INTERFACES_OVERLAP


async def test_engine_off_runs_no_accounting(disks: FakeDisks) -> None:
    hass = core_make_hass()
    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    coord = FakeCoordinator(poll(100.0, 1))
    await async_setup_traffic(hass, FakeEntry("e1"), coord)
    coord.poll()
    assert engine.accounting.summary() == {
        "duplicate_sightings": 0,
        "untracked_sightings": 0,
        "sighting_clients": 0,
    }
    assert coord.router_calls() == []
