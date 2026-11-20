"""VLAN traffic view (plan 2026-11-20, §4 "VLAN"): traffic_vlan.py.

Test area 14 of the task (§21): values only from measured VLAN netdevs,
configured membership shown apart, no invented totals, inter-VLAN and
WAN-related traffic unavailable, active clients only where provable. No
router, no network; MACs are locally administered test values.
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
from custom_components.openwrt_router.traffic_const import (
    BASIS_FDB_SINGLE_VLAN_PORT,
    REASON_NO_CLIENT_VLAN_SOURCE,
    REASON_NO_VLAN_NETDEV,
    REASON_NO_WIFI_VLAN_MAPPING,
    REASON_PORT_VLAN_AMBIGUOUS,
    REASON_PORT_VLAN_UNKNOWN,
    REASON_VLAN_NOT_CONFIGURED,
    SUM_NO_FLEET_VLAN_TOTAL,
    SUM_VLAN_NETDEVS_OVERLAP,
)
from custom_components.openwrt_router.traffic_engine import (
    TrafficEngine,
    async_setup_traffic,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)
from custom_components.openwrt_router.traffic_vlan import fleet_vlan_total, vlan_views

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
KEY = bytes(range(32))
MAC_A = "02:00:5e:20:00:01"
MAC_B = "02:00:5e:20:00:02"
MAC_C = "02:00:5e:20:00:03"
CONFIGURED = (("lan1", (10,)), ("lan2", (20,)), ("lan3", (10, 20)), ("wan", ()))


def vlan_point(device: str, vid: int, router: str = RID) -> MeasurementPoint:
    return MeasurementPoint(router, Scope.VLAN, device=device, vlan_id=vid)


def ok(
    point: MeasurementPoint,
    rx: int = 6_000,
    tx: int = 3_000,
    *,
    coverage: Coverage = Coverage.FULL,
    reason: CoverageReason | None = None,
) -> Rate:
    return Rate(
        point,
        Quality.OK,
        interval_s=60.0,
        rx_bps=rx * 8 / 60,
        tx_bps=tx * 8 / 60,
        rx_delta=rx,
        tx_delta=tx,
        coverage=coverage,
        coverage_reason=reason,
    )


def by_vid(views: list[Any]) -> dict[int, Any]:
    return {v.vlan_id: v for v in views}


def test_one_measured_netdev_gives_the_vlan_values() -> None:
    views = by_vid(
        vlan_views(
            RID,
            [ok(vlan_point("br-lan.10", 10))],
            port_vlans=CONFIGURED,
        )
    )
    assert sorted(views) == [10, 20]
    ten = views[10]
    assert (ten.rx_bps, ten.tx_bps) == (800.0, 400.0)
    assert (ten.rx_bytes, ten.tx_bytes) == (6_000, 3_000)
    assert ten.coverage is Coverage.FULL
    assert [d.device for d in ten.measured] == ["br-lan.10"]
    assert ten.configured_ports == ("lan1", "lan3")
    # router view of a netdev: no download/upload guess
    assert ten.direction.download is None and ten.direction.upload is None
    assert ten.direction.reason is not None
    for flow in (ten.inter_vlan, ten.wan_related):
        assert flow.coverage is Coverage.UNAVAILABLE
        assert flow.reason == "needs_flow_source"
    assert ten.unavailable["inter_vlan"] == "needs_flow_source"
    assert ten.unavailable["wan_related"] == "needs_flow_source"
    # configured only: shown, never turned into traffic
    twenty = views[20]
    assert twenty.measured == ()
    assert twenty.rx_bps is None and twenty.tx_bytes is None
    assert twenty.coverage is Coverage.UNAVAILABLE
    assert twenty.coverage_reasons == (REASON_NO_VLAN_NETDEV,)
    assert twenty.unavailable["rx_bps"] == REASON_NO_VLAN_NETDEV
    assert twenty.configured_ports == ("lan2", "lan3")


def test_offload_unknown_keeps_the_coverage_partial() -> None:
    rate = ok(
        vlan_point("br-lan.10", 10),
        coverage=Coverage.PARTIAL,
        reason=CoverageReason.HW_OFFLOAD_UNKNOWN,
    )
    (view,) = vlan_views(RID, [rate], port_vlans=None)
    assert view.coverage is Coverage.PARTIAL
    assert view.coverage_reasons == ("hw_offload_unknown",)
    assert view.rx_bps == 800.0


def test_several_netdevs_of_one_vlan_are_not_added() -> None:
    rates = [ok(vlan_point("br-lan.10", 10)), ok(vlan_point("lan1.10", 10), 100, 100)]
    (view,) = vlan_views(RID, rates, port_vlans=None)
    assert [d.device for d in view.measured] == ["br-lan.10", "lan1.10"]
    assert [d.rx_bytes for d in view.measured] == [6_000, 100]
    assert view.rx_bps is None and view.rx_bytes is None
    assert view.coverage is Coverage.UNAVAILABLE
    assert view.coverage_reasons == (SUM_VLAN_NETDEVS_OVERLAP,)
    assert view.unavailable["rx_bytes"] == SUM_VLAN_NETDEVS_OVERLAP


def test_first_sample_is_not_a_zero() -> None:
    rate = Rate(vlan_point("br-lan.10", 10), Quality.FIRST_SAMPLE)
    (view,) = vlan_views(RID, [rate], port_vlans=None)
    assert view.rx_bps is None and view.tx_bytes is None
    assert view.coverage is Coverage.UNAVAILABLE
    assert view.unavailable["rx_bps"] == Quality.FIRST_SAMPLE.value
    assert view.measured[0].quality == "first_sample"


def test_configured_ports_unknown_or_missing() -> None:
    rates = [ok(vlan_point("br-lan.30", 30))]
    (unknown,) = vlan_views(RID, rates, port_vlans=None)
    assert unknown.configured_ports == ()
    assert unknown.unavailable["configured_ports"] == REASON_PORT_VLAN_UNKNOWN
    (empty,) = vlan_views(RID, rates, port_vlans=())
    assert empty.unavailable["configured_ports"] == REASON_PORT_VLAN_UNKNOWN
    views = by_vid(vlan_views(RID, rates, port_vlans=CONFIGURED))
    assert views[30].configured_ports == ()
    assert views[30].unavailable["configured_ports"] == REASON_VLAN_NOT_CONFIGURED
    assert views[30].rx_bps == 800.0  # measured stays measured


def test_other_routers_and_other_scopes_are_ignored() -> None:
    rates = [
        ok(vlan_point("br-lan.10", 10, RID2)),
        ok(MeasurementPoint(RID, Scope.INTERFACE, device="br-lan")),
        ok(MeasurementPoint(RID, Scope.WAN, device="wan")),
    ]
    assert vlan_views(RID, rates, port_vlans=None) == []


@pytest.mark.parametrize(
    ("wired", "has_wifi", "count10", "coverage10", "note"),
    [
        (
            {"cli_a": "lan1", "cli_b": "lan1", "cli_c": "lan2"},
            False,
            2,
            Coverage.FULL,
            None,
        ),
        (
            {"cli_a": "lan1", "cli_c": "lan2"},
            True,
            1,
            Coverage.PARTIAL,
            REASON_NO_WIFI_VLAN_MAPPING,
        ),
        (
            {"cli_a": "lan1", "cli_b": "lan3"},
            False,
            1,
            Coverage.PARTIAL,
            REASON_PORT_VLAN_AMBIGUOUS,
        ),
    ],
)
def test_active_clients_only_from_single_vlan_ports(
    wired: dict[str, str],
    has_wifi: bool,
    count10: int,
    coverage10: Coverage,
    note: str | None,
) -> None:
    views = by_vid(
        vlan_views(RID, [], port_vlans=CONFIGURED, wired_ports=wired, has_wifi=has_wifi)
    )
    ten = views[10]
    assert ten.active_clients == count10
    assert ten.active_clients_coverage is coverage10
    assert ten.active_clients_basis == BASIS_FDB_SINGLE_VLAN_PORT
    assert ten.unavailable.get("active_clients_wifi") == note
    assert "active_clients" not in ten.unavailable


def test_no_active_clients_without_evidence() -> None:
    for wired in (None, {}):
        views = by_vid(vlan_views(RID, [], port_vlans=CONFIGURED, wired_ports=wired))
        assert views[10].active_clients is None
        assert views[10].active_clients_coverage is Coverage.UNAVAILABLE
        assert views[10].unavailable["active_clients"] == REASON_NO_CLIENT_VLAN_SOURCE
    # only ports with several VLANs: no provable count
    views = by_vid(
        vlan_views(
            RID,
            [],
            port_vlans=(("lan3", (10, 20)),),
            wired_ports={"cli_a": "lan3"},
        )
    )
    assert views[10].active_clients is None
    assert views[10].unavailable["active_clients"] == REASON_NO_CLIENT_VLAN_SOURCE


def test_no_fleet_wide_vlan_total() -> None:
    views = vlan_views(RID, [ok(vlan_point("br-lan.10", 10))], port_vlans=None)
    views += vlan_views(RID2, [ok(vlan_point("br-lan.10", 10, RID2))], port_vlans=None)
    total = fleet_vlan_total(views)
    assert not total.ok
    assert total.refused == SUM_NO_FLEET_VLAN_TOTAL
    assert total.rx_bps is None and total.omitted == 2


def test_view_is_json_safe() -> None:
    (view,) = vlan_views(
        RID,
        [ok(vlan_point("br-lan.10", 10))],
        port_vlans=(("lan1", (10,)),),
        wired_ports={"cli_" + "a" * 16: "lan1"},
    )
    dumped = json.dumps(view.to_dict())
    assert "cli_" not in dumped  # counts only, never client ids
    assert json.loads(dumped)["active_clients"] == 1


# --- engine wiring -----------------------------------------------------------------------------


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


def poll(mono: float, step: int) -> Any:
    data = router_data()
    data.wan_status = {**data.wan_status, "l3_device": "wan"}
    data.uptime = 5_000 + int(mono)
    data.device_counters = {
        "br-lan": _counters(step * 10_000, step * 20_000),
        "br-lan.10": _counters(step * 6_000, step * 3_000),
        "wan": _counters(step * 100_000, step * 10_000),
    }
    data.port_stats = [
        {"name": "lan1", "speed_mbps": 1000, "duplex": "full"},
        {"name": "lan2", "speed_mbps": 1000, "duplex": "full"},
        {"name": "lan3", "speed_mbps": 1000, "duplex": "full"},
    ]
    data.counters_sampled_mono = mono
    data.clients = [
        {"mac": MAC_C, "radio": "phy0-ap0", "rx_bytes": step, "tx_bytes": step}
    ]
    data.port_fdb_map = {MAC_A: "lan1", MAC_B: "lan2", MAC_C: "lan1"}
    data.port_vlan_map = {"lan1": [10], "lan2": [20], "lan3": [10, 20]}
    return data


async def test_engine_vlan_views(disks: FakeDisks) -> None:
    disks[TRAFFIC_COARSE_STORE_KEY].data = {
        "version": 1,
        "minor_version": 1,
        "key": TRAFFIC_COARSE_STORE_KEY,
        "data": {"settings": {"v": 1, "enabled": True, "routers": {}}},
    }
    hass = core_make_hass()
    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    engine.router_id_of = {"e1": RID}.get
    engine.clock = Clock()
    engine.wall = lambda: 1_800_000_000.0 + engine.clock()
    engine.registry_source = lambda: None
    coord = FakeCoordinator(poll(100.0, 1))
    coord.update_interval = timedelta(seconds=60)
    coord.poll_running = False
    await async_setup_traffic(hass, FakeEntry("e1"), coord)
    engine._module_key = KEY
    assert engine.vlan_views(RID2) == []  # unknown router: nothing invented
    coord.poll(data=poll(100.0, 1))
    await drain(hass)
    coord.poll(data=poll(160.0, 2))
    await drain(hass)
    views = by_vid(engine.vlan_views(RID))
    assert sorted(views) == [10, 20]
    ten = views[10]
    assert (ten.rx_bytes, ten.tx_bytes) == (6_000, 3_000)
    # offload state never probed: partial, never "full"
    assert ten.coverage is Coverage.PARTIAL
    assert "hw_offload_unknown" in ten.coverage_reasons
    assert ten.configured_ports == ("lan1", "lan3")
    # MAC_C is a Wi-Fi station: never counted as a wired VLAN client
    assert ten.active_clients == 1
    assert ten.active_clients_coverage is Coverage.PARTIAL
    assert ten.unavailable["active_clients_wifi"] == REASON_NO_WIFI_VLAN_MAPPING
    twenty = views[20]
    assert twenty.rx_bps is None
    assert twenty.unavailable["rx_bps"] == REASON_NO_VLAN_NETDEV
    assert twenty.active_clients == 1
    assert engine.port_vlans() == {
        RID: {"lan1": (10,), "lan2": (20,), "lan3": (10, 20)}
    }
    dumped = json.dumps([v.to_dict() for v in views.values()]).lower()
    assert MAC_A not in dumped and MAC_B not in dumped and "cli_" not in dumped
