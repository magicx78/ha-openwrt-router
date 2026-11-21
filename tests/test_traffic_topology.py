"""Traffic values on the topology snapshot (Phase J): traffic_topology.

The engine runs on FakeDisks with FakeCoordinator polls (as in
``test_traffic_engine``); the mesh snapshot is a small hand-made one with
the shape of ``topology_mesh.build_mesh_snapshot``. No router, no HA
instance, no network. Ids and MACs are synthetic.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from core_testkit import FakeDisks
from core_testkit import make_hass as core_make_hass
from test_traffic_engine import (
    _reset_pending,  # noqa: F401 - autouse fixture
    enabled,
    start,
    two_polls,
)

from custom_components.openwrt_router import traffic_topology as tt
from custom_components.openwrt_router.const import DATA_TRAFFIC_ANALYTICS
from custom_components.openwrt_router.topology_panel import _with_traffic

GW = "02:00:5e:20:00:01"  # topology node ids are router MACs
AP = "02:00:5e:20:00:02"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def snapshot() -> dict[str, Any]:
    return {
        "nodes": [
            {"id": GW, "type": "router", "attributes": {"mac": GW}},
            {"id": AP, "type": "router", "attributes": {"mac": AP}},
            {"id": "c1", "type": "client", "attributes": {}},
        ],
        "edges": [
            {
                "id": f"{GW}--uplink--{AP}",
                "from": GW,
                "to": AP,
                "relationship": "router_uplink",
                "attributes": {"from_port": "lan1", "to_port": "wan"},
            },
            {"id": "x", "from": GW, "to": "lan9", "relationship": "router_uplink"},
            {"id": "w", "from": AP, "to": "c1", "relationship": "wifi_client"},
        ],
        "meta": {"routers": 2},
    }


def with_entries(hass: Any) -> Any:
    """Config entries whose first router is the engine's entry e1."""
    entry = SimpleNamespace(
        entry_id="e1",
        data={"host": "10.0.0.1"},
        runtime_data=SimpleNamespace(
            coordinator=SimpleNamespace(data=SimpleNamespace(router_info={"mac": GW}))
        ),
    )
    other = SimpleNamespace(
        entry_id="e2",
        data={"host": "10.0.0.2"},
        runtime_data=SimpleNamespace(
            coordinator=SimpleNamespace(data=SimpleNamespace(router_info={"mac": AP}))
        ),
    )
    hass.config_entries.async_entries = MagicMock(return_value=[entry, other])
    return hass


async def test_off_leaves_the_snapshot_untouched(disks) -> None:
    for hass in (core_make_hass(), None):
        if hass is None:  # engine present but switched off
            hass = with_entries(core_make_hass())
            engine, _coord = await start(hass)
            assert not engine.active
        snap = snapshot()
        before = copy.deepcopy(snap)
        assert tt.annotate_snapshot(hass, snap) is snap
        assert snap == before
        assert _with_traffic(hass, snap) is snap
        assert snap == before


async def test_active_annotates_routers_and_uplinks_only(disks) -> None:
    hass = with_entries(core_make_hass())
    enabled(disks)
    engine, coord = await start(hass)
    await two_polls(engine, coord, hass)
    calls = len(coord.router_calls())
    snap = snapshot()
    shape = copy.deepcopy(snap)
    out = tt.annotate_snapshot(hass, snap)
    assert len(coord.router_calls()) == calls  # no router call
    # nothing added or removed: same nodes, same edges, same other keys
    assert [n["id"] for n in out["nodes"]] == [n["id"] for n in shape["nodes"]]
    assert [e["id"] for e in out["edges"]] == [e["id"] for e in shape["edges"]]
    assert out["meta"]["routers"] == 2

    gw = out["nodes"][0]["attributes"]["traffic"]
    assert gw["state"] == "available"
    assert gw["wan"]["down_bps"] == pytest.approx(1_000_000.0)
    assert gw["wan"]["coverage"] == "partial"
    lan1 = gw["ports"]["lan1"]
    assert lan1["rx_bps"] is not None
    assert lan1["down_bps"] is None  # bridged: no guessed direction
    if lan1["link_mbps"] is None:
        assert lan1["utilization_pct"] is None
        assert lan1["utilization_reason"] == "link_speed_unknown"
    else:
        assert lan1["utilization_pct"] is not None
    ap = out["nodes"][1]["attributes"]["traffic"]
    assert ap == {"state": "unavailable", "reason": "router_not_measured"}
    assert "traffic" not in out["nodes"][2]["attributes"]  # clients untouched

    uplink = out["edges"][0]["attributes"]["traffic"]
    assert uplink["from_port"] == lan1
    assert uplink["to_port"] is None
    assert uplink["to_port_reason"] == "router_not_measured"
    bare = out["edges"][1]["attributes"]["traffic"]
    assert bare["from_port"] is None and bare["from_port_reason"] == "port_not_measured"
    assert "attributes" not in out["edges"][2]  # other relations untouched
    assert out["edges"][0]["attributes"]["from_port"] == "lan1"  # kept

    meta = out["meta"]["traffic"]
    assert meta["status"] in {"ready", "not_ready"}
    assert meta["flow_relations"] == {
        "state": "unavailable",
        "reason": "needs_flow_source",
    }
    # no pseudonym is linked to a topology node
    body = json.dumps(out)
    for token in ("rtr_", "tpt_", "cli_", "phy0-ap0"):
        assert token not in body, token


async def test_a_failing_annotation_never_costs_the_topology(disks) -> None:
    hass = with_entries(core_make_hass())
    enabled(disks)
    engine, coord = await start(hass)
    await two_polls(engine, coord, hass)
    snap = snapshot()
    before = copy.deepcopy(snap)
    with patch.object(tt, "_router_traffic", side_effect=RuntimeError("boom")):
        assert _with_traffic(hass, snap) is snap
    assert snap == before  # built completely before it is applied


async def test_shared_attribute_dicts_are_not_changed_in_place(disks) -> None:
    hass = with_entries(core_make_hass())
    enabled(disks)
    engine, coord = await start(hass)
    await two_polls(engine, coord, hass)
    shared: dict[str, Any] = {"mac": GW}
    snap = snapshot()
    snap["nodes"][0]["attributes"] = shared
    tt.annotate_snapshot(hass, snap)
    assert shared == {"mac": GW}
    assert hass.data[DATA_TRAFFIC_ANALYTICS] is engine


def test_router_id_for_entry_is_none_for_unknown_entries() -> None:
    from custom_components.openwrt_router.traffic_engine import TrafficEngine

    engine = TrafficEngine(core_make_hass())
    assert engine.router_id_for_entry("nope") is None
