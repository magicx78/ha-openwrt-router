"""Traffic Analytics regression guard (test area 33, plan 2026-11-20).

* Switched off, traffic analytics costs 0 extra router calls; switched on
  without any extra-call option it still costs 0 (stage A-standard reads
  only what the poll already fetched).
* ``coordinator.data.as_dict()`` and the existing sensors (``unique_id``,
  WAN and interface values) do not change.
* The three switchable ``api.py`` reads reject path-like or over-long
  netdev names before any router call.

Real ``OpenWrtAPI`` + ``OpenWrtCoordinator`` on the ubus session mock of
``test_poll_no_ssh``; no router, no network (conftest blocks it).
"""

from __future__ import annotations

import time as time_module
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import test_poll_no_ssh as model
from core_testkit import FakeDisks, FakeEntry
from core_testkit import make_hass as core_make_hass

from custom_components.openwrt_router import OpenWrtRuntimeData
from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.const import DATA_TRAFFIC_ANALYTICS
from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinatorData,
    traffic_device_counters,
)
from custom_components.openwrt_router.sensor import async_setup_entry as sensor_setup
from custom_components.openwrt_router.traffic_const import SYSFS_COUNTER_FILES
from custom_components.openwrt_router.traffic_engine import (
    TrafficEngine,
    async_release_traffic,
    async_setup_traffic,
)

RID = "rtr_" + "1" * 32
MAC = "02:00:5e:10:00:01"
TRAFFIC_FIELDS = (
    "device_counters",
    "counters_sampled_mono",
    "active_connections_source",
)


def _api(session: Any) -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=session,
        protocol="http",
    )
    # LLDP is the one allowed SSH reader (600 s cadence): primed, not measured
    api._lldp_checked = True
    api._lldp_available = False
    api._lldp_last_fetch = time_module.monotonic()
    return api


async def _run_polls(mode: str, polls: int = 3) -> tuple[int, Any, Any]:
    """Polls with traffic analytics absent / off / on; returns the call count."""
    session = model._ubus_session()
    coord = model._make_coordinator(_api(session))
    hass = core_make_hass()
    engine: TrafficEngine | None = None
    with FakeDisks().patch() as disks:
        if mode != "absent":
            if mode == "on":
                disks["openwrt_router.traffic_coarse"].data = {
                    "version": 1,
                    "minor_version": 1,
                    "key": "openwrt_router.traffic_coarse",
                    "data": {"settings": {"v": 1, "enabled": True, "routers": {}}},
                }
            engine = TrafficEngine(hass)
            hass.data[DATA_TRAFFIC_ANALYTICS] = engine
            engine.router_id_of = {"e1": RID}.get
            await async_setup_traffic(hass, FakeEntry("e1"), coord)
        model._MODE["empty_tables"] = False
        with (
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for _n in range(polls):
                coord.data = await coord._async_update_data()
                coord.async_update_listeners()
                while hass.tasks:
                    await hass.tasks.pop(0)
        calls = session.post.call_count
        if engine is not None:
            await async_release_traffic(hass, "e1")
    return calls, coord, engine


# --- 0 extra router calls ----------------------------------------------------------------


async def test_traffic_analytics_adds_no_router_calls() -> None:
    calls_absent, _, _ = await _run_polls("absent")
    calls_off, coord_off, engine_off = await _run_polls("off")
    calls_on, _, engine_on = await _run_polls("on")
    assert calls_absent > 0
    assert calls_off == calls_absent
    assert calls_on == calls_absent  # stage A-standard: no call of its own
    # off: it did nothing at all; on: it did work on the same polls
    assert engine_off.counters == {}
    assert not coord_off._listeners
    assert engine_on.counters["processed_snapshots"] == 3
    assert engine_on.planner.counters["extra_calls"] == 0


async def test_poll_carries_the_traffic_inputs() -> None:
    _calls, coord, _ = await _run_polls("absent", polls=1)
    data = coord.data
    assert set(data.device_counters) == {"wan", "lan1", "br-lan"}
    wan = data.device_counters["wan"]
    assert (wan["rx_bytes"], wan["tx_bytes"], wan["speed"]) == (1000, 500, "1000F")
    assert wan["rx_errors"] is None  # not delivered: unknown, never 0
    assert data.device_counters["br-lan"]["rx_bytes"] is None
    assert isinstance(data.counters_sampled_mono, float)
    assert data.active_connections == 12
    assert data.active_connections_source == "count_file"
    assert coord.poll_running is False


def test_device_counter_copy_is_bounded_and_strict() -> None:
    raw = {f"eth{i:02d}": {"statistics": {"rx_bytes": i}} for i in range(70)}
    raw["x" * 16] = {"statistics": {"rx_bytes": 1}}
    raw["bad"] = {"statistics": {"rx_bytes": True, "tx_bytes": -1}, "up": "yes"}
    out = traffic_device_counters(raw)
    assert len(out) == 64
    assert "x" * 16 not in out
    assert traffic_device_counters({}) is None
    assert traffic_device_counters(None) is None
    bad = traffic_device_counters({"bad": raw["bad"]})["bad"]
    assert (bad["rx_bytes"], bad["tx_bytes"], bad["up"]) == (None, None, None)


# --- as_dict and sensors unchanged ----------------------------------------------------------


def test_as_dict_does_not_carry_traffic_fields() -> None:
    plain = OpenWrtCoordinatorData()
    with_traffic = OpenWrtCoordinatorData()
    with_traffic.device_counters = {"wan": {"rx_bytes": 1}}
    with_traffic.counters_sampled_mono = 123.0
    with_traffic.active_connections_source = "count_file"
    assert with_traffic.as_dict() == plain.as_dict()
    for name in TRAFFIC_FIELDS:
        assert name not in plain.as_dict()


async def test_polled_as_dict_is_the_same_with_traffic_on() -> None:
    _, coord_absent, _ = await _run_polls("absent", polls=1)
    _, coord_on, _ = await _run_polls("on", polls=1)
    a, b = coord_absent.data.as_dict(), coord_on.data.as_dict()
    assert set(a) == set(b)
    for name in TRAFFIC_FIELDS:
        assert name not in a
    volatile = {"last_update", "poll_duration", "poll_timings", "updated_at"}
    for key in set(a) - volatile:
        if key.startswith(("last_", "poll_")):
            continue
        assert a[key] == b[key], key


async def _sensor_entities(coordinator: Any, entry: Any) -> list[Any]:
    added: list[Any] = []
    entry.runtime_data = OpenWrtRuntimeData(api=AsyncMock(), coordinator=coordinator)
    entry.async_on_unload = MagicMock()
    await sensor_setup(
        hass=MagicMock(),
        entry=entry,
        async_add_entities=lambda entities, **kw: added.extend(entities),
    )
    return added


async def test_sensor_unique_ids_and_values_unchanged(
    mock_coordinator: Any, mock_config_entry: Any
) -> None:
    data = mock_coordinator.data
    data.network_interfaces = [
        {"interface": "wan", "rx_bytes": 100, "tx_bytes": 50},
        {"interface": "lan", "rx_bytes": 200, "tx_bytes": 80},
    ]
    before = await _sensor_entities(mock_coordinator, mock_config_entry)
    data.device_counters = traffic_device_counters(
        {"wan": {"statistics": {"rx_bytes": 9, "tx_bytes": 9}}}
    )
    data.counters_sampled_mono = 1.0
    data.active_connections_source = "count_file"
    after = await _sensor_entities(mock_coordinator, mock_config_entry)

    ids_before = [e.unique_id for e in before]
    assert ids_before == [e.unique_id for e in after]
    assert "test_entry_id_uptime" in ids_before
    assert "test_entry_id_iface_wan_rx" in ids_before
    assert not any("traffic" in (uid or "") for uid in ids_before)
    for old, new in zip(before, after, strict=True):
        if old.unique_id and ("wan" in old.unique_id or "_iface_" in old.unique_id):
            assert old.native_value == new.native_value, old.unique_id


# --- api.py name validation ------------------------------------------------------------------


BAD_NAMES = ["../x", "a/b", "abcdefghijklmnop", "", "..", ".", "a b", "x\x00", 5, None]


@pytest.mark.parametrize("name", BAD_NAMES)
@pytest.mark.parametrize(
    "method", ["async_traffic_station_detail", "async_traffic_sysfs_counters"]
)
async def test_api_rejects_bad_names_before_any_call(name: Any, method: str) -> None:
    session = MagicMock()
    api = _api(session)
    with pytest.raises(ValueError):
        await getattr(api, method)([name])
    assert session.post.call_count == 0


@pytest.mark.parametrize(
    ("method", "names"),
    [
        ("async_traffic_station_detail", []),
        ("async_traffic_station_detail", [f"phy{i}-ap0" for i in range(5)]),
        ("async_traffic_station_detail", ["phy0-ap0", "phy0-ap0"]),
        ("async_traffic_sysfs_counters", []),
        ("async_traffic_sysfs_counters", [f"eth{i}" for i in range(5)]),
        ("async_traffic_sysfs_counters", ["wan", "wan"]),
    ],
)
async def test_api_rejects_bad_name_lists(method: str, names: list[str]) -> None:
    session = MagicMock()
    api = _api(session)
    with pytest.raises(ValueError):
        await getattr(api, method)(names)
    assert session.post.call_count == 0


async def test_station_detail_reads_assoclist() -> None:
    reply = {
        "results": [
            {"mac": MAC, "rx": {"bytes": 10, "packets": 1}, "tx": {"bytes": 20}},
            {"mac": "", "rx": {"bytes": 1}},
            "junk",
            {"mac": "02:00:5e:10:00:02", "rx": {"bytes": True}},
        ]
    }
    session = model._ubus_session()
    with patch.dict(model.RESPONSES, {("iwinfo", "assoclist"): reply}):
        out = await _api(session).async_traffic_station_detail(["phy0-ap0"])
    assert out == {
        "phy0-ap0": [
            {
                "mac": MAC,
                "rx_bytes": 10,
                "tx_bytes": 20,
                "rx_packets": 1,
                "tx_packets": None,
            },
            {
                "mac": "02:00:5e:10:00:02",
                "rx_bytes": None,
                "tx_bytes": None,
                "rx_packets": None,
                "tx_packets": None,
            },
        ]
    }


async def test_sysfs_counters_read_fixed_files_only() -> None:
    session = model._ubus_session()
    api = _api(session)
    out = await api.async_traffic_sysfs_counters(["wan", "lan9"])
    assert out["wan"]["rx_bytes"] == 1000
    assert out["wan"]["tx_bytes"] == 500
    assert out["lan9"] == dict.fromkeys(SYSFS_COUNTER_FILES)  # not there: unknown
    paths = [
        c.kwargs["json"]["params"][3].get("path")
        for c in session.post.call_args_list
        if c.kwargs["json"]["params"][1] == "file"
    ]
    assert len(paths) == 2 * len(SYSFS_COUNTER_FILES)
    assert all(
        p.startswith(
            ("/sys/class/net/wan/statistics/", "/sys/class/net/lan9/statistics/")
        )
        for p in paths
    )


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        (
            {"cfg01": {".type": "defaults", "flow_offloading": "1"}},
            {"flow_offloading": True, "flow_offloading_hw": False},
        ),
        (
            {"cfg01": {".type": "defaults", "flow_offloading_hw": "maybe"}},
            {"flow_offloading": False, "flow_offloading_hw": None},
        ),
        (
            {"cfg02": {".type": "zone", "name": "lan"}},
            {"flow_offloading": None, "flow_offloading_hw": None},
        ),
    ],
)
async def test_offload_state_reads_only_two_options(
    values: dict[str, Any], expected: dict[str, Any]
) -> None:
    def uci_get(params: dict[str, Any]) -> Any:
        if params.get("config") == "firewall":
            return {"values": values}
        return None

    session = model._ubus_session()
    with patch.dict(model.RESPONSES, {("uci", "get"): uci_get}):
        out = await _api(session).async_traffic_offload_state()
    assert out == expected
