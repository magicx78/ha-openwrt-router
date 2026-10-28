"""Tests for interface traffic counters and sensor metadata (package A9).

- N8: ``network.interface dump`` carries no ``statistics``; per-interface
  bytes come from the single ``network.device status {}`` call that the port
  stats already make, fetched once per poll and shared.
- NEU-B6: rate sensors are unknown (None) without a valid previous sample.
- NEU-B7: state_class / device_class fixes, time-based CPU history.
- NEU-B3: the "WAN connected" event shows the address from ``ipv4``.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass

from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError
from custom_components.openwrt_router.const import (
    CPU_HISTORY_WINDOW_SECONDS,
    SUFFIX_DISK_FREE,
    SUFFIX_TMPFS_FREE,
)
from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData

from conftest import MOCK_NETWORK_DUMP
from test_coordinator import _make_coordinator

# Real shape of `network.device status {}`: every netifd device by name,
# counters under "statistics".
DEVICE_STATUS = {
    "wan": {
        "up": True,
        "devtype": "dsa",
        "speed": "1000F",
        "statistics": {"rx_bytes": 1048576, "tx_bytes": 524288},
    },
    "br-lan": {
        "up": True,
        "devtype": "bridge",
        "statistics": {"rx_bytes": 5242880, "tx_bytes": 2097152},
    },
    "lan1": {
        "up": True,
        "devtype": "dsa",
        "speed": "1000F",
        "statistics": {"rx_bytes": 10, "tx_bytes": 20},
    },
}


def _recording_call(responses):
    seen: list[tuple[str, str, dict]] = []

    async def _call(obj, method, params, *args, **kwargs):
        seen.append((obj, method, dict(params or {})))
        value = responses.get((obj, method))
        if isinstance(value, Exception):
            raise value
        return value

    return _call, seen


# ---------------------------------------------------------------------------
# N8 — counters from network.device status
# ---------------------------------------------------------------------------


class TestFixtureShape:
    def test_interface_dump_fixture_has_no_statistics(self):
        # netifd does not report counters in network.interface dump.
        for iface in MOCK_NETWORK_DUMP["interface"]:
            assert "statistics" not in iface


class TestInterfaceCounters:
    @pytest.mark.asyncio
    async def test_counters_taken_from_device_status_by_l3_device(self, mock_api):
        mock_api._call = AsyncMock(
            side_effect=_recording_call(
                {("network.interface", "dump"): MOCK_NETWORK_DUMP}
            )[0]
        )
        ifaces = await mock_api.get_network_interfaces(device_status=DEVICE_STATUS)
        by_name = {i["logical_name"]: i for i in ifaces}
        assert by_name["wan"]["rx_bytes"] == 1048576
        assert by_name["wan"]["tx_bytes"] == 524288
        assert by_name["lan"]["rx_bytes"] == 5242880
        assert by_name["lan"]["tx_bytes"] == 2097152

    @pytest.mark.asyncio
    async def test_unknown_device_gives_none_not_zero(self, mock_api):
        dump = {
            "interface": [
                {"interface": "vpn", "up": True, "l3_device": "wg0"},
            ]
        }
        mock_api._call = AsyncMock(
            side_effect=_recording_call({("network.interface", "dump"): dump})[0]
        )
        ifaces = await mock_api.get_network_interfaces(device_status=DEVICE_STATUS)
        assert ifaces[0]["rx_bytes"] is None
        assert ifaces[0]["tx_bytes"] is None

    @pytest.mark.asyncio
    async def test_get_network_interfaces_makes_no_device_call(self, mock_api):
        call, seen = _recording_call(
            {("network.interface", "dump"): MOCK_NETWORK_DUMP}
        )
        mock_api._call = AsyncMock(side_effect=call)
        await mock_api.get_network_interfaces(device_status=DEVICE_STATUS)
        assert [s[:2] for s in seen] == [("network.interface", "dump")]

    @pytest.mark.asyncio
    async def test_device_status_is_one_unnamed_call(self, mock_api):
        call, seen = _recording_call({("network.device", "status"): DEVICE_STATUS})
        mock_api._call = AsyncMock(side_effect=call)
        assert await mock_api.get_device_status() == DEVICE_STATUS
        assert seen == [("network.device", "status", {})]

    @pytest.mark.asyncio
    async def test_device_status_blocked_returns_empty(self, mock_api):
        call, _ = _recording_call(
            {("network.device", "status"): OpenWrtMethodNotFoundError("acl")}
        )
        mock_api._call = AsyncMock(side_effect=call)
        assert await mock_api.get_device_status() == {}

    @pytest.mark.asyncio
    async def test_port_stats_reuse_given_device_status(self, mock_api):
        call, seen = _recording_call({})
        mock_api._call = AsyncMock(side_effect=call)
        ports = await mock_api.get_port_stats(device_status=DEVICE_STATUS)
        assert seen == []
        assert {p["name"] for p in ports} == {"lan1", "wan"}

    @pytest.mark.asyncio
    async def test_poll_fetches_device_status_once_and_shares_it(self):
        coord, api = _make_coordinator()
        api.get_device_status = AsyncMock(return_value=DEVICE_STATUS)
        api.get_port_stats = AsyncMock(return_value=[])
        await coord._async_update_data()
        api.get_device_status.assert_awaited_once()
        assert (
            api.get_network_interfaces.await_args.kwargs["device_status"]
            is DEVICE_STATUS
        )
        assert api.get_port_stats.await_args.kwargs["device_status"] is DEVICE_STATUS


# ---------------------------------------------------------------------------
# NEU-B6 — rates are None without a valid previous sample
# ---------------------------------------------------------------------------


def _rate_coord(interfaces):
    coord, api = _make_coordinator()
    api.get_network_interfaces = AsyncMock(return_value=interfaces)
    return coord, api


def _iface(data, name):
    return next(i for i in data.network_interfaces if i["interface"] == name)


class TestRateNone:
    @pytest.mark.asyncio
    async def test_new_interface_has_no_rate(self):
        coord, api = _rate_coord([{"interface": "wan", "rx_bytes": 0, "tx_bytes": 0}])
        await coord._async_update_data()
        coord._prev_poll_time = datetime.now(UTC) - timedelta(seconds=10)
        api.get_network_interfaces = AsyncMock(return_value=[
            {"interface": "wan", "rx_bytes": 100, "tx_bytes": 100},
            {"interface": "wg0", "rx_bytes": 10**9, "tx_bytes": 10**9},
        ])
        data = await coord._async_update_data()
        assert _iface(data, "wg0")["rx_rate"] is None
        assert _iface(data, "wg0")["tx_rate"] is None
        assert _iface(data, "wan")["rx_rate"] == pytest.approx(10.0, abs=1.0)

    @pytest.mark.asyncio
    async def test_unknown_counters_give_no_rate(self):
        coord, api = _rate_coord(
            [{"interface": "wan", "rx_bytes": None, "tx_bytes": None}]
        )
        await coord._async_update_data()
        coord._prev_poll_time = datetime.now(UTC) - timedelta(seconds=10)
        data = await coord._async_update_data()
        assert _iface(data, "wan")["rx_rate"] is None

    @pytest.mark.asyncio
    async def test_counter_reset_gives_no_rate(self):
        coord, api = _rate_coord(
            [{"interface": "lan", "rx_bytes": 5000, "tx_bytes": 5000}]
        )
        await coord._async_update_data()
        coord._prev_poll_time = datetime.now(UTC) - timedelta(seconds=10)
        api.get_network_interfaces = AsyncMock(
            return_value=[{"interface": "lan", "rx_bytes": 100, "tx_bytes": 100}]
        )
        data = await coord._async_update_data()
        assert _iface(data, "lan")["rx_rate"] is None

    @pytest.mark.asyncio
    async def test_stale_cache_gives_no_rate_and_keeps_baseline(self):
        coord, api = _rate_coord(
            [{"interface": "wan", "rx_bytes": 1000, "tx_bytes": 1000}]
        )
        await coord._async_update_data()
        baseline_time = coord._prev_poll_time
        api.get_network_interfaces = AsyncMock(side_effect=OSError("io"))
        data = await coord._async_update_data()
        assert data.vlans_stale is True
        assert _iface(data, "wan")["rx_rate"] is None
        assert coord._prev_poll_time == baseline_time

    def test_rate_sensor_reports_none(self):
        from custom_components.openwrt_router.sensor import OpenWrtInterfaceRateSensor

        coord, _ = _make_coordinator()
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "wan", "rx_bytes": 1, "tx_bytes": 1, "rx_rate": None}
        ]
        coord.data = data
        entry = MagicMock()
        entry.entry_id = "e"
        sensor = OpenWrtInterfaceRateSensor(coord, entry, "wan", "rx_rate")
        assert sensor.native_value is None


# ---------------------------------------------------------------------------
# NEU-B7 — sensor metadata and CPU history
# ---------------------------------------------------------------------------


class TestSensorMetadata:
    @pytest.mark.parametrize("key", [SUFFIX_DISK_FREE, SUFFIX_TMPFS_FREE])
    def test_free_space_sensors_are_measurements(self, key):
        from custom_components.openwrt_router.sensor import SENSOR_DESCRIPTIONS

        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == key)
        assert desc.state_class == SensorStateClass.MEASUREMENT

    @pytest.mark.parametrize("metric", ["signal", "noise"])
    def test_radio_dbm_sensor_is_signal_strength(self, metric):
        from custom_components.openwrt_router.sensor import OpenWrtRadioSensor

        coord, _ = _make_coordinator()
        entry = MagicMock()
        entry.entry_id = "e"
        entry.options = {}
        sensor = OpenWrtRadioSensor(coord, entry, "phy0-ap0", metric)
        assert sensor.native_unit_of_measurement == "dBm"
        assert sensor.device_class == SensorDeviceClass.SIGNAL_STRENGTH


class TestCpuHistoryWindow:
    @pytest.mark.asyncio
    async def test_points_older_than_window_are_dropped(self):
        coord, _ = _make_coordinator()
        now = int(datetime.now(UTC).timestamp())
        coord._cpu_history.extend(
            [
                {"ts": now - CPU_HISTORY_WINDOW_SECONDS - 60, "cpu": 1.0, "mem": 1.0},
                {"ts": now - 60, "cpu": 2.0, "mem": 2.0},
            ]
        )
        data = await coord._async_update_data()
        assert [p["cpu"] for p in data.cpu_history][:1] == [2.0]
        assert all(p["ts"] >= now - CPU_HISTORY_WINDOW_SECONDS for p in data.cpu_history)

    def test_cap_covers_window_at_fastest_regular_poll(self):
        from custom_components.openwrt_router.const import (
            CPU_HISTORY_MAX_POINTS,
            SCAN_INTERVAL_SECONDS,
        )

        assert CPU_HISTORY_MAX_POINTS >= CPU_HISTORY_WINDOW_SECONDS // SCAN_INTERVAL_SECONDS


# ---------------------------------------------------------------------------
# NEU-B3 — WAN connected event detail
# ---------------------------------------------------------------------------


class TestWanConnectedDetail:
    def test_detail_uses_ipv4(self):
        coord, _ = _make_coordinator()
        coord._prev_wan_connected = False
        data = OpenWrtCoordinatorData()
        data.wan_connected = True
        # Shape returned by OpenWrtAPI.get_wan_status
        data.wan_status = {"connected": True, "interface": "wan", "ipv4": "203.0.113.7"}
        coord._record_events(data)
        event = next(e for e in data.events if "WAN" in e["message"])
        assert event["detail"] == "203.0.113.7"
