"""Tests for DFS / channel change detection (F3)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.const import EVENT_DFS, EVENT_WIFI
from custom_components.openwrt_router.log_parser import (
    CATEGORY_DFS,
    DFS_CAC_COMPLETED,
    DFS_CAC_FAILED,
    DFS_CAC_START,
    DFS_NEW_CHANNEL,
    DFS_NOP_FINISHED,
    DFS_RADAR_DETECTED,
    EventLimiter,
    parse_entry,
)

T = 1_793_094_113_364  # epoch ms


def _e(msg, log_id=1, time_ms=T):
    return {"msg": msg, "id": log_id, "priority": 30, "source": 1, "time": time_ms}


# =====================================================================
# Parser
# =====================================================================


class TestDfsParser:
    @pytest.mark.parametrize(
        ("rest", "kind", "freq", "chan"),
        [
            (
                "DFS-RADAR-DETECTED freq=5260 ht_enabled=1 chan_offset=0 chan_width=3 cf1=5290 cf2=0",
                DFS_RADAR_DETECTED,
                5260,
                52,
            ),
            (
                "DFS-CAC-START freq=5500 chan=100 sec_chan=1, width=1, seg0=106, seg1=0, cac_time=60s",
                DFS_CAC_START,
                5500,
                100,
            ),
            ("DFS-CAC-COMPLETED success=1 freq=5500 ht_enabled=1 chan_offset=0", DFS_CAC_COMPLETED, 5500, 100),
            ("DFS-CAC-COMPLETED success=0 freq=5500 ht_enabled=1 chan_offset=0", DFS_CAC_FAILED, 5500, 100),
            ("DFS-NOP-FINISHED freq=5260 ht_enabled=1 chan_offset=0 chan_width=3", DFS_NOP_FINISHED, 5260, 52),
            ("DFS-NEW-CHANNEL freq=5180 chan=36 sec_chan=1", DFS_NEW_CHANNEL, 5180, 36),
        ],
    )
    def test_dfs_lines(self, rest, kind, freq, chan):
        event = parse_entry(_e(f"hostapd: phy1-ap0: {rest}"))
        assert event.category == CATEGORY_DFS
        assert event.kind == kind
        assert (event.frequency, event.channel) == (freq, chan)
        assert event.interface == "phy1-ap0"
        assert event.mac is None

    @pytest.mark.parametrize(
        "rest",
        ["DFS-UNKNOWN-THING freq=5260", "DFS-", "DFS-RADAR-DETECTEDX", "AP-CSA-FINISHED freq=5180 dfs=0"],
    )
    def test_unknown_dfs_lines(self, rest):
        assert parse_entry(_e(f"hostapd: phy1-ap0: {rest}")) is None

    def test_without_frequency(self):
        event = parse_entry(_e("hostapd: phy1-ap0: DFS-RADAR-DETECTED"))
        assert (event.kind, event.frequency, event.channel) == (DFS_RADAR_DETECTED, None, None)

    def test_limiter_keys_dfs_by_interface(self):
        limiter = EventLimiter(10, 300_000)
        a = parse_entry(_e("hostapd: phy1-ap0: DFS-RADAR-DETECTED freq=5260", 1))
        b = parse_entry(_e("hostapd: phy2-ap0: DFS-RADAR-DETECTED freq=5500", 2))
        c = parse_entry(_e("hostapd: phy1-ap0: DFS-RADAR-DETECTED freq=5280", 3))
        fire, suppressed = limiter.select([a, b, c], T)
        assert [e.interface for e in fire] == ["phy1-ap0", "phy2-ap0"]
        assert suppressed == 1


# =====================================================================
# Coordinator
# =====================================================================


def _iface(ifname, channel, htmode="HE80", freq=None):
    return {
        "ifname": ifname,
        "channel": channel,
        "htmode": htmode,
        "frequency": freq or 5000 + 5 * channel,
        "phy": ifname.split("-")[0],
        "mode": "Master",
    }


def _coordinator():
    from custom_components.openwrt_router.coordinator import OpenWrtCoordinator

    hass = MagicMock()
    api = AsyncMock()
    with patch("homeassistant.helpers.frame.report_usage"):
        coord = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    coord._entry = MagicMock(entry_id="e1", title="Router A")
    api.reset_ssh_fallback_flag = MagicMock()
    api.uses_ssh_fallback = False
    api.detect_features = AsyncMock(return_value={})
    api.get_router_info = AsyncMock(return_value={})
    api.get_wan_status = AsyncMock(return_value={"connected": True})
    api.get_wifi_status = AsyncMock(return_value=[])
    api.get_dhcp_leases = AsyncMock(return_value={})
    api.get_connected_clients = AsyncMock(return_value=[])
    api.get_router_status = AsyncMock(return_value={"memory": {}})
    api.get_services = AsyncMock(return_value=[])
    api.get_sta_interface_details = AsyncMock(return_value=[])
    api.get_log_entries = AsyncMock(return_value=[])
    return coord, api


def _dfs_events(coord):
    return [
        c.args[1] for c in coord.hass.bus.async_fire.call_args_list if c.args[0] == EVENT_DFS
    ]


async def _poll(coord, api, ifaces, log=None):
    api.get_ap_interface_details = AsyncMock(return_value=ifaces)
    if log is not None:
        api.get_log_entries = AsyncMock(return_value=log)
    coord.data = await coord._async_update_data()
    return coord.data


class TestChannelChange:
    @pytest.mark.asyncio
    async def test_change_without_evidence_is_not_dfs_related(self):
        coord, api = _coordinator()
        await _poll(coord, api, [_iface("phy1-ap0", 36), _iface("phy0-ap0", 6, "HE20", 2437)])
        await _poll(coord, api, [_iface("phy1-ap0", 36), _iface("phy0-ap0", 6, "HE20", 2437)])
        assert _dfs_events(coord) == []
        data = await _poll(coord, api, [_iface("phy1-ap0", 100), _iface("phy0-ap0", 6, "HE20", 2437)])
        (event,) = _dfs_events(coord)
        assert event["type"] == "channel_change"
        assert (event["radio"], event["band"]) == ("phy1", "5g")
        assert (event["old_channel"], event["new_channel"]) == (36, 100)
        assert (event["old_width_mhz"], event["new_width_mhz"]) == (80, 80)
        assert event["dfs_related"] is False
        assert event["evidence"] == []
        assert event["entry_id"] == "e1"
        assert data.dfs["events_24h"] == 1
        assert data.dfs["by_type"] == {"channel_change": 1}
        assert data.dfs["last_event"]["new_channel"] == 100

    @pytest.mark.asyncio
    async def test_change_with_radar_line_is_dfs_related(self):
        coord, api = _coordinator()
        now_ms = T
        with patch("custom_components.openwrt_router.coordinator.time.time", return_value=now_ms / 1000):
            await _poll(coord, api, [_iface("phy1-ap0", 52)], log=[_e("x: baseline", 10, now_ms - 60_000)])
            await _poll(coord, api, [_iface("phy1-ap0", 52)])
            radar = [
                _e("x: baseline", 10, now_ms - 60_000),
                _e("hostapd: phy1-ap0: DFS-RADAR-DETECTED freq=5260 chan_width=3", 11, now_ms - 5_000),
                _e("hostapd: phy1-ap0: DFS-NEW-CHANNEL freq=5180 chan=36 sec_chan=1", 12, now_ms - 4_000),
            ]
            # poll 3 is off-cycle for the log: the channel change pulls it in
            data = await _poll(coord, api, [_iface("phy1-ap0", 36)], log=radar)
        types = [e["type"] for e in _dfs_events(coord)]
        assert sorted(types) == ["channel_change", "new_channel", "radar_detected"]
        change = next(e for e in _dfs_events(coord) if e["type"] == "channel_change")
        assert change["dfs_related"] is True
        assert change["evidence"] == ["new_channel", "radar_detected"]
        radar_event = next(e for e in _dfs_events(coord) if e["type"] == "radar_detected")
        assert radar_event["radio"] == "phy1"
        assert radar_event["channel"] == 52
        assert radar_event["dfs_related"] is True
        assert data.dfs["events_24h"] == 3

    @pytest.mark.asyncio
    async def test_old_evidence_does_not_count(self):
        coord, api = _coordinator()
        now_ms = T
        old_radar = _e("hostapd: phy1-ap0: DFS-RADAR-DETECTED freq=5260", 11, now_ms - 3_600_000)
        with patch("custom_components.openwrt_router.coordinator.time.time", return_value=now_ms / 1000):
            await _poll(coord, api, [_iface("phy1-ap0", 52)])
            await _poll(coord, api, [_iface("phy1-ap0", 52)], log=[old_radar])  # baseline
            await _poll(coord, api, [_iface("phy1-ap0", 36)], log=[old_radar])
        (change,) = [e for e in _dfs_events(coord) if e["type"] == "channel_change"]
        assert change["dfs_related"] is False

    @pytest.mark.asyncio
    async def test_evidence_of_other_radio_does_not_count(self):
        coord, api = _coordinator()
        with patch("custom_components.openwrt_router.coordinator.time.time", return_value=T / 1000):
            await _poll(coord, api, [_iface("phy1-ap0", 52), _iface("phy2-ap0", 100)])
            await _poll(coord, api, [_iface("phy1-ap0", 52), _iface("phy2-ap0", 100)], log=[_e("x: y", 1)])
            log = [_e("x: y", 1), _e("hostapd: phy2-ap0: DFS-RADAR-DETECTED freq=5500", 2, T - 1000)]
            await _poll(coord, api, [_iface("phy1-ap0", 36), _iface("phy2-ap0", 100)], log=log)
        change = next(e for e in _dfs_events(coord) if e["type"] == "channel_change")
        assert change["radio"] == "phy1"
        assert change["dfs_related"] is False

    @pytest.mark.asyncio
    async def test_width_change_counts(self):
        coord, api = _coordinator()
        await _poll(coord, api, [_iface("phy1-ap0", 36, "HE160")])
        await _poll(coord, api, [_iface("phy1-ap0", 36, "HE80")])
        (event,) = _dfs_events(coord)
        assert (event["old_width_mhz"], event["new_width_mhz"]) == (160, 80)
        assert event["old_channel"] == event["new_channel"] == 36

    @pytest.mark.asyncio
    async def test_missing_radio_or_empty_poll_is_no_change(self):
        coord, api = _coordinator()
        await _poll(coord, api, [_iface("phy1-ap0", 36), _iface("phy2-ap0", 100)])
        await _poll(coord, api, [])  # iwinfo failed
        await _poll(coord, api, [_iface("phy1-ap0", 36)])  # phy2 switched off
        await _poll(coord, api, [_iface("phy1-ap0", 36), _iface("phy2-ap0", 100)])
        assert _dfs_events(coord) == []

    @pytest.mark.asyncio
    async def test_first_poll_records_only(self):
        coord, api = _coordinator()
        await _poll(coord, api, [_iface("phy1-ap0", 36)])
        assert _dfs_events(coord) == []
        assert coord.data.dfs == {"events_24h": 0, "by_type": {}, "last_event": None}

    @pytest.mark.asyncio
    async def test_dfs_log_line_without_change_fires_event_not_wifi(self):
        coord, api = _coordinator()
        with patch("custom_components.openwrt_router.coordinator.time.time", return_value=T / 1000):
            await _poll(coord, api, [_iface("phy1-ap0", 52)])
            await _poll(coord, api, [_iface("phy1-ap0", 52)], log=[_e("x: y", 1)])
            await _poll(coord, api, [_iface("phy1-ap0", 52)])
            log = [_e("x: y", 1), _e("hostapd: phy1-ap0: DFS-CAC-START freq=5260 chan=52", 2, T)]
            await _poll(coord, api, [_iface("phy1-ap0", 52)], log=log)
        (event,) = _dfs_events(coord)
        assert event["type"] == "cac_start"
        wifi = [c for c in coord.hass.bus.async_fire.call_args_list if c.args[0] == EVENT_WIFI]
        assert wifi == []


# =====================================================================
# Sensor + logbook
# =====================================================================


class TestDfsSensor:
    def test_description(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.sensor import (
            SENSOR_DESCRIPTIONS,
            OpenWrtSensorEntity,
        )

        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "dfs_events_24h")
        mock_coordinator.data.dfs = {
            "events_24h": 2,
            "by_type": {"radar_detected": 1, "channel_change": 1},
            "last_event": {"type": "channel_change"},
        }
        sensor = OpenWrtSensorEntity(
            coordinator=mock_coordinator, entry=mock_config_entry, description=desc
        )
        assert sensor.native_value == 2
        assert sensor.extra_state_attributes["by_type"]["radar_detected"] == 1
        assert sensor.unique_id == "test_entry_id_dfs_events_24h"
        for legacy in ("_rate", "_ap_", "_port_", "_radio_", "_iface_"):
            assert legacy not in sensor.unique_id

    def test_empty_data(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.sensor import (
            SENSOR_DESCRIPTIONS,
            OpenWrtSensorEntity,
        )

        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "dfs_events_24h")
        mock_coordinator.data.dfs = {}
        sensor = OpenWrtSensorEntity(
            coordinator=mock_coordinator, entry=mock_config_entry, description=desc
        )
        assert sensor.native_value == 0
        assert sensor.extra_state_attributes == {"by_type": {}, "last_event": None}


class TestDfsLogbook:
    def test_descriptions(self):
        from custom_components.openwrt_router.logbook import async_describe_events

        registered = {}
        async_describe_events(MagicMock(), lambda d, e, fn: registered.setdefault(e, fn))
        describe = registered[EVENT_DFS]
        change = describe(
            MagicMock(
                data={
                    "router": "Router A",
                    "type": "channel_change",
                    "radio": "phy1",
                    "old_channel": 52,
                    "new_channel": 36,
                    "dfs_related": True,
                }
            )
        )
        assert change == {
            "name": "Router A",
            "message": "channel change on phy1: 52 → 36 (DFS)",
        }
        radar = describe(MagicMock(data={"type": "radar_detected", "radio": "phy1", "channel": 52}))
        assert radar["message"] == "DFS radar detected on phy1 (channel 52)"
