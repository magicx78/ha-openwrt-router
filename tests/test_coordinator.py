"""Tests for the OpenWrt Coordinator (coordinator.py)."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.const import (
    BOARD_REFRESH_CYCLES,
    FEATURE_HAS_5GHZ,
    FEATURE_HAS_IWINFO,
    FEATURE_DHCP_LEASES,
    RADIO_KEY_BAND,
    RADIO_KEY_IS_GUEST,
)
from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
)

from conftest import MOCK_BOARD_INFO, MOCK_SYSTEM_INFO


# ---------------------------------------------------------------------------
# Helper to create a coordinator with a mock API
# ---------------------------------------------------------------------------

def _make_coordinator(api=None):
    """Create a coordinator with a mock HA instance and optional mock API."""
    hass = MagicMock()
    hass.async_create_task = MagicMock(side_effect=lambda coro: coro)

    if api is None:
        api = AsyncMock()
        # Default API responses
        api.detect_features = AsyncMock(return_value={
            FEATURE_HAS_IWINFO: True,
            FEATURE_HAS_5GHZ: True,
            FEATURE_DHCP_LEASES: True,
        })
        api.get_router_info = AsyncMock(return_value={
            "model": "TestRouter",
            "hostname": "openwrt-test",
            "release": {"version": "24.10.0"},
            "mac": "aa:bb:cc:dd:ee:ff",
            "board_name": "test",
            "kernel": "6.6.73",
            "platform_architecture": "test_arch",
        })
        api.get_wan_status = AsyncMock(return_value={
            "connected": True, "interface": "wan", "ipv4": "1.2.3.4",
            "uptime": 1000, "rx_bytes": None, "tx_bytes": None,
        })
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(return_value={
            "uptime": 86400, "cpu_load": 50.0, "cpu_load_5min": 40.0,
            "cpu_load_15min": 30.0, "memory": {"total": 256, "free": 128},
        })
        api.get_disk_space = AsyncMock(return_value={"primary": {}})
        api.get_tmpfs_stats = AsyncMock(return_value={"total_mb": 64})
        api.get_network_interfaces = AsyncMock(return_value=[])
        api.get_active_connections = AsyncMock(return_value=10)

    # Patch the HA frame helper that DataUpdateCoordinator requires in HA 2026+
    with patch("homeassistant.helpers.frame.report_usage"):
        coordinator = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    return coordinator, api


# =====================================================================
# Feature Detection
# =====================================================================

class TestFeatureDetection:
    @pytest.mark.asyncio
    async def test_first_refresh_runs_feature_detection(self):
        coord, api = _make_coordinator()
        await coord._async_update_data()
        api.detect_features.assert_awaited_once()
        assert coord._features_detected is True

    @pytest.mark.asyncio
    async def test_features_detected_only_once(self):
        coord, api = _make_coordinator()
        await coord._async_update_data()
        await coord._async_update_data()
        api.detect_features.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_feature_detection_failure_non_fatal(self):
        coord, api = _make_coordinator()
        api.detect_features = AsyncMock(side_effect=Exception("boom"))
        data = await coord._async_update_data()
        assert data.features == {}
        assert coord._features_detected is True  # Still marked done


# =====================================================================
# Board Info Refresh Cycles
# =====================================================================

class TestBoardInfoRefresh:
    @pytest.mark.asyncio
    async def test_first_cycle_fetches_board_info(self):
        coord, api = _make_coordinator()
        await coord._async_update_data()
        api.get_router_info.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_cached_between_refreshes(self):
        coord, api = _make_coordinator()
        data1 = await coord._async_update_data()
        # Set coord.data so subsequent calls can access it
        coord.data = data1
        data2 = await coord._async_update_data()
        # get_router_info called once on first cycle only
        assert api.get_router_info.await_count == 1
        # But router_info is still present (carried forward)
        assert data2.router_info["model"] == "TestRouter"

    @pytest.mark.asyncio
    async def test_refreshed_every_n_cycles(self):
        coord, api = _make_coordinator()
        # Run first cycle
        data = await coord._async_update_data()
        coord.data = data
        # Run cycles 2 through BOARD_REFRESH_CYCLES
        for _ in range(BOARD_REFRESH_CYCLES - 1):
            data = await coord._async_update_data()
            coord.data = data
        # At cycle 20, get_router_info should be called again
        assert api.get_router_info.await_count == 2


# =====================================================================
# Error Handling
# =====================================================================

class TestErrorHandling:
    @pytest.mark.asyncio
    async def test_auth_error_raises_update_failed_on_first_attempt(self):
        """Single auth error → UpdateFailed (transient), not ConfigEntryAuthFailed."""
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthError("bad"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()
        assert coord._consecutive_auth_failures == 1

    @pytest.mark.asyncio
    async def test_auth_error_raises_config_entry_auth_failed_after_three_attempts(self):
        """Three consecutive auth errors → ConfigEntryAuthFailed (real credential issue)."""
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthError("bad"))
        for _ in range(2):
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()
        assert coord._consecutive_auth_failures == 0

    @pytest.mark.asyncio
    async def test_auth_failure_counter_resets_on_success(self):
        """Successful poll after auth error resets the consecutive failure counter."""
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthError("bad"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()
        assert coord._consecutive_auth_failures == 1
        # Next poll succeeds
        api.get_wan_status = AsyncMock(return_value={"wan_connected": True})
        coord.data = None
        await coord._async_update_data()
        assert coord._consecutive_auth_failures == 0

    @pytest.mark.asyncio
    async def test_connection_error_raises_update_failed(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtConnectionError("down"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()

    @pytest.mark.asyncio
    async def test_timeout_error_raises_update_failed(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()

    @pytest.mark.asyncio
    async def test_response_error_raises_update_failed(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtResponseError("bad"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()

    @pytest.mark.asyncio
    async def test_unexpected_error_raises_update_failed(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=RuntimeError("oops"))
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()


# =====================================================================
# Non-Fatal Extended Monitoring Errors
# =====================================================================

class TestNonFatalErrors:
    @pytest.mark.asyncio
    async def test_disk_space_failure(self):
        coord, api = _make_coordinator()
        api.get_disk_space = AsyncMock(side_effect=Exception("no disk"))
        data = await coord._async_update_data()
        assert data.disk_space == {}

    @pytest.mark.asyncio
    async def test_tmpfs_failure(self):
        coord, api = _make_coordinator()
        api.get_tmpfs_stats = AsyncMock(side_effect=Exception("no tmpfs"))
        data = await coord._async_update_data()
        assert data.tmpfs == {}

    @pytest.mark.asyncio
    async def test_active_connections_failure(self):
        coord, api = _make_coordinator()
        api.get_active_connections = AsyncMock(side_effect=Exception("no conn"))
        data = await coord._async_update_data()
        assert data.active_connections == 0

    @pytest.mark.asyncio
    async def test_network_interfaces_failure(self):
        coord, api = _make_coordinator()
        api.get_network_interfaces = AsyncMock(side_effect=Exception("fail"))
        data = await coord._async_update_data()
        assert data.network_interfaces == []


# =====================================================================
# Data Population
# =====================================================================

class TestDataPopulation:
    @pytest.mark.asyncio
    async def test_all_fields_populated(self):
        coord, api = _make_coordinator()
        data = await coord._async_update_data()
        assert data.uptime == 86400
        assert data.cpu_load == 50.0
        assert data.cpu_load_5min == 40.0
        assert data.cpu_load_15min == 30.0
        assert data.memory == {"total": 256, "free": 128}
        assert data.wan_connected is True
        assert data.active_connections == 10

    @pytest.mark.asyncio
    async def test_features_carried_forward(self):
        coord, api = _make_coordinator()
        data1 = await coord._async_update_data()
        assert data1.features[FEATURE_HAS_IWINFO] is True
        coord.data = data1
        data2 = await coord._async_update_data()
        assert data2.features[FEATURE_HAS_IWINFO] is True


# =====================================================================
# Convenience Accessors
# =====================================================================

class TestConvenienceAccessors:
    def test_router_info_with_data(self, mock_coordinator):
        assert mock_coordinator.router_info["model"] == "GL.iNet GL-MT3000"

    def test_features_with_data(self, mock_coordinator):
        assert mock_coordinator.features[FEATURE_HAS_IWINFO] is True

    def test_get_client_by_mac(self, mock_coordinator):
        client = mock_coordinator.get_client_by_mac("B8:27:EB:AA:BB:01")
        assert client is not None
        assert client["hostname"] == "raspberrypi"

    def test_get_client_by_mac_not_found(self, mock_coordinator):
        client = mock_coordinator.get_client_by_mac("00:00:00:00:00:00")
        assert client is None

    def test_is_client_connected_true(self, mock_coordinator):
        assert mock_coordinator.is_client_connected("B8:27:EB:AA:BB:01") is True

    def test_is_client_connected_false(self, mock_coordinator):
        assert mock_coordinator.is_client_connected("00:00:00:00:00:00") is False


# =====================================================================
# Coordinator Properties (real coordinator, not mock)
# =====================================================================

class TestCoordinatorProperties:
    @pytest.mark.asyncio
    async def test_router_info_no_data(self):
        coord, _ = _make_coordinator()
        # Before first refresh, data is None
        assert coord.router_info == {}

    @pytest.mark.asyncio
    async def test_features_no_data(self):
        coord, _ = _make_coordinator()
        assert coord.features == {}

    @pytest.mark.asyncio
    async def test_has_iwinfo(self):
        coord, _ = _make_coordinator()
        data = await coord._async_update_data()
        coord.data = data
        assert coord.has_iwinfo is True

    @pytest.mark.asyncio
    async def test_has_5ghz(self):
        coord, _ = _make_coordinator()
        data = await coord._async_update_data()
        coord.data = data
        assert coord.has_5ghz is True

    @pytest.mark.asyncio
    async def test_has_dhcp_leases(self):
        coord, _ = _make_coordinator()
        data = await coord._async_update_data()
        coord.data = data
        assert coord.has_dhcp_leases is True

    @pytest.mark.asyncio
    async def test_get_radio_by_band_none(self):
        coord, _ = _make_coordinator()
        assert coord.get_radio_by_band("5g") is None

    @pytest.mark.asyncio
    async def test_get_guest_radio_none(self):
        coord, _ = _make_coordinator()
        assert coord.get_guest_radio() is None

    @pytest.mark.asyncio
    async def test_get_client_by_mac_none(self):
        coord, _ = _make_coordinator()
        assert coord.get_client_by_mac("AA:BB:CC:DD:EE:FF") is None

    @pytest.mark.asyncio
    async def test_is_client_connected_no_data(self):
        coord, _ = _make_coordinator()
        assert coord.is_client_connected("AA:BB:CC:DD:EE:FF") is False


class TestCoordinatorDataAsDict:
    def test_as_dict_keys(self, mock_coordinator_data):
        d = mock_coordinator_data.as_dict()
        assert "router_info" in d
        assert "uptime" in d
        assert "cpu_load" in d
        assert "memory" in d
        assert "wifi_radios" in d
        assert "clients" in d
        assert "features" in d
        assert "disk_space" in d
        assert "tmpfs" in d
        assert "active_connections" in d
        assert "ap_interfaces" in d
        # STA interfaces are exposed for downstream WLAN-Repeater detection
        assert "sta_interfaces" in d
        assert d["sta_interfaces"] == []


# =====================================================================
# T-C1 through T-C5: Client tracking and _client_first_seen
# =====================================================================

from custom_components.openwrt_router.const import CLIENT_KEY_CONNECTED_SINCE


class TestClientTracking:
    """Tests for per-client online-time tracking via _client_first_seen."""

    @pytest.mark.asyncio
    async def test_t_c1_client_first_seen_populated_on_first_poll(self):
        """T-C1: _client_first_seen is populated when a client appears."""
        coord, api = _make_coordinator()
        mac = "AA:BB:CC:DD:EE:FF"
        api.get_connected_clients = AsyncMock(return_value=[
            {"mac": mac, "ip": "192.168.1.10", "hostname": "device"}
        ])
        await coord._async_update_data()
        assert mac in coord._client_first_seen

    @pytest.mark.asyncio
    async def test_t_c2_client_first_seen_stable_on_second_poll(self):
        """T-C2: _client_first_seen timestamp does not change on second poll."""
        coord, api = _make_coordinator()
        mac = "AA:BB:CC:DD:EE:FF"
        api.get_connected_clients = AsyncMock(return_value=[
            {"mac": mac, "ip": "192.168.1.10", "hostname": "device"}
        ])
        await coord._async_update_data()
        first_seen = coord._client_first_seen[mac]
        await coord._async_update_data()
        assert coord._client_first_seen[mac] == first_seen

    @pytest.mark.asyncio
    async def test_t_c3_client_first_seen_cleaned_up_after_disconnect(self):
        """T-C3: _client_first_seen entry removed when client is gone."""
        coord, api = _make_coordinator()
        mac = "AA:BB:CC:DD:EE:FF"
        api.get_connected_clients = AsyncMock(return_value=[
            {"mac": mac, "ip": "192.168.1.10", "hostname": "device"}
        ])
        await coord._async_update_data()
        assert mac in coord._client_first_seen

        api.get_connected_clients = AsyncMock(return_value=[])
        await coord._async_update_data()
        assert mac not in coord._client_first_seen

    @pytest.mark.asyncio
    async def test_t_c4_connected_since_in_client_after_poll(self):
        """T-C4: connected_since is present in client dict after polling."""
        coord, api = _make_coordinator()
        mac = "AA:BB:CC:DD:EE:FF"
        api.get_connected_clients = AsyncMock(return_value=[
            {"mac": mac, "ip": "192.168.1.10", "hostname": "device"}
        ])
        data = await coord._async_update_data()
        client = next(c for c in data.clients if c.get("mac") == mac)
        assert CLIENT_KEY_CONNECTED_SINCE in client
        # Must be a non-empty string
        assert isinstance(client[CLIENT_KEY_CONNECTED_SINCE], str)
        assert len(client[CLIENT_KEY_CONNECTED_SINCE]) > 0

    @pytest.mark.asyncio
    async def test_t_c5_client_with_missing_mac_is_skipped(self):
        """T-C5: Client entry without a MAC is skipped in _client_first_seen."""
        coord, api = _make_coordinator()
        api.get_connected_clients = AsyncMock(return_value=[
            {"mac": "", "ip": "192.168.1.10", "hostname": "ghost"},
            {"ip": "192.168.1.11", "hostname": "no_mac"},  # MAC key missing
        ])
        await coord._async_update_data()
        # _client_first_seen must remain empty — no valid MACs
        assert len(coord._client_first_seen) == 0


# =====================================================================
# T-R1 through T-R4: Bandwidth rate calculation
# =====================================================================

from datetime import datetime, UTC, timedelta as _timedelta


class TestBandwidthRateCalculation:
    """Tests for per-interface bytes/s rate calculation in the coordinator."""

    def _make_coordinator_with_interfaces(self, interfaces):
        """Return a coordinator whose get_network_interfaces returns *interfaces*."""
        coord, api = _make_coordinator()
        api.get_network_interfaces = AsyncMock(return_value=interfaces)
        return coord, api

    @pytest.mark.asyncio
    async def test_rate_none_on_first_poll(self):
        """T-R1: rx_rate / tx_rate are absent on the very first poll (no prev data)."""
        coord, _ = self._make_coordinator_with_interfaces([
            {"interface": "wan", "rx_bytes": 1000, "tx_bytes": 500, "status": "up"},
        ])
        data = await coord._async_update_data()
        iface = next(i for i in data.network_interfaces if i["interface"] == "wan")
        # On first poll _prev_poll_time was None → rates not injected
        assert iface.get("rx_rate") is None
        assert iface.get("tx_rate") is None

    @pytest.mark.asyncio
    async def test_rate_calculated_on_second_poll(self):
        """T-R2: Correct bytes/s after second poll (1000 bytes / 10 s = 100 B/s)."""
        coord, api = self._make_coordinator_with_interfaces([
            {"interface": "wan", "rx_bytes": 0, "tx_bytes": 0, "status": "up"},
        ])
        # First poll — establishes baseline
        await coord._async_update_data()

        # Manually set prev state to simulate 10s elapsed with 0 bytes
        coord._prev_poll_time = datetime.now(UTC) - _timedelta(seconds=10)
        coord._prev_interface_bytes = {"wan": {"rx_bytes": 0, "tx_bytes": 0}}

        api.get_network_interfaces = AsyncMock(return_value=[
            {"interface": "wan", "rx_bytes": 1000, "tx_bytes": 500, "status": "up"},
        ])
        data = await coord._async_update_data()

        iface = next(i for i in data.network_interfaces if i["interface"] == "wan")
        assert iface["rx_rate"] == pytest.approx(100.0, abs=2.0)
        assert iface["tx_rate"] == pytest.approx(50.0, abs=2.0)

    @pytest.mark.asyncio
    async def test_rate_zero_on_counter_wraparound(self):
        """T-R3: Rate is 0 when counter decreases (wraparound protection)."""
        coord, api = self._make_coordinator_with_interfaces([
            {"interface": "lan", "rx_bytes": 5000, "tx_bytes": 5000, "status": "up"},
        ])
        await coord._async_update_data()

        # Set prev state to simulate 10s elapsed with high bytes (so new value is lower)
        coord._prev_poll_time = datetime.now(UTC) - _timedelta(seconds=10)
        coord._prev_interface_bytes = {"lan": {"rx_bytes": 5000, "tx_bytes": 5000}}

        # Counter reset: new values lower than previous
        api.get_network_interfaces = AsyncMock(return_value=[
            {"interface": "lan", "rx_bytes": 100, "tx_bytes": 100, "status": "up"},
        ])
        data = await coord._async_update_data()

        iface = next(i for i in data.network_interfaces if i["interface"] == "lan")
        assert iface["rx_rate"] == 0
        assert iface["tx_rate"] == 0

    @pytest.mark.asyncio
    async def test_rate_sensor_native_value_none_before_second_poll(self):
        """T-R4: OpenWrtInterfaceRateSensor returns None when rx_rate not yet in data."""
        from unittest.mock import MagicMock
        from custom_components.openwrt_router.sensor import OpenWrtInterfaceRateSensor
        from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData

        coord, _ = _make_coordinator()
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "wan", "rx_bytes": 1000, "tx_bytes": 500, "status": "up"}
            # no rx_rate key — first poll
        ]
        coord.data = data

        entry = MagicMock()
        entry.entry_id = "test_entry"
        entry.data = {"host": "192.168.1.1", "port": 80}

        sensor = OpenWrtInterfaceRateSensor(coord, entry, "wan", "rx_rate")
        assert sensor.native_value is None


# =====================================================================
# Event timeline — _record_events
# =====================================================================

class TestRecordEvents:
    """Unit tests for _record_events() — RAM formula, WAN tracking, CPU spikes."""

    def _make_data(self, *, wan_connected=False, cpu=0.0, total=0, free=0, buffered=0):
        from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
        d = OpenWrtCoordinatorData()
        d.wan_connected = wan_connected
        d.wan_status = {"ipv4_address": "1.2.3.4"} if wan_connected else {}
        d.cpu_load = cpu
        d.memory = {"total": total, "free": free, "buffered": buffered}
        return d

    def _make_coord(self):
        coord, _ = _make_coordinator()
        return coord

    def test_no_events_on_first_call(self):
        """No events on very first call (prev state unknown → no transition)."""
        coord = self._make_coord()
        d = self._make_data(wan_connected=True, total=1000, free=500)
        coord._record_events(d)
        assert d.events == []

    def test_wan_connect_event(self):
        coord = self._make_coord()
        # Establish baseline: WAN was disconnected
        coord._prev_wan_connected = False
        d = self._make_data(wan_connected=True, total=1000, free=500)
        coord._record_events(d)
        assert len(d.events) == 1
        assert d.events[0]["type"] == "info"
        assert "WAN" in d.events[0]["message"]

    def test_wan_disconnect_event(self):
        coord = self._make_coord()
        coord._prev_wan_connected = True
        d = self._make_data(wan_connected=False, total=1000, free=500)
        coord._record_events(d)
        assert len(d.events) == 1
        assert d.events[0]["type"] == "error"

    def test_mem_spike_excludes_buffered(self):
        """RAM warning must NOT fire when apparent usage is high but buffered
        memory accounts for the difference (effective pressure < 90%)."""
        coord = self._make_coord()
        coord._prev_wan_connected = False
        # total=1000, free=50, buffered=200 → effective=(1000-50-200)/1000=75% < 90%
        d = self._make_data(wan_connected=False, total=1000, free=50, buffered=200)
        coord._record_events(d)
        # No mem warning should fire (75% is below 90% threshold)
        mem_events = [e for e in d.events if "RAM" in e.get("message", "")]
        assert mem_events == []

    def test_mem_spike_fires_when_effective_pressure_high(self):
        """RAM warning fires when effective pressure (excluding buffered) >= 90%."""
        coord = self._make_coord()
        coord._prev_wan_connected = False
        # total=1000, free=50, buffered=20 → effective=(1000-50-20)/1000=93% >= 90%
        d = self._make_data(wan_connected=False, total=1000, free=50, buffered=20)
        coord._record_events(d)
        mem_events = [e for e in d.events if "RAM" in e.get("message", "")]
        assert len(mem_events) == 1
        assert mem_events[0]["type"] == "warn"

    def test_mem_spike_no_buffered_field(self):
        """RAM threshold works correctly when buffered key is absent (falls back to 0)."""
        coord = self._make_coord()
        coord._prev_wan_connected = False
        d = self._make_data(wan_connected=False, total=1000, free=50)
        # buffered defaults to 0 → (1000-50)/1000=95% >= 90%
        d.memory = {"total": 1000, "free": 50}  # no 'buffered' key
        coord._record_events(d)
        mem_events = [e for e in d.events if "RAM" in e.get("message", "")]
        assert len(mem_events) == 1

    def test_cpu_spike_event(self):
        coord = self._make_coord()
        coord._prev_wan_connected = False
        d = self._make_data(wan_connected=False, cpu=85.0, total=1000, free=500)
        coord._record_events(d)
        cpu_events = [e for e in d.events if "CPU" in e.get("message", "")]
        assert len(cpu_events) == 1
        assert cpu_events[0]["type"] == "warn"
        assert coord._cpu_warn_active is True

    def test_cpu_recovery_event(self):
        coord = self._make_coord()
        coord._prev_wan_connected = False
        coord._cpu_warn_active = True
        d = self._make_data(wan_connected=False, cpu=55.0, total=1000, free=500)
        coord._record_events(d)
        cpu_events = [e for e in d.events if "CPU" in e.get("message", "")]
        assert len(cpu_events) == 1
        assert cpu_events[0]["type"] == "info"
        assert coord._cpu_warn_active is False
