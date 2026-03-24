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
    async def test_auth_error_raises_config_entry_auth_failed(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthError("bad"))
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()

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
