"""Tests for the OpenWrt Router integration __init__.py."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router import (
    OpenWrtRuntimeData,
    async_setup_entry,
    async_unload_entry,
    async_reload_entry,
    PLATFORMS,
)
from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
    PROTOCOL_HTTP,
)

from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry():
    """Create a mock config entry."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.title = "OpenWrt-Test"
    entry.data = {
        CONF_HOST: "192.168.1.1",
        CONF_PORT: 80,
        CONF_USERNAME: "root",
        CONF_PASSWORD: "secret",
        CONF_PROTOCOL: PROTOCOL_HTTP,
    }
    return entry


def _make_hass():
    """Create a mock HomeAssistant instance."""
    hass = MagicMock()
    hass.config_entries = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    return hass


# =====================================================================
# async_setup_entry
# =====================================================================

class TestSetupEntry:
    @pytest.mark.asyncio
    async def test_successful_setup(self):
        """Full successful setup: login, coordinator refresh, platform forward."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {"model": "TestRouter"}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        mock_api.login.assert_awaited_once()
        mock_coordinator.async_config_entry_first_refresh.assert_awaited_once()
        hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(
            entry, PLATFORMS
        )
        # runtime_data should be set
        assert isinstance(entry.runtime_data, OpenWrtRuntimeData)

    @pytest.mark.asyncio
    async def test_auth_error_raises_config_entry_auth_failed(self):
        """Login auth error should raise ConfigEntryAuthFailed."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtAuthError("bad creds"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryAuthFailed):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_connection_error_raises_not_ready(self):
        """Connection error during login should raise ConfigEntryNotReady."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtConnectionError("down"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryNotReady):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_timeout_error_raises_not_ready(self):
        """Timeout error during login should raise ConfigEntryNotReady."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryNotReady):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_default_protocol_when_missing(self):
        """Should use default protocol when CONF_PROTOCOL is not in data."""
        hass = _make_hass()
        entry = _make_entry()
        del entry.data[CONF_PROTOCOL]

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ) as api_cls, patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ):
            await async_setup_entry(hass, entry)
            # API should have been created with the default protocol
            api_cls.assert_called_once()


# =====================================================================
# async_unload_entry
# =====================================================================

class TestUnloadEntry:
    @pytest.mark.asyncio
    async def test_unload_success(self):
        """Should forward unload to all platforms."""
        hass = _make_hass()
        entry = _make_entry()

        result = await async_unload_entry(hass, entry)
        assert result is True
        hass.config_entries.async_unload_platforms.assert_awaited_once_with(
            entry, PLATFORMS
        )


# =====================================================================
# async_reload_entry
# =====================================================================

class TestReloadEntry:
    @pytest.mark.asyncio
    async def test_reload_calls_unload_then_setup(self):
        """Reload should call unload then setup."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ):
            await async_reload_entry(hass, entry)

        # unload was called
        hass.config_entries.async_unload_platforms.assert_awaited_once()
        # setup was called (forward_entry_setups)
        hass.config_entries.async_forward_entry_setups.assert_awaited_once()


# =====================================================================
# OpenWrtRuntimeData
# =====================================================================

class TestRuntimeData:
    def test_dataclass_fields(self):
        api = MagicMock()
        coordinator = MagicMock()
        rd = OpenWrtRuntimeData(api=api, coordinator=coordinator)
        assert rd.api is api
        assert rd.coordinator is coordinator

    def test_platforms_list(self):
        """PLATFORMS should contain all expected platforms."""
        from homeassistant.const import Platform
        assert Platform.SENSOR in PLATFORMS
        assert Platform.SWITCH in PLATFORMS
        assert Platform.DEVICE_TRACKER in PLATFORMS
        assert Platform.BUTTON in PLATFORMS
        assert Platform.BINARY_SENSOR in PLATFORMS
        assert len(PLATFORMS) == 5
