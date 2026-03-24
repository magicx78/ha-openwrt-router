"""Tests for the OpenWrt Button platform (button.py)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.button import (
    BUTTON_DESCRIPTIONS,
    OpenWrtButtonEntity,
)
from custom_components.openwrt_router.const import (
    DOMAIN,
    SUFFIX_CHECK_UPDATES,
    SUFFIX_PERFORM_UPDATES,
    SUFFIX_RELOAD_WIFI,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_button(
    mock_coordinator,
    mock_config_entry,
    key: str,
    api: AsyncMock | None = None,
) -> OpenWrtButtonEntity:
    """Create a button entity for a given description key."""
    desc = next(d for d in BUTTON_DESCRIPTIONS if d.key == key)
    if api is None:
        api = AsyncMock()
        api.reload_wifi = AsyncMock(return_value=True)
        api.get_available_updates = AsyncMock(return_value={
            "available": False, "system": [], "addons": [],
        })
        api.perform_update = AsyncMock(return_value={
            "status": "initiated", "message": "ok",
        })
    return OpenWrtButtonEntity(
        coordinator=mock_coordinator,
        api=api,
        entry=mock_config_entry,
        description=desc,
    )


# =====================================================================
# Entity Creation
# =====================================================================

class TestButtonCreation:
    def test_three_buttons_defined(self):
        assert len(BUTTON_DESCRIPTIONS) == 3

    def test_reload_wifi_unique_id(self, mock_coordinator, mock_config_entry):
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_RELOAD_WIFI)
        assert btn.unique_id == f"test_entry_id_{SUFFIX_RELOAD_WIFI}"

    def test_check_updates_unique_id(self, mock_coordinator, mock_config_entry):
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES)
        assert btn.unique_id == f"test_entry_id_{SUFFIX_CHECK_UPDATES}"

    def test_perform_updates_unique_id(self, mock_coordinator, mock_config_entry):
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_PERFORM_UPDATES)
        assert btn.unique_id == f"test_entry_id_{SUFFIX_PERFORM_UPDATES}"

    def test_device_info(self, mock_coordinator, mock_config_entry):
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_RELOAD_WIFI)
        info = btn.device_info
        assert (DOMAIN, "test_entry_id") in info["identifiers"]
        assert info["manufacturer"] == "OpenWrt"


# =====================================================================
# Press Handlers
# =====================================================================

class TestReloadWifiButton:
    @pytest.mark.asyncio
    async def test_press_calls_reload(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.reload_wifi = AsyncMock(return_value=True)
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_RELOAD_WIFI, api=api)
        await btn.async_press()
        api.reload_wifi.assert_awaited_once()
        mock_coordinator.async_request_refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_press_failure_no_raise(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.reload_wifi = AsyncMock(return_value=False)
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_RELOAD_WIFI, api=api)
        # Should not raise
        await btn.async_press()
        mock_coordinator.async_request_refresh.assert_awaited_once()


class TestCheckUpdatesButton:
    @pytest.mark.asyncio
    async def test_press_calls_get_updates(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.get_available_updates = AsyncMock(return_value={
            "available": True, "system": [{"name": "pkg1"}], "addons": [],
        })
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES, api=api)
        await btn.async_press()
        api.get_available_updates.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_press_error_caught(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.get_available_updates = AsyncMock(side_effect=Exception("boom"))
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES, api=api)
        # Should not raise
        await btn.async_press()


class TestPerformUpdatesButton:
    @pytest.mark.asyncio
    async def test_press_calls_perform_update(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.perform_update = AsyncMock(return_value={
            "status": "initiated", "message": "ok",
        })
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_PERFORM_UPDATES, api=api)
        await btn.async_press()
        api.perform_update.assert_awaited_once_with(update_type="both")

    @pytest.mark.asyncio
    async def test_press_error_caught(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.perform_update = AsyncMock(side_effect=Exception("fail"))
        btn = _make_button(mock_coordinator, mock_config_entry, SUFFIX_PERFORM_UPDATES, api=api)
        # Should not raise
        await btn.async_press()
