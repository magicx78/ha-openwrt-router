"""Tests for the OpenWrt Switch platform (switch.py)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.const import (
    DOMAIN,
    RADIO_KEY_BAND,
    RADIO_KEY_ENABLED,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_SSID,
    RADIO_KEY_UCI_SECTION,
)
from custom_components.openwrt_router.switch import OpenWrtWifiSwitchEntity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_switch(
    mock_coordinator,
    mock_config_entry,
    radio: dict | None = None,
    api: AsyncMock | None = None,
) -> OpenWrtWifiSwitchEntity:
    """Create a switch entity with mock dependencies."""
    if radio is None:
        radio = mock_coordinator.data.wifi_radios[0]  # OpenWrt-Home 2.4g
    if api is None:
        api = AsyncMock()
        api.set_wifi_state = AsyncMock(return_value=True)
    return OpenWrtWifiSwitchEntity(
        coordinator=mock_coordinator,
        api=api,
        entry=mock_config_entry,
        radio=radio,
    )


# =====================================================================
# Entity Creation
# =====================================================================

class TestSwitchCreation:
    def test_name_with_known_band(self, mock_coordinator, mock_config_entry):
        radio = mock_coordinator.data.wifi_radios[1]  # 5g band
        switch = _make_switch(mock_coordinator, mock_config_entry, radio=radio)
        assert switch.name == "OpenWrt-Home-5G (5 GHz)"

    def test_name_with_24g_band(self, mock_coordinator, mock_config_entry):
        # "2.4g" returned by _detect_band must display as "2.4 GHz"
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch.name == "OpenWrt-Home (2.4 GHz)"

    def test_unique_id(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch.unique_id == "test_entry_id_wifi_ssid_default_radio0"

    def test_5g_name(self, mock_coordinator, mock_config_entry):
        radio = mock_coordinator.data.wifi_radios[1]  # 5g
        switch = _make_switch(mock_coordinator, mock_config_entry, radio=radio)
        assert "5 GHz" in switch.name

    def test_guest_icon(self, mock_coordinator, mock_config_entry):
        radio = mock_coordinator.data.wifi_radios[2]  # Guest
        switch = _make_switch(mock_coordinator, mock_config_entry, radio=radio)
        assert switch.icon == "mdi:wifi-star"

    def test_normal_icon(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch.icon == "mdi:wifi"

    def test_device_info(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        info = switch.device_info
        assert (DOMAIN, "test_entry_id") in info["identifiers"]
        assert info["manufacturer"] == "OpenWrt"


# =====================================================================
# State
# =====================================================================

class TestSwitchState:
    def test_is_on_enabled(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch.is_on is True

    def test_is_on_disabled(self, mock_coordinator, mock_config_entry):
        # Modify radio to be disabled
        radio = dict(mock_coordinator.data.wifi_radios[0])
        radio[RADIO_KEY_ENABLED] = False
        mock_coordinator.data.wifi_radios[0] = radio
        switch = _make_switch(mock_coordinator, mock_config_entry, radio=radio)
        assert switch.is_on is False

    def test_is_on_none_when_radio_missing(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        mock_coordinator.data.wifi_radios = []  # Remove all radios
        assert switch.is_on is None

    def test_is_on_none_when_no_data(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        mock_coordinator.data = None
        assert switch.is_on is None


# =====================================================================
# Turn On / Off
# =====================================================================

class TestSwitchControl:
    @pytest.mark.asyncio
    async def test_turn_on(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.set_wifi_state = AsyncMock(return_value=True)
        switch = _make_switch(mock_coordinator, mock_config_entry, api=api)
        await switch.async_turn_on()
        api.set_wifi_state.assert_awaited_once_with("default_radio0", enabled=True)
        mock_coordinator.async_request_refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_turn_off(self, mock_coordinator, mock_config_entry):
        api = AsyncMock()
        api.set_wifi_state = AsyncMock(return_value=True)
        switch = _make_switch(mock_coordinator, mock_config_entry, api=api)
        await switch.async_turn_off()
        api.set_wifi_state.assert_awaited_once_with("default_radio0", enabled=False)
        mock_coordinator.async_request_refresh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_turn_on_no_uci_section(self, mock_coordinator, mock_config_entry):
        """When UCI section is empty, no API call should be made."""
        radio = {
            RADIO_KEY_SSID: "NoUCI",
            RADIO_KEY_BAND: "2g",
            RADIO_KEY_ENABLED: True,
            RADIO_KEY_IS_GUEST: False,
            RADIO_KEY_UCI_SECTION: "",
            RADIO_KEY_IFNAME: "wlan0",
        }
        api = AsyncMock()
        switch = _make_switch(mock_coordinator, mock_config_entry, radio=radio, api=api)
        await switch.async_turn_on()
        api.set_wifi_state.assert_not_awaited()


# =====================================================================
# Extra Attributes
# =====================================================================

class TestSwitchAttributes:
    def test_extra_attrs(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        attrs = switch.extra_state_attributes
        assert attrs["ssid"] == "OpenWrt-Home"
        assert attrs["band"] == "2.4g"
        assert attrs["uci_section"] == "default_radio0"
        assert attrs["is_guest"] is False
        assert "connected_clients" in attrs
        assert "clients" in attrs

    def test_extra_attrs_empty_when_radio_missing(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        mock_coordinator.data.wifi_radios = []
        assert switch.extra_state_attributes == {}

    def test_client_count_for_ssid(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        attrs = switch.extra_state_attributes
        # One client is on OpenWrt-Home
        assert attrs["connected_clients"] == 1

    def test_clients_list_structure(self, mock_coordinator, mock_config_entry):
        """Client list must include name, mac, ip, signal_dbm, connected_since, dhcp_expires."""
        switch = _make_switch(mock_coordinator, mock_config_entry)
        clients = switch.extra_state_attributes["clients"]
        assert len(clients) == 1
        c = clients[0]
        assert c["name"] == "raspberrypi"
        assert c["mac"] == "B8:27:EB:AA:BB:01"
        assert c["ip"] == "192.168.1.101"
        assert c["signal_dbm"] == -55
        assert c["connected_since"] == "2026-04-07T10:00:00+00:00"
        # dhcp_expires is a non-empty string (far-future timestamp 9999999999)
        assert c["dhcp_expires"] != ""

    def test_clients_list_uses_mac_when_no_hostname(self, mock_coordinator, mock_config_entry):
        """When hostname is absent, name should fall back to MAC."""
        from custom_components.openwrt_router.const import CLIENT_KEY_HOSTNAME
        mock_coordinator.data.clients[0][CLIENT_KEY_HOSTNAME] = ""
        switch = _make_switch(mock_coordinator, mock_config_entry)
        clients = switch.extra_state_attributes["clients"]
        assert clients[0]["name"] == "B8:27:EB:AA:BB:01"


# =====================================================================
# _format_band Helper
# =====================================================================

class TestFormatBand:
    def test_2g(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch._format_band("2g") == "2.4 GHz"

    def test_5g(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch._format_band("5g") == "5 GHz"

    def test_6g(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch._format_band("6g") == "6 GHz"

    def test_60g(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch._format_band("60g") == "60 GHz"

    def test_unknown(self, mock_coordinator, mock_config_entry):
        switch = _make_switch(mock_coordinator, mock_config_entry)
        assert switch._format_band("xyz") == ""
