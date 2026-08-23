"""Tests for the OpenWrt Device Tracker platform (device_tracker.py)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call

import pytest

from custom_components.openwrt_router.const import (
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    DOMAIN,
)
from custom_components.openwrt_router.device_tracker import (
    OpenWrtClientTrackerEntity,
    async_setup_entry,
)
from homeassistant.components.device_tracker import SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tracker(
    mock_coordinator,
    mock_config_entry,
    mac: str = "B8:27:EB:AA:BB:01",
) -> OpenWrtClientTrackerEntity:
    """Create a tracker entity with mock dependencies."""
    return OpenWrtClientTrackerEntity(
        coordinator=mock_coordinator,
        entry=mock_config_entry,
        mac=mac,
    )


def _make_hass() -> MagicMock:
    """Mock hass with a real data dict (needed for the MAC claim registry)."""
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_loaded_entries.return_value = []
    return hass


# =====================================================================
# async_setup_entry
# =====================================================================

class TestAsyncSetupEntry:
    @pytest.mark.asyncio
    async def test_adds_entities_for_existing_clients(
        self, mock_coordinator, mock_config_entry
    ):
        """Should create tracker entities for clients already present."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        added: list = []
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=lambda entities: added.extend(entities),
        )
        # 2 clients in mock_coordinator_data
        assert len(added) == 2
        macs = {e.mac_address for e in added}
        assert "B8:27:EB:AA:BB:01" in macs
        assert "AC:DE:48:11:22:01" in macs

    @pytest.mark.asyncio
    async def test_no_entities_when_no_data(self, mock_coordinator, mock_config_entry):
        """Should not crash when coordinator.data is None."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_coordinator.data = None
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        added: list = []
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=lambda entities: added.extend(entities),
        )
        assert len(added) == 0

    @pytest.mark.asyncio
    async def test_registers_listener(self, mock_coordinator, mock_config_entry):
        """Should register a coordinator listener for new clients."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=MagicMock(),
        )
        mock_coordinator.async_add_listener.assert_called_once()
        # one unload hook for the listener, one for the MAC claim release
        assert mock_config_entry.async_on_unload.call_count == 2


# =====================================================================
# Entity Creation
# =====================================================================

class TestTrackerCreation:
    def test_unique_id(self, mock_coordinator, mock_config_entry):
        """Newer HA cores force unique_id = mac_address; older ones use ours."""
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker._attr_unique_id == "test_entry_id_tracker_b827ebaabb01"
        assert tracker.unique_id in {
            "B8:27:EB:AA:BB:01",  # ScannerEntity.unique_id override (new cores)
            "test_entry_id_tracker_b827ebaabb01",  # _attr_unique_id (old cores)
        }

    def test_mac_address(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.mac_address == "B8:27:EB:AA:BB:01"

    def test_source_type(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.source_type == SourceType.ROUTER


# =====================================================================
# Name
# =====================================================================

class TestTrackerName:
    def test_name_uses_hostname(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.name == "raspberrypi"

    def test_name_falls_back_to_mac(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.name == "00:00:00:00:00:00"

    def test_name_when_hostname_empty(self, mock_coordinator, mock_config_entry):
        """If client found but hostname is empty, use MAC."""
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={"hostname": "", CLIENT_KEY_MAC: "B8:27:EB:AA:BB:01"}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.name == "B8:27:EB:AA:BB:01"


# =====================================================================
# Connection State
# =====================================================================

class TestTrackerState:
    def test_is_connected_true(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.is_connected is True

    def test_is_connected_false(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.is_connected is False


# =====================================================================
# IP Address
# =====================================================================

class TestTrackerIP:
    def test_ip_address_known(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.ip_address == "192.168.1.101"

    def test_ip_address_unknown_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.ip_address is None

    def test_ip_address_empty_string(self, mock_coordinator, mock_config_entry):
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={CLIENT_KEY_IP: ""}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.ip_address is None


# =====================================================================
# Hostname
# =====================================================================

class TestTrackerHostname:
    def test_hostname_present(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.hostname == "raspberrypi"

    def test_hostname_none_when_client_missing(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.hostname is None

    def test_hostname_none_when_empty(self, mock_coordinator, mock_config_entry):
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={"hostname": ""}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.hostname is None


# =====================================================================
# Extra State Attributes
# =====================================================================

class TestTrackerAttributes:
    def test_attrs_connected_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is True
        assert attrs["mac"] == "B8:27:EB:AA:BB:01"
        assert attrs["ssid"] == "OpenWrt-Home"
        assert attrs["signal"] == -55
        assert attrs["ip_address"] == "192.168.1.101"
        assert "radio" in attrs

    def test_attrs_disconnected_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is False
        assert attrs["mac"] == "00:00:00:00:00:00"
        assert "ssid" not in attrs


# =====================================================================
# Device Info
# =====================================================================

class TestTrackerDeviceInfo:
    def test_device_info(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        info = tracker.device_info
        assert (DOMAIN, "test_entry_id") in info["identifiers"]
        assert info["manufacturer"] == "OpenWrt"
        assert info["model"] == "GL.iNet GL-MT3000"
        assert info["sw_version"] == "24.10.0"

    def test_device_info_fallback_name(self, mock_coordinator, mock_config_entry):
        """When hostname missing from router_info, use entry title."""
        mock_coordinator.router_info = {"release": {}}
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        info = tracker.device_info
        assert info["name"] == "OpenWrt-Dev"  # entry.title


# =====================================================================
# T-DT1 through T-DT3: connected_since in extra_state_attributes
# =====================================================================

from custom_components.openwrt_router.const import CLIENT_KEY_CONNECTED_SINCE


class TestTrackerConnectedSince:
    """Tests that connected_since is surfaced in extra_state_attributes."""

    def _tracker_with_connected_since(self, mock_coordinator, mock_config_entry):
        """Return a tracker whose client has a connected_since timestamp."""
        mock_coordinator.get_client_by_mac = MagicMock(return_value={
            CLIENT_KEY_MAC: "B8:27:EB:AA:BB:01",
            CLIENT_KEY_IP: "192.168.1.101",
            CLIENT_KEY_SIGNAL: -55,
            CLIENT_KEY_SSID: "OpenWrt-Home",
            CLIENT_KEY_RADIO: "phy0-ap0",
            "hostname": "raspberrypi",
            CLIENT_KEY_CONNECTED_SINCE: "2026-04-06T10:00:00+00:00",
        })
        mock_coordinator.is_client_connected = MagicMock(return_value=True)
        return _make_tracker(mock_coordinator, mock_config_entry)

    def test_t_dt1_connected_since_present_when_online(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT1: connected_since appears in extra_state_attributes for connected client."""
        tracker = self._tracker_with_connected_since(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        assert "connected_since" in attrs
        assert attrs["connected_since"] == "2026-04-06T10:00:00+00:00"

    def test_t_dt2_no_connected_since_when_offline(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT2: Offline client has connected: False and no connected_since."""
        mock_coordinator.get_client_by_mac = MagicMock(return_value=None)
        mock_coordinator.is_client_connected = MagicMock(return_value=False)
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is False
        assert "connected_since" not in attrs

    def test_t_dt3_connected_since_is_iso_format(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT3: connected_since value is a valid ISO-8601 datetime string."""
        from datetime import datetime
        tracker = self._tracker_with_connected_since(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        ts = attrs.get("connected_since", "")
        # Must parse without error
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            pytest.fail(f"connected_since '{ts}' is not a valid ISO datetime")


# =====================================================================
# Cross-entry dedup + mesh-wide roaming (v1.26.4)
# =====================================================================

class TestCrossEntryDedup:
    """Same client MAC visible on several routers → only ONE entity."""

    def _entry(self, entry_id: str, mock_coordinator):
        from custom_components.openwrt_router import OpenWrtRuntimeData
        entry = MagicMock()
        entry.entry_id = entry_id
        entry.title = entry_id
        entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        entry.async_on_unload = MagicMock()
        return entry

    @pytest.mark.asyncio
    async def test_second_entry_skips_claimed_macs(self, mock_coordinator):
        """Entry B must not create entities for MACs already claimed by A."""
        hass = _make_hass()
        entry_a = self._entry("entry_a", mock_coordinator)
        entry_b = self._entry("entry_b", mock_coordinator)

        added_a: list = []
        added_b: list = []
        await async_setup_entry(hass, entry_a, lambda e: added_a.extend(e))
        await async_setup_entry(hass, entry_b, lambda e: added_b.extend(e))

        assert len(added_a) == 2
        assert len(added_b) == 0

    @pytest.mark.asyncio
    async def test_claims_released_on_unload(self, mock_coordinator):
        """After entry A unloads, entry B can claim the same MACs."""
        hass = _make_hass()
        entry_a = self._entry("entry_a", mock_coordinator)
        entry_b = self._entry("entry_b", mock_coordinator)

        added_a: list = []
        await async_setup_entry(hass, entry_a, lambda e: added_a.extend(e))
        assert len(added_a) == 2

        # Simulate unload of A: run all registered unload callbacks
        for call_args in entry_a.async_on_unload.call_args_list:
            call_args.args[0]()

        added_b: list = []
        await async_setup_entry(hass, entry_b, lambda e: added_b.extend(e))
        assert len(added_b) == 2


class TestMeshRoaming:
    """Tracker reports 'home' when ANY loaded router sees the client."""

    def _roaming_setup(self, mock_coordinator, mock_config_entry, client: dict):
        """Tracker owned by A; the client is only visible on router B."""
        from custom_components.openwrt_router import OpenWrtRuntimeData

        # Real runtime_data for the owning entry so the mesh lookup skips it
        # via coordinator identity (a bare MagicMock would auto-create a
        # truthy fake coordinator instead).
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )

        coordinator_b = MagicMock()
        coordinator_b.get_client_by_mac = MagicMock(
            side_effect=lambda mac: client
            if mac.upper() == client[CLIENT_KEY_MAC].upper()
            else None
        )
        coordinator_b.router_info = {"hostname": "OpenWrt-AP4"}

        entry_b = MagicMock()
        entry_b.entry_id = "entry_b"
        entry_b.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=coordinator_b
        )

        hass = _make_hass()
        hass.config_entries.async_loaded_entries.return_value = [
            mock_config_entry, entry_b
        ]

        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac=client[CLIENT_KEY_MAC]
        )
        tracker.hass = hass
        return tracker

    def test_roaming_client_is_home(self, mock_coordinator, mock_config_entry):
        client = {
            CLIENT_KEY_MAC: "0A:0B:0C:0D:0E:0F",
            CLIENT_KEY_IP: "192.168.1.199",
            CLIENT_KEY_SSID: "OpenWrt-Home",
            CLIENT_KEY_RADIO: "phy1-ap0",
            CLIENT_KEY_SIGNAL: -61,
            "hostname": "wanderer",
        }
        tracker = self._roaming_setup(mock_coordinator, mock_config_entry, client)

        assert tracker.is_connected is True
        assert tracker.ip_address == "192.168.1.199"
        assert tracker.hostname == "wanderer"
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is True
        assert attrs["connected_ap"] == "OpenWrt-AP4"

    def test_client_gone_everywhere_is_not_home(
        self, mock_coordinator, mock_config_entry
    ):
        client = {CLIENT_KEY_MAC: "0A:0B:0C:0D:0E:0F"}
        tracker = self._roaming_setup(mock_coordinator, mock_config_entry, client)
        tracker._mac = "FF:FF:FF:FF:FF:FF"  # a MAC no coordinator knows

        assert tracker.is_connected is False
        assert tracker.extra_state_attributes["connected"] is False
