"""Tests for the OpenWrt binary_sensor platform."""
from __future__ import annotations

from custom_components.openwrt_router.binary_sensor import (
    BINARY_SENSOR_DESCRIPTIONS,
    OpenWrtBinarySensorEntity,
)
from custom_components.openwrt_router.const import (
    DOMAIN,
    SUFFIX_CONNECTIVITY,
    SUFFIX_WAN_CONNECTIVITY,
)


def _make(coordinator, entry, key):
    desc = next(d for d in BINARY_SENSOR_DESCRIPTIONS if d.key == key)
    return OpenWrtBinarySensorEntity(coordinator, entry, desc)


class TestBinarySensorDeviceInfo:
    """Regression for v1.17.0 → 1.17.1.

    The first v1.17.0 used a MAC-based identifier which created a SECOND
    device in the HA registry — making all other entities seem to vanish
    from the device card. v1.17.1 reverts to entry.entry_id, matching every
    other platform in the integration.
    """

    def test_connectivity_uses_entry_id(self, mock_coordinator, mock_config_entry):
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_CONNECTIVITY)
        assert sensor.device_info["identifiers"] == {(DOMAIN, "test_entry_id")}

    def test_wan_connectivity_uses_entry_id(self, mock_coordinator, mock_config_entry):
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_WAN_CONNECTIVITY)
        assert sensor.device_info["identifiers"] == {(DOMAIN, "test_entry_id")}


class TestBinarySensorValues:
    def test_connectivity_on_when_update_succeeded(
        self, mock_coordinator, mock_config_entry
    ):
        mock_coordinator.last_update_success = True
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_CONNECTIVITY)
        assert sensor.is_on is True

    def test_connectivity_off_when_update_failed(
        self, mock_coordinator, mock_config_entry
    ):
        mock_coordinator.last_update_success = False
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_CONNECTIVITY)
        assert sensor.is_on is False

    def test_connectivity_always_available(
        self, mock_coordinator, mock_config_entry
    ):
        mock_coordinator.last_update_success = False
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_CONNECTIVITY)
        # Connectivity must remain available so we can show "offline"
        assert sensor.available is True

    def test_unique_id_format(self, mock_coordinator, mock_config_entry):
        sensor = _make(mock_coordinator, mock_config_entry, SUFFIX_CONNECTIVITY)
        assert sensor.unique_id == f"test_entry_id_{SUFFIX_CONNECTIVITY}"
