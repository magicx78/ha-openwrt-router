"""Tests for the OpenWrt Sensor platform (sensor.py)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.sensor import (
    SENSOR_DESCRIPTIONS,
    OpenWrtSensorEntity,
    _calc_memory_pct,
    _format_uptime,
)
from custom_components.openwrt_router.const import DOMAIN


# =====================================================================
# Utility Functions
# =====================================================================

class TestFormatUptime:
    def test_zero(self):
        assert _format_uptime(0) == "0s"

    def test_negative(self):
        assert _format_uptime(-1) == "0s"

    def test_seconds_only(self):
        assert _format_uptime(45) == "45s"

    def test_minutes_and_seconds(self):
        assert _format_uptime(125) == "2m 5s"

    def test_hours_minutes_seconds(self):
        assert _format_uptime(3665) == "1h 1m 5s"

    def test_days_hours_minutes_seconds(self):
        assert _format_uptime(90061) == "1d 1h 1m 1s"

    def test_large_value(self):
        result = _format_uptime(86400 * 30)  # 30 days
        assert result.startswith("30d")

    def test_exact_day(self):
        assert _format_uptime(86400) == "1d 0s"


class TestCalcMemoryPct:
    def test_normal(self):
        mem = {"total": 268435456, "free": 134217728}  # 256MB, 128MB
        assert _calc_memory_pct(mem) == 50.0

    def test_zero_total(self):
        assert _calc_memory_pct({"total": 0, "free": 0}) is None

    def test_empty_dict(self):
        assert _calc_memory_pct({}) is None

    def test_all_used(self):
        assert _calc_memory_pct({"total": 100, "free": 0}) == 100.0

    def test_all_free(self):
        assert _calc_memory_pct({"total": 100, "free": 100}) == 0.0


# =====================================================================
# Sensor Descriptions
# =====================================================================

class TestSensorDescriptions:
    def test_all_have_value_fn(self):
        for desc in SENSOR_DESCRIPTIONS:
            assert callable(desc.value_fn), f"{desc.key} missing value_fn"

    def test_all_have_key(self):
        for desc in SENSOR_DESCRIPTIONS:
            assert desc.key, f"Sensor description missing key"

    def test_keys_are_unique(self):
        keys = [d.key for d in SENSOR_DESCRIPTIONS]
        assert len(keys) == len(set(keys))

    def test_at_least_15_sensors(self):
        assert len(SENSOR_DESCRIPTIONS) >= 15


# =====================================================================
# Sensor Entity
# =====================================================================

def _make_sensor(mock_coordinator, mock_config_entry, key: str) -> OpenWrtSensorEntity:
    """Create a sensor entity for a given description key."""
    desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == key)
    return OpenWrtSensorEntity(
        coordinator=mock_coordinator,
        entry=mock_config_entry,
        description=desc,
    )


class TestSensorEntity:
    def test_uptime_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        val = sensor.native_value
        assert val is not None
        assert "1d" in val  # 86400 seconds = 1 day

    def test_uptime_extra_attrs(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        attrs = sensor.extra_state_attributes
        assert "uptime_seconds" in attrs
        assert attrs["uptime_seconds"] == 86400

    def test_cpu_load_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "cpu_load")
        assert sensor.native_value == 100.0

    def test_memory_usage_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "memory_usage")
        assert sensor.native_value == 50.0  # (256-128)/256 * 100

    def test_memory_free_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "memory_free")
        assert sensor.native_value == 128.0  # 134217728 / 1024 / 1024

    def test_client_count_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "client_count")
        assert sensor.native_value == 2

    def test_firmware_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "firmware")
        assert sensor.native_value == "24.10.0"

    def test_active_connections_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "active_connections")
        assert sensor.native_value == 42

    def test_disk_usage_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "disk_usage")
        assert sensor.native_value == 30.0

    def test_tmpfs_usage_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "tmpfs_usage")
        assert sensor.native_value == 7.8

    def test_platform_architecture_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "platform_architecture")
        assert sensor.native_value == "mediatek/filogic"

    def test_wan_status_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "wan_status")
        assert sensor.native_value == "connected"

    def test_update_status_value(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "update_status")
        assert sensor.native_value == "current"  # available is False by default

    def test_none_when_no_data(self, mock_coordinator, mock_config_entry):
        mock_coordinator.data = None
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        assert sensor.native_value is None

    def test_empty_attrs_when_no_data(self, mock_coordinator, mock_config_entry):
        mock_coordinator.data = None
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        assert sensor.extra_state_attributes == {}

    def test_unique_id_format(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        assert sensor.unique_id == "test_entry_id_uptime"

    def test_device_info(self, mock_coordinator, mock_config_entry):
        sensor = _make_sensor(mock_coordinator, mock_config_entry, "uptime")
        info = sensor.device_info
        assert (DOMAIN, "test_entry_id") in info["identifiers"]
        assert info["manufacturer"] == "OpenWrt"
        assert info["model"] == "GL.iNet GL-MT3000"


# =====================================================================
# All value_fn calls with mock data (smoke test)
# =====================================================================

class TestAllSensorValueFns:
    def test_all_value_fns_dont_crash(self, mock_coordinator_data):
        """Every value_fn should run without error on valid coordinator data."""
        for desc in SENSOR_DESCRIPTIONS:
            try:
                val = desc.value_fn(mock_coordinator_data)
            except Exception as e:
                pytest.fail(f"value_fn for {desc.key} raised {e}")

    def test_all_extra_attrs_fns_dont_crash(self, mock_coordinator_data):
        """Every extra_attrs_fn should run without error."""
        for desc in SENSOR_DESCRIPTIONS:
            if desc.extra_attrs_fn is not None:
                try:
                    attrs = desc.extra_attrs_fn(mock_coordinator_data)
                    assert isinstance(attrs, dict)
                except Exception as e:
                    pytest.fail(f"extra_attrs_fn for {desc.key} raised {e}")
