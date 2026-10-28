"""Volatile / large state attributes are kept out of the recorder (N9).

HA combines ``_entity_component_unrecorded_attributes`` with the
``_unrecorded_attributes`` of the concrete class in ``__init_subclass__``;
a class that does not define the set itself inherits an empty one. These
tests therefore check the set on each entity class directly, and that the
excluded names are real attribute keys (no typo silently keeps recording).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from custom_components.openwrt_router.binary_sensor import (
    BINARY_SENSOR_DESCRIPTIONS,
    OpenWrtBinarySensorEntity,
    OpenWrtStickyClientsBinarySensor,
)
from custom_components.openwrt_router.const import SUFFIX_CONNECTIVITY
from custom_components.openwrt_router.device_tracker import (
    OpenWrtClientTrackerEntity,
)
from custom_components.openwrt_router.sensor import (
    SENSOR_DESCRIPTIONS,
    OpenWrtPortSensor,
    OpenWrtRouterStatusSensor,
    OpenWrtSensorEntity,
)
from custom_components.openwrt_router.switch import OpenWrtWifiSwitchEntity

SENSOR_VOLATILE = {
    # elapsed times
    "uptime_seconds",
    "uptime_raw",
    "uptime_formatted",
    # client list with signal values
    "clients",
    # per-poll load / memory readings
    "load_1min",
    "load_average_1min",
    "load_average_5min",
    "load_average_15min",
    "free_mb",
    "used_mb",
    "available_mb",
    "pressure_pct",
    # update check: package lists + check timestamp
    "packages",
    "system_packages",
    "addon_packages",
    "last_check",
    # log parser counters
    "lines_processed",
    "baseline_lines",
    "missed_lines",
    "events_fired",
    "events_suppressed",
    "counts_24h",
    # unstable clients ranking
    "top",
}
SENSOR_STABLE = {
    "interface",
    "ip_address",
    "protocol",
    "cpu_cores",
    "total_mb",
    "updates_count",
    "package_manager",
    "index_refreshed",
    "system_updates_count",
    "addon_updates_count",
    "distribution",
    "kernel",
    "board",
    "by_type",
    "last_event",
}


def _own_set(cls: type) -> frozenset[str]:
    """The set defined on the class itself (not an inherited empty one)."""
    assert "_unrecorded_attributes" in vars(cls), cls.__name__
    return cls._unrecorded_attributes


def _fill_data(data) -> None:
    data.uptime = 3600
    data.load_average = [0.5, 0.4, 0.3]
    data.updates_available = {
        "available": True,
        "count": 1,
        "packages": [{"name": "pkg-a"}],
        "package_manager": "apk",
        "index_refreshed": True,
        "last_check": "2026-01-01T00:00:00+00:00",
        "system": [{"name": "pkg-a"}],
        "addons": [],
    }
    data.log_stats = {
        "lines_processed": 1,
        "baseline_lines": 1,
        "missed_lines": 0,
        "events_fired": 0,
        "events_suppressed": 0,
        "counts_24h": {},
    }
    data.client_stability = {"unstable": []}


class TestSensor:
    def test_description_sensor_excludes_volatile(self):
        own = _own_set(OpenWrtSensorEntity)
        assert own >= SENSOR_VOLATILE
        assert not own & SENSOR_STABLE

    def test_excluded_keys_exist(self, mock_coordinator, mock_config_entry):
        _fill_data(mock_coordinator.data)
        keys: set[str] = set()
        for desc in SENSOR_DESCRIPTIONS:
            entity = OpenWrtSensorEntity(mock_coordinator, mock_config_entry, desc)
            keys |= set(entity.extra_state_attributes)
        assert _own_set(OpenWrtSensorEntity) <= keys
        assert keys >= SENSOR_STABLE

    def test_router_status_excludes_last_seen(self):
        own = _own_set(OpenWrtRouterStatusSensor)
        assert own == {"last_seen"}

    def test_port_sensor_excludes_packet_counters(self):
        own = _own_set(OpenWrtPortSensor)
        assert own == {"rx_packets", "tx_packets"}


class TestBinarySensor:
    def test_connectivity_excludes_last_seen(self, mock_coordinator, mock_config_entry):
        own = _own_set(OpenWrtBinarySensorEntity)
        assert own == {"last_seen"}
        mock_coordinator.data.last_seen = datetime(2026, 1, 1, tzinfo=UTC)
        desc = next(
            d for d in BINARY_SENSOR_DESCRIPTIONS if d.key == SUFFIX_CONNECTIVITY
        )
        entity = OpenWrtBinarySensorEntity(mock_coordinator, mock_config_entry, desc)
        assert own <= set(entity.extra_state_attributes)

    def test_sticky_clients_excludes_client_list(self):
        assert _own_set(OpenWrtStickyClientsBinarySensor) == {"clients"}


class TestSwitch:
    def test_wifi_switch_excludes_client_list(self):
        own = _own_set(OpenWrtWifiSwitchEntity)
        assert own == {"clients"}
        assert "connected_clients" not in own


class TestDeviceTracker:
    @pytest.mark.parametrize("key", ["signal"])
    def test_tracker_excludes_signal(self, key):
        assert key in _own_set(OpenWrtClientTrackerEntity)

    def test_tracker_keeps_presence_attributes(self):
        own = _own_set(OpenWrtClientTrackerEntity)
        for key in ("mac", "connected", "ssid", "ip_address", "connected_ap"):
            assert key not in own
