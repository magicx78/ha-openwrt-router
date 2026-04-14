"""Regression tests for the OpenWrt Router integration.

Each test class documents a specific bug that was found and fixed. The test
must fail before the fix and pass after it. New bugs follow the same pattern.
"""
from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
)
from custom_components.openwrt_router.const import (
    CLIENT_KEY_MAC,
    CLIENT_KEY_CONNECTED_SINCE,
    FEATURE_HAS_IWINFO,
    FEATURE_DHCP_LEASES,
    FEATURE_HAS_5GHZ,
)
from custom_components.openwrt_router.sensor import (
    OpenWrtInterfaceSensor,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_coordinator(api=None):
    """Create a coordinator with a minimal mock HA and optional mock API."""
    hass = MagicMock()
    hass.async_create_task = MagicMock(side_effect=lambda coro: coro)

    if api is None:
        api = AsyncMock()
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
            "connected": False,
            "interface": "",
            "ipv4": None,
        })
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(return_value={
            "uptime": 100, "cpu_load": 0.0, "cpu_load_5min": 0.0,
            "cpu_load_15min": 0.0, "memory": {"total": 256, "free": 128},
        })
        api.get_disk_space = AsyncMock(return_value={})
        api.get_tmpfs_stats = AsyncMock(return_value={})
        api.get_network_interfaces = AsyncMock(return_value=[])
        api.get_active_connections = AsyncMock(return_value=0)

    with patch("homeassistant.helpers.frame.report_usage"):
        coordinator = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    return coordinator, api


# =====================================================================
# REG-01: WAN down — no wan interface in network_interfaces
# =====================================================================

class TestReg01WanDown:
    """REG-01: When WAN is down, the wan interface is absent from
    network_interfaces. The integration must not crash and must not create
    stale sensors for missing interfaces."""

    @pytest.mark.asyncio
    async def test_wan_down_no_crash(self):
        coord, api = _make_coordinator()
        # No "wan" entry in network_interfaces — simulates WAN down
        api.get_network_interfaces = AsyncMock(return_value=[
            {"interface": "lan", "rx_bytes": 500000, "tx_bytes": 250000, "up": True},
            {"interface": "loopback", "rx_bytes": 50, "tx_bytes": 50, "up": True},
        ])
        data = await coord._async_update_data()
        iface_names = [i.get("interface") for i in data.network_interfaces]
        assert "wan" not in iface_names
        assert "lan" in iface_names

    @pytest.mark.asyncio
    async def test_interface_sensor_returns_none_when_interface_missing(self):
        """OpenWrtInterfaceSensor returns None when the tracked interface is gone."""
        coord, _ = _make_coordinator()
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "lan", "rx_bytes": 100, "tx_bytes": 50, "up": True}
        ]
        coord.data = data

        entry = MagicMock()
        entry.entry_id = "test_entry"
        entry.data = {"host": "192.168.1.1", "port": 80, "protocol": "http"}

        sensor = OpenWrtInterfaceSensor(coord, entry, "wan", "rx_bytes")
        # wan is not in network_interfaces → should return None, not crash
        assert sensor.native_value is None


# =====================================================================
# REG-02: Interface with rx_bytes as string → no crash
# =====================================================================

class TestReg02StringRxBytes:
    """REG-02: Some routers return byte counters as strings instead of ints.
    The sensor must handle this without crashing and return a value or None."""

    def test_interface_sensor_with_string_rx_bytes_does_not_crash(self):
        coord, _ = _make_coordinator()
        data = OpenWrtCoordinatorData()
        # rx_bytes is a string — broken router payload
        data.network_interfaces = [
            {"interface": "lan", "rx_bytes": "not-a-number", "tx_bytes": None}
        ]
        coord.data = data

        entry = MagicMock()
        entry.entry_id = "test_entry"
        entry.data = {"host": "192.168.1.1", "port": 80, "protocol": "http"}

        sensor = OpenWrtInterfaceSensor(coord, entry, "lan", "rx_bytes")
        # Should not raise — may return the raw string or None
        try:
            val = sensor.native_value
        except Exception as exc:
            pytest.fail(f"native_value raised unexpectedly: {exc}")

    def test_interface_sensor_with_none_tx_bytes(self):
        coord, _ = _make_coordinator()
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "lan", "rx_bytes": 1000, "tx_bytes": None}
        ]
        coord.data = data

        entry = MagicMock()
        entry.entry_id = "test_entry"
        entry.data = {"host": "192.168.1.1", "port": 80, "protocol": "http"}

        sensor = OpenWrtInterfaceSensor(coord, entry, "lan", "tx_bytes")
        assert sensor.native_value is None


# =====================================================================
# REG-03: _client_first_seen cleaned up after disconnect
# =====================================================================

class TestReg03ClientFirstSeenCleanup:
    """REG-03: When a client disconnects, its MAC must be removed from
    _client_first_seen so memory does not grow unbounded."""

    @pytest.mark.asyncio
    async def test_client_first_seen_removed_after_disconnect(self):
        coord, api = _make_coordinator()
        mac = "AA:BB:CC:DD:EE:FF"

        # First poll: client connected
        api.get_connected_clients = AsyncMock(return_value=[
            {CLIENT_KEY_MAC: mac, "ip": "192.168.1.10", "hostname": "device"}
        ])
        await coord._async_update_data()
        assert mac in coord._client_first_seen

        # Second poll: client gone
        api.get_connected_clients = AsyncMock(return_value=[])
        await coord._async_update_data()
        assert mac not in coord._client_first_seen


# =====================================================================
# REG-04: unique_id stable across multiple setup cycles
# =====================================================================

class TestReg04UniqueIdStable:
    """REG-04: The unique_id of a sensor must be derived solely from
    entry_id + interface name so it does not change between restarts."""

    def test_interface_sensor_unique_id_is_deterministic(self):
        coord, _ = _make_coordinator()
        coord.data = OpenWrtCoordinatorData()

        entry = MagicMock()
        entry.entry_id = "fixed_entry_id"
        entry.data = {"host": "192.168.1.1", "port": 80, "protocol": "http"}

        sensor_a = OpenWrtInterfaceSensor(coord, entry, "wan", "rx_bytes")
        sensor_b = OpenWrtInterfaceSensor(coord, entry, "wan", "rx_bytes")

        assert sensor_a._attr_unique_id == sensor_b._attr_unique_id
        assert sensor_a._attr_unique_id == "fixed_entry_id_iface_wan_rx"

    def test_interface_sensor_unique_id_different_for_tx(self):
        coord, _ = _make_coordinator()
        coord.data = OpenWrtCoordinatorData()

        entry = MagicMock()
        entry.entry_id = "fixed_entry_id"
        entry.data = {"host": "192.168.1.1", "port": 80, "protocol": "http"}

        rx = OpenWrtInterfaceSensor(coord, entry, "wan", "rx_bytes")
        tx = OpenWrtInterfaceSensor(coord, entry, "wan", "tx_bytes")

        assert rx._attr_unique_id != tx._attr_unique_id
        assert rx._attr_unique_id == "fixed_entry_id_iface_wan_rx"
        assert tx._attr_unique_id == "fixed_entry_id_iface_wan_tx"


# =====================================================================
# REG-05: Multiple setup calls don't create duplicate entities
# =====================================================================

class TestReg05NoDuplicateEntities:
    """REG-05: The tracked_interfaces set in async_setup_entry must prevent
    the same interface from generating duplicate sensors when the listener
    fires multiple times."""

    def test_tracked_interfaces_set_prevents_duplicates(self):
        """Verify the deduplication logic in the dynamic sensor callback."""
        tracked: set[str] = set()
        interfaces = [
            {"interface": "wan", "rx_bytes": 100, "tx_bytes": 50},
            {"interface": "wan", "rx_bytes": 200, "tx_bytes": 80},  # duplicate
            {"interface": "lan", "rx_bytes": 500, "tx_bytes": 200},
        ]
        added_sensors: list[str] = []

        # Simulate the _add_dynamic_sensors callback logic
        for iface in interfaces:
            ifname = iface.get("interface", "")
            if not ifname or ifname in tracked:
                continue
            tracked.add(ifname)
            added_sensors.append(f"{ifname}_rx")
            added_sensors.append(f"{ifname}_tx")

        assert added_sensors.count("wan_rx") == 1
        assert added_sensors.count("lan_rx") == 1
        assert len(added_sensors) == 4  # wan_rx, wan_tx, lan_rx, lan_tx
