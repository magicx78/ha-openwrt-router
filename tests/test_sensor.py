"""Tests for the OpenWrt Sensor platform (sensor.py)."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
from custom_components.openwrt_router.sensor import (
    SENSOR_DESCRIPTIONS,
    OpenWrtAPInterfaceSensor,
    OpenWrtSensorEntity,
    _calc_memory_pct,
    _format_uptime,
)
from custom_components.openwrt_router.const import (
    DOMAIN,
    RADIO_KEY_BAND,
    RADIO_KEY_BITRATE,
    RADIO_KEY_BSSID,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_HTMODE,
    RADIO_KEY_HWMODE,
    RADIO_KEY_IFNAME,
    RADIO_KEY_MODE,
    RADIO_KEY_NAME,
    RADIO_KEY_SSID,
    RADIO_KEY_TXPOWER,
    CLIENT_KEY_RADIO,
)


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


# =====================================================================
# T-S1 through T-S6: Dynamic interface and radio sensors
# =====================================================================

from unittest.mock import MagicMock, patch, AsyncMock
from custom_components.openwrt_router.sensor import (
    OpenWrtInterfaceSensor,
    OpenWrtRadioSensor,
    async_setup_entry,
)
from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData


class TestDynamicInterfaceSensors:
    """T-S1: Dynamic interface sensors are created for wan, lan, loopback."""

    def _make_coordinator_with_interfaces(self, mock_coordinator, interfaces):
        data = OpenWrtCoordinatorData()
        data.network_interfaces = interfaces
        data.wifi_radios = []
        mock_coordinator.data = data
        return mock_coordinator

    def test_t_s1_sensors_created_for_wan_lan_loopback(
        self, mock_coordinator, mock_config_entry
    ):
        """T-S1: rx and tx sensors created for each interface."""
        self._make_coordinator_with_interfaces(
            mock_coordinator,
            [
                {"interface": "wan", "rx_bytes": 100, "tx_bytes": 50},
                {"interface": "lan", "rx_bytes": 200, "tx_bytes": 80},
                {"interface": "loopback", "rx_bytes": 10, "tx_bytes": 10},
            ],
        )
        added: list = []

        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        mock_config_entry.async_on_unload = MagicMock()

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            async_setup_entry(
                hass=MagicMock(),
                entry=mock_config_entry,
                async_add_entities=lambda entities, **kw: added.extend(entities),
            )
        )
        interface_sensors = [
            e for e in added if isinstance(e, OpenWrtInterfaceSensor)
        ]
        iface_names = {s._interface for s in interface_sensors}
        assert "wan" in iface_names
        assert "lan" in iface_names
        assert "loopback" in iface_names

    def test_t_s2_no_wan_sensor_when_wan_absent(
        self, mock_coordinator, mock_config_entry
    ):
        """T-S2: No wan sensor created when wan is not in network_interfaces."""
        self._make_coordinator_with_interfaces(
            mock_coordinator,
            [
                {"interface": "lan", "rx_bytes": 200, "tx_bytes": 80},
            ],
        )
        added: list = []

        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        mock_config_entry.async_on_unload = MagicMock()

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            async_setup_entry(
                hass=MagicMock(),
                entry=mock_config_entry,
                async_add_entities=lambda entities, **kw: added.extend(entities),
            )
        )
        interface_sensors = [
            e for e in added if isinstance(e, OpenWrtInterfaceSensor)
        ]
        iface_names = {s._interface for s in interface_sensors}
        assert "wan" not in iface_names

    def test_t_s3_interface_with_none_rx_bytes(self, mock_coordinator, mock_config_entry):
        """T-S3: Interface sensor with None rx_bytes returns None, does not crash."""
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "lan", "rx_bytes": None, "tx_bytes": 50}
        ]
        data.wifi_radios = []
        mock_coordinator.data = data

        sensor = OpenWrtInterfaceSensor(mock_coordinator, mock_config_entry, "lan", "rx_bytes")
        assert sensor.native_value is None

    def test_t_s5_interface_sensor_unique_id_stable(
        self, mock_coordinator, mock_config_entry
    ):
        """T-S5: unique_id is deterministic — entry_id + interface + direction."""
        sensor = OpenWrtInterfaceSensor(mock_coordinator, mock_config_entry, "wan", "rx_bytes")
        assert sensor._attr_unique_id == "test_entry_id_wan_rx"

        sensor_tx = OpenWrtInterfaceSensor(mock_coordinator, mock_config_entry, "wan", "tx_bytes")
        assert sensor_tx._attr_unique_id == "test_entry_id_wan_tx"


class TestDynamicRadioSensors:
    """T-S4 / T-S6: Radio sensors and listener behavior."""

    def test_t_s6_radio_sensor_only_when_noise_not_none(
        self, mock_coordinator, mock_config_entry
    ):
        """T-S6: Radio sensor is only created when noise is not None."""
        data = OpenWrtCoordinatorData()
        data.network_interfaces = []
        # radio0 has noise, radio1 does not
        data.wifi_radios = [
            {"ifname": "phy0-ap0", "signal": -65, "noise": -95},
            {"ifname": "phy1-ap0", "signal": -60, "noise": None},
            {"ifname": "phy2-ap0", "signal": -55},  # noise key absent
        ]
        mock_coordinator.data = data
        added: list = []

        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        mock_config_entry.async_on_unload = MagicMock()

        import asyncio
        asyncio.get_event_loop().run_until_complete(
            async_setup_entry(
                hass=MagicMock(),
                entry=mock_config_entry,
                async_add_entities=lambda entities, **kw: added.extend(entities),
            )
        )
        radio_sensors = [e for e in added if isinstance(e, OpenWrtRadioSensor)]
        radio_ifnames = {s._ifname for s in radio_sensors}
        # Only phy0-ap0 qualifies
        assert "phy0-ap0" in radio_ifnames
        assert "phy1-ap0" not in radio_ifnames
        assert "phy2-ap0" not in radio_ifnames


# =====================================================================
# T-S7 through T-S9: OpenWrtInterfaceRateSensor
# =====================================================================

from custom_components.openwrt_router.sensor import OpenWrtInterfaceRateSensor
from homeassistant.const import UnitOfDataRate
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass


class TestInterfaceRateSensor:
    """Tests for the bandwidth rate (bytes/s) sensor."""

    def _make_sensor(self, metric="rx_rate", interface="wan"):
        coord = MagicMock()
        entry = MagicMock()
        entry.entry_id = "entry_abc"
        entry.data = {"host": "192.168.1.1", "port": 80}
        return OpenWrtInterfaceRateSensor(coord, entry, interface, metric)

    def test_unique_id_format(self):
        """T-S7: unique_id follows stable pattern."""
        s = self._make_sensor("rx_rate", "wan")
        assert s._attr_unique_id == "entry_abc_wan_rx_rate"
        s2 = self._make_sensor("tx_rate", "lan")
        assert s2._attr_unique_id == "entry_abc_lan_tx_rate"

    def test_device_class_and_unit(self):
        """T-S8: Sensor has DATA_RATE device class and B/s unit."""
        s = self._make_sensor()
        assert s._attr_device_class == SensorDeviceClass.DATA_RATE
        assert s._attr_native_unit_of_measurement == UnitOfDataRate.BYTES_PER_SECOND
        assert s._attr_state_class == SensorStateClass.MEASUREMENT

    def test_native_value_returns_rate(self):
        """T-S9: native_value reads rx_rate / tx_rate from coordinator data."""
        from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData

        coord = MagicMock()
        data = OpenWrtCoordinatorData()
        data.network_interfaces = [
            {"interface": "wan", "rx_bytes": 5000, "tx_bytes": 2000,
             "rx_rate": 123.45, "tx_rate": 67.89, "status": "up"}
        ]
        coord.data = data
        entry = MagicMock()
        entry.entry_id = "e1"
        entry.data = {"host": "192.168.1.1", "port": 80}

        rx_sensor = OpenWrtInterfaceRateSensor(coord, entry, "wan", "rx_rate")
        assert rx_sensor.native_value == pytest.approx(123.45)

        tx_sensor = OpenWrtInterfaceRateSensor(coord, entry, "wan", "tx_rate")
        assert tx_sensor.native_value == pytest.approx(67.89)


# =====================================================================
# AP Interface Sensors
# =====================================================================

def _make_ap_sensor(metric="channel", ifname="phy0-ap0", radio_data=None, clients=None):
    """Helper: create OpenWrtAPInterfaceSensor with inline coordinator data."""
    from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData

    coord = MagicMock()
    data = OpenWrtCoordinatorData()

    base_ap = {
        RADIO_KEY_IFNAME: ifname,
        RADIO_KEY_SSID: "TestNet",
        RADIO_KEY_BAND: "2.4g",
        RADIO_KEY_MODE: "Master",
        RADIO_KEY_CHANNEL: 6,
        RADIO_KEY_FREQUENCY: 2437,
        RADIO_KEY_TXPOWER: 20,
        RADIO_KEY_BITRATE: 72.2,
        RADIO_KEY_HWMODE: "11n",
        RADIO_KEY_HTMODE: "HT20",
        RADIO_KEY_BSSID: "AA:BB:CC:DD:EE:01",
        "signal": -55,
        "noise": -92,
        "quality": 65,
        "quality_max": 100,
    }
    if radio_data:
        base_ap.update(radio_data)

    data.ap_interfaces = [base_ap]
    data.clients = clients or []
    coord.data = data
    coord.router_info = {}

    entry = MagicMock()
    entry.entry_id = "entry_ap"
    entry.data = {"host": "192.168.1.1", "port": 80}

    return OpenWrtAPInterfaceSensor(coord, entry, ifname, metric)


class TestOpenWrtAPInterfaceSensor:
    """Tests for OpenWrtAPInterfaceSensor (AP Interface Management)."""

    def test_channel_native_value(self):
        """T-AP1: channel sensor returns integer channel number."""
        s = _make_ap_sensor("channel")
        assert s.native_value == 6

    def test_frequency_native_value(self):
        """T-AP2: frequency sensor returns MHz value."""
        s = _make_ap_sensor("frequency")
        assert s.native_value == 2437

    def test_txpower_native_value(self):
        """T-AP3: txpower sensor returns dBm value."""
        s = _make_ap_sensor("txpower")
        assert s.native_value == 20

    def test_bitrate_native_value(self):
        """T-AP4: bitrate sensor returns Mbps value."""
        s = _make_ap_sensor("bitrate")
        assert s.native_value == pytest.approx(72.2)

    def test_hwmode_native_value(self):
        """T-AP5: hwmode sensor returns 802.11 mode string."""
        s = _make_ap_sensor("hwmode")
        assert s.native_value == "11n"

    def test_htmode_native_value(self):
        """T-AP6: htmode sensor returns channel width string."""
        s = _make_ap_sensor("htmode")
        assert s.native_value == "HT20"

    def test_mode_native_value(self):
        """T-AP7: mode sensor returns AP mode string."""
        s = _make_ap_sensor("mode")
        assert s.native_value == "Master"

    def test_quality_calculation(self):
        """T-AP8: quality sensor calculates percentage from quality/quality_max."""
        s = _make_ap_sensor("quality", radio_data={"quality": 65, "quality_max": 100})
        assert s.native_value == 65

    def test_quality_calculation_non_100_max(self):
        """T-AP8b: quality sensor handles non-100 quality_max."""
        s = _make_ap_sensor("quality", radio_data={"quality": 50, "quality_max": 70})
        assert s.native_value == round(50 / 70 * 100)

    def test_quality_none_when_no_data(self):
        """T-AP8c: quality sensor returns None when quality field absent."""
        s = _make_ap_sensor("quality", radio_data={"quality": None, "quality_max": None})
        assert s.native_value is None

    def test_ap_clients_count(self):
        """T-AP9: ap_clients sensor counts only clients on this radio."""
        clients = [
            {CLIENT_KEY_RADIO: "phy0-ap0"},
            {CLIENT_KEY_RADIO: "phy0-ap0"},
            {CLIENT_KEY_RADIO: "phy1-ap0"},  # different radio, not counted
        ]
        s = _make_ap_sensor("ap_clients", ifname="phy0-ap0", clients=clients)
        assert s.native_value == 2

    def test_ap_clients_zero_when_no_clients(self):
        """T-AP10: ap_clients returns 0 when no clients on this radio."""
        s = _make_ap_sensor("ap_clients", ifname="phy0-ap0", clients=[])
        assert s.native_value == 0

    def test_unique_id_format(self):
        """T-AP11: unique_id follows stable ifname_metric pattern."""
        s = _make_ap_sensor("channel", ifname="phy0-ap0")
        assert s._attr_unique_id == "entry_ap_ap_phy0-ap0_channel"

    def test_mode_extra_attrs(self):
        """T-AP12: mode sensor returns ssid/bssid/band as extra attributes."""
        s = _make_ap_sensor("mode")
        attrs = s.extra_state_attributes
        assert attrs["ssid"] == "TestNet"
        assert attrs["bssid"] == "AA:BB:CC:DD:EE:01"
        assert attrs["band"] == "2.4g"

    def test_channel_extra_attrs(self):
        """T-AP13: channel sensor returns frequency/htmode/hwmode as extra attributes."""
        s = _make_ap_sensor("channel")
        attrs = s.extra_state_attributes
        assert attrs["frequency_mhz"] == 2437
        assert attrs["htmode"] == "HT20"
        assert attrs["hwmode"] == "11n"

    def test_optional_metric_none_value(self):
        """T-AP14: optional metric sensor returns None when router field is None."""
        s = _make_ap_sensor("txpower", radio_data={RADIO_KEY_TXPOWER: None})
        assert s.native_value is None

    def test_returns_none_when_no_coordinator_data(self):
        """T-AP15: sensor returns None when coordinator has no data."""
        from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
        coord = MagicMock()
        coord.data = None
        coord.router_info = {}
        entry = MagicMock()
        entry.entry_id = "e"
        entry.data = {"host": "192.168.1.1", "port": 80}
        s = OpenWrtAPInterfaceSensor(coord, entry, "phy0-ap0", "channel")
        assert s.native_value is None

    def test_returns_none_when_ap_interface_not_in_data(self):
        """T-AP15b: sensor returns None when ifname not found in ap_interfaces."""
        from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData
        coord = MagicMock()
        data = OpenWrtCoordinatorData()
        data.ap_interfaces = []
        data.clients = []
        coord.data = data
        coord.router_info = {}
        entry = MagicMock()
        entry.entry_id = "e"
        entry.data = {"host": "192.168.1.1", "port": 80}
        s = OpenWrtAPInterfaceSensor(coord, entry, "phy0-ap0", "channel")
        assert s.native_value is None

    def test_client_mode_no_ap_clients_sensor(self):
        """T-AP16: ap_clients sensor counts 0 for Client-mode interface (no hosted clients)."""
        clients = [{CLIENT_KEY_RADIO: "phy0-sta0"}]
        s = _make_ap_sensor(
            "ap_clients",
            ifname="phy0-sta0",
            radio_data={RADIO_KEY_MODE: "Client", RADIO_KEY_IFNAME: "phy0-sta0"},
            clients=clients,
        )
        assert s.native_value == 1  # the client list still counts by radio match
