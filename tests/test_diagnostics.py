"""Tests for the OpenWrt Diagnostics module (diagnostics.py)."""
from __future__ import annotations

import json

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.const import (
    DIAGNOSTICS_REDACTED,
    DOMAIN,
)
from custom_components.openwrt_router.diagnostics import (
    _is_sensitive_key,
    _redact,
    async_get_config_entry_diagnostics,
)


# =====================================================================
# _is_sensitive_key
# =====================================================================

class TestIsSensitiveKey:
    def test_password(self):
        assert _is_sensitive_key("password") is True

    def test_token(self):
        assert _is_sensitive_key("token") is True

    def test_ubus_rpc_session(self):
        assert _is_sensitive_key("ubus_rpc_session") is True

    def test_secret(self):
        assert _is_sensitive_key("secret") is True

    def test_auth(self):
        assert _is_sensitive_key("auth") is True

    def test_key(self):
        assert _is_sensitive_key("key") is True

    def test_non_sensitive(self):
        assert _is_sensitive_key("hostname") is False

    def test_case_insensitive(self):
        assert _is_sensitive_key("Password") is True
        assert _is_sensitive_key("TOKEN") is True

    def test_partial_match(self):
        assert _is_sensitive_key("auth_token") is True
        assert _is_sensitive_key("api_key_value") is True


# =====================================================================
# _redact
# =====================================================================

class TestRedact:
    def test_password_redacted(self):
        result = _redact({"password": "secret123"})
        assert result["password"] == DIAGNOSTICS_REDACTED

    def test_token_redacted(self):
        result = _redact({"ubus_rpc_session": "deadbeef"})
        assert result["ubus_rpc_session"] == DIAGNOSTICS_REDACTED

    def test_non_sensitive_preserved(self):
        result = _redact({"interface": "wan", "model": "test"})
        assert result["interface"] == "wan"
        assert result["model"] == "test"

    def test_identifiers_redacted_by_exact_name(self):
        result = _redact({"hostname": "openwrt", "mac": "02:00:00:00:00:01"})
        assert result["hostname"] == DIAGNOSTICS_REDACTED
        assert result["mac"] == DIAGNOSTICS_REDACTED

    def test_identifier_names_not_matched_as_substring(self):
        result = _redact({"logical_name": "lan", "ip_count": 3})
        assert result == {"logical_name": "lan", "ip_count": 3}

    def test_nested_dicts(self):
        result = _redact({"outer": {"password": "hidden", "name": "ok"}})
        assert result["outer"]["password"] == DIAGNOSTICS_REDACTED
        assert result["outer"]["name"] == "ok"

    def test_list_of_dicts(self):
        result = _redact([{"token": "abc"}, {"name": "ok"}])
        assert result[0]["token"] == DIAGNOSTICS_REDACTED
        assert result[1]["name"] == "ok"

    def test_scalar_passthrough(self):
        assert _redact(42) == 42
        assert _redact("hello") == "hello"
        assert _redact(None) is None

    def test_empty_dict(self):
        assert _redact({}) == {}

    def test_empty_list(self):
        assert _redact([]) == []

    def test_deep_nesting(self):
        data = {"level1": {"level2": {"secret": "hidden", "val": 1}}}
        result = _redact(data)
        assert result["level1"]["level2"]["secret"] == DIAGNOSTICS_REDACTED
        assert result["level1"]["level2"]["val"] == 1


# =====================================================================
# async_get_config_entry_diagnostics
# =====================================================================

class TestDiagnosticsExport:
    @pytest.mark.asyncio
    async def test_structure(self, mock_config_entry_with_runtime):
        hass = MagicMock()
        entry = mock_config_entry_with_runtime
        result = await async_get_config_entry_diagnostics(hass, entry)

        assert result["integration"] == DOMAIN
        assert result["entry_id"] == "test_entry_id"
        assert result["entry_title"] == DIAGNOSTICS_REDACTED
        assert "config" in result
        assert "coordinator" in result
        assert "features" in result
        assert "router_info" in result

    @pytest.mark.asyncio
    async def test_password_redacted_in_config(self, mock_config_entry_with_runtime):
        hass = MagicMock()
        entry = mock_config_entry_with_runtime
        result = await async_get_config_entry_diagnostics(hass, entry)

        assert result["config"]["password"] == DIAGNOSTICS_REDACTED

    @pytest.mark.asyncio
    async def test_dhcp_leases_redacted(self, mock_config_entry_with_runtime):
        hass = MagicMock()
        entry = mock_config_entry_with_runtime
        result = await async_get_config_entry_diagnostics(hass, entry)

        coord_data = result["coordinator"]["data"]
        assert "leases redacted" in coord_data["dhcp_leases"]

    @pytest.mark.asyncio
    async def test_coordinator_metadata(self, mock_config_entry_with_runtime):
        hass = MagicMock()
        entry = mock_config_entry_with_runtime
        result = await async_get_config_entry_diagnostics(hass, entry)

        coord = result["coordinator"]
        assert coord["last_update_success"] is True
        assert coord["update_interval_seconds"] == 30.0

    @pytest.mark.asyncio
    async def test_no_coordinator_data(self, mock_config_entry_with_runtime):
        hass = MagicMock()
        entry = mock_config_entry_with_runtime
        entry.runtime_data.coordinator.data = None
        result = await async_get_config_entry_diagnostics(hass, entry)

        assert result["coordinator"]["data"] == {}


# =====================================================================
# Personal data (E4): HA convention via async_redact_data
# =====================================================================

# Every value here identifies a person, a device or the network; none of them
# may appear anywhere in the exported diagnostics.
_PII = {
    "host": "192.0.2.1",
    "username": "diag-user",
    "router_hostname": "home-gateway-7",
    "router_mac": "02:11:22:33:44:55",
    "wan_ip": "198.51.100.77",
    "client_mac": "02:aa:bb:cc:dd:01",
    "client_ip": "192.0.2.101",
    "client_hostname": "alice-phone",
    "client_url": "http://192.0.2.101",
    "ssid": "Family-Net-xyz",
    "bssid": "02:BB:CC:DD:EE:10",
    "ap_mac": "02:BB:CC:DD:EE:11",
    "sta_bssid": "02:BB:CC:DD:EE:12",
    "iface_ip": "192.0.2.254",
    "ddns_domain": "family.example.org",
    "ddns_ip": "198.51.100.78",
    "sticky_mac": "02:aa:bb:cc:dd:02",
    "sticky_hostname": "bob-laptop",
    "weak_mac": "02:aa:bb:cc:dd:03",
    "weak_hostname": "carol-tablet",
    "unstable_mac": "02:aa:bb:cc:dd:04",
    "unstable_hostname": "dave-tv",
    "sta_mac": "02:BB:CC:DD:EE:13",
    "sta_ssid": "Upstream-Net-abc",
    "lldp_name": "switch-office-3",
    "lldp_port_mac": "02:cc:dd:ee:ff:01",
}


@pytest.fixture
def pii_entry(mock_config_entry_with_runtime):
    """Config entry whose coordinator data is full of personal data."""
    entry = mock_config_entry_with_runtime
    # config_flow names the entry after the router hostname (or host).
    entry.title = _PII["router_hostname"]
    entry.data = {
        "host": _PII["host"],
        "port": 443,
        "username": _PII["username"],
        "password": "pw",
        "protocol": "https",
    }
    coordinator = entry.runtime_data.coordinator
    data = coordinator.data
    data.router_info = {
        "model": "Test Model",
        "hostname": _PII["router_hostname"],
        "mac": _PII["router_mac"],
    }
    coordinator.router_info = data.router_info
    data.wan_status = {"connected": True, "ipv4": _PII["wan_ip"], "proto": "dhcp"}
    data.wifi_radios = [{"name": "radio0", "ssid": _PII["ssid"], "bssid": _PII["bssid"]}]
    data.clients = [
        {
            "mac": _PII["client_mac"],
            "ip": _PII["client_ip"],
            "hostname": _PII["client_hostname"],
            "ssid": _PII["ssid"],
            "signal": -60,
            "web_url": _PII["client_url"],
            "connection_type": "wifi",
        },
        {"mac": "02:aa:bb:cc:dd:09", "signal": -40, "connection_type": "wifi"},
        {"mac": "02:aa:bb:cc:dd:0a", "signal": None, "connection_type": "wired"},
        {"mac": "02:aa:bb:cc:dd:0b", "signal": True, "connection_type": "wifi"},
    ]
    data.ap_interfaces = [{"ifname": "phy0-ap0", "ssid": _PII["ssid"], "mac": _PII["ap_mac"]}]
    data.sta_interfaces = [
        {
            "ifname": "phy1-sta0",
            "ssid": _PII["sta_ssid"],
            "bssid": _PII["sta_bssid"],
            "mac": _PII["sta_mac"],
        }
    ]
    data.dfs = {"events_24h": 1, "last_event": {"router": entry.title, "channel": 52}}
    data.lldp_neighbors = [
        {
            "local_interface": "lan1",
            "chassis_name": _PII["lldp_name"],
            "chassis_id": "02:cc:dd:ee:ff:00",
            "port_id": _PII["lldp_port_mac"],
            "port_descr": "eth0",
        },
        {"local_interface": "lan2", "port_id": "gi1/0/7"},
    ]
    data.network_interfaces = [{"logical_name": "lan", "ipv4_addr": _PII["iface_ip"]}]
    data.ddns_status = [
        {"service_name": "x", "domain": _PII["ddns_domain"], "ip": _PII["ddns_ip"]}
    ]
    data.client_stability = {
        "usteer": False,
        "sticky": [{"mac": _PII["sticky_mac"], "hostname": _PII["sticky_hostname"]}],
        "weak": [{"mac": _PII["weak_mac"], "hostname": _PII["weak_hostname"]}],
        "unstable": [
            {"mac": _PII["unstable_mac"], "hostname": _PII["unstable_hostname"]}
        ],
        "unstable_count": 1,
    }
    data.features = {"ssids": [_PII["ssid"]], "has_5ghz": True}
    coordinator.features = data.features
    return entry


class TestPersonalDataRedaction:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("name", sorted(_PII))
    async def test_value_absent_from_export(self, pii_entry, name):
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        dump = json.dumps(result, default=str)
        assert _PII[name] not in dump
        assert _PII[name].lower() not in dump.lower()

    @pytest.mark.asyncio
    async def test_config_keys_redacted_by_name(self, pii_entry):
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        config = result["config"]
        assert config["host"] == DIAGNOSTICS_REDACTED
        assert config["username"] == DIAGNOSTICS_REDACTED
        assert config["password"] == DIAGNOSTICS_REDACTED
        # Non-identifying settings stay readable for troubleshooting.
        assert config["port"] == 443
        assert config["protocol"] == "https"

    @pytest.mark.asyncio
    async def test_clients_become_summary(self, pii_entry):
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        clients = result["coordinator"]["data"]["clients"]
        assert clients == {
            "count": 4,
            "by_connection_type": {"wifi": 3, "wired": 1},
            "signal_min": -60,
            "signal_max": -40,
            "signal_avg": -50.0,
        }

    @pytest.mark.asyncio
    async def test_stability_lists_become_counts(self, pii_entry):
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        stability = result["coordinator"]["data"]["client_stability"]
        assert stability["sticky"] == "<1 clients redacted>"
        assert stability["weak"] == "<1 clients redacted>"
        assert stability["unstable"] == "<1 clients redacted>"
        assert stability["unstable_count"] == 1
        assert stability["usteer"] is False

    @pytest.mark.asyncio
    async def test_troubleshooting_facts_kept(self, pii_entry):
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        data = result["coordinator"]["data"]
        assert data["wan_status"]["connected"] is True
        assert data["wan_status"]["proto"] == "dhcp"
        assert data["network_interfaces"][0]["logical_name"] == "lan"
        assert result["router_info"]["model"] == "Test Model"
        assert result["features"]["has_5ghz"] is True
        assert data["dfs"]["last_event"]["channel"] == 52
        lldp = data["lldp_neighbors"]
        assert lldp[0]["local_interface"] == "lan1"
        assert lldp[0]["port_descr"] == "eth0"
        # A port name that is not a MAC stays readable.
        assert lldp[1]["port_id"] == "gi1/0/7"

    @pytest.mark.asyncio
    async def test_empty_clients_summary(self, pii_entry):
        pii_entry.runtime_data.coordinator.data.clients = []
        result = await async_get_config_entry_diagnostics(MagicMock(), pii_entry)
        assert result["coordinator"]["data"]["clients"] == {
            "count": 0,
            "by_connection_type": {},
            "signal_min": None,
            "signal_max": None,
            "signal_avg": None,
        }
