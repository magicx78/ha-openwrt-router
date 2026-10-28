"""WAN detection by name and upstream protocol, no first-up fallback (1.38.9, A4/E5).

Before: ``get_wan_status()`` took the first interface named like a WAN
(``wan``, ``wan6``, ``pppoe-wan``, ``wwan*``) and otherwise fell back to the
first interface that was up. On a dumb AP that was ``lan`` or ``guest``, so
the AP reported a connected WAN, showed the guest traffic as WAN counters and
polled DDNS on every cycle (seen on hardware: ``interface: guest``,
``proto: none``, ``connected: true``). A gateway whose uplink is called
``lte``, ``modem`` or ``umts`` counted as a router without WAN.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtMethodNotFoundError,
    is_wan_interface,
)
from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
)
from custom_components.openwrt_router.sensor import router_has_wan
from custom_components.openwrt_router.topology_mesh import _detect_router_role


def _iface(name: str, proto: str, *, up: bool = True, l3: str | None = None, ipv4: str | None = None) -> dict:
    entry: dict = {"interface": name, "proto": proto, "up": up, "uptime": 100 if up else 0}
    if l3:
        entry["l3_device"] = l3
        entry["device"] = l3
    if ipv4:
        entry["ipv4-address"] = [{"address": ipv4, "mask": 24}]
    return entry


# ``network.interface dump`` of a dumb AP: nothing but bridges and loopback.
DUMB_AP_DUMP = {
    "interface": [
        _iface("loopback", "static", l3="lo", ipv4="127.0.0.1"),
        _iface("lan", "static", l3="br-lan.10", ipv4="192.0.2.4"),
        _iface("guest", "none", l3="br-lan.40"),
        _iface("iot", "none", l3="br-lan.20"),
    ]
}

# A gateway on a cellular stick: the uplink is called "lte" and runs qmi.
LTE_GATEWAY_DUMP = {
    "interface": [
        _iface("loopback", "static", l3="lo", ipv4="127.0.0.1"),
        _iface("lan", "static", l3="br-lan", ipv4="192.0.2.1"),
        _iface("lte", "qmi", l3="wwan0", ipv4="100.64.0.7"),
    ]
}


def _mock_calls(mock_api, dump: dict) -> list[tuple[str, str, dict]]:
    seen: list[tuple[str, str, dict]] = []

    async def _call(obj, method, params=None, **kwargs):
        seen.append((obj, method, dict(params or {})))
        if (obj, method) == ("network.interface", "dump"):
            return dump
        if (obj, method) == ("network.device", "status"):
            return {"up": True, "statistics": {"rx_bytes": 1000, "tx_bytes": 500}}
        raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

    mock_api._call = AsyncMock(side_effect=_call)
    mock_api._asyncssh_run = AsyncMock()
    mock_api._run_ssh = AsyncMock()
    return seen


class TestIsWanInterface:
    @pytest.mark.parametrize(
        "name",
        ["wan", "wan6", "pppoe-wan", "wwan", "wwan0", "wan_lte", "WAN", "lte", "lte1", "modem", "umts", "3g", "4g", "5g"],
    )
    def test_wan_names(self, name):
        assert is_wan_interface(name) is True
        assert is_wan_interface(name, "dhcp") is True

    @pytest.mark.parametrize("proto", ["pppoe", "pppoa", "qmi", "mbim", "ncm", "modemmanager", "3g", "wwan"])
    def test_upstream_protocols_on_any_name(self, proto):
        assert is_wan_interface("internet", proto) is True

    @pytest.mark.parametrize(
        ("name", "proto"),
        [
            ("lan", "static"),
            ("guest", "none"),
            ("iot", "static"),
            ("loopback", "static"),
            ("wg0", "wireguard"),
            ("vpn", "openvpn"),
            ("lan6", "dhcpv6"),
            ("docker", "static"),
            ("4ghz", "none"),
            ("", "pppoe"),
            ("", ""),
        ],
    )
    def test_non_wan(self, name, proto):
        assert is_wan_interface(name, proto) is False


class TestGetWanStatusDetection:
    @pytest.mark.asyncio
    async def test_dumb_ap_has_no_wan(self, mock_api):
        """The regression: lan/guest were taken as WAN because they were up."""
        seen = _mock_calls(mock_api, DUMB_AP_DUMP)
        res = await mock_api.get_wan_status()
        assert res["wan_found"] is False
        assert res["connected"] is False
        assert res["interface"] == ""
        assert res["ipv4"] == ""
        assert res["rx_bytes"] is None and res["tx_bytes"] is None
        # no counters are read for a non-WAN interface
        assert not [s for s in seen if s[0] in ("network.device", "file")], seen
        mock_api._asyncssh_run.assert_not_awaited()
        mock_api._run_ssh.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_lte_gateway_is_found_by_name(self, mock_api):
        seen = _mock_calls(mock_api, LTE_GATEWAY_DUMP)
        res = await mock_api.get_wan_status()
        assert res["wan_found"] is True
        assert res["connected"] is True
        assert res["interface"] == "lte"
        assert res["proto"] == "qmi"
        assert res["ipv4"] == "100.64.0.7"
        assert (res["rx_bytes"], res["tx_bytes"]) == (1000, 500)
        assert ("network.device", "status", {"name": "wwan0"}) in seen

    @pytest.mark.asyncio
    async def test_found_by_upstream_protocol_only(self, mock_api):
        dump = {
            "interface": [
                _iface("lan", "static", l3="br-lan", ipv4="192.0.2.1"),
                _iface("internet", "pppoe", l3="pppoe-internet", ipv4="203.0.113.5"),
            ]
        }
        _mock_calls(mock_api, dump)
        res = await mock_api.get_wan_status()
        assert res["wan_found"] is True
        assert res["interface"] == "internet"
        assert res["ipv4"] == "203.0.113.5"

    @pytest.mark.asyncio
    async def test_first_candidate_in_dump_order_wins(self, mock_api):
        dump = {
            "interface": [
                _iface("lan", "static", l3="br-lan"),
                _iface("wan6", "dhcpv6", l3="wan"),
                _iface("wan", "dhcp", l3="wan", ipv4="198.51.100.2"),
            ]
        }
        _mock_calls(mock_api, dump)
        assert (await mock_api.get_wan_status())["interface"] == "wan6"

    @pytest.mark.asyncio
    async def test_wan_down_is_found_but_disconnected(self, mock_api):
        dump = {"interface": [_iface("lan", "static", l3="br-lan"), _iface("wan", "dhcp", up=False)]}
        seen = _mock_calls(mock_api, dump)
        res = await mock_api.get_wan_status()
        assert res["wan_found"] is True
        assert res["connected"] is False
        assert res["interface"] == "wan"
        assert res["rx_bytes"] is None
        assert not [s for s in seen if s[0] == "network.device"]

    @pytest.mark.asyncio
    async def test_empty_dump_is_unknown_not_no_wan(self, mock_api):
        """netifd answered nothing: do not flag the router as WAN-less."""
        _mock_calls(mock_api, {"interface": []})
        res = await mock_api.get_wan_status()
        assert res["connected"] is False
        assert "wan_found" not in res

    @pytest.mark.asyncio
    async def test_ssh_fallback_result_leaves_wan_presence_unknown(self, mock_api):
        mock_api._asyncssh_run = AsyncMock(
            return_value=(0, '{"wan_connected": true, "rx_bytes": 1, "tx_bytes": 2}', b"")
        )
        res = await mock_api._get_wan_status_ssh()
        assert res["connected"] is True
        assert "wan_found" not in res


class TestRouterHasWanFlag:
    def _has(self, status: dict) -> bool:
        data = OpenWrtCoordinatorData()
        data.wan_status = status
        return router_has_wan(data)

    def test_flag_false_means_no_wan(self):
        assert self._has({"wan_found": False, "connected": False, "interface": ""}) is False

    def test_flag_true_wins_even_when_down(self):
        assert self._has({"wan_found": True, "connected": False, "interface": "lte"}) is True

    @pytest.mark.parametrize("name", ["lte", "modem", "umts", "3g", "wwan0"])
    def test_status_without_flag_by_extended_name(self, name):
        assert self._has({"connected": True, "interface": name}) is True

    def test_status_without_flag_by_protocol(self):
        assert self._has({"connected": True, "interface": "internet", "proto": "pppoe"}) is True

    def test_status_without_flag_non_wan_name_stays_no_wan(self):
        assert self._has({"connected": True, "interface": "guest", "proto": "none"}) is False


class TestRouterRoleWithUpstreamProtocols:
    def _data(self, status: dict) -> OpenWrtCoordinatorData:
        data = OpenWrtCoordinatorData()
        data.wan_status = status
        return data

    @pytest.mark.parametrize("proto", ["qmi", "mbim", "ncm", "modemmanager", "3g", "wwan", "pppoa"])
    def test_cellular_gateway_is_a_gateway(self, proto):
        status = {"connected": True, "interface": "lte", "proto": proto, "ipv4": "100.64.0.7", "wan_found": True}
        assert _detect_router_role(self._data(status), "192.0.2.1") == "gateway"

    def test_router_without_wan_is_an_ap(self):
        status = {"connected": False, "interface": "", "proto": "", "wan_found": False}
        assert _detect_router_role(self._data(status), "192.0.2.4") == "ap"


class TestCoordinatorSkipsDdnsWithoutWan:
    """Guard: the DDNS poll keys off wan_connected, which a WAN-less router no longer sets."""

    def _api(self, wan_status: dict) -> AsyncMock:
        api = AsyncMock()
        api.get_router_info = AsyncMock(return_value={"hostname": "ap", "model": "x"})
        api.get_wan_status = AsyncMock(return_value=wan_status)
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(return_value={"uptime": 1, "cpu_load": 1.0, "memory": {}})
        api.get_disk_space = AsyncMock(return_value={})
        api.get_tmpfs_stats = AsyncMock(return_value={})
        api.get_network_interfaces = AsyncMock(return_value=[])
        api.get_active_connections = AsyncMock(return_value=0)
        api.get_ddns_status = AsyncMock(return_value=[])
        api.detect_features = AsyncMock(return_value={})
        api.reset_ssh_fallback_flag = MagicMock()
        api.uses_ssh_fallback = False
        return api

    def _coordinator(self, api) -> OpenWrtCoordinator:
        hass = MagicMock()
        hass.async_create_task = MagicMock(side_effect=lambda coro: coro)
        with patch("homeassistant.helpers.frame.report_usage"):
            return OpenWrtCoordinator(hass=hass, api=api, entry_title="test")

    async def _two_polls(self, coordinator: OpenWrtCoordinator) -> OpenWrtCoordinatorData:
        """Ping and DDNS are skipped on the very first poll (HA bootstrap)."""
        with patch("asyncio.open_connection", side_effect=OSError("no net")):
            coordinator.data = await coordinator._async_update_data()
            return await coordinator._async_update_data()

    @pytest.mark.asyncio
    async def test_no_ddns_poll_on_a_router_without_wan(self):
        api = self._api({"connected": False, "interface": "", "proto": "", "wan_found": False})
        data = await self._two_polls(self._coordinator(api))
        assert data.wan_connected is False
        api.get_ddns_status.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ddns_polled_on_a_gateway(self):
        api = self._api({"connected": True, "interface": "wan", "proto": "dhcp", "wan_found": True})
        data = await self._two_polls(self._coordinator(api))
        assert data.wan_connected is True
        api.get_ddns_status.assert_awaited()
