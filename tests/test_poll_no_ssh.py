"""A healthy ubus poll must not open a single SSH connection (v1.38.3, AK1).

Background (plan 2026-10-28, finding N2): with ubus fully working and the
rpcd ACL in place, v1.38.2 still logged in over SSH five to six times per
poll and router — WAN byte counters (file/read result misparsed), disk and
tmpfs (SSH-only path running a GNU-only ``df -B`` that BusyBox rejects, so
the sensors showed 0.0) and the bridge FDB (``file/read`` without ``base64``
returns nothing for the binary ``brforward`` file, then SSH twice). The
dropbear lines then crowded the router log that the log sensor reads.

This test drives the real :class:`OpenWrtAPI` against a path-aware ubus
mock through two full coordinator polls and asserts that
``asyncssh.connect`` is never awaited, while the data the former SSH paths
produced is still present. LLDP is the one legitimate SSH reader (every
600 s, only with lldpd); its cache is primed as "unavailable" here.
"""

from __future__ import annotations

import base64
import struct
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAPI,
    OpenWrtConnectionError,
)
from custom_components.openwrt_router.coordinator import OpenWrtCoordinator

from conftest import (
    MOCK_BOARD_INFO,
    MOCK_DHCP_LEASES_RAW,
    MOCK_IWINFO_INFO,
    MOCK_SESSION_TOKEN,
    MOCK_SYSTEM_INFO,
    MOCK_UCI_WIRELESS,
    MOCK_WIRELESS_STATUS,
)

UBUS_OK = 0
UBUS_METHOD_NOT_FOUND = 3
UBUS_NOT_FOUND = 4


def _fdb_entry(mac: bytes, port_no: int) -> bytes:
    return struct.pack("<6sBBIBBH", mac, port_no, 0, 1234, 0, 0, 0)


_BRFORWARD_B64 = base64.b64encode(
    _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x01", 1)
).decode()

_PROC_NET_ARP = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.101    0x1         0x2         b8:27:eb:aa:bb:01     *        br-lan\n"
)

_SYSTEM_INFO = {
    **MOCK_SYSTEM_INFO,
    "root": {"total": 3328, "free": 2996, "used": 332, "avail": 2996},
    "tmp": {"total": 119784, "free": 119120, "used": 664, "avail": 119120},
}

_NETWORK_DUMP = {
    "interface": [
        {
            "interface": "wan",
            "up": True,
            "uptime": 3600,
            "proto": "dhcp",
            "l3_device": "wan",
            "device": "wan",
            "ipv4-address": [{"address": "203.0.113.42", "mask": 24}],
        },
        {
            "interface": "lan",
            "up": True,
            "uptime": 86000,
            "proto": "static",
            "l3_device": "br-lan",
            "device": "br-lan",
            "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
        },
    ]
}

_DEVICES = {
    "wan": {
        "up": True,
        "devtype": "dsa",
        "speed": "1000F",
        "statistics": {"rx_bytes": 1000, "tx_bytes": 500, "rx_packets": 1, "tx_packets": 1},
    },
    "lan1": {
        "up": True,
        "devtype": "dsa",
        "speed": "1000F",
        "statistics": {"rx_bytes": 10, "tx_bytes": 20, "rx_packets": 1, "tx_packets": 1},
    },
    "br-lan": {"up": True, "devtype": "bridge", "statistics": {}},
}


def _file_read(params: dict[str, Any]) -> Any:
    path = params.get("path", "")
    if path == "/proc/cpuinfo":
        return {"data": "processor\t: 0\nprocessor\t: 1\n"}
    if path == "/proc/net/arp":
        return {"data": _PROC_NET_ARP}
    if path == "/proc/sys/net/netfilter/nf_conntrack_count":
        return {"data": "12\n"}
    if path == "/sys/class/net/br-lan/brforward":
        # rpcd returns binary files base64-encoded only when asked to
        return {"data": _BRFORWARD_B64 if params.get("base64") else ""}
    if path == "/sys/class/net/lan1/brport/port_no":
        return {"data": "0x1\n"}
    if path.startswith("/sys/class/net/wan/statistics/"):
        return {"data": "1000\n" if path.endswith("rx_bytes") else "500\n"}
    if path.endswith("dhcp.leases"):
        return {"data": MOCK_DHCP_LEASES_RAW}
    return None  # NOT_FOUND


def _file_list(params: dict[str, Any]) -> Any:
    if params.get("path") == "/sys/class/net":
        return {
            "entries": [
                {"name": n, "type": "directory"} for n in ("wan", "lan1", "br-lan", "lo")
            ]
        }
    return None


def _device_status(params: dict[str, Any]) -> Any:
    name = params.get("name")
    if name is None:
        return _DEVICES
    return _DEVICES.get(name)


def _uci_get(params: dict[str, Any]) -> Any:
    config = params.get("config")
    if config == "wireless":
        return MOCK_UCI_WIRELESS
    if config in ("network", "dhcp", "system"):
        return {"values": {}}
    return None


RESPONSES: dict[tuple[str, str], Any] = {
    ("session", "login"): {
        "ubus_rpc_session": MOCK_SESSION_TOKEN,
        "timeout": 300,
        "expires": 300,
        "acls": {},
        "data": {"username": "root"},
    },
    ("system", "board"): MOCK_BOARD_INFO,
    ("system", "info"): _SYSTEM_INFO,
    ("network.interface", "dump"): _NETWORK_DUMP,
    ("network.device", "status"): _device_status,
    ("network.wireless", "status"): MOCK_WIRELESS_STATUS,
    ("iwinfo", "info"): MOCK_IWINFO_INFO,
    ("iwinfo", "devices"): {"devices": ["phy0-ap0", "phy1-ap0"]},
    ("iwinfo", "assoclist"): {"results": []},
    ("hostapd.phy0-ap0", "get_clients"): {"clients": {}},
    ("hostapd.phy1-ap0", "get_clients"): {"clients": {}},
    ("luci-rpc", "getDHCPLeases"): {"dhcp_leases": []},
    ("uci", "get"): _uci_get,
    ("file", "read"): _file_read,
    ("file", "list"): _file_list,
    ("log", "read"): {"log": []},
    ("service", "list"): {},
    ("rc", "list"): {},
}


def _ubus_session() -> MagicMock:
    """aiohttp session mock that routes ubus calls by object/method/params."""
    session = MagicMock()

    def _post(url, json=None, **kwargs):
        params = (json or {}).get("params", [None, "", "", {}])
        obj, method = params[1], params[2]
        args = params[3] if len(params) > 3 and isinstance(params[3], dict) else {}
        handler = RESPONSES.get((obj, method))
        if handler is None:
            envelope = [UBUS_METHOD_NOT_FOUND]
        else:
            data = handler(args) if callable(handler) else handler
            envelope = [UBUS_OK, data] if data is not None else [UBUS_NOT_FOUND]
        resp = AsyncMock()
        resp.status = 200
        resp.json = AsyncMock(
            return_value={"jsonrpc": "2.0", "id": (json or {}).get("id", 1), "result": envelope}
        )
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    session.post = MagicMock(side_effect=_post)
    return session


def _make_coordinator(api) -> OpenWrtCoordinator:
    hass = MagicMock()
    hass.async_create_task = MagicMock(side_effect=lambda coro: coro)
    with patch("homeassistant.helpers.frame.report_usage"):
        return OpenWrtCoordinator(hass=hass, api=api, entry_title="test")


@pytest.mark.asyncio
async def test_two_full_polls_open_no_ssh_connection():
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=_ubus_session(),
        protocol="http",
    )
    # LLDP is the one allowed SSH reader (600 s cadence); prime its cache so
    # this test only measures the per-poll paths.
    api._lldp_checked = True
    api._lldp_available = False
    api._lldp_last_fetch = time.monotonic()

    coordinator = _make_coordinator(api)
    connect = AsyncMock(side_effect=AssertionError("SSH must not be used"))
    with (
        patch("custom_components.openwrt_router.api.asyncssh.connect", connect),
        patch("asyncio.open_connection", side_effect=OSError("no net")),
    ):
        first = await coordinator._async_update_data()
        coordinator.data = first
        second = await coordinator._async_update_data()

    assert connect.await_count == 0

    # The data the SSH paths used to deliver now comes from ubus.
    assert second.wan_status["rx_bytes"] == 1000
    assert second.wan_status["tx_bytes"] == 500
    assert second.disk_space["primary"]["mount"] == "/"
    assert second.disk_space["primary"]["total_mb"] > 0
    assert second.tmpfs["total_mb"] > 0
    assert second.tmpfs["mounts"][0]["mount"] == "/tmp"
    assert second.port_fdb_map == {"aa:bb:cc:dd:ee:01": "lan1"}
    assert second.arp_table == {"b8:27:eb:aa:bb:01": "192.168.1.101"}
    assert second.cpu_cores == 2


class TestCoordinatorReleasesSsh:
    def _api(self) -> AsyncMock:
        api = AsyncMock()
        api.get_router_info = AsyncMock(return_value=MOCK_BOARD_INFO)
        api.get_wan_status = AsyncMock(return_value={"connected": True, "interface": "wan"})
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(return_value={"uptime": 1, "cpu_load": 1.0, "memory": {}})
        api.get_disk_space = AsyncMock(return_value={})
        api.get_tmpfs_stats = AsyncMock(return_value={})
        api.get_network_interfaces = AsyncMock(return_value=[])
        api.get_active_connections = AsyncMock(return_value=0)
        api.detect_features = AsyncMock(return_value={})
        api.reset_ssh_fallback_flag = MagicMock()
        api.uses_ssh_fallback = False
        return api

    @pytest.mark.asyncio
    async def test_release_called_after_successful_poll(self):
        api = self._api()
        coordinator = _make_coordinator(api)
        await coordinator._async_update_data()
        api.async_release_ssh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_release_called_when_poll_fails(self):
        from homeassistant.helpers.update_coordinator import UpdateFailed

        api = self._api()
        api.get_router_info = AsyncMock(side_effect=OpenWrtConnectionError("down"))
        coordinator = _make_coordinator(api)
        with pytest.raises(UpdateFailed):
            await coordinator._async_update_data()
        api.async_release_ssh.assert_awaited_once()
