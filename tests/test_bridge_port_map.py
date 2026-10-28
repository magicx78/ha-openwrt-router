"""Bridge port map built over ubus (1.38.8, hardware regression since 1.38.3).

rpcd (2025.12.03 and 2026.10.04 verified) lists ``/sys/class/net`` as one
``symlink`` entry per interface, named after the interface, plus one
``directory`` entry named after the link TARGET
(``../../devices/.../net/lan1``). Keeping only the directories keyed the port
map by those paths, every FDB record then failed the physical-port filter and
the panel lost its port mapping on every router — since 1.38.3, when the ubus
brforward read started to succeed (before that the FDB always fell through to
SSH, which built its own map). The map is now built from the plain names and
cached, so a poll no longer costs one ``port_no`` read per interface.
"""

from __future__ import annotations

import base64
import struct
from unittest.mock import AsyncMock

import pytest

from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

_SYSFS_NET_TARGETS = {
    "br-lan": "../../devices/virtual/net/br-lan",
    "eth0": "../../devices/platform/soc/15100000.ethernet/net/eth0",
    "lan1": "../../devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/lan1",
    "lan2": "../../devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/lan2",
    "lan3": "../../devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/lan3",
    "lo": "../../devices/virtual/net/lo",
    "phy0-ap0": "../../devices/platform/soc/18000000.wifi/net/phy0-ap0",
    "wan": "../../devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/wan",
}

# Members of br-lan and their port numbers as ``brport/port_no`` reports them.
PORT_NOS = {"lan1": "0x1", "lan2": "0x2", "lan3": "0x3", "phy0-ap0": "0x4"}


def _sysfs_net_listing() -> list[dict]:
    """``file list /sys/class/net`` exactly as rpcd returns it on hardware."""
    entries: list[dict] = []
    for name, target in _SYSFS_NET_TARGETS.items():
        entries.append({"name": target, "type": "directory", "size": 0, "mode": 16877})
        entries.append({"name": name, "type": "symlink", "size": 0, "mode": 41471})
    return entries


def _fdb_record(port_no: int) -> bytes:
    """One kernel struct __fdb_entry (16 bytes) for MAC aa:bb:cc:dd:ee:<port>."""
    mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, port_no])
    return struct.pack("<6sBBIBBH", mac, port_no, 0, 12345, 0, 0, 0)


def _mac(port_no: int) -> str:
    return f"aa:bb:cc:dd:ee:{port_no:02x}"


def _mock_ubus(mock_api, *, port_nos=None, listing=None, fdb_ports=None) -> dict:
    """ubus mock: hardware listing, port_no per member, brforward from fdb_ports.

    ``port_nos`` and ``fdb_ports`` are read on every call, so a test can let a
    port join the bridge between two polls by mutating them.
    """
    calls: dict = {"list": 0, "port_no": [], "brforward": 0}
    port_nos = PORT_NOS if port_nos is None else port_nos
    listing = _sysfs_net_listing() if listing is None else listing
    fdb_ports = [1, 3, 4] if fdb_ports is None else fdb_ports

    async def call_side_effect(obj, method, params=None, **kwargs):
        params = params or {}
        path = params.get("path", "")
        if method == "list" and path == "/sys/class/net":
            calls["list"] += 1
            if isinstance(listing, Exception):
                raise listing
            return {"entries": listing}
        if path.endswith("/brport/port_no"):
            iface = path[len("/sys/class/net/") : -len("/brport/port_no")]
            calls["port_no"].append(iface)
            if iface in port_nos:
                return {"data": port_nos[iface] + "\n"}
            # not a bridge member: rpcd answers "not found"
            raise OpenWrtMethodNotFoundError(path)
        if path.endswith("/brforward"):
            calls["brforward"] += 1
            buf = b"".join(_fdb_record(p) for p in fdb_ports)
            return {"data": base64.b64encode(buf).decode()}
        raise OpenWrtMethodNotFoundError(path)

    mock_api._call = AsyncMock(side_effect=call_side_effect)
    mock_api._run_ssh = AsyncMock(return_value="")
    mock_api._run_ssh_binary = AsyncMock(return_value=b"")
    return calls


class TestBridgePortMapFromFileList:
    @pytest.mark.asyncio
    async def test_interfaces_come_from_the_plain_entry_names(self, mock_api):
        """The regression: link targets were taken as interface names."""
        calls = _mock_ubus(mock_api)
        fdb = await mock_api.get_bridge_fdb()
        # port 4 is a Wi-Fi member, which the physical-port filter drops
        assert fdb == {_mac(1): "lan1", _mac(3): "lan3"}
        assert calls["port_no"], "port numbers were not read at all"
        assert all("/" not in iface for iface in calls["port_no"]), calls["port_no"]
        assert len(calls["port_no"]) == len(set(calls["port_no"]))
        mock_api._run_ssh.assert_not_awaited()
        mock_api._run_ssh_binary.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_port_map_is_cached_between_polls(self, mock_api):
        calls = _mock_ubus(mock_api)
        assert await mock_api.get_bridge_fdb()
        assert await mock_api.get_bridge_fdb()
        assert calls["list"] == 1
        assert calls["brforward"] == 2
        assert len(calls["port_no"]) == len(_SYSFS_NET_TARGETS)

    @pytest.mark.asyncio
    async def test_port_map_is_rebuilt_after_the_refresh_interval(self, mock_api):
        from custom_components.openwrt_router.const import (
            BRIDGE_PORT_MAP_REFRESH_INTERVAL,
        )

        calls = _mock_ubus(mock_api)
        await mock_api.get_bridge_fdb()
        mock_api._bridge_port_map_at -= BRIDGE_PORT_MAP_REFRESH_INTERVAL + 1
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 2

    @pytest.mark.asyncio
    async def test_port_joining_the_bridge_is_resolved_at_once(self, mock_api):
        """A new member's number is not in the cached map: rebuild in that poll."""
        port_nos = {"lan1": "0x1", "phy0-ap0": "0x4"}
        fdb_ports = [1, 4]
        calls = _mock_ubus(mock_api, port_nos=port_nos, fdb_ports=fdb_ports)
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert calls["list"] == 1
        port_nos["lan3"] = "0x3"  # lan3 joins br-lan …
        fdb_ports.append(3)  # … and a device behind it shows up in the FDB
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1", _mac(3): "lan3"}
        assert calls["list"] == 2

    @pytest.mark.asyncio
    async def test_numbers_still_unknown_after_a_rebuild_do_not_churn(self, mock_api):
        """A number no member resolves to must not cost a rebuild per poll."""
        calls = _mock_ubus(mock_api, port_nos={"lan1": "0x1"})
        for _ in range(3):
            assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert calls["list"] == 2  # initial build + one rebuild, then quiet

    @pytest.mark.asyncio
    async def test_list_failure_falls_back_to_the_static_port_names(self, mock_api):
        calls = _mock_ubus(mock_api, listing=OpenWrtMethodNotFoundError("acl"))
        fdb = await mock_api.get_bridge_fdb()
        assert fdb == {_mac(1): "lan1", _mac(3): "lan3"}
        assert "lan1" in calls["port_no"] and "lan3" in calls["port_no"]
        mock_api._run_ssh.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_acl_reset_drops_the_cached_map(self, mock_api):
        """After an ACL deploy a formerly denied port_no read may work now."""
        calls = _mock_ubus(mock_api)
        await mock_api.get_bridge_fdb()
        mock_api.reset_acl_blocked()
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 2


class TestSysfsNetNames:
    def test_plain_names_only_and_in_order(self):
        from custom_components.openwrt_router.api import _sysfs_net_names

        names = _sysfs_net_names({"entries": _sysfs_net_listing()})
        assert names == list(_SYSFS_NET_TARGETS)

    def test_older_rpcd_without_directory_duplicates(self):
        from custom_components.openwrt_router.api import _sysfs_net_names

        listing = {
            "entries": [
                {"name": "lan1", "type": "directory"},
                {"name": "lan2", "type": "symlink"},
            ]
        }
        assert _sysfs_net_names(listing) == ["lan1", "lan2"]

    def test_garbage_is_ignored(self):
        from custom_components.openwrt_router.api import _sysfs_net_names

        listing = {
            "entries": [{"name": "."}, {"name": ".."}, {"name": ""}, {"type": "file"}, {"name": 5}, "x"]
        }
        assert _sysfs_net_names(listing) == []
        assert _sysfs_net_names({}) == []
