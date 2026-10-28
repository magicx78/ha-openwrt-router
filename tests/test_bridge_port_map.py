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
        assert calls["list"] == 1  # built once; its unknown numbers are remembered

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


# ---------------------------------------------------------------------
# Review findings on 4b2c506 (2026-10-28): remembered unknown numbers must
# accumulate (F1), the interval refresh must not add a second rebuild (F2),
# a rebuild that resolves nothing must not evict the good map (F3), an ACL
# reset during a rebuild must win (F5), one record walker for both parsers
# (F6).
# ---------------------------------------------------------------------


class TestBridgePortMapReviewFindings:
    @pytest.mark.asyncio
    async def test_unknown_numbers_accumulate_across_polls(self, mock_api):
        """F1: a second unknown number must not make the first one forgotten."""
        fdb_ports = [1, 4]
        calls = _mock_ubus(mock_api, port_nos={"lan1": "0x1"}, fdb_ports=fdb_ports)
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert calls["list"] == 1  # a map built in this poll is not rebuilt again
        assert mock_api._bridge_port_map_unknown == {4}
        fdb_ports.append(5)  # another member nobody resolves
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert calls["list"] == 2  # one rebuild for the new number
        assert mock_api._bridge_port_map_unknown == {4, 5}
        for _ in range(3):
            assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert calls["list"] == 2

    @pytest.mark.asyncio
    async def test_interval_refresh_does_not_add_a_second_rebuild(self, mock_api):
        """F2: with a persistently unknown number the interval poll rebuilds once."""
        from custom_components.openwrt_router.const import (
            BRIDGE_PORT_MAP_REFRESH_INTERVAL,
        )

        calls = _mock_ubus(mock_api, port_nos={"lan1": "0x1"}, fdb_ports=[1, 4])
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 1
        mock_api._bridge_port_map_at -= BRIDGE_PORT_MAP_REFRESH_INTERVAL + 1
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 2
        assert mock_api._bridge_port_map_unknown == {4}

    @pytest.mark.asyncio
    async def test_interval_refresh_forgets_numbers_it_resolves(self, mock_api):
        """A port that joined is picked up by the interval refresh at the latest."""
        from custom_components.openwrt_router.const import (
            BRIDGE_PORT_MAP_REFRESH_INTERVAL,
        )

        port_nos = {"lan1": "0x1"}
        calls = _mock_ubus(mock_api, port_nos=port_nos, fdb_ports=[1, 3])
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1"}
        assert mock_api._bridge_port_map_unknown == {3}
        port_nos["lan3"] = "0x3"
        mock_api._bridge_port_map_at -= BRIDGE_PORT_MAP_REFRESH_INTERVAL + 1
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1", _mac(3): "lan3"}
        assert mock_api._bridge_port_map_unknown == set()
        assert calls["list"] == 2

    @pytest.mark.asyncio
    async def test_failed_rebuild_keeps_the_last_good_map(self, mock_api):
        """F3: a poll in which no port_no read succeeds must not blank the map."""
        from custom_components.openwrt_router.const import (
            BRIDGE_PORT_MAP_REFRESH_INTERVAL,
        )

        port_nos = dict(PORT_NOS)
        calls = _mock_ubus(mock_api, port_nos=port_nos)
        good = await mock_api.get_bridge_fdb()
        assert good == {_mac(1): "lan1", _mac(3): "lan3"}
        saved = dict(port_nos)
        port_nos.clear()  # every port_no read fails (timeouts, denied)
        mock_api._bridge_port_map_at -= BRIDGE_PORT_MAP_REFRESH_INTERVAL + 1
        assert await mock_api.get_bridge_fdb() == good
        assert calls["list"] == 2
        assert mock_api._bridge_port_map_unknown == set()
        port_nos.update(saved)  # router healthy again: retried on the next poll
        assert await mock_api.get_bridge_fdb() == good
        assert calls["list"] == 3
        assert await mock_api.get_bridge_fdb() == good  # and cached again
        assert calls["list"] == 3

    @pytest.mark.asyncio
    async def test_first_build_failure_is_retried_next_poll(self, mock_api):
        port_nos: dict = {}
        calls = _mock_ubus(mock_api, port_nos=port_nos)
        assert await mock_api.get_bridge_fdb() == {}
        assert calls["list"] == 1  # one attempt per poll, nothing remembered
        assert mock_api._bridge_port_map_unknown == set()
        port_nos.update(PORT_NOS)
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1", _mac(3): "lan3"}
        assert calls["list"] == 2

    @pytest.mark.asyncio
    async def test_acl_reset_during_a_rebuild_wins(self, mock_api):
        """F5: reset_acl_blocked() while the map is being built → rebuild next poll."""
        calls = _mock_ubus(mock_api)
        inner = mock_api._call

        async def reset_during_listing(obj, method, params=None, **kwargs):
            result = await inner(obj, method, params, **kwargs)
            if method == "list":
                mock_api.reset_acl_blocked()  # the ACL deploy finished meanwhile
            return result

        mock_api._call = AsyncMock(side_effect=reset_during_listing)
        assert await mock_api.get_bridge_fdb() == {_mac(1): "lan1", _mac(3): "lan3"}
        assert calls["list"] == 1
        mock_api._call = inner
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 2
        await mock_api.get_bridge_fdb()
        assert calls["list"] == 2


class TestBrforwardPortNumbers:
    def test_port_hi_and_record_filters(self):
        """F6: the number walker applies the parser's filters and port_hi."""
        from custom_components.openwrt_router.api import _brforward_port_numbers

        buf = (
            struct.pack("<6sBBIBBH", b"\xaa\xbb\xcc\xdd\xee\x01", 1, 0, 1, 1, 0, 0)  # 257
            + struct.pack("<6sBBIBBH", b"\xaa\xbb\xcc\xdd\xee\x02", 2, 1, 1, 0, 0, 0)  # local
            + struct.pack("<6sBBIBBH", b"\x01\x00\x5e\x00\x00\x01", 3, 0, 1, 0, 0, 0)  # mcast
            + struct.pack("<6sBBIBBH", b"\x00" * 6, 4, 0, 1, 0, 0, 0)  # all-zero
            + _fdb_record(5)
        )
        assert _brforward_port_numbers(buf) == {257, 5}
        assert _brforward_port_numbers(buf[:-1]) == set()
        assert _brforward_port_numbers(b"") == set()
