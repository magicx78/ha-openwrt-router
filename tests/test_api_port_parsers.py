"""Tests for the port-mapping data sources in api.py (v1.21).

Covers the 16-byte brforward parser (regression lock against the old
8-byte bug), /proc/net/arp parsing, get_arp_table with file/read + SSH
fallback, and the trunk-port-map refactor that reuses pre-fetched maps.
"""

from __future__ import annotations

import base64
import struct
from unittest.mock import AsyncMock

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtMethodNotFoundError,
    _parse_brforward,
    _parse_proc_net_arp,
)


def _fdb_entry(
    mac: bytes,
    port_no: int,
    is_local: int = 0,
    ageing: int = 12345,
    port_hi: int = 0,
) -> bytes:
    """Build one kernel struct __fdb_entry record (16 bytes)."""
    return struct.pack("<6sBBIBBH", mac, port_no, is_local, ageing, port_hi, 0, 0)


PORT_NO_MAP = {1: "lan1", 2: "lan2", 3: "lan3"}


# =====================================================================
# _parse_brforward — 16-byte struct __fdb_entry records
# =====================================================================


class TestParseBrforward:
    def test_parse_brforward_16_byte_records(self):
        """Regression lock: the old 8-byte parser would misread this buffer."""
        buf = _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x01", 1) + _fdb_entry(
            b"\xaa\xbb\xcc\xdd\xee\x02", 3
        )
        fdb = _parse_brforward(buf, PORT_NO_MAP)
        assert fdb == {
            "aa:bb:cc:dd:ee:01": "lan1",
            "aa:bb:cc:dd:ee:02": "lan3",
        }

    def test_parse_brforward_skips_is_local(self):
        """is_local entries are the bridge's own MACs — never devices."""
        buf = _fdb_entry(b"\xde\xad\xbe\xef\x00\x01", 1, is_local=1) + _fdb_entry(
            b"\xaa\xbb\xcc\xdd\xee\x01", 1
        )
        fdb = _parse_brforward(buf, PORT_NO_MAP)
        assert fdb == {"aa:bb:cc:dd:ee:01": "lan1"}

    def test_parse_brforward_port_hi(self):
        """Port index is port_no | (port_hi << 8)."""
        big_map = {0x101: "lan1"}
        buf = _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x03", 0x01, port_hi=0x01)
        assert _parse_brforward(buf, big_map) == {"aa:bb:cc:dd:ee:03": "lan1"}

    def test_parse_brforward_rejects_bad_length(self):
        """A buffer that is not whole 16-byte records yields {} — never guess."""
        buf = _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x01", 1)[:12]
        assert _parse_brforward(buf, PORT_NO_MAP) == {}
        assert _parse_brforward(b"", PORT_NO_MAP) == {}

    def test_parse_brforward_skips_multicast_broadcast_and_zero(self):
        buf = (
            _fdb_entry(b"\x01\x00\x5e\x00\x00\xfb", 1)  # multicast
            + _fdb_entry(b"\xff\xff\xff\xff\xff\xff", 1)  # broadcast
            + _fdb_entry(b"\x00\x00\x00\x00\x00\x00", 1)  # all-zero
            + _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x04", 2)  # real device
        )
        assert _parse_brforward(buf, PORT_NO_MAP) == {"aa:bb:cc:dd:ee:04": "lan2"}

    def test_parse_brforward_unknown_port_skipped(self):
        buf = _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x05", 9)
        assert _parse_brforward(buf, PORT_NO_MAP) == {}

    def test_parse_brforward_vlan_subinterface_normalised(self):
        """A lan1.10 bridge member is attributed to physical lan1."""
        vlan_map = {1: "lan1.10", 2: "phy0-ap0"}
        buf = _fdb_entry(b"\xaa\xbb\xcc\xdd\xee\x06", 1) + _fdb_entry(
            b"\xaa\xbb\xcc\xdd\xee\x07", 2
        )
        fdb = _parse_brforward(buf, vlan_map)
        assert fdb == {"aa:bb:cc:dd:ee:06": "lan1"}  # phy* member dropped


# =====================================================================
# _parse_proc_net_arp / get_arp_table
# =====================================================================

ARP_RAW = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
    "192.168.1.23     0x1         0x2         aa:bb:cc:dd:ee:01     *        br-lan\n"
    "192.168.1.99     0x1         0x0         aa:bb:cc:dd:ee:02     *        br-lan\n"
    "10.99.0.1        0x1         0x2         aa:bb:cc:dd:ee:03     *        wan\n"
    "not-an-ip        0x1         0x2         aa:bb:cc:dd:ee:04     *        br-lan\n"
    "192.168.1.50     0x1         0x2         00:00:00:00:00:00     *        br-lan\n"
)


class TestParseProcNetArp:
    def test_flags_and_validation(self):
        """Only complete (0x2) entries with a valid IPv4 and real MAC count."""
        arp = _parse_proc_net_arp(ARP_RAW)
        assert arp == {
            "aa:bb:cc:dd:ee:01": "192.168.1.23",
            "aa:bb:cc:dd:ee:03": "10.99.0.1",
        }

    def test_duplicate_mac_prefers_br_lan_then_smallest_ip(self):
        raw = (
            "IP address HW type Flags HW address Mask Device\n"
            "192.168.1.200 0x1 0x2 aa:bb:cc:dd:ee:10 * eth1\n"
            "192.168.1.5   0x1 0x2 aa:bb:cc:dd:ee:10 * br-lan\n"
            "192.168.1.4   0x1 0x2 aa:bb:cc:dd:ee:11 * eth1\n"
            "192.168.1.9   0x1 0x2 aa:bb:cc:dd:ee:11 * eth1\n"
        )
        arp = _parse_proc_net_arp(raw)
        assert arp["aa:bb:cc:dd:ee:10"] == "192.168.1.5"  # br-lan wins
        assert arp["aa:bb:cc:dd:ee:11"] == "192.168.1.4"  # smallest IP wins

    def test_empty_and_header_only(self):
        assert _parse_proc_net_arp("") == {}
        header = "IP address HW type Flags HW address Mask Device\n"
        assert _parse_proc_net_arp(header) == {}


class TestGetArpTable:
    @pytest.mark.asyncio
    async def test_get_arp_table_via_file_read(self, mock_api):
        mock_api._call = AsyncMock(return_value={"data": ARP_RAW})
        arp = await mock_api.get_arp_table()
        assert arp["aa:bb:cc:dd:ee:01"] == "192.168.1.23"
        mock_api._call.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_arp_table_ssh_fallback(self, mock_api):
        mock_api._call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("no file"))
        mock_api._run_ssh = AsyncMock(return_value=ARP_RAW)
        arp = await mock_api.get_arp_table()
        assert arp["aa:bb:cc:dd:ee:03"] == "10.99.0.1"

    @pytest.mark.asyncio
    async def test_get_arp_table_total_failure(self, mock_api):
        mock_api._call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("no file"))
        mock_api._run_ssh = AsyncMock(side_effect=RuntimeError("no ssh"))
        assert await mock_api.get_arp_table() == {}


# =====================================================================
# get_trunk_port_map — reuse of pre-fetched maps
# =====================================================================


class TestTrunkPortMapReuse:
    @pytest.mark.asyncio
    async def test_trunk_port_map_reuses_passed_fdb_arp(self, mock_api):
        """No second FDB/ARP fetch when the maps are passed in."""
        mock_api.get_bridge_fdb = AsyncMock()
        mock_api.get_arp_table = AsyncMock()
        result = await mock_api.get_trunk_port_map(
            fdb={"aa:bb:cc:dd:ee:01": "lan3"},
            arp={
                "aa:bb:cc:dd:ee:01": "10.10.10.2",
                "aa:bb:cc:dd:ee:02": "10.10.10.9",
            },
        )
        assert result == {"10.10.10.2": "lan3"}
        mock_api.get_bridge_fdb.assert_not_awaited()
        mock_api.get_arp_table.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_trunk_port_map_fetches_when_not_passed(self, mock_api):
        mock_api.get_bridge_fdb = AsyncMock(return_value={"aa:bb:cc:dd:ee:01": "lan1"})
        mock_api.get_arp_table = AsyncMock(
            return_value={"aa:bb:cc:dd:ee:01": "192.168.1.7"}
        )
        result = await mock_api.get_trunk_port_map()
        assert result == {"192.168.1.7": "lan1"}
        mock_api.get_bridge_fdb.assert_awaited_once()
        mock_api.get_arp_table.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_trunk_port_map_empty_fdb_short_circuits(self, mock_api):
        mock_api.get_bridge_fdb = AsyncMock(return_value={})
        mock_api.get_arp_table = AsyncMock()
        assert await mock_api.get_trunk_port_map() == {}
        mock_api.get_arp_table.assert_not_awaited()


# =====================================================================
# get_bridge_fdb end-to-end through the file/read path
# =====================================================================


class TestGetBridgeFdbParsing:
    @pytest.mark.asyncio
    async def test_file_read_path_uses_16_byte_parser(self, mock_api):
        """End-to-end: base64 file/read buffer → clean MAC→port map."""
        buf = _fdb_entry(b"\xde\xad\xbe\xef\x00\x01", 1, is_local=1) + _fdb_entry(
            b"\xaa\xbb\xcc\xdd\xee\x01", 1
        )

        async def call_side_effect(obj, method, params=None, **kwargs):
            path = (params or {}).get("path", "")
            if path == "/sys/class/net":
                return {"entries": [{"name": "lan1", "type": "directory"}]}
            if path.endswith("/brport/port_no"):
                return {"data": "0x1\n"}
            if path.endswith("/brforward"):
                return {"data": base64.b64encode(buf).decode()}
            raise OpenWrtMethodNotFoundError(path)

        mock_api._call = AsyncMock(side_effect=call_side_effect)
        fdb = await mock_api.get_bridge_fdb()
        assert fdb == {"aa:bb:cc:dd:ee:01": "lan1"}
