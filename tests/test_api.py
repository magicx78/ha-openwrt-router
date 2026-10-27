"""Tests for the OpenWrt API client (api.py)."""

from __future__ import annotations

import asyncio
import logging
import shlex
from collections.abc import Iterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from custom_components.openwrt_router import api as api_module
from custom_components.openwrt_router.api import (
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
    UBUS_STATUS_METHOD_NOT_FOUND,
    UBUS_STATUS_NO_DATA,
    UBUS_STATUS_NOT_FOUND,
    UBUS_STATUS_OK,
    UBUS_STATUS_PERMISSION_DENIED,
)
from custom_components.openwrt_router.const import (
    DEFAULT_SESSION_ID,
    RC_LIST_REFRESH_INTERVAL,
)

from conftest import (
    MOCK_BOARD_INFO,
    MOCK_SESSION_TOKEN,
    MOCK_SYSTEM_INFO,
    MOCK_UBUS_RESPONSES,
    MOCK_WIRELESS_STATUS,
    MOCK_IWINFO_INFO,
)


# =====================================================================
# Helpers
# =====================================================================


def _make_raw_call_response(status_code=200, json_data=None, raise_on_json=False):
    """Build a mock response for _raw_call tests."""
    resp = AsyncMock()
    resp.status = status_code
    if raise_on_json:
        resp.json = AsyncMock(side_effect=ValueError("bad json"))
    else:
        resp.json = AsyncMock(return_value=json_data or {})

    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _make_api_with_response(
    status_code=200, json_data=None, raise_on_json=False, side_effect=None
):
    """Create an API instance with a mock session returning a specific response."""
    session = MagicMock()
    if side_effect:
        # side_effect must be a sync function that raises (not async),
        # because aiohttp session.post() returns an async CM directly
        session.post = MagicMock(side_effect=side_effect)
    else:
        cm = _make_raw_call_response(status_code, json_data, raise_on_json)
        session.post = MagicMock(return_value=cm)
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="test",
        session=session,
        protocol="http",
    )
    api._token = MOCK_SESSION_TOKEN
    return api


# =====================================================================
# check_capabilities — wireless satisfied via iwinfo fallback (v1.23.0)
# =====================================================================


class TestCheckCapabilitiesWireless:
    def _api(self):
        return OpenWrtAPI(
            host="192.168.1.1",
            port=80,
            username="root",
            password="test",
            session=MagicMock(),
            protocol="http",
        )

    @pytest.mark.asyncio
    async def test_wireless_green_when_only_iwinfo_works(self):
        """Cudy firmware: network.wireless/status errors (rc 2) but iwinfo works.

        The wireless capability must still be reported available.
        """
        api = self._api()

        async def _call(obj, method, params, *a, **k):
            if obj == "network.wireless":
                raise OpenWrtResponseError("ubus error 2")  # INVALID_ARGUMENT
            return {}  # everything else (incl. iwinfo/devices) succeeds

        api._call = AsyncMock(side_effect=_call)
        api.probe_lldp = AsyncMock(return_value="unavailable")  # skip SSH lldpcli
        caps = await api.check_capabilities()
        assert caps["network_wireless"] is True
        assert caps["iwinfo"] is True

    @pytest.mark.asyncio
    async def test_wireless_green_when_only_uci_works(self):
        """Stock Cudy: no netifd/iwinfo/hostapd, but UCI is readable.

        The runtime reads wireless via UCI in that case, so the capability
        must be reported available (no false 'critical' alarm).
        """
        api = self._api()

        async def _call(obj, method, params, *a, **k):
            if obj in ("network.wireless", "iwinfo") or obj.startswith("hostapd"):
                raise OpenWrtResponseError("blocked")
            return {}  # uci/get and system succeed

        api._call = AsyncMock(side_effect=_call)
        api.probe_lldp = AsyncMock(return_value="unavailable")  # skip SSH lldpcli
        caps = await api.check_capabilities()
        assert caps["network_wireless"] is True
        assert caps["iwinfo"] is False

    @pytest.mark.asyncio
    async def test_wireless_red_when_all_sources_fail(self):
        api = self._api()

        async def _call(obj, method, params, *a, **k):
            # No wireless source at all: netifd, iwinfo, hostapd AND uci fail.
            if (
                obj in ("network.wireless", "iwinfo", "uci")
                or obj.startswith("hostapd")
            ):
                raise OpenWrtResponseError("blocked")
            return {}

        api._call = AsyncMock(side_effect=_call)
        api.probe_lldp = AsyncMock(return_value="unavailable")  # skip SSH lldpcli
        caps = await api.check_capabilities()
        assert caps["network_wireless"] is False
        assert caps["iwinfo"] is False


class TestResetAclBlocked:
    """reset_acl_blocked() must clear cached ACL-blocked methods so they are
    re-probed after an ACL (re)deploy (setup path)."""

    def _api(self):
        return OpenWrtAPI(
            host="10.0.0.1",
            port=80,
            username="root",
            password="x",
            session=MagicMock(),
            protocol="http",
        )

    def test_clears_cached_blocks(self):
        api = self._api()
        api._acl_blocked.add(("file", "read"))
        api._acl_blocked.add(("network.wireless", "status"))
        assert api._acl_blocked
        api.reset_acl_blocked()
        assert api._acl_blocked == set()

    def test_noop_when_empty(self):
        api = self._api()
        api.reset_acl_blocked()
        assert api._acl_blocked == set()


class TestStaInterfaceDetailsUciFallback:
    """UCI fallback of get_sta_interface_details must skip disabled wifi-ifaces
    so a leftover-disabled mesh/sta entry can't flip a wired AP to wireless."""

    def _api(self):
        return OpenWrtAPI(
            host="10.0.0.1",
            port=80,
            username="root",
            password="x",
            session=MagicMock(),
            protocol="http",
        )

    @pytest.mark.asyncio
    async def test_uci_fallback_skips_disabled(self):
        api = self._api()
        # iwinfo/info returns no STA candidates -> forces the UCI fallback path.
        api._call = AsyncMock(return_value={})
        api.get_uci_wireless = AsyncMock(
            return_value={
                "m0": {".type": "wifi-iface", "mode": "mesh",
                       "ssid": "bh", "disabled": "1"},   # disabled -> skipped
                "m1": {".type": "wifi-iface", "mode": "mesh",
                       "ssid": "bh2", "disabled": "0"},   # enabled -> kept
                "s0": {".type": "wifi-iface", "mode": "sta",
                       "ssid": "rep"},                    # no disabled key -> kept
            }
        )
        result = await api.get_sta_interface_details()
        ifnames = {r["ifname"] for r in result}
        assert "m0" not in ifnames
        assert "m1" in ifnames
        assert "s0" in ifnames


# =====================================================================
# Parsing Tests (pure functions)
# =====================================================================


class TestParseDhcpLeases:
    def test_normal(self):
        raw = (
            "1741600000 b8:27:eb:aa:bb:cc 192.168.1.100 raspberrypi 01:b8:27:eb:aa:bb:cc\n"
            "1741600001 ac:de:48:11:22:33 192.168.1.101 myphone *\n"
            "1741600002 00:11:22:33:44:55 192.168.1.102 * *\n"
        )
        leases = OpenWrtAPI._parse_dhcp_leases(raw)
        assert leases["B8:27:EB:AA:BB:CC"] == {
            "ip": "192.168.1.100",
            "hostname": "raspberrypi",
            "expires": 1741600000,
        }
        assert leases["AC:DE:48:11:22:33"] == {
            "ip": "192.168.1.101",
            "hostname": "myphone",
            "expires": 1741600001,
        }
        assert leases["00:11:22:33:44:55"] == {
            "ip": "192.168.1.102",
            "hostname": "",
            "expires": 1741600002,
        }

    def test_empty(self):
        assert OpenWrtAPI._parse_dhcp_leases("") == {}
        assert OpenWrtAPI._parse_dhcp_leases("\n\n") == {}

    def test_malformed_lines_ignored(self):
        assert OpenWrtAPI._parse_dhcp_leases("bad\nonly two fields\n") == {}

    def test_uppercase_mac(self):
        raw = "1741600000 AA:BB:CC:DD:EE:FF 10.0.0.1 laptop *\n"
        leases = OpenWrtAPI._parse_dhcp_leases(raw)
        assert "AA:BB:CC:DD:EE:FF" in leases


class TestParseWirelessStatus:
    def test_normal(self, mock_api):
        radios = mock_api._parse_wireless_status(MOCK_WIRELESS_STATUS)
        assert len(radios) == 3
        ssids = [r["ssid"] for r in radios]
        assert "OpenWrt-Home" in ssids
        assert "OpenWrt-Home-5G" in ssids
        assert "Guest-WiFi" in ssids

    def test_empty(self, mock_api):
        assert mock_api._parse_wireless_status({}) == []

    def test_non_dict_values_skipped(self, mock_api):
        assert mock_api._parse_wireless_status({"radio0": "not a dict"}) == []


class TestParseIwinfoInfo:
    def test_normal(self, mock_api):
        radios = mock_api._parse_iwinfo_info(MOCK_IWINFO_INFO)
        assert len(radios) == 2
        bands = {r["ssid"]: r["band"] for r in radios}
        assert bands["OpenWrt-Home"] == "2.4g"
        assert bands["OpenWrt-Home-5G"] == "5g"

    def test_empty(self, mock_api):
        assert mock_api._parse_iwinfo_info({}) == []


class TestDetectBand:
    def test_frequency_24ghz(self, mock_api):
        assert mock_api._detect_band("wlan0", {"frequency": 2412}) == "2.4g"

    def test_frequency_5ghz(self, mock_api):
        assert mock_api._detect_band("wlan1", {"frequency": 5200}) == "5g"

    def test_frequency_6ghz(self, mock_api):
        assert mock_api._detect_band("wlan2", {"frequency": 6100}) == "6g"

    def test_hwmode_bgn(self, mock_api):
        assert mock_api._detect_band("wlan0", {"hwmode": "bgn"}) == "2.4g"

    def test_hwmode_ac(self, mock_api):
        assert mock_api._detect_band("wlan0", {"hwmode": "ac"}) == "5g"

    def test_keyword_radio0(self, mock_api):
        assert mock_api._detect_band("radio0", {}) == "2.4g"

    def test_keyword_radio1(self, mock_api):
        assert mock_api._detect_band("radio1", {}) == "5g"

    def test_unknown(self, mock_api):
        # Note: "some_iface" contains "ac" which matches 5GHz keyword
        # Use a name that doesn't match any keywords
        assert mock_api._detect_band("eth0", {}) == "unknown"

    @pytest.mark.parametrize(
        "frequency", [5925, 5935, 5955, 5975, 5995, 6015, 7115, 7125]
    )
    def test_frequency_lower_6ghz_channels(self, mock_api, frequency):
        """6 GHz starts at 5925 MHz; 5935-5995 (ch 2, 1, 5, 9) used to read as 5g."""
        assert mock_api._detect_band("wlan2", {"frequency": frequency}) == "6g"

    @pytest.mark.parametrize("frequency", [4920, 5180, 5825, 5885, 5924])
    def test_frequency_5ghz_edges(self, mock_api, frequency):
        assert mock_api._detect_band("wlan1", {"frequency": frequency}) == "5g"

    @pytest.mark.parametrize("frequency", [7126, 58320])
    def test_frequency_60ghz_is_not_6ghz(self, mock_api, frequency):
        assert mock_api._detect_band("wlan3", {"frequency": frequency}) == "unknown"

    @pytest.mark.parametrize("hwmode", ["11ad", "ad"])
    def test_hwmode_60ghz_is_unknown(self, mock_api, hwmode):
        assert mock_api._detect_band("radio9", {"hwmode": hwmode, "channel": 2}) == "unknown"

    @pytest.mark.parametrize(
        ("uci_band", "expected"),
        [("2g", "2.4g"), ("5g", "5g"), ("6g", "6g"), ("60g", "unknown")],
    )
    def test_band_option_beats_name(self, mock_api, uci_band, expected):
        """UCI band option wins over the radio0 = 2.4 GHz name heuristic."""
        data = {".type": "wifi-device", "band": uci_band, "channel": "auto"}
        assert mock_api._detect_band("radio0", data) == expected

    @pytest.mark.parametrize("channel", ["1", "2", "5", "13", "37", "149"])
    def test_band_option_beats_ambiguous_channel(self, mock_api, channel):
        data = {"band": "6g", "channel": channel}
        assert mock_api._detect_band("radio1", data) == "6g"

    def test_wireless_status_config_block(self, mock_api):
        """network.wireless/status keeps band and channel in the config block."""
        data = {"up": True, "config": {"band": "6g", "channel": "5"}, "interfaces": []}
        assert mock_api._detect_band("radio0", data) == "6g"

    def test_frequency_beats_hwmode(self, mock_api):
        data = {"frequency": 5955, "hwmode": "ac"}
        assert mock_api._detect_band("phy2-ap0", data) == "6g"

    @pytest.mark.parametrize("hwmode", ["11n", "11ax", "11be", "ax", "auto"])
    def test_multiband_hwmode_defers_to_channel(self, mock_api, hwmode):
        """11n/ax/be exist on several bands: the channel decides, not the mode."""
        assert mock_api._detect_band("radio9", {"hwmode": hwmode, "channel": 36}) == "5g"
        assert mock_api._detect_band("radio9", {"hwmode": hwmode, "channel": 6}) == "2.4g"

    @pytest.mark.parametrize(
        ("channel", "expected"),
        [
            # 2.4 GHz; 1, 2, 5, 9 and 13 also exist on 6 GHz but stay 2.4 GHz
            (1, "2.4g"),
            (2, "2.4g"),
            (6, "2.4g"),
            (13, "2.4g"),
            (14, "2.4g"),
            ("11", "2.4g"),
            # 5 GHz; 149-177 also exist on 6 GHz but stay 5 GHz
            (36, "5g"),
            ("100", "5g"),
            (144, "5g"),
            (149, "5g"),
            (177, "5g"),
            # numbers that only exist on 6 GHz
            (17, "6g"),
            (33, "6g"),
            ("37", "6g"),
            (145, "6g"),
            (181, "6g"),
            (233, "6g"),
        ],
    )
    def test_channel_only(self, mock_api, channel, expected):
        assert mock_api._detect_band("radio9", {"channel": channel}) == expected

    @pytest.mark.parametrize(
        "data",
        [
            {},
            {"channel": "auto"},
            {"channel": None, "frequency": None, "hwmode": None, "band": None},
            {"channel": 0, "frequency": 0},
            {"channel": -3},
            {"channel": 15},
            {"channel": 237},
            {"frequency": "n/a"},
            {"band": ""},
            {"hardware": "not a dict"},
        ],
    )
    def test_missing_or_invalid_data_is_unknown(self, mock_api, data):
        assert mock_api._detect_band("eth0", data) == "unknown"

    def test_missing_data_keeps_name_fallback(self, mock_api):
        assert mock_api._detect_band("radio1", {"channel": "auto"}) == "5g"


class TestBandInParsers:
    """Band detection through the three Wi-Fi parsers with tri-band data."""

    def test_wireless_status_reads_config_band(self, mock_api):
        status = {
            name: {
                "up": True,
                "config": {"band": band, "channel": channel},
                "interfaces": [{"ifname": f"phy{i}-ap0", "config": {"ssid": f"Net-{i}"}}],
            }
            for i, (name, band, channel) in enumerate(
                [("radio0", "5g", "36"), ("radio1", "2g", "1"), ("radio2", "6g", "5")]
            )
        }
        bands = {r["name"]: r["band"] for r in mock_api._parse_wireless_status(status)}
        assert bands == {"radio0": "5g", "radio1": "2.4g", "radio2": "6g"}

    def test_iwinfo_low_6ghz_channel(self, mock_api):
        info = {
            "phy0-ap0": {"ssid": "Net-24", "channel": 1, "frequency": 2412},
            "phy1-ap0": {"ssid": "Net-5", "channel": 149, "frequency": 5745},
            "phy2-ap0": {"ssid": "Net-6", "channel": 1, "frequency": 5955},
        }
        bands = {r["ssid"]: r["band"] for r in mock_api._parse_iwinfo_info(info)}
        assert bands == {"Net-24": "2.4g", "Net-5": "5g", "Net-6": "6g"}

    def test_uci_wireless_band_option(self, mock_api):
        values = {
            "radio0": {".type": "wifi-device", "band": "5g", "channel": "36"},
            "radio1": {".type": "wifi-device", "band": "2g", "channel": "1"},
            "radio2": {".type": "wifi-device", "band": "6g", "channel": "1"},
            "radio3": {".type": "wifi-device", "channel": "auto"},
        }
        for i in range(4):
            values[f"default_radio{i}"] = {
                ".type": "wifi-iface",
                ".index": i + 4,
                "device": f"radio{i}",
                "ssid": f"Net-{i}",
            }
        bands = {r["name"]: r["band"] for r in mock_api._parse_uci_wireless(values)}
        # radio3 has no band data at all: unchanged name fallback ("radio" + "3")
        assert bands == {
            "radio0": "5g",
            "radio1": "2.4g",
            "radio2": "6g",
            "radio3": "unknown",
        }

    async def test_ssh_uci_show_band_option(self, mock_api):
        """The SSH fallback normalises the band like every other Wi-Fi path."""
        lines = []
        radios = [
            ("radio0", ["band='5g'", "channel='36'"]),
            ("radio1", ["band='2g'", "channel='1'"]),
            ("radio2", ["band='6g'", "channel='1'"]),
            ("radio3", ["channel='auto'"]),
            ("radio4", ["hwmode='11a'", "channel='auto'"]),
            ("radio5", ["band='60g'", "channel='2'"]),
            ("radio7", ["channel='100'"]),
        ]
        for i, (name, options) in enumerate(radios):
            lines.append(f"wireless.{name}=wifi-device")
            lines += [f"wireless.{name}.{opt}" for opt in options]
            lines += [
                f"wireless.default_{name}=wifi-iface",
                f"wireless.default_{name}.device='{name}'",
                f"wireless.default_{name}.ssid='Net-{i}'",
            ]
        ssh = AsyncMock(return_value=(0, "\n".join(lines), b""))
        with patch.object(mock_api, "_asyncssh_run", ssh):
            result = await mock_api._get_wifi_status_ssh()
        bands = {r["name"]: r["band"] for r in result}
        # radio3: no band data at all, name fallback ("radio" + "3") stays unknown
        assert bands == {
            "radio0": "5g",
            "radio1": "2.4g",
            "radio2": "6g",
            "radio3": "unknown",
            "radio4": "5g",
            "radio5": "unknown",  # 60 GHz, the band option beats the name
            "radio7": "5g",
        }


# =====================================================================
# network.wireless status: channel/htmode live in the radio "config" block
# =====================================================================

# Shape of `ubus call network.wireless status` on OpenWrt 25.12 (netifd
# ucode): no top-level channel, the channel is a string inside "config";
# "section" sits next to "ifname", not inside the interface config.
WIRELESS_STATUS_25_12 = {
    "radio0": {
        "up": True,
        "pending": False,
        "autostart": True,
        "disabled": False,
        "retry_setup_failed": False,
        "config": {
            "type": "mac80211",
            "band": "2g",
            "cell_density": 1,
            "channel": "1",
            "country": "DE",
            "htmode": "HE20",
            "path": "platform/soc/18000000.wifi",
        },
        "interfaces": [
            {
                "section": "default_radio0",
                "ifname": "phy0-ap0",
                "config": {"mode": "ap", "ssid": "Example-Net"},
                "vlans": [],
                "stations": [],
            }
        ],
    },
    "radio1": {
        "up": True,
        "pending": False,
        "autostart": True,
        "disabled": False,
        "retry_setup_failed": False,
        "config": {
            "type": "mac80211",
            "band": "5g",
            "cell_density": 1,
            "channel": "36",
            "country": "DE",
            "htmode": "HE40",
            "path": "platform/soc/18000000.wifi+1",
        },
        "interfaces": [
            {
                "section": "lan_5g",
                "ifname": "phy1-ap0",
                "config": {"mode": "ap", "ssid": "Example-Net-5G"},
                "vlans": [],
                "stations": [],
            }
        ],
    },
}


class TestWirelessStatusConfigBlock:
    """AK5: channel (and htmode/hwmode) come from the radio config block."""

    def test_channel_from_config_block(self, mock_api):
        radios = mock_api._parse_wireless_status(WIRELESS_STATUS_25_12)
        by_name = {r["name"]: r for r in radios}
        # int like the iwinfo and UCI paths (channel_plan, panel expect numbers)
        assert by_name["radio0"]["channel"] == 1
        assert by_name["radio1"]["channel"] == 36
        assert isinstance(by_name["radio1"]["channel"], int)

    def test_htmode_from_config_block(self, mock_api):
        radios = mock_api._parse_wireless_status(WIRELESS_STATUS_25_12)
        by_name = {r["name"]: r for r in radios}
        assert by_name["radio0"]["htmode"] == "HE20"
        assert by_name["radio1"]["htmode"] == "HE40"

    @pytest.mark.parametrize("channel", [36, "36"])
    def test_top_level_channel_still_read(self, mock_api, channel):
        """Older status formats with a top-level channel keep working."""
        status = {
            "radio1": {
                "up": True,
                "channel": channel,
                "interfaces": [
                    {"ifname": "phy1-ap0", "config": {"ssid": "Example-Net-5G"}}
                ],
            }
        }
        (radio,) = mock_api._parse_wireless_status(status)
        assert radio["channel"] == 36

    @pytest.mark.parametrize(
        ("config", "top_level", "expected"),
        [
            ({"channel": "auto"}, {}, None),
            ({}, {}, None),
            ({"channel": ""}, {}, None),
            ({"channel": "auto"}, {"channel": 44}, 44),
            ({"channel": "40"}, {"channel": 44}, 40),
        ],
    )
    def test_auto_or_missing_channel(self, mock_api, config, top_level, expected):
        status = {
            "radio1": {
                "up": True,
                **top_level,
                "config": {"band": "5g", **config},
                "interfaces": [
                    {"ifname": "phy1-ap0", "config": {"ssid": "Example-Net-5G"}}
                ],
            }
        }
        (radio,) = mock_api._parse_wireless_status(status)
        assert radio["channel"] == expected

    def test_legacy_hwmode_from_config_block(self, mock_api):
        """OpenWrt <= 22.03 keeps hwmode in the radio config as well."""
        status = {
            "radio0": {
                "up": True,
                "config": {"hwmode": "11a", "channel": "100", "htmode": "VHT80"},
                "interfaces": [
                    {"ifname": "wlan0", "config": {"ssid": "Example-Net-5G"}}
                ],
            }
        }
        (radio,) = mock_api._parse_wireless_status(status)
        assert radio["hwmode"] == "11a"
        assert radio["channel"] == 100
        assert radio["htmode"] == "VHT80"


# =====================================================================
# SSH fallback: `uci show wireless` parsing and ap_interfaces
# =====================================================================

# `uci show wireless` of a router with one anonymous and one named wifi-iface
# per radio. uci prints a ' inside a value as '\'' (close, escaped quote,
# reopen). Placeholder SSIDs/keys only.
UCI_SHOW_WIRELESS = "\n".join(
    [
        "wireless.radio0=wifi-device",
        "wireless.radio0.type='mac80211'",
        "wireless.radio0.path='platform/soc/18000000.wifi'",
        "wireless.radio0.band='2g'",
        "wireless.radio0.channel='6'",
        "wireless.radio0.htmode='HE20'",
        "wireless.radio0.country='DE'",
        "wireless.radio0.cell_density='0'",
        "wireless.radio1=wifi-device",
        "wireless.radio1.type='mac80211'",
        "wireless.radio1.path='platform/soc/18000000.wifi+1'",
        "wireless.radio1.band='5g'",
        "wireless.radio1.channel='36'",
        "wireless.radio1.htmode='HE80'",
        "wireless.radio1.country='DE'",
        "wireless.@wifi-iface[0]=wifi-iface",
        "wireless.@wifi-iface[0].device='radio0'",
        "wireless.@wifi-iface[0].network='lan'",
        "wireless.@wifi-iface[0].mode='ap'",
        "wireless.@wifi-iface[0].ssid='Example-Net'",
        "wireless.@wifi-iface[0].encryption='sae-mixed'",
        "wireless.@wifi-iface[0].key='placeholder-key'",
        "wireless.@wifi-iface[1]=wifi-iface",
        "wireless.@wifi-iface[1].device='radio1'",
        "wireless.@wifi-iface[1].network='lan'",
        "wireless.@wifi-iface[1].mode='ap'",
        "wireless.@wifi-iface[1].ssid='Example-Net-5G'",
        "wireless.guest_5g=wifi-iface",
        "wireless.guest_5g.device='radio1'",
        "wireless.guest_5g.network='guest'",
        "wireless.guest_5g.mode='ap'",
        "wireless.guest_5g.ssid='Example'\\''s Guest'",
        "wireless.guest_5g.disabled='1'",
    ]
)


def _ssh_only_api(uci_text: str = UCI_SHOW_WIRELESS) -> tuple[OpenWrtAPI, AsyncMock]:
    """API whose rpcd denies every Wi-Fi call, so only the SSH fallback works."""
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="test",
        session=MagicMock(),
        protocol="http",
    )
    api._call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("ACL"))
    ssh = AsyncMock(return_value=(0, uci_text, b""))
    api._asyncssh_run = ssh
    return api, ssh


class TestSshUciShowParsing:
    """AK7: anonymous sections and SSIDs with a single quote."""

    @pytest.mark.asyncio
    async def test_anonymous_sections_are_read(self):
        api, _ssh = _ssh_only_api()
        radios = await api._get_wifi_status_ssh()
        sections = [r["uci_section"] for r in radios]
        assert sections == ["@wifi-iface[0]", "@wifi-iface[1]", "guest_5g"]
        by_section = {r["uci_section"]: r for r in radios}
        anon = by_section["@wifi-iface[0]"]
        assert anon["ifname"] == "@wifi-iface[0]"
        assert anon["name"] == "radio0"
        assert anon["ssid"] == "Example-Net"
        assert anon["band"] == "2.4g"
        assert anon["enabled"] is True

    @pytest.mark.asyncio
    async def test_ssid_with_single_quote_round_trips(self):
        api, _ssh = _ssh_only_api()
        radios = await api._get_wifi_status_ssh()
        guest = next(r for r in radios if r["uci_section"] == "guest_5g")
        assert guest["ssid"] == "Example's Guest"
        assert guest["enabled"] is False
        assert guest["is_guest"] is True

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("'it'\\''s'", "it's"),
            ("''\\'''", "'"),
            ("'Net = 5 GHz'", "Net = 5 GHz"),
            ("'a \"b\" c'", 'a "b" c'),
            ("''", ""),
        ],
    )
    @pytest.mark.asyncio
    async def test_quoted_values(self, raw, expected):
        text = "\n".join(
            [
                "wireless.radio0=wifi-device",
                "wireless.radio0.band='5g'",
                "wireless.default_radio0=wifi-iface",
                "wireless.default_radio0.device='radio0'",
                f"wireless.default_radio0.ssid={raw}",
            ]
        )
        api, _ssh = _ssh_only_api(text)
        (radio,) = await api._get_wifi_status_ssh()
        assert radio["ssid"] == expected


class TestApInterfacesSshFallback:
    """AK7: routers on the SSH fallback fill ap_interfaces from `uci show`."""

    @pytest.mark.asyncio
    async def test_ssh_fallback_fills_ap_interfaces(self):
        api, ssh = _ssh_only_api()
        radios = await api.get_wifi_status()
        assert api._wifi_method == "ssh"
        assert len(radios) == 3
        api._hostapd_ifaces = []

        ifaces = await api.get_ap_interface_details()

        by_name = {i["ifname"]: i for i in ifaces}
        assert list(by_name) == ["@wifi-iface[0]", "@wifi-iface[1]", "guest_5g"]
        anon = by_name["@wifi-iface[0]"]
        assert anon["ssid"] == "Example-Net"
        assert anon["band"] == "2.4g"
        assert anon["channel"] == 6
        assert anon["htmode"] == "HE20"
        assert anon["phy"] == "radio0"
        assert anon["mode"] == "ap"
        assert by_name["guest_5g"]["ssid"] == "Example's Guest"
        assert by_name["guest_5g"]["channel"] == 36
        assert by_name["guest_5g"]["htmode"] == "HE80"
        assert by_name["guest_5g"]["is_guest"] is True
        # Same key set as the UCI branch / iwinfo path
        assert set(anon) >= {
            "ifname", "ssid", "band", "is_guest", "mode", "bssid", "channel",
            "frequency", "txpower", "bitrate", "hwmode", "htmode", "phy",
            "center_chan1", "signal", "noise", "quality", "quality_max",
        }
        # Reuses the `uci show wireless` of this poll: no extra SSH round-trip
        assert ssh.await_count == 1

    @pytest.mark.asyncio
    async def test_ssh_ap_interfaces_feed_the_channel_plan(self):
        from custom_components.openwrt_router.channel_plan import (
            Radio,
            radios_from_ap_interfaces,
        )

        api, _ssh = _ssh_only_api()
        await api.get_wifi_status()
        api._hostapd_ifaces = []
        ifaces = await api.get_ap_interface_details()

        radios = radios_from_ap_interfaces("ap", "AP", ifaces)
        assert sorted(radios, key=lambda r: r.phy) == [
            Radio(entry_id="ap", router="AP", phy="radio0", band="2.4g",
                  channel=6, width=20, center=6),
            Radio(entry_id="ap", router="AP", phy="radio1", band="5g",
                  channel=36, width=80, center=42),
        ]

    @pytest.mark.asyncio
    async def test_ssh_fallback_after_failed_iwinfo_per_device(self):
        """ACL-blocked hostapd candidates: iwinfo per device fails, SSH fills."""
        api, ssh = _ssh_only_api()
        await api.get_wifi_status()
        api._hostapd_ifaces = ["phy0-ap0", "phy1-ap0"]

        ifaces = await api.get_ap_interface_details()

        assert [i["ifname"] for i in ifaces] == [
            "@wifi-iface[0]", "@wifi-iface[1]", "guest_5g",
        ]
        assert ssh.await_count == 1

    @pytest.mark.asyncio
    async def test_failed_ssh_poll_leaves_no_stale_interfaces(self):
        api, ssh = _ssh_only_api()
        await api.get_wifi_status()
        api._hostapd_ifaces = []
        assert await api.get_ap_interface_details()

        # Next poll: SSH fails -> no Wi-Fi method, no leftover interfaces
        ssh.return_value = (1, "", b"uci: Entry not found")
        api._wifi_method = None
        assert await api.get_wifi_status() == []
        assert await api.get_ap_interface_details() == []

    @pytest.mark.asyncio
    async def test_no_ssh_data_without_ssh_method(self):
        """Without the SSH fallback the cache is never consulted."""
        api, ssh = _ssh_only_api()
        api._hostapd_ifaces = []
        api._wifi_method = None
        assert await api.get_ap_interface_details() == []
        assert ssh.await_count == 0

    @pytest.mark.asyncio
    async def test_uci_branch_unchanged(self):
        """The ubus UCI branch still builds the same entries."""
        api, _ssh = _ssh_only_api()
        api._wifi_method = "uci"
        api._hostapd_ifaces = []
        api.get_uci_wireless = AsyncMock(
            return_value={
                "radio1": {".type": "wifi-device", "band": "5g",
                           "channel": "auto", "htmode": "HE80"},
                "default_radio1": {".type": "wifi-iface", ".index": 1,
                                   "device": "radio1", "ssid": "Example-Net-5G"},
            }
        )
        (iface,) = await api.get_ap_interface_details()
        assert iface["ifname"] == "default_radio1"
        assert iface["channel"] is None
        assert iface["band"] == "5g"
        assert iface["htmode"] == "HE80"
        assert iface["mode"] == "ap"


# `uci show wireless` with an `ifname` option, a switched-off radio (DFS
# channel), a switched-off SSID and the secret options a wifi-iface can carry.
# Placeholder SSIDs/secrets only.
UCI_SHOW_WIRELESS_SECRETS = "\n".join(
    [
        "wireless.radio0=wifi-device",
        "wireless.radio0.band='2g'",
        "wireless.radio0.channel='1'",
        "wireless.radio1=wifi-device",
        "wireless.radio1.band='5g'",
        "wireless.radio1.channel='36'",
        "wireless.radio1.htmode='HE80'",
        "wireless.radio2=wifi-device",
        "wireless.radio2.band='5g'",
        "wireless.radio2.channel='100'",
        "wireless.radio2.disabled='1'",
        "wireless.@wifi-iface[0]=wifi-iface",
        "wireless.@wifi-iface[0].device='radio0'",
        "wireless.@wifi-iface[0].mode='ap'",
        "wireless.@wifi-iface[0].ssid='Example-Net'",
        "wireless.@wifi-iface[0].ifname='wlan0'",
        "wireless.@wifi-iface[0].encryption='sae-mixed'",
        "wireless.@wifi-iface[0].key='placeholder-psk-0'",
        "wireless.@wifi-iface[0].sae_password='placeholder-sae-0'",
        "wireless.radius_5g=wifi-iface",
        "wireless.radius_5g.device='radio1'",
        "wireless.radius_5g.mode='ap'",
        "wireless.radius_5g.ssid='Example-Corp'",
        "wireless.radius_5g.encryption='wpa2'",
        "wireless.radius_5g.auth_secret='placeholder-radius-auth'",
        "wireless.radius_5g.acct_secret='placeholder-radius-acct'",
        "wireless.off_5g=wifi-iface",
        "wireless.off_5g.device='radio1'",
        "wireless.off_5g.mode='ap'",
        "wireless.off_5g.ssid='Example-Off'",
        "wireless.off_5g.disabled='1'",
        "wireless.dfs_5g=wifi-iface",
        "wireless.dfs_5g.device='radio2'",
        "wireless.dfs_5g.mode='ap'",
        "wireless.dfs_5g.ssid='Example-DFS'",
        "wireless.dfs_5g.key='placeholder-psk-2'",
    ]
)
_UCI_SECRETS = (
    "placeholder-psk-0",
    "placeholder-sae-0",
    "placeholder-radius-auth",
    "placeholder-radius-acct",
    "placeholder-psk-2",
)


def _strings_in(obj: Any) -> Iterator[str]:
    """Yield every str held in plain containers; other objects are skipped."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _strings_in(key)
            yield from _strings_in(value)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            yield from _strings_in(item)


async def _ssh_poll(uci_text: str) -> tuple[OpenWrtAPI, list[dict[str, Any]]]:
    """One SSH-fallback poll: get_wifi_status(), then the AP interfaces."""
    api, _ssh = _ssh_only_api(uci_text)
    await api.get_wifi_status()
    assert api._wifi_method == "ssh"
    api._hostapd_ifaces = []
    return api, await api.get_ap_interface_details()


class TestUciApInterfaceNameAndState:
    """UCI-derived AP interfaces: `ifname` option, disabled radios and SSIDs."""

    @pytest.mark.asyncio
    async def test_ifname_option_names_the_interface(self):
        """Clients and usteer report the kernel name, so it is the ifname."""
        _api, ifaces = await _ssh_poll(UCI_SHOW_WIRELESS_SECRETS)
        by_ssid = {i["ssid"]: i for i in ifaces}
        named = by_ssid["Example-Net"]
        assert named["ifname"] == "wlan0"
        assert named["uci_section"] == "@wifi-iface[0]"
        assert named["ifname_is_section"] is False
        section = by_ssid["Example-Corp"]
        assert section["ifname"] == "radius_5g"
        assert section["uci_section"] == "radius_5g"
        assert section["ifname_is_section"] is True

    @pytest.mark.asyncio
    async def test_switches_keep_the_section_name(self):
        """wifi_radios (switch unique_id, `uci set`) still use the section."""
        api, _ssh = _ssh_only_api(UCI_SHOW_WIRELESS_SECRETS)
        radios = await api.get_wifi_status()
        named = next(r for r in radios if r["ssid"] == "Example-Net")
        assert named["ifname"] == "@wifi-iface[0]"
        assert named["uci_section"] == "@wifi-iface[0]"

    @pytest.mark.asyncio
    async def test_disabled_radio_and_ssid_are_flagged(self):
        _api, ifaces = await _ssh_poll(UCI_SHOW_WIRELESS_SECRETS)
        assert {i["ssid"]: i["enabled"] for i in ifaces} == {
            "Example-Net": True,
            "Example-Corp": True,
            "Example-Off": False,  # wifi-iface disabled
            "Example-DFS": False,  # wifi-device disabled
        }

    @pytest.mark.asyncio
    async def test_disabled_radios_stay_out_of_the_channel_plan(self):
        from custom_components.openwrt_router.channel_plan import (
            analyze,
            radios_from_ap_interfaces,
        )

        _api, ifaces = await _ssh_poll(UCI_SHOW_WIRELESS_SECRETS)
        radios = radios_from_ap_interfaces("ap", "AP", ifaces)
        # radio2 is off: no radio on channel 100, hence no DFS finding
        assert sorted((r.phy, r.channel) for r in radios) == [
            ("radio0", 1),
            ("radio1", 36),
        ]
        assert analyze(radios) == []

    @pytest.mark.parametrize(
        ("iface_opt", "device_opt", "enabled"),
        [
            ({}, {}, True),
            ({"disabled": "0"}, {"disabled": "0"}, True),
            ({"disabled": "false"}, {}, True),
            ({"disabled": "1"}, {}, False),
            ({"disabled": "true"}, {}, False),
            ({"disabled": "on"}, {}, False),
            ({"disabled": "yes"}, {}, False),
            ({}, {"disabled": "1"}, False),
            ({}, {"disabled": "enabled"}, False),
        ],
    )
    def test_uci_boolean_spellings(self, mock_api, iface_opt, device_opt, enabled):
        """ubus `uci get` and `uci show` both give UCI's boolean strings."""
        values = {
            "radio1": {".type": "wifi-device", "band": "5g", "channel": "36",
                       **device_opt},
            "default_radio1": {".type": "wifi-iface", ".index": 1,
                               "device": "radio1", "ssid": "Example-Net-5G",
                               **iface_opt},
        }
        (iface,) = mock_api._ap_interfaces_from_uci(values)
        assert iface["enabled"] is enabled

    @pytest.mark.asyncio
    async def test_ubus_uci_branch_keeps_section_names(self):
        """Existing AP sensor unique_ids on the ubus UCI path must not change."""
        api, _ssh = _ssh_only_api()
        api._wifi_method = "uci"
        api._hostapd_ifaces = []
        api.get_uci_wireless = AsyncMock(
            return_value={
                "radio1": {".type": "wifi-device", "band": "5g",
                           "channel": "36", "disabled": "1"},
                "cfg033579": {".type": "wifi-iface", ".index": 1,
                              "device": "radio1", "ssid": "Example-Net-5G",
                              "ifname": "wlan1"},
            }
        )
        (iface,) = await api.get_ap_interface_details()
        assert iface["ifname"] == "cfg033579"
        assert iface["uci_section"] == "cfg033579"
        assert iface["ifname_is_section"] is True
        assert iface["enabled"] is False


class TestSshWirelessSecrets:
    """Only the derived AP interfaces stay on the API between polls."""

    @pytest.mark.asyncio
    async def test_no_key_or_password_survives_on_the_instance(self):
        api, ifaces = await _ssh_poll(UCI_SHOW_WIRELESS_SECRETS)
        assert len(ifaces) == 4
        held = list(_strings_in(vars(api)))
        # The scan sees the poll's data (SSIDs of the AP interfaces) ...
        assert any("Example-Corp" in s for s in held)
        # ... but no key, SAE password or RADIUS secret
        assert [x for x in _UCI_SECRETS if any(x in s for s in held)] == []
        # Nor in what the poll hands to the coordinator
        handed = list(_strings_in(ifaces))
        assert [x for x in _UCI_SECRETS if any(x in s for s in handed)] == []

    @pytest.mark.asyncio
    async def test_ssh_data_dropped_when_the_method_leaves_ssh(self):
        """E.g. after the ACL v7 deploy network.wireless status answers."""
        api, _ifaces = await _ssh_poll(UCI_SHOW_WIRELESS_SECRETS)
        api._call = AsyncMock(return_value=WIRELESS_STATUS_25_12)

        await api.get_wifi_status()

        assert api._wifi_method == "wireless"
        held = list(_strings_in(vars(api)))
        assert not any("Example-Corp" in s for s in held)


class TestSshWifiWriteQuoting:
    """`uci set` gets the section as one shell-quoted word."""

    @pytest.mark.parametrize(
        ("section", "enabled", "argument"),
        [
            # [0] is a glob pattern for the remote shell
            ("@wifi-iface[0]", False, "wireless.@wifi-iface[0].disabled=1"),
            ("default_radio0", True, "wireless.default_radio0.disabled=0"),
            ("x;reboot", True, "wireless.x;reboot.disabled=0"),
        ],
    )
    @pytest.mark.asyncio
    async def test_uci_set_argument_is_quoted(self, section, enabled, argument):
        api, ssh = _ssh_only_api()
        ssh.return_value = (0, "", b"")

        assert await api._set_wifi_state_ssh(section, enabled) is True

        (command,) = ssh.await_args.args
        assert command == (
            f"uci set {shlex.quote(argument)} && uci commit wireless && wifi reload"
        )
        assert shlex.split(command)[:4] == ["uci", "set", argument, "&&"]


class TestIsGuestSsid:
    def test_guest(self, mock_api):
        assert mock_api._is_guest_ssid("Guest-WiFi") is True

    def test_not_guest(self, mock_api):
        assert mock_api._is_guest_ssid("HomeNet") is False

    def test_case_insensitive(self, mock_api):
        assert mock_api._is_guest_ssid("GUEST-NET") is True

    def test_visitor(self, mock_api):
        assert mock_api._is_guest_ssid("Visitor-Access") is True


class TestExtractPlatformArchitecture:
    def test_from_target(self, mock_api):
        board = {"release": {"target": "ath79"}}
        assert mock_api._extract_platform_architecture(board) == "ath79"

    def test_from_board_name(self, mock_api):
        board = {"board_name": "glinet,gl-mt3000", "release": {}}
        assert mock_api._extract_platform_architecture(board) == "glinet"

    def test_from_kernel_x86(self, mock_api):
        board = {"kernel": "6.1.0-x86_64", "board_name": "", "release": {}}
        assert mock_api._extract_platform_architecture(board) == "x86_64"

    def test_from_kernel_arm(self, mock_api):
        board = {"kernel": "5.15-ARM", "board_name": "", "release": {}}
        assert mock_api._extract_platform_architecture(board) == "arm"

    def test_unknown_fallback(self, mock_api):
        assert mock_api._extract_platform_architecture({}) == "unknown"


# =====================================================================
# SSL / URL Construction
# =====================================================================


class TestSSLContext:
    def test_http_returns_none(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=80,
            username="root",
            password="test",
            session=session,
            protocol="http",
        )
        assert api._ssl_context is None

    def test_https_returns_context(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=443,
            username="root",
            password="test",
            session=session,
            protocol="https",
        )
        assert api._ssl_context is not None
        assert api._ssl_context.check_hostname is True

    def test_https_insecure(self):
        import ssl

        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=443,
            username="root",
            password="test",
            session=session,
            protocol="https-insecure",
        )
        assert api._ssl_context is not None
        assert api._ssl_context.check_hostname is False
        assert api._ssl_context.verify_mode == ssl.CERT_NONE

    def test_injected_context_is_used_verbatim(self):
        """HA callers inject a pre-built context — no context is built here."""
        import ssl

        session = MagicMock()
        injected = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=443,
            username="root",
            password="test",
            session=session,
            protocol="https",
            ssl_context=injected,
        )
        assert api._ssl_context is injected

    def test_injected_context_ignored_for_http(self):
        import ssl

        session = MagicMock()
        injected = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=80,
            username="root",
            password="test",
            session=session,
            protocol="http",
            ssl_context=injected,
        )
        assert api._ssl_context is None


class TestURLConstruction:
    def test_ipv4(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=80,
            username="root",
            password="test",
            session=session,
            protocol="http",
        )
        assert api._ubus_url == "http://192.168.1.1:80/ubus"

    def test_ipv6(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="::1",
            port=80,
            username="root",
            password="test",
            session=session,
            protocol="http",
        )
        assert api._ubus_url == "http://[::1]:80/ubus"

    def test_https_scheme(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1",
            port=443,
            username="root",
            password="test",
            session=session,
            protocol="https",
        )
        assert api._ubus_url.startswith("https://")


# =====================================================================
# _raw_call Error Handling
# =====================================================================


def _make_error_cm(error):
    """Create a mock async CM whose __aenter__ raises the given error."""
    cm = AsyncMock()
    cm.__aenter__ = AsyncMock(side_effect=error)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


class TestRawCallErrors:
    @pytest.mark.asyncio
    async def test_connection_error(self):
        err = aiohttp.ClientConnectorError(
            connection_key=MagicMock(), os_error=OSError("refused")
        )
        api = _make_api_with_response()
        api._session.post = MagicMock(return_value=_make_error_cm(err))
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtConnectionError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        api = _make_api_with_response()
        api._session.post = MagicMock(
            return_value=_make_error_cm(asyncio.TimeoutError())
        )
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtTimeoutError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_client_error(self):
        api = _make_api_with_response()
        api._session.post = MagicMock(
            return_value=_make_error_cm(aiohttp.ClientError("generic"))
        )
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtConnectionError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_http_403(self):
        api = _make_api_with_response(
            json_data={"jsonrpc": "2.0", "id": 1, "result": [0, {}]},
            status_code=403,
        )
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtAuthError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_http_500(self):
        api = _make_api_with_response(status_code=500)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtResponseError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_json_parse_failure(self):
        api = _make_api_with_response(raise_on_json=True)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtResponseError, match="parse JSON"):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_malformed_result(self):
        api = _make_api_with_response(json_data={"jsonrpc": "2.0", "id": 1})
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtResponseError, match="Malformed"):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_ubus_status_method_not_found(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": [3, None]}
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "nonexistent", {})
        with pytest.raises(OpenWrtMethodNotFoundError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_ubus_status_not_found(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": [4, None]}
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("nosuch", "obj", {})
        with pytest.raises(OpenWrtMethodNotFoundError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_ubus_status_no_data(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": [5, None]}
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("iwinfo", "assoclist", {})
        result = await api._raw_call(payload)
        assert result == {}

    @pytest.mark.asyncio
    async def test_ubus_status_permission_denied(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": [6, None]}
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "info", {})
        with pytest.raises(OpenWrtAuthError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_rpcd_error_minus32002(self):
        """Fix 4: rpcd -32002 must raise OpenWrtAuthError (triggers re-login retry)."""
        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32002, "message": "Access denied"},
        }
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtAuthError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_rpcd_error_minus32002_not_method_not_found(self):
        """Fix 4: OpenWrtMethodNotFoundError must NOT be raised for -32002."""
        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32002, "message": "Access denied"},
        }
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("network.wireless", "status", {})
        try:
            await api._raw_call(payload)
        except OpenWrtAuthError:
            pass  # Expected — fix is in place
        except OpenWrtMethodNotFoundError:
            pytest.fail(
                "Fix 4 regression: -32002 must not raise OpenWrtMethodNotFoundError"
            )

    @pytest.mark.asyncio
    async def test_generic_ubus_error(self):
        envelope = {"jsonrpc": "2.0", "id": 1, "result": [9, None]}
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtResponseError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_generic_jsonrpc_error(self):
        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32600, "message": "Invalid request"},
        }
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtResponseError):
            await api._raw_call(payload)


# =====================================================================
# Session / Authentication
# =====================================================================


class TestLogin:
    @pytest.mark.asyncio
    async def test_login_success(self, mock_api):
        mock_api._token = DEFAULT_SESSION_ID  # Reset
        await mock_api.login()
        assert mock_api._token == MOCK_SESSION_TOKEN
        assert mock_api._login_failure_count == 0

    @pytest.mark.asyncio
    async def test_login_invalid_token(self):
        envelope = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": [0, {"ubus_rpc_session": DEFAULT_SESSION_ID}],
        }
        api = _make_api_with_response(json_data=envelope)
        with pytest.raises(OpenWrtAuthError, match="invalid session token"):
            await api.login()
        assert api._login_failure_count == 1

    @pytest.mark.asyncio
    async def test_login_response_error_becomes_auth_error(self):
        api = _make_api_with_response(status_code=500)
        with pytest.raises(OpenWrtAuthError, match="Login failed"):
            await api.login()
        assert api._login_failure_count == 1

    @pytest.mark.asyncio
    async def test_login_failure_count_resets_on_success(self, mock_api):
        mock_api._login_failure_count = 3
        mock_api._token = DEFAULT_SESSION_ID
        await mock_api.login()
        assert mock_api._login_failure_count == 0


# =====================================================================
# Root-account warning: once per host and process, after login (v1.37.5)
# =====================================================================

_ROOT_WARNING = "Using 'root' as rpcd user"
_LOGIN_OK = {"ubus_rpc_session": MOCK_SESSION_TOKEN}


def _login_api(host="192.168.1.1", username="root", login_result=None):
    """API whose login request returns/raises ``login_result`` (default: ok).

    A list is consumed one item per login attempt (AsyncMock side_effect).
    """
    api = OpenWrtAPI(
        host=host,
        port=80,
        username=username,
        password="test",
        session=MagicMock(),
        protocol="http",
    )
    api._raw_call = AsyncMock(
        side_effect=login_result if login_result is not None else [_LOGIN_OK]
    )
    return api


def _root_warnings(caplog) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and _ROOT_WARNING in r.getMessage()
    ]


class TestRootAccountWarning:
    """Befund 1: every config-entry setup retry builds a new OpenWrtAPI.

    The per-instance latch warned again on every retry, and before the login
    was even attempted - unreachable routers produced 15 warnings in ~60 s.
    """

    @pytest.fixture(autouse=True)
    def _fresh_process(self, caplog):
        # tests/conftest.py resets the process-wide latch before every test.
        caplog.set_level(logging.DEBUG, logger=api_module.__name__)

    @pytest.mark.asyncio
    async def test_once_per_host_across_setup_retries(self, caplog):
        for _ in range(3):  # each setup retry creates a fresh API instance
            assert await _login_api().login() is True
        assert len(_root_warnings(caplog)) == 1

    @pytest.mark.asyncio
    async def test_relogin_on_same_instance_does_not_repeat(self, caplog):
        api = _login_api(login_result=[_LOGIN_OK, _LOGIN_OK])
        await api.login()
        await api.login()  # proactive token refresh
        assert len(_root_warnings(caplog)) == 1

    @pytest.mark.asyncio
    async def test_unreachable_router_never_warns(self, caplog):
        for _ in range(3):
            api = _login_api(login_result=OpenWrtConnectionError("unreachable"))
            with pytest.raises(OpenWrtConnectionError):
                await api.login()
        assert _root_warnings(caplog) == []

    @pytest.mark.asyncio
    async def test_rejected_login_never_warns(self, caplog):
        api = _login_api(login_result=OpenWrtResponseError("ubus error 6"))
        with pytest.raises(OpenWrtAuthError):
            await api.login()
        bad_token = _login_api(login_result=[{"ubus_rpc_session": DEFAULT_SESSION_ID}])
        with pytest.raises(OpenWrtAuthError):
            await bad_token.login()
        assert _root_warnings(caplog) == []

    @pytest.mark.asyncio
    async def test_warns_only_once_the_router_answers(self, caplog):
        down = _login_api(login_result=OpenWrtTimeoutError("timeout"))
        with pytest.raises(OpenWrtTimeoutError):
            await down.login()
        assert _root_warnings(caplog) == []

        assert await _login_api().login() is True
        assert len(_root_warnings(caplog)) == 1

    @pytest.mark.asyncio
    async def test_each_host_warns_once(self, caplog):
        for host in ("192.168.1.1", "192.168.1.2", "192.168.1.1"):
            await _login_api(host=host).login()
        warned = [r.getMessage() for r in _root_warnings(caplog)]
        assert len(warned) == 2
        assert "192.168.1.1" in warned[0]
        assert "192.168.1.2" in warned[1]

    @pytest.mark.asyncio
    async def test_dedicated_user_never_warns(self, caplog):
        assert await _login_api(username="hass").login() is True
        assert _root_warnings(caplog) == []


class TestSessionDestroyOnRelogin:
    """Regression: re-login must destroy the previous rpcd session.

    Without this, every re-login (proactive refresh + ACL -32002 retries) left a
    long-lived orphan session behind. They accumulated and leaked rpcd memory
    until the router OOM-killed processes — the root cause of the camera outage.
    """

    _OLD = "OLDSESSIONOLDSESSIONOLDSESSION01"

    def _api_with_raw(self, recorded: list):
        api = _make_api_with_response(json_data={})

        async def _raw(payload):
            recorded.append(payload["params"])
            if payload["params"][2] == "login":
                return {"ubus_rpc_session": MOCK_SESSION_TOKEN}
            return {}

        api._raw_call = AsyncMock(side_effect=_raw)
        return api

    @pytest.mark.asyncio
    async def test_relogin_destroys_previous_session(self):
        calls: list = []
        api = self._api_with_raw(calls)
        api._token = self._OLD  # a real, non-default session is active

        assert await api.login() is True
        assert api._token == MOCK_SESSION_TOKEN

        destroys = [p for p in calls if p[2] == "destroy"]
        assert len(destroys) == 1
        params = destroys[0]
        assert params[0] == MOCK_SESSION_TOKEN  # authed with the NEW session
        assert params[1] == "session"
        assert params[3] == {"ubus_rpc_session": self._OLD}

    @pytest.mark.asyncio
    async def test_first_login_does_not_destroy(self):
        calls: list = []
        api = self._api_with_raw(calls)
        api._token = DEFAULT_SESSION_ID  # nothing to free yet

        await api.login()
        assert [p for p in calls if p[2] == "destroy"] == []

    @pytest.mark.asyncio
    async def test_destroy_failure_does_not_break_login(self):
        api = _make_api_with_response(json_data={})

        async def _raw(payload):
            if payload["params"][2] == "login":
                return {"ubus_rpc_session": MOCK_SESSION_TOKEN}
            raise OpenWrtConnectionError("router briefly unreachable")

        api._raw_call = AsyncMock(side_effect=_raw)
        api._token = self._OLD

        # destroy raises internally but must be swallowed
        assert await api.login() is True
        assert api._token == MOCK_SESSION_TOKEN

    @pytest.mark.asyncio
    async def test_async_close_destroys_active_session(self):
        calls: list = []
        api = self._api_with_raw(calls)
        api._token = MOCK_SESSION_TOKEN

        await api.async_close()

        destroys = [p for p in calls if p[2] == "destroy"]
        assert len(destroys) == 1
        assert destroys[0][3] == {"ubus_rpc_session": MOCK_SESSION_TOKEN}
        assert api._token == DEFAULT_SESSION_ID


class TestAutoRelogin:
    @pytest.mark.asyncio
    async def test_relogin_on_auth_error(self, mock_api):
        """_call should re-login and retry when first call returns auth error."""
        call_count = 0

        async def _side_effect(payload):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise OpenWrtAuthError("expired")
            return MOCK_BOARD_INFO

        mock_api._raw_call = AsyncMock(side_effect=_side_effect)
        mock_api.login = AsyncMock()

        result = await mock_api._call("system", "board", {})
        assert result == MOCK_BOARD_INFO
        mock_api.login.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_no_relogin_when_disabled(self, mock_api):
        mock_api._raw_call = AsyncMock(side_effect=OpenWrtAuthError("expired"))
        mock_api.login = AsyncMock()

        with pytest.raises(OpenWrtAuthError):
            await mock_api._call("system", "board", {}, retry_on_auth=False)
        mock_api.login.assert_not_awaited()


class TestAclBlockCache:
    """ACL-blocked methods are cached so they stop triggering re-logins.

    On ACL-restricted routers a -32002 on every poll used to re-login each
    time, spawning rpcd sessions endlessly. Once a method is confirmed blocked
    (authenticated OK but still denied) it must be remembered and short-circuited.
    """

    @pytest.mark.asyncio
    async def test_blocked_method_cached_and_skips_relogin(self, mock_api):
        import time

        mock_api._token_expires_at = (
            time.monotonic() + 3600
        )  # valid → no proactive refresh
        mock_api._raw_call = AsyncMock(side_effect=OpenWrtAuthError("rpcd -32002"))
        mock_api.login = AsyncMock()

        # First call: one confirming re-login, still denied → cached + MethodNotFound
        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("hostapd.phy0-ap0", "get_clients", {})
        assert ("hostapd.phy0-ap0", "get_clients") in mock_api._acl_blocked
        assert mock_api.login.await_count == 1

        # Second call: short-circuited, NO further re-login
        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("hostapd.phy0-ap0", "get_clients", {})
        assert mock_api.login.await_count == 1

    @pytest.mark.asyncio
    async def test_blocked_file_path_does_not_block_other_paths(self, mock_api):
        """A denied file path must not short-circuit reads of permitted paths.

        rpcd enforces file ACLs per PATH. Regression: the cache keyed on
        (object, method) only, so ONE uncovered /proc entry sent every
        file/read of the session into the SSH fallback — massively raising
        router load on routers with an outdated ACL.
        """
        import time

        mock_api._token_expires_at = time.monotonic() + 3600
        mock_api.login = AsyncMock()

        blocked_path = "/proc/net/nf_conntrack"

        async def _raw(payload):
            params = payload["params"][3]
            if params.get("path") == blocked_path:
                raise OpenWrtAuthError("rpcd -32002")
            return {"data": "ok"}

        mock_api._raw_call = AsyncMock(side_effect=_raw)

        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("file", "read", {"path": blocked_path})
        assert ("file", "read", blocked_path) in mock_api._acl_blocked

        # A different, permitted path must still go through.
        result = await mock_api._call("file", "read", {"path": "/proc/net/arp"})
        assert result == {"data": "ok"}

        # The blocked path stays short-circuited (no new _raw_call).
        raw_calls_before = mock_api._raw_call.await_count
        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("file", "read", {"path": blocked_path})
        assert mock_api._raw_call.await_count == raw_calls_before

    @pytest.mark.asyncio
    async def test_blocked_uci_config_does_not_block_other_configs(self, mock_api):
        """A denied uci config must not short-circuit reads of permitted configs.

        rpcd enforces uci ACLs per CONFIG file. Regression (v1.26.4): the
        cache keyed on ("uci", "get") only, so the denied ddns probe killed
        the uci wireless fallback for the rest of the session and pushed
        every later poll into the SSH fallback.
        """
        import time

        mock_api._token_expires_at = time.monotonic() + 3600
        mock_api.login = AsyncMock()

        async def _raw(payload):
            params = payload["params"][3]
            if params.get("config") == "ddns":
                raise OpenWrtAuthError("rpcd -32002")
            return {"values": {}}

        mock_api._raw_call = AsyncMock(side_effect=_raw)

        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("uci", "get", {"config": "ddns"})
        assert ("uci", "get", "ddns") in mock_api._acl_blocked

        # A different, permitted config must still go through.
        result = await mock_api._call("uci", "get", {"config": "wireless"})
        assert result == {"values": {}}

        # The blocked config stays short-circuited (no new _raw_call).
        raw_calls_before = mock_api._raw_call.await_count
        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api._call("uci", "get", {"config": "ddns"})
        assert mock_api._raw_call.await_count == raw_calls_before

    @pytest.mark.asyncio
    async def test_transient_auth_error_is_not_cached(self, mock_api):
        import time

        mock_api._token_expires_at = time.monotonic() + 3600
        calls = {"n": 0}

        async def _raw(payload):
            calls["n"] += 1
            if calls["n"] == 1:
                raise OpenWrtAuthError("expired session")
            return {"ok": True}

        mock_api._raw_call = AsyncMock(side_effect=_raw)
        mock_api.login = AsyncMock()

        result = await mock_api._call("system", "board", {})
        assert result == {"ok": True}
        assert ("system", "board") not in mock_api._acl_blocked


class TestEnsureFreshToken:
    @pytest.mark.asyncio
    async def test_no_refresh_when_token_valid(self, mock_api):
        """No re-login when token has plenty of time left."""
        import time

        mock_api._token_expires_at = time.monotonic() + 3600
        mock_api.login = AsyncMock()
        await mock_api._ensure_fresh_token()
        mock_api.login.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_refresh_when_token_expired(self, mock_api):
        """Re-login triggered when token is past expiry."""
        import time

        mock_api._token_expires_at = time.monotonic() - 1  # already expired
        mock_api.login = AsyncMock()
        await mock_api._ensure_fresh_token()
        mock_api.login.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_refresh_within_margin(self, mock_api):
        """Re-login triggered when within SESSION_REFRESH_MARGIN_SECONDS."""
        import time
        from custom_components.openwrt_router.const import (
            SESSION_REFRESH_MARGIN_SECONDS,
        )

        mock_api._token_expires_at = (
            time.monotonic() + SESSION_REFRESH_MARGIN_SECONDS - 10
        )
        mock_api.login = AsyncMock()
        await mock_api._ensure_fresh_token()
        mock_api.login.assert_awaited_once()


# =====================================================================
# High-Level API Methods
# =====================================================================


class TestGetRouterInfo:
    @pytest.mark.asyncio
    async def test_success(self, mock_api):
        result = await mock_api.get_router_info()
        assert result["model"] == "GL.iNet GL-MT3000"
        assert result["hostname"] == "OpenWrt-Dev"
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["platform_architecture"] == "mediatek/filogic"

    @pytest.mark.asyncio
    async def test_access_denied_fallback(self, mock_api):
        mock_api._call = AsyncMock(side_effect=OpenWrtAuthError("access denied"))
        result = await mock_api.get_router_info()
        assert result["model"] == "OpenWrt Router"


class TestGetRouterStatus:
    @pytest.mark.asyncio
    async def test_success(self, mock_api):
        result = await mock_api.get_router_status()
        assert result["uptime"] == 86400
        # 65536 / 65536 * 100 = 100.0
        assert result["cpu_load"] == 100.0
        # 131072 / 65536 * 100 = 200.0
        assert result["cpu_load_5min"] == 200.0
        # 98304 / 65536 * 100 = 150.0
        assert result["cpu_load_15min"] == 150.0
        assert result["memory"]["total"] == 268435456


# /proc/cpuinfo samples (synthetic, real layouts). aarch64 has no "model name"
# line, only one "processor\t: N" block per core.
CPUINFO_AARCH64_DUAL = (
    "processor\t: 0\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm crc32 cpuid\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU part\t: 0xd03\n"
    "CPU revision\t: 4\n"
    "\n"
    "processor\t: 1\n"
    "BogoMIPS\t: 26.00\n"
    "Features\t: fp asimd evtstrm crc32 cpuid\n"
    "CPU implementer\t: 0x41\n"
    "CPU architecture: 8\n"
    "CPU part\t: 0xd03\n"
    "CPU revision\t: 4\n"
    "\n"
)
CPUINFO_MIPS_SINGLE = (
    "system type\t\t: Generic MIPS SoC\n"
    "machine\t\t\t: Generic\n"
    "processor\t\t: 0\n"
    "cpu model\t\t: MIPS 24Kc V7.4\n"
    "BogoMIPS\t\t: 265.42\n"
)
# Older 32-bit ARM kernels add a capitalised "Processor" model line.
CPUINFO_ARMV7_DUAL = (
    "Processor\t: ARMv7 Processor rev 5 (v7l)\n"
    "processor\t: 0\n"
    "BogoMIPS\t: 38.40\n"
    "\n"
    "processor\t: 1\n"
    "BogoMIPS\t: 38.40\n"
    "\n"
    "Hardware\t: Generic DT based system\n"
)

# Load average 1.22 / 1.00 / 0.50 as system/info reports it (* 65536)
LOAD_1_22 = [79954, 65536, 32768]


def _status_ubus(cpuinfo, load=None) -> AsyncMock:
    """_call stub for get_router_status.

    ``cpuinfo`` is the /proc/cpuinfo text, or an exception instance to raise
    for file/read on that path.
    """

    async def _call(obj, method, params, *args, **kwargs):
        if (obj, method) == ("system", "info"):
            return {"uptime": 100, "load": list(load or LOAD_1_22), "memory": {}}
        if (obj, method) == ("file", "read") and params == {"path": "/proc/cpuinfo"}:
            if isinstance(cpuinfo, Exception):
                raise cpuinfo
            return {"data": cpuinfo}
        raise AssertionError(f"unexpected ubus call {obj}/{method} {params}")

    return AsyncMock(side_effect=_call)


def _cpuinfo_reads(call_mock: AsyncMock) -> int:
    return sum(
        1
        for c in call_mock.await_args_list
        if c.args[:3] == ("file", "read", {"path": "/proc/cpuinfo"})
    )


class TestParseCpuinfoCores:
    """One "processor : N" line per logical CPU; anything else counts 0."""

    @pytest.mark.parametrize(
        ("text", "cores"),
        [
            (CPUINFO_AARCH64_DUAL, 2),
            (CPUINFO_MIPS_SINGLE, 1),
            (CPUINFO_ARMV7_DUAL, 2),  # "Processor : ARMv7 ..." is not a core
            ("", 0),
            ("garbage\nno cpu here\n", 0),
            ("processor\t: \nprocessors\t: 4\n", 0),  # malformed lines
        ],
        ids=["aarch64-2", "mips-1", "armv7-model-line", "empty", "garbage", "malformed"],
    )
    def test_counts_processor_lines(self, text, cores):
        assert api_module._parse_cpuinfo_cores(text) == cores


class TestCpuLoadPerCore:
    """Befund 4: system/info load is the run-queue average, not % of the CPU.

    A load average of 1.22 on a dual-core router is 61 % of its capacity, not
    122 %. The core count comes from /proc/cpuinfo (ACL v7), read once per API
    instance; without it the old un-normalised value is kept (1 core).
    """

    @pytest.mark.asyncio
    async def test_dual_core_halves_the_percentage(self, mock_api):
        mock_api._call = _status_ubus(CPUINFO_AARCH64_DUAL)

        result = await mock_api.get_router_status()

        assert result["cpu_cores"] == 2
        assert result["cpu_load"] == 61.0
        assert result["cpu_load_5min"] == 50.0
        assert result["cpu_load_15min"] == 25.0
        assert result["load_average"] == [1.22, 1.0, 0.5]
        assert result["load"] == LOAD_1_22  # raw values unchanged

    @pytest.mark.asyncio
    async def test_single_core_keeps_the_percentage(self, mock_api):
        mock_api._call = _status_ubus(CPUINFO_MIPS_SINGLE)

        result = await mock_api.get_router_status()

        assert result["cpu_cores"] == 1
        assert result["cpu_load"] == 122.0
        assert result["load_average"] == [1.22, 1.0, 0.5]

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "cpuinfo",
        [
            "",
            "garbage\n",
            OpenWrtMethodNotFoundError("rpcd ACL blocks file/read//proc/cpuinfo"),
            OpenWrtAuthError("access denied"),
            OpenWrtResponseError("malformed"),
            OpenWrtTimeoutError("timeout"),
            OpenWrtConnectionError("refused"),
        ],
        ids=[
            "empty",
            "malformed",
            "not-permitted",
            "auth",
            "response",
            "timeout",
            "connection",
        ],
    )
    async def test_unknown_core_count_falls_back_to_one(self, mock_api, cpuinfo):
        mock_api._call = _status_ubus(cpuinfo)

        result = await mock_api.get_router_status()

        assert result["cpu_cores"] is None
        assert result["cpu_load"] == 122.0
        assert result["cpu_load_5min"] == 100.0
        assert result["load_average"] == [1.22, 1.0, 0.5]

    @pytest.mark.asyncio
    async def test_core_count_is_read_once(self, mock_api):
        mock_api._call = _status_ubus(CPUINFO_AARCH64_DUAL)

        for _ in range(3):
            result = await mock_api.get_router_status()

        assert result["cpu_load"] == 61.0
        assert _cpuinfo_reads(mock_api._call) == 1

    @pytest.mark.asyncio
    async def test_failure_is_not_retried_every_poll(self, mock_api):
        mock_api._call = _status_ubus(OpenWrtMethodNotFoundError("blocked"))

        for _ in range(3):
            result = await mock_api.get_router_status()

        assert result["cpu_cores"] is None
        assert _cpuinfo_reads(mock_api._call) == 1

    @pytest.mark.asyncio
    async def test_permanent_failure_is_retried_after_the_interval(self, mock_api):
        mock_api._call = _status_ubus(OpenWrtMethodNotFoundError("blocked"))
        await mock_api.get_router_status()
        assert mock_api._cpu_cores_retry_at - api_module.time.monotonic() > (
            api_module.CPU_CORES_RETRY_INTERVAL - 60
        )

        # Interval elapsed and the ACL was meanwhile fixed by hand
        mock_api._cpu_cores_retry_at -= api_module.CPU_CORES_RETRY_INTERVAL + 1
        mock_api._call = _status_ubus(CPUINFO_AARCH64_DUAL)
        result = await mock_api.get_router_status()

        assert result["cpu_cores"] == 2
        assert result["cpu_load"] == 61.0
        assert _cpuinfo_reads(mock_api._call) == 1

    @pytest.mark.asyncio
    async def test_due_retry_bypasses_the_cached_acl_denial(self, mock_api):
        """A cached ACL denial must not swallow the hourly retry."""
        key = mock_api._acl_cache_key(
            "file", "read", {"path": api_module.PROC_CPUINFO_PATH}
        )
        mock_api._acl_blocked.add(key)
        status = _status_ubus(CPUINFO_AARCH64_DUAL)

        async def _call(obj, method, params, *args, **kwargs):
            if (obj, method) == ("file", "read"):
                assert key not in mock_api._acl_blocked
            return await status(obj, method, params, *args, **kwargs)

        mock_api._call = AsyncMock(side_effect=_call)
        result = await mock_api.get_router_status()

        assert result["cpu_cores"] == 2

    @pytest.mark.asyncio
    async def test_response_error_is_retried_sooner(self, mock_api):
        mock_api._call = _status_ubus(OpenWrtResponseError("HTTP 502"))
        await mock_api.get_router_status()

        remaining = mock_api._cpu_cores_retry_at - api_module.time.monotonic()
        assert 0 < remaining <= api_module.CPU_CORES_TRANSIENT_RETRY_INTERVAL

    @pytest.mark.asyncio
    async def test_transient_failure_is_retried_sooner(self, mock_api):
        mock_api._call = _status_ubus(OpenWrtTimeoutError("timeout"))
        await mock_api.get_router_status()

        remaining = mock_api._cpu_cores_retry_at - api_module.time.monotonic()
        assert 0 < remaining <= api_module.CPU_CORES_TRANSIENT_RETRY_INTERVAL
        assert (
            api_module.CPU_CORES_TRANSIENT_RETRY_INTERVAL
            < api_module.CPU_CORES_RETRY_INTERVAL
        )

    @pytest.mark.asyncio
    async def test_reset_acl_blocked_rearms_the_probe(self, mock_api):
        """After an ACL (re)deploy the core count is probed again at once."""
        mock_api._call = _status_ubus(OpenWrtMethodNotFoundError("blocked"))
        await mock_api.get_router_status()

        mock_api.reset_acl_blocked()
        mock_api._call = _status_ubus(CPUINFO_AARCH64_DUAL)
        result = await mock_api.get_router_status()

        assert result["cpu_cores"] == 2
        assert _cpuinfo_reads(mock_api._call) == 1

    @pytest.mark.asyncio
    async def test_known_core_count_survives_reset_acl_blocked(self, mock_api):
        mock_api._call = _status_ubus(CPUINFO_AARCH64_DUAL)
        await mock_api.get_router_status()

        mock_api.reset_acl_blocked()
        await mock_api.get_router_status()

        assert _cpuinfo_reads(mock_api._call) == 1

    @pytest.mark.asyncio
    async def test_not_probed_when_system_info_fails(self, mock_api):
        call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("no system/info"))
        mock_api._call = call

        with pytest.raises(OpenWrtMethodNotFoundError):
            await mock_api.get_router_status()

        assert _cpuinfo_reads(call) == 0

    @pytest.mark.asyncio
    async def test_ssh_fallback_is_not_normalised(self, mock_api):
        """The SSH script computes its own percentage — passed through as-is."""
        call = AsyncMock(side_effect=OpenWrtAuthError("system/info denied"))
        mock_api._call = call
        ssh_status = {
            "uptime": 5,
            "load": [0, 0, 0],
            "cpu_load": 80.0,
            "cpu_load_5min": 70.0,
            "cpu_load_15min": 60.0,
            "memory": {},
        }
        with patch.object(
            mock_api, "_get_router_status_ssh", AsyncMock(return_value=ssh_status)
        ):
            result = await mock_api.get_router_status()

        assert result["cpu_load"] == 80.0
        assert result.get("cpu_cores") is None
        assert _cpuinfo_reads(call) == 0


class TestGetDhcpLeases:
    @pytest.mark.asyncio
    async def test_success(self, mock_api):
        leases = await mock_api.get_dhcp_leases()
        assert "B8:27:EB:AA:BB:01" in leases
        assert leases["B8:27:EB:AA:BB:01"]["ip"] == "192.168.1.101"


class TestTestConnection:
    @pytest.mark.asyncio
    async def test_success(self, mock_api):
        result = await mock_api.test_connection()
        assert result["model"] == "GL.iNet GL-MT3000"


class TestSetWifiState:
    @pytest.mark.asyncio
    async def test_enable(self, mock_api):
        result = await mock_api.set_wifi_state("default_radio0", enabled=True)
        assert result is True

    @pytest.mark.asyncio
    async def test_disable(self, mock_api):
        result = await mock_api.set_wifi_state("default_radio0", enabled=False)
        assert result is True


class TestReloadWifi:
    @pytest.mark.asyncio
    async def test_success(self, mock_api):
        result = await mock_api.reload_wifi()
        assert result is True


class TestNetworkReloadWarning:
    """Befund 5: rpcd ACLs before v7 have no network/reload.

    The Wi-Fi switch still works: uci/commit makes rpcd emit ``config.change``
    and procd's reload trigger for ``wireless`` re-applies the radios. The
    missing network/reload must not warn on every switch.
    """

    _BLOCKED = OpenWrtMethodNotFoundError("rpcd ACL blocks network/reload")

    @staticmethod
    def _ubus(reload_error: Exception) -> AsyncMock:
        async def _call(obj, method, params, *args, **kwargs):
            if (obj, method) == ("network", "reload"):
                raise reload_error
            return {}

        return AsyncMock(side_effect=_call)

    @staticmethod
    def _warnings(caplog) -> list[logging.LogRecord]:
        return [r for r in caplog.records if r.levelno >= logging.WARNING]

    @pytest.mark.asyncio
    async def test_switch_applied_by_commit_does_not_warn(self, mock_api, caplog):
        caplog.set_level(logging.DEBUG, logger=api_module.__name__)
        mock_api._call = self._ubus(self._BLOCKED)

        assert await mock_api.set_wifi_state("guest_radio0", enabled=False) is True

        calls = [c.args[:2] for c in mock_api._call.await_args_list]
        assert calls == [("uci", "set"), ("uci", "commit"), ("network", "reload")]
        assert self._warnings(caplog) == []
        assert any(
            r.levelno == logging.DEBUG and "network.reload" in r.getMessage()
            for r in caplog.records
        )

    @pytest.mark.parametrize(
        "reload_error",
        [
            OpenWrtTimeoutError("network/reload timed out"),
            OpenWrtConnectionError("connection dropped"),
            OpenWrtAuthError("auth backoff"),
            OpenWrtResponseError("bad response"),
        ],
    )
    @pytest.mark.asyncio
    async def test_reload_failure_after_commit_is_not_a_commit_failure(
        self, mock_api, caplog, reload_error
    ):
        """The commit applied the change; a failing reload must not undo success."""
        caplog.set_level(logging.DEBUG, logger=api_module.__name__)
        mock_api._call = self._ubus(reload_error)

        assert await mock_api.set_wifi_state("guest_radio0", enabled=True) is True

        calls = [c.args[:2] for c in mock_api._call.await_args_list]
        assert calls == [("uci", "set"), ("uci", "commit"), ("network", "reload")]
        assert self._warnings(caplog) == []

    @pytest.mark.asyncio
    async def test_reload_button_still_warns(self, mock_api, caplog):
        """A bare reload (button) applies nothing without network/reload."""
        caplog.set_level(logging.DEBUG, logger=api_module.__name__)
        mock_api._call = self._ubus(self._BLOCKED)

        assert await mock_api.reload_wifi() is False

        assert any(
            "network.reload not available" in r.getMessage()
            for r in self._warnings(caplog)
        )


class TestReboot:
    @pytest.mark.asyncio
    async def test_ubus_reboot(self, mock_api):
        with patch.object(mock_api, "_call", AsyncMock(return_value={})) as call:
            assert await mock_api.reboot() is True
        call.assert_awaited_once_with("system", "reboot", {})

    @pytest.mark.asyncio
    async def test_falls_back_to_ssh_when_ubus_blocked(self, mock_api):
        ssh = AsyncMock(return_value=(0, "", b""))
        with (
            patch.object(
                mock_api,
                "_call",
                AsyncMock(side_effect=OpenWrtMethodNotFoundError("no system/reboot")),
            ),
            patch.object(mock_api, "_run_ssh_detached", ssh),
        ):
            assert await mock_api.reboot() is True
        assert "reboot" in ssh.await_args.args[0]

    @pytest.mark.asyncio
    async def test_falls_back_to_ssh_on_timeout(self, mock_api):
        # The router can drop the connection while going down — inconclusive,
        # so the SSH fallback still gets its turn.
        ssh = AsyncMock(return_value=(0, "", b""))
        with (
            patch.object(
                mock_api, "_call", AsyncMock(side_effect=OpenWrtTimeoutError("gone"))
            ),
            patch.object(mock_api, "_run_ssh_detached", ssh),
        ):
            assert await mock_api.reboot() is True
        ssh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_when_both_paths_fail(self, mock_api):
        with (
            patch.object(
                mock_api, "_call", AsyncMock(side_effect=OpenWrtAuthError("acl"))
            ),
            patch.object(
                mock_api,
                "_run_ssh_detached",
                AsyncMock(return_value=(255, "", b"Permission denied")),
            ),
        ):
            assert await mock_api.reboot() is False


class TestBuildCall:
    def test_payload_structure(self, mock_api):
        payload = mock_api._build_call("system", "board", {"foo": "bar"})
        assert payload["jsonrpc"] == "2.0"
        assert payload["method"] == "call"
        params = payload["params"]
        assert params[0] == MOCK_SESSION_TOKEN  # token
        assert params[1] == "system"
        assert params[2] == "board"
        assert params[3] == {"foo": "bar"}

    def test_default_session(self, mock_api):
        payload = mock_api._build_call("session", "login", {}, use_default_session=True)
        assert payload["params"][0] == DEFAULT_SESSION_ID

    def test_rpc_id_increments(self, mock_api):
        p1 = mock_api._build_call("a", "b", {})
        p2 = mock_api._build_call("a", "b", {})
        assert p2["id"] > p1["id"]


# =====================================================================
# Fix 3: luci-rpc DHCP Leases — dhcp_leases key (OpenWrt 25)
# =====================================================================


class TestGetDhcpLeasesLuciRpc:
    """Fix 3: _get_dhcp_leases_luci_rpc handles dhcp_leases/leases/list responses."""

    @pytest.mark.asyncio
    async def test_openwrt25_dhcp_leases_key(self, mock_api):
        """Fix 3: OpenWrt 25 returns 'dhcp_leases' key — must be parsed correctly."""
        result = {
            "dhcp_leases": [
                {
                    "macaddr": "aa:bb:cc:dd:ee:01",
                    "ipaddr": "192.168.1.101",
                    "hostname": "host1",
                    "expires": 1741700000,
                },
            ]
        }
        mock_api._call = AsyncMock(return_value=result)
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert "AA:BB:CC:DD:EE:01" in leases
        assert leases["AA:BB:CC:DD:EE:01"]["ip"] == "192.168.1.101"
        assert leases["AA:BB:CC:DD:EE:01"]["hostname"] == "host1"
        assert leases["AA:BB:CC:DD:EE:01"]["expires"] == 1741700000

    @pytest.mark.asyncio
    async def test_legacy_leases_key(self, mock_api):
        """Fix 3: Older OpenWrt uses 'leases' key — must still work."""
        result = {
            "leases": [
                {
                    "macaddr": "bb:cc:dd:ee:ff:01",
                    "ipaddr": "192.168.1.102",
                    "hostname": "host2",
                    "expires": 1741700001,
                },
            ]
        }
        mock_api._call = AsyncMock(return_value=result)
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert "BB:CC:DD:EE:FF:01" in leases
        assert leases["BB:CC:DD:EE:FF:01"]["hostname"] == "host2"

    @pytest.mark.asyncio
    async def test_direct_list_response(self, mock_api):
        """Fix 3: Direct list response (no wrapper key) also works."""
        result = [
            {
                "macaddr": "cc:dd:ee:ff:00:01",
                "ipaddr": "192.168.1.103",
                "hostname": "host3",
                "expires": 0,
            },
        ]
        mock_api._call = AsyncMock(return_value=result)
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert "CC:DD:EE:FF:00:01" in leases

    @pytest.mark.asyncio
    async def test_dhcp_leases_takes_priority_over_leases(self, mock_api):
        """Fix 3: 'dhcp_leases' key takes priority when both are present."""
        result = {
            "dhcp_leases": [
                {
                    "macaddr": "aa:00:00:00:00:01",
                    "ipaddr": "10.0.0.1",
                    "hostname": "new",
                    "expires": 100,
                },
            ],
            "leases": [
                {
                    "macaddr": "bb:00:00:00:00:02",
                    "ipaddr": "10.0.0.2",
                    "hostname": "old",
                    "expires": 100,
                },
            ],
        }
        mock_api._call = AsyncMock(return_value=result)
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert "AA:00:00:00:00:01" in leases
        assert "BB:00:00:00:00:02" not in leases  # dhcp_leases wins

    @pytest.mark.asyncio
    async def test_empty_dhcp_leases_list(self, mock_api):
        """Fix 3: Empty dhcp_leases list returns empty dict, no crash."""
        result = {"dhcp_leases": []}
        mock_api._call = AsyncMock(return_value=result)
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert leases == {}

    @pytest.mark.asyncio
    async def test_call_error_returns_empty(self, mock_api):
        """Fix 3: If _call raises, returns {} gracefully."""
        mock_api._call = AsyncMock(side_effect=OpenWrtAuthError("blocked"))
        leases = await mock_api._get_dhcp_leases_luci_rpc()
        assert leases == {}


# =====================================================================
# get_services — rpcd rc/list leak (v1.28.4)
# =====================================================================

# Shapes as returned by OpenWrt 25.12.1 (rpcd 2025.12.03, procd 2026.03.13).
_RC_LIST_SKIP_RUNNING = {
    "dnsmasq": {"start": 19, "enabled": True},
    "dropbear": {"start": 19, "stop": 50, "enabled": True},
    "firewall": {"start": 19, "enabled": True},
    "odhcpd": {"start": 35, "stop": 85, "enabled": False},
}
_PROCD_SERVICE_LIST = {
    "cron": {},
    "dnsmasq": {"instances": {"cfg01411c": {"running": True, "pid": 3820}}},
    "dropbear": {"instances": {"instance1": {"running": True, "pid": 1}}},
    "firewall": {},  # fw4 runs no procd instance — rc/list said running=false
}


class TestGetServicesRcListLeak:
    """rpcd < 2026-05-31 leaks ~4.7 KB per rc/list call (upstream d06d2a8).

    Measured on aP4 (rpcd 2025.12.03): 500x rc/list -> +2320 kB rpcd RSS,
    300x procd service/list -> +0 kB. Polling rc/list every cycle grew rpcd
    to 110 MB within 17 days. rc/list must therefore not run per poll.
    """

    @staticmethod
    def _calls(api, obj, method):
        return [
            c for c in api._call.await_args_list if c.args[:2] == (obj, method)
        ]

    @staticmethod
    def _ubus(rc_list=None, service_list=None):
        async def _call(obj, method, params, *args, **kwargs):
            if (obj, method) == ("rc", "list"):
                if isinstance(rc_list, Exception):
                    raise rc_list
                return rc_list
            if (obj, method) == ("service", "list"):
                if isinstance(service_list, Exception):
                    raise service_list
                return service_list
            raise AssertionError(f"unexpected ubus call {obj}/{method}")

        return AsyncMock(side_effect=_call)

    @pytest.mark.asyncio
    async def test_rc_list_not_called_every_poll(self, mock_api):
        mock_api._call = self._ubus(_RC_LIST_SKIP_RUNNING, _PROCD_SERVICE_LIST)

        for _ in range(10):
            await mock_api.get_services(names=["dnsmasq", "firewall"])

        rc_calls = self._calls(mock_api, "rc", "list")
        assert len(rc_calls) == 1
        # No per-script "running" fork either.
        assert rc_calls[0].args[2] == {"skip_running_check": True}
        assert len(self._calls(mock_api, "service", "list")) == 10

    @pytest.mark.asyncio
    async def test_running_from_procd_enabled_from_rc(self, mock_api):
        mock_api._call = self._ubus(_RC_LIST_SKIP_RUNNING, _PROCD_SERVICE_LIST)

        services = await mock_api.get_services()
        by_name = {s["name"]: s for s in services}

        assert by_name["dnsmasq"] == {
            "name": "dnsmasq",
            "running": True,
            "enabled": True,
        }
        # Instance-less procd service and rc-only script both stay listed,
        # so their switch entities do not vanish.
        assert by_name["firewall"]["running"] is False
        assert by_name["firewall"]["enabled"] is True
        assert by_name["odhcpd"] == {
            "name": "odhcpd",
            "running": False,
            "enabled": False,
        }
        assert by_name["cron"]["enabled"] is None  # procd only, no init script

    @pytest.mark.asyncio
    async def test_rc_list_refreshed_after_interval(self, mock_api):
        mock_api._call = self._ubus(_RC_LIST_SKIP_RUNNING, _PROCD_SERVICE_LIST)
        await mock_api.get_services()

        mock_api._rc_enabled_fetched_at -= RC_LIST_REFRESH_INTERVAL + 1
        await mock_api.get_services()

        assert len(self._calls(mock_api, "rc", "list")) == 2

    @pytest.mark.asyncio
    async def test_rc_list_unavailable_is_throttled_too(self, mock_api):
        mock_api._call = self._ubus(
            OpenWrtMethodNotFoundError("rc not found"), _PROCD_SERVICE_LIST
        )

        for _ in range(5):
            services = await mock_api.get_services(names=["dnsmasq"])

        assert services == [{"name": "dnsmasq", "running": True, "enabled": None}]
        assert len(self._calls(mock_api, "rc", "list")) == 1

    @pytest.mark.asyncio
    async def test_failed_refresh_keeps_previous_enabled_flags(self, mock_api):
        mock_api._call = self._ubus(_RC_LIST_SKIP_RUNNING, _PROCD_SERVICE_LIST)
        await mock_api.get_services()

        mock_api._call = self._ubus(
            OpenWrtResponseError("rc/list failed"), _PROCD_SERVICE_LIST
        )
        mock_api._rc_enabled_fetched_at -= RC_LIST_REFRESH_INTERVAL + 1
        services = await mock_api.get_services(names=["odhcpd"])

        assert services[0]["enabled"] is False

    @pytest.mark.asyncio
    async def test_fallback_to_full_rc_list_without_procd(self, mock_api):
        full_rc = {
            "dnsmasq": {"start": 19, "enabled": True, "running": True},
            "firewall": {"start": 19, "enabled": True, "running": False},
        }

        async def _call(obj, method, params, *args, **kwargs):
            if (obj, method) == ("service", "list"):
                raise OpenWrtAuthError("service/list denied")
            if (obj, method) == ("rc", "list"):
                return full_rc
            raise AssertionError(f"unexpected ubus call {obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        services = await mock_api.get_services(names=["dnsmasq", "firewall"])

        assert {s["name"]: s["running"] for s in services} == {
            "dnsmasq": True,
            "firewall": False,
        }
        # Only the full rc/list (with running check) can supply running state,
        # and it is the only rc/list call.
        assert [c.args[2] for c in self._calls(mock_api, "rc", "list")] == [{}]

    @pytest.mark.asyncio
    async def test_enable_disable_invalidates_rc_cache(self, mock_api):
        mock_api._call = self._ubus(_RC_LIST_SKIP_RUNNING, _PROCD_SERVICE_LIST)
        await mock_api.get_services()

        mock_api._call = AsyncMock(return_value={})
        assert await mock_api.control_service("odhcpd", "enable") is True
        assert mock_api._rc_enabled_fetched_at is None

        mock_api._rc_enabled_fetched_at = 0.0
        assert await mock_api.control_service("odhcpd", "restart") is True
        assert mock_api._rc_enabled_fetched_at == 0.0


# =====================================================================
# v1.38.3 — WAN counters, disk and tmpfs come from ubus; SSH only as a
# real fallback (plan 2026-10-28, N2 / AK2 / AK3)
# =====================================================================


def _wan_dump(l3_device: str = "wan") -> dict[str, Any]:
    return {
        "interface": [
            {
                "interface": "wan",
                "up": True,
                "uptime": 3600,
                "proto": "dhcp",
                "l3_device": l3_device,
                "device": l3_device,
                "ipv4-address": [{"address": "203.0.113.42", "mask": 24}],
            },
            {"interface": "lan", "up": True, "proto": "static", "l3_device": "br-lan"},
        ]
    }


class TestWanCountersViaUbus:
    """AK2: counters from network.device status, then file/read, SSH last."""

    @pytest.mark.asyncio
    async def test_counters_from_network_device_status(self, mock_api):
        seen: list[tuple[str, str, dict]] = []

        async def _call(obj, method, params=None, **kwargs):
            seen.append((obj, method, dict(params or {})))
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump()
            if (obj, method) == ("network.device", "status"):
                return {"up": True, "statistics": {"rx_bytes": 1000, "tx_bytes": 500}}
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert res["rx_bytes"] == 1000
        assert res["tx_bytes"] == 500
        assert res["interface"] == "wan"
        assert ("network.device", "status", {"name": "wan"}) in seen
        # No file/read needed when device status works, and never SSH.
        assert not [s for s in seen if s[:2] == ("file", "read")]
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_counters_use_l3_device_not_logical_name(self, mock_api):
        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump("pppoe-wan")
            if (obj, method) == ("network.device", "status"):
                assert params == {"name": "pppoe-wan"}
                return {"statistics": {"rx_bytes": 7, "tx_bytes": 8}}
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert (res["rx_bytes"], res["tx_bytes"]) == (7, 8)
        # The logical name stays the interface key (rate baseline in coordinator).
        assert res["interface"] == "wan"
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_counters_from_file_read_when_device_status_denied(self, mock_api):
        """Older ACL without network.device: file/read {"data": ...} is parsed."""

        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump()
            if (obj, method) == ("network.device", "status"):
                mock_api._acl_blocked.add(mock_api._acl_cache_key(obj, method, params))
                raise OpenWrtMethodNotFoundError("acl")
            if (obj, method) == ("file", "read"):
                path = params["path"]
                assert path.startswith("/sys/class/net/wan/statistics/")
                return {"data": "1000\n" if path.endswith("rx_bytes") else "500\n"}
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert (res["rx_bytes"], res["tx_bytes"]) == (1000, 500)
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_unreadable_counters_without_acl_block_do_not_use_ssh(self, mock_api):
        """Unknown device (NOT_FOUND, not an ACL denial): None, and no SSH login."""

        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump("wwan0")
            raise OpenWrtMethodNotFoundError(f"{obj}/{method} not found")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert res["rx_bytes"] is None
        assert res["tx_bytes"] is None
        assert res["connected"] is True
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_garbage_counter_data_gives_none_without_ssh(self, mock_api):
        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump()
            if (obj, method) == ("network.device", "status"):
                return {"statistics": {"rx_bytes": "n/a", "tx_bytes": None}}
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert res["rx_bytes"] is None
        assert res["tx_bytes"] is None
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_ssh_fallback_only_when_both_ubus_paths_acl_blocked(self, mock_api):
        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump()
            if (obj, method) in (("network.device", "status"), ("file", "read")):
                mock_api._acl_blocked.add(mock_api._acl_cache_key(obj, method, params))
                raise OpenWrtMethodNotFoundError("acl")
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._run_ssh = AsyncMock(return_value="1000\n500\n")
        res = await mock_api.get_wan_status()
        assert (res["rx_bytes"], res["tx_bytes"]) == (1000, 500)
        mock_api._run_ssh.assert_awaited_once()
        assert "/sys/class/net/wan/statistics/rx_bytes" in mock_api._run_ssh.await_args.args[0]


MOCK_SYSTEM_INFO_FS = {
    **MOCK_SYSTEM_INFO,
    # KiB, as procd reports them (values seen on real hardware)
    "root": {"total": 3328, "free": 2996, "used": 332, "avail": 2996},
    "tmp": {"total": 119784, "free": 119120, "used": 664, "avail": 119120},
}

_BUSYBOX_DF_PK = (
    "Filesystem           1024-blocks    Used Available Capacity Mounted on\n"
    "/dev/root                 7936    7936         0 100% /rom\n"
    "tmpfs                   119784     664    119120   1% /tmp\n"
    "/dev/mtdblock6            3328     332      2996  10% /overlay\n"
    "overlayfs:/overlay        3328     332      2996  10% /\n"
    "tmpfs                      512       0       512   0% /dev\n"
)


class TestDiskAndTmpfsFromSystemInfo:
    """AK3: no extra call, no SSH, real values instead of 0.0."""

    @pytest.mark.asyncio
    async def test_disk_space_from_system_info(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO_FS)
        mock_api._asyncssh_run = AsyncMock()
        await mock_api.get_router_status()
        mock_api._call.reset_mock()
        disk = await mock_api.get_disk_space()
        primary = disk["primary"]
        assert primary["mount"] == "/"
        assert primary["total_mb"] == round(3328 / 1024, 1)
        assert primary["used_mb"] == round(332 / 1024, 1)
        assert primary["free_mb"] == round(2996 / 1024, 1)
        assert primary["usage_percent"] == round(332 / 3328 * 100, 1)
        assert disk["mounts"] == [primary]
        mock_api._call.assert_not_awaited()  # no second system/info call
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_tmpfs_from_system_info(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO_FS)
        mock_api._asyncssh_run = AsyncMock()
        await mock_api.get_router_status()
        mock_api._call.reset_mock()
        tmp = await mock_api.get_tmpfs_stats()
        assert tmp["total_mb"] == round(119784 / 1024, 1)
        assert tmp["used_mb"] == round(664 / 1024, 1)
        assert tmp["free_mb"] == round(119120 / 1024, 1)
        assert tmp["usage_percent"] == round(664 / 119784 * 100, 1)
        assert tmp["mounts"][0]["mount"] == "/tmp"
        mock_api._call.assert_not_awaited()
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_disk_ssh_fallback_uses_posix_df_and_is_cached(self, mock_api):
        """Old OpenWrt without root/tmp in system/info: df -Pk via SSH, 600 s cache."""
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO)
        await mock_api.get_router_status()
        mock_api._asyncssh_run = AsyncMock(return_value=(0, _BUSYBOX_DF_PK, b""))
        first = await mock_api.get_disk_space()
        assert first["primary"]["mount"] == "/"
        assert first["primary"]["total_mb"] == round(3328 / 1024, 1)
        assert {m["mount"] for m in first["mounts"]} == {"/rom", "/tmp", "/overlay", "/", "/dev"}
        cmd = mock_api._asyncssh_run.await_args.args[0]
        assert cmd.startswith("df -Pk")
        assert "-B" not in cmd
        second = await mock_api.get_disk_space()
        assert second == first
        assert mock_api._asyncssh_run.await_count == 1  # served from cache
        # Expired cache entry → one more SSH run
        key, (_ts, value) = next(iter(mock_api._ssh_slow_cache.items()))
        mock_api._ssh_slow_cache[key] = (0.0, value)
        await mock_api.get_disk_space()
        assert mock_api._asyncssh_run.await_count == 2

    @pytest.mark.asyncio
    async def test_tmpfs_ssh_fallback_uses_posix_df(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO)
        await mock_api.get_router_status()
        tmpfs_only = "".join(
            line + "\n" for line in _BUSYBOX_DF_PK.splitlines() if "tmpfs" in line or "Filesystem" in line
        )
        mock_api._asyncssh_run = AsyncMock(return_value=(0, tmpfs_only, b""))
        tmp = await mock_api.get_tmpfs_stats()
        cmd = mock_api._asyncssh_run.await_args.args[0]
        assert cmd.startswith("df -Pk")
        assert "-t tmpfs" in cmd
        assert tmp["total_mb"] == round((119784 + 512) / 1024, 1)
        assert {m["mount"] for m in tmp["mounts"]} == {"/tmp", "/dev"}

    @pytest.mark.asyncio
    async def test_df_failure_returns_defaults_without_exception(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO)
        await mock_api.get_router_status()
        mock_api._asyncssh_run = AsyncMock(return_value=(1, "", b"df: unrecognized option"))
        assert (await mock_api.get_disk_space()) == {"primary": {}, "mounts": []}
        assert (await mock_api.get_tmpfs_stats())["total_mb"] == 0.0

    def test_no_gnu_df_block_size_flag_in_source(self):
        from pathlib import Path

        src = Path(api_module.__file__).read_text(encoding="utf-8")
        assert "df -B" not in src  # BusyBox df has no -B; it broke the sensors (0.0)


class TestWanCountersWhileInterfaceDown:
    """Review finding: no counters while the WAN interface is down.

    A PPPoE/LTE reconnect drops ``l3_device`` from the dump for a few
    seconds; reading the physical port's counters in that gap would be
    compared with the last ``pppoe-wan`` sample under the same interface
    key and produce a phantom throughput peak.
    """

    @pytest.mark.asyncio
    async def test_down_interface_reads_no_counters(self, mock_api):
        seen: list[tuple[str, str]] = []

        async def _call(obj, method, params=None, **kwargs):
            seen.append((obj, method))
            if (obj, method) == ("network.interface", "dump"):
                return {
                    "interface": [
                        {"interface": "wan", "up": False, "proto": "pppoe", "device": "wan"},
                        {"interface": "lan", "up": True, "proto": "static", "l3_device": "br-lan"},
                    ]
                }
            if (obj, method) == ("network.device", "status"):
                return {"statistics": {"rx_bytes": 10**12, "tx_bytes": 10**11}}
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._asyncssh_run = AsyncMock()
        res = await mock_api.get_wan_status()
        assert res["interface"] == "wan"
        assert res["connected"] is False
        assert res["rx_bytes"] is None
        assert res["tx_bytes"] is None
        assert ("network.device", "status") not in seen
        mock_api._asyncssh_run.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_key_auth_router_with_old_acl_still_gets_ssh_fallback(self, mock_api):
        """SSH gate accepts key-auth (``_ssh_use_key``) like the other SSH readers."""

        async def _call(obj, method, params=None, **kwargs):
            if (obj, method) == ("network.interface", "dump"):
                return _wan_dump()
            if (obj, method) in (("network.device", "status"), ("file", "read")):
                mock_api._acl_blocked.add(mock_api._acl_cache_key(obj, method, params))
                raise OpenWrtMethodNotFoundError("acl")
            raise OpenWrtMethodNotFoundError(f"{obj}/{method}")

        mock_api._call = AsyncMock(side_effect=_call)
        mock_api._password = ""
        mock_api._ssh_use_key = True
        mock_api._run_ssh = AsyncMock(return_value="1\n2\n")
        res = await mock_api.get_wan_status()
        assert (res["rx_bytes"], res["tx_bytes"]) == (1, 2)
        mock_api._run_ssh.assert_awaited_once()


class TestDfSshCacheTransientFailures:
    @pytest.mark.asyncio
    async def test_transport_failure_is_not_cached(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO)
        await mock_api.get_router_status()
        mock_api._asyncssh_run = AsyncMock(
            side_effect=[
                (api_module.SUBPROCESS_RC_TIMEOUT, "", b"timeout"),
                (0, _BUSYBOX_DF_PK, b""),
            ]
        )
        assert (await mock_api.get_disk_space()) == {"primary": {}, "mounts": []}
        # Next poll retries instead of serving 0.0 for ten minutes
        assert (await mock_api.get_disk_space())["primary"]["mount"] == "/"
        assert mock_api._asyncssh_run.await_count == 2

    @pytest.mark.asyncio
    async def test_command_failure_is_cached(self, mock_api):
        mock_api._call = AsyncMock(return_value=MOCK_SYSTEM_INFO)
        await mock_api.get_router_status()
        mock_api._asyncssh_run = AsyncMock(return_value=(1, "", b"df: bad option"))
        await mock_api.get_disk_space()
        await mock_api.get_disk_space()
        assert mock_api._asyncssh_run.await_count == 1
