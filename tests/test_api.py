"""Tests for the OpenWrt API client (api.py)."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

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
from custom_components.openwrt_router.const import DEFAULT_SESSION_ID

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


def _make_api_with_response(status_code=200, json_data=None, raise_on_json=False, side_effect=None):
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
        host="192.168.1.1", port=80, username="root", password="test",
        session=session, protocol="http",
    )
    api._token = MOCK_SESSION_TOKEN
    return api


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
        assert leases["B8:27:EB:AA:BB:CC"] == {"ip": "192.168.1.100", "hostname": "raspberrypi"}
        assert leases["AC:DE:48:11:22:33"] == {"ip": "192.168.1.101", "hostname": "myphone"}
        assert leases["00:11:22:33:44:55"] == {"ip": "192.168.1.102", "hostname": ""}

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
            host="192.168.1.1", port=80, username="root", password="test",
            session=session, protocol="http",
        )
        assert api._ssl_context is None

    def test_https_returns_context(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1", port=443, username="root", password="test",
            session=session, protocol="https",
        )
        assert api._ssl_context is not None
        assert api._ssl_context.check_hostname is True

    def test_https_insecure(self):
        import ssl
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1", port=443, username="root", password="test",
            session=session, protocol="https-insecure",
        )
        assert api._ssl_context is not None
        assert api._ssl_context.check_hostname is False
        assert api._ssl_context.verify_mode == ssl.CERT_NONE


class TestURLConstruction:
    def test_ipv4(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1", port=80, username="root", password="test",
            session=session, protocol="http",
        )
        assert api._ubus_url == "http://192.168.1.1:80/ubus"

    def test_ipv6(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="::1", port=80, username="root", password="test",
            session=session, protocol="http",
        )
        assert api._ubus_url == "http://[::1]:80/ubus"

    def test_https_scheme(self):
        session = MagicMock()
        api = OpenWrtAPI(
            host="192.168.1.1", port=443, username="root", password="test",
            session=session, protocol="https",
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
        api._session.post = MagicMock(return_value=_make_error_cm(asyncio.TimeoutError()))
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtTimeoutError):
            await api._raw_call(payload)

    @pytest.mark.asyncio
    async def test_client_error(self):
        api = _make_api_with_response()
        api._session.post = MagicMock(return_value=_make_error_cm(aiohttp.ClientError("generic")))
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
        envelope = {
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32002, "message": "Access denied"},
        }
        api = _make_api_with_response(json_data=envelope)
        payload = api._build_call("system", "board", {})
        with pytest.raises(OpenWrtMethodNotFoundError):
            await api._raw_call(payload)

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
            "jsonrpc": "2.0", "id": 1,
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
            "jsonrpc": "2.0", "id": 1,
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
        mock_api._call = AsyncMock(
            side_effect=OpenWrtAuthError("access denied")
        )
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
