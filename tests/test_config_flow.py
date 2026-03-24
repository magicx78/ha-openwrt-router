"""Tests for the OpenWrt Router config flow (config_flow.py)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.config_flow import (
    OpenWrtConfigFlow,
    _validate_host,
)
from custom_components.openwrt_router.const import (
    CONF_PROTOCOL,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    PROTOCOL_HTTP,
)


# =====================================================================
# _validate_host (pure function)
# =====================================================================

class TestValidateHost:
    def test_valid_ip(self):
        assert _validate_host("192.168.1.1") is None

    def test_valid_hostname(self):
        assert _validate_host("router.local") is None

    def test_valid_hostname_with_underscore(self):
        assert _validate_host("my_router") is None

    def test_loopback_rejected(self):
        assert _validate_host("127.0.0.1") == ERROR_INVALID_HOST

    def test_link_local_rejected(self):
        assert _validate_host("169.254.1.1") == ERROR_INVALID_HOST

    def test_unspecified_rejected(self):
        assert _validate_host("0.0.0.0") == ERROR_INVALID_HOST

    def test_ipv6_loopback_rejected(self):
        assert _validate_host("::1") == ERROR_INVALID_HOST

    def test_empty_rejected(self):
        assert _validate_host("") == ERROR_INVALID_HOST

    def test_whitespace_only_rejected(self):
        assert _validate_host("   ") == ERROR_INVALID_HOST

    def test_special_chars_rejected(self):
        assert _validate_host("router;rm -rf") == ERROR_INVALID_HOST

    def test_valid_ipv6(self):
        assert _validate_host("2001:db8::1") is None

    def test_valid_ip_with_whitespace_stripped(self):
        assert _validate_host("  192.168.1.1  ") is None


# =====================================================================
# Config Flow Steps
# =====================================================================

def _make_flow():
    """Create an OpenWrtConfigFlow with a mock hass."""
    flow = OpenWrtConfigFlow()
    flow.hass = MagicMock()
    # Mock the flow context
    flow.context = {"source": "user"}
    return flow


class TestUserStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        result = await flow.async_step_user(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "user"

    @pytest.mark.asyncio
    async def test_invalid_host_shows_error(self):
        flow = _make_flow()
        result = await flow.async_step_user(user_input={
            "host": "127.0.0.1",
            "port": 80,
            "username": "root",
            "password": "test",
        })
        assert result["type"] == "form"
        assert result["errors"]["host"] == ERROR_INVALID_HOST

    @pytest.mark.asyncio
    async def test_auth_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("bad")):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "wrong",
            })
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtTimeoutError("slow")):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "test",
            })
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_TIMEOUT

    @pytest.mark.asyncio
    async def test_connection_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtConnectionError("down")):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "test",
            })
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_response_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtResponseError("bad")):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "test",
            })
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_unknown_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=RuntimeError("oops")):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "test",
            })
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_UNKNOWN

    @pytest.mark.asyncio
    async def test_success_proceeds_to_protocol(self):
        flow = _make_flow()
        board_info = {"hostname": "OpenWrt-Dev", "model": "Test", "mac": "aa:bb:cc:dd:ee:ff"}

        with patch.object(flow, "_validate_input", return_value=board_info), \
             patch.object(flow, "async_set_unique_id", new_callable=AsyncMock), \
             patch.object(flow, "_abort_if_unique_id_configured"):
            result = await flow.async_step_user(user_input={
                "host": "192.168.1.1",
                "port": 80,
                "username": "root",
                "password": "test",
            })
        # Should proceed to protocol step (show form)
        assert result["type"] == "form"
        assert result["step_id"] == "protocol"


class TestProtocolStep:
    @pytest.mark.asyncio
    async def test_creates_entry(self):
        flow = _make_flow()
        flow._board_info = {"hostname": "OpenWrt-Dev"}
        flow._user_data = {
            "host": "192.168.1.1",
            "port": 80,
            "username": "root",
            "password": "test",
        }
        result = await flow.async_step_protocol(user_input={
            CONF_PROTOCOL: PROTOCOL_HTTP,
        })
        assert result["type"] == "create_entry"
        assert result["title"] == "OpenWrt-Dev"
        assert result["data"][CONF_PROTOCOL] == PROTOCOL_HTTP
        assert result["data"]["host"] == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1"}
        result = await flow.async_step_protocol(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "protocol"


class TestBuildSchemas:
    def test_user_schema_defaults(self):
        schema = OpenWrtConfigFlow._build_user_schema(None)
        assert schema is not None

    def test_user_schema_with_previous_input(self):
        schema = OpenWrtConfigFlow._build_user_schema({
            "host": "10.0.0.1",
            "port": 8080,
            "username": "admin",
        })
        assert schema is not None

    def test_protocol_schema(self):
        schema = OpenWrtConfigFlow._build_protocol_schema()
        assert schema is not None
