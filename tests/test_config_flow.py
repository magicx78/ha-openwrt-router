"""Tests for the OpenWrt Router config flow (config_flow.py)."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtRpcdSetupError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.config_flow import (
    OpenWrtConfigFlow,
    _validate_host,
)
from custom_components.openwrt_router.const import (
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    ERROR_CANNOT_CONNECT,
    ERROR_INVALID_AUTH,
    ERROR_INVALID_HOST,
    ERROR_RPCD_SETUP,
    ERROR_TIMEOUT,
    ERROR_UNKNOWN,
    PROTOCOL_HTTP,
    PROTOCOL_HTTPS_INSECURE,
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
    flow.context = {"source": "user"}
    return flow


# Shared valid user_input for the user step (now includes protocol)
_VALID_USER_INPUT = {
    "host": "192.168.1.1",
    "port": 443,
    "protocol": PROTOCOL_HTTPS_INSECURE,
    "username": "root",
    "password": "test",
}


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
            "port": 443,
            "protocol": PROTOCOL_HTTPS_INSECURE,
            "username": "root",
            "password": "test",
        })
        assert result["type"] == "form"
        assert result["errors"]["host"] == ERROR_INVALID_HOST

    @pytest.mark.asyncio
    async def test_auth_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("bad")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_timeout_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtTimeoutError("slow")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_TIMEOUT

    @pytest.mark.asyncio
    async def test_connection_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtConnectionError("down")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_response_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtResponseError("bad")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_unknown_error(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=RuntimeError("oops")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_UNKNOWN

    @pytest.mark.asyncio
    async def test_success_proceeds_to_devices(self):
        """After successful connection the flow moves to the devices selection step."""
        flow = _make_flow()
        board_info = {"hostname": "OpenWrt-Dev", "model": "Test", "mac": "aa:bb:cc:dd:ee:ff"}

        with patch.object(flow, "_validate_input", return_value=board_info), \
             patch.object(flow, "async_set_unique_id", new_callable=AsyncMock), \
             patch.object(flow, "_abort_if_unique_id_configured"):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)

        assert result["type"] == "form"
        assert result["step_id"] == "devices"

    @pytest.mark.asyncio
    async def test_protocol_stored_in_user_data(self):
        """Protocol selected in user step is stored and used for the connection test."""
        flow = _make_flow()
        board_info = {"hostname": "OpenWrt-Dev", "model": "Test", "mac": "aa:bb:cc:dd:ee:ff"}

        with patch.object(flow, "_validate_input", return_value=board_info) as mock_validate, \
             patch.object(flow, "async_set_unique_id", new_callable=AsyncMock), \
             patch.object(flow, "_abort_if_unique_id_configured"):
            await flow.async_step_user(user_input=_VALID_USER_INPUT)

        mock_validate.assert_called_once_with(
            "192.168.1.1", 443, "root", "test", PROTOCOL_HTTPS_INSECURE
        )
        assert flow._user_data[CONF_PROTOCOL] == PROTOCOL_HTTPS_INSECURE


class TestDevicesStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1", "port": 443}
        flow._board_info = {"model": "Test Router"}
        result = await flow.async_step_devices(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "devices"

    @pytest.mark.asyncio
    async def test_no_extras_goes_to_checklist(self):
        flow = _make_flow()
        flow._user_data = {
            "host": "192.168.1.1", "port": 443,
            "protocol": PROTOCOL_HTTPS_INSECURE,
            "username": "root", "password": "test",
        }
        flow._board_info = {"hostname": "Router", "model": "Test"}

        with patch.object(flow, "async_step_checklist", return_value={"type": "form", "step_id": "checklist"}) as mock_checklist:
            result = await flow.async_step_devices(user_input={"add_fritzbox": False, "add_switch": False})

        mock_checklist.assert_called_once()

    @pytest.mark.asyncio
    async def test_fritzbox_checked_goes_to_fritzbox_step(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1", "port": 443}
        flow._board_info = {}

        with patch.object(flow, "async_step_fritzbox", return_value={"type": "form", "step_id": "fritzbox"}) as mock_fb:
            await flow.async_step_devices(user_input={"add_fritzbox": True, "add_switch": False})

        mock_fb.assert_called_once()

    @pytest.mark.asyncio
    async def test_switch_checked_goes_to_switch_step(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1", "port": 443}
        flow._board_info = {}

        with patch.object(flow, "async_step_switch_dev", return_value={"type": "form", "step_id": "switch_dev"}) as mock_sw:
            await flow.async_step_devices(user_input={"add_fritzbox": False, "add_switch": True})

        mock_sw.assert_called_once()


class TestFritzboxStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1"}
        result = await flow.async_step_fritzbox(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "fritzbox"

    @pytest.mark.asyncio
    async def test_submit_stores_fritzbox_data(self):
        flow = _make_flow()
        flow._user_data = {
            "host": "192.168.1.1", "port": 443,
            "protocol": PROTOCOL_HTTPS_INSECURE,
            "username": "root", "password": "test",
        }
        flow._board_info = {"hostname": "Router"}
        flow._add_switch = False

        with patch.object(flow, "async_step_checklist", return_value={"type": "form", "step_id": "checklist"}):
            await flow.async_step_fritzbox(user_input={
                "fritzbox_host": "172.16.1.254",
                "fritzbox_port": 49000,
                "fritzbox_user": "admin",
                "fritzbox_password": "secret",
            })

        assert flow._user_data["fritzbox_host"] == "172.16.1.254"
        assert flow._user_data["fritzbox_port"] == 49000


class TestSwitchDevStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow = _make_flow()
        flow._user_data = {"host": "192.168.1.1"}
        result = await flow.async_step_switch_dev(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "switch_dev"

    @pytest.mark.asyncio
    async def test_submit_stores_switch_data(self):
        flow = _make_flow()
        flow._user_data = {
            "host": "192.168.1.1", "port": 443,
            "protocol": PROTOCOL_HTTPS_INSECURE,
            "username": "root", "password": "test",
        }
        flow._board_info = {"hostname": "Router"}

        with patch.object(flow, "async_step_checklist", return_value={"type": "form", "step_id": "checklist"}):
            await flow.async_step_switch_dev(user_input={
                "switch_host": "192.168.1.2",
                "switch_port": 443,
                "switch_protocol": PROTOCOL_HTTPS_INSECURE,
                "switch_username": "root",
                "switch_password": "swpass",
            })

        assert flow._user_data["switch_host"] == "192.168.1.2"
        assert flow._user_data["switch_protocol"] == PROTOCOL_HTTPS_INSECURE


class TestUserStepRpcdSetup:
    """status=6 on session/login → wrong credentials, not rpcd setup issue."""

    @pytest.mark.asyncio
    async def test_auth_error_status6_maps_to_invalid_auth(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("permission denied")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_INVALID_AUTH

    @pytest.mark.asyncio
    async def test_response_error_maps_to_cannot_connect(self):
        flow = _make_flow()
        with patch.object(flow, "_validate_input", side_effect=OpenWrtResponseError("garbled")):
            result = await flow.async_step_user(user_input=_VALID_USER_INPUT)
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT


def _make_reauth_flow(entry_data: dict):
    """Create a flow with a mocked reauth entry."""
    flow = OpenWrtConfigFlow()
    flow.hass = MagicMock()
    flow.context = {"source": "reauth", "entry_id": "test_id"}
    mock_entry = MagicMock()
    mock_entry.data = entry_data
    flow._get_reauth_entry = MagicMock(return_value=mock_entry)
    return flow, mock_entry


_REAUTH_DATA = {
    "host": "10.10.10.4",
    "port": 443,
    "protocol": PROTOCOL_HTTPS_INSECURE,
    "username": "root",
    "password": "secret",
}


class TestReauthDiagnosis:
    """async_step_reauth should diagnose first, never blindly ask for password."""

    @pytest.mark.asyncio
    async def test_existing_credentials_work_auto_resolves(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}), \
             patch.object(flow, "async_update_reload_and_abort", return_value={"type": "abort", "reason": "reauth_successful"}):
            result = await flow.async_step_reauth({})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_response_error_routes_to_rpcd_setup_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtResponseError("garbled")):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_rpcd_setup"

    @pytest.mark.asyncio
    async def test_connection_error_routes_to_cannot_connect_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtConnectionError("down")):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_timeout_error_routes_to_cannot_connect_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtTimeoutError("slow")):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_auth_error_routes_to_confirm_step(self):
        flow, entry = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("bad")):
            result = await flow.async_step_reauth({})
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_confirm"


class TestReauthRpcdSetupStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        result = await flow.async_step_reauth_rpcd_setup(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_rpcd_setup"

    @pytest.mark.asyncio
    async def test_retry_success_auto_resolves(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}), \
             patch.object(flow, "async_update_reload_and_abort", return_value={"type": "abort", "reason": "reauth_successful"}):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_retry_still_failing_shows_error(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtResponseError("still garbled")):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_RPCD_SETUP

    @pytest.mark.asyncio
    async def test_retry_auth_error_switches_to_confirm(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtAuthError("wrong pw")):
            result = await flow.async_step_reauth_rpcd_setup(user_input={})
        assert result["step_id"] == "reauth_confirm"


class TestReauthCannotConnectStep:
    @pytest.mark.asyncio
    async def test_shows_form_on_first_call(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        result = await flow.async_step_reauth_cannot_connect(user_input=None)
        assert result["type"] == "form"
        assert result["step_id"] == "reauth_cannot_connect"

    @pytest.mark.asyncio
    async def test_retry_success_auto_resolves(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", return_value={"hostname": "AP4"}), \
             patch.object(flow, "async_update_reload_and_abort", return_value={"type": "abort", "reason": "reauth_successful"}):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["type"] == "abort"

    @pytest.mark.asyncio
    async def test_retry_still_failing_shows_error(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtConnectionError("still down")):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["type"] == "form"
        assert result["errors"]["base"] == ERROR_CANNOT_CONNECT

    @pytest.mark.asyncio
    async def test_retry_rpcd_setup_switches_step(self):
        flow, _ = _make_reauth_flow(_REAUTH_DATA)
        with patch.object(flow, "_validate_input", side_effect=OpenWrtRpcdSetupError("rpcd")):
            result = await flow.async_step_reauth_cannot_connect(user_input={})
        assert result["step_id"] == "reauth_rpcd_setup"


class TestBuildSchemas:
    def test_user_schema_defaults(self):
        schema = OpenWrtConfigFlow._build_user_schema(None)
        assert schema is not None

    def test_user_schema_with_previous_input(self):
        schema = OpenWrtConfigFlow._build_user_schema({
            "host": "10.0.0.1",
            "port": 8080,
            "protocol": PROTOCOL_HTTPS_INSECURE,
            "username": "admin",
        })
        assert schema is not None

    def test_user_schema_includes_protocol(self):
        """Protocol must be part of the user step schema (not a separate step)."""
        schema = OpenWrtConfigFlow._build_user_schema(None)
        keys = [str(k) for k in schema.schema]
        assert any("protocol" in k for k in keys)

    def test_protocol_schema_still_available(self):
        """_build_protocol_schema kept for backward compatibility."""
        schema = OpenWrtConfigFlow._build_protocol_schema()
        assert schema is not None
