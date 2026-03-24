"""Tests for the OpenWrt Diagnostics module (diagnostics.py)."""
from __future__ import annotations

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
        result = _redact({"hostname": "openwrt", "model": "test"})
        assert result["hostname"] == "openwrt"
        assert result["model"] == "test"

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
        assert result["entry_title"] == "OpenWrt-Dev"
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
