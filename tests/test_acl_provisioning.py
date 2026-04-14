"""Tests for acl_provisioning.py — Auto-deploy rpcd ACL via ubus file API."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.acl_provisioning import (
    ACL_FILE_PATH,
    RPCD_ACL_CONTENT,
    check_and_deploy_acl,
)
from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError


def _make_api(host="10.10.10.2"):
    """Create a mock OpenWrtAPI with a controllable _call coroutine."""
    api = MagicMock()
    api._host = host
    api._call = AsyncMock()
    return api


class TestCheckAndDeployAcl:
    @pytest.mark.asyncio
    async def test_returns_false_when_acl_exists(self):
        """No deployment if file/stat succeeds (file already exists)."""
        api = _make_api()
        # file/stat returns metadata dict → file exists
        api._call.return_value = {"type": "regular", "size": 512}

        result = await check_and_deploy_acl(api)

        assert result is False
        # Only the stat call should have been made
        api._call.assert_awaited_once_with("file", "stat", {"path": ACL_FILE_PATH})

    @pytest.mark.asyncio
    async def test_deploys_when_acl_missing(self):
        """Deploy ACL and return True when file/stat raises MethodNotFoundError."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}  # write + exec succeed

        api._call.side_effect = _side_effect

        result = await check_and_deploy_acl(api)

        assert result is True
        calls = [c.args[1] for c in api._call.call_args_list]  # method names
        assert "stat" in calls
        assert "write" in calls

    @pytest.mark.asyncio
    async def test_restarts_rpcd_after_deploy(self):
        """rpcd restart (file/exec) is attempted after writing the ACL."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}

        api._call.side_effect = _side_effect

        await check_and_deploy_acl(api)

        methods = [c.args[1] for c in api._call.call_args_list]
        assert "exec" in methods

    @pytest.mark.asyncio
    async def test_returns_false_when_write_fails(self):
        """Graceful degradation when file/write is rejected."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "write":
                raise RuntimeError("permission denied")
            return {}

        api._call.side_effect = _side_effect

        result = await check_and_deploy_acl(api)

        assert result is False

    @pytest.mark.asyncio
    async def test_returns_true_even_if_rpcd_restart_fails(self):
        """ACL was written; non-fatal rpcd restart failure still returns True."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "exec":
                raise RuntimeError("rpcd restart failed")
            return {}

        api._call.side_effect = _side_effect

        result = await check_and_deploy_acl(api)

        assert result is True

    @pytest.mark.asyncio
    async def test_continues_to_write_when_stat_raises_unexpected_error(self):
        """If stat fails with a non-MethodNotFound error, still attempt write."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "stat":
                raise RuntimeError("file module unavailable")
            return {}  # write + exec succeed

        api._call.side_effect = _side_effect

        result = await check_and_deploy_acl(api)

        assert result is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_write_includes_acl_content(self):
        """file/write payload must contain the ACL JSON."""
        import json

        api = _make_api()

        captured: list[dict] = []

        def _side_effect(obj, method, params):
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            captured.append({"method": method, "params": params})
            return {}

        api._call.side_effect = _side_effect

        await check_and_deploy_acl(api)

        write_call = next(c for c in captured if c["method"] == "write")
        written = json.loads(write_call["params"]["data"])
        assert written == RPCD_ACL_CONTENT


class TestAclContent:
    def test_acl_has_hostapd(self):
        """ACL must include hostapd access."""
        ubus = RPCD_ACL_CONTENT["root"]["read"]["ubus"]
        assert "hostapd.*" in ubus
        assert "get_clients" in ubus["hostapd.*"]

    def test_acl_has_wireless(self):
        """ACL must include network.wireless."""
        ubus = RPCD_ACL_CONTENT["root"]["read"]["ubus"]
        assert "network.wireless" in ubus

    def test_acl_has_iwinfo(self):
        """ACL must include iwinfo."""
        ubus = RPCD_ACL_CONTENT["root"]["read"]["ubus"]
        assert "iwinfo" in ubus

    def test_acl_has_system(self):
        """ACL must include system board/info."""
        ubus = RPCD_ACL_CONTENT["root"]["read"]["ubus"]
        assert "system" in ubus
        assert "board" in ubus["system"]

    def test_acl_file_path(self):
        """ACL file path is correct."""
        assert ACL_FILE_PATH == "/usr/share/rpcd/acl.d/ha-openwrt-router.json"
