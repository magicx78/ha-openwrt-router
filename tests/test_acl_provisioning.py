"""Tests for acl_provisioning.py — Auto-deploy rpcd ACL."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.acl_provisioning import (
    ACL_FILE_PATH,
    RPCD_ACL_CONTENT,
    check_and_deploy_acl,
    _check_acl_exists,
)


def _make_api(host="10.10.10.2", username="root", password="secret"):
    """Create a mock API with host/username/password."""
    api = MagicMock()
    api._host = host
    api._username = username
    api._password = password
    return api


class TestCheckAndDeployAcl:
    @pytest.mark.asyncio
    async def test_returns_false_when_acl_exists(self):
        """No deployment if ACL file already exists."""
        api = _make_api()
        with patch(
            "custom_components.openwrt_router.acl_provisioning._check_acl_exists",
            new=AsyncMock(return_value=True),
        ):
            result = await check_and_deploy_acl(api)
        assert result is False

    @pytest.mark.asyncio
    async def test_deploys_when_acl_missing(self):
        """Deploy ACL when file is missing, return True."""
        api = _make_api()
        with patch(
            "custom_components.openwrt_router.acl_provisioning._check_acl_exists",
            new=AsyncMock(return_value=False),
        ), patch(
            "custom_components.openwrt_router.acl_provisioning._deploy_acl",
            new=AsyncMock(),
        ) as mock_deploy:
            result = await check_and_deploy_acl(api)
        assert result is True
        mock_deploy.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_false_on_ssh_unavailable(self):
        """Graceful skip when SSH is not available."""
        api = _make_api()
        with patch(
            "custom_components.openwrt_router.acl_provisioning._check_acl_exists",
            new=AsyncMock(side_effect=RuntimeError("sshpass not found")),
        ):
            result = await check_and_deploy_acl(api)
        assert result is False

    @pytest.mark.asyncio
    async def test_returns_false_on_deploy_failure(self):
        """Graceful degradation when deployment fails."""
        api = _make_api()
        with patch(
            "custom_components.openwrt_router.acl_provisioning._check_acl_exists",
            new=AsyncMock(return_value=False),
        ), patch(
            "custom_components.openwrt_router.acl_provisioning._deploy_acl",
            new=AsyncMock(side_effect=RuntimeError("permission denied")),
        ):
            result = await check_and_deploy_acl(api)
        assert result is False


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
