"""Tests for acl_provisioning.py — ensure/deploy rpcd ACL via ubus file API."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.acl_provisioning import (
    ACL_FILE_PATH,
    ACL_VERSION,
    RPCD_ACL_CONTENT,
    check_and_deploy_acl,
    ensure_acl,
)
from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError


def _make_api(host="10.10.10.2"):
    """Create a mock OpenWrtAPI with a controllable _call coroutine."""
    api = MagicMock()
    api._host = host
    api._call = AsyncMock()
    return api


class TestEnsureAcl:
    """ensure_acl: deploy when missing, UPDATE when stale, skip when current."""

    @pytest.mark.asyncio
    async def test_skips_when_acl_current(self):
        """ACL on router equal to expected content → no write, returns False."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": json.dumps(RPCD_ACL_CONTENT, indent=2)}
            raise AssertionError(f"unexpected call: file/{method}")

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is False
        methods = [c.args[1] for c in api._call.call_args_list]
        assert methods == ["read"]
        assert "write" not in methods

    @pytest.mark.asyncio
    async def test_updates_when_acl_outdated(self):
        """ACL present but content differs (older/narrower) → rewrite, True.

        This is the update scenario: an integration update widened the ACL and
        the previously-deployed file must be refreshed instead of left stale.
        """
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                # A narrower ACL than the integration now expects.
                return {"data": json.dumps({"root": {"read": {"ubus": {}}}})}
            return {}  # write + exec succeed

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "read" in methods
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_redeploys_when_content_not_json(self):
        """ACL present but corrupted (not valid JSON) → rewrite, True."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": "}{ not json"}
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is True

    @pytest.mark.asyncio
    async def test_deploys_when_acl_missing(self):
        """file/read NOT_FOUND → deploy and return True (first install)."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_restarts_rpcd_after_deploy(self):
        """rpcd restart (file/exec) is attempted after writing the ACL."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}

        api._call.side_effect = _side_effect

        await ensure_acl(api)

        methods = [c.args[1] for c in api._call.call_args_list]
        assert "exec" in methods

    @pytest.mark.asyncio
    async def test_returns_false_when_write_fails(self):
        """Blocked file/write → best-effort, returns False (setup not broken)."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "write":
                raise RuntimeError("permission denied")
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is False

    @pytest.mark.asyncio
    async def test_returns_true_even_if_rpcd_restart_fails(self):
        """ACL written; non-fatal rpcd restart failure still returns True."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "exec":
                raise RuntimeError("rpcd restart failed")
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is True

    @pytest.mark.asyncio
    async def test_read_blocked_but_file_exists_leaves_as_is(self):
        """file/read blocked (ACL) but file/stat shows it exists → skip, no write."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise RuntimeError("access denied")
            if method == "stat":
                return {"type": "regular", "size": 512}
            raise AssertionError(f"unexpected call: file/{method}")

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is False
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" not in methods

    @pytest.mark.asyncio
    async def test_read_blocked_and_stat_missing_deploys(self):
        """file/read blocked, file/stat NOT_FOUND → deploy, True."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise RuntimeError("access denied")
            if method == "stat":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_write_includes_acl_content(self):
        """file/write payload must contain the expected ACL JSON."""
        api = _make_api()
        captured: list[dict] = []

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            captured.append({"method": method, "params": params})
            return {}

        api._call.side_effect = _side_effect

        await ensure_acl(api)

        write_call = next(c for c in captured if c["method"] == "write")
        assert json.loads(write_call["params"]["data"]) == RPCD_ACL_CONTENT


class TestCheckAndDeployAclAlias:
    """check_and_deploy_acl must delegate to ensure_acl (backwards compat)."""

    @pytest.mark.asyncio
    async def test_alias_skips_when_current(self):
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": json.dumps(RPCD_ACL_CONTENT, indent=2)}
            return {}

        api._call.side_effect = _side_effect
        assert await check_and_deploy_acl(api) is False

    @pytest.mark.asyncio
    async def test_alias_deploys_when_missing(self):
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            return {}

        api._call.side_effect = _side_effect
        assert await check_and_deploy_acl(api) is True


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

    def test_acl_version_is_positive_int(self):
        """ACL_VERSION is a positive integer (used in deploy log messages)."""
        assert isinstance(ACL_VERSION, int)
        assert ACL_VERSION >= 1
