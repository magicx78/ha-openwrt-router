"""Tests for acl_provisioning.py — ensure/deploy rpcd ACL via ubus file API."""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.acl_provisioning import (
    ACL_FILE_PATH,
    ACL_VERSION,
    RPCD_ACL_CONTENT,
    AclDeployError,
    check_and_deploy_acl,
    ensure_acl,
)
from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)


def _make_api(host="10.10.10.2"):
    """Create a mock OpenWrtAPI with controllable _call/_run_ssh coroutines."""
    api = MagicMock()
    api._host = host
    api._call = AsyncMock()
    # Default: SSH fallback unavailable (empty stdout → None, see _run_ssh quirk)
    api._run_ssh = AsyncMock(return_value=None)
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
    async def test_write_blocked_raises_acl_deploy_error(self):
        """Blocked file/write + failed SSH fallback → AclDeployError(write_blocked)."""
        api = _make_api()

        write_err = OpenWrtMethodNotFoundError("rpcd ACL blocks file/write")

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "write":
                raise write_err
            return {}

        api._call.side_effect = _side_effect

        with pytest.raises(AclDeployError) as excinfo:
            await ensure_acl(api)

        assert excinfo.value.reason == "write_blocked"
        assert excinfo.value.__cause__ is write_err
        api._run_ssh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_returns_true_even_if_rpcd_restart_fails(self):
        """ACL written; non-fatal rpcd restart failure still returns True."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "exec":
                raise OpenWrtResponseError("rpcd restart failed")
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is True

    @pytest.mark.asyncio
    async def test_read_permission_blocked_but_file_exists_redeploys(self):
        """file/read ACL-denied, file/stat shows it exists → pre-v5 ACL, redeploy.

        Every shipped ACL since v5 grants file/read on its own path; an
        unreadable deployed ACL is therefore outdated and must be rewritten
        (≤v1.26.3 left it as-is and kept the router in the SSH fallback).
        """
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtResponseError("ubus error 6 for file/read")
            if method == "stat":
                return {"type": "regular", "size": 512}
            return {}

        api._call.side_effect = _side_effect

        result = await ensure_acl(api)

        assert result is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_read_transient_failure_file_exists_leaves_as_is(self):
        """file/read fails transiently but the file exists → skip, no write.

        A network blip must not rewrite the ACL and restart rpcd.
        """
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtTimeoutError("timeout")
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
                raise OpenWrtResponseError("ubus error 6 for file/read")
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


class TestSshFallbackDeploy:
    """SSH fallback when ubus file/write is blocked (chicken-and-egg case)."""

    @staticmethod
    def _block_write(api):
        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "write":
                raise OpenWrtMethodNotFoundError("rpcd ACL blocks file/write")
            return {}

        api._call.side_effect = _side_effect

    @pytest.mark.asyncio
    async def test_ssh_fallback_deploys_when_ubus_write_blocked(self):
        """Marker in stdout → deploy counts as successful, returns True."""
        api = _make_api()
        api._password = "s3cret-router-pw"
        self._block_write(api)
        api._run_ssh = AsyncMock(return_value="HA_ACL_DEPLOYED\n")

        assert await ensure_acl(api) is True

        api._run_ssh.assert_awaited_once()
        remote_cmd = api._run_ssh.await_args.args[0]
        assert ACL_FILE_PATH in remote_cmd
        assert "printf" in remote_cmd
        assert "/etc/init.d/rpcd restart" in remote_cmd
        # sshpass -e contract: the password must never appear in the command
        assert "s3cret-router-pw" not in remote_cmd

    @pytest.mark.asyncio
    async def test_ssh_fallback_empty_output_raises(self):
        """_run_ssh returns None (spawn failure/empty stdout) → AclDeployError."""
        api = _make_api()
        self._block_write(api)

        with pytest.raises(AclDeployError) as excinfo:
            await ensure_acl(api)
        assert excinfo.value.reason == "write_blocked"

    @pytest.mark.asyncio
    async def test_ssh_fallback_marker_missing_raises(self):
        """stdout without the success marker (e.g. shell error) → AclDeployError."""
        api = _make_api()
        self._block_write(api)
        api._run_ssh = AsyncMock(
            return_value="ash: can't create /usr/share/...: Permission denied"
        )

        with pytest.raises(AclDeployError):
            await ensure_acl(api)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "write_err",
        [
            OpenWrtAuthError("rpcd access denied for file/write"),
            OpenWrtResponseError("ubus error 6 for file/write"),
            OpenWrtMethodNotFoundError("rpcd ACL blocks file/write"),
        ],
        ids=["auth", "response", "method_not_found"],
    )
    async def test_every_permission_shaped_write_error_triggers_ssh(self, write_err):
        """All three permission-shaped write rejections must reach the SSH deploy.

        Regression: the real exception classes were referenced in except
        clauses without being imported (NameError killed every deploy), and
        the _call conversion to OpenWrtMethodNotFoundError was not caught at
        all — the SSH fallback was unreachable in production.
        """
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "write":
                raise write_err
            return {}

        api._call.side_effect = _side_effect
        api._run_ssh = AsyncMock(return_value="HA_ACL_DEPLOYED\n")

        assert await ensure_acl(api) is True
        api._run_ssh.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_read_blocked_via_acl_conversion_still_deploys(self):
        """An ACL-blocked file/read (surfaces as MethodNotFound) → deploy runs.

        Regression: with the router's old ACL, reading ACL_FILE_PATH is denied
        and _call converts that to OpenWrtMethodNotFoundError after the
        confirming re-login. ensure_acl must treat this like a missing file
        and proceed to the deploy instead of crashing.
        """
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError(
                    "rpcd ACL blocks file/read (authenticated OK, method not permitted)"
                )
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods

    @pytest.mark.asyncio
    async def test_blocked_rpcd_restart_via_exec_is_nonfatal(self):
        """ACL-blocked file/exec (MethodNotFound) after a write must not fail."""
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                raise OpenWrtMethodNotFoundError("NOT_FOUND")
            if method == "exec":
                raise OpenWrtMethodNotFoundError("rpcd ACL blocks file/exec")
            return {}

        api._call.side_effect = _side_effect

        assert await ensure_acl(api) is True


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

    def test_acl_grants_read_file_paths(self):
        """read.file must grant the paths the integration reads via ubus file/read.

        Without these, every file/read (firmware, bridge FDB, ARP, conntrack)
        falls back to SSH. The nested /sys/class/net/* glob covers brforward,
        statistics/* and brport/port_no (verified on real hardware).
        """
        files = RPCD_ACL_CONTENT["root"]["read"]["file"]
        for path in (
            "/etc/openwrt_release",
            "/sys/class/net/*",
            "/proc/net/arp",
            "/proc/net/nf_conntrack",
            "/proc/sys/net/netfilter/nf_conntrack_count",
        ):
            assert path in files, f"read.file missing {path}"
            assert "read" in files[path]

    def test_acl_grants_sys_class_net_list(self):
        """file/list on /sys/class/net needs "list" on the directory itself.

        The capability check probes file/list on the bare directory path —
        the /sys/class/net/* glob does not match it.
        """
        files = RPCD_ACL_CONTENT["root"]["read"]["file"]
        assert "/sys/class/net" in files
        assert "list" in files["/sys/class/net"]

    def test_acl_grants_read_on_own_acl_file(self):
        """ensure_acl verifies the deployed ACL via ubus — needs read, NOT write.

        write on acl.d would let any rpcd HTTP session widen its own
        permissions, so it must never be granted.
        """
        files = RPCD_ACL_CONTENT["root"]["read"]["file"]
        assert ACL_FILE_PATH in files
        assert files[ACL_FILE_PATH] == ["read"]
        write_files = RPCD_ACL_CONTENT["root"].get("write", {}).get("file", {})
        assert "write" not in write_files.get(ACL_FILE_PATH, [])

    def test_acl_grants_rpcd_restart_exec(self):
        """file/exec of /etc/init.d/rpcd (restart after deploy) must be granted."""
        write_files = RPCD_ACL_CONTENT["root"]["write"]["file"]
        assert write_files["/etc/init.d/rpcd"] == ["exec"]

    def test_acl_file_path(self):
        """ACL file path is correct."""
        assert ACL_FILE_PATH == "/usr/share/rpcd/acl.d/ha-openwrt-router.json"

    def test_acl_version_is_positive_int(self):
        """ACL_VERSION is a positive integer (used in deploy log messages)."""
        assert isinstance(ACL_VERSION, int)
        assert ACL_VERSION >= 1

    def test_acl_version_is_at_least_7(self):
        """v7 adds /proc/cpuinfo (core count) and network/reload."""
        assert ACL_VERSION >= 7

    def test_acl_grants_proc_cpuinfo_read_only(self):
        """The CPU load is normalised per core; the core count comes from
        /proc/cpuinfo via ubus file/read (once per setup)."""
        files = RPCD_ACL_CONTENT["root"]["read"]["file"]
        assert files["/proc/cpuinfo"] == ["read"]
        write_files = RPCD_ACL_CONTENT["root"]["write"]["file"]
        assert "/proc/cpuinfo" not in write_files

    def test_acl_grants_network_reload_only(self):
        """network/reload backs the "reload Wi-Fi" button and the Wi-Fi
        switches. Only reload — not restart or the other network methods."""
        write_ubus = RPCD_ACL_CONTENT["root"]["write"]["ubus"]
        assert write_ubus["network"] == ["reload"]
        assert "network" not in RPCD_ACL_CONTENT["root"]["read"]["ubus"]

    def test_acl_v7_keeps_v6_grants(self):
        """v7 only adds grants; nothing granted by v6 is dropped."""
        read = RPCD_ACL_CONTENT["root"]["read"]
        write = RPCD_ACL_CONTENT["root"]["write"]
        assert read["ubus"]["log"] == ["read"]
        assert read["ubus"]["usteer"] == ["get_clients"]
        assert read["ubus"]["network.wireless"] == ["status", "up", "down"]
        assert read["ubus"]["file"] == ["read", "stat", "list", "exec"]
        assert write["ubus"]["network.wireless"] == ["up", "down"]
        assert write["file"]["/etc/init.d/rpcd"] == ["exec"]
        for path in (
            "/etc/openwrt_release",
            "/etc/config/ddns",
            "/var/run/ddns/*",
            "/sys/class/net/*",
            "/proc/net/arp",
            "/proc/net/nf_conntrack",
            "/proc/sys/net/netfilter/nf_conntrack_count",
            "/tmp/opkg_list",
            ACL_FILE_PATH,
        ):
            assert read["file"][path] == ["read"], path

    def test_scripts_json_matches_rpcd_acl_content(self):
        """scripts/ha-openwrt-router.json must equal RPCD_ACL_CONTENT.

        That file is what the SSH-fallback notification tells users to scp to
        the router — if it drifts behind the code, a manual deploy silently
        fails to fix the SSH fallback (happened once already).
        """
        scripts_json = (
            Path(__file__).resolve().parent.parent / "scripts" / "ha-openwrt-router.json"
        )
        assert json.loads(scripts_json.read_text()) == RPCD_ACL_CONTENT


# =====================================================================
# ACL v8 (1.38.7): rpcd >= 2026.x re-checks file ACLs against the realpath()
# of the requested file. /proc/net/* resolves to /proc/<pid>/net/*,
# /sys/class/net/<if>/... to /sys/devices/.../net/<if>/..., /var/run to
# /tmp/run — so the resolved paths must be granted as well (read-only).
# Verified on hardware: rpcd 2026.10.04 denied /proc/net/arp and brforward
# for the integration's session while rpcd 2025.12.03 allowed them.
# =====================================================================


_RESOLVED_READ_PATHS = (
    "/proc/7729/net/arp",
    "/proc/7729/net/nf_conntrack",
    "/sys/devices/virtual/net/br-lan/brforward",
    "/sys/devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/wan/statistics/rx_bytes",
    "/sys/devices/platform/soc/15100000.ethernet/mdio_bus/mdio-bus/mdio-bus:1f/net/lan1/brport/port_no",
    "/sys/devices/virtual/net/phy0-ap0/statistics/tx_bytes",
    "/tmp/run/ddns/myddns.ip",
)

_MUST_NOT_MATCH = (
    "/etc/shadow",
    "/etc/config/wireless",
    "/proc/1/environ",
    "/proc/7729/cmdline",
    "/sys/devices/platform/soc/18000000.spi/spi_master/spi0/spi0.0/mtd/mtd0/data",
    # Target of /sys/class/net/wlan0/phy80211/macaddress: a symlink leading OUT
    # of the netdev's directory must not be covered by /sys/devices/*/net/*.
    "/sys/devices/platform/soc/18000000.wifi/ieee80211/phy0/macaddress",
    "/tmp/run/hostapd/phy0-ap0",
)


def _read_granted(path: str) -> bool:
    """fnmatch(3) without FNM_PATHNAME, as rpcd's session ACL uses it."""
    files = RPCD_ACL_CONTENT["root"]["read"]["file"]
    return any(
        fnmatch.fnmatchcase(path, pattern) and "read" in perms
        for pattern, perms in files.items()
    )


class TestAclV8ResolvedPaths:
    def test_acl_version_is_8(self):
        assert ACL_VERSION == 8

    @pytest.mark.parametrize("path", _RESOLVED_READ_PATHS)
    def test_resolved_symlink_targets_are_readable(self, path):
        assert _read_granted(path), path

    def test_resolved_ddns_run_dir_is_listable(self):
        files = RPCD_ACL_CONTENT["root"]["read"]["file"]
        assert "list" in files["/tmp/run/ddns"]
        assert "list" in files["/var/run/ddns"]

    @pytest.mark.parametrize("path", _MUST_NOT_MATCH)
    def test_resolved_patterns_stay_narrow(self, path):
        assert not _read_granted(path), path

    def test_symlink_paths_still_granted_for_older_rpcd(self):
        """rpcd before the realpath re-check only sees the requested path."""
        for path in ("/proc/net/arp", "/proc/net/nf_conntrack", "/sys/class/net/*", "/var/run/ddns/*"):
            assert RPCD_ACL_CONTENT["root"]["read"]["file"][path] == ["read"], path

    @pytest.mark.asyncio
    async def test_v7_deployment_is_upgraded_to_v8(self):
        """The real upgrade path: a router carrying exactly the v7 file."""
        v7 = json.loads(json.dumps(RPCD_ACL_CONTENT))
        for key in (
            "/proc/*/net/arp",
            "/proc/*/net/nf_conntrack",
            "/sys/devices/*/net/*",
            "/tmp/run/ddns",
            "/tmp/run/ddns/*",
        ):
            del v7["root"]["read"]["file"][key]
        api = _make_api()

        def _side_effect(obj, method, params):
            if method == "read":
                return {"data": json.dumps(v7, indent=2)}
            return {}

        api._call.side_effect = _side_effect
        assert await ensure_acl(api) is True
        methods = [c.args[1] for c in api._call.call_args_list]
        assert "write" in methods
        assert "exec" in methods  # rpcd restart

    def test_v8_adds_no_write_or_exec(self):
        write = RPCD_ACL_CONTENT["root"]["write"]
        assert write["file"] == {"/etc/init.d/rpcd": ["exec"]}
        assert write["ubus"] == {"network.wireless": ["up", "down"], "network": ["reload"]}
        for perms in RPCD_ACL_CONTENT["root"]["read"]["file"].values():
            assert set(perms) <= {"read", "list"}, perms
