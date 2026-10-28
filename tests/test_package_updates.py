"""Tests for the package update check (finding N6, decision E3).

"Check for updates" runs the router's package manager (apk on OpenWrt >= 25,
opkg before) over SSH on button press only, stores the result in the
coordinator and never runs it from a poll. The "install updates" button is
gone.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.exceptions import HomeAssistantError

from custom_components.openwrt_router.api import (
    SUBPROCESS_RC_TIMEOUT,
    OpenWrtAPI,
    OpenWrtUpdateCheckError,
    parse_apk_upgradable,
    parse_opkg_upgradable,
)
from custom_components.openwrt_router.button import (
    BUTTON_DESCRIPTIONS,
    OpenWrtButtonEntity,
)
from custom_components.openwrt_router.const import (
    SUFFIX_CHECK_UPDATES,
    SUFFIX_PERFORM_UPDATES,
)
from custom_components.openwrt_router.coordinator import OpenWrtCoordinator
from custom_components.openwrt_router.sensor import SENSOR_DESCRIPTIONS


# ---------------------------------------------------------------------------
# Sample package manager output
# ---------------------------------------------------------------------------

OPKG_LIST_UPGRADABLE = (
    "luci-mod-network - 25.020.54000~1a2b3c4 - 25.051.61000~5d6e7f8\n"
    "busybox - 1.36.1-r1 - 1.36.1-r2\n"
    "\n"
    "Collected errors:\n"
    " * opkg_conf_load: Could not lock /var/lock/opkg.lock\n"
)

# apk-tools v3 (OpenWrt 25.x): `apk list --upgradable`
APK_LIST_UPGRADABLE = (
    "busybox-1.37.0-r5 aarch64_cortex-a53 {busybox} (GPL-2.0) "
    "[upgradable from: busybox-1.37.0-r4]\n"
    "luci-app-firewall-25.100.12345~abcdef1-r1 noarch {luci-app-firewall} "
    "(Apache-2.0) [upgradable from: luci-app-firewall-25.050.11111~1234567-r1]\n"
    "libpcre2-8-10.42-r2 aarch64_cortex-a53 {pcre2} (BSD-3-Clause) "
    "[upgradable from: libpcre2-8-10.42-r1]\n"
    "WARNING: opening /etc/apk/repositories.d/x: No such file or directory\n"
)

# `apk version -l '<'` (fallback when `apk list` lacks --upgradable)
APK_VERSION_LT = (
    "Installed:                                Available:\n"
    "busybox-1.37.0-r4                       < 1.37.0-r5\n"
    "kmod-nf-ipt6-6.6.86-r1                  < 6.6.93-r1\n"
)


def _api() -> OpenWrtAPI:
    return OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="test",
        session=MagicMock(),
        protocol="http",
    )


def _script_output(pm: str, body: str = "", update_rc: int = 0, list_rc: int = 0) -> str:
    if pm == "none":
        return "@@pm=none\n"
    return f"@@pm={pm}\n@@update_rc={update_rc}\n{body}@@list_rc={list_rc}\n"


# =====================================================================
# Parsing
# =====================================================================


class TestParseOpkg:
    def test_parses_name_current_available(self):
        assert parse_opkg_upgradable(OPKG_LIST_UPGRADABLE) == [
            {
                "name": "luci-mod-network",
                "current": "25.020.54000~1a2b3c4",
                "available": "25.051.61000~5d6e7f8",
            },
            {"name": "busybox", "current": "1.36.1-r1", "available": "1.36.1-r2"},
        ]

    def test_empty_output(self):
        assert parse_opkg_upgradable("") == []


class TestParseApk:
    def test_list_upgradable_format(self):
        assert parse_apk_upgradable(APK_LIST_UPGRADABLE) == [
            {"name": "busybox", "current": "1.37.0-r4", "available": "1.37.0-r5"},
            {
                "name": "luci-app-firewall",
                "current": "25.050.11111~1234567-r1",
                "available": "25.100.12345~abcdef1-r1",
            },
            {"name": "libpcre2-8", "current": "10.42-r1", "available": "10.42-r2"},
        ]

    def test_version_lt_format(self):
        assert parse_apk_upgradable(APK_VERSION_LT) == [
            {"name": "busybox", "current": "1.37.0-r4", "available": "1.37.0-r5"},
            {"name": "kmod-nf-ipt6", "current": "6.6.86-r1", "available": "6.6.93-r1"},
        ]

    def test_installed_lines_are_ignored(self):
        text = "busybox-1.37.0-r5 aarch64_cortex-a53 {busybox} (GPL-2.0) [installed]\n"
        assert parse_apk_upgradable(text) == []


# =====================================================================
# API: package manager selection + errors
# =====================================================================


class TestCheckPackageUpdates:
    @pytest.mark.asyncio
    async def test_apk_selected(self):
        api = _api()
        api._asyncssh_run = AsyncMock(
            return_value=(0, _script_output("apk", APK_LIST_UPGRADABLE), b"")
        )
        result = await api.check_package_updates()
        assert result["package_manager"] == "apk"
        assert result["index_refreshed"] is True
        assert [p["name"] for p in result["packages"]] == [
            "busybox",
            "luci-app-firewall",
            "libpcre2-8",
        ]
        # Runs over SSH, apk preferred, opkg as the alternative
        cmd = api._asyncssh_run.await_args.args[0]
        assert "apk" in cmd and "opkg" in cmd
        assert cmd.index("apk") < cmd.index("opkg")

    @pytest.mark.asyncio
    async def test_opkg_selected(self):
        api = _api()
        api._asyncssh_run = AsyncMock(
            return_value=(0, _script_output("opkg", OPKG_LIST_UPGRADABLE), b"")
        )
        result = await api.check_package_updates()
        assert result["package_manager"] == "opkg"
        assert len(result["packages"]) == 2

    @pytest.mark.asyncio
    async def test_no_package_manager_raises(self):
        api = _api()
        api._asyncssh_run = AsyncMock(return_value=(0, _script_output("none"), b""))
        with pytest.raises(OpenWrtUpdateCheckError, match="package manager"):
            await api.check_package_updates()

    @pytest.mark.asyncio
    async def test_timeout_raises(self):
        api = _api()
        api._asyncssh_run = AsyncMock(return_value=(SUBPROCESS_RC_TIMEOUT, "", b"timeout"))
        with pytest.raises(OpenWrtUpdateCheckError, match="timed out"):
            await api.check_package_updates()

    @pytest.mark.asyncio
    async def test_permission_denied_raises(self):
        api = _api()
        api._asyncssh_run = AsyncMock(return_value=(255, "", b"Permission denied"))
        with pytest.raises(OpenWrtUpdateCheckError, match="SSH"):
            await api.check_package_updates()

    @pytest.mark.asyncio
    async def test_list_failure_raises(self):
        api = _api()
        api._asyncssh_run = AsyncMock(
            return_value=(0, _script_output("opkg", "", list_rc=1), b"")
        )
        with pytest.raises(OpenWrtUpdateCheckError):
            await api.check_package_updates()

    @pytest.mark.asyncio
    async def test_failed_index_refresh_is_flagged_not_fatal(self):
        # One unreachable feed makes `opkg update` exit non-zero; the list of
        # the reachable feeds is still worth showing.
        api = _api()
        api._asyncssh_run = AsyncMock(
            return_value=(
                0,
                _script_output("opkg", OPKG_LIST_UPGRADABLE, update_rc=1),
                b"",
            )
        )
        result = await api.check_package_updates()
        assert result["index_refreshed"] is False
        assert len(result["packages"]) == 2

    def test_install_code_is_gone(self):
        assert not hasattr(OpenWrtAPI, "perform_update")
        assert not hasattr(OpenWrtAPI, "get_available_updates")


# =====================================================================
# Coordinator: stores the result, polls keep it and never run the check
# =====================================================================


def _coordinator(api: AsyncMock) -> OpenWrtCoordinator:
    hass = MagicMock()
    hass.async_create_task = MagicMock(side_effect=lambda coro: coro)
    with patch("homeassistant.helpers.frame.report_usage"):
        return OpenWrtCoordinator(hass=hass, api=api, entry_title="test")


def _poll_api() -> AsyncMock:
    api = AsyncMock()
    api.reset_ssh_fallback_flag = MagicMock()
    api.detect_features = AsyncMock(return_value={})
    api.get_router_info = AsyncMock(return_value={"hostname": "openwrt-test"})
    api.get_wan_status = AsyncMock(return_value={"connected": True})
    api.get_wifi_status = AsyncMock(return_value=[])
    api.get_dhcp_leases = AsyncMock(return_value={})
    api.get_connected_clients = AsyncMock(return_value=[])
    api.get_router_status = AsyncMock(
        return_value={"uptime": 1, "cpu_load": 1.0, "memory": {}}
    )
    api.get_disk_space = AsyncMock(return_value={})
    api.get_tmpfs_stats = AsyncMock(return_value={})
    api.get_network_interfaces = AsyncMock(return_value=[])
    api.get_active_connections = AsyncMock(return_value=0)
    api.check_package_updates = AsyncMock(
        return_value={
            "package_manager": "apk",
            "index_refreshed": True,
            "packages": [
                {"name": "busybox", "current": "1.37.0-r4", "available": "1.37.0-r5"},
                {"name": "luci-base", "current": "1", "available": "2"},
            ],
        }
    )
    return api


class TestCoordinatorUpdateCheck:
    @pytest.mark.asyncio
    async def test_check_stores_result_and_timestamp(self):
        api = _poll_api()
        coord = _coordinator(api)
        coord.data = await coord._async_update_data()
        listener = MagicMock()
        coord.async_add_listener(listener)

        result = await coord.async_check_package_updates()

        updates = coord.data.updates_available
        assert updates is result
        assert updates["available"] is True
        assert updates["count"] == 2
        assert updates["package_manager"] == "apk"
        assert updates["last_check"]
        assert [p["name"] for p in updates["system"]] == ["busybox"]
        assert [p["name"] for p in updates["addons"]] == ["luci-base"]
        assert updates["packages"][0] == {
            "name": "busybox",
            "current": "1.37.0-r4",
            "available": "1.37.0-r5",
        }
        listener.assert_called()

    @pytest.mark.asyncio
    async def test_polls_keep_result_and_never_run_check(self):
        api = _poll_api()
        coord = _coordinator(api)
        coord.data = await coord._async_update_data()
        await coord.async_check_package_updates()
        api.check_package_updates.reset_mock()

        for _ in range(3):
            coord.data = await coord._async_update_data()

        api.check_package_updates.assert_not_awaited()
        assert coord.data.updates_available["count"] == 2
        assert coord.data.updates_available["last_check"]

    @pytest.mark.asyncio
    async def test_poll_without_check_has_no_timestamp(self):
        api = _poll_api()
        coord = _coordinator(api)
        data = await coord._async_update_data()
        api.check_package_updates.assert_not_awaited()
        assert data.updates_available.get("last_check") is None


# =====================================================================
# Button
# =====================================================================


def _button(coordinator, entry, key: str) -> OpenWrtButtonEntity:
    desc = next(d for d in BUTTON_DESCRIPTIONS if d.key == key)
    return OpenWrtButtonEntity(
        coordinator=coordinator, api=AsyncMock(), entry=entry, description=desc
    )


class TestCheckUpdatesButton:
    def test_install_button_not_created(self):
        assert SUFFIX_PERFORM_UPDATES not in {d.key for d in BUTTON_DESCRIPTIONS}

    @pytest.mark.asyncio
    async def test_press_runs_coordinator_check(self, mock_coordinator, mock_config_entry):
        mock_coordinator.async_check_package_updates = AsyncMock(
            return_value={"count": 0, "package_manager": "opkg"}
        )
        btn = _button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES)
        await btn.async_press()
        mock_coordinator.async_check_package_updates.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_press_failure_raises_ha_error(self, mock_coordinator, mock_config_entry):
        mock_coordinator.async_check_package_updates = AsyncMock(
            side_effect=OpenWrtUpdateCheckError("no package manager found")
        )
        btn = _button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES)
        with pytest.raises(HomeAssistantError):
            await btn.async_press()


# =====================================================================
# Sensor
# =====================================================================


def _update_status_desc():
    return next(d for d in SENSOR_DESCRIPTIONS if d.key == "update_status")


class TestUpdateStatusSensor:
    def test_unknown_before_first_check(self, mock_coordinator_data):
        desc = _update_status_desc()
        assert desc.value_fn(mock_coordinator_data) is None

    def test_shows_count_and_list(self, mock_coordinator_data):
        mock_coordinator_data.updates_available = {
            "available": True,
            "count": 1,
            "packages": [
                {"name": "busybox", "current": "1.37.0-r4", "available": "1.37.0-r5"}
            ],
            "system": [
                {"name": "busybox", "current": "1.37.0-r4", "available": "1.37.0-r5"}
            ],
            "addons": [],
            "package_manager": "apk",
            "index_refreshed": True,
            "last_check": "2026-10-28T10:00:00+00:00",
        }
        desc = _update_status_desc()
        assert desc.value_fn(mock_coordinator_data) == "available"
        attrs = desc.extra_attrs_fn(mock_coordinator_data)
        assert attrs["updates_count"] == 1
        assert attrs["packages"][0]["available"] == "1.37.0-r5"
        assert attrs["package_manager"] == "apk"
        assert attrs["last_check"] == "2026-10-28T10:00:00+00:00"
        assert attrs["system_packages"] == ["busybox"]
