"""Tests for the OpenWrt Router integration __init__.py."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router import (
    OpenWrtRuntimeData,
    async_setup_entry,
    async_unload_entry,
    async_reload_entry,
    PLATFORMS,
)
from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
    PROTOCOL_HTTP,
)

from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import entity_registry as er


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_entry():
    """Create a mock config entry."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.title = "OpenWrt-Test"
    entry.data = {
        CONF_HOST: "192.168.1.1",
        CONF_PORT: 80,
        CONF_USERNAME: "root",
        CONF_PASSWORD: "secret",
        CONF_PROTOCOL: PROTOCOL_HTTP,
    }
    return entry


def _make_hass():
    """Create a mock HomeAssistant instance."""
    hass = MagicMock()
    hass.config_entries = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock()
    hass.config_entries.async_unload_platforms = AsyncMock(return_value=True)
    return hass


# =====================================================================
# async_setup_entry
# =====================================================================

class TestSetupEntry:
    @pytest.mark.asyncio
    async def test_successful_setup(self):
        """Full successful setup: login, coordinator refresh, platform forward."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {"model": "TestRouter"}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        mock_api.login.assert_awaited_once()
        mock_api.reset_acl_blocked.assert_called_once()
        mock_coordinator.async_config_entry_first_refresh.assert_awaited_once()
        hass.config_entries.async_forward_entry_setups.assert_awaited_once_with(
            entry, PLATFORMS
        )
        # runtime_data should be set
        assert isinstance(entry.runtime_data, OpenWrtRuntimeData)

    @pytest.mark.asyncio
    async def test_auth_error_raises_config_entry_auth_failed(self):
        """Login auth error should raise ConfigEntryAuthFailed."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtAuthError("bad creds"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryAuthFailed):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_connection_error_raises_not_ready(self):
        """Connection error during login should raise ConfigEntryNotReady."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtConnectionError("down"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryNotReady):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_timeout_error_raises_not_ready(self):
        """Timeout error during login should raise ConfigEntryNotReady."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), pytest.raises(ConfigEntryNotReady):
            await async_setup_entry(hass, entry)

    @pytest.mark.asyncio
    async def test_default_protocol_when_missing(self):
        """Should use default protocol when CONF_PROTOCOL is not in data."""
        hass = _make_hass()
        entry = _make_entry()
        del entry.data[CONF_PROTOCOL]

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ) as api_cls, patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ):
            await async_setup_entry(hass, entry)
            # API should have been created with the default protocol
            api_cls.assert_called_once()

    @pytest.mark.asyncio
    async def test_acl_deployed_before_first_refresh(self):
        """ensure_acl must run BEFORE the first refresh; on a deploy the API is
        re-logged-in and its ACL-block cache cleared, so the first poll sees the
        freshly granted methods (no 'degraded until reload')."""
        hass = _make_hass()
        entry = _make_entry()

        order: list[str] = []
        mock_api = AsyncMock()
        mock_api.login = AsyncMock(side_effect=lambda: order.append("login"))
        mock_api.reset_acl_blocked = MagicMock(
            side_effect=lambda: order.append("reset")
        )

        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock(
            side_effect=lambda: order.append("first_refresh")
        )
        mock_coordinator.router_info = {}

        async def _ensure(_api):
            order.append("ensure_acl")
            return True  # simulate a deploy happened

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            side_effect=_ensure,
        ), patch(
            "custom_components.openwrt_router._ACL_DEPLOY_GRACE_S", 0
        ), patch(
            "custom_components.openwrt_router._ACL_LOGIN_RETRY_DELAY_S", 0
        ):
            result = await async_setup_entry(hass, entry)

        assert result is True
        assert order.index("ensure_acl") < order.index("first_refresh")
        assert order.index("reset") < order.index("first_refresh")
        # login called twice: initial + after the deploy's rpcd restart
        assert order.count("login") == 2
        mock_api.reset_acl_blocked.assert_called_once()


# =====================================================================
# async_unload_entry
# =====================================================================

class TestUnloadEntry:
    @pytest.mark.asyncio
    async def test_unload_success(self):
        """Should forward unload to all platforms."""
        hass = _make_hass()
        entry = _make_entry()

        result = await async_unload_entry(hass, entry)
        assert result is True
        hass.config_entries.async_unload_platforms.assert_awaited_once_with(
            entry, PLATFORMS
        )


# =====================================================================
# async_reload_entry
# =====================================================================

class TestReloadEntry:
    @pytest.mark.asyncio
    async def test_reload_calls_unload_then_setup(self):
        """Reload should call unload then setup."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.login = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        mock_coordinator.router_info = {}

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ):
            await async_reload_entry(hass, entry)

        # unload was called
        hass.config_entries.async_unload_platforms.assert_awaited_once()
        # setup was called (forward_entry_setups)
        hass.config_entries.async_forward_entry_setups.assert_awaited_once()


# =====================================================================
# OpenWrtRuntimeData
# =====================================================================

class TestRuntimeData:
    def test_dataclass_fields(self):
        api = MagicMock()
        coordinator = MagicMock()
        rd = OpenWrtRuntimeData(api=api, coordinator=coordinator)
        assert rd.api is api
        assert rd.coordinator is coordinator

    def test_platforms_list(self):
        """PLATFORMS should contain all expected platforms."""
        from homeassistant.const import Platform
        assert Platform.SENSOR in PLATFORMS
        assert Platform.SWITCH in PLATFORMS
        assert Platform.DEVICE_TRACKER in PLATFORMS
        assert Platform.BUTTON in PLATFORMS
        assert Platform.BINARY_SENSOR in PLATFORMS
        assert len(PLATFORMS) == 5


# ---------------------------------------------------------------------------
# v1.17.2 — orphan device merge
# ---------------------------------------------------------------------------

class TestMergeOrphanMacDevices:
    """Regression for v1.17.0 → 1.17.2.

    v1.17.0 used `(DOMAIN, mac)` as device identifier in binary_sensor.py and
    OpenWrtRouterStatusSensor; v1.17.1 reverted to entry_id but HA does not
    automatically migrate existing entity↔device links. The setup-time merge
    moves entities from any non-canonical device to the canonical one and
    removes the orphan.
    """

    def _setup_registry(self, canonical_id="dev_canon", orphan_id="dev_orphan"):
        from custom_components.openwrt_router import _merge_orphan_mac_devices
        from custom_components.openwrt_router.const import DOMAIN

        canonical = MagicMock()
        canonical.id = canonical_id
        canonical.identifiers = {(DOMAIN, "test_entry_id")}

        orphan = MagicMock()
        orphan.id = orphan_id
        orphan.identifiers = {(DOMAIN, "aabbccddeeff")}

        return canonical, orphan, _merge_orphan_mac_devices, DOMAIN

    def test_moves_entities_and_removes_orphan(self):
        canonical, orphan, merge, _ = self._setup_registry()

        ent_a = MagicMock(entity_id="binary_sensor.x_connectivity")
        ent_b = MagicMock(entity_id="sensor.x_router_status")

        with patch(
            "custom_components.openwrt_router.dr.async_get"
        ) as mock_dr_get, patch(
            "custom_components.openwrt_router.er.async_get"
        ) as mock_er_get, patch(
            "custom_components.openwrt_router.dr.async_entries_for_config_entry",
            return_value=[canonical, orphan],
        ), patch(
            "custom_components.openwrt_router.er.async_entries_for_device",
            return_value=[ent_a, ent_b],
        ):
            dev_reg = MagicMock()
            ent_reg = MagicMock()
            mock_dr_get.return_value = dev_reg
            mock_er_get.return_value = ent_reg

            entry = _make_entry()
            merge(MagicMock(), entry)

            # Both entities re-parented to canonical device
            assert ent_reg.async_update_entity.call_count == 2
            ent_reg.async_update_entity.assert_any_call(
                "binary_sensor.x_connectivity", device_id="dev_canon"
            )
            ent_reg.async_update_entity.assert_any_call(
                "sensor.x_router_status", device_id="dev_canon"
            )
            # Orphan removed
            dev_reg.async_remove_device.assert_called_once_with("dev_orphan")

    def test_noop_when_no_canonical_device(self):
        """If no canonical device exists yet, leave orphans alone (next setup will merge)."""
        from custom_components.openwrt_router import _merge_orphan_mac_devices

        with patch(
            "custom_components.openwrt_router.dr.async_get"
        ) as mock_dr_get, patch(
            "custom_components.openwrt_router.er.async_get"
        ) as mock_er_get, patch(
            "custom_components.openwrt_router.dr.async_entries_for_config_entry",
            return_value=[],
        ):
            dev_reg = MagicMock()
            mock_dr_get.return_value = dev_reg
            mock_er_get.return_value = MagicMock()

            _merge_orphan_mac_devices(MagicMock(), _make_entry())
            dev_reg.async_remove_device.assert_not_called()

    def test_disables_legacy_dynamic_sensors(self):
        """v1.17.4 mass-disable migration."""
        from custom_components.openwrt_router import _disable_legacy_dynamic_sensors

        ent_iface = MagicMock(
            entity_id="sensor.x_eth0_rx",
            unique_id="entry_iface_eth0_rx",
            disabled_by=None,
        )
        ent_radio = MagicMock(
            entity_id="sensor.x_phy0_signal",
            unique_id="entry_radio_phy0_signal",
            disabled_by=None,
        )
        ent_ap = MagicMock(
            entity_id="sensor.x_phy0_ap0_channel",
            unique_id="entry_ap_phy0-ap0_channel",
            disabled_by=None,
        )
        ent_port = MagicMock(
            entity_id="sensor.x_lan1_link",
            unique_id="entry_port_lan1_status",
            disabled_by=None,
        )
        ent_static = MagicMock(
            entity_id="sensor.x_uptime",
            unique_id="entry_uptime",
            disabled_by=None,
        )
        ent_already_disabled = MagicMock(
            entity_id="sensor.x_disabled",
            unique_id="entry_iface_old_rx",
            disabled_by="user",
        )

        with patch(
            "custom_components.openwrt_router.er.async_get"
        ) as mock_er_get, patch(
            "custom_components.openwrt_router.er.async_entries_for_config_entry",
            return_value=[
                ent_iface, ent_radio, ent_ap, ent_port,
                ent_static, ent_already_disabled,
            ],
        ):
            ent_reg = MagicMock()
            mock_er_get.return_value = ent_reg

            _disable_legacy_dynamic_sensors(MagicMock(), _make_entry())

            # 4 dynamic disabled, static/already-disabled untouched
            assert ent_reg.async_update_entity.call_count == 4
            disabled_ids = {
                c.args[0] for c in ent_reg.async_update_entity.call_args_list
            }
            assert disabled_ids == {
                "sensor.x_eth0_rx",
                "sensor.x_phy0_signal",
                "sensor.x_phy0_ap0_channel",
                "sensor.x_lan1_link",
            }

    def test_noop_on_clean_install(self):
        """Only one device, the canonical one — nothing to merge."""
        canonical, _, merge, _ = self._setup_registry()

        with patch(
            "custom_components.openwrt_router.dr.async_get"
        ) as mock_dr_get, patch(
            "custom_components.openwrt_router.er.async_get"
        ) as mock_er_get, patch(
            "custom_components.openwrt_router.dr.async_entries_for_config_entry",
            return_value=[canonical],
        ):
            dev_reg = MagicMock()
            mock_dr_get.return_value = dev_reg
            mock_er_get.return_value = MagicMock()

            merge(MagicMock(), _make_entry())
            dev_reg.async_remove_device.assert_not_called()


# ---------------------------------------------------------------------------
# v1.28.3 — legacy dynamic-sensor disable runs once per entry
# ---------------------------------------------------------------------------

class TestLegacySensorDisableRunsOnce:
    """Regression: re-enabled radio/AP/port sensors were disabled on every reload.

    Up to v1.28.2 ``_disable_legacy_dynamic_sensors`` ran in every
    ``async_setup_entry``. It is now a one-time config-entry migration
    (minor version 1 → 2).
    """

    @staticmethod
    def _ent(entity_id, unique_id, disabled_by=None):
        return MagicMock(
            entity_id=entity_id, unique_id=unique_id, disabled_by=disabled_by
        )

    def _run_disable(self, entities):
        from custom_components.openwrt_router import _disable_legacy_dynamic_sensors

        with patch(
            "custom_components.openwrt_router.er.async_get"
        ) as mock_er_get, patch(
            "custom_components.openwrt_router.er.async_entries_for_config_entry",
            return_value=entities,
        ):
            ent_reg = MagicMock()
            mock_er_get.return_value = ent_reg
            _disable_legacy_dynamic_sensors(MagicMock(), _make_entry())
        return ent_reg

    @pytest.mark.asyncio
    async def test_setup_no_longer_disables_dynamic_sensors(self):
        """A reload must not touch sensors the user re-enabled."""
        hass = _make_hass()
        entry = _make_entry()

        mock_api = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ), patch(
            "custom_components.openwrt_router._merge_orphan_mac_devices"
        ), patch(
            "custom_components.openwrt_router._disable_legacy_dynamic_sensors"
        ) as mock_disable:
            assert await async_setup_entry(hass, entry) is True
            assert await async_setup_entry(hass, entry) is True

        mock_disable.assert_not_called()

    def test_user_reenabled_sensors_survive_migration(self):
        """Entry already cleaned by an earlier version: leave enabled ones alone."""
        ent_reg = self._run_disable(
            [
                self._ent("sensor.x_phy1_ap0_channel", "entry_ap_phy1-ap0_channel"),
                self._ent("sensor.x_phy0_signal", "entry_radio_phy0_signal"),
                self._ent(
                    "sensor.x_lan1_link",
                    "entry_port_lan1_status",
                    disabled_by=er.RegistryEntryDisabler.INTEGRATION,
                ),
            ]
        )
        ent_reg.async_update_entity.assert_not_called()

    def test_pre_v1174_entry_still_cleaned(self):
        """No integration-disabled dynamic sensor yet: the cleanup still runs."""
        ent_reg = self._run_disable(
            [
                self._ent("sensor.x_phy1_ap0_channel", "entry_ap_phy1-ap0_channel"),
                self._ent(
                    "sensor.x_eth0_rx",
                    "entry_iface_eth0_rx",
                    disabled_by=er.RegistryEntryDisabler.USER,
                ),
                self._ent("sensor.x_uptime", "entry_uptime"),
            ]
        )
        ent_reg.async_update_entity.assert_called_once_with(
            "sensor.x_phy1_ap0_channel",
            disabled_by=er.RegistryEntryDisabler.INTEGRATION,
        )

    @pytest.mark.asyncio
    async def test_migration_minor1_runs_disable_and_bumps(self):
        from custom_components.openwrt_router import async_migrate_entry

        entry = _make_entry()
        entry.version = 2
        entry.minor_version = 1
        hass = MagicMock()

        with patch(
            "custom_components.openwrt_router._disable_legacy_dynamic_sensors"
        ) as mock_disable:
            assert await async_migrate_entry(hass, entry) is True

        mock_disable.assert_called_once_with(hass, entry)
        hass.config_entries.async_update_entry.assert_called_once_with(
            entry, minor_version=2
        )

    @pytest.mark.asyncio
    async def test_migration_minor2_is_noop(self):
        from custom_components.openwrt_router import async_migrate_entry

        entry = _make_entry()
        entry.version = 2
        entry.minor_version = 2
        hass = MagicMock()

        with patch(
            "custom_components.openwrt_router._disable_legacy_dynamic_sensors"
        ) as mock_disable:
            assert await async_migrate_entry(hass, entry) is True

        mock_disable.assert_not_called()
        hass.config_entries.async_update_entry.assert_not_called()

    def test_new_entries_start_at_minor_version_2(self):
        from custom_components.openwrt_router.config_flow import OpenWrtConfigFlow

        assert OpenWrtConfigFlow.VERSION == 2
        assert OpenWrtConfigFlow.MINOR_VERSION == 2


class TestOutageTrackerWiring:
    @pytest.mark.asyncio
    async def test_setup_registers_router_and_unload_unregisters(self):
        hass = _make_hass()
        entry = _make_entry()
        mock_api = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        tracker = MagicMock()

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ), patch(
            "custom_components.openwrt_router.async_get_outage_tracker",
            return_value=tracker,
        ):
            assert await async_setup_entry(hass, entry) is True

        assert tracker.register.call_args.args[:2] == ("test_entry_id", "OpenWrt-Test")
        mock_coordinator.attach_outage_tracker.assert_called_once_with(tracker)
        # The unload callbacks unregister exactly this entry and drop its
        # RAM pressure issue.
        with patch("custom_components.openwrt_router.issues.ir") as mock_ir:
            for call in entry.async_on_unload.call_args_list:
                call.args[0]()
        tracker.unregister.assert_called_once_with("test_entry_id")
        mock_ir.async_delete_issue.assert_called_once_with(
            hass, "openwrt_router", "ram_high_test_entry_id"
        )


class TestChannelPlanWiring:
    @pytest.mark.asyncio
    async def test_listener_evaluates_and_unload_unregisters(self):
        hass = _make_hass()
        entry = _make_entry()
        mock_api = AsyncMock()
        mock_api.reset_acl_blocked = MagicMock()
        mock_coordinator = MagicMock()
        mock_coordinator.async_config_entry_first_refresh = AsyncMock()
        remove_listener = MagicMock()
        mock_coordinator.async_add_listener = MagicMock(return_value=remove_listener)
        monitor = MagicMock()

        with patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.OpenWrtAPI",
            return_value=mock_api,
        ), patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=mock_coordinator,
        ), patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl",
            AsyncMock(return_value=False),
        ), patch(
            "custom_components.openwrt_router.async_get_outage_tracker",
            return_value=MagicMock(),
        ), patch(
            "custom_components.openwrt_router.async_get_channel_plan_monitor",
            return_value=monitor,
        ):
            assert await async_setup_entry(hass, entry) is True

        listener = mock_coordinator.async_add_listener.call_args.args[0]
        listener()
        monitor.evaluate.assert_called_once_with("test_entry_id")

        callbacks = [c.args[0] for c in entry.async_on_unload.call_args_list]
        assert remove_listener in callbacks
        with patch("custom_components.openwrt_router.issues.ir"):
            for cb in callbacks:
                cb()
        monitor.unregister.assert_called_once_with("test_entry_id")
