"""Tests for the "extended Wi-Fi sensors" options switch."""
from __future__ import annotations

from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from homeassistant.helpers import entity_registry as er

from custom_components.openwrt_router.config_flow import OpenWrtOptionsFlow
from custom_components.openwrt_router.const import (
    CONF_EXTENDED_WIFI_SENSORS,
    CONF_TOPOLOGY_PANEL_ALL_USERS,
    CONF_TOPOLOGY_PORT_DEBUG,
    OPT_EXTENDED_WIFI_PREEXISTING,
)
from custom_components.openwrt_router.extended_sensors import (
    async_apply_extended_wifi_sensors,
)
from custom_components.openwrt_router.sensor import (
    OpenWrtAPInterfaceSensor,
    OpenWrtPortSensor,
    OpenWrtRadioSensor,
)

INTEGRATION = er.RegistryEntryDisabler.INTEGRATION
USER = er.RegistryEntryDisabler.USER


def _ent(unique_id, disabled_by=None, domain="sensor"):
    return MagicMock(
        entity_id=f"{domain}.{unique_id}",
        unique_id=unique_id,
        disabled_by=disabled_by,
        domain=domain,
    )


def _registry_entries():
    return [
        _ent("E1_radio_phy0-ap0_signal", INTEGRATION),  # → on
        _ent("E1_ap_phy1-ap0_channel", INTEGRATION),  # → on
        _ent("E1_port_lan1_status", None),  # already on (user)
        _ent("E1_port_lan2_status", USER),  # user-disabled: never touch
        _ent("E1_uptime", None),  # not extended
        _ent("E1_iface_eth0_rx", INTEGRATION),  # interface sensors: not part
        _ent("E1_wan_port_status", INTEGRATION),  # "_port_" but not anchored
        _ent("E1_radio_phy0_wifi", INTEGRATION, domain="switch"),  # other platform
    ]


def _apply(entries, enabled, preexisting=()):
    entry = MagicMock(entry_id="E1")
    with patch(
        "custom_components.openwrt_router.extended_sensors.er.async_get"
    ) as mock_get, patch(
        "custom_components.openwrt_router.extended_sensors.er.async_entries_for_config_entry",
        return_value=entries,
    ):
        ent_reg = MagicMock()
        mock_get.return_value = ent_reg
        result = async_apply_extended_wifi_sensors(
            MagicMock(), entry, enabled, list(preexisting)
        )
    return ent_reg, result


class TestApply:
    def test_switch_on_enables_only_integration_disabled_extended_sensors(self):
        ent_reg, preexisting = _apply(_registry_entries(), True)

        changed = {
            c.args[0]: c.kwargs["disabled_by"]
            for c in ent_reg.async_update_entity.call_args_list
        }
        assert changed == {
            "sensor.E1_radio_phy0-ap0_signal": None,
            "sensor.E1_ap_phy1-ap0_channel": None,
        }
        assert preexisting == ["E1_port_lan1_status"]

    def test_switch_off_restores_previous_state(self):
        entries = _registry_entries()
        # State after switching on: the two formerly disabled ones are on now.
        entries[0].disabled_by = None
        entries[1].disabled_by = None

        ent_reg, result = _apply(entries, False, preexisting=["E1_port_lan1_status"])

        changed = {
            c.args[0]: c.kwargs["disabled_by"]
            for c in ent_reg.async_update_entity.call_args_list
        }
        assert changed == {
            "sensor.E1_radio_phy0-ap0_signal": INTEGRATION,
            "sensor.E1_ap_phy1-ap0_channel": INTEGRATION,
        }
        assert result == []

    def test_preexisting_is_keyed_by_unique_id_not_entity_id(self):
        """A renamed entity_id between on and off must not lose the user's choice."""
        ent = _ent("E1_port_lan1_status", None)
        ent.entity_id = "sensor.renamed_by_user"
        ent_reg, _ = _apply([ent], False, preexisting=["E1_port_lan1_status"])
        ent_reg.async_update_entity.assert_not_called()


def _options_flow(options):
    flow = OpenWrtOptionsFlow()
    entry = MagicMock()
    entry.options = options
    flow.hass = MagicMock()
    return flow, entry


class TestOptionsFlow:
    @pytest.mark.asyncio
    async def test_form_offers_both_options(self):
        flow, entry = _options_flow({})
        with patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry:
            mock_entry.return_value = entry
            result = await flow.async_step_init(user_input=None)
        keys = {str(k) for k in result["data_schema"].schema}
        assert keys == {
            CONF_EXTENDED_WIFI_SENSORS,
            CONF_TOPOLOGY_PORT_DEBUG,
            CONF_TOPOLOGY_PANEL_ALL_USERS,
        }

    @pytest.mark.asyncio
    async def test_switching_on_applies_and_stores_preexisting(self):
        flow, entry = _options_flow({CONF_TOPOLOGY_PORT_DEBUG: True})
        with patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry, patch(
            "custom_components.openwrt_router.config_flow.async_apply_extended_wifi_sensors",
            return_value=["E1_port_lan1_status"],
        ) as mock_apply:
            mock_entry.return_value = entry
            result = await flow.async_step_init(
                user_input={CONF_EXTENDED_WIFI_SENSORS: True}
            )

        mock_apply.assert_called_once_with(flow.hass, entry, True, [])
        assert result["data"] == {
            CONF_TOPOLOGY_PORT_DEBUG: True,  # preserved, not wiped
            CONF_EXTENDED_WIFI_SENSORS: True,
            OPT_EXTENDED_WIFI_PREEXISTING: ["E1_port_lan1_status"],
        }

    @pytest.mark.asyncio
    async def test_switching_off_passes_stored_preexisting(self):
        flow, entry = _options_flow(
            {
                CONF_EXTENDED_WIFI_SENSORS: True,
                OPT_EXTENDED_WIFI_PREEXISTING: ["E1_port_lan1_status"],
            }
        )
        with patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry, patch(
            "custom_components.openwrt_router.config_flow.async_apply_extended_wifi_sensors",
            return_value=[],
        ) as mock_apply:
            mock_entry.return_value = entry
            result = await flow.async_step_init(
                user_input={CONF_EXTENDED_WIFI_SENSORS: False}
            )

        mock_apply.assert_called_once_with(
            flow.hass, entry, False, ["E1_port_lan1_status"]
        )
        assert result["data"][OPT_EXTENDED_WIFI_PREEXISTING] == []

    @pytest.mark.asyncio
    async def test_unchanged_switch_does_not_touch_registry(self):
        flow, entry = _options_flow({CONF_EXTENDED_WIFI_SENSORS: True})
        with patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry, patch(
            "custom_components.openwrt_router.config_flow.async_apply_extended_wifi_sensors"
        ) as mock_apply:
            mock_entry.return_value = entry
            await flow.async_step_init(
                user_input={
                    CONF_EXTENDED_WIFI_SENSORS: True,
                    CONF_TOPOLOGY_PORT_DEBUG: True,
                }
            )
        mock_apply.assert_not_called()


class TestNewEntitiesFollowOption:
    @pytest.mark.parametrize(
        ("cls", "args"),
        [
            (OpenWrtRadioSensor, ("phy0-ap0", "signal")),
            (OpenWrtAPInterfaceSensor, ("phy0-ap0", "channel")),
            (OpenWrtPortSensor, ("lan1", "status")),
        ],
    )
    @pytest.mark.parametrize("option", [True, False, None])
    def test_enabled_default_follows_option(self, cls, args, option):
        entry = MagicMock(entry_id="E1")
        entry.options = {} if option is None else {CONF_EXTENDED_WIFI_SENSORS: option}
        sensor = cls(MagicMock(), entry, *args)
        assert sensor.entity_registry_enabled_default is bool(option)
