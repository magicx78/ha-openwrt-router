"""Options of WiFi RF Intelligence (1.48.0, sub-step A).

All switches are off by default, the cadence N is validated (1-60,
default 5), odd stored values fall back, the options are saved without a
reload and have translations in strings.json, en.json and de.json.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
import voluptuous as vol

from custom_components.openwrt_router import config_flow as cf
from custom_components.openwrt_router.const import (
    DEFAULT_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_ASSOCLIST,
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_LISTS,
    OPTION_WIFI_RF_SURVEY,
    WIFI_RF_SWITCH_OPTIONS,
)

ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
RF_KEYS = (*WIFI_RF_SWITCH_OPTIONS, OPTION_WIFI_RF_EVERY_N_POLLS)


async def _form(options: dict) -> dict:
    flow = cf.OpenWrtOptionsFlow()
    flow.hass = MagicMock()
    entry = MagicMock()
    entry.options = options
    with (
        patch.object(
            cf.OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry,
        patch.object(cf, "_offer_config_backup_option", return_value=False),
    ):
        mock_entry.return_value = entry
        return await flow.async_step_init(user_input=None)


def _defaults(result: dict) -> dict:
    out = {}
    for key in result["data_schema"].schema:
        default = key.default
        out[str(key)] = default() if callable(default) else default
    return out


def _validator(result: dict, name: str):
    for key, value in result["data_schema"].schema.items():
        if str(key) == name:
            return value
    raise AssertionError(name)


async def test_all_switches_off_by_default_and_cadence_five():
    defaults = _defaults(await _form({}))
    assert set(RF_KEYS) <= set(defaults)
    for key in WIFI_RF_SWITCH_OPTIONS:
        assert defaults[key] is False, key
    assert defaults[OPTION_WIFI_RF_EVERY_N_POLLS] == DEFAULT_WIFI_RF_EVERY_N_POLLS == 5
    assert set(WIFI_RF_SWITCH_OPTIONS) == {
        OPTION_WIFI_RF_ENABLED,
        OPTION_WIFI_RF_GET_STATUS,
        OPTION_WIFI_RF_ASSOCLIST,
        OPTION_WIFI_RF_LISTS,
        OPTION_WIFI_RF_SURVEY,
    }


async def test_stored_values_shown_and_odd_values_fall_back():
    stored = {OPTION_WIFI_RF_ENABLED: True, OPTION_WIFI_RF_EVERY_N_POLLS: 12}
    defaults = _defaults(await _form(stored))
    assert defaults[OPTION_WIFI_RF_ENABLED] is True
    assert defaults[OPTION_WIFI_RF_GET_STATUS] is False
    assert defaults[OPTION_WIFI_RF_EVERY_N_POLLS] == 12
    for odd in (0, 61, "5", True, None, 2.5):
        odd_opts = {OPTION_WIFI_RF_ENABLED: "yes", OPTION_WIFI_RF_EVERY_N_POLLS: odd}
        defaults = _defaults(await _form(odd_opts))
        assert defaults[OPTION_WIFI_RF_EVERY_N_POLLS] == 5, odd
        # Only a real True switches on, never a truthy string.
        assert defaults[OPTION_WIFI_RF_ENABLED] is False


@pytest.mark.parametrize("value", [1, 5, 60, "7"])
async def test_cadence_accepts_the_range(value):
    check = _validator(await _form({}), OPTION_WIFI_RF_EVERY_N_POLLS)
    assert check(value) == int(value)


@pytest.mark.parametrize("value", [0, 61, -1, "x", None])
async def test_cadence_rejects_values_outside_the_range(value):
    check = _validator(await _form({}), OPTION_WIFI_RF_EVERY_N_POLLS)
    with pytest.raises(vol.Invalid):
        check(value)


async def test_submitted_values_are_saved_without_a_reload():
    flow = cf.OpenWrtOptionsFlow()
    flow.hass = MagicMock()
    flow.context = {}
    entry = MagicMock()
    entry.options = {"keep_me": 1}
    user_input = {
        OPTION_WIFI_RF_ENABLED: True,
        OPTION_WIFI_RF_GET_STATUS: True,
        OPTION_WIFI_RF_ASSOCLIST: False,
        OPTION_WIFI_RF_LISTS: False,
        OPTION_WIFI_RF_SURVEY: False,
        OPTION_WIFI_RF_EVERY_N_POLLS: 10,
    }
    with (
        patch.object(
            cf.OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry,
        patch.object(cf, "async_update_topology_panel_access"),
    ):
        mock_entry.return_value = entry
        result = await flow.async_step_init(user_input=user_input)
    assert result["type"] == "create_entry"
    assert result["data"]["keep_me"] == 1
    for key, value in user_input.items():
        assert result["data"][key] == value
    flow.hass.config_entries.async_reload.assert_not_called()
    flow.hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_option_translations_exist(name):
    data = json.loads((ROOT / name).read_text(encoding="utf-8"))
    init = data["options"]["step"]["init"]
    for key in RF_KEYS:
        assert init["data"][key], (name, key)
        assert init["data_description"][key], (name, key)


def test_strings_and_english_translation_match():
    strings = json.loads((ROOT / "strings.json").read_text(encoding="utf-8"))
    en = json.loads((ROOT / "translations/en.json").read_text(encoding="utf-8"))
    a = strings["options"]["step"]["init"]
    b = en["options"]["step"]["init"]
    for part in ("data", "data_description"):
        for key in RF_KEYS:
            assert a[part][key] == b[part][key]
