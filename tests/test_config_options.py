"""Options of the configuration manager (plan 2026-11-18, section 2).

Schedule, time and drift check appear together with config_backup_enabled,
are saved with the other options (no update listener, no reload) and have
translations in strings.json, en.json and de.json. Mocks only.
"""

from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch

import pytest
from config_manager_kit import ON, cm_env, stop
from core_test_provider import short_tmp_path  # noqa: F401 - Windows path limit
from core_testkit import FakeDisks

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import config_flow as cf
from custom_components.openwrt_router.const import (
    CONFIG_BACKUP_SCHEDULE_DAILY,
    CONFIG_BACKUP_SCHEDULE_OFF,
    CONFIG_BACKUP_SCHEDULES,
    DEFAULT_CONFIG_BACKUP_SCHEDULE,
    DEFAULT_CONFIG_BACKUP_TIME,
    DEFAULT_CONFIG_DRIFT_CHECK,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    OPTION_CONFIG_BACKUP_TIME,
    OPTION_CONFIG_DRIFT_CHECK,
)
from custom_components.openwrt_router.core_models import OPTION_CONFIG_BACKUP_ENABLED

ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
NEW_KEYS = (
    OPTION_CONFIG_BACKUP_SCHEDULE,
    OPTION_CONFIG_BACKUP_TIME,
    OPTION_CONFIG_DRIFT_CHECK,
)


async def _form(options: dict, *, offered: bool) -> dict:
    flow = cf.OpenWrtOptionsFlow()
    flow.hass = MagicMock()
    entry = MagicMock()
    entry.options = options
    with (
        patch.object(
            cf.OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry,
        patch.object(cf, "_offer_config_backup_option", return_value=offered),
    ):
        mock_entry.return_value = entry
        return await flow.async_step_init(user_input=None)


def _defaults(result: dict) -> dict:
    out = {}
    for key in result["data_schema"].schema:
        default = key.default
        out[str(key)] = default() if callable(default) else default
    return out


async def test_fields_shown_with_the_backup_option():
    result = await _form({}, offered=True)
    keys = {str(k) for k in result["data_schema"].schema}
    assert {OPTION_CONFIG_BACKUP_ENABLED, *NEW_KEYS} <= keys
    defaults = _defaults(result)
    assert defaults[OPTION_CONFIG_BACKUP_SCHEDULE] == DEFAULT_CONFIG_BACKUP_SCHEDULE
    assert (
        defaults[OPTION_CONFIG_BACKUP_TIME] == DEFAULT_CONFIG_BACKUP_TIME == "03:30:00"
    )
    assert defaults[OPTION_CONFIG_DRIFT_CHECK] is DEFAULT_CONFIG_DRIFT_CHECK is True
    assert DEFAULT_CONFIG_BACKUP_SCHEDULE == "daily"
    assert set(CONFIG_BACKUP_SCHEDULES) == {"daily", "off"}


async def test_fields_hidden_without_the_backup_option():
    result = await _form({}, offered=False)
    keys = {str(k) for k in result["data_schema"].schema}
    assert not keys & {OPTION_CONFIG_BACKUP_ENABLED, *NEW_KEYS}


async def test_stored_values_are_the_defaults_and_odd_values_fall_back():
    stored = {
        OPTION_CONFIG_BACKUP_ENABLED: True,
        OPTION_CONFIG_BACKUP_SCHEDULE: "off",
        OPTION_CONFIG_BACKUP_TIME: "22:15:00",
        OPTION_CONFIG_DRIFT_CHECK: False,
    }
    defaults = _defaults(await _form(stored, offered=True))
    assert defaults[OPTION_CONFIG_BACKUP_SCHEDULE] == "off"
    assert defaults[OPTION_CONFIG_BACKUP_TIME] == "22:15:00"
    assert defaults[OPTION_CONFIG_DRIFT_CHECK] is False
    odd = {OPTION_CONFIG_BACKUP_SCHEDULE: "hourly", OPTION_CONFIG_BACKUP_TIME: 5}
    defaults = _defaults(await _form(odd, offered=True))
    assert defaults[OPTION_CONFIG_BACKUP_SCHEDULE] == "daily"
    assert defaults[OPTION_CONFIG_BACKUP_TIME] == "03:30:00"


async def test_schedule_selector_uses_its_translation_key():
    result = await _form({}, offered=True)
    for key, value in result["data_schema"].schema.items():
        if str(key) == OPTION_CONFIG_BACKUP_SCHEDULE:
            config = value.config
            assert config["translation_key"] == OPTION_CONFIG_BACKUP_SCHEDULE
            assert list(config["options"]) == ["daily", "off"]
            break
    else:  # pragma: no cover - the field must exist
        pytest.fail("schedule field missing")


async def test_submitted_values_are_saved_without_a_reload():
    flow = cf.OpenWrtOptionsFlow()
    flow.hass = MagicMock()
    flow.context = {}
    entry = MagicMock()
    entry.options = {"keep_me": 1}
    user_input = {
        OPTION_CONFIG_BACKUP_ENABLED: True,
        OPTION_CONFIG_BACKUP_SCHEDULE: "off",
        OPTION_CONFIG_BACKUP_TIME: "01:00:00",
        OPTION_CONFIG_DRIFT_CHECK: False,
    }
    with (
        patch.object(
            cf.OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry,
        patch.object(cf, "async_update_topology_panel_access"),
        patch.object(cf, "_apply_config_backup_option") as apply,
    ):
        mock_entry.return_value = entry
        result = await flow.async_step_init(user_input=user_input)
    assert result["type"] == "create_entry"
    assert result["data"]["keep_me"] == 1
    for key, value in user_input.items():
        assert result["data"][key] == value
    apply.assert_called_once()
    flow.hass.config_entries.async_reload.assert_not_called()
    flow.hass.config_entries.async_schedule_reload.assert_not_called()


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_option_translations_exist(name):
    data = json.loads((ROOT / name).read_text(encoding="utf-8"))
    init = data["options"]["step"]["init"]
    for key in NEW_KEYS:
        assert init["data"][key], (name, key)
        assert init["data_description"][key], (name, key)
    options = data["selector"][OPTION_CONFIG_BACKUP_SCHEDULE]["options"]
    assert set(options) == set(CONFIG_BACKUP_SCHEDULES)


def test_hooks_sit_where_the_plan_puts_them():
    setup = inspect.getsource(integration.async_setup_entry)
    core_hook = setup.index("async_setup_entry_core(hass, entry, coordinator)")
    ours = setup.index("async_setup_config_manager(hass, entry, coordinator)")
    forward = setup.index("async_forward_entry_setups")
    assert core_hook < ours < forward
    unload = inspect.getsource(integration.async_unload_entry)
    release = unload.index("async_release_config_manager(hass, entry.entry_id)")
    assert release < unload.index("async_unload_entry_core(hass, entry)")
    assert unload.index("if unload_ok:") < release


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def test_schedule_reads_new_options_at_next_tick(disks, tmp_path):
    """Saved without a reload: the next tick uses the new values (12:00 now)."""
    env = await cm_env(
        disks,
        tmp_path,
        options={**ON, OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_OFF},
    )
    entry = env.entries[0]

    def collects() -> int:
        return len(env.provider.ops("collect"))

    await env.tick()
    assert collects() == 0  # schedule off
    entry.options = {
        **ON,
        OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_DAILY,
        OPTION_CONFIG_BACKUP_TIME: "13:30:00",
    }
    await env.tick()
    assert collects() == 0  # daily, but 13:30 + offset is still ahead
    entry.options = {**entry.options, OPTION_CONFIG_BACKUP_TIME: "06:00:00"}
    await env.tick()
    assert collects() == 1
    entry.options = {**entry.options, OPTION_CONFIG_BACKUP_TIME: "garbage"}
    assert env.runtime.next_run_at(env.rid) is not None  # falls back to 03:30
    await stop(env)
