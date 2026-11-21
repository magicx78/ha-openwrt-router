"""The Network Time Machine switch in the router options flow (Phase A).

ONE switch for the fleet, off by default: stored in the options of every
router entry. Saving it on one router writes the same value to every other
router entry (only where it differs, all other options kept); the form
shows the fleet state. No update listener, no reload. Mocks only.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from core_testkit import FakeEntry, make_hass

from custom_components.openwrt_router import config_flow
from custom_components.openwrt_router.config_flow import OpenWrtOptionsFlow
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.tm_query import time_machine_enabled

KEY = OPTION_TIME_MACHINE_ENABLED
ROOT = Path(__file__).resolve().parents[1] / "custom_components" / "openwrt_router"


def fleet(*options: dict[str, Any]) -> tuple[Any, list[FakeEntry]]:
    entries = [FakeEntry(f"e{i + 1}", options=dict(o)) for i, o in enumerate(options)]
    hass = make_hass(entries)

    def update(entry: Any, *, options: dict[str, Any]) -> bool:
        entry.options = options
        return True

    hass.config_entries.async_update_entry = MagicMock(side_effect=update)
    return hass, entries


async def _form(entry: Any, hass: Any) -> dict[str, Any]:
    flow = OpenWrtOptionsFlow()
    flow.hass = hass
    with patch.object(
        OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
    ) as mock_entry:
        mock_entry.return_value = entry
        result = await flow.async_step_init(user_input=None)
    keys = {str(k): k for k in result["data_schema"].schema}
    marker = keys[KEY]
    return marker.default() if callable(marker.default) else marker.default


async def _save(entry: Any, user_input: dict[str, Any], hass: Any) -> Any:
    flow = OpenWrtOptionsFlow()
    flow.hass = hass
    flow.context = {}
    with (
        patch.object(
            OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
        ) as mock_entry,
        patch(
            "custom_components.openwrt_router.config_flow."
            "async_update_topology_panel_access",
            AsyncMock(),
        ),
    ):
        mock_entry.return_value = entry
        return await flow.async_step_init(user_input=user_input)


async def test_the_switch_is_offered_and_off_by_default() -> None:
    hass, (entry,) = fleet({})
    assert await _form(entry, hass) is False
    assert time_machine_enabled(hass) is False
    assert await _form(entry, MagicMock()) is False  # a hass without entries


@pytest.mark.parametrize("stored", ["yes", 1, None])
async def test_odd_stored_values_show_off(stored: Any) -> None:
    hass, (entry,) = fleet({KEY: stored})
    assert await _form(entry, hass) is False
    assert time_machine_enabled(hass) is False


async def test_the_form_shows_the_fleet_state() -> None:
    hass, (first, second) = fleet({}, {KEY: True})
    assert time_machine_enabled(hass) is True
    assert await _form(first, hass) is True
    assert await _form(second, hass) is True


async def test_saving_on_writes_through_and_keeps_every_other_option() -> None:
    hass, (first, second, third) = fleet(
        {"wifi_rf_enabled": True, "_internal": 7},
        {"traffic_enabled": True, "_secret_marker": "x"},
        {KEY: True, "extended_wifi_sensors": True},
    )
    result = await _save(first, {KEY: True, "topology_port_debug": True}, hass)
    assert result["type"] == "create_entry"
    assert result["data"] == {
        "wifi_rf_enabled": True,
        "_internal": 7,
        KEY: True,
        "topology_port_debug": True,
    }
    # the second router gets the value, the third already had it
    assert second.options == {"traffic_enabled": True, "_secret_marker": "x", KEY: True}
    assert third.options == {KEY: True, "extended_wifi_sensors": True}
    assert hass.config_entries.async_update_entry.call_count == 1


async def test_saving_off_switches_the_whole_fleet_off() -> None:
    hass, (first, second, third) = fleet({KEY: True}, {KEY: True}, {})
    result = await _save(first, {KEY: False}, hass)
    assert result["data"][KEY] is False
    assert second.options == {KEY: False}
    assert third.options == {}  # off already (missing = off): untouched
    first.options = result["data"]  # what HA stores for the saved entry
    assert time_machine_enabled(hass) is False


async def test_a_form_without_the_key_writes_nothing_through() -> None:
    hass, (first, _second) = fleet({"a": 1}, {KEY: True})
    result = await _save(first, {"topology_port_debug": True}, hass)
    assert KEY not in result["data"]
    hass.config_entries.async_update_entry.assert_not_called()


async def test_a_failing_write_through_never_stops_the_save(caplog) -> None:
    hass, (first, _second) = fleet({}, {})
    hass.config_entries.async_update_entry = MagicMock(
        side_effect=RuntimeError("02:00:5E:10:00:01")
    )
    with caplog.at_level("WARNING"):
        result = await _save(first, {KEY: True}, hass)
    assert result["data"][KEY] is True
    assert "RuntimeError" in caplog.text and "02:00:5E" not in caplog.text


def test_translations_name_and_describe_the_switch() -> None:
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        init = json.loads((ROOT / name).read_text(encoding="utf-8"))["options"]["step"][
            "init"
        ]
        assert KEY in init["data"][KEY] or "(time_machine_enabled)" in init["data"][KEY]
        assert len(init["data_description"][KEY]) > 100, name
    assert config_flow.OPTION_TIME_MACHINE_ENABLED == KEY
