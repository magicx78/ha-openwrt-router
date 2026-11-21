"""The traffic switch in the router options flow (Phase K).

``traffic_enabled`` per router (default off), three extra-call switches and
the history profile (``compact`` default, ``standard`` selectable). Saving
merges into the existing options and applies them to the fleet engine
directly (no update listener, no reload). Mocks only.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
import voluptuous as vol
from core_testkit import FakeDisks, drain
from test_traffic_engine import (
    _reset_pending,  # noqa: F401 - autouse fixture
    make_hass,
    start,
    two_polls,
)

from custom_components.openwrt_router import traffic_engine
from custom_components.openwrt_router.config_flow import OpenWrtOptionsFlow
from custom_components.openwrt_router.const import (
    OPTION_TRAFFIC_ENABLED,
    OPTION_TRAFFIC_HISTORY_PROFILE,
    TRAFFIC_COARSE_STORE_KEY,
    TRAFFIC_SWITCH_OPTIONS,
)

TRAFFIC_KEYS = (*TRAFFIC_SWITCH_OPTIONS, OPTION_TRAFFIC_HISTORY_PROFILE)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _form(options: dict[str, Any], hass: Any = None) -> dict[str, Any]:
    flow = OpenWrtOptionsFlow()
    flow.hass = hass or MagicMock()
    entry = MagicMock()
    entry.options = options
    entry.entry_id = "e1"
    with patch.object(
        OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
    ) as mock_entry:
        mock_entry.return_value = entry
        result = await flow.async_step_init(user_input=None)
    return {str(k): k for k in result["data_schema"].schema}


async def _save(options: dict[str, Any], user_input: dict[str, Any], hass: Any) -> Any:
    flow = OpenWrtOptionsFlow()
    flow.hass = hass
    flow.context = {}
    entry = MagicMock()
    entry.options = options
    entry.entry_id = "e1"
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


def _default(marker: Any) -> Any:
    return marker.default() if callable(marker.default) else marker.default


async def test_form_offers_the_switch_off_and_compact_by_default() -> None:
    keys = await _form({})
    for key in TRAFFIC_SWITCH_OPTIONS:
        assert _default(keys[key]) is False, key
    assert _default(keys[OPTION_TRAFFIC_HISTORY_PROFILE]) == "compact"


@pytest.mark.parametrize(
    "stored", [{"traffic_enabled": "yes"}, {"traffic_enabled": 1}, {}]
)
async def test_odd_stored_switch_shows_off(stored: dict[str, Any]) -> None:
    keys = await _form(stored)
    assert _default(keys[OPTION_TRAFFIC_ENABLED]) is False


@pytest.mark.parametrize("stored", ["huge", 3, None])
async def test_odd_stored_profile_falls_back_to_compact(stored: Any) -> None:
    keys = await _form({OPTION_TRAFFIC_HISTORY_PROFILE: stored})
    assert _default(keys[OPTION_TRAFFIC_HISTORY_PROFILE]) == "compact"


async def test_form_keeps_a_chosen_standard_profile_and_switch() -> None:
    keys = await _form(
        {OPTION_TRAFFIC_ENABLED: True, OPTION_TRAFFIC_HISTORY_PROFILE: "standard"}
    )
    assert _default(keys[OPTION_TRAFFIC_ENABLED]) is True
    assert _default(keys[OPTION_TRAFFIC_HISTORY_PROFILE]) == "standard"


async def test_profile_selector_refuses_unknown_values() -> None:
    from homeassistant.helpers.selector import SelectSelector

    fields = {str(k): v for k, v in (await _schema({})).items()}
    selector = fields[OPTION_TRAFFIC_HISTORY_PROFILE]
    assert isinstance(selector, SelectSelector)
    assert selector("standard") == "standard"
    with pytest.raises(vol.Invalid):
        selector("huge")


async def _schema(options: dict[str, Any]) -> dict[Any, Any]:
    flow = OpenWrtOptionsFlow()
    flow.hass = MagicMock()
    entry = MagicMock()
    entry.options = options
    with patch.object(
        OpenWrtOptionsFlow, "config_entry", new_callable=PropertyMock
    ) as mock_entry:
        mock_entry.return_value = entry
        result = await flow.async_step_init(user_input=None)
    return dict(result["data_schema"].schema)


async def test_saving_merges_and_applies_directly() -> None:
    hass = make_hass()
    stored = {"extended_wifi_sensors": False, "wifi_rf_enabled": True, "_internal": 7}
    with patch.object(
        traffic_engine, "async_apply_traffic_options", AsyncMock()
    ) as apply:
        result = await _save(
            stored,
            {OPTION_TRAFFIC_ENABLED: True, OPTION_TRAFFIC_HISTORY_PROFILE: "standard"},
            hass,
        )
    assert result["type"] == "create_entry"
    data = result["data"]
    assert data["wifi_rf_enabled"] is True and data["_internal"] == 7  # kept
    assert data[OPTION_TRAFFIC_ENABLED] is True
    assert data[OPTION_TRAFFIC_HISTORY_PROFILE] == "standard"
    apply.assert_awaited_once()
    assert apply.await_args.args[1] == "e1"
    assert apply.await_args.args[2] == data


async def test_saving_without_traffic_keys_does_not_touch_the_engine() -> None:
    hass = make_hass()
    with patch.object(
        traffic_engine, "async_apply_traffic_options", AsyncMock()
    ) as apply:
        await _save({}, {"extended_wifi_sensors": False}, hass)
    apply.assert_not_awaited()


async def test_apply_never_raises_without_an_engine() -> None:
    hass = make_hass()
    await traffic_engine.async_apply_traffic_options(
        hass, "e1", {OPTION_TRAFFIC_ENABLED: True}
    )
    assert traffic_engine.async_get_traffic_engine(hass) is None


async def test_switch_on_through_the_form_starts_measuring(disks) -> None:
    hass = make_hass()
    engine, coord = await start(hass)
    assert not engine.active and TRAFFIC_COARSE_STORE_KEY not in disks.options
    await _save({}, {OPTION_TRAFFIC_ENABLED: True}, hass)
    assert engine.active and coord.listener_count == 1
    await two_polls(engine, coord, hass)
    await drain(hass)
    assert engine.latest
    await _save({OPTION_TRAFFIC_ENABLED: True}, {OPTION_TRAFFIC_ENABLED: False}, hass)
    assert not engine.active and coord.listener_count == 0
