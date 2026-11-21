"""WiFi RF entities, review finding R2 of 1.49.3.

The start must not drop the registry entries of a router with RF on that
is set up after a router with RF off. Mocks only.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from core_testkit import make_hass
from homeassistant.helpers import entity_registry as er
from rf_center_kit import options
from test_net_entities import loaded_registry

from custom_components.openwrt_router import wifi_rf_entities as we
from custom_components.openwrt_router.const import DOMAIN


def _entry(entry_id: str, opts: dict[str, Any]) -> Any:
    return SimpleNamespace(
        entry_id=entry_id,
        domain=DOMAIN,
        options=opts,
        disabled_by=None,
        pref_disable_new_entities=False,
    )


async def _registry_with_rf(hass: Any, entries: dict[str, Any]) -> Any:
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    for uid in we.RF_FLEET_UNIQUE_IDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=entries["gw"])
    for eid, item in entries.items():
        for uid in (
            we.ap_health_unique_id(eid),
            we.radio_unique_id(eid, "radio1", "noise"),
        ):
            registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=item)
    return registry


async def test_r2_start_with_an_rf_off_router_first_keeps_the_rf_on_router():
    entries = {
        "ap2": _entry("ap2", options(enabled=False)),
        "gw": _entry("gw", options("get_status")),
    }
    hass = make_hass(list(entries.values()))
    registry = await _registry_with_rf(hass, entries)
    # Only ap2 (RF off) is set up so far: the center does not know gw yet.
    center = SimpleNamespace(loaded=True, enabled=False, routers={})
    with patch.object(we, "_center", lambda _h: center):
        await we.async_sync_rf_entities(hass)
    left = {e.unique_id for e in registry.entities.values()}
    assert we.ap_health_unique_id("gw") in left
    assert we.radio_unique_id("gw", "radio1", "noise") in left
    assert set(we.RF_FLEET_UNIQUE_IDS) <= left
    # ap2's own switch is off: its entities go.
    assert we.ap_health_unique_id("ap2") not in left
    assert we.radio_unique_id("ap2", "radio1", "noise") not in left


async def test_r2_every_entry_off_still_removes_the_whole_set():
    entries = {
        "ap2": _entry("ap2", options(enabled=False)),
        "gw": _entry("gw", options(enabled=False)),
    }
    hass = make_hass(list(entries.values()))
    registry = await _registry_with_rf(hass, entries)
    center = SimpleNamespace(loaded=True, enabled=False, routers={})
    with patch.object(we, "_center", lambda _h: center):
        await we.async_sync_rf_entities(hass)
    assert registry.entities == {} or not any(
        we.WIFI_RF_UID_INFIX in (e.unique_id or "")
        or e.unique_id in we.RF_FLEET_UNIQUE_IDS
        for e in registry.entities.values()
    )


async def test_r2_unknown_entries_remove_nothing():
    entries = {"gw": _entry("gw", options("get_status"))}
    hass = make_hass(list(entries.values()))
    registry = await _registry_with_rf(hass, entries)

    def boom(_domain: Any = None) -> Any:
        raise RuntimeError

    hass.config_entries.async_entries = boom
    center = SimpleNamespace(loaded=True, enabled=False, routers={})
    with patch.object(we, "_center", lambda _h: center):
        await we.async_sync_rf_entities(hass)
    assert len(registry.entities) == len(we.RF_FLEET_UNIQUE_IDS) + 2
