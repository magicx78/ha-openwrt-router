"""1.49.4: safety net against changing unique_ids.

Every entity of one router (all platforms, Enterprise modules off, WiFi RF
off) is set up against the rpcd-faithful router model of
``test_wifi_switch_ids_v1492`` (``iwinfo info {}`` answers status 2, no
``network.wireless``, UCI readable), extended here by one Wi-Fi client and
the procd service list so device trackers and service switches exist too.
The unique_ids must equal ``EXPECTED`` exactly (``{entry}`` stands for the
config entry id).

A changed unique_id makes Home Assistant create a new entity and orphan the
old one (history, names, areas and automations stay on the old one). If this
test fails, do not just regenerate the list: make sure the change is wanted
and that existing installations keep their entities (migration or repair).
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import test_wifi_switch_ids_v1492 as model
from test_wifi_switch_ids_v1492 import ENTRY, _api, _registry

from custom_components.openwrt_router import PLATFORMS, OpenWrtRuntimeData
from custom_components.openwrt_router.coordinator import OpenWrtCoordinator

_CLIENT_MAC = "02:00:00:00:0a:0a"
_SERVICE_LIST = {
    "cron": {},
    "dnsmasq": {"instances": {"cfg01411c": {"running": True, "pid": 3820}}},
    "dropbear": {"instances": {"instance1": {"running": True, "pid": 1}}},
    "firewall": {},
}
_RC_LIST = {
    "dnsmasq": {"start": 19, "enabled": True},
    "dropbear": {"start": 19, "stop": 50, "enabled": True},
    "firewall": {"start": 19, "enabled": True},
}

# Recorded with this model; the same list comes out of 1.49.3 (main ea8781f).
EXPECTED: dict[str, list[str]] = {
    "sensor": [
        "{entry}_uptime",
        "{entry}_wan_status",
        "{entry}_client_count",
        "{entry}_cpu_load",
        "{entry}_memory_usage",
        "{entry}_memory_total",
        "{entry}_memory_used",
        "{entry}_memory_free",
        "{entry}_wan_ip",
        "{entry}_wan_rx",
        "{entry}_wan_tx",
        "{entry}_firmware",
        "{entry}_update_status",
        "{entry}_platform_architecture",
        "{entry}_cpu_load_5min",
        "{entry}_cpu_load_15min",
        "{entry}_memory_cached",
        "{entry}_memory_shared",
        "{entry}_memory_buffered",
        "{entry}_disk_total",
        "{entry}_disk_used",
        "{entry}_disk_free",
        "{entry}_disk_usage",
        "{entry}_tmpfs_total",
        "{entry}_tmpfs_used",
        "{entry}_tmpfs_free",
        "{entry}_tmpfs_usage",
        "{entry}_active_connections",
        "{entry}_log_status",
        "{entry}_dfs_events_24h",
        "{entry}_unstable_clients",
        "{entry}_router_status",
        "{entry}_channel_plan",
        "{entry}_ap_phy0-ap0_channel",
        "{entry}_ap_phy0-ap0_mode",
        "{entry}_ap_phy0-ap0_ap_clients",
        "{entry}_ap_phy1-ap0_channel",
        "{entry}_ap_phy1-ap0_mode",
        "{entry}_ap_phy1-ap0_ap_clients",
        "{entry}_ap_phy1-ap1_channel",
        "{entry}_ap_phy1-ap1_mode",
        "{entry}_ap_phy1-ap1_ap_clients",
        "{entry}_ap_phy1-sta0_channel",
        "{entry}_ap_phy1-sta0_mode",
        "{entry}_ap_phy1-sta0_ap_clients",
        "{entry}_network_topology",
        "{entry}_topology_status",
    ],
    "switch": [
        "{entry}_wifi_ssid_lan_2g",
        "{entry}_wifi_ssid_lan_5g",
        "{entry}_wifi_ssid_iot_5g",
        "{entry}_wifi_ssid_uplink",
        "{entry}_service_dnsmasq",
        "{entry}_service_dropbear",
        "{entry}_service_firewall",
    ],
    "device_tracker": [
        "02:00:00:00:0A:0A",
    ],
    "button": [
        "{entry}_reload_wifi",
        "{entry}_check_updates",
        "{entry}_reboot",
        "{entry}_service_dnsmasq_restart",
        "{entry}_service_dropbear_restart",
        "{entry}_service_firewall_restart",
    ],
    "binary_sensor": [
        "{entry}_connectivity",
        "{entry}_wan_connectivity",
        "{entry}_sticky_clients",
    ],
}


def _answer(obj: str, method: str, args: dict) -> list[Any]:
    if (obj, method) == ("hostapd.phy1-ap0", "get_clients"):
        return [0, {"clients": {_CLIENT_MAC: {"signal": -55, "authorized": True}}}]
    if (obj, method) == ("service", "list"):
        return [0, _SERVICE_LIST]
    if (obj, method) == ("rc", "list"):
        return [0, _RC_LIST]
    return _ORIGINAL_ANSWER(obj, method, args)


_ORIGINAL_ANSWER = model._answer


async def _no_ssh(*_args: Any, **_kwargs: Any) -> None:
    raise OSError("no SSH on this router")


async def _unique_ids() -> dict[str, list[str]]:
    hass, _, _ = await _registry()
    hass.async_create_task = MagicMock(side_effect=lambda coro, *a, **k: coro.close())
    api = _api([])
    with patch("homeassistant.helpers.frame.report_usage"):
        coordinator = OpenWrtCoordinator(hass=hass, api=api, entry_title="AP3")
    with (
        patch.object(model, "_answer", _answer),
        patch("custom_components.openwrt_router.api.asyncssh.connect", _no_ssh),
    ):
        coordinator.data = await coordinator._async_update_data()
    entry = MagicMock()
    entry.entry_id = ENTRY
    entry.title = "AP3"
    entry.options = {}
    entry.data = {"host": "192.0.2.1"}
    entry.runtime_data = OpenWrtRuntimeData(api=api, coordinator=coordinator)
    found: dict[str, list[str]] = {}
    for platform in PLATFORMS:
        module = importlib.import_module(
            f"custom_components.openwrt_router.{platform.value}"
        )
        added: list[Any] = []
        await module.async_setup_entry(
            hass, entry, lambda entities, *a, _into=added, **k: _into.extend(entities)
        )
        found[platform.value] = [
            str(e.unique_id).replace(ENTRY, "{entry}") for e in added
        ]
    return found


@pytest.mark.asyncio
async def test_unique_ids_of_all_entities_are_unchanged() -> None:
    found = await _unique_ids()
    assert found == EXPECTED


@pytest.mark.asyncio
async def test_model_covers_every_platform() -> None:
    found = await _unique_ids()
    assert set(found) == {p.value for p in PLATFORMS}
    assert all(found.values()), found
    ids = [uid for uids in found.values() for uid in uids]
    assert len(ids) == len(set(ids))
