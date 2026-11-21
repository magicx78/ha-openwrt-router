"""1.49.4: safety net against changing unique_ids.

A changed unique_id makes Home Assistant create a new entity and orphan the
old one (history, names, areas and automations stay on the old one). If a
test here fails, do not just regenerate the list: make sure the change is
wanted and that existing installations keep their entities (migration or
repair).

Model (``full_router_kit``): a DSA gateway with static WAN and full poll
data over ubus (``network.interface dump``, ``network.device status``,
disks, conntrack, leases, ``uci get dhcp``), Wi-Fi answered like real rpcd
(``iwinfo info {}`` -> status 2, radios from UCI), one Wi-Fi client and
three procd services. The real ``OpenWrtAPI`` and ``OpenWrtCoordinator``
poll twice without SSH fallback (SSH raises), then every platform is set
up. ``{entry}`` stands for the config entry id.

Covered (130 unique_ids; the lists equal those of origin/main = 1.49.3,
except the traffic router sensors, which 1.49.3 did not create here):

* ``EXPECTED``, 109 entities, Enterprise modules off: sensor 92 (33 static
  incl. WAN, router status and channel plan; 16 interface byte/rate for
  ``br-lan``, ``lo``, ``wan``, ``wan6``; 8 port for ``lan1``, ``wan``; 32 AP
  detail for three APs and one STA; 1 DHCP pool; 2 topology), switch 7
  (4 Wi-Fi with UCI section keys, 3 services), device_tracker 1 (the Wi-Fi
  client), button 6, binary_sensor 3. Entities created disabled count too;
  with ``extended_wifi_sensors`` on the ids are the same and only the port
  and AP sensors switch to enabled.
* ``EXPECTED_IWINFO_PATH``, 12: the Wi-Fi ids on the iwinfo path (``iwinfo
  info {}`` answering, which real rpcd does not do): 4 switches keyed by
  ifname and 8 radio noise/signal sensors, the only path that creates those
  without WiFi RF.
* ``EXPECTED_TRAFFIC``, 9: Traffic on at the same gateway: 7 router sensors
  ``<entry>_traffic_*`` and the two fleet sensors.

Not covered: the Enterprise modules WiFi RF, Diagnose, Security Center and
Configuration Manager, network intelligence and client stability sensors
(none of them set up here); Traffic client sensors and Traffic on routers
without WAN; ``_ap_<ifname>_hwmode`` (the model sends no ``hwmode``); Wi-Fi
switches on the ``network.wireless`` and SSH paths; device trackers of other
clients (the model has one Wi-Fi client); VLAN sub-interfaces (skipped by
design); routers with other interface, port, pool or radio names than the
model's.
"""

from __future__ import annotations

import importlib
from typing import Any
from unittest.mock import MagicMock, patch

import full_router_kit as kit
import pytest
from core_testkit import FakeCoordinator, FakeDisks, drain
from test_diag_entities import Host
from test_traffic_engine import (
    _reset_pending,  # noqa: F401 - autouse fixture
    enabled,
    make_hass,
    start,
)
from test_wifi_switch_ids_v1492 import ENTRY, _registry

from custom_components.openwrt_router import PLATFORMS, OpenWrtRuntimeData
from custom_components.openwrt_router import traffic_entities as te
from custom_components.openwrt_router.const import CONF_EXTENDED_WIFI_SENSORS

# Recorded on this branch; origin/main (1.49.3, ea8781f) gives the same lists.
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
        "{entry}_iface_br-lan_rx",
        "{entry}_iface_br-lan_tx",
        "{entry}_br-lan_rx_rate",
        "{entry}_br-lan_tx_rate",
        "{entry}_iface_lo_rx",
        "{entry}_iface_lo_tx",
        "{entry}_lo_rx_rate",
        "{entry}_lo_tx_rate",
        "{entry}_iface_wan_rx",
        "{entry}_iface_wan_tx",
        "{entry}_wan_rx_rate",
        "{entry}_wan_tx_rate",
        "{entry}_iface_wan6_rx",
        "{entry}_iface_wan6_tx",
        "{entry}_wan6_rx_rate",
        "{entry}_wan6_tx_rate",
        "{entry}_port_lan1_status",
        "{entry}_port_lan1_speed_mbps",
        "{entry}_port_lan1_rx_bytes",
        "{entry}_port_lan1_tx_bytes",
        "{entry}_port_wan_status",
        "{entry}_port_wan_speed_mbps",
        "{entry}_port_wan_rx_bytes",
        "{entry}_port_wan_tx_bytes",
        "{entry}_ap_phy0-ap0_channel",
        "{entry}_ap_phy0-ap0_mode",
        "{entry}_ap_phy0-ap0_quality",
        "{entry}_ap_phy0-ap0_ap_clients",
        "{entry}_ap_phy0-ap0_frequency",
        "{entry}_ap_phy0-ap0_txpower",
        "{entry}_ap_phy0-ap0_bitrate",
        "{entry}_ap_phy0-ap0_htmode",
        "{entry}_ap_phy1-ap0_channel",
        "{entry}_ap_phy1-ap0_mode",
        "{entry}_ap_phy1-ap0_quality",
        "{entry}_ap_phy1-ap0_ap_clients",
        "{entry}_ap_phy1-ap0_frequency",
        "{entry}_ap_phy1-ap0_txpower",
        "{entry}_ap_phy1-ap0_bitrate",
        "{entry}_ap_phy1-ap0_htmode",
        "{entry}_ap_phy1-ap1_channel",
        "{entry}_ap_phy1-ap1_mode",
        "{entry}_ap_phy1-ap1_quality",
        "{entry}_ap_phy1-ap1_ap_clients",
        "{entry}_ap_phy1-ap1_frequency",
        "{entry}_ap_phy1-ap1_txpower",
        "{entry}_ap_phy1-ap1_bitrate",
        "{entry}_ap_phy1-ap1_htmode",
        "{entry}_ap_phy1-sta0_channel",
        "{entry}_ap_phy1-sta0_mode",
        "{entry}_ap_phy1-sta0_quality",
        "{entry}_ap_phy1-sta0_ap_clients",
        "{entry}_ap_phy1-sta0_frequency",
        "{entry}_ap_phy1-sta0_txpower",
        "{entry}_ap_phy1-sta0_bitrate",
        "{entry}_ap_phy1-sta0_htmode",
        "{entry}_dhcp_pool-lan",
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
# Wi-Fi ids on the iwinfo path (``iwinfo_flat``): kernel ifnames as keys, plus
# the radio noise/signal sensors. Same on origin/main.
EXPECTED_IWINFO_PATH: list[str] = [
    "{entry}_radio_phy0-ap0_noise",
    "{entry}_radio_phy0-ap0_signal",
    "{entry}_radio_phy1-ap0_noise",
    "{entry}_radio_phy1-ap0_signal",
    "{entry}_radio_phy1-ap1_noise",
    "{entry}_radio_phy1-ap1_signal",
    "{entry}_radio_phy1-sta0_noise",
    "{entry}_radio_phy1-sta0_signal",
    "{entry}_wifi_ssid_phy0-ap0",
    "{entry}_wifi_ssid_phy1-ap0",
    "{entry}_wifi_ssid_phy1-ap1",
    "{entry}_wifi_ssid_phy1-sta0",
]
# Traffic on, same gateway (entry id ``e1``): the router sensors exist from
# 1.49.4 on (WAN point from netifd's ``l3_device``); 1.49.3 created only the
# two fleet sensors here.
EXPECTED_TRAFFIC: list[str] = [
    "e1_traffic_uplink_load",
    "e1_traffic_uplink_rx_errors",
    "e1_traffic_uplink_tx_errors",
    "e1_traffic_wan_down",
    "e1_traffic_wan_peak",
    "e1_traffic_wan_total",
    "e1_traffic_wan_up",
    "openwrt_router_fleet_traffic_anomalies",
    "openwrt_router_fleet_traffic_coverage",
]


def _entry(api: Any, coordinator: Any, options: dict[str, Any]) -> MagicMock:
    entry = MagicMock()
    entry.entry_id = ENTRY
    entry.title = "GW"
    entry.options = options
    entry.data = {"host": "192.0.2.1", "port": 80}
    entry.runtime_data = OpenWrtRuntimeData(api=api, coordinator=coordinator)
    return entry


async def _entities(
    options: dict[str, Any] | None = None, *, iwinfo_flat: bool = False
) -> dict[str, list[Any]]:
    """All entities the platforms create after two polls, per platform."""
    hass, _, _ = await _registry()
    hass.async_create_task = MagicMock(side_effect=lambda coro, *a, **k: coro.close())
    api = kit.make_api(iwinfo_flat=iwinfo_flat)
    coordinator = kit.make_coordinator(hass, api)
    await kit.full_polls(coordinator)
    assert api._wifi_method == ("iwinfo" if iwinfo_flat else "uci")
    entry = _entry(api, coordinator, options or {})
    found: dict[str, list[Any]] = {}
    for platform in PLATFORMS:
        module = importlib.import_module(
            f"custom_components.openwrt_router.{platform.value}"
        )
        added: list[Any] = []
        await module.async_setup_entry(
            hass, entry, lambda entities, *a, _into=added, **k: _into.extend(entities)
        )
        found[platform.value] = added
    return found


def _uid(entity: Any) -> str:
    return str(entity.unique_id).replace(ENTRY, "{entry}")


async def _unique_ids(
    options: dict[str, Any] | None = None, *, iwinfo_flat: bool = False
) -> dict[str, list[str]]:
    found = await _entities(options, iwinfo_flat=iwinfo_flat)
    return {p: [_uid(e) for e in ents] for p, ents in found.items()}


def _disabled_by_default(found: dict[str, list[Any]]) -> set[str]:
    """Sensors created disabled (the option only touches sensors; the device
    tracker's default comes from Home Assistant's ScannerEntity and differs
    between HA versions)."""
    return {
        _uid(e) for e in found["sensor"] if e.entity_registry_enabled_default is False
    }


# --- Traffic off (default) -------------------------------------------------------


@pytest.mark.asyncio
async def test_unique_ids_of_all_entities_are_unchanged() -> None:
    found = await _unique_ids()
    assert found == EXPECTED


@pytest.mark.asyncio
async def test_extended_wifi_sensors_option_keeps_the_ids() -> None:
    """The option only enables port and AP sensors that already exist."""
    off = await _entities()
    on = await _entities({CONF_EXTENDED_WIFI_SENSORS: True})
    assert {p: [_uid(e) for e in ents] for p, ents in on.items()} == EXPECTED
    switched = _disabled_by_default(off) - _disabled_by_default(on)
    assert switched == {
        uid
        for uid in EXPECTED["sensor"]
        if uid.startswith(("{entry}_port_", "{entry}_ap_"))
    }
    # Interface byte and rate sensors stay disabled by default either way.
    assert _disabled_by_default(on) == {
        uid
        for uid in EXPECTED["sensor"]
        if uid.startswith("{entry}_iface_") or uid.endswith(("_rx_rate", "_tx_rate"))
    }


@pytest.mark.asyncio
async def test_iwinfo_path_wifi_unique_ids_are_unchanged() -> None:
    found = await _unique_ids(iwinfo_flat=True)
    wifi = [
        uid
        for uids in found.values()
        for uid in uids
        if uid.startswith(("{entry}_wifi_ssid_", "{entry}_radio_"))
    ]
    assert wifi == EXPECTED_IWINFO_PATH
    # Everything else is the same as on the UCI path.
    rest = {p: [uid for uid in uids if uid not in wifi] for p, uids in found.items()}
    assert rest == {
        p: [uid for uid in uids if not uid.startswith("{entry}_wifi_ssid_")]
        for p, uids in EXPECTED.items()
    }


@pytest.mark.asyncio
async def test_model_covers_every_platform_and_entity_family() -> None:
    hass, _, _ = await _registry()
    api = kit.make_api()
    coordinator = kit.make_coordinator(hass, api)
    first, second = await kit.full_polls(coordinator)
    # Full poll data, no SSH fallback (full_polls asserts that per poll).
    assert second.network_interfaces and second.port_stats and second.dhcp_pools
    assert first.dhcp_pools == []  # pools come with poll 2
    found = await _unique_ids()
    assert set(found) == {p.value for p in PLATFORMS}
    assert all(found.values()), found
    ids = [uid for uids in found.values() for uid in uids]
    assert len(ids) == len(set(ids))
    for family in ("_iface_", "_port_", "_ap_", "_dhcp_pool-", "_wifi_ssid_"):
        assert any(family in uid for uid in ids), family


# --- Traffic on --------------------------------------------------------------------


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


@pytest.fixture
def host() -> Any:
    found = Host(make_hass())
    with patch.object(te, "platforms_of", found):
        yield found


def _sample(data: Any, n: int) -> None:
    # the sample time the poll measured, made deterministic
    data.counters_sampled_mono = 100.0 + 10 * n
    data.uptime = 5_000 + 10 * n


@pytest.mark.asyncio
async def test_traffic_unique_ids_on_the_gateway(host, disks) -> None:
    hass_poll, _, _ = await _registry()
    coordinator = kit.make_coordinator(hass_poll, kit.make_api())
    first, second = await kit.full_polls(coordinator, on_poll=_sample)
    hass = host.hass
    host.load("e1")
    hass.devices["e1"] = "dev-e1"
    enabled(disks)
    engine, coord = await start(hass, coord=FakeCoordinator(first))
    await te.async_sync_traffic_entities(hass)
    coord.poll(data=first)
    await drain(hass)
    engine.clock.t += 10
    coord.poll(data=second)
    await drain(hass)
    assert sorted(host.by_uid()) == EXPECTED_TRAFFIC
