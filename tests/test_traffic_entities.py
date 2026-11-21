"""Entities of Traffic Analytics (plan §17, Bauplan §9, Phase K).

The bounded set (two fleet sensors; per router with ``traffic_enabled`` and
an existing device the WAN and uplink sensors; optional client sensors) on
the loaded sensor platforms of the entries (fake platforms here), created
through the real HA dispatcher path (``SIGNAL_TRAFFIC_ANALYTICS``) after a
poll. Registry clean-up on "off" runs on a real entity registry. Mocks
only: no router, no Home Assistant instance, no network.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from core_testkit import FakeDisks, FakeEntry, drain, fake_device_registry
from homeassistant.components.sensor import SensorDeviceClass, SensorStateClass
from homeassistant.const import EntityCategory
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from test_diag_entities import Host
from test_net_entities import COMPONENT, loaded_registry
from test_traffic_engine import (
    MAC1,
    RID,
    RID2,
    _reset_pending,  # noqa: F401 - autouse fixture
    enabled,
    make_hass,
    poll_data,
    start,
    two_polls,
)

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import traffic_entities as te
from custom_components.openwrt_router.__init__ import _LEGACY_DYNAMIC_PATTERNS
from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ENTITIES,
    DOMAIN,
    OPTION_TRAFFIC_ENABLED,
    TRAFFIC_COARSE_STORE_KEY,
)
from custom_components.openwrt_router.traffic_engine import (
    async_apply_traffic_options,
)

CLIENT = "cli_" + "a" * 16


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


@pytest.fixture
def host() -> Any:
    hass = make_hass()
    found = Host(hass)
    with patch.object(te, "platforms_of", found):
        yield found


def fleet(host: Host) -> dict[str, Any]:
    return {u: e for u, e in host.by_uid().items() if u in te.FLEET_UNIQUE_IDS}


def router(host: Host, entry_id: str) -> dict[str, Any]:
    prefix = f"{entry_id}_traffic_"
    return {
        u.removeprefix(prefix): e
        for u, e in host.by_uid().items()
        if u.startswith(prefix)
    }


def refresh(host: Host) -> None:
    for entity in host.entities():
        entity._refresh()


async def gateway(host: Host, *, on: bool = True, device: bool = True) -> Any:
    """One gateway entry e1 (sensor platform loaded) after two polls."""
    hass = host.hass
    host.load("e1")
    if device:
        hass.devices["e1"] = "dev-e1"
    if on:
        enabled(None)  # type: ignore[arg-type]
    engine, coord = await start(hass)
    await te.async_sync_traffic_entities(hass)  # what the setup wrapper does
    if on:
        await two_polls(engine, coord, hass)
        await drain(hass)  # the signal's sync task
    return engine, coord


# --- off ----------------------------------------------------------------------------


async def test_off_creates_nothing_and_reads_no_store(host, disks) -> None:
    _engine, coord = await gateway(host, on=False)
    coord.poll(data=poll_data(200.0))
    await drain(host.hass)
    assert host.entities() == []
    assert TRAFFIC_COARSE_STORE_KEY not in disks.options
    assert coord.listener_count == 0
    assert host.hass.data[DATA_TRAFFIC_ENTITIES].anchor is None


async def test_before_the_engine_is_loaded_nothing_happens(host) -> None:
    hass = host.hass
    host.load("e1")
    engine = SimpleNamespace(loaded=False, active=False)
    with patch.object(te, "_engine", lambda _h: engine):
        await te.async_sync_traffic_entities(hass)
    assert host.entities() == [] and DATA_TRAFFIC_ENTITIES not in hass.data


# --- the set --------------------------------------------------------------------------


async def test_gateway_gets_fleet_wan_and_uplink_sensors_via_the_signal(
    host, disks
) -> None:
    _engine, _coord = await gateway(host)
    # created by the dispatcher receiver after the polls, not by a direct sync
    assert set(fleet(host)) == set(te.FLEET_UNIQUE_IDS)
    mine = router(host, "e1")
    assert set(mine) == set(te.ROUTER_KEYS)
    assert len(host.entities()) == 2 + 7
    for entity in mine.values():
        assert entity.device_info["identifiers"] == {(DOMAIN, "e1")}
    for entity in fleet(host).values():
        assert getattr(entity, "device_info", None) is None
    # the fleet set lives on the anchor entry's sensor platform only
    assert all(e in host.platforms[("sensor", "e1")].added for e in host.entities())


async def test_no_device_no_router_entities(host, disks) -> None:
    await gateway(host, device=False)
    assert router(host, "e1") == {}
    assert set(fleet(host)) == set(te.FLEET_UNIQUE_IDS)


async def test_values_units_and_classes(host, disks) -> None:
    engine, _coord = await gateway(host)
    refresh(host)
    s = router(host, "e1")
    # two polls 10 s apart: WAN rx +1 250 000 B, tx +125 000 B
    assert s["wan_down"].native_value == 1_000_000
    assert s["wan_up"].native_value == 100_000
    assert s["wan_total"].native_value == 1_375_000
    assert s["uplink_load"].native_value == 0.1  # 1 Mbit/s of 1000 Mbit/s
    assert s["uplink_load"].extra_state_attributes["uplink"] == "wan"
    assert s["uplink_rx_errors"].native_value == 0
    for key in ("wan_down", "wan_up", "wan_peak"):
        d = s[key].entity_description
        assert d.device_class is SensorDeviceClass.DATA_RATE
        assert d.native_unit_of_measurement == "bit/s"
        assert d.suggested_unit_of_measurement == "Mbit/s"
        assert d.state_class is SensorStateClass.MEASUREMENT
    total = s["wan_total"].entity_description
    assert total.device_class is SensorDeviceClass.DATA_SIZE
    assert total.native_unit_of_measurement == "B"
    assert total.suggested_unit_of_measurement == "GiB"
    assert total.state_class is SensorStateClass.TOTAL_INCREASING
    assert s["uplink_load"].entity_description.native_unit_of_measurement == "%"
    for key in ("uplink_rx_errors", "uplink_tx_errors"):
        d = s[key].entity_description
        assert d.entity_category is EntityCategory.DIAGNOSTIC
        assert d.entity_registry_enabled_default is False
        assert d.state_class is SensorStateClass.TOTAL_INCREASING
    for key in ("wan_down", "wan_up", "wan_total", "wan_peak", "uplink_load"):
        assert s[key].entity_description.entity_registry_enabled_default is True
    cov = fleet(host)[te.FLEET_UNIQUE_IDS[1]]
    assert cov.entity_description.native_unit_of_measurement == "%"
    assert 0 <= cov.native_value <= 100
    assert cov.extra_state_attributes["points"] == len(engine.latest)


async def test_unknown_is_none_never_zero(host, disks) -> None:
    engine, _coord = await gateway(host)
    engine.latest.clear()
    engine.totals.clear()
    engine.anomalies.counters["evaluations"] = 0
    refresh(host)
    for entity in host.entities():
        assert entity.available is True
        assert entity.native_value is None, entity.unique_id
    # a peak needs a 5-minute bucket with at least half coverage
    assert (
        router(host, "e1")["wan_peak"].extra_state_attributes["upload_peak_bps"] is None
    )


async def test_unknown_link_speed_gives_no_utilization(host, disks) -> None:
    engine, _coord = await gateway(host)
    with patch.object(engine, "link_facts", dict):
        sensor = router(host, "e1")["uplink_load"]
        sensor._refresh()
        assert sensor.native_value is None
        assert sensor.extra_state_attributes["reason"] == "link_speed_unknown"


async def test_peak_uses_five_minute_buckets_only(host, disks) -> None:
    engine, _coord = await gateway(host)
    point = engine.wan_point(RID)
    bucket = SimpleNamespace(
        rx_bytes=37_500_000, tx_bytes=3_750_000, coverage_ratio=1.0, resolution_s=300
    )
    thin = SimpleNamespace(
        rx_bytes=999_000_000, tx_bytes=0, coverage_ratio=0.2, resolution_s=300
    )
    window = SimpleNamespace(buckets=(bucket, thin), depth_s=6 * 3600.0)
    calls: list[Any] = []

    def fake_window(pid: str, window_s: int, **kw: Any) -> Any:
        calls.append((pid, window_s, kw.get("resolution_s")))
        return window

    with patch.object(engine.series, "window", fake_window):
        sensor = router(host, "e1")["wan_peak"]
        sensor._refresh()
    assert calls == [(point.point_id, 86_400, 300)]
    assert sensor.native_value == 1_000_000  # 37.5 MB in 300 s
    attrs = sensor.extra_state_attributes
    assert attrs["upload_peak_bps"] == 100_000
    assert attrs["history_depth_s"] == 6 * 3600


async def test_router_without_wan_gets_no_wan_sensors(host, disks) -> None:
    engine, _coord = await gateway(host)
    with (
        patch.object(engine, "wan_point", lambda rid: None),
        patch.object(engine, "uplink_point", lambda rid: (None, "uplink_unknown")),
    ):
        assert te.router_keys(engine, RID) == []


# --- unique ids and privacy -----------------------------------------------------------


async def test_unique_ids_avoid_the_legacy_patterns_and_identities(host, disks) -> None:
    engine, _coord = await gateway(host)
    await engine.async_update_settings({"client_sensors": [CLIENT]})
    await drain(host.hass)
    uids = set(host.by_uid())
    uids |= {te.router_unique_id("01JABCDEF0123456789XYZ", k) for k in te.ROUTER_KEYS}
    uids |= {te.client_unique_id(CLIENT, d) for d in te.CLIENT_DIRECTIONS}
    assert len(uids) >= 2 + 7 + 2
    for uid in uids:
        for pattern in _LEGACY_DYNAMIC_PATTERNS:
            assert pattern not in uid, (uid, pattern)
    host.hass.devices["e1"] = "dev-e1"
    refresh(host)
    for entity in host.entities():
        blob = json.dumps(
            [entity.unique_id, entity.extra_state_attributes], default=str
        )
        for needle in (MAC1, MAC1.upper(), "wan", "lan1", "phy0-ap0"):
            if needle == "wan":
                # the uplink kind token "wan" is allowed; no device name
                blob = blob.replace('"uplink": "wan"', "")
            assert needle not in blob.replace("wan_", ""), (entity.unique_id, needle)


# --- client sensors -------------------------------------------------------------------


async def test_client_sensors_only_when_selected_and_removed_when_deselected(
    host, disks
) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    engine, _coord = await gateway(host)
    assert not [u for u in host.by_uid() if "traffic_client_" in u]
    await engine.async_update_settings({"client_sensors": [CLIENT]})
    await drain(hass)
    clients = {u: e for u, e in host.by_uid().items() if "traffic_client_" in u}
    assert set(clients) == {te.client_unique_id(CLIENT, d) for d in ("down", "up")}
    for entity in clients.values():
        assert getattr(entity, "device_info", None) is None
        assert entity.translation_placeholders == {"client": CLIENT}
        entity._refresh()
        assert entity.native_value is None  # never seen: unknown, not 0
        assert entity.extra_state_attributes["perspective"] == "wifi_at_ap"
    for uid in clients:
        registry.async_get_or_create("sensor", DOMAIN, uid)
    await engine.async_update_settings({"client_sensors": []})
    await drain(hass)
    left = {e.unique_id for e in registry.entities.values()}
    assert not left & set(clients)
    assert hass.data[DATA_TRAFFIC_ENTITIES].clients == set()


# --- switching off --------------------------------------------------------------------


async def test_off_removes_exactly_the_traffic_entities_and_keeps_the_history(
    host, disks
) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    item = FakeEntry("e1")
    hass.entries = [item]
    engine, coord = await gateway(host)
    for uid in host.by_uid():
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=item)
    client_uid = te.client_unique_id(CLIENT, "down")
    registry.async_get_or_create("sensor", DOMAIN, client_uid)
    keep = [
        registry.async_get_or_create(
            "sensor", DOMAIN, "e1_wan_rx", config_entry=item
        ).entity_id,
        # an interface called "traffic": its rate sensor shares the infix
        registry.async_get_or_create(
            "sensor", DOMAIN, "e1_traffic_rx_rate", config_entry=item
        ).entity_id,
        registry.async_get_or_create(
            "sensor", "other", "e1_traffic_wan_down"
        ).entity_id,
    ]
    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: False})
    await drain(hass)  # the signal's sync task
    assert sorted(e.entity_id for e in registry.entities.values()) == sorted(keep)
    hosts = hass.data[DATA_TRAFFIC_ENTITIES]
    assert hosts.anchor is None and hosts.created == {} and hosts.clients == set()
    for entity in host.entities():
        entity._refresh()
        assert entity.available is False
    # the history is written, not deleted
    assert disks[TRAFFIC_COARSE_STORE_KEY].saves
    # on again: created again after the next polls (no reload)
    host.platforms[("sensor", "e1")].added.clear()
    await async_apply_traffic_options(hass, "e1", {OPTION_TRAFFIC_ENABLED: True})
    await two_polls(engine, coord, hass)
    await drain(hass)
    assert set(router(host, "e1")) == set(te.ROUTER_KEYS)


async def test_one_router_off_keeps_the_other_and_the_fleet(host, disks) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    for eid in ("e1", "e2"):
        host.load(eid)
        hass.devices[eid] = f"dev-{eid}"
    enabled(None)  # type: ignore[arg-type]
    engine, c1 = await start(hass, rids={"e1": RID, "e2": RID2})
    from test_traffic_engine import FakeCoordinator

    _, c2 = await start(hass, entry_id="e2", coord=FakeCoordinator(poll_data(1.0)))
    await te.async_sync_traffic_entities(hass)
    await two_polls(engine, c1, hass)
    await two_polls(engine, c2, hass)
    await drain(hass)
    for uid in host.by_uid():
        registry.async_get_or_create("sensor", DOMAIN, uid)
    assert router(host, "e1") and router(host, "e2")
    await async_apply_traffic_options(hass, "e2", {OPTION_TRAFFIC_ENABLED: False})
    await drain(hass)
    left = {e.unique_id for e in registry.entities.values()}
    assert not any(u.startswith("e2_traffic_") for u in left)
    assert {te.router_unique_id("e1", k) for k in te.ROUTER_KEYS} <= left
    assert set(te.FLEET_UNIQUE_IDS) <= left


async def test_setup_with_traffic_off_cleans_that_entry_only(host, disks) -> None:
    """A restart after switching off: the entry's stale entries go; an entry
    not loaded yet keeps its entries; the fleet set goes only when every
    entry of the domain has traffic off."""
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    for uid in (
        te.router_unique_id("e1", "wan_down"),
        te.router_unique_id("e2", "wan_down"),
        *te.FLEET_UNIQUE_IDS,
    ):
        registry.async_get_or_create("sensor", DOMAIN, uid)
    hass.entries = [
        FakeEntry("e1", options={}),
        FakeEntry("e2", options={OPTION_TRAFFIC_ENABLED: True}),
    ]
    await gateway(host, on=False)
    left = {e.unique_id for e in registry.entities.values()}
    assert te.router_unique_id("e1", "wan_down") not in left
    assert te.router_unique_id("e2", "wan_down") in left  # e2 not loaded yet
    assert set(te.FLEET_UNIQUE_IDS) <= left
    hass.entries = [FakeEntry("e1", options={})]
    await te.async_sync_traffic_entities(hass)
    left = {e.unique_id for e in registry.entities.values()}
    assert not set(te.FLEET_UNIQUE_IDS) & left


# --- hosting --------------------------------------------------------------------------


async def test_receiver_is_a_callback_and_a_failed_start_is_released(
    host, disks
) -> None:
    from homeassistant.core import is_callback
    from homeassistant.helpers.dispatcher import DATA_DISPATCHER

    from custom_components.openwrt_router.const import SIGNAL_TRAFFIC_ANALYTICS

    _engine, _coord = await gateway(host)
    targets = list(host.hass.data[DATA_DISPATCHER][SIGNAL_TRAFFIC_ANALYTICS])
    assert len(targets) == 1 and is_callback(targets[0])
    hosts = host.hass.data[DATA_TRAFFIC_ENTITIES]
    host.platforms[("sensor", "e1")].added.clear()
    hosts.anchor = None
    host.hass.async_create_task.side_effect = RuntimeError("stopping")
    with pytest.raises(RuntimeError):
        te._on_update(host.hass)
    assert hosts.syncing is False


async def test_entry_release_moves_the_anchor(host, disks) -> None:
    hass = host.hass
    for eid in ("e1", "e2"):
        host.load(eid)
    enabled(None)  # type: ignore[arg-type]
    _engine, _c1 = await start(hass, rids={"e1": RID, "e2": RID2})
    from test_traffic_engine import FakeCoordinator

    await start(hass, entry_id="e2", coord=FakeCoordinator(poll_data(1.0)))
    await te.async_sync_traffic_entities(hass)
    hosts = hass.data[DATA_TRAFFIC_ENTITIES]
    assert hosts.anchor == "e1"
    host.unload("e1")
    await te.async_entry_released(hass, "e1", last=False)
    assert hosts.anchor == "e2"
    await te.async_entry_released(hass, "e2", last=True)
    assert DATA_TRAFFIC_ENTITIES not in hass.data


async def test_entity_errors_never_fail_setup_or_unload() -> None:
    hass = make_hass()
    item = SimpleNamespace(
        entry_id="gw", runtime_data=SimpleNamespace(coordinator=object())
    )
    with (
        patch.object(
            integration, "_async_setup_entry_rf", AsyncMock(return_value=True)
        ),
        patch.object(integration._traffic_engine, "async_setup_traffic", AsyncMock()),
        patch.object(te, "async_sync_traffic_entities", AsyncMock(side_effect=OSError)),
    ):
        assert await integration.async_setup_entry(hass, item) is True
    with (
        patch.object(
            integration, "_async_unload_entry_rf", AsyncMock(return_value=True)
        ),
        patch.object(te, "async_entry_released", AsyncMock(side_effect=OSError)),
    ):
        assert await integration.async_unload_entry(hass, item) is True


# --- translations ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_translation_keys(name: str) -> None:
    data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
    sensors = data["entity"]["sensor"]
    for d in (*te.FLEET_SENSORS, *te.ROUTER_SENSORS.values()):
        assert sensors[d.translation_key]["name"], d.key
    for direction in te.CLIENT_DIRECTIONS:
        name_ = sensors[f"traffic_client_{direction}"]["name"]
        assert "{client}" in name_ and "internet" not in name_.lower()
    init = data["options"]["step"]["init"]
    for key in (
        "traffic_enabled",
        "traffic_station_detail",
        "traffic_sysfs_fallback",
        "traffic_offload_probe",
        "traffic_history_profile",
    ):
        assert init["data"][key] and init["data_description"][key], key
    assert set(data["selector"]["traffic_history_profile"]["options"]) == {
        "compact",
        "standard",
    }
