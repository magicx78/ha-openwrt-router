"""Entities of WiFi RF Intelligence (release 1.48.0, part 2).

The bounded set (three fleet sensors; per router with RF on and an existing
device AP RF health plus three sensors per radio, capped), hosted on the
loaded sensor platforms of the entries (fake platforms here), fed by the RF
center only. Registry clean-up on "off" runs on a real entity registry.
Mocks only: no router, no Home Assistant instance, no network.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from core_testkit import fake_device_registry, make_hass
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from rf_center_kit import (
    MAC_A,
    RID1,
    RID2,
    FakeCoordinator,
    ap,
    client,
    entry,
    load,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
)
from test_diag_entities import Host
from test_net_entities import COMPONENT, loaded_registry

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import wifi_rf_entities as we
from custom_components.openwrt_router.const import (
    DATA_WIFI_RF_CENTER,
    DATA_WIFI_RF_ENTITIES,
    DOMAIN,
    WIFI_RF_RADIO_ENTITIES_MAX,
)
from custom_components.openwrt_router.rf_conflicts import RadioRef

STATUS_A = load("hostapd_get_status_mt76_a.json")
RADIO_NAMES = {"phy1-ap0": "radio1", "phy0-ap0": "radio0"}
APS = [
    ap("phy1-ap0"),
    ap("phy0-ap0", phy="phy0", channel=6, frequency=2437, htmode="HE20", center=6),
]


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


@pytest.fixture
def host() -> Any:
    hass = make_hass()
    found = Host(hass)
    with patch.object(we, "platforms_of", found):
        yield found


def _status() -> Any:
    counters = {"time": 200_000_000, "time_busy": 60_000_000}

    def answer() -> dict[str, Any]:
        counters["time"] += 300_000
        counters["time_busy"] += 120_000  # 40 % busy
        return {**STATUS_A, "airtime": {**STATUS_A["airtime"], **counters}}

    return answer


async def _setup(
    host: Host,
    opts: dict[str, dict[str, Any]],
    *,
    devices: tuple[str, ...] = ("gw",),
    key: Any = "default",
) -> Any:
    hass = host.hass
    for entry_id in opts:
        host.load(entry_id)
    for entry_id in devices:
        hass.devices[entry_id] = f"dev-{entry_id}"
    coords = {e: FakeCoordinator(api=e) for e in opts}
    kw = {} if key == "default" else {"key": key}
    center, clock, reader = await new_center(
        hass,
        *((entry(e, o), coords[e]) for e, o in opts.items()),
        rids={"gw": RID1, "ap2": RID2},
        **kw,
    )

    async def read(api: Any, kind: str, device: str) -> dict[str, Any]:
        return await reader(api, kind, f"{api}:{device}")

    center.read = read
    for entry_id in opts:
        for dev in RADIO_NAMES:
            reader.answers[("get_status", f"{entry_id}:{dev}")] = _status()
    hass.data[DATA_WIFI_RF_CENTER] = center
    for i in range(2):
        data = poll_data(
            uptime=1000 + 300 * i,
            aps=APS,
            clients=[client(MAC_A)],
            radio_names=RADIO_NAMES,
        )
        for coord in coords.values():
            await poll(center, coord, data)
        clock.advance(300)
    await we.async_sync_rf_entities(hass)
    return SimpleNamespace(center=center, clock=clock, coords=coords, reader=reader)


def _fleet(host: Host) -> dict[str, Any]:
    return {u: e for u, e in host.by_uid().items() if u in we.RF_FLEET_UNIQUE_IDS}


def _router(host: Host, entry_id: str) -> dict[str, Any]:
    prefix = f"{entry_id}_wifi_rf_"
    return {u: e for u, e in host.by_uid().items() if u.startswith(prefix)}


async def _settle(hass: Any) -> None:
    for task in list(hass.tasks):
        await task


# --- case 29 -------------------------------------------------------------------------


async def test_case_29_home_assistant_entities_rf_off_creates_nothing(
    host, disk
) -> None:
    rf = await _setup(host, {"gw": {}, "ap2": {}}, devices=("gw", "ap2"))
    assert rf.center.enabled is False
    assert host.entities() == []
    await we.async_sync_rf_entities(host.hass)
    assert host.entities() == []


async def test_case_29_home_assistant_entities_bounded_set_on_existing_devices(
    host, disk
) -> None:
    # ap2 has RF on but no device: no entity, no new device
    rf = await _setup(host, {"gw": options("get_status"), "ap2": options("get_status")})
    assert rf.center.status == "ready"
    assert set(_fleet(host)) == set(we.RF_FLEET_UNIQUE_IDS)
    gw = _router(host, "gw")
    assert set(gw) == {
        "gw_wifi_rf_ap_health",
        *(
            f"gw_wifi_rf_{radio}_{metric}"
            for radio in ("radio0", "radio1")
            for metric in ("utilization", "noise", "retry_rate")
        ),
    }
    assert _router(host, "ap2") == {}
    assert len(host.entities()) == 3 + 1 + 2 * 3
    assert host.hass.devices == {"gw": "dev-gw"}
    # the fleet set lives on the smallest entry (no device), the rest on gw's
    assert {type(e) for e in host.platforms[("sensor", "ap2")].added} == {
        we.RfFleetSensor
    }
    for entity in _fleet(host).values():
        assert entity.device_info is None
    for entity in gw.values():
        assert entity.device_info == DeviceInfo(identifiers={(DOMAIN, "gw")})
    # a second sync adds nothing twice; the update listener neither
    await we.async_sync_rf_entities(host.hass)
    we._on_update(host.hass)
    await _settle(host.hass)
    assert len(host.entities()) == 10
    # ap2's device appears: the next evaluation adds its set, once
    host.hass.devices["ap2"] = "dev-ap2"
    we._on_update(host.hass)
    we._on_update(host.hass)  # still syncing: no second task
    await _settle(host.hass)
    assert len(_router(host, "ap2")) == 7
    assert len(host.entities()) == 3 + 2 * 7


async def test_case_29_home_assistant_entities_values_units_and_unknown(
    host, disk
) -> None:
    await _setup(host, {"gw": options("get_status")})
    gw = _router(host, "gw")
    util = gw["gw_wifi_rf_radio1_utilization"]
    assert util.available and util.native_value == pytest.approx(40.0)
    assert util.native_unit_of_measurement == "%"
    assert util.extra_state_attributes == {
        "band": "5g",
        "state": "measured",
        "source": "hostapd.get_status",
        "measured_at": util.extra_state_attributes["measured_at"],
    }
    noise = gw["gw_wifi_rf_radio1_noise"]
    assert noise.native_value == -92 and noise.native_unit_of_measurement == "dBm"
    retry = gw["gw_wifi_rf_radio1_retry_rate"]
    # assoclist is off: not assessed, state unknown, never 0
    assert retry.available and retry.native_value is None
    assert retry.extra_state_attributes["state"] == "not_assessed"
    health = gw["gw_wifi_rf_ap_health"]
    assert health.native_value is None or 0 < health.native_value <= 100
    if health.native_value is None:
        assert health.extra_state_attributes["grade"] == "unknown"
    fleet = _fleet(host)
    roaming = fleet[we.UID_FLEET_WIFI_RF_ROAMING]
    # no client history running: unknown, never 0
    assert roaming.native_value is None
    assert roaming.extra_state_attributes["withheld"] == ["no_client_history"]
    recs = fleet[we.UID_FLEET_WIFI_RF_RECOMMENDATIONS]
    assert isinstance(recs.native_value, int)
    for entity in host.entities():
        text = repr(entity.extra_state_attributes)
        for secret in (RID1, RID2, MAC_A, "02:00:00", "example-ssid"):
            assert secret not in text, (entity.unique_id, secret)
        assert set(entity.extra_state_attributes or {}) <= (
            entity._unrecorded_attributes
        ), entity.unique_id


async def test_case_29_home_assistant_entities_not_ready_is_unknown(host, disk) -> None:
    rf = await _setup(host, {"gw": options("get_status")}, key=None)
    assert rf.center.status == "not_ready"
    fleet = _fleet(host)
    for uid in we.RF_FLEET_UNIQUE_IDS:
        assert fleet[uid].available and fleet[uid].native_value is None
    health = fleet[we.UID_FLEET_WIFI_RF_HEALTH]
    assert health.extra_state_attributes["withheld"] == ["module_key_missing"]
    assert _router(host, "gw")["gw_wifi_rf_ap_health"].native_value is None


def test_case_29_home_assistant_entities_radio_cap() -> None:
    results = {
        RadioRef(RID1, f"radio{i}"): SimpleNamespace(ref=RadioRef(RID1, f"radio{i}"))
        for i in range(7, -1, -1)
    }
    center = SimpleNamespace(results=results)
    radios = we.entity_radios(center, RID1)
    assert len(radios) == WIFI_RF_RADIO_ENTITIES_MAX == 4
    assert radios == ["radio0", "radio1", "radio2", "radio3"]  # stable order
    per_router = 1 + len(we.RADIO_SENSORS) * WIFI_RF_RADIO_ENTITIES_MAX
    assert per_router == 13  # never per client or per foreign network


# --- off: clean removal ---------------------------------------------------------------


def _entry(entry_id: str) -> Any:
    return SimpleNamespace(
        entry_id=entry_id,
        domain=DOMAIN,
        disabled_by=None,
        pref_disable_new_entities=False,
    )


async def test_case_29_home_assistant_entities_off_removes_them(host, disk) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    entries = {"gw": _entry("gw"), "ap2": _entry("ap2")}
    hass.config_entries.async_get_entry = lambda eid: entries.get(eid)
    for uid in we.RF_FLEET_UNIQUE_IDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=entries["gw"])
    for eid in ("gw", "ap2"):
        for uid in (
            we.ap_health_unique_id(eid),
            we.radio_unique_id(eid, "radio1", "noise"),
        ):
            registry.async_get_or_create(
                "sensor", DOMAIN, uid, config_entry=entries[eid]
            )
    keep = [
        registry.async_get_or_create(
            "sensor", DOMAIN, "gw_uptime", config_entry=entries["gw"]
        ).entity_id,
        registry.async_get_or_create(
            "sensor", "other", "gw_wifi_rf_ap_health"
        ).entity_id,
    ]
    rf = await _setup(
        host,
        {"gw": options("get_status"), "ap2": options("get_status")},
        devices=("gw", "ap2"),
    )
    assert len(host.entities()) == 3 + 2 * 7
    # RF off on ap2 only: its entities go, gw's and the fleet set stay
    rf.center._entries["ap2"][0].options = options(enabled=False)
    await poll(rf.center, rf.coords["ap2"], poll_data(uptime=2000, aps=APS))
    await we.async_sync_rf_entities(hass)
    left = {e.unique_id for e in registry.entities.values()}
    assert we.ap_health_unique_id("ap2") not in left
    assert we.ap_health_unique_id("gw") in left
    assert set(we.RF_FLEET_UNIQUE_IDS) <= left
    # RF off everywhere: the whole set goes, the rest of the registry stays
    rf.center._entries["gw"][0].options = options(enabled=False)
    await poll(rf.center, rf.coords["gw"], poll_data(uptime=2000, aps=APS))
    await we.async_sync_rf_entities(hass)
    assert sorted(e.entity_id for e in registry.entities.values()) == sorted(keep)
    hosts = hass.data[DATA_WIFI_RF_ENTITIES]
    assert hosts.anchor is None and hosts.created == {}
    for entity in host.entities():
        assert not entity.available


async def test_case_29_home_assistant_entities_restart_before_load_removes_nothing(
    host, disk
) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    item = _entry("gw")
    hass.config_entries.async_get_entry = lambda eid: item
    registry.async_get_or_create(
        "sensor", DOMAIN, we.RF_FLEET_UNIQUE_IDS[0], config_entry=item
    )
    center = SimpleNamespace(loaded=False, enabled=False)
    with patch.object(we, "_center", lambda _h: center):
        await we.async_sync_rf_entities(hass)
        assert len(registry.entities) == 1
        center.loaded = True
        center.routers = {}
        await we.async_sync_rf_entities(hass)
    assert len(registry.entities) == 0


async def test_case_29_home_assistant_entities_error_never_fails_setup() -> None:
    hass = make_hass()
    item = SimpleNamespace(
        entry_id="gw", runtime_data=SimpleNamespace(coordinator=None)
    )
    with (
        patch.object(
            integration, "_async_setup_entry_sec", AsyncMock(return_value=True)
        ),
        patch.object(
            integration._rf_center,
            "async_setup_rf_center",
            AsyncMock(side_effect=OSError),
        ),
        patch.object(we, "async_sync_rf_entities", AsyncMock(side_effect=RuntimeError)),
    ):
        assert await integration.async_setup_entry(hass, item) is True
    with (
        patch.object(
            integration, "_async_unload_entry_sec", AsyncMock(return_value=True)
        ),
        patch.object(
            integration._rf_center,
            "async_release_rf_center",
            AsyncMock(side_effect=OSError),
        ),
        patch.object(we, "async_entry_released", AsyncMock(side_effect=RuntimeError)),
    ):
        assert await integration.async_unload_entry(hass, item) is True


async def test_case_29_home_assistant_entities_entry_release_moves_the_anchor(
    host, disk
) -> None:
    await _setup(host, {"gw": options("get_status"), "ap2": options("get_status")})
    hosts = host.hass.data[DATA_WIFI_RF_ENTITIES]
    assert hosts.anchor == "ap2"
    host.unload("ap2")
    await we.async_entry_released(host.hass, "ap2", last=False)
    assert hosts.anchor == "gw"
    await we.async_entry_released(host.hass, "gw", last=True)
    assert DATA_WIFI_RF_ENTITIES not in host.hass.data


# --- translations -------------------------------------------------------------------


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_case_29_home_assistant_entities_translation_keys(name: str) -> None:
    data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
    sensors = data["entity"]["sensor"]
    for description in we.FLEET_SENSORS:
        assert sensors[description.translation_key]["name"], description.key
    assert sensors["wifi_rf_ap_health"]["name"]
    for description in we.RADIO_SENSORS:
        assert "{radio}" in sensors[description.translation_key]["name"]
