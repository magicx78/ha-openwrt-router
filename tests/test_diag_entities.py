"""Entities of the network diagnostics (release 1.47.0, part 2).

The bounded set (six fleet sensors plus one gateway sensor per router with
an existing device), hosted on the loaded entity platforms of the entries
(fake platforms here), fed by the module's view only. Registry clean-up on
"off" runs on a real entity registry (``loaded_registry``). No network, no
Home Assistant instance, no router.
"""

from __future__ import annotations

import inspect
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import fake_device_registry, make_hass
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from test_diag_chain import ICMP, OK, TCP, TIMEOUT, ext, facts, probe
from test_diag_runtime import (
    RID1,
    RIDS,
    T0,
    disk,  # noqa: F401 - fixture
    make_diag,
    poll,
    wan_status,
)
from test_net_entities import COMPONENT, loaded_registry

from custom_components.openwrt_router import diag_entities as de
from custom_components.openwrt_router.const import (
    DATA_DIAG_ENTITIES,
    DATA_NET_DIAGNOSTICS,
    DIAG_GATEWAY_UID_SUFFIX,
    DOMAIN,
    SIGNAL_NET_DIAGNOSTICS,
)
from custom_components.openwrt_router.diag_chain import classify, evaluate_chain
from custom_components.openwrt_router.diag_core import point_for
from custom_components.openwrt_router.diag_model import Stage
from custom_components.openwrt_router.diag_runtime import (
    async_release_net_diagnostics,
    merge_settings,
)

RID3 = "rtr_" + "3" * 32
ALL_RIDS = {**RIDS, "r3": RID3}


class Platform:
    """A loaded entity platform of one entry (what ``async_get_platforms``
    gives): records what is added and binds it to hass like HA does."""

    def __init__(self, hass: Any, domain: str, entry_id: str) -> None:
        self.hass = hass
        self.domain = domain
        self.config_entry = SimpleNamespace(entry_id=entry_id)
        self.added: list[Any] = []

    async def async_add_entities(self, entities: list[Any]) -> None:
        for entity in entities:
            entity.hass = self.hass
            self.added.append(entity)


class Host:
    def __init__(self, hass: Any, *entries: str) -> None:
        self.hass = hass
        self.platforms: dict[tuple[str, str], Platform] = {}
        for entry in entries:
            self.load(entry)

    def load(self, entry: str) -> None:
        for domain in ("sensor", "binary_sensor"):
            self.platforms[(domain, entry)] = Platform(self.hass, domain, entry)

    def unload(self, entry: str) -> None:
        for domain in ("sensor", "binary_sensor"):
            self.platforms.pop((domain, entry), None)

    def __call__(self, hass: Any) -> list[Platform]:
        return list(self.platforms.values())

    def entities(self) -> list[Any]:
        return [e for p in self.platforms.values() for e in p.added]

    def by_uid(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for entity in self.entities():
            assert entity.unique_id not in out, entity.unique_id  # no duplicate
            out[entity.unique_id] = entity
        return out


@pytest.fixture
def host() -> Any:
    hass = make_hass()
    found = Host(hass)
    with patch.object(de, "platforms_of", found):
        yield found


async def module(
    host: Host, *entries: str, enabled: bool = True, devices: tuple[str, ...] = ()
) -> Any:
    hass = host.hass
    for entry in entries:
        host.load(entry)
    for entry in devices:
        hass.devices[entry] = f"dev-{entry}"
    diag = await make_diag(hass, *entries, enabled=enabled)
    diag.router_id_of = ALL_RIDS.get
    for entry in entries:  # one passive poll each: the core ids are known
        poll(diag, entry, T0, uptime=5000, wan_status=wan_status())
    await diag._async_sync_entities()
    return diag


def fleet(host: Host) -> dict[str, Any]:
    return {u: e for u, e in host.by_uid().items() if u in de.DIAG_FLEET_UNIQUE_IDS}


def gateways(host: Host) -> dict[str, Any]:
    return {
        u: e for u, e in host.by_uid().items() if u.endswith(DIAG_GATEWAY_UID_SUFFIX)
    }


def direct_finding(outcome: Any) -> Any:
    """A router finding from a DIRECT gateway-stage measurement."""
    point = point_for(RID1)
    chain = evaluate_chain(
        point,
        [
            probe(Stage.GATEWAY, outcome, ICMP, "gw", point=point),
            probe(Stage.GATEWAY, outcome, TCP, "gw-tcp", point=point),
            *ext(outcome, "ext-a", "ext-b", point=point),
        ],
        facts(),
    )
    return classify(chain)


# --- the bounded set --------------------------------------------------------------------


async def test_module_off_creates_no_entity(host, disk) -> None:  # noqa: F811
    diag = await module(host, "r1", "r2", enabled=False, devices=("r1", "r2"))
    assert host.entities() == []
    await diag._async_sync_entities()
    assert host.entities() == []
    assert diag.view is None
    await async_release_net_diagnostics(host.hass, "r1")
    await async_release_net_diagnostics(host.hass, "r2")


async def test_six_fleet_entities_plus_one_per_router_with_a_device(
    host,
    disk,  # noqa: F811
) -> None:
    # r3 has no device: it gets no sensor and no device is created for it
    diag = await module(host, "r1", "r2", "r3", devices=("r1", "r2"))
    assert len(fleet(host)) == 6 and set(fleet(host)) == set(de.DIAG_FLEET_UNIQUE_IDS)
    assert set(gateways(host)) == {
        f"r1{DIAG_GATEWAY_UID_SUFFIX}",
        "r2" + DIAG_GATEWAY_UID_SUFFIX,
    }
    assert len(host.entities()) == 6 + 2
    # the fleet set lives on the smallest entry, each gateway on its router
    assert {type(e) for e in host.platforms[("sensor", "r1")].added} == {
        de.DiagFleetSensor
    }
    assert [e.unique_id for e in host.platforms[("binary_sensor", "r2")].added] == [
        "r2" + DIAG_GATEWAY_UID_SUFFIX
    ]
    for entity in fleet(host).values():
        assert entity.device_info is None  # fleet: no device
    for entry, entity in (("r1", gateways(host)["r1" + DIAG_GATEWAY_UID_SUFFIX]),):
        # the router's existing device, identifiers only (nothing to create)
        assert entity.device_info == DeviceInfo(identifiers={(DOMAIN, entry)})
    assert host.hass.devices == {"r1": "dev-r1", "r2": "dev-r2"}
    # a second sync adds nothing twice
    await diag._async_sync_entities()
    assert len(host.entities()) == 8
    # r3's device appears: the update listener adds its sensor, once
    host.hass.devices["r3"] = "dev-r3"
    assert de.router_waiting(host.hass, diag)
    de._on_update(host.hass)
    de._on_update(host.hass)  # still syncing: no second task
    assert len(host.hass.tasks) == 1
    await host.hass.tasks[0]
    assert len(host.entities()) == 6 + 3
    assert not de.router_waiting(host.hass, diag)
    for entry in ("r1", "r2", "r3"):
        await async_release_net_diagnostics(host.hass, entry)


async def test_entry_release_moves_the_fleet_host_and_the_last_one_ends(
    host,
    disk,  # noqa: F811
) -> None:
    await module(host, "r1", "r2", devices=("r1", "r2"))
    assert len(host.platforms[("sensor", "r1")].added) == 6
    host.unload("r1")  # HA unloads the entry's platforms first
    await async_release_net_diagnostics(host.hass, "r1")
    assert {e.unique_id for e in host.platforms[("sensor", "r2")].added} == set(
        de.DIAG_FLEET_UNIQUE_IDS
    )
    assert host.hass.data[DATA_DIAG_ENTITIES].anchor == "r2"
    host.unload("r2")
    await async_release_net_diagnostics(host.hass, "r2")
    assert DATA_DIAG_ENTITIES not in host.hass.data


# --- values: the runtime only, unknown stays unknown ------------------------------------


async def test_unknown_is_unknown_never_a_healthy_value(host, disk) -> None:  # noqa: F811
    hass = host.hass
    host.load("r1")
    hass.devices["r1"] = "dev-r1"
    diag = await make_diag(hass, "r1")
    diag.router_id_of = ALL_RIDS.get
    diag._publish()
    await diag._async_sync_entities()
    sensors = fleet(host)
    assert len(sensors) == 6
    for entity in sensors.values():
        assert entity.native_value is None, entity.unique_id  # no data yet
    score = sensors[de.SENSORS[0].unique_id]
    attrs = score.extra_state_attributes
    assert attrs["coverage"] is None and attrs["low_confidence"] is True
    # a passive poll: the next hop is known, not whether it answers
    poll(diag, "r1", T0, uptime=5000, wan_status=wan_status())
    await diag._async_sync_entities()
    [gateway] = gateways(host).values()
    assert gateway.available and gateway.is_on is None
    assert gateway.extra_state_attributes["reason"] == "not_measured"
    view = diag.view
    for key in ("ha_latency_ms", "ha_loss_pct", "dns_ms"):
        assert view[key] is None  # no HA round: unknown, never 0
    by_uid = fleet(host)
    for uid in (
        de.SENSORS[3].unique_id,
        de.SENSORS[4].unique_id,
        de.SENSORS[5].unique_id,
    ):
        assert by_uid[uid].native_value is None
    # the score always carries its coverage and confidence
    assert {"coverage", "low_confidence"} <= set(score.extra_state_attributes)
    # module gone: unavailable, the attributes still name both
    diag.view = None
    assert not score.available and score.native_value is None
    assert score.extra_state_attributes["low_confidence"] is True
    assert "coverage" in score.extra_state_attributes
    hass.data.pop(DATA_NET_DIAGNOSTICS)
    assert not gateway.available and gateway.is_on is None
    hass.data[DATA_NET_DIAGNOSTICS] = diag
    await async_release_net_diagnostics(hass, "r1")


async def test_gateway_state_from_a_direct_measurement_only(
    host,
    disk,  # noqa: F811
) -> None:
    diag = await module(host, "r1", devices=("r1",))
    [gateway] = gateways(host).values()
    state = diag._routers[RID1]
    for outcome, expected in ((OK, True), (TIMEOUT, False)):
        state.finding = direct_finding(outcome)
        diag._publish()
        assert gateway.is_on is expected, outcome
        assert gateway.extra_state_attributes["family"] == "ipv4"
    await async_release_net_diagnostics(host.hass, "r1")


async def test_entities_read_the_module_view_only(host, disk) -> None:  # noqa: F811
    diag = await module(host, "r1", devices=("r1",))
    for entity in host.entities():
        assert not isinstance(entity, CoordinatorEntity)
        assert entity.should_poll is False
        assert entity.has_entity_name is True
        assert entity.translation_key
    diag.view = {
        "score": 81.6,
        "score_coverage": 0.75,
        "low_confidence": False,
        "routers": 1,
        "routers_scored": 1,
        "routers_unknown": 0,
        "coverage": 75,
        "ha_state": "ok",
        "findings_active": 2,
        "findings_by_classification": {"wan_problem": 2},
        "ha_latency_ms": 12.5,
        "ha_loss_pct": 0.0,
        "dns_ms": 4.2,
        "ha_measured_at": T0,
        "gateways": {RID1: {"state": True, "reason": "healthy", "family": "ipv4"}},
    }
    values = {u: e.native_value for u, e in fleet(host).items()}
    assert values == {
        de.SENSORS[0].unique_id: 82,
        de.SENSORS[1].unique_id: 75,
        de.SENSORS[2].unique_id: 2,
        de.SENSORS[3].unique_id: 12.5,
        de.SENSORS[4].unique_id: 0.0,
        de.SENSORS[5].unique_id: 4.2,
    }
    score = fleet(host)[de.SENSORS[0].unique_id]
    assert score.extra_state_attributes == {
        "coverage": 0.75,
        "low_confidence": False,
        "routers": 1,
        "routers_scored": 1,
        "routers_unknown": 0,
    }
    [gateway] = gateways(host).values()
    assert gateway.is_on is True
    # a value of the wrong type is unknown, never coerced to healthy
    diag.view = {**diag.view, "score": True, "gateways": {RID1: {"state": "yes"}}}
    assert score.native_value is None and gateway.is_on is None
    # the module file has no network path and no coordinator
    imports = [
        line
        for line in inspect.getsource(de).splitlines()
        if line.startswith(("import ", "from ")) or "import " in line
    ]
    for forbidden in ("api", "aiohttp", "clientsession", "coordinator"):
        assert not [line for line in imports if forbidden in line], forbidden
    await async_release_net_diagnostics(host.hass, "r1")


async def test_the_signal_writes_the_state(host, disk) -> None:  # noqa: F811
    await module(host, "r1", devices=("r1",))
    entity = next(iter(fleet(host).values()))
    with (
        patch.object(de, "async_dispatcher_connect") as connect,
        patch.object(entity, "async_write_ha_state") as write,
    ):
        entity.platform = SimpleNamespace(platform_name=DOMAIN)
        await entity.async_added_to_hass()
        signal, handler = connect.call_args.args[1:]
        assert signal == SIGNAL_NET_DIAGNOSTICS
        handler()
    write.assert_called_once()
    await async_release_net_diagnostics(host.hass, "r1")


# --- off: clean removal -------------------------------------------------------------------


def _entry(entry_id: str) -> Any:
    return SimpleNamespace(
        entry_id=entry_id,
        domain=DOMAIN,
        disabled_by=None,
        pref_disable_new_entities=False,
    )


async def test_switching_off_removes_the_entities_and_on_brings_them_back(
    host,
    disk,  # noqa: F811
) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    # the router devices: the fake device registry again (read only)
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    entries = {"r1": _entry("r1"), "r2": _entry("r2")}
    hass.config_entries.async_get_entry = lambda eid: entries.get(eid)
    for uid in de.DIAG_FLEET_UNIQUE_IDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=entries["r1"])
    for entry in ("r1", "r2"):
        registry.async_get_or_create(
            "binary_sensor",
            DOMAIN,
            de.gateway_unique_id(entry),
            config_entry=entries[entry],
        )
    # other entities of the integration and a foreign one stay
    keep = [
        registry.async_get_or_create(
            "sensor", DOMAIN, "r1_uptime", config_entry=entries["r1"]
        ).entity_id,
        registry.async_get_or_create(
            "binary_sensor", DOMAIN, "r1_wan_connected", config_entry=entries["r1"]
        ).entity_id,
        registry.async_get_or_create(
            "binary_sensor", "other", "x" + DIAG_GATEWAY_UID_SUFFIX
        ).entity_id,
    ]
    assert len(registry.entities) == 6 + 2 + 3

    diag = await module(host, "r1", "r2", devices=("r1", "r2"))
    assert len(host.entities()) == 8
    # off (what the settings route does without the core)
    diag.store.settings = merge_settings(diag.settings, {"enabled": False})
    diag._rebuild_registry()
    await diag.async_deactivate()
    diag._publish()
    await diag._async_sync_entities()
    assert sorted(e.entity_id for e in registry.entities.values()) == sorted(keep)
    hosts = hass.data[DATA_DIAG_ENTITIES]
    assert hosts.anchor is None and hosts.gateways == {}
    for entity in host.entities():
        assert not entity.available  # HA removes the live ones
    # on again: created at once, no reload
    for platform in host.platforms.values():
        platform.added.clear()
    diag.store.settings = merge_settings(diag.settings, {"enabled": True})
    diag._rebuild_registry()
    await diag.async_activate()
    await diag._async_sync_entities()
    assert len(fleet(host)) == 6  # at once
    # the gateway sensors follow with the next poll (the core ids again)
    for entry in ("r1", "r2"):
        poll(diag, entry, T0 + 60, uptime=5060)
    de._on_update(hass)
    for task in list(hass.tasks):
        await task
    assert len(host.entities()) == 8
    for entry in ("r1", "r2"):
        await async_release_net_diagnostics(hass, entry)


async def test_a_restart_before_the_store_is_read_removes_nothing(
    host,
    disk,  # noqa: F811
) -> None:
    hass = host.hass
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    entry = _entry("r1")
    hass.config_entries.async_get_entry = lambda eid: entry
    registry.async_get_or_create(
        "sensor", DOMAIN, de.DIAG_FLEET_UNIQUE_IDS[0], config_entry=entry
    )
    diag = await make_diag(hass, "r1", enabled=False, activate=False)
    diag.loaded = False
    await de.async_sync_diag_entities(hass)
    assert len(registry.entities) == 1
    diag.loaded = True
    await de.async_sync_diag_entities(hass)
    assert len(registry.entities) == 0
    await async_release_net_diagnostics(hass, "r1")


# --- recorder and translations -------------------------------------------------------------


def test_unrecorded_attributes_cover_the_attributes() -> None:
    view = {
        "findings_by_classification": {},
        "gateways": {},
    }
    for description in de.SENSORS:
        if description.extra_attrs_fn is not None:
            keys = set(description.extra_attrs_fn(view))
            assert keys <= de.DiagFleetSensor._unrecorded_attributes, keys
    assert de.DiagGatewaySensor._unrecorded_attributes >= {
        "reason",
        "family",
        "next_hop_known",
    }


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_every_translation_key_exists(name: str) -> None:
    data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
    for description in de.SENSORS:
        entry = data["entity"]["sensor"].get(description.translation_key)
        assert entry and entry["name"], (name, description.translation_key)
    entry = data["entity"]["binary_sensor"].get(de.GATEWAY_TRANSLATION_KEY)
    assert entry and entry["name"], name
