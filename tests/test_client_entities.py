"""B7: client stability sensors (client_entities.py).

No entity without a selection; five sensors per selected MAC (two enabled
by default), hosted by the fleet anchor; deselecting removes them from the
entity registry; the anchor's successor takes the registry entries over;
unique_ids avoid the legacy dynamic patterns; translation keys exist;
volatile attributes stay out of the recorder. The sensors read the engine's
published state only. MACs are locally administered test values.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from homeassistant.components.sensor import SensorDeviceClass
from homeassistant.helpers import entity_registry as er
from test_client_engine import client
from test_client_routes import poll
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_entities import loaded_registry

from custom_components.openwrt_router import (
    _LEGACY_DYNAMIC_PATTERNS,
    client_engine,
    net_engine,
)
from custom_components.openwrt_router import client_entities as ce
from custom_components.openwrt_router import net_entities as ne
from custom_components.openwrt_router.client_engine import (
    ClientStability,
    async_get_client_stability,
)
from custom_components.openwrt_router.const import DOMAIN
from custom_components.openwrt_router.net_engine import (
    NetIntelligence,
    async_get_net_intelligence,
)

G, A = "01JGWENTRY000000000000000GW", "01JAPENTRY000000000000000AP"
T0 = 1_800_000_000.0
M1 = "02:00:5E:10:00:01"
M2 = "02:00:5E:10:00:02"
COMPONENT = Path(__file__).parent.parent / "custom_components" / "openwrt_router"


def config_entry(entry_id: str) -> MagicMock:
    entry = MagicMock()
    entry.entry_id = entry_id
    entry.domain = DOMAIN
    entry.disabled_by = None
    entry.pref_disable_new_entities = False
    return entry


class Setup:
    """Engines, a real entity registry and the captured dispatcher listeners."""

    def __init__(
        self, engine: NetIntelligence, cs: ClientStability, registry: Any
    ) -> None:
        self.engine = engine
        self.cs = cs
        self.registry = registry
        self.hass = engine.hass
        self.entries = {G: config_entry(G), A: config_entry(A)}
        self.hass.config_entries.async_get_entry.side_effect = self.entries.get
        self.listeners: list[Callable[[], None]] = []
        self.added: dict[str, list[Any]] = {G: [], A: []}

    def connect(self, _hass: Any, _signal: str, target: Any) -> Callable[[], None]:
        self.listeners.append(target)
        return lambda: self.listeners.remove(target)

    def fire(self) -> None:
        for target in tuple(self.listeners):
            target()

    def setup(self, entry_id: str) -> list[Any]:
        def add(entities: Any) -> None:
            for entity in entities:
                entity.hass = self.hass
                # register like the entity platform does
                self.registry.async_get_or_create(
                    "sensor",
                    DOMAIN,
                    entity.unique_id,
                    config_entry=self.entries[entry_id],
                )
            self.added[entry_id].extend(entities)

        ce.async_setup_client_sensors(self.hass, self.entries[entry_id], add)
        return self.added[entry_id]

    def uids(self) -> set[str]:
        return {
            e.unique_id
            for e in self.registry.entities.values()
            if e.unique_id.startswith("openwrt_router_client_")
        }


@pytest.fixture
async def env() -> Setup:
    disks: dict[str, FakeDisk] = {}

    def store(*args: Any, **kw: Any) -> FakeStore:
        return FakeStore(disks.setdefault(args[2], FakeDisk()), *args, **kw)

    hass = make_hass()
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry  # what er.async_get(hass) returns
    with (
        patch.object(net_engine, "Store", store),
        patch.object(client_engine, "Store", store),
        patch.object(net_engine, "async_call_later", lambda *a: lambda: None),
    ):
        engine = await async_get_net_intelligence(hass)
        for router in (G, A):
            engine.register(router)
        cs = await async_get_client_stability(hass, engine)
        env = Setup(engine, cs, registry)
        with (
            patch.object(ce, "async_dispatcher_connect", env.connect),
            patch.object(client_engine, "async_dispatcher_send", lambda *a: env.fire()),
        ):
            for i in range(30):
                cs.on_poll(
                    poll(G, T0 + i * 60, client(M1, signal=-55, hostname="phone"))
                )
            yield env


def select(env: Setup, *macs: str) -> None:
    env.cs.update_settings({"entity_macs": list(macs)})


# --- set-up ------------------------------------------------------------------------


async def test_no_entities_without_a_selection(env: Setup) -> None:
    assert env.setup(G) == []
    assert env.uids() == set()


async def test_five_sensors_per_selected_client(env: Setup) -> None:
    select(env, M1)
    added = env.setup(G)
    uids = {e.unique_id for e in added}
    assert uids == {f"openwrt_router_client_02005e100001_{k}" for k in ce.SENSOR_KEYS}
    assert len(uids) == 5
    for uid in uids:
        for pattern in _LEGACY_DYNAMIC_PATTERNS:
            assert pattern not in uid, (uid, pattern)
    on = {e.translation_key for e in added if e.entity_registry_enabled_default}
    assert on == {"client_stability_score", "client_connection_quality"}
    assert all(e.device_info is None for e in added)
    assert all(e.translation_placeholders == {"client": "phone"} for e in added)


async def test_selecting_later_adds_and_deselecting_removes(env: Setup) -> None:
    env.setup(G)
    select(env, M1, M2)
    assert len(env.added[G]) == 10
    assert len(env.uids()) == 10
    select(env, M2)
    remaining = env.uids()
    assert len(remaining) == 5
    assert all("02005e100002" in uid for uid in remaining)
    # selecting M1 again creates it anew
    select(env, M1, M2)
    assert len(env.uids()) == 10


async def test_stale_registry_entries_are_removed_at_start(env: Setup) -> None:
    env.registry.async_get_or_create(
        "sensor",
        DOMAIN,
        f"openwrt_router_client_02005e100002_{ce.KEY_SCORE}",
        config_entry=env.entries[G],
    )
    env.setup(G)
    assert env.uids() == set()


async def test_second_router_hosts_no_client_sensors(env: Setup) -> None:
    select(env, M1)
    env.setup(G)
    assert env.setup(A) == []


async def test_sensor_values_come_from_the_published_state(env: Setup) -> None:
    select(env, M1)
    sensors = {e.translation_key: e for e in env.setup(G)}
    env.fire()
    score = sensors["client_stability_score"]
    assert score.available
    assert 0 <= score.native_value <= 100
    assert set(score.extra_state_attributes) == {"score_7d", "coverage"}
    quality = sensors["client_connection_quality"]
    assert quality.device_class is SensorDeviceClass.ENUM
    assert quality.native_value in quality.options
    assert "unknown" not in quality.options
    assert sensors["client_reconnects_24h"].native_value == 0  # full log cover
    uptime = sensors["client_connection_uptime"]
    assert uptime.device_class is SensorDeviceClass.DURATION
    assert uptime.native_value == 29 * 60
    last = sensors["client_last_disconnect"]
    assert last.device_class is SensorDeviceClass.TIMESTAMP
    assert last.native_value is None


async def test_unknown_class_is_no_state_and_gone_client_is_unavailable(
    env: Setup,
) -> None:
    select(env, M2)  # never seen
    sensors = {e.translation_key: e for e in env.setup(G)}
    assert not sensors["client_stability_score"].available
    assert sensors["client_connection_quality"].native_value is None
    assert sensors["client_stability_score"].translation_placeholders == {"client": M2}


async def test_last_disconnect_is_a_utc_timestamp(env: Setup) -> None:
    select(env, M1)
    sensors = {e.translation_key: e for e in env.setup(G)}
    for i in range(30, 34):
        env.cs.on_poll(poll(G, T0 + i * 60))
    value = sensors["client_last_disconnect"].native_value
    assert isinstance(value, datetime)
    assert value.tzinfo is UTC
    assert sensors["client_connection_uptime"].native_value is None


async def test_sensors_unavailable_without_the_engine(env: Setup) -> None:
    select(env, M1)
    sensors = env.setup(G)
    env.hass.data.pop(client_engine._DATA_KEY)
    assert not any(e.available for e in sensors)


# --- fleet anchor ------------------------------------------------------------------


async def test_withdraw_moves_client_sensors_to_the_successor(env: Setup) -> None:
    select(env, M1)
    env.setup(G)
    env.setup(A)
    ne.async_withdraw_fleet(env.hass, G)
    owners = {
        e.config_entry_id
        for e in env.registry.entities.values()
        if e.unique_id.startswith("openwrt_router_client_")
    }
    assert owners == {A}


# --- recorder and translations -------------------------------------------------------


def test_unrecorded_attributes_cover_the_attributes() -> None:
    assert ce.ClientStabilityScoreSensor._unrecorded_attributes >= {
        "score_7d",
        "coverage",
    }


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
async def test_every_translation_key_exists(env: Setup, name: str) -> None:
    data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
    select(env, M1)
    for entity in env.setup(G):
        entry = data["entity"]["sensor"].get(entity.translation_key)
        assert entry and "{client}" in entry["name"], (name, entity.translation_key)
        if entity.device_class is SensorDeviceClass.ENUM:
            states = entry.get("state", {})
            assert set(entity.options) <= set(states), (name, entity.options)


def test_registry_removal_uses_only_the_client_prefix() -> None:
    assert ce.client_unique_id(M1, ce.KEY_SCORE) == (
        "openwrt_router_client_02005e100001_stability_score"
    )
    assert (
        ce.mac_of_unique_id("openwrt_router_client_02005e100001_stability_score") == M1
    )
    assert ce.mac_of_unique_id("openwrt_router_fleet_net_health") is None
    assert ce.mac_of_unique_id("x_02005e100001_y") is None
    assert ce.mac_of_unique_id("openwrt_router_client_nothex_y") is None
