"""Self-Healing package K1: the read-only entities.

Seven fleet entities (no device) and one diagnostic mode sensor per router,
all computed from the running engine's memory. Sensors and binary sensors
only; created while the engine runs, removed from the entity registry when
the fleet switch goes off, never removed while the switch is on.

Also here: the recorded router calls with the module on in Observe (two
polls, module off vs on: the same calls).
"""

from __future__ import annotations

import dataclasses
import inspect
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import full_router_kit as kit
import pytest
from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.const import EntityCategory
from homeassistant.helpers import entity_registry as er
from test_heal_engine_v1530 import E1, E2, World, world
from test_heal_events_audit_v1530 import FakeAudit, record
from test_heal_store_v1530 import R1, R2, T0, disks

from custom_components.openwrt_router import config_api
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_entities as hx
from custom_components.openwrt_router import heal_journal as hj
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router.const import (
    DATA_SELF_HEALING_ENGINE,
    DOMAIN,
    OPTION_SELF_HEALING_ENABLED,
)

S = hm.ActionState
M = hm.HealMode
DAY = 86400.0
COMPONENT = Path(__file__).parent.parent / "custom_components" / "openwrt_router"

__all__ = ["disks", "world"]  # fixtures used here


# ---------------------------------------------------------------------------
# Stand-ins
# ---------------------------------------------------------------------------


class Adder:
    """``async_add_entities`` of one platform of one entry."""

    def __init__(self) -> None:
        self.added: list[Any] = []
        self.calls = 0

    def __call__(self, entities: Any, *args: Any, **kwargs: Any) -> None:
        self.calls += 1
        self.added.extend(entities)

    def uids(self) -> list[str]:
        return [e.unique_id for e in self.added]


class Registry:
    """The entity registry as ``heal_entities`` uses it."""

    def __init__(self) -> None:
        self.ids: dict[tuple[str, str, str], str] = {}
        self.removed: list[str] = []

    def put(self, domain: str, unique_id: str) -> str:
        entity_id = f"{domain}.e{len(self.ids)}"
        self.ids[(domain, DOMAIN, unique_id)] = entity_id
        return entity_id

    def async_get_entity_id(self, domain: str, platform: str, uid: str) -> Any:
        return self.ids.get((domain, platform, uid))

    def async_remove(self, entity_id: str) -> None:
        self.removed.append(entity_id)
        self.ids = {k: v for k, v in self.ids.items() if v != entity_id}

    def unique_ids(self) -> set[str]:
        return {k[2] for k in self.ids}


FLEET_SENSOR_UIDS = [
    "openwrt_router_fleet_self_healing_mode",
    "openwrt_router_fleet_remediation_active",
    "openwrt_router_fleet_remediation_pending",
    "openwrt_router_fleet_remediation_succeeded_30d",
    "openwrt_router_fleet_remediation_failed_30d",
    "openwrt_router_fleet_remediation_last_result",
]
FLEET_BINARY_UIDS = ["openwrt_router_fleet_auto_heal_enabled"]


def offer(hass: Any) -> dict[str, tuple[Adder, Adder]]:
    """Every entry's sensor and binary-sensor platform offers to host."""
    out = {}
    for entry in hass.entries:
        sensors, binaries = Adder(), Adder()
        hx.async_setup_heal_sensors(hass, entry, sensors)
        hx.async_setup_heal_binary_sensors(hass, entry, binaries)
        out[entry.entry_id] = (sensors, binaries)
    return out


def bound(entity: Any, hass: Any) -> Any:
    entity.hass = hass
    return entity


def set_mode(engine: he.HealEngine, **modes: M) -> None:
    rid_of = {"r1": R1, "r2": R2}
    engine.store.set_settings(
        hm.HealSettings(
            routers={rid_of[k]: hm.RouterSettings(mode=v) for k, v in modes.items()}
        )
    )


def put(engine: he.HealEngine, *recs: hm.RemediationAction) -> None:
    for rec in recs:
        engine.store.actions[rec.action_id] = rec


def ended(state: hm.ActionState, at: float, *, executed: bool) -> hm.RemediationAction:
    """A record that ended in ``state`` at ``at``."""
    if executed:
        path = [
            S.ANALYZED,
            S.PROPOSED,
            S.PREFLIGHT,
            S.WAITING_APPROVAL,
            S.APPROVED,
            S.EXECUTING,
            S.VERIFYING,
        ]
    else:
        path = [S.ANALYZED, S.PROPOSED]
    rec = record([*path, state], ts0=at - len(path) - 1)
    assert rec.history[-1].ts == at
    return rec


# ---------------------------------------------------------------------------
# Closed sets
# ---------------------------------------------------------------------------


def test_the_unique_ids_options_and_keys_are_literal() -> None:
    assert [d.unique_id for d in hx.FLEET_SENSORS] == FLEET_SENSOR_UIDS
    assert [d.unique_id for d in hx.FLEET_BINARY_SENSORS] == FLEET_BINARY_UIDS
    assert hx.FLEET_UNIQUE_IDS == (*FLEET_SENSOR_UIDS, *FLEET_BINARY_UIDS)
    assert hx.router_unique_id("abc") == "abc_self_healing_mode"
    assert hx.FLEET_MODE_OPTIONS == ("observe", "approval", "auto_heal", "mixed")
    assert hx.ROUTER_MODE_OPTIONS == ("observe", "approval", "auto_heal")
    assert hx.LAST_RESULT_OPTIONS == (
        "resolved",
        "rejected",
        "cancelled",
        "escalated",
        "manual_recovery_required",
        "rolled_back",
    )
    assert set(hx.LAST_RESULT_OPTIONS) == {s.value for s in hm.TERMINAL_STATES}
    assert hx.WINDOW_S == 30 * 86400.0
    assert [d.translation_key for d in hx.FLEET_SENSORS] == [
        "fleet_self_healing_mode",
        "fleet_remediation_active",
        "fleet_remediation_pending",
        "fleet_remediation_succeeded_30d",
        "fleet_remediation_failed_30d",
        "fleet_remediation_last_result",
    ]
    assert hx.FLEET_BINARY_SENSORS[0].translation_key == "fleet_auto_heal_enabled"
    assert hx.ROUTER_MODE_SENSOR.translation_key == "self_healing_mode"


def test_the_enum_sensors_name_their_options() -> None:
    by_uid = {d.unique_id: d for d in hx.FLEET_SENSORS}
    mode = by_uid["openwrt_router_fleet_self_healing_mode"]
    last = by_uid["openwrt_router_fleet_remediation_last_result"]
    for desc, options in (
        (mode, hx.FLEET_MODE_OPTIONS),
        (last, hx.LAST_RESULT_OPTIONS),
    ):
        assert desc.device_class is SensorDeviceClass.ENUM
        assert desc.options == list(options)
        assert desc.state_class is None
        assert desc.native_unit_of_measurement is None
    router = hx.ROUTER_MODE_SENSOR
    assert router.device_class is SensorDeviceClass.ENUM
    assert router.options == list(hx.ROUTER_MODE_OPTIONS)
    assert router.entity_category is EntityCategory.DIAGNOSTIC
    for desc in hx.FLEET_SENSORS:
        if desc.device_class is None:
            assert desc.state_class == "measurement"


def test_the_descriptions_are_frozen() -> None:
    for desc in (*hx.FLEET_SENSORS, *hx.FLEET_BINARY_SENSORS):
        with pytest.raises(dataclasses.FrozenInstanceError):
            desc.unique_id = "x"  # type: ignore[misc]
    assert hx.HealSensorDescription.__dataclass_params__.frozen is True
    assert hx.HealBinarySensorDescription.__dataclass_params__.frozen is True


@pytest.mark.parametrize("name", ["strings.json", "translations/en.json"])
def test_every_entity_has_its_english_texts(name: str) -> None:
    texts = json.loads((COMPONENT / name).read_text(encoding="utf-8"))["entity"]
    sensors = texts["sensor"]
    assert sensors["fleet_self_healing_mode"] == {
        "name": "Self-Healing mode (all routers)",
        "state": {
            "observe": "Observe",
            "approval": "Approval",
            "auto_heal": "Auto-Heal",
            "mixed": "Mixed",
        },
    }
    assert set(sensors["fleet_remediation_last_result"]["state"]) == set(
        hx.LAST_RESULT_OPTIONS
    )
    assert set(sensors["self_healing_mode"]["state"]) == set(hx.ROUTER_MODE_OPTIONS)
    for desc in hx.FLEET_SENSORS:
        assert sensors[desc.translation_key]["name"].endswith("(all routers)")
    assert texts["binary_sensor"]["fleet_auto_heal_enabled"] == {
        "name": "Auto-Heal enabled (any router)"
    }


def test_every_entity_has_its_german_texts() -> None:
    texts = json.loads((COMPONENT / "translations/de.json").read_text("utf-8"))
    sensors = texts["entity"]["sensor"]
    assert sensors["fleet_self_healing_mode"]["state"] == {
        "observe": "Beobachten",
        "approval": "Freigabe",
        "auto_heal": "Auto-Heal",
        "mixed": "Gemischt",
    }
    assert set(sensors["fleet_remediation_last_result"]["state"]) == set(
        hx.LAST_RESULT_OPTIONS
    )
    for desc in (*hx.FLEET_SENSORS, hx.ROUTER_MODE_SENSOR):
        assert sensors[desc.translation_key]["name"]
    assert texts["entity"]["binary_sensor"]["fleet_auto_heal_enabled"]["name"]


def test_read_only_no_button_switch_service_or_router_access() -> None:
    source = inspect.getsource(hx)
    for forbidden in (
        "ButtonEntity",
        "SwitchEntity",
        "services.async_register",
        "async_call(",
        "from .api",
        "OpenWrtAPI",
        "async_request_refresh",
        "async_refresh",
        "aiohttp",
        "async_get_clientsession",
        "async_load",
        "async_save",
        ".schedule(",
        "store.now(",
        "set_settings",
        "store.apply",
        "store.add",
    ):
        assert forbidden not in source, forbidden
    classes = [hx.HealFleetSensor, hx.HealFleetBinarySensor, hx.HealRouterModeSensor]
    for cls in classes:
        assert issubclass(cls, SensorEntity | BinarySensorEntity)
        assert cls._attr_should_poll is False
        assert cls._attr_has_entity_name is True
    journal = inspect.getsource(hj)
    for forbidden in ("from .api", "OpenWrtAPI", "async_listen", "aiohttp"):
        assert forbidden not in journal, forbidden


def test_the_engine_module_still_names_no_entity_and_fires_nothing() -> None:
    """The static rule of package C1 holds for ``heal_engine`` with K1."""
    source = inspect.getsource(he)
    for forbidden in ("async_fire", "Entity", "services.async_register"):
        assert forbidden not in source, forbidden


# ---------------------------------------------------------------------------
# Values, from the engine's memory
# ---------------------------------------------------------------------------


async def test_the_fleet_mode_follows_the_mode_in_force(world: World) -> None:
    engine = await world.start()
    assert hx.fleet_mode(engine) == "observe"
    set_mode(engine, r1=M.APPROVAL)
    assert hx.fleet_mode(engine) == "mixed"
    set_mode(engine, r1=M.APPROVAL, r2=M.APPROVAL)
    assert hx.fleet_mode(engine) == "approval"
    set_mode(engine, r1=M.AUTO_HEAL, r2=M.AUTO_HEAL)
    assert hx.fleet_mode(engine) == "auto_heal"
    engine.store.loop.holds[R1] = hm.RouterHold(
        router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=0.0
    )
    assert hx.fleet_mode(engine) == "mixed"  # held: Observe on R1
    engine.store.loop.holds.clear()
    engine.store.set_settings(dataclasses.replace(engine.store.settings, enabled=False))
    assert hx.fleet_mode(engine) == "observe"  # module off: Observe


async def test_the_fleet_mode_is_unknown_without_routers_or_clock(
    world: World,
) -> None:
    engine = await world.start()
    engine.entries.clear()
    assert hx.fleet_mode(engine) is None
    engine.entries.add(E1)
    # a store that has not observed the clock yet (never true after a load)
    kept = engine.store.loop.clock
    engine.store.loop.clock = SimpleNamespace(safe=None)  # type: ignore[assignment]
    assert hx.fleet_mode(engine) is None
    assert hx.auto_heal_any(engine) is None
    assert hx.router_mode(engine, E1) == (
        None,
        {
            "router_id": R1,
            "configured_mode": "observe",
            "held": None,
            "fleet_paused": None,
            "module_enabled": True,
        },
    )
    engine.store.loop.clock = kept


async def test_auto_heal_any_router(world: World) -> None:
    engine = await world.start()
    assert hx.auto_heal_any(engine) is False
    set_mode(engine, r2=M.AUTO_HEAL)
    assert hx.auto_heal_any(engine) is True
    engine.store.set_settings(dataclasses.replace(engine.store.settings, enabled=False))
    assert hx.auto_heal_any(engine) is False
    engine.router_ids = MagicMock(side_effect=RuntimeError("x"))  # type: ignore[method-assign]
    assert hx.auto_heal_any(engine) is None


async def test_the_router_mode_and_what_holds_it(world: World) -> None:
    engine = await world.start()
    set_mode(engine, r1=M.APPROVAL)
    assert hx.router_mode(engine, E1) == (
        "approval",
        {
            "router_id": R1,
            "configured_mode": "approval",
            "held": False,
            "fleet_paused": False,
            "module_enabled": True,
        },
    )
    engine.store.loop.holds[R1] = hm.RouterHold(
        router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=0.0
    )
    mode, attrs = hx.router_mode(engine, E1)
    assert mode == "observe" and attrs["held"] is True
    assert hx.router_mode(engine, "unknown-entry") == (None, {})


async def test_active_and_pending_counts(world: World) -> None:
    engine = await world.start()
    assert (hx.active_count(engine), hx.pending_count(engine)) == (0, 0)
    world.open("inc-1")
    assert (hx.active_count(engine), hx.pending_count(engine)) == (1, 0)
    put(engine, record([S.ANALYZED, S.PROPOSED, S.PREFLIGHT, S.WAITING_APPROVAL]))
    assert (hx.active_count(engine), hx.pending_count(engine)) == (2, 1)
    world.resolve("inc-1")
    assert (hx.active_count(engine), hx.pending_count(engine)) == (1, 1)


async def test_the_30_day_window(world: World) -> None:
    engine = await world.start()
    now = T0 + 100 * DAY
    assert hx.window(engine, now) == hx._Window(0, 0)
    put(
        engine,
        ended(S.RESOLVED, now - DAY, executed=True),
        ended(S.RESOLVED, now - 30 * DAY, executed=True),  # on the edge: in
        ended(S.RESOLVED, now - 30 * DAY - 1, executed=True),  # out
        ended(S.ESCALATED, now - 2 * DAY, executed=True),
        ended(S.MANUAL_RECOVERY_REQUIRED, now - 3 * DAY, executed=True),
        ended(S.CANCELLED, now - DAY, executed=False),  # no repair
        ended(S.REJECTED, now - DAY, executed=False),  # no repair
    )
    put(engine, record([S.ANALYZED, S.PROPOSED]))  # open: not counted
    assert hx.window(engine, now) == hx._Window(2, 2)


async def test_the_window_is_unknown_after_an_eviction_it_cannot_rule_out(
    world: World,
) -> None:
    engine = await world.start()
    now = T0 + 100 * DAY
    put(engine, ended(S.RESOLVED, now - DAY, executed=True))
    engine.store.counters["evicted_terminal"] = 1
    assert hx.window(engine, now) == hx._Window(None, None)
    # a kept record older than the window: every evicted one is older still
    put(engine, ended(S.CANCELLED, now - 40 * DAY, executed=False))
    assert hx.window(engine, now) == hx._Window(1, 0)


async def test_the_last_result(world: World) -> None:
    engine = await world.start()
    assert hx.last_result(engine) == (None, {})
    old = ended(S.RESOLVED, T0 + 10, executed=True)
    new = ended(S.ROLLED_BACK, T0 + 20, executed=False)
    put(engine, old, new, record([S.ANALYZED]))
    assert hx.last_result(engine) == (
        "rolled_back",
        {
            "action_id": new.action_id,
            "router_id": R1,
            "action_type": "observe.evaluate",
            "incident_type": "dns_failure",
            "ended_at": T0 + 20,
        },
    )
    world.open("inc-9", router=E2)
    world.clock.now = T0 + 30
    world.resolve("inc-9")
    state, attrs = hx.last_result(engine)
    assert state == "cancelled" and attrs["router_id"] == R2


# ---------------------------------------------------------------------------
# The entity objects
# ---------------------------------------------------------------------------


async def test_entities_read_the_engine_and_are_unavailable_without_it(
    world: World,
) -> None:
    hass = world.hass
    fleet = {d.unique_id: bound(hx.HealFleetSensor(d), hass) for d in hx.FLEET_SENSORS}
    binary = bound(hx.HealFleetBinarySensor(hx.FLEET_BINARY_SENSORS[0]), hass)
    router = bound(hx.HealRouterModeSensor(E1), hass)
    everything = [*fleet.values(), binary, router]
    for entity in everything:
        assert entity.available is False
    assert [e.native_value for e in fleet.values()] == [None] * 6
    assert binary.is_on is None and router.native_value is None
    assert router.extra_state_attributes is None
    engine = await world.start()
    world.clock.now = T0
    world.open("inc-1")
    for entity in everything:
        assert entity.available is True
    assert {uid: e.native_value for uid, e in fleet.items()} == {
        "openwrt_router_fleet_self_healing_mode": "observe",
        "openwrt_router_fleet_remediation_active": 1,
        "openwrt_router_fleet_remediation_pending": 0,
        "openwrt_router_fleet_remediation_succeeded_30d": 0,
        "openwrt_router_fleet_remediation_failed_30d": 0,
        "openwrt_router_fleet_remediation_last_result": None,
    }
    assert fleet[
        "openwrt_router_fleet_remediation_failed_30d"
    ].extra_state_attributes == {"window_days": 30}
    assert (
        fleet["openwrt_router_fleet_remediation_active"].extra_state_attributes is None
    )
    assert binary.is_on is False
    assert router.native_value == "observe"
    assert router.device_info == {"identifiers": {(DOMAIN, E1)}}
    assert router.unique_id == "e1_self_healing_mode"
    assert router.entity_category is EntityCategory.DIAGNOSTIC
    await engine.async_stop()
    for entity in everything:
        assert entity.available is False


async def test_a_failing_read_is_unknown(world: World) -> None:
    hass = world.hass
    engine = await world.start()
    bad = dataclasses.replace(
        hx.FLEET_SENSORS[1],
        value_fn=MagicMock(side_effect=RuntimeError("x")),
        extra_attrs_fn=MagicMock(side_effect=RuntimeError("x")),
    )
    sensor = bound(hx.HealFleetSensor(bad), hass)
    assert sensor.available is True
    assert sensor.native_value is None and sensor.extra_state_attributes is None
    bad_bin = dataclasses.replace(
        hx.FLEET_BINARY_SENSORS[0], value_fn=MagicMock(side_effect=RuntimeError("x"))
    )
    assert bound(hx.HealFleetBinarySensor(bad_bin), hass).is_on is None
    router = bound(hx.HealRouterModeSensor(E1), hass)
    with patch.object(hx, "router_mode", MagicMock(side_effect=RuntimeError("x"))):
        assert router.native_value is None
        assert router.extra_state_attributes is None
    assert engine.loaded is True


async def test_an_entity_listens_to_the_journal_signal(world: World) -> None:
    hass = world.hass
    sensor = bound(hx.HealFleetSensor(hx.FLEET_SENSORS[0]), hass)
    connected: list[tuple[Any, ...]] = []

    def connect(h: Any, signal: str, target: Any) -> Any:
        connected.append((h, signal, target))
        return lambda: None

    with patch.object(hx, "async_dispatcher_connect", connect):
        sensor.async_on_remove = MagicMock()  # type: ignore[method-assign]
        await sensor.async_added_to_hass()
    [(h, signal, target)] = connected
    assert h is hass and signal == hj.SIGNAL_SELF_HEALING
    assert target == sensor._handle_update
    assert getattr(type(sensor)._handle_update, "_hass_callback", False) is True
    sensor.async_write_ha_state = MagicMock()  # type: ignore[method-assign]
    target()
    sensor.async_write_ha_state.assert_called_once_with()


# ---------------------------------------------------------------------------
# Life cycle
# ---------------------------------------------------------------------------


async def test_created_once_the_engine_runs_and_only_once(world: World) -> None:
    hass = world.hass
    adders = offer(hass)
    assert all(a.added == [] and b.added == [] for a, b in adders.values())
    await he.async_setup_self_healing(hass, hass.entries[0])
    s1, b1 = adders[E1]
    s2, b2 = adders[E2]
    assert s1.uids() == [*FLEET_SENSOR_UIDS, "e1_self_healing_mode"]
    assert b1.uids() == FLEET_BINARY_UIDS
    assert s2.uids() == ["e2_self_healing_mode"] and b2.uids() == []
    await he.async_setup_self_healing(hass, hass.entries[1])
    hx.async_sync_heal_entities(hass)
    assert len(s1.added) == 7 and len(s2.added) == 1 and len(b1.added) == 1
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)


async def test_switched_off_they_are_removed_and_on_again_created(
    world: World,
) -> None:
    hass = world.hass
    registry = Registry()
    hass.data[er.DATA_REGISTRY] = registry
    adders = offer(hass)
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    for uid in FLEET_SENSOR_UIDS + ["e1_self_healing_mode", "e2_self_healing_mode"]:
        registry.put("sensor", uid)
    registry.put("binary_sensor", FLEET_BINARY_UIDS[0])
    registry.put("sensor", "e1_uptime")  # not ours: stays
    registry.put("sensor", "openwrt_router_fleet_security_score")  # not ours
    for entry in hass.entries:
        entry.options[OPTION_SELF_HEALING_ENABLED] = False
    await he.async_apply_self_healing_option(hass, on=False)
    assert he.async_get_self_healing(hass) is None
    assert registry.unique_ids() == {"e1_uptime", "openwrt_router_fleet_security_score"}
    assert len(registry.removed) == 9
    for entry in hass.entries:
        entry.options[OPTION_SELF_HEALING_ENABLED] = True
    await he.async_apply_self_healing_option(hass, on=True)
    s1, b1 = adders[E1]
    s2, _b2 = adders[E2]
    assert s1.uids() == [*FLEET_SENSOR_UIDS, "e1_self_healing_mode"] * 2
    assert b1.uids() == FLEET_BINARY_UIDS * 2
    assert s2.uids() == ["e2_self_healing_mode"] * 2
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)


async def test_the_off_switch_is_applied_even_before_the_options_are_saved(
    world: World,
) -> None:
    """The options flow applies the switch before it saves the entry's own
    options: removal follows the flow's value, not the stored one."""
    hass = world.hass
    registry = Registry()
    hass.data[er.DATA_REGISTRY] = registry
    offer(hass)
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    registry.put("sensor", FLEET_SENSOR_UIDS[0])
    assert he.self_healing_enabled(hass) is True
    await he.async_apply_self_healing_option(hass, on=False)
    assert registry.unique_ids() == set()


async def test_off_at_a_start_nothing_is_created_and_old_ones_go(
    world: World,
) -> None:
    hass = world.hass
    registry = Registry()
    hass.data[er.DATA_REGISTRY] = registry
    registry.put("sensor", FLEET_SENSOR_UIDS[1])
    registry.put("sensor", "e2_self_healing_mode")
    hass.entries[0].options[OPTION_SELF_HEALING_ENABLED] = False
    adders = offer(hass)
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    assert he.async_get_self_healing(hass) is None
    assert all(a.added == [] and b.added == [] for a, b in adders.values())
    assert registry.unique_ids() == set()


async def test_on_but_not_running_yet_nothing_is_removed(world: World) -> None:
    hass = world.hass
    registry = Registry()
    hass.data[er.DATA_REGISTRY] = registry
    registry.put("sensor", FLEET_SENSOR_UIDS[0])
    adders = offer(hass)
    assert registry.removed == []
    assert all(a.added == [] for a, _b in adders.values())


async def test_no_registry_is_never_created(world: World) -> None:
    hass = world.hass
    hass.entries[0].options[OPTION_SELF_HEALING_ENABLED] = False
    offer(hass)
    hx.async_remove_heal_entities(hass)
    assert er.DATA_REGISTRY not in hass.data


async def test_the_fleet_moves_when_its_host_unloads(world: World) -> None:
    hass = world.hass
    adders = offer(hass)
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    await he.async_release_self_healing(hass, E1)
    s2, b2 = adders[E2]
    assert s2.uids() == ["e2_self_healing_mode", *FLEET_SENSOR_UIDS]
    assert b2.uids() == FLEET_BINARY_UIDS
    # E1 comes back: the fleet stays on E2, E1 gets its own sensor again
    s1 = Adder()
    hx.async_setup_heal_sensors(hass, hass.entries[0], s1)
    assert s1.uids() == ["e1_self_healing_mode"]
    assert len(s2.added) == 7
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)
    assert hx.DATA_HEAL_ENTITIES not in hass.data


async def test_an_unload_without_an_engine_keeps_the_others_offers(
    world: World,
) -> None:
    hass = world.hass
    for entry in hass.entries:
        entry.options[OPTION_SELF_HEALING_ENABLED] = False
    adders = offer(hass)
    await he.async_release_self_healing(hass, E1)
    hosts = hass.data[hx.DATA_HEAL_ENTITIES]
    assert set(hosts.sensor.adders) == {E2} and set(hosts.binary.adders) == {E2}
    for entry in hass.entries:
        entry.options[OPTION_SELF_HEALING_ENABLED] = True
    await he.async_apply_self_healing_option(hass, on=True)
    s2, b2 = adders[E2]
    assert s2.uids() == [*FLEET_SENSOR_UIDS, "e2_self_healing_mode"]
    assert b2.uids() == FLEET_BINARY_UIDS
    await he.async_release_self_healing(hass, E2)


async def test_a_failing_entity_module_never_breaks_the_engine(world: World) -> None:
    hass = world.hass
    with patch.object(
        hx, "async_sync_heal_entities", MagicMock(side_effect=RuntimeError("bug"))
    ):
        await he.async_setup_self_healing(hass, hass.entries[0])
    assert he.async_get_self_healing(hass) is not None
    with patch.object(
        hx, "async_entry_unloaded", MagicMock(side_effect=RuntimeError("bug"))
    ):
        await he.async_release_self_healing(hass, E1)
    assert he.async_get_self_healing(hass) is None


async def test_the_platforms_survive_a_broken_entity_module() -> None:
    from core_testkit import make_hass

    from custom_components.openwrt_router import binary_sensor, sensor

    hass = make_hass()
    entry = SimpleNamespace(entry_id="e1", title="r")
    with (
        patch.object(sensor, "_async_setup_entry_sensor_base", AsyncMock()),
        patch.object(
            hx, "async_setup_heal_sensors", MagicMock(side_effect=RuntimeError("x"))
        ),
    ):
        await sensor.async_setup_entry(hass, entry, MagicMock())
    calls = MagicMock()
    with (
        patch.object(
            hx,
            "async_setup_heal_binary_sensors",
            MagicMock(side_effect=RuntimeError("x")),
        ),
        patch.object(binary_sensor, "async_setup_intel_binary_sensors", MagicMock()),
        patch.object(binary_sensor, "async_setup_config_binary_sensors", MagicMock()),
    ):
        entry.runtime_data = SimpleNamespace(coordinator=MagicMock())
        await binary_sensor.async_setup_entry(hass, entry, calls)
    calls.assert_called_once()  # the router's own binary sensors


# ---------------------------------------------------------------------------
# Recorded router calls: module on (Observe) vs off, two polls
# ---------------------------------------------------------------------------


async def test_zero_extra_router_calls_with_the_module_on(world: World) -> None:
    off_calls: list[Any] = []
    off = kit.make_coordinator(MagicMock(), kit.make_api(off_calls))
    await kit.full_polls(off, on_poll=lambda d, n: None)

    hass = world.hass
    on_calls: list[Any] = []
    coordinator = kit.make_coordinator(hass, kit.make_api(on_calls))
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_refresh = AsyncMock()
    for entry in hass.entries:
        entry.runtime_data = SimpleNamespace(
            coordinator=coordinator, api=coordinator.api
        )
    adders = offer(hass)
    audit = FakeAudit(world.registry)
    with patch.object(
        config_api, "async_get_configuration_api", AsyncMock(return_value=audit)
    ):
        for entry in hass.entries:
            await he.async_setup_self_healing(hass, entry)
    engine = he.async_get_self_healing(hass)
    assert engine is not None and engine.journal is not None
    world.engine = engine
    entities = [
        bound(e, hass) for a, b in adders.values() for e in (*a.added, *b.added)
    ]
    assert len(entities) == 9

    def after_poll(result: Any, n: int) -> None:
        coordinator.data = result
        coordinator.async_update_listeners()
        world.open(f"inc-{n + 1}", router=E1 if n == 0 else E2)
        world.tick()
        for entity in entities:
            _ = entity.available, entity.extra_state_attributes
            _ = (
                entity.is_on
                if isinstance(entity, BinarySensorEntity)
                else entity.native_value
            )

    await kit.full_polls(coordinator, on_poll=after_poll)
    assert on_calls == off_calls and len(on_calls) > 0
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()
    assert coordinator._listeners == {}
    assert engine.counters["records_created"] == 2
    assert audit.types().count("self_healing.action_proposed") == 2
    assert len([t for t, _d in hass.fired if t == hj.EVENT_REMEDIATION]) == 2
    hass.services.async_call.assert_not_called()
    assert hass.data[DATA_SELF_HEALING_ENGINE] is engine
    await he.async_release_self_healing(hass, E1)
    await he.async_release_self_healing(hass, E2)
