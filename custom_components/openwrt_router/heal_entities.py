"""Self-Healing (Phase 7), package K1: read-only entities.

Developer document: ``docs/self-healing.md`` §11.

Fleet (no device, ``unique_id`` ``openwrt_router_fleet_*``; one set per HA
instance, hosted by the smallest loaded entry id):

* ``openwrt_router_fleet_self_healing_mode`` (enum): the mode in force on
  the loaded routers, ``mixed`` when they differ, unknown without one;
* ``openwrt_router_fleet_remediation_active``: records not in an end state;
* ``openwrt_router_fleet_remediation_pending``: records waiting for an
  approval;
* ``openwrt_router_fleet_remediation_succeeded_30d`` /
  ``openwrt_router_fleet_remediation_failed_30d``: repairs that ended in
  the last 30 days, resolved / not resolved after an execution started
  (unknown when the store had to evict a record that may lie in the
  window);
* ``openwrt_router_fleet_remediation_last_result`` (enum): the end state
  of the record that ended last (unknown before the first);
* ``openwrt_router_fleet_auto_heal_enabled`` (binary sensor): Auto-Heal is
  in force on at least one router.

Per router (``unique_id`` ``f"{entry_id}_self_healing_mode"``, diagnostic,
on the router device): the mode in force on that router (enum).

**Read only.** Sensors and binary sensors only: no button, no switch, no
service. Every value is computed from the running engine's memory (its
store's records, settings and loop state); no router call, no disk read,
no store change (the safety time is the one the engine last observed). The
engine is looked up on every read, never kept. The entities write their
state when the engine's journal sends ``SIGNAL_SELF_HEALING`` (after a
transition and on every tick). Without a running engine they are
unavailable.

**Life cycle.** The entries' sensor and binary-sensor platforms offer their
``async_add_entities``; the entities are created once the engine runs
(fleet switch ``self_healing_enabled`` on, the default). Switched off, the
engine stops and the entities are removed from the entity registry, so
nothing is left behind; with the switch off at a start nothing is created.
While the switch is on but the engine is not running yet (a restart),
nothing is removed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from homeassistant.components.binary_sensor import (
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .heal_journal import SIGNAL_SELF_HEALING
from .heal_model import (
    TERMINAL_STATES,
    ActionState,
    HealMode,
    RemediationAction,
    RiskClass,
)

_LOGGER = logging.getLogger(__name__)

S = ActionState

DATA_HEAL_ENTITIES: Final = f"{DOMAIN}_self_healing_entities"
# The window of the two repair counters.
WINDOW_S: Final = 30 * 86400.0

UID_FLEET_MODE: Final = "openwrt_router_fleet_self_healing_mode"
UID_FLEET_ACTIVE: Final = "openwrt_router_fleet_remediation_active"
UID_FLEET_PENDING: Final = "openwrt_router_fleet_remediation_pending"
UID_FLEET_SUCCEEDED_30D: Final = "openwrt_router_fleet_remediation_succeeded_30d"
UID_FLEET_FAILED_30D: Final = "openwrt_router_fleet_remediation_failed_30d"
UID_FLEET_LAST_RESULT: Final = "openwrt_router_fleet_remediation_last_result"
UID_FLEET_AUTO_HEAL: Final = "openwrt_router_fleet_auto_heal_enabled"
SUFFIX_ROUTER_MODE: Final = "self_healing_mode"

MODE_MIXED: Final = "mixed"
FLEET_MODE_OPTIONS: Final = ("observe", "approval", "auto_heal", MODE_MIXED)
ROUTER_MODE_OPTIONS: Final = ("observe", "approval", "auto_heal")
LAST_RESULT_OPTIONS: Final = (
    "resolved",
    "rejected",
    "cancelled",
    "escalated",
    "manual_recovery_required",
    "rolled_back",
)


@dataclass(frozen=True, slots=True)
class _Window:
    """The repairs of the 30-day window (None: not known completely)."""

    succeeded: int | None
    failed: int | None


def _engine(hass: HomeAssistant) -> Any:
    try:
        from .heal_engine import async_get_self_healing

        engine = async_get_self_healing(hass)
    except Exception:  # noqa: BLE001 - no engine: unavailable
        return None
    return engine if engine is not None and getattr(engine, "loaded", False) else None


def _actions(engine: Any) -> list[RemediationAction]:
    actions = getattr(getattr(engine, "store", None), "actions", None)
    if not isinstance(actions, Mapping):
        return []
    return [a for a in actions.values() if isinstance(a, RemediationAction)]


def _ended_at(action: RemediationAction) -> float | None:
    """Wall time of the record's end (its history's last entry)."""
    if action.state not in TERMINAL_STATES or not action.history:
        return None
    last = action.history[-1]
    return float(last.ts) if last.to_state is action.state else None


def _executed(action: RemediationAction) -> bool:
    return any(h.to_state is S.EXECUTING for h in action.history)


def _mode_in_force(engine: Any, router_id: str) -> HealMode | None:
    """The mode in force on a router, from memory only (None: unknown).

    The safety time is the one the engine last observed: reading here never
    moves the store's clock.
    """
    try:
        from . import heal_policy as hp

        store = engine.store
        safe = store.loop.clock.safe
        if safe is None:
            return None
        return hp.effective_mode(
            store.settings.router(router_id).mode,
            module_enabled=engine.module_enabled(),
            held=store.loop.hold_on(router_id, safe) is not None,
            fleet_paused=store.loop.fleet.paused(safe),
            risk=RiskClass.LOW,
        )
    except Exception as err:  # noqa: BLE001 - unknown
        _LOGGER.debug("Self-Healing mode unknown (%s)", type(err).__name__)
        return None


def _loaded_router_ids(engine: Any) -> list[str]:
    out: list[str] = []
    for entry_id in sorted(getattr(engine, "entries", ()) or ()):
        rid = engine.router_id_for_entry(entry_id)
        if isinstance(rid, str):
            out.append(rid)
    return out


def fleet_mode(engine: Any) -> str | None:
    """One mode for the loaded routers, ``mixed`` when they differ."""
    modes: set[str] = set()
    for rid in _loaded_router_ids(engine):
        mode = _mode_in_force(engine, rid)
        if mode is None:
            return None  # one unknown router: the fleet's mode is unknown
        modes.add(mode.value)
    if not modes:
        return None
    return modes.pop() if len(modes) == 1 else MODE_MIXED


def active_count(engine: Any) -> int:
    """Records not in an end state."""
    return sum(1 for a in _actions(engine) if a.state not in TERMINAL_STATES)


def pending_count(engine: Any) -> int:
    """Records waiting for an approval."""
    return sum(1 for a in _actions(engine) if a.state is S.WAITING_APPROVAL)


def window(engine: Any, now: float) -> _Window:
    """Repairs that ended inside the last 30 days.

    Succeeded: ended resolved. Failed: ended in another end state after an
    execution started (a rejected or cancelled proposal is no repair).
    The store evicts the oldest ended records when it is full; once it did,
    the counts are known only if a kept ended record is older than the
    window (every evicted one is older still).
    """
    cutoff = now - WINDOW_S
    succeeded = failed = 0
    older_kept = False
    for action in _actions(engine):
        ended = _ended_at(action)
        if ended is None:
            continue
        if ended < cutoff:
            older_kept = True
            continue
        if action.state is S.RESOLVED:
            succeeded += 1
        elif _executed(action):
            failed += 1
    counters = getattr(engine.store, "counters", None)
    evicted = (
        counters.get("evicted_terminal", 0) if isinstance(counters, Mapping) else 1
    )
    if evicted and not older_kept:
        return _Window(None, None)
    return _Window(succeeded, failed)


def last_result(engine: Any) -> tuple[str | None, dict[str, Any]]:
    """The end state of the record that ended last, with its ids."""
    best: tuple[float, str, RemediationAction] | None = None
    for action in _actions(engine):
        ended = _ended_at(action)
        if ended is None:
            continue
        key = (ended, action.action_id, action)
        if best is None or key[:2] > best[:2]:
            best = key
    if best is None:
        return None, {}
    ended, _id, action = best
    return action.state.value, {
        "action_id": action.action_id,
        "router_id": action.router_id,
        "action_type": action.action_type,
        "incident_type": action.incident_type,
        "ended_at": ended,
    }


def auto_heal_any(engine: Any) -> bool | None:
    """Auto-Heal is in force on at least one known router (None: unknown)."""
    try:
        router_ids = list(engine.router_ids())
    except Exception:  # noqa: BLE001
        return None
    unknown = False
    for rid in router_ids:
        mode = _mode_in_force(engine, rid)
        if mode is HealMode.AUTO_HEAL:
            return True
        unknown = unknown or mode is None
    return None if unknown else False


def router_mode(engine: Any, entry_id: str) -> tuple[str | None, dict[str, Any]]:
    """The mode in force on the entry's router, with what holds it."""
    rid = engine.router_id_for_entry(entry_id)
    if not isinstance(rid, str):
        return None, {}
    mode = _mode_in_force(engine, rid)
    try:
        store = engine.store
        safe = store.loop.clock.safe
        attrs: dict[str, Any] = {
            "router_id": rid,
            "configured_mode": store.settings.router(rid).mode.value,
            "held": None if safe is None else store.loop.hold_on(rid, safe) is not None,
            "fleet_paused": None if safe is None else store.loop.fleet.paused(safe),
            "module_enabled": engine.module_enabled(),
        }
    except Exception:  # noqa: BLE001 - the mode alone
        attrs = {"router_id": rid}
    return (None if mode is None else mode.value), attrs


# --- descriptions -----------------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class HealSensorDescription(SensorEntityDescription):
    """A fleet sensor: its unique id and how it reads the engine."""

    unique_id: str
    value_fn: Callable[[Any, float], int | str | None]
    extra_attrs_fn: Callable[[Any, float], dict[str, Any]] | None = None


@dataclass(frozen=True, kw_only=True)
class HealBinarySensorDescription(BinarySensorEntityDescription):
    """A fleet binary sensor: its unique id and how it reads the engine."""

    unique_id: str
    value_fn: Callable[[Any], bool | None]


def _last_value(engine: Any, _now: float) -> str | None:
    return last_result(engine)[0]


def _last_attrs(engine: Any, _now: float) -> dict[str, Any]:
    return last_result(engine)[1]


def _window_attrs(_engine: Any, _now: float) -> dict[str, Any]:
    return {"window_days": int(WINDOW_S // 86400)}


FLEET_SENSORS: Final[tuple[HealSensorDescription, ...]] = (
    HealSensorDescription(
        key="self_healing_mode",
        translation_key="fleet_self_healing_mode",
        unique_id=UID_FLEET_MODE,
        device_class=SensorDeviceClass.ENUM,
        options=list(FLEET_MODE_OPTIONS),
        value_fn=lambda e, _n: fleet_mode(e),
    ),
    HealSensorDescription(
        key="remediation_active",
        translation_key="fleet_remediation_active",
        unique_id=UID_FLEET_ACTIVE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e, _n: active_count(e),
    ),
    HealSensorDescription(
        key="remediation_pending",
        translation_key="fleet_remediation_pending",
        unique_id=UID_FLEET_PENDING,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e, _n: pending_count(e),
    ),
    HealSensorDescription(
        key="remediation_succeeded_30d",
        translation_key="fleet_remediation_succeeded_30d",
        unique_id=UID_FLEET_SUCCEEDED_30D,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e, n: window(e, n).succeeded,
        extra_attrs_fn=_window_attrs,
    ),
    HealSensorDescription(
        key="remediation_failed_30d",
        translation_key="fleet_remediation_failed_30d",
        unique_id=UID_FLEET_FAILED_30D,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda e, n: window(e, n).failed,
        extra_attrs_fn=_window_attrs,
    ),
    HealSensorDescription(
        key="remediation_last_result",
        translation_key="fleet_remediation_last_result",
        unique_id=UID_FLEET_LAST_RESULT,
        device_class=SensorDeviceClass.ENUM,
        options=list(LAST_RESULT_OPTIONS),
        value_fn=_last_value,
        extra_attrs_fn=_last_attrs,
    ),
)
FLEET_BINARY_SENSORS: Final[tuple[HealBinarySensorDescription, ...]] = (
    HealBinarySensorDescription(
        key="auto_heal_enabled",
        translation_key="fleet_auto_heal_enabled",
        unique_id=UID_FLEET_AUTO_HEAL,
        value_fn=auto_heal_any,
    ),
)
ROUTER_MODE_SENSOR: Final = SensorEntityDescription(
    key=SUFFIX_ROUTER_MODE,
    translation_key="self_healing_mode",
    device_class=SensorDeviceClass.ENUM,
    options=list(ROUTER_MODE_OPTIONS),
    entity_category=EntityCategory.DIAGNOSTIC,
)
FLEET_UNIQUE_IDS: Final = tuple(d.unique_id for d in FLEET_SENSORS) + tuple(
    d.unique_id for d in FLEET_BINARY_SENSORS
)


def router_unique_id(entry_id: str) -> str:
    """The unique id of a router's mode sensor."""
    return f"{entry_id}_{SUFFIX_ROUTER_MODE}"


# --- entities ---------------------------------------------------------------------------


class _HealEntity:
    """Pushed by the journal's signal, never polled; reads the engine."""

    hass: HomeAssistant
    _attr_has_entity_name = True
    _attr_should_poll = False

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()  # type: ignore[misc]
        self.async_on_remove(  # type: ignore[attr-defined]
            async_dispatcher_connect(
                self.hass, SIGNAL_SELF_HEALING, self._handle_update
            )
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()  # type: ignore[attr-defined]

    @property
    def _heal(self) -> Any:
        return _engine(self.hass)

    @property
    def available(self) -> bool:
        return self._heal is not None


class HealFleetSensor(_HealEntity, SensorEntity):
    """One fleet number or state of Self-Healing."""

    entity_description: HealSensorDescription
    _unrecorded_attributes = frozenset(
        {"action_id", "action_type", "ended_at", "incident_type", "router_id"}
    )

    def __init__(self, description: HealSensorDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    def _now(self, engine: Any) -> float:
        return float(engine.clock())

    @property
    def native_value(self) -> int | str | None:
        engine = self._heal
        if engine is None:
            return None
        try:
            return self.entity_description.value_fn(engine, self._now(engine))
        except Exception as err:  # noqa: BLE001 - unknown, never a made-up value
            _LOGGER.debug("Self-Healing sensor unknown (%s)", type(err).__name__)
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        engine = self._heal
        attrs = self.entity_description.extra_attrs_fn
        if engine is None or attrs is None:
            return None
        try:
            return attrs(engine, self._now(engine))
        except Exception:  # noqa: BLE001
            return None


class HealFleetBinarySensor(_HealEntity, BinarySensorEntity):
    """Auto-Heal in force on any router (read only)."""

    entity_description: HealBinarySensorDescription

    def __init__(self, description: HealBinarySensorDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    @property
    def is_on(self) -> bool | None:
        engine = self._heal
        if engine is None:
            return None
        try:
            return self.entity_description.value_fn(engine)
        except Exception:  # noqa: BLE001 - unknown
            return None


class HealRouterModeSensor(_HealEntity, SensorEntity):
    """The mode in force on one router (diagnostic, on its device)."""

    _unrecorded_attributes = frozenset(
        {"configured_mode", "fleet_paused", "held", "module_enabled", "router_id"}
    )

    def __init__(self, entry_id: str) -> None:
        self.entity_description = ROUTER_MODE_SENSOR
        self._entry_id = entry_id
        self._attr_unique_id = router_unique_id(entry_id)
        self._attr_translation_key = ROUTER_MODE_SENSOR.translation_key
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    @property
    def native_value(self) -> str | None:
        engine = self._heal
        if engine is None:
            return None
        try:
            return router_mode(engine, self._entry_id)[0]
        except Exception:  # noqa: BLE001 - unknown
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        engine = self._heal
        if engine is None:
            return None
        try:
            return router_mode(engine, self._entry_id)[1]
        except Exception:  # noqa: BLE001
            return None


# --- hosting ----------------------------------------------------------------------------

PLATFORM_SENSOR: Final = "sensor"
PLATFORM_BINARY: Final = "binary_sensor"


@dataclass(slots=True)
class _Platform:
    """The entries' platform of one kind offering to host entities."""

    adders: dict[str, AddEntitiesCallback] = field(default_factory=dict)
    anchor: str | None = None  # the entry hosting the fleet entities
    routers: set[str] = field(default_factory=set)  # entries with their sensor


@dataclass(slots=True)
class _Hosts:
    sensor: _Platform = field(default_factory=_Platform)
    binary: _Platform = field(default_factory=_Platform)


def _hosts(hass: HomeAssistant) -> _Hosts:
    hosts = hass.data.get(DATA_HEAL_ENTITIES)
    if not isinstance(hosts, _Hosts):
        hosts = _Hosts()
        hass.data[DATA_HEAL_ENTITIES] = hosts
    return hosts


def _switch_on(hass: HomeAssistant) -> bool:
    try:
        from .heal_engine import self_healing_enabled

        return self_healing_enabled(hass)
    except Exception:  # noqa: BLE001 - unknown: keep what exists
        return True


@callback
def async_setup_heal_sensors(
    hass: HomeAssistant, entry: Any, async_add_entities: AddEntitiesCallback
) -> None:
    """The entry's sensor platform offers to host Self-Healing sensors."""
    _hosts(hass).sensor.adders[entry.entry_id] = async_add_entities
    async_sync_heal_entities(hass)


@callback
def async_setup_heal_binary_sensors(
    hass: HomeAssistant, entry: Any, async_add_entities: AddEntitiesCallback
) -> None:
    """The entry's binary-sensor platform offers to host the fleet one."""
    _hosts(hass).binary.adders[entry.entry_id] = async_add_entities
    async_sync_heal_entities(hass)


@callback
def async_sync_heal_entities(hass: HomeAssistant) -> None:
    """Create the entities while the engine runs; remove them once the
    switch is off. Engine not running with the switch on: nothing."""
    if _engine(hass) is None:
        if not _switch_on(hass):
            async_remove_heal_entities(hass)
        return
    hosts = _hosts(hass)
    _host_fleet(hosts.sensor, lambda: [HealFleetSensor(d) for d in FLEET_SENSORS])
    _host_fleet(
        hosts.binary, lambda: [HealFleetBinarySensor(d) for d in FLEET_BINARY_SENSORS]
    )
    for entry_id, adder in sorted(hosts.sensor.adders.items()):
        if entry_id in hosts.sensor.routers:
            continue
        hosts.sensor.routers.add(entry_id)
        adder([HealRouterModeSensor(entry_id)])


def _host_fleet(platform: _Platform, build: Callable[[], Iterable[Any]]) -> None:
    if platform.anchor is not None and platform.anchor in platform.adders:
        return
    platform.anchor = None
    if not platform.adders:
        return
    anchor = min(platform.adders)
    platform.anchor = anchor
    platform.adders[anchor](list(build()))


@callback
def async_remove_heal_entities(hass: HomeAssistant) -> None:
    """The switch is off: drop every Self-Healing entity from the entity
    registry (live ones are removed by Home Assistant)."""
    hosts = _hosts(hass)
    entry_ids = set(hosts.sensor.adders)
    for platform in (hosts.sensor, hosts.binary):
        platform.anchor = None
        platform.routers.clear()
    if er.DATA_REGISTRY not in hass.data:
        return  # no registry (tests, shutdown); never create one here
    try:
        registry = er.async_get(hass)
        entries = hass.config_entries.async_entries(DOMAIN)
        if isinstance(entries, list):
            entry_ids |= {e.entry_id for e in entries}
    except Exception:  # noqa: BLE001
        return
    wanted = [("sensor", d.unique_id) for d in FLEET_SENSORS]
    wanted += [("binary_sensor", d.unique_id) for d in FLEET_BINARY_SENSORS]
    wanted += [("sensor", router_unique_id(e)) for e in sorted(entry_ids)]
    for domain, unique_id in wanted:
        entity_id = registry.async_get_entity_id(domain, DOMAIN, unique_id)
        if entity_id is not None:
            registry.async_remove(entity_id)


@callback
def async_entry_unloaded(hass: HomeAssistant, entry_id: str, *, last: bool) -> None:
    """The entry is unloaded (its platforms are gone): move the host.

    ``last``: no entry is left; the registry entries stay for the next
    start (the switch decides then).
    """
    hosts = hass.data.get(DATA_HEAL_ENTITIES)
    if not isinstance(hosts, _Hosts):
        return  # nothing was offered: nothing to move
    for platform in (hosts.sensor, hosts.binary):
        platform.adders.pop(entry_id, None)
        platform.routers.discard(entry_id)
        if platform.anchor == entry_id:
            platform.anchor = None
    if last:
        hass.data.pop(DATA_HEAL_ENTITIES, None)
        return
    if _engine(hass) is not None:
        # only a running engine's entities move; an unload never removes
        async_sync_heal_entities(hass)


__all__ = [
    "FLEET_BINARY_SENSORS",
    "FLEET_MODE_OPTIONS",
    "FLEET_SENSORS",
    "FLEET_UNIQUE_IDS",
    "LAST_RESULT_OPTIONS",
    "ROUTER_MODE_OPTIONS",
    "ROUTER_MODE_SENSOR",
    "WINDOW_S",
    "HealBinarySensorDescription",
    "HealFleetBinarySensor",
    "HealFleetSensor",
    "HealRouterModeSensor",
    "HealSensorDescription",
    "active_count",
    "async_entry_unloaded",
    "async_remove_heal_entities",
    "async_setup_heal_binary_sensors",
    "async_setup_heal_sensors",
    "async_sync_heal_entities",
    "auto_heal_any",
    "fleet_mode",
    "last_result",
    "pending_count",
    "router_mode",
    "router_unique_id",
    "window",
]
