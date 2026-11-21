"""Entities of WiFi RF Intelligence (release 1.48.0, part 2).

Named wifi_rf_* (not rf_*): the rf_* modules are the pure RF layer with
its own source contract (tests/test_rf_core_contract.py); this one is Home
Assistant entity wiring like diag_entities and security_entities.

A fixed, bounded set; never one entity per client or per foreign network:

* three fleet sensors (no device, ``unique_id`` ``openwrt_router_fleet_
  wifi_rf_*``): WiFi health score, active roaming problems and channel
  optimisation recommendations (count);
* per router with RF on, only on its existing device: AP RF health;
* per radio of such a router, for at most ``WIFI_RF_RADIO_ENTITIES_MAX``
  radios (sorted by UCI name): channel utilization, noise floor and retry
  rate.

So N routers give at most 3 + N * (1 + 3 * WIFI_RF_RADIO_ENTITIES_MAX).

DECIDED: no airtime utilization sensor. The only airtime figure is
hostapd's ``airtime.time_busy / time``, the very counter channel
utilization is computed from; a second sensor would repeat the same
measurement under another name.

Unknown stays unknown: a value without a fresh measurement (not read, no
data, unsupported, unreachable, stale) or a rating while the module is
not ready is ``None`` (state unknown), never 0 or 100. The attributes name
the source and the capability state, never a MAC, SSID, BSSID or router
id.

RF off (default, per router): the entities are **not created**, and
switching RF off removes them from the entity registry (like the network
diagnostics and the Security Center). Switching it on creates them after
the next poll (no reload). An error here never fails an entry's setup.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, SIGNAL_STRENGTH_DECIBELS_MILLIWATT
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_platform
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import (
    DATA_WIFI_RF_ENTITIES,
    DOMAIN,
    OPTION_WIFI_RF_ENABLED,
    SIGNAL_WIFI_RF,
    UID_FLEET_WIFI_RF_HEALTH,
    UID_FLEET_WIFI_RF_RECOMMENDATIONS,
    UID_FLEET_WIFI_RF_ROAMING,
    WIFI_RF_RADIO_ENTITIES_MAX,
    WIFI_RF_UID_INFIX,
)
from .rf_client_link import history_of, roaming_problems
from .rf_models import CapabilityState

_LOGGER = logging.getLogger(__name__)

SENSOR_DOMAIN = "sensor"
STATUS_READY = "ready"
SOURCE_RF = "wifi_rf"
AP_HEALTH_UID = "ap_health"


def _center(hass: HomeAssistant) -> Any:
    try:
        from .rf_center import async_get_rf_center
    except Exception:  # noqa: BLE001 - module not importable: unavailable
        return None
    return async_get_rf_center(hass)


def _ready(center: Any) -> bool:
    return center is not None and center.enabled and center.status == STATUS_READY


def _withheld(center: Any) -> list[str]:
    if center is None or not center.enabled:
        return ["off"]
    return list(center.not_ready_reasons()) or ([] if _ready(center) else ["no_data"])


def _router_id(center: Any, entry_id: str) -> str | None:
    state = center.routers.get(entry_id) if center is not None else None
    if state is None or not state.options.enabled:
        return None
    return state.router_id


def _results(center: Any, router_id: str) -> list[Any]:
    return sorted(
        (r for r in center.results.values() if r.ref.router_id == router_id),
        key=lambda r: r.ref.radio_id,
    )


def entity_radios(center: Any, router_id: str) -> list[str]:
    """Radios of a router that get entities (sorted, at most the cap)."""
    return [r.ref.radio_id for r in _results(center, router_id)][
        :WIFI_RF_RADIO_ENTITIES_MAX
    ]


# --- fleet ------------------------------------------------------------------------


def _health_value(center: Any) -> tuple[int | None, dict[str, Any]]:
    network = center.fleet.network if _ready(center) else None
    if network is None:
        return None, {
            "grade": "unknown",
            "coverage": None,
            "withheld": _withheld(center) or ["no_evaluation"],
            "source": SOURCE_RF,
        }
    return network.score, {
        "grade": network.grade,
        "coverage": network.coverage,
        "capped": network.capped,
        "withheld": [],
        "source": SOURCE_RF,
    }


def _roaming_value(hass: HomeAssistant, center: Any) -> tuple[int | None, dict]:
    if not _ready(center):
        return None, {"withheld": _withheld(center), "source": "client_history"}
    macs = sorted({m for r in center.results.values() for m in r.client_macs})
    found = roaming_problems(center, history_of(hass), macs, center.clock())
    attrs = found.as_dict()
    if found.count is None:
        attrs["withheld"] = ["no_client_history"]
    return found.count, attrs


def _recommendation_value(center: Any) -> tuple[int | None, dict[str, Any]]:
    if not _ready(center):
        return None, {"withheld": _withheld(center), "source": SOURCE_RF}
    recs = center.fleet.recommendations
    kinds: dict[str, int] = {}
    for rec in recs:
        kinds[rec.kind] = kinds.get(rec.kind, 0) + 1
    return len(recs), {"kinds": kinds, "source": SOURCE_RF}


@dataclass(frozen=True, kw_only=True)
class RfFleetDescription(SensorEntityDescription):
    """A fleet sensor: unique id and how it reads the center."""

    unique_id: str
    value_fn: Callable[[HomeAssistant, Any], tuple[int | None, dict[str, Any]]]


FLEET_SENSORS: tuple[RfFleetDescription, ...] = (
    RfFleetDescription(
        key="wifi_rf_health_score",
        translation_key="fleet_wifi_rf_health_score",
        unique_id=UID_FLEET_WIFI_RF_HEALTH,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda _hass, center: _health_value(center),
    ),
    RfFleetDescription(
        key="wifi_rf_roaming_problems",
        translation_key="fleet_wifi_rf_roaming_problems",
        unique_id=UID_FLEET_WIFI_RF_ROAMING,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=_roaming_value,
    ),
    RfFleetDescription(
        key="wifi_rf_recommendations",
        translation_key="fleet_wifi_rf_recommendations",
        unique_id=UID_FLEET_WIFI_RF_RECOMMENDATIONS,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda _hass, center: _recommendation_value(center),
    ),
)
RF_FLEET_UNIQUE_IDS: tuple[str, ...] = tuple(d.unique_id for d in FLEET_SENSORS)


class _RfEntity:
    """Pushed by SIGNAL_WIFI_RF; no polling, no network."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    hass: HomeAssistant

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()  # type: ignore[misc]
        self.async_on_remove(  # type: ignore[attr-defined]
            async_dispatcher_connect(self.hass, SIGNAL_WIFI_RF, self._handle_update)
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()  # type: ignore[attr-defined]


class RfFleetSensor(_RfEntity, SensorEntity):
    """One fleet number of WiFi RF Intelligence."""

    entity_description: RfFleetDescription
    _unrecorded_attributes = frozenset(
        {
            "capped",
            "clients_checked",
            "coverage",
            "flapping_clients",
            "grade",
            "kinds",
            "poor_roaming_clients",
            "roams",
            "source",
            "withheld",
        }
    )

    def __init__(self, description: RfFleetDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    def _read(self) -> tuple[int | None, dict[str, Any]] | None:
        center = _center(self.hass)
        if center is None or not center.enabled:
            return None
        try:
            return self.entity_description.value_fn(self.hass, center)
        except Exception as err:  # noqa: BLE001 - unknown, never a value
            _LOGGER.debug("WiFi RF sensor failed (%s)", type(err).__name__)
            return None, {"withheld": ["error"]}

    @property
    def available(self) -> bool:
        return self._read() is not None

    @property
    def native_value(self) -> int | None:
        found = self._read()
        return None if found is None else found[0]

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        found = self._read()
        return None if found is None else found[1]


# --- per router and radio -------------------------------------------------------------


def ap_health_unique_id(entry_id: str) -> str:
    """Unique id of a router's AP RF health sensor."""
    return f"{entry_id}{WIFI_RF_UID_INFIX}{AP_HEALTH_UID}"


def radio_unique_id(entry_id: str, radio_id: str, metric: str) -> str:
    """Unique id of one radio sensor (stable UCI radio name)."""
    return f"{entry_id}{WIFI_RF_UID_INFIX}{radio_id}_{metric}"


class _RouterEntity(_RfEntity):
    def __init__(self, entry_id: str) -> None:
        self._entry_id = entry_id
        # the router's existing device (checked before creation)
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    def _router(self) -> tuple[Any, str] | None:
        center = _center(self.hass)
        router_id = _router_id(center, self._entry_id)
        return None if router_id is None else (center, router_id)


class RfApHealthSensor(_RouterEntity, SensorEntity):
    """RF health of one AP (all its radios)."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_translation_key = "wifi_rf_ap_health"
    _unrecorded_attributes = frozenset(
        {"capped", "coverage", "grade", "radios", "source", "withheld"}
    )

    def __init__(self, entry_id: str) -> None:
        super().__init__(entry_id)
        self._attr_unique_id = ap_health_unique_id(entry_id)

    @property
    def available(self) -> bool:
        return self._router() is not None

    def _health(self) -> Any:
        found = self._router()
        if found is None or not _ready(found[0]):
            return None
        return found[0].fleet.ap_health.get(found[1])

    @property
    def native_value(self) -> int | None:
        health = self._health()
        return None if health is None else health.score

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        found = self._router()
        if found is None:
            return None
        health = self._health()
        radios = len(_results(*found))
        if health is None:
            return {
                "grade": "unknown",
                "coverage": None,
                "withheld": _withheld(found[0]) or ["no_evaluation"],
                "radios": radios,
                "source": SOURCE_RF,
            }
        return {
            "grade": health.grade,
            "coverage": health.coverage,
            "capped": health.capped,
            "withheld": [],
            "radios": radios,
            "source": SOURCE_RF,
        }


@dataclass(frozen=True, kw_only=True)
class RfRadioDescription(SensorEntityDescription):
    """A radio sensor: which metric and how it becomes the state."""

    metric: str
    scale: float = 1.0
    digits: int = 1


RADIO_SENSORS: tuple[RfRadioDescription, ...] = (
    RfRadioDescription(
        key="utilization",
        translation_key="wifi_rf_channel_utilization",
        metric="utilization",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=0,
    ),
    RfRadioDescription(
        key="noise",
        translation_key="wifi_rf_noise_floor",
        metric="noise",
        device_class=SensorDeviceClass.SIGNAL_STRENGTH,
        native_unit_of_measurement=SIGNAL_STRENGTH_DECIBELS_MILLIWATT,
        state_class=SensorStateClass.MEASUREMENT,
        digits=0,
    ),
    RfRadioDescription(
        key="retry_rate",
        translation_key="wifi_rf_retry_rate",
        metric="retry_rate",
        native_unit_of_measurement=PERCENTAGE,
        state_class=SensorStateClass.MEASUREMENT,
        suggested_display_precision=1,
        scale=100.0,  # retries per sent packet -> percent
    ),
)


class RfRadioSensor(_RouterEntity, SensorEntity):
    """One measured figure of one radio (fresh measurement only)."""

    entity_description: RfRadioDescription
    _unrecorded_attributes = frozenset({"band", "measured_at", "source", "state"})

    def __init__(
        self, entry_id: str, radio_id: str, description: RfRadioDescription
    ) -> None:
        super().__init__(entry_id)
        self.entity_description = description
        self._radio_id = radio_id
        self._attr_unique_id = radio_unique_id(entry_id, radio_id, description.key)
        self._attr_translation_key = description.translation_key
        self._attr_translation_placeholders = {"radio": radio_id}

    def _result(self) -> Any:
        found = self._router()
        if found is None:
            return None
        return next(
            (r for r in _results(*found) if r.ref.radio_id == self._radio_id), None
        )

    def _metric(self) -> Any:
        result = self._result()
        return (
            None
            if result is None
            else result.metrics.get(self.entity_description.metric)
        )

    @property
    def available(self) -> bool:
        return self._result() is not None

    @property
    def native_value(self) -> float | None:
        metric = self._metric()
        if metric is None or metric.state is not CapabilityState.MEASURED:
            return None  # unknown, stale or not read: never 0
        value = metric.value
        if isinstance(value, bool) or not isinstance(value, int | float):
            return None
        desc = self.entity_description
        return round(float(value) * desc.scale, desc.digits)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        result = self._result()
        if result is None:
            return None
        metric = result.metrics.get(self.entity_description.metric)
        return {
            "band": result.radio.band,
            "state": "not_assessed" if metric is None else metric.state.value,
            "source": None if metric is None else metric.source,
            "measured_at": None if metric is None else metric.measured_at,
        }


# --- hosting --------------------------------------------------------------------------


@dataclass(slots=True)
class _Hosts:
    """What is created where (entry ids and unique ids only)."""

    anchor: str | None = None
    created: dict[str, set[str]] = field(default_factory=dict)
    unsub: Callable[[], None] | None = None
    syncing: bool = False


def _hosts(hass: HomeAssistant) -> _Hosts:
    hosts = hass.data.get(DATA_WIFI_RF_ENTITIES)
    if not isinstance(hosts, _Hosts):
        hosts = _Hosts()
        hass.data[DATA_WIFI_RF_ENTITIES] = hosts
    return hosts


def _default_platforms(hass: HomeAssistant) -> list[Any]:
    return list(entity_platform.async_get_platforms(hass, DOMAIN))


# Test seam: the loaded entity platforms of this integration.
platforms_of: Callable[[HomeAssistant], list[Any]] = _default_platforms


def _sensor_platforms(hass: HomeAssistant) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for platform in platforms_of(hass):
        entry = getattr(platform, "config_entry", None)
        entry_id = getattr(entry, "entry_id", None)
        if getattr(platform, "domain", None) == SENSOR_DOMAIN and isinstance(
            entry_id, str
        ):
            out[entry_id] = platform
    return out


def _device_exists(hass: HomeAssistant, entry_id: str) -> bool:
    """The router's own device ``(DOMAIN, entry_id)`` exists (read only)."""
    identifier = (DOMAIN, entry_id)
    try:
        devices = dr.async_get(hass)
        by_identifier = getattr(devices, "async_get_device_by_identifier", None)
        if by_identifier is not None:
            return by_identifier(identifier, entry_id) is not None
        return devices.async_get_device(identifiers={identifier}) is not None
    except Exception:  # noqa: BLE001 - no registry: create nothing
        return False


def _router_entities(center: Any, entry_id: str, router_id: str) -> dict[str, Any]:
    """Unique id -> entity of one router (AP health and capped radios)."""
    out: dict[str, Any] = {ap_health_unique_id(entry_id): RfApHealthSensor}
    for radio_id in entity_radios(center, router_id):
        for desc in RADIO_SENSORS:
            out[radio_unique_id(entry_id, radio_id, desc.key)] = (radio_id, desc)
    return out


def _build(entry_id: str, spec: Any) -> Any:
    if spec is RfApHealthSensor:
        return RfApHealthSensor(entry_id)
    radio_id, desc = spec
    return RfRadioSensor(entry_id, radio_id, desc)


def _wanted(hass: HomeAssistant, center: Any) -> dict[str, dict[str, Any]]:
    """Entry -> missing entities (RF on, device exists, platform loaded)."""
    hosts = _hosts(hass)
    sensors = _sensor_platforms(hass)
    out: dict[str, dict[str, Any]] = {}
    for entry_id in sorted(center.routers):
        router_id = _router_id(center, entry_id)
        if router_id is None or entry_id not in sensors:
            continue
        done = hosts.created.get(entry_id, set())
        missing = {
            uid: spec
            for uid, spec in _router_entities(center, entry_id, router_id).items()
            if uid not in done
        }
        if missing and _device_exists(hass, entry_id):
            out[entry_id] = missing
    return out


def _entry_switches(hass: HomeAssistant) -> dict[str, bool] | None:
    """Entry -> ``wifi_rf_enabled`` of every config entry of the domain.

    Read from the options of all entries, not only the ones already set up
    (read only; None when the entries cannot be listed).
    """
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
        return {
            e.entry_id: isinstance(opts := getattr(e, "options", None), Mapping)
            and opts.get(OPTION_WIFI_RF_ENABLED) is True
            for e in entries
            if isinstance(getattr(e, "entry_id", None), str)
        }
    except Exception:  # noqa: BLE001 - unknown: remove nothing
        return None


async def async_sync_rf_entities(hass: HomeAssistant) -> None:
    """Create the set for routers with RF on; remove it where RF is off.

    Before the center has read its store nothing happens (a restart must
    not drop the registry entries of a module that is on).
    """
    center = _center(hass)
    if center is None or not getattr(center, "loaded", False):
        return
    hosts = _hosts(hass)
    if hosts.unsub is None:

        @callback
        def _receiver() -> None:
            # @callback: HA runs it on the loop (a lambda is an executor job)
            _on_update(hass)

        hosts.unsub = async_dispatcher_connect(hass, SIGNAL_WIFI_RF, _receiver)
    for entry_id in list(hosts.created):
        if _router_id(center, entry_id) is None:
            hosts.created.pop(entry_id, None)
            _remove_router(hass, entry_id)
    if not center.enabled:
        hosts.anchor = None
        hosts.created.clear()
        switches = _entry_switches(hass)
        if switches is None:
            return  # entries unknown: remove nothing
        if not any(switches.values()):
            _remove_all(hass)
            return
        # 1.49.3: the center only knows the entries set up so far; an entry
        # with RF on that is set up later keeps its entries (and the fleet set).
        for entry_id, on in switches.items():
            if not on:
                _remove_router(hass, entry_id)
        return
    sensors = _sensor_platforms(hass)
    if sensors and (hosts.anchor is None or hosts.anchor not in sensors):
        anchor = min(sensors)
        hosts.anchor = anchor
        await sensors[anchor].async_add_entities(
            [RfFleetSensor(d) for d in FLEET_SENSORS]
        )
    for entry_id, missing in _wanted(hass, center).items():
        hosts.created.setdefault(entry_id, set()).update(missing)
        await sensors[entry_id].async_add_entities(
            [_build(entry_id, spec) for spec in missing.values()]
        )


def _needs_sync(hass: HomeAssistant, center: Any, hosts: _Hosts) -> bool:
    if not center.enabled:
        return hosts.anchor is not None or bool(hosts.created)
    if hosts.anchor is None and _sensor_platforms(hass):
        return True
    if any(_router_id(center, e) is None for e in hosts.created):
        return True
    return bool(_wanted(hass, center))


@callback
def _on_update(hass: HomeAssistant) -> None:
    """After an evaluation: create what is missing, remove what is off."""
    hosts = hass.data.get(DATA_WIFI_RF_ENTITIES)
    center = _center(hass)
    if not isinstance(hosts, _Hosts) or center is None or hosts.syncing:
        return
    try:
        if not _needs_sync(hass, center, hosts):
            return
    except Exception as err:  # noqa: BLE001 - next update tries again
        _LOGGER.debug("WiFi RF entity check failed (%s)", type(err).__name__)
        return
    hosts.syncing = True

    async def run() -> None:
        try:
            await async_sync_rf_entities(hass)
        except Exception as err:  # noqa: BLE001 - next update tries again
            _LOGGER.warning("WiFi RF entities not updated (%s)", type(err).__name__)
        finally:
            hosts.syncing = False

    job = run()
    try:
        hass.async_create_task(job, name="openwrt_router wifi rf entities")
    except Exception:
        hosts.syncing = False  # never stuck: the next signal tries again
        job.close()
        raise


def _registry(hass: HomeAssistant) -> Any:
    try:
        registry = er.async_get(hass)
    except Exception:  # noqa: BLE001 - no registry (tests, shutdown)
        return None
    return registry if getattr(registry, "entities", None) is not None else None


def _remove_router(hass: HomeAssistant, entry_id: str) -> None:
    """RF off on one router: drop its entities (HA removes live ones)."""
    registry = _registry(hass)
    if registry is None:
        return
    prefix = f"{entry_id}{WIFI_RF_UID_INFIX}"
    for entity in list(registry.entities.values()):
        if (
            entity.platform == DOMAIN
            and entity.domain == SENSOR_DOMAIN
            and isinstance(entity.unique_id, str)
            and entity.unique_id.startswith(prefix)
        ):
            registry.async_remove(entity.entity_id)


def _remove_all(hass: HomeAssistant) -> None:
    """RF off everywhere: drop the fleet set and every router's entities."""
    registry = _registry(hass)
    if registry is None:
        return
    for unique_id in RF_FLEET_UNIQUE_IDS:
        entity_id = registry.async_get_entity_id(SENSOR_DOMAIN, DOMAIN, unique_id)
        if entity_id is not None:
            registry.async_remove(entity_id)
    for entity in list(registry.entities.values()):
        if (
            entity.platform == DOMAIN
            and entity.domain == SENSOR_DOMAIN
            and isinstance(entity.unique_id, str)
            and WIFI_RF_UID_INFIX in entity.unique_id
        ):
            registry.async_remove(entity.entity_id)


async def async_entry_released(
    hass: HomeAssistant, entry_id: str, *, last: bool
) -> None:
    """The entry is unloaded (its platforms are gone): move the fleet host.

    ``last``: no entry is left; the registry entries stay for the next
    start (the router's RF switch decides then).
    """
    hosts = hass.data.get(DATA_WIFI_RF_ENTITIES)
    if not isinstance(hosts, _Hosts):
        return
    hosts.created.pop(entry_id, None)
    if last:
        if hosts.unsub is not None:
            hosts.unsub()
        hass.data.pop(DATA_WIFI_RF_ENTITIES, None)
        return
    if hosts.anchor == entry_id:
        hosts.anchor = None
        await async_sync_rf_entities(hass)


__all__ = [
    "FLEET_SENSORS",
    "RADIO_SENSORS",
    "RF_FLEET_UNIQUE_IDS",
    "RfApHealthSensor",
    "RfFleetSensor",
    "RfRadioSensor",
    "ap_health_unique_id",
    "async_entry_released",
    "async_sync_rf_entities",
    "entity_radios",
    "platforms_of",
    "radio_unique_id",
]
