"""Entities of the network diagnostics (release 1.47.0, part 2).

A fixed, bounded set; never one entity per target or per probe:

* six fleet sensors (no device, ``unique_id``
  ``openwrt_router_fleet_diag_*``), one set per HA instance: network quality
  score, monitoring coverage, active diagnostics findings, HA -> internet
  latency, HA -> internet loss (24 h) and DNS response time;
* one connectivity binary sensor per router ("gateway reachable"), only on
  a router device that already exists (no new device is created) and only
  once the router's core id is known.

So N routers give at most 6 + N entities.

Every value comes from the module's entity view (``NetDiagnostics.view``,
rebuilt after each poll and HA round) and is pushed with
``SIGNAL_NET_DIAGNOSTICS``; nothing here talks to a router or probes.
Unknown stays unknown: a value the module has no data for is ``None``,
never a healthy value. The gateway sensor is ``on`` / ``off`` only from a
DIRECT gateway-stage measurement; the passive poll knows the next hop but
not whether it answers, so it stays unknown (reason ``not_measured``).

Module off (default): the entities are **not created**, and switching the
module off removes them from the entity registry (like the Security Center
sensors). Switching it on creates them at once (no reload).

Host: the entity platforms of the loaded entries (``entity_platform.
async_get_platforms``; the platform files are not wrapped once more). The
smallest entry id hosts the fleet set; each router entry's own
binary_sensor platform hosts its gateway sensor.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_platform
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import (
    DATA_DIAG_ENTITIES,
    DIAG_GATEWAY_UID_SUFFIX,
    DOMAIN,
    SIGNAL_NET_DIAGNOSTICS,
    UID_FLEET_DIAG_COVERAGE,
    UID_FLEET_DIAG_DNS,
    UID_FLEET_DIAG_FINDINGS,
    UID_FLEET_DIAG_LATENCY,
    UID_FLEET_DIAG_LOSS,
    UID_FLEET_DIAG_SCORE,
)

_LOGGER = logging.getLogger(__name__)

type _View = Mapping[str, Any]

SENSOR_DOMAIN = "sensor"
BINARY_SENSOR_DOMAIN = "binary_sensor"


@dataclass(frozen=True, kw_only=True)
class DiagSensorDescription(SensorEntityDescription):
    """A fleet sensor: its unique id and how it reads the view."""

    unique_id: str
    value_fn: Callable[[_View], float | int | None]
    extra_attrs_fn: Callable[[_View], dict[str, Any]] | None = None


def _num(view: _View, key: str) -> float | None:
    value = view.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return value


def _int(view: _View, key: str) -> int | None:
    value = _num(view, key)
    return None if value is None else round(value)


def _score_attrs(view: _View) -> dict[str, Any]:
    # always both: a score without its coverage and confidence misleads
    return {
        "coverage": view.get("score_coverage"),
        "low_confidence": view.get("low_confidence") is not False,
        "routers": view.get("routers"),
        "routers_scored": view.get("routers_scored"),
        "routers_unknown": view.get("routers_unknown"),
    }


def _coverage_attrs(view: _View) -> dict[str, Any]:
    return {
        "routers": view.get("routers"),
        "routers_unknown": view.get("routers_unknown"),
    }


def _findings_attrs(view: _View) -> dict[str, Any]:
    by_class = view.get("findings_by_classification")
    return {
        "classifications": dict(by_class) if isinstance(by_class, Mapping) else {},
        "ha_state": view.get("ha_state"),
    }


def _measured_attrs(view: _View) -> dict[str, Any]:
    return {"measured_at": view.get("ha_measured_at")}


def _loss_attrs(view: _View) -> dict[str, Any]:
    return {"window": "24h"}


SENSORS: tuple[DiagSensorDescription, ...] = (
    DiagSensorDescription(
        key="diag_quality_score",
        translation_key="fleet_diag_quality_score",
        unique_id=UID_FLEET_DIAG_SCORE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "score"),
        extra_attrs_fn=_score_attrs,
    ),
    DiagSensorDescription(
        key="diag_monitoring_coverage",
        translation_key="fleet_diag_monitoring_coverage",
        unique_id=UID_FLEET_DIAG_COVERAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: _int(v, "coverage"),
        extra_attrs_fn=_coverage_attrs,
    ),
    DiagSensorDescription(
        key="diag_findings_active",
        translation_key="fleet_diag_findings_active",
        unique_id=UID_FLEET_DIAG_FINDINGS,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "findings_active"),
        extra_attrs_fn=_findings_attrs,
    ),
    DiagSensorDescription(
        key="diag_ha_internet_latency",
        translation_key="fleet_diag_ha_internet_latency",
        unique_id=UID_FLEET_DIAG_LATENCY,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTime.MILLISECONDS,
        suggested_display_precision=1,
        value_fn=lambda v: _num(v, "ha_latency_ms"),
        extra_attrs_fn=_measured_attrs,
    ),
    DiagSensorDescription(
        key="diag_ha_internet_loss",
        translation_key="fleet_diag_ha_internet_loss",
        unique_id=UID_FLEET_DIAG_LOSS,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=1,
        value_fn=lambda v: _num(v, "ha_loss_pct"),
        extra_attrs_fn=_loss_attrs,
    ),
    DiagSensorDescription(
        key="diag_dns_response_time",
        translation_key="fleet_diag_dns_response_time",
        unique_id=UID_FLEET_DIAG_DNS,
        device_class=SensorDeviceClass.DURATION,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=UnitOfTime.MILLISECONDS,
        suggested_display_precision=1,
        value_fn=lambda v: _num(v, "dns_ms"),
        extra_attrs_fn=_measured_attrs,
    ),
)
DIAG_FLEET_UNIQUE_IDS: tuple[str, ...] = tuple(d.unique_id for d in SENSORS)
GATEWAY_TRANSLATION_KEY = "diag_gateway_reachable"


def gateway_unique_id(entry_id: str) -> str:
    """Unique id of the router's gateway sensor."""
    return f"{entry_id}{DIAG_GATEWAY_UID_SUFFIX}"


def _diag(hass: HomeAssistant) -> Any:
    try:
        from .diag_runtime import async_get_net_diagnostics
    except Exception:  # noqa: BLE001 - module not importable: unavailable
        return None
    return async_get_net_diagnostics(hass)


def _view(hass: HomeAssistant) -> _View | None:
    diag = _diag(hass)
    if diag is None or not diag.enabled:
        return None
    view = diag.view
    return view if isinstance(view, Mapping) else None


class _DiagEntity:
    """Pushed by the module's signal; no polling, no network."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    hass: HomeAssistant

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()  # type: ignore[misc]
        self.async_on_remove(  # type: ignore[attr-defined]
            async_dispatcher_connect(
                self.hass, SIGNAL_NET_DIAGNOSTICS, self._handle_update
            )
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()  # type: ignore[attr-defined]


class DiagFleetSensor(_DiagEntity, SensorEntity):
    """One fleet number of the network diagnostics."""

    entity_description: DiagSensorDescription
    # context only, the history needs the numbers
    _unrecorded_attributes = frozenset(
        {
            "classifications",
            "coverage",
            "ha_state",
            "low_confidence",
            "measured_at",
            "routers",
            "routers_scored",
            "routers_unknown",
            "window",
        }
    )

    def __init__(self, description: DiagSensorDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    @property
    def available(self) -> bool:
        return _view(self.hass) is not None

    @property
    def native_value(self) -> float | int | None:
        view = _view(self.hass)
        return None if view is None else self.entity_description.value_fn(view)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        view = _view(self.hass)
        attrs = self.entity_description.extra_attrs_fn
        if attrs is None:
            return None
        return attrs({} if view is None else view)


class DiagGatewaySensor(_DiagEntity, BinarySensorEntity):
    """Next hop of one router reachable (direct measurement only)."""

    _attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
    _attr_translation_key = GATEWAY_TRANSLATION_KEY
    _unrecorded_attributes = frozenset({"reason", "family", "next_hop_known"})

    def __init__(self, entry_id: str, router_id: str) -> None:
        self._entry_id = entry_id
        self._router_id = router_id
        self._attr_unique_id = gateway_unique_id(entry_id)
        # the router's existing device (checked before creation)
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    def _gateway(self) -> Mapping[str, Any] | None:
        view = _view(self.hass)
        gateways = None if view is None else view.get("gateways")
        if not isinstance(gateways, Mapping):
            return None
        gateway = gateways.get(self._router_id)
        return gateway if isinstance(gateway, Mapping) else None

    @property
    def available(self) -> bool:
        return self._gateway() is not None

    @property
    def is_on(self) -> bool | None:
        gateway = self._gateway()
        state = None if gateway is None else gateway.get("state")
        return state if isinstance(state, bool) else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        gateway = self._gateway()
        if gateway is None:
            return None
        return {
            "reason": gateway.get("reason"),
            "family": gateway.get("family"),
            "next_hop_known": gateway.get("next_hop_known"),
        }


# --- hosting ------------------------------------------------------------------------


@dataclass(slots=True)
class _Hosts:
    """What is created where (entry ids only)."""

    anchor: str | None = None
    gateways: dict[str, str] = field(default_factory=dict)  # entry -> router id
    unsub: Callable[[], None] | None = None
    syncing: bool = False


def _hosts(hass: HomeAssistant) -> _Hosts:
    hosts = hass.data.get(DATA_DIAG_ENTITIES)
    if not isinstance(hosts, _Hosts):
        hosts = _Hosts()
        hass.data[DATA_DIAG_ENTITIES] = hosts
    return hosts


def _default_platforms(hass: HomeAssistant) -> list[Any]:
    return list(entity_platform.async_get_platforms(hass, DOMAIN))


# Test seam: the loaded entity platforms of this integration.
platforms_of: Callable[[HomeAssistant], list[Any]] = _default_platforms


def _platforms(hass: HomeAssistant, domain: str) -> dict[str, Any]:
    """Entry id -> loaded platform of ``domain`` (entries only)."""
    out: dict[str, Any] = {}
    for platform in platforms_of(hass):
        entry = getattr(platform, "config_entry", None)
        entry_id = getattr(entry, "entry_id", None)
        if getattr(platform, "domain", None) == domain and isinstance(entry_id, str):
            out[entry_id] = platform
    return out


def _device_exists(hass: HomeAssistant, entry_id: str) -> bool:
    """The router's own device ``(DOMAIN, entry_id)`` exists (read only).

    Same lookup as the coordinator: ``async_get_device_by_identifier``
    (HA 2026.8+); older cores (floor 2026.2) only have ``async_get_device``
    (deprecated since 2026.9, removed in 2027.8).
    """
    identifier = (DOMAIN, entry_id)
    try:
        devices = dr.async_get(hass)
        by_identifier = getattr(devices, "async_get_device_by_identifier", None)
        if by_identifier is not None:
            return by_identifier(identifier, entry_id) is not None
        return devices.async_get_device(identifiers={identifier}) is not None
    except Exception:  # noqa: BLE001 - no registry: create nothing
        return False


def router_waiting(hass: HomeAssistant, diag: Any) -> bool:
    """A mapped router with an existing device has no gateway sensor yet."""
    hosts = hass.data.get(DATA_DIAG_ENTITIES)
    if not isinstance(hosts, _Hosts) or not diag.enabled:
        return False
    return any(
        entry_id not in hosts.gateways for entry_id in diag.entries_by_router().values()
    )


async def async_sync_diag_entities(hass: HomeAssistant) -> None:
    """Create the set while the module is on; remove it once it is off.

    Before the module has read its store nothing happens (a restart must
    not drop the registry entries of a module that is on).
    """
    diag = _diag(hass)
    if diag is None or not getattr(diag, "loaded", False):
        return
    hosts = _hosts(hass)
    if not diag.enabled:
        hosts.anchor = None
        hosts.gateways.clear()
        _remove_from_registry(hass)
        return
    if hosts.unsub is None:

        @callback
        def _receiver() -> None:
            # @callback: HA runs it on the loop (a lambda is an executor job)
            _on_update(hass)

        hosts.unsub = async_dispatcher_connect(hass, SIGNAL_NET_DIAGNOSTICS, _receiver)
    sensors = _platforms(hass, SENSOR_DOMAIN)
    if sensors and (hosts.anchor is None or hosts.anchor not in sensors):
        anchor = min(sensors)
        hosts.anchor = anchor
        await sensors[anchor].async_add_entities([DiagFleetSensor(d) for d in SENSORS])
    binaries = _platforms(hass, BINARY_SENSOR_DOMAIN)
    for router_id, entry_id in sorted(diag.entries_by_router().items()):
        if entry_id in hosts.gateways or entry_id not in binaries:
            continue
        if not _device_exists(hass, entry_id):
            continue  # never a new device
        hosts.gateways[entry_id] = router_id
        await binaries[entry_id].async_add_entities(
            [DiagGatewaySensor(entry_id, router_id)]
        )


@callback
def _on_update(hass: HomeAssistant) -> None:
    """After a poll: a router got its id -> add its gateway sensor."""
    hosts = hass.data.get(DATA_DIAG_ENTITIES)
    diag = _diag(hass)
    if not isinstance(hosts, _Hosts) or diag is None or hosts.syncing:
        return
    if not router_waiting(hass, diag):
        return
    binaries = _platforms(hass, BINARY_SENSOR_DOMAIN)
    if not any(
        entry_id not in hosts.gateways
        and entry_id in binaries
        and _device_exists(hass, entry_id)
        for entry_id in diag.entries_by_router().values()
    ):
        return
    hosts.syncing = True

    async def run() -> None:
        try:
            await async_sync_diag_entities(hass)
        except Exception as err:  # noqa: BLE001 - next poll tries again
            _LOGGER.warning(
                "Network diagnostics entities not added (%s)", type(err).__name__
            )
        finally:
            hosts.syncing = False

    job = run()
    try:
        hass.async_create_task(job, name="openwrt_router diag entities")
    except Exception:
        hosts.syncing = False  # never stuck: the next signal tries again
        job.close()
        raise


def _remove_from_registry(hass: HomeAssistant) -> None:
    """Module off: drop its entities (live ones are removed by HA)."""
    try:
        registry = er.async_get(hass)
    except Exception:  # noqa: BLE001 - no registry (tests, shutdown)
        return
    if getattr(registry, "entities", None) is None:
        return  # not loaded (yet): nothing to remove
    for unique_id in DIAG_FLEET_UNIQUE_IDS:
        entity_id = registry.async_get_entity_id(SENSOR_DOMAIN, DOMAIN, unique_id)
        if entity_id is not None:
            registry.async_remove(entity_id)
    for entity in list(registry.entities.values()):
        if (
            entity.platform == DOMAIN
            and entity.domain == BINARY_SENSOR_DOMAIN
            and isinstance(entity.unique_id, str)
            and entity.unique_id.endswith(DIAG_GATEWAY_UID_SUFFIX)
        ):
            registry.async_remove(entity.entity_id)


async def async_entry_released(
    hass: HomeAssistant, entry_id: str, *, last: bool
) -> None:
    """The entry is unloaded (its platforms are gone): move the fleet host.

    ``last``: no entry is left; the registry entries stay for the next
    start (the module's setting decides then).
    """
    hosts = hass.data.get(DATA_DIAG_ENTITIES)
    if not isinstance(hosts, _Hosts):
        return
    hosts.gateways.pop(entry_id, None)
    if last:
        if hosts.unsub is not None:
            hosts.unsub()
        hass.data.pop(DATA_DIAG_ENTITIES, None)
        return
    if hosts.anchor == entry_id:
        hosts.anchor = None
        await async_sync_diag_entities(hass)


__all__ = [
    "DIAG_FLEET_UNIQUE_IDS",
    "SENSORS",
    "DiagFleetSensor",
    "DiagGatewaySensor",
    "DiagSensorDescription",
    "async_entry_released",
    "async_sync_diag_entities",
    "gateway_unique_id",
    "platforms_of",
    "router_waiting",
]
