"""Fleet sensors of the Security Center (release 1.46.0 part 2).

Seven sensors for the whole fleet (no device, ``unique_id``
``openwrt_router_fleet_security_*``), one set per HA instance:

* security score (0-100; unknown while no source is covered),
* active hints, critical hints (own ``sec_*`` incidents),
* unknown devices (not confirmed: new, unrecognized, suspicious),
* blocked firewall log lines and failed Wi-Fi authentications in the last
  hour,
* detection coverage (%).

Every value comes from the center's ``fleet_view`` (counts only, rebuilt
after each poll) and is pushed with ``SIGNAL_SECURITY_CENTER``; nothing here
talks to a router or polls. A value whose source no router delivers is
``None`` (unknown), never 0: no data is not "nothing happened". Without a
view (center off, no router yet) the sensors are unavailable.

Center off (default): the sensors are **not created**, and switching the
center off removes them from the entity registry. Reason: a feature that
was never switched on must not leave anything behind, and a disabled
registry entry would still show up in every entity list. Switching the
center on creates them at once (no reload).

Host: the sensor platforms of the loaded entries offer their
``async_add_entities``; the smallest entry id hosts the set. When it
unloads, the next one creates them again after the old ones are gone (the
entity registry moves the same unique_id to the new entry).
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from homeassistant.components.sensor import (
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import PERCENTAGE
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    DATA_SECURITY_ENTITIES,
    DOMAIN,
    SIGNAL_SECURITY_CENTER,
    UID_FLEET_SECURITY_COVERAGE,
    UID_FLEET_SECURITY_FIREWALL_EVENTS,
    UID_FLEET_SECURITY_HINTS_ACTIVE,
    UID_FLEET_SECURITY_HINTS_CRITICAL,
    UID_FLEET_SECURITY_SCORE,
    UID_FLEET_SECURITY_UNKNOWN_DEVICES,
    UID_FLEET_SECURITY_WIFI_AUTH_FAILURES,
)

_LOGGER = logging.getLogger(__name__)

type _View = Mapping[str, Any]


@dataclass(frozen=True, kw_only=True)
class SecuritySensorDescription(SensorEntityDescription):
    """A fleet sensor: its unique id and how it reads the view."""

    unique_id: str
    value_fn: Callable[[_View], int | None]
    extra_attrs_fn: Callable[[_View], dict[str, Any]] | None = None


def _int(view: _View, key: str) -> int | None:
    value = view.get(key)
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _score_attrs(view: _View) -> dict[str, Any]:
    return {
        "coverage": view.get("coverage"),
        "cap": view.get("score_cap"),
        "reason": view.get("score_reason"),
        "routers": view.get("routers"),
    }


def _coverage_attrs(view: _View) -> dict[str, Any]:
    return {
        "missing": list(view.get("missing") or []),
        "stale": list(view.get("stale") or []),
        "routers": view.get("routers"),
    }


def _device_attrs(view: _View) -> dict[str, Any]:
    counts = view.get("device_counts")
    return {"states": dict(counts) if isinstance(counts, Mapping) else {}}


SENSORS: tuple[SecuritySensorDescription, ...] = (
    SecuritySensorDescription(
        key="security_score",
        translation_key="fleet_security_score",
        unique_id=UID_FLEET_SECURITY_SCORE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "score"),
        extra_attrs_fn=_score_attrs,
    ),
    SecuritySensorDescription(
        key="security_hints_active",
        translation_key="fleet_security_hints_active",
        unique_id=UID_FLEET_SECURITY_HINTS_ACTIVE,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "hints_active"),
    ),
    SecuritySensorDescription(
        key="security_hints_critical",
        translation_key="fleet_security_hints_critical",
        unique_id=UID_FLEET_SECURITY_HINTS_CRITICAL,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "hints_critical"),
    ),
    SecuritySensorDescription(
        key="security_unknown_devices",
        translation_key="fleet_security_unknown_devices",
        unique_id=UID_FLEET_SECURITY_UNKNOWN_DEVICES,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "unknown_devices"),
        extra_attrs_fn=_device_attrs,
    ),
    SecuritySensorDescription(
        key="security_firewall_events_1h",
        translation_key="fleet_security_firewall_events_1h",
        unique_id=UID_FLEET_SECURITY_FIREWALL_EVENTS,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "firewall_events_1h"),
    ),
    SecuritySensorDescription(
        key="security_wifi_auth_failures_1h",
        translation_key="fleet_security_wifi_auth_failures_1h",
        unique_id=UID_FLEET_SECURITY_WIFI_AUTH_FAILURES,
        state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda v: _int(v, "wifi_auth_failures_1h"),
    ),
    SecuritySensorDescription(
        key="security_coverage",
        translation_key="fleet_security_coverage",
        unique_id=UID_FLEET_SECURITY_COVERAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        value_fn=lambda v: _int(v, "coverage"),
        extra_attrs_fn=_coverage_attrs,
    ),
)
SECURITY_UNIQUE_IDS: tuple[str, ...] = tuple(d.unique_id for d in SENSORS)


def _center(hass: HomeAssistant) -> Any:
    try:
        from .security_center import async_get_security_center
    except Exception:  # noqa: BLE001 - module not importable: unavailable
        return None
    return async_get_security_center(hass)


class SecurityFleetSensor(SensorEntity):
    """One fleet number of the Security Center (pushed, no polling)."""

    entity_description: SecuritySensorDescription
    _attr_has_entity_name = True
    _attr_should_poll = False
    # Context only, the history needs the numbers (HA reads this per class).
    _unrecorded_attributes = frozenset(
        {"cap", "coverage", "missing", "reason", "routers", "stale", "states"}
    )

    def __init__(self, description: SecuritySensorDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_SECURITY_CENTER, self._handle_update
            )
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()

    @property
    def _view(self) -> _View | None:
        center = _center(self.hass)
        if center is None or not center.enabled:
            return None
        view = center.fleet_view
        return view if isinstance(view, Mapping) else None

    @property
    def available(self) -> bool:
        return self._view is not None

    @property
    def native_value(self) -> int | None:
        view = self._view
        return None if view is None else self.entity_description.value_fn(view)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        view = self._view
        attrs = self.entity_description.extra_attrs_fn
        if view is None or attrs is None:
            return None
        return attrs(view)


# --- hosting ------------------------------------------------------------------------


@dataclass(slots=True)
class _Hosts:
    """The entries' sensor platforms offering to host the set."""

    adders: dict[str, AddEntitiesCallback] = field(default_factory=dict)
    anchor: str | None = None


def _hosts(hass: HomeAssistant) -> _Hosts:
    hosts = hass.data.get(DATA_SECURITY_ENTITIES)
    if not isinstance(hosts, _Hosts):
        hosts = _Hosts()
        hass.data[DATA_SECURITY_ENTITIES] = hosts
    return hosts


@callback
def async_setup_security_sensors(
    hass: HomeAssistant, entry: Any, async_add_entities: AddEntitiesCallback
) -> None:
    """The entry's sensor platform offers to host the fleet sensors."""
    _hosts(hass).adders[entry.entry_id] = async_add_entities
    async_sync_security_entities(hass)


@callback
def async_sync_security_entities(hass: HomeAssistant) -> None:
    """Create the set while the center is on; remove it once it is off.

    Before the center has read its store nothing happens (a restart must
    not drop the registry entries of a center that is on).
    """
    center = _center(hass)
    if center is None or not getattr(center, "loaded", False):
        return
    hosts = _hosts(hass)
    if center.enabled:
        if hosts.anchor is not None and hosts.anchor in hosts.adders:
            return
        if not hosts.adders:
            return
        anchor = min(hosts.adders)
        hosts.anchor = anchor
        hosts.adders[anchor]([SecurityFleetSensor(d) for d in SENSORS])
        return
    hosts.anchor = None
    _remove_from_registry(hass)


def _remove_from_registry(hass: HomeAssistant) -> None:
    """Center off: drop the fleet sensors (live ones are removed by HA)."""
    try:
        registry = er.async_get(hass)
    except Exception:  # noqa: BLE001 - no registry (tests, shutdown)
        return
    for unique_id in SECURITY_UNIQUE_IDS:
        entity_id = registry.async_get_entity_id("sensor", DOMAIN, unique_id)
        if entity_id is not None:
            registry.async_remove(entity_id)


@callback
def async_entry_unloaded(hass: HomeAssistant, entry_id: str, *, last: bool) -> None:
    """The entry is unloaded (its platforms are gone): move the host.

    ``last``: no entry is left; the registry entries stay for the next
    start (the center's setting decides then).
    """
    hosts = _hosts(hass)
    hosts.adders.pop(entry_id, None)
    if last:
        hass.data.pop(DATA_SECURITY_ENTITIES, None)
        return
    if hosts.anchor == entry_id:
        hosts.anchor = None
        async_sync_security_entities(hass)


__all__ = [
    "SECURITY_UNIQUE_IDS",
    "SENSORS",
    "SecurityFleetSensor",
    "SecuritySensorDescription",
    "async_entry_unloaded",
    "async_setup_security_sensors",
    "async_sync_security_entities",
]
