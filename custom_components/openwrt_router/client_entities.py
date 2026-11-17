"""Client stability sensors (B7, plan section 8).

No entity without a selection: only the MACs of the setting
``entity_macs`` (at most 25, chosen in the panel) get sensors, five each:
stability score and connection quality (enabled), reconnects in 24 h,
connection uptime and last disconnect (disabled by default).

The sensors are hosted by the fleet anchor entry (``claim_fleet``) and have
no device. [CS-Entscheidung] Without a device: the Wi-Fi tracker of a
client lives on a router device per entry, so a client device would be a
second, router-independent device; the panel and the entity name identify
the client. Deselecting a client removes its sensors from the entity
registry. The sensors read only the engine's published state
(``ClientStability.entity_states``, rebuilt at most every 60 s) and update
on ``SIGNAL_CLIENT_STABILITY``; no polling, no router call.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfTime
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .client_analysis import (
    CLASS_CRITICAL,
    CLASS_NOTICEABLE,
    CLASS_STABLE,
    CLASS_UNKNOWN,
    CLASS_UNSTABLE,
    CLASS_VERY_STABLE,
)
from .client_engine import ClientEntityState, ClientStability, async_get_client_engine
from .client_history import normalize_mac
from .const import CLIENT_UID_PREFIX, DOMAIN, SIGNAL_CLIENT_STABILITY
from .net_engine import async_get_engine

_LOGGER = logging.getLogger(__name__)

KEY_SCORE = "stability_score"
KEY_QUALITY = "connection_quality"
KEY_RECONNECTS = "reconnects_24h"
KEY_UPTIME = "connection_uptime"
KEY_LAST_DISCONNECT = "last_disconnect"
SENSOR_KEYS = (KEY_SCORE, KEY_QUALITY, KEY_RECONNECTS, KEY_UPTIME, KEY_LAST_DISCONNECT)
QUALITY_OPTIONS = [
    CLASS_VERY_STABLE,
    CLASS_STABLE,
    CLASS_NOTICEABLE,
    CLASS_UNSTABLE,
    CLASS_CRITICAL,
]
FLEET_PLATFORM = "client_sensor"


def client_unique_id(mac: str, key: str) -> str:
    """``openwrt_router_client_<mac12>_<key>``."""
    return f"{CLIENT_UID_PREFIX}{mac.replace(':', '').lower()}_{key}"


def mac_of_unique_id(unique_id: str) -> str | None:
    """The MAC of a client sensor's unique_id, None for any other entity."""
    if not unique_id.startswith(CLIENT_UID_PREFIX):
        return None
    mac12 = unique_id[len(CLIENT_UID_PREFIX) :].split("_", 1)[0]
    if len(mac12) != 12:
        return None
    return normalize_mac(":".join(mac12[i : i + 2] for i in range(0, 12, 2)))


@callback
def async_setup_client_sensors(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    """Offer this router as host of the client sensors (fleet anchor)."""
    engine = async_get_engine(hass)
    if engine is None or entry.entry_id not in engine.routers:
        return
    if async_get_client_engine(hass) is None:
        return
    engine.claim_fleet(
        FLEET_PLATFORM,
        entry.entry_id,
        lambda: _ClientSensorHost(hass, entry, async_add_entities).start(),
    )


class _ClientSensorHost:
    """Keeps the client sensors of the anchor entry in line with the
    selection: adds sensors for new MACs, removes deselected ones."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        async_add_entities: AddEntitiesCallback,
    ) -> None:
        self._hass = hass
        self._entry = entry
        self._add = async_add_entities
        self._macs: set[str] = set()

    @callback
    def start(self) -> None:
        self._remove_stale()
        self.sync()
        self._entry.async_on_unload(
            async_dispatcher_connect(self._hass, SIGNAL_CLIENT_STABILITY, self.sync)
        )

    @callback
    def sync(self) -> None:
        cs = async_get_client_engine(self._hass)
        wanted = list(cs.settings["entity_macs"]) if cs is not None else []
        new = [mac for mac in wanted if mac not in self._macs]
        gone = self._macs - set(wanted)
        if gone:
            self._remove(gone)
            self._macs -= gone
        if new:
            self._macs.update(new)
            self._add([s for mac in new for s in _sensors(mac, cs)])

    def _remove_stale(self) -> None:
        """Registry entries of clients deselected while not loaded."""
        cs = async_get_client_engine(self._hass)
        wanted = set(cs.settings["entity_macs"]) if cs is not None else set()
        registry = er.async_get(self._hass)
        stale = {
            mac
            for item in er.async_entries_for_config_entry(
                registry, self._entry.entry_id
            )
            if (mac := mac_of_unique_id(item.unique_id)) and mac not in wanted
        }
        if stale:
            self._remove(stale)

    def _remove(self, macs: Iterable[str]) -> None:
        registry = er.async_get(self._hass)
        for mac in macs:
            for key in SENSOR_KEYS:
                entity_id = registry.async_get_entity_id(
                    "sensor", DOMAIN, client_unique_id(mac, key)
                )
                if entity_id is not None:
                    registry.async_remove(entity_id)


def _sensors(mac: str, cs: ClientStability | None) -> list[_ClientSensor]:
    state = cs.entity_states.get(mac) if cs is not None else None
    name = state.name if state is not None else mac
    return [cls(mac, name) for cls in _SENSOR_TYPES]


class _ClientSensor(SensorEntity):
    """One value of one selected client; pushed, never polled."""

    _attr_has_entity_name = True
    _attr_should_poll = False
    _key: str = ""

    def __init__(self, mac: str, name: str) -> None:
        self._mac = mac
        self._attr_unique_id = client_unique_id(mac, self._key)
        self._attr_translation_key = f"client_{self._key}"
        self._attr_translation_placeholders = {"client": name}

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_CLIENT_STABILITY, self._handle_update
            )
        )

    @callback
    def _handle_update(self) -> None:
        self.async_write_ha_state()

    @property
    def _cs(self) -> ClientStability | None:
        return async_get_client_engine(self.hass)

    @property
    def _state(self) -> ClientEntityState | None:
        cs = self._cs
        return cs.entity_states.get(self._mac) if cs is not None else None

    @property
    def available(self) -> bool:
        return self._state is not None


class ClientStabilityScoreSensor(_ClientSensor):
    """Stability score 0-100 of the last 24 h (unknown below the coverage)."""

    _key = KEY_SCORE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _unrecorded_attributes = frozenset({"score_7d", "coverage"})

    @property
    def native_value(self) -> float | None:
        state = self._state
        return state.score if state is not None else None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        state = self._state
        if state is None:
            return {}
        return {"score_7d": state.score_7d, "coverage": state.coverage}


class ClientConnectionQualitySensor(_ClientSensor):
    """Class of the score; no state while the score is unknown."""

    _key = KEY_QUALITY
    _attr_device_class = SensorDeviceClass.ENUM
    _attr_options = QUALITY_OPTIONS

    @property
    def native_value(self) -> str | None:
        state = self._state
        if state is None or state.cls == CLASS_UNKNOWN:
            return None
        return state.cls


class ClientReconnectsSensor(_ClientSensor):
    """Reconnects in the last 24 h (unknown without a readable log)."""

    _key = KEY_RECONNECTS
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_registry_enabled_default = False

    @property
    def native_value(self) -> int | None:
        state = self._state
        return state.reconnects_24h if state is not None else None


class ClientConnectionUptimeSensor(_ClientSensor):
    """Length of the running connection at the last poll."""

    _key = KEY_UPTIME
    _attr_device_class = SensorDeviceClass.DURATION
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_entity_registry_enabled_default = False

    @property
    def native_value(self) -> int | None:
        state = self._state
        cs = self._cs
        if state is None or cs is None or cs.last_now is None:
            return None
        if not state.connected or state.session_start is None:
            return None
        return max(0, int(cs.last_now - state.session_start))


class ClientLastDisconnectSensor(_ClientSensor):
    """Time of the last disconnect."""

    _key = KEY_LAST_DISCONNECT
    _attr_device_class = SensorDeviceClass.TIMESTAMP
    _attr_entity_registry_enabled_default = False

    @property
    def native_value(self) -> datetime | None:
        state = self._state
        if state is None or state.last_disconnect is None:
            return None
        return datetime.fromtimestamp(state.last_disconnect, UTC)


_SENSOR_TYPES: tuple[Callable[[str, str], _ClientSensor], ...] = (
    ClientStabilityScoreSensor,
    ClientConnectionQualitySensor,
    ClientReconnectsSensor,
    ClientConnectionUptimeSensor,
    ClientLastDisconnectSensor,
)
