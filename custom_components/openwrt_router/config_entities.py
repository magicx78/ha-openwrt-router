"""Configuration manager entities (plan 2026-11-18, section 6).

Per router, on its device (``DeviceInfo(identifiers={(DOMAIN, entry_id)})``),
``unique_id`` ``f"{router_id}_{suffix}"`` with the core's router id:

* ``sensor`` last backup (timestamp of the newest usable version),
* ``sensor`` backup status (enum: ok, partial, failed, running, disabled,
  never; attributes ``error_class``, ``error_reason``, ``last_attempt_at``,
  ``next_run_at``),
* ``sensor`` stored versions (diagnostic),
* ``binary_sensor`` drift (problem: on while a drift is open).

They are created for every router, also with the backup option off (the
status then says ``disabled``). Every value comes from the runtime's memory
(``config_manager.ConfigManagerRuntime``), which is filled from the version
store and the core's audit; nothing here talks to a router, polls or calls
HTTP. Updates arrive with ``SIGNAL_CONFIG_MANAGER`` (argument: router id).
The runtime and the core are looked up on every read and imported lazily,
so a core that cannot be imported never breaks the sensor platform.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import (
    CONFIG_BACKUP_STATUSES,
    DOMAIN,
    SIGNAL_CONFIG_MANAGER,
    SUFFIX_CONFIG_BACKUP_STATUS,
    SUFFIX_CONFIG_DRIFT,
    SUFFIX_CONFIG_LAST_BACKUP,
    SUFFIX_CONFIG_VERSIONS,
)

_LOGGER = logging.getLogger(__name__)

# Suffixes of the entities of this module (unique_id f"{router_id}_{suffix}").
CONFIG_ENTITY_SUFFIXES = (
    SUFFIX_CONFIG_LAST_BACKUP,
    SUFFIX_CONFIG_BACKUP_STATUS,
    SUFFIX_CONFIG_VERSIONS,
    SUFFIX_CONFIG_DRIFT,
)


def config_router_id(hass: HomeAssistant, entry_id: str) -> str | None:
    """The core's router id of a config entry (None without a core)."""
    try:
        from .enterprise_core import async_get_core

        core = async_get_core(hass)
        if core is None:
            return None
        router_id = core.registry.router_id_for_entry(entry_id)
    except Exception:  # noqa: BLE001 - no core: no configuration entities
        return None
    return router_id if isinstance(router_id, str) and router_id else None


def _runtime(hass: HomeAssistant) -> Any:
    try:
        from .config_manager import async_get_runtime
    except Exception:  # noqa: BLE001 - module not importable: unavailable
        return None
    return async_get_runtime(hass)


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if isinstance(value, datetime) else None


@callback
def async_setup_config_sensors(
    hass: HomeAssistant, entry: Any, async_add_entities: AddEntitiesCallback
) -> None:
    """Add the three configuration sensors of the entry's router."""
    router_id = config_router_id(hass, entry.entry_id)
    if router_id is None:
        _LOGGER.debug(
            "No router id for %s yet: no configuration sensors", entry.entry_id
        )
        return
    async_add_entities(
        [
            ConfigLastBackupSensor(entry.entry_id, router_id),
            ConfigBackupStatusSensor(entry.entry_id, router_id),
            ConfigVersionsSensor(entry.entry_id, router_id),
        ]
    )


@callback
def async_setup_config_binary_sensors(
    hass: HomeAssistant, entry: Any, async_add_entities: AddEntitiesCallback
) -> None:
    """Add the drift problem sensor of the entry's router."""
    router_id = config_router_id(hass, entry.entry_id)
    if router_id is None:
        return
    async_add_entities([ConfigDriftBinarySensor(entry.entry_id, router_id)])


class _ConfigEntity(Entity):
    """Pushed by the runtime's dispatcher signal; no polling."""

    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry_id: str, router_id: str, suffix: str) -> None:
        self._entry_id = entry_id
        self._router_id = router_id
        self._attr_unique_id = f"{router_id}_{suffix}"
        self._attr_translation_key = suffix
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_CONFIG_MANAGER, self._handle_update
            )
        )

    @callback
    def _handle_update(self, router_id: str | None = None) -> None:
        if router_id is None or router_id in (self._router_id, self._rid):
            self.async_write_ha_state()

    @property
    def _manager(self) -> Any:
        return _runtime(self.hass)

    @property
    def _state(self) -> Any:
        """The entry's router state; follows an adoption (new router id)."""
        runtime = self._manager
        return None if runtime is None else runtime.state_for_entry(self._entry_id)

    @property
    def _rid(self) -> str:
        """The router id the entry is bound to now."""
        state = self._state
        return self._router_id if state is None else state.router_id

    @property
    def available(self) -> bool:
        return self._state is not None


class ConfigLastBackupSensor(_ConfigEntity, SensorEntity):
    """When the newest usable version was taken."""

    _attr_device_class = SensorDeviceClass.TIMESTAMP

    def __init__(self, entry_id: str, router_id: str) -> None:
        super().__init__(entry_id, router_id, SUFFIX_CONFIG_LAST_BACKUP)

    @property
    def native_value(self) -> datetime | None:
        state = self._state
        return None if state is None else state.last_backup_at


class ConfigBackupStatusSensor(_ConfigEntity, SensorEntity):
    """ok, partial, failed, running, disabled or never."""

    _attr_device_class = SensorDeviceClass.ENUM

    def __init__(self, entry_id: str, router_id: str) -> None:
        super().__init__(entry_id, router_id, SUFFIX_CONFIG_BACKUP_STATUS)
        self._attr_options = list(CONFIG_BACKUP_STATUSES)

    @property
    def available(self) -> bool:
        return self._manager is not None

    @property
    def native_value(self) -> str:
        runtime = self._manager
        return "disabled" if runtime is None else runtime.status(self._rid)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        runtime = self._manager
        state = self._state
        if runtime is None or state is None:
            return {
                "error_class": None,
                "error_reason": None,
                "last_attempt_at": None,
                "next_run_at": None,
            }
        return {
            "error_class": runtime.error_class(state.router_id),
            "error_reason": runtime.error_reason(state.router_id),
            "last_attempt_at": _iso(state.last_attempt_at),
            "next_run_at": _iso(runtime.next_run_at(state.router_id)),
        }


class ConfigVersionsSensor(_ConfigEntity, SensorEntity):
    """Number of stored versions of the router."""

    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(self, entry_id: str, router_id: str) -> None:
        super().__init__(entry_id, router_id, SUFFIX_CONFIG_VERSIONS)

    @property
    def native_value(self) -> int | None:
        state = self._state
        return None if state is None else state.version_count


class ConfigDriftBinarySensor(_ConfigEntity, BinarySensorEntity):
    """On while the live configuration drifted and nobody acknowledged it."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM

    def __init__(self, entry_id: str, router_id: str) -> None:
        super().__init__(entry_id, router_id, SUFFIX_CONFIG_DRIFT)

    @property
    def _drift(self) -> dict[str, Any] | None:
        state = self._state
        return None if state is None else state.drift

    @property
    def is_on(self) -> bool | None:
        drift = self._drift
        if drift is None:
            return None  # never checked (plan L7: unknown)
        return drift.get("state") == "open"

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        drift = self._drift or {}
        return {
            "drift_id": drift.get("drift_id"),
            "critical_count": drift.get("critical_count"),
            "unknown_count": drift.get("unknown_count"),
            "comparison": drift.get("comparison"),
            "checked_at": _iso(drift.get("checked_at")),
        }


_SUFFIX_PLATFORMS = {
    SUFFIX_CONFIG_LAST_BACKUP: "sensor",
    SUFFIX_CONFIG_BACKUP_STATUS: "sensor",
    SUFFIX_CONFIG_VERSIONS: "sensor",
    SUFFIX_CONFIG_DRIFT: "binary_sensor",
}


@callback
def async_migrate_config_unique_ids(
    hass: HomeAssistant, old_router_id: str, new_router_id: str
) -> int:
    """Move the registry entries of an adopted entry to its new router id.

    Keeps entity_id, name and history: after the next start the platform
    creates the entities with ``f"{new_router_id}_{suffix}"`` again and finds
    them. Registry only, no router call. Returns how many entries moved.
    """
    if not old_router_id or not new_router_id or old_router_id == new_router_id:
        return 0
    registry = er.async_get(hass)
    moved = 0
    for suffix, platform in _SUFFIX_PLATFORMS.items():
        entity_id = registry.async_get_entity_id(
            platform, DOMAIN, f"{old_router_id}_{suffix}"
        )
        if entity_id is None:
            continue
        try:
            registry.async_update_entity(
                entity_id, new_unique_id=f"{new_router_id}_{suffix}"
            )
        except ValueError:  # the new unique_id is taken: leave both alone
            _LOGGER.debug("Unique id of %s not moved: taken", entity_id)
            continue
        moved += 1
    return moved


__all__ = [
    "CONFIG_ENTITY_SUFFIXES",
    "ConfigBackupStatusSensor",
    "ConfigDriftBinarySensor",
    "ConfigLastBackupSensor",
    "ConfigVersionsSensor",
    "async_migrate_config_unique_ids",
    "async_setup_config_binary_sensors",
    "async_setup_config_sensors",
    "config_router_id",
]
