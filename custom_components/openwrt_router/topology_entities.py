"""topology_entities.py — HA sensor entities for topology diagnostic.

Two sensors per router config entry:

  sensor.<router>_network_topology
      EntityCategory.DIAGNOSTIC
      native_value  = total node count in snapshot
      attributes:
          topology_snapshot  — full snapshot dict (matches /api/topology/snapshot schema)
          interfaces         — list of interface objects
          clients            — list of client objects
          inference_used     — bool: True when any node/edge is inferred
          topology_debug     — meta + known_limitations

  sensor.<router>_topology_status
      EntityCategory.DIAGNOSTIC
      native_value  = active interface count
      attributes:
          active_interfaces      — int
          inactive_interfaces    — int
          invalid_data           — int (negative rx or tx)
          inferred_nodes         — int
          clients_without_signal — int (signal=None count)
          unknown_interface_types — int
          known_limitations      — list[str]

The "network_topology" sensor is the primary cross-comparison point
against the provisioning server's /api/topology/snapshot output.
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import OpenWrtConfigEntry
from .const import (
    CONF_PROTOCOL,
    DEFAULT_PROTOCOL,
    DOMAIN,
    SUFFIX_TOPOLOGY_SNAPSHOT,
    SUFFIX_TOPOLOGY_STATUS,
)
from .coordinator import OpenWrtCoordinator
from .topology_diagnostic import build_topology_snapshot, get_topology_status

_LOGGER = logging.getLogger(__name__)


def setup_topology_entities(
    coordinator: OpenWrtCoordinator,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create and register topology diagnostic sensor entities.

    Called from sensor.async_setup_entry — no new platform needed.
    """
    entities: list[SensorEntity] = [
        OpenWrtTopologySnapshotSensor(coordinator, entry),
        OpenWrtTopologyStatusSensor(coordinator, entry),
    ]
    async_add_entities(entities)
    _LOGGER.debug(
        "Added topology diagnostic sensors for entry %s", entry.entry_id
    )


class _TopologyEntityBase(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """Shared base for topology diagnostic sensors."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        suffix: str,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{suffix}"

    @property
    def device_info(self) -> DeviceInfo:
        """Group under the router device card."""
        router_info = self.coordinator.router_info
        release = (router_info.get("release") or {})
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"{self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL)}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )

    def _snapshot(self) -> dict[str, Any]:
        """Build and return the current topology snapshot (cached per call)."""
        if not self.coordinator.data:
            return {}
        try:
            return build_topology_snapshot(self.coordinator.data)
        except Exception:  # noqa: BLE001
            _LOGGER.debug(
                "topology_diagnostic: snapshot build failed for %s",
                self._attr_unique_id,
                exc_info=True,
            )
            return {}


class OpenWrtTopologySnapshotSensor(_TopologyEntityBase):
    """Topology snapshot sensor.

    native_value = total node count.
    Primary attribute 'topology_snapshot' mirrors the structure of
    /api/topology/snapshot from the provisioning server for direct
    side-by-side comparison.
    """

    _attr_icon = "mdi:graph-outline"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "nodes"

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
    ) -> None:
        super().__init__(coordinator, entry, SUFFIX_TOPOLOGY_SNAPSHOT)

    @property
    def name(self) -> str:
        """Human-readable sensor name."""
        return "Network Topology"

    @property
    def native_value(self) -> int | None:
        """Return total node count in the snapshot."""
        snap = self._snapshot()
        if not snap:
            return None
        return snap["meta"].get("node_count", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return topology snapshot and diagnostic attributes."""
        snap = self._snapshot()
        if not snap:
            return {}
        return {
            # Full snapshot — primary comparison target vs provisioning server
            "topology_snapshot": snap,
            # Convenience sub-lists (same data, easier to browse in HA UI)
            "interfaces": snap.get("interfaces", []),
            "clients": snap.get("clients", []),
            "inference_used": snap.get("meta", {}).get("inference_used", False),
            # Debug envelope
            "topology_debug": {
                "source": snap.get("meta", {}).get("source"),
                "schema_version": snap.get("meta", {}).get("schema_version"),
                "generated_at": snap.get("generated_at"),
                "meta": snap.get("meta", {}),
                "known_limitations": [
                    "signal=null when iw station dump returns bracket-format signal",
                    "inactive = strict 0/0 rx/tx only",
                    "rx_bytes/tx_bytes per AP interface not available from HA coordinator",
                    "wifi_iface_status={} when provisioning server has no SSH key",
                ],
            },
        }


class OpenWrtTopologyStatusSensor(_TopologyEntityBase):
    """Topology status counts sensor.

    native_value = active interface count.
    Attributes expose per-category counts for quick dashboard validation.
    """

    _attr_icon = "mdi:network-outline"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "interfaces"

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
    ) -> None:
        super().__init__(coordinator, entry, SUFFIX_TOPOLOGY_STATUS)

    @property
    def name(self) -> str:
        """Human-readable sensor name."""
        return "Topology Status"

    @property
    def native_value(self) -> int | None:
        """Return active interface count."""
        snap = self._snapshot()
        if not snap:
            return None
        return get_topology_status(snap).get("active_interfaces", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return topology status counts."""
        snap = self._snapshot()
        if not snap:
            return {}
        return get_topology_status(snap)
