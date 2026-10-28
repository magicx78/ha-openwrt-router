"""topology_entities.py — HA sensor entities for topology diagnostic.

Two sensors per router config entry:

  sensor.<router>_network_topology
      EntityCategory.DIAGNOSTIC
      native_value  = total node count in snapshot
      attributes:
          node_count / edge_count / interface_count / client_count — int
          inference_used  — bool: True when any node/edge is inferred
          source          — snapshot producer id
          schema_version  — snapshot schema version

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

Attributes are deliberately small and free of timestamps, so the state only
changes when a count changes. The raw snapshot (nodes, edges, interfaces,
clients) is served exclusively by the authenticated panel API
(``/api/openwrt_topology/snapshot``, see topology_panel.py).

The snapshot is built at most once per coordinator update and shared by both
sensors of a router (``TopologySnapshotCache``).
"""

from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.const import MATCH_ALL, EntityCategory
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
    url_scheme_for,
)
from .coordinator import OpenWrtCoordinator, OpenWrtCoordinatorData
from .topology_diagnostic import build_topology_snapshot, get_topology_status

_LOGGER = logging.getLogger(__name__)


class TopologySnapshotCache:
    """Per-router topology snapshot, built once per coordinator update.

    The coordinator replaces ``coordinator.data`` with a fresh object on every
    successful poll, so the identity of that object is the cache key: the
    first property read after an update builds the snapshot, every further
    read (from either sensor) reuses it. A failed build is cached as ``{}``
    too, so a broken payload is not re-parsed on every attribute access.
    """

    def __init__(self, coordinator: OpenWrtCoordinator, label: str) -> None:
        self._coordinator = coordinator
        self._label = label
        self._source: OpenWrtCoordinatorData | None = None
        self._snapshot: dict[str, Any] = {}
        self._status: dict[str, Any] = {}

    def _refresh(self) -> None:
        """Rebuild the cached snapshot if the coordinator data was replaced."""
        data = self._coordinator.data
        if data is self._source:
            return
        self._source = data
        self._snapshot = {}
        self._status = {}
        if not data:
            return
        try:
            self._snapshot = build_topology_snapshot(data)
            self._status = get_topology_status(self._snapshot)
        except Exception:
            _LOGGER.debug(
                "topology_diagnostic: snapshot build failed for %s",
                self._label,
                exc_info=True,
            )
            self._snapshot = {}
            self._status = {}

    @property
    def snapshot(self) -> dict[str, Any]:
        """Return the snapshot for the current coordinator data ({} if none)."""
        self._refresh()
        return self._snapshot

    @property
    def status(self) -> dict[str, Any]:
        """Return the status counts for the current snapshot ({} if none)."""
        self._refresh()
        return self._status


def setup_topology_entities(
    coordinator: OpenWrtCoordinator,
    entry: OpenWrtConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create and register topology diagnostic sensor entities.

    Called from sensor.async_setup_entry — no new platform needed.
    """
    cache = TopologySnapshotCache(coordinator, entry.entry_id)
    entities: list[SensorEntity] = [
        OpenWrtTopologySnapshotSensor(coordinator, entry, cache),
        OpenWrtTopologyStatusSensor(coordinator, entry, cache),
    ]
    async_add_entities(entities)
    _LOGGER.debug("Added topology diagnostic sensors for entry %s", entry.entry_id)


class _TopologyEntityBase(CoordinatorEntity[OpenWrtCoordinator], SensorEntity):
    """Shared base for topology diagnostic sensors."""

    _attr_has_entity_name = True
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    # Diagnostic counts only — the sensor state (node count / active interface
    # count) is recorded, the attributes are not. The full topology is
    # available from the panel API, not from these entities.
    _unrecorded_attributes = frozenset({MATCH_ALL})

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        suffix: str,
        cache: TopologySnapshotCache,
    ) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._cache = cache
        self._attr_unique_id = f"{entry.entry_id}_{suffix}"

    @property
    def device_info(self) -> DeviceInfo:
        """Group under the router device card."""
        router_info = self.coordinator.router_info
        release = router_info.get("release") or {}
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name=router_info.get("hostname") or self._entry.title,
            manufacturer="OpenWrt",
            model=router_info.get("model", "OpenWrt Router"),
            sw_version=release.get("version", ""),
            configuration_url=(
                f"{url_scheme_for(self._entry.data.get(CONF_PROTOCOL, DEFAULT_PROTOCOL))}://"
                f"{self._entry.data['host']}:{self._entry.data['port']}"
            ),
        )


class OpenWrtTopologySnapshotSensor(_TopologyEntityBase):
    """Topology snapshot sensor.

    native_value = total node count.
    Attributes are the snapshot's meta counts — the raw snapshot itself is
    only available from the authenticated panel API.
    """

    _attr_icon = "mdi:graph-outline"
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = "nodes"

    def __init__(
        self,
        coordinator: OpenWrtCoordinator,
        entry: OpenWrtConfigEntry,
        cache: TopologySnapshotCache,
    ) -> None:
        super().__init__(coordinator, entry, SUFFIX_TOPOLOGY_SNAPSHOT, cache)

    @property
    def name(self) -> str:
        """Human-readable sensor name."""
        return "Network Topology"

    @property
    def native_value(self) -> int | None:
        """Return total node count in the snapshot."""
        snap = self._cache.snapshot
        if not snap:
            return None
        return snap.get("meta", {}).get("node_count", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return small, stable snapshot counts (no timestamps, no raw lists)."""
        snap = self._cache.snapshot
        if not snap:
            return {}
        meta = snap.get("meta", {})
        return {
            "node_count": meta.get("node_count", 0),
            "edge_count": meta.get("edge_count", 0),
            "interface_count": meta.get("interface_count", 0),
            "client_count": meta.get("client_count", 0),
            "inference_used": meta.get("inference_used", False),
            "source": meta.get("source"),
            "schema_version": meta.get("schema_version"),
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
        cache: TopologySnapshotCache,
    ) -> None:
        super().__init__(coordinator, entry, SUFFIX_TOPOLOGY_STATUS, cache)

    @property
    def name(self) -> str:
        """Human-readable sensor name."""
        return "Topology Status"

    @property
    def native_value(self) -> int | None:
        """Return active interface count."""
        status = self._cache.status
        if not status:
            return None
        return status.get("active_interfaces", 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Return topology status counts."""
        return dict(self._cache.status)
