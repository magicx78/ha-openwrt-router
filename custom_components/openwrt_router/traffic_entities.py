"""Entities of Traffic Analytics (plan §17, Bauplan §9, Phase K).

Home Assistant entity wiring like ``wifi_rf_entities``. A fixed, bounded
set; never one entity per flow, VLAN, port or short-lived client:

* two fleet sensors (no device, ``unique_id`` ``openwrt_router_fleet_
  traffic_*``): active traffic anomalies (count) and monitoring coverage
  (share of measurement points with ``full`` coverage, percent);
* per router with ``traffic_enabled``, only on its existing device:
  - a gateway (a router that measured WAN traffic): WAN download rate,
    WAN upload rate, WAN traffic total and peak bandwidth (24 h);
  - its uplink (the WAN of a gateway, else the one trunk port of the
    topology): utilisation (only with a known link speed) and RX/TX error
    totals (diagnostic, disabled by default);
* optional client sensors: only for the clients an administrator selected
  in the traffic settings (at most ``TRAFFIC_CLIENT_SENSORS_MAX``), no
  device, named "Wi-Fi traffic at the AP", never "internet".

So N routers give at most 2 + 7 * N + 2 * TRAFFIC_CLIENT_SENSORS_MAX.
DECIDED: plan §9 says "at most 6 per router" but its own table lists 7 for a
gateway (4 WAN + 3 uplink); the table is kept.

Unique ids: ``<entry_id>_traffic_<key>`` and ``openwrt_router_fleet_
traffic_*``; none contains ``_rate``, ``_ap_``, ``_port_``, ``_radio_`` or
``_iface_`` (the v1.17.4 migration disables every entity whose unique id
contains one of those, without anchor). Client sensors use the pseudonym
``client_ref``; no MAC, host name, IP, SSID or AP interface name appears in
a unique id, a name or an attribute.

Unknown stays unknown: no measurement yet, a counter gap or an unknown link
speed is ``None`` (state unknown), never 0. A total counts the valid deltas
since the module started (``TOTAL_INCREASING``; a Home Assistant restart
starts a new meter cycle, gaps are never estimated).

Off (default, per router): the entities are **not created**; switching a
router off removes its entities from the entity registry, switching the
last one off also the fleet and client sensors. The history stays in the
store. Switching on creates them after the next poll (no reload). An error
here never fails an entry's setup.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    EntityCategory,
    UnitOfDataRate,
    UnitOfInformation,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_platform
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.dispatcher import async_dispatcher_connect

from .const import (
    DATA_TRAFFIC_ENTITIES,
    DOMAIN,
    OPTION_TRAFFIC_ENABLED,
    SIGNAL_TRAFFIC_ANALYTICS,
    TRAFFIC_CLIENT_SENSORS_MAX,
    TRAFFIC_UID_INFIX,
    UID_FLEET_TRAFFIC_ANOMALIES,
    UID_FLEET_TRAFFIC_CLIENT_PREFIX,
    UID_FLEET_TRAFFIC_COVERAGE,
)

_LOGGER = logging.getLogger(__name__)

SENSOR_DOMAIN = "sensor"
SOURCE = "traffic_analytics"
PEAK_WINDOW_S = 86_400
PEAK_RESOLUTION_S = 300
MIN_BUCKET_COVERAGE = 0.5  # a bucket below is "lückenhaft" (plan §3.3)

# Router sensor keys (part of the unique id): kept short and free of the
# legacy patterns (no "_rate", "_port_" ...).
KEY_WAN_DOWN = "wan_down"
KEY_WAN_UP = "wan_up"
KEY_WAN_TOTAL = "wan_total"
KEY_WAN_PEAK = "wan_peak"
KEY_UPLINK_LOAD = "uplink_load"
KEY_UPLINK_RX_ERRORS = "uplink_rx_errors"
KEY_UPLINK_TX_ERRORS = "uplink_tx_errors"
WAN_KEYS = (KEY_WAN_DOWN, KEY_WAN_UP, KEY_WAN_TOTAL, KEY_WAN_PEAK)
UPLINK_KEYS = (KEY_UPLINK_RX_ERRORS, KEY_UPLINK_TX_ERRORS)
ROUTER_KEYS = (*WAN_KEYS, KEY_UPLINK_LOAD, *UPLINK_KEYS)
CLIENT_DIRECTIONS = ("down", "up")
FLEET_UNIQUE_IDS = (UID_FLEET_TRAFFIC_ANOMALIES, UID_FLEET_TRAFFIC_COVERAGE)


def _engine(hass: HomeAssistant) -> Any:
    try:
        from .traffic_engine import async_get_traffic_engine
    except Exception:  # noqa: BLE001 - module not importable: unavailable
        return None
    return async_get_traffic_engine(hass)


def _active(engine: Any) -> bool:
    return engine is not None and getattr(engine, "active", False) is True


def router_unique_id(entry_id: str, key: str) -> str:
    """Unique id of one router traffic sensor."""
    return f"{entry_id}{TRAFFIC_UID_INFIX}{key}"


def client_unique_id(client_ref: str, direction: str) -> str:
    """Unique id of one optional client sensor (pseudonym only)."""
    return f"{UID_FLEET_TRAFFIC_CLIENT_PREFIX}{client_ref}_{direction}"


def _bits(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return round(float(value), 0)


# --- values ---------------------------------------------------------------------------
# Each reader returns (value, attributes); value None is "unknown".

Reading = tuple[Any, dict[str, Any]]


def _rate_of(engine: Any, point: Any) -> Any:
    return None if point is None else engine.latest.get(point.point_id)


def _rate_attrs(rate: Any) -> dict[str, Any]:
    if rate is None:
        return {"coverage": "unknown", "quality": None, "source": SOURCE}
    return {
        "coverage": rate.coverage.value,
        "quality": rate.quality.value,
        "source": SOURCE,
    }


def _wan_rate(engine: Any, router_id: str, attr: str) -> Reading:
    rate = _rate_of(engine, engine.wan_point(router_id))
    value = None if rate is None else _bits(getattr(rate, attr))
    return value, _rate_attrs(rate)


def _total(engine: Any, point: Any, key: str) -> Reading:
    totals = engine.totals.get(point.point_id) if point is not None else None
    value = None if totals is None else totals.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        value = None
    return value, {"since": "module_start", "source": SOURCE}


def _wan_total(engine: Any, router_id: str) -> Reading:
    return _total(engine, engine.wan_point(router_id), "bytes")


def _bucket_bps(bucket: Any, attr: str) -> float | None:
    value = getattr(bucket, attr)
    if value is None or bucket.coverage_ratio < MIN_BUCKET_COVERAGE:
        return None
    return value * 8 / bucket.resolution_s


def _wan_peak(engine: Any, router_id: str) -> Reading:
    point = engine.wan_point(router_id)
    attrs: dict[str, Any] = {
        "window": "24h",
        "resolution_s": PEAK_RESOLUTION_S,
        "upload_peak_bps": None,
        "source": SOURCE,
    }
    if point is None:
        return None, attrs
    win = engine.history_source.window(
        point.point_id,
        PEAK_WINDOW_S,
        end=engine.wall(),
        resolution_s=PEAK_RESOLUTION_S,
    )
    buckets = getattr(win, "buckets", None) or ()
    down = [v for b in buckets if (v := _bucket_bps(b, "rx_bytes")) is not None]
    up = [v for b in buckets if (v := _bucket_bps(b, "tx_bytes")) is not None]
    attrs["upload_peak_bps"] = _bits(max(up)) if up else None
    attrs["buckets"] = len(down)
    # 5-minute values are kept 6 h (compact) or 24 h (standard): the depth
    # actually held, never an hourly peak mixed in.
    depth = getattr(win, "depth_s", None)
    attrs["history_depth_s"] = None if depth is None else min(PEAK_WINDOW_S, int(depth))
    return (_bits(max(down)) if down else None), attrs


def _uplink_load(engine: Any, router_id: str) -> Reading:
    point, kind = engine.uplink_point(router_id)
    attrs: dict[str, Any] = {
        "uplink": kind,
        "link_mbps": None,
        "reason": None,
        "source": SOURCE,
    }
    if point is None:
        attrs["reason"] = kind
        return None, attrs
    link = engine.link_facts().get(point.point_id)
    mbps = getattr(link, "link_mbps", None)
    attrs["link_mbps"] = mbps
    rate = _rate_of(engine, point)
    known = (
        [] if rate is None else [v for v in (rate.rx_bps, rate.tx_bps) if v is not None]
    )
    if not mbps:
        attrs["reason"] = "link_speed_unknown"
        return None, attrs
    if not known:
        attrs["reason"] = "no_rate"
        return None, attrs
    return round(max(known) / (mbps * 1_000_000) * 100, 1), attrs


def _uplink_errors(engine: Any, router_id: str, key: str) -> Reading:
    point, kind = engine.uplink_point(router_id)
    value, attrs = _total(engine, point, key)
    attrs["uplink"] = kind
    return value, attrs


@dataclass(frozen=True, kw_only=True)
class TrafficRouterDescription(SensorEntityDescription):
    """A router sensor and how it reads the engine."""

    read: Callable[[Any, str], Reading]


ROUTER_SENSORS: dict[str, TrafficRouterDescription] = {
    d.key: d
    for d in (
        TrafficRouterDescription(
            key=KEY_WAN_DOWN,
            translation_key="traffic_wan_download",
            device_class=SensorDeviceClass.DATA_RATE,
            state_class=SensorStateClass.MEASUREMENT,
            native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
            suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
            suggested_display_precision=1,
            read=lambda engine, rid: _wan_rate(engine, rid, "rx_bps"),
        ),
        TrafficRouterDescription(
            key=KEY_WAN_UP,
            translation_key="traffic_wan_upload",
            device_class=SensorDeviceClass.DATA_RATE,
            state_class=SensorStateClass.MEASUREMENT,
            native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
            suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
            suggested_display_precision=1,
            read=lambda engine, rid: _wan_rate(engine, rid, "tx_bps"),
        ),
        TrafficRouterDescription(
            key=KEY_WAN_TOTAL,
            translation_key="traffic_wan_total",
            device_class=SensorDeviceClass.DATA_SIZE,
            state_class=SensorStateClass.TOTAL_INCREASING,
            native_unit_of_measurement=UnitOfInformation.BYTES,
            suggested_unit_of_measurement=UnitOfInformation.GIBIBYTES,
            suggested_display_precision=2,
            read=_wan_total,
        ),
        TrafficRouterDescription(
            key=KEY_WAN_PEAK,
            translation_key="traffic_wan_peak",
            device_class=SensorDeviceClass.DATA_RATE,
            state_class=SensorStateClass.MEASUREMENT,
            native_unit_of_measurement=UnitOfDataRate.BITS_PER_SECOND,
            suggested_unit_of_measurement=UnitOfDataRate.MEGABITS_PER_SECOND,
            suggested_display_precision=1,
            read=_wan_peak,
        ),
        TrafficRouterDescription(
            key=KEY_UPLINK_LOAD,
            translation_key="traffic_uplink_utilization",
            state_class=SensorStateClass.MEASUREMENT,
            native_unit_of_measurement=PERCENTAGE,
            suggested_display_precision=1,
            read=_uplink_load,
        ),
        TrafficRouterDescription(
            key=KEY_UPLINK_RX_ERRORS,
            translation_key="traffic_uplink_rx_errors",
            state_class=SensorStateClass.TOTAL_INCREASING,
            entity_category=EntityCategory.DIAGNOSTIC,
            entity_registry_enabled_default=False,
            read=lambda engine, rid: _uplink_errors(engine, rid, "rx_errors"),
        ),
        TrafficRouterDescription(
            key=KEY_UPLINK_TX_ERRORS,
            translation_key="traffic_uplink_tx_errors",
            state_class=SensorStateClass.TOTAL_INCREASING,
            entity_category=EntityCategory.DIAGNOSTIC,
            entity_registry_enabled_default=False,
            read=lambda engine, rid: _uplink_errors(engine, rid, "tx_errors"),
        ),
    )
}


def _anomalies(engine: Any) -> Reading:
    detector = engine.anomalies
    if not detector.counters.get("evaluations"):
        return None, {"withheld": ["no_evaluation"], "source": SOURCE}
    kinds: dict[str, int] = {}
    for candidate in detector.book.open.values():
        kinds[candidate.kind] = kinds.get(candidate.kind, 0) + 1
    return len(detector.book.open), {
        "kinds": dict(sorted(kinds.items())),
        "candidates_not_incidents": True,
        "source": SOURCE,
    }


def _coverage(engine: Any) -> Reading:
    by: dict[str, int] = {}
    for rate in engine.latest.values():
        by[rate.coverage.value] = by.get(rate.coverage.value, 0) + 1
    total = sum(by.values())
    attrs = {"points": total, **dict(sorted(by.items())), "source": SOURCE}
    if not total:
        return None, attrs
    return round(by.get("full", 0) / total * 100, 1), attrs


@dataclass(frozen=True, kw_only=True)
class TrafficFleetDescription(SensorEntityDescription):
    """A fleet sensor: unique id and how it reads the engine."""

    unique_id: str
    read: Callable[[Any], Reading]


FLEET_SENSORS: tuple[TrafficFleetDescription, ...] = (
    TrafficFleetDescription(
        key="traffic_anomalies",
        translation_key="fleet_traffic_anomalies",
        unique_id=UID_FLEET_TRAFFIC_ANOMALIES,
        state_class=SensorStateClass.MEASUREMENT,
        read=_anomalies,
    ),
    TrafficFleetDescription(
        key="traffic_coverage",
        translation_key="fleet_traffic_coverage",
        unique_id=UID_FLEET_TRAFFIC_COVERAGE,
        state_class=SensorStateClass.MEASUREMENT,
        native_unit_of_measurement=PERCENTAGE,
        suggested_display_precision=0,
        read=_coverage,
    ),
)


def _client(engine: Any, client_ref: str, direction: str) -> Reading:
    view = engine.client_view(client_ref)
    attrs: dict[str, Any] = {
        "perspective": "wifi_at_ap",
        "coverage": "unknown",
        "source": SOURCE,
    }
    if view is None:
        attrs["reason"] = "client_not_seen"
        return None, attrs
    attrs["coverage"] = view.coverage.value
    attrs["router_id"] = view.router_id  # pseudonym (rtr_...)
    value = view.down_bps if direction == "down" else view.up_bps
    return _bits(value), attrs


# --- entities -------------------------------------------------------------------------


class _TrafficSensor(SensorEntity):
    """Pushed by SIGNAL_TRAFFIC_ANALYTICS; no polling, no network.

    The values are computed once per push (``_refresh``), not on every
    property read.
    """

    _attr_has_entity_name = True
    _attr_should_poll = False
    _unrecorded_attributes = frozenset(
        {
            "buckets",
            "candidates_not_incidents",
            "coverage",
            "estimated",
            "full",
            "history_depth_s",
            "kinds",
            "link_mbps",
            "partial",
            "perspective",
            "points",
            "quality",
            "reason",
            "resolution_s",
            "router_id",
            "since",
            "source",
            "unavailable",
            "unknown",
            "upload_peak_bps",
            "uplink",
            "window",
            "withheld",
        }
    )

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(
            async_dispatcher_connect(
                self.hass, SIGNAL_TRAFFIC_ANALYTICS, self._handle_update
            )
        )
        self._refresh()

    @callback
    def _handle_update(self) -> None:
        self._refresh()
        self.async_write_ha_state()

    def _read(self, engine: Any) -> Reading | None:
        """(value, attributes), or None while the entity is unavailable."""
        raise NotImplementedError

    def _refresh(self) -> None:
        engine = _engine(self.hass)
        found: Reading | None = None
        if _active(engine):
            try:
                found = self._read(engine)
            except Exception as err:  # noqa: BLE001 - unknown, never a value
                _LOGGER.debug("Traffic sensor failed (%s)", type(err).__name__)
                found = (None, {"withheld": ["error"], "source": SOURCE})
        self._attr_available = found is not None
        self._attr_native_value = None if found is None else found[0]
        self._attr_extra_state_attributes = {} if found is None else found[1]


class TrafficFleetSensor(_TrafficSensor):
    """One fleet number of Traffic Analytics."""

    entity_description: TrafficFleetDescription

    def __init__(self, description: TrafficFleetDescription) -> None:
        self.entity_description = description
        self._attr_unique_id = description.unique_id
        self._attr_translation_key = description.translation_key

    def _read(self, engine: Any) -> Reading | None:
        return self.entity_description.read(engine)


class TrafficRouterSensor(_TrafficSensor):
    """One traffic figure of one router (on its existing device)."""

    entity_description: TrafficRouterDescription

    def __init__(self, entry_id: str, description: TrafficRouterDescription) -> None:
        self.entity_description = description
        self._entry_id = entry_id
        self._attr_unique_id = router_unique_id(entry_id, description.key)
        self._attr_translation_key = description.translation_key
        self._attr_device_info = DeviceInfo(identifiers={(DOMAIN, entry_id)})

    def _read(self, engine: Any) -> Reading | None:
        if not engine.entry_enabled(self._entry_id):
            return None
        router_id = engine.router_id_for_entry(self._entry_id)
        if router_id is None:
            return None
        return self.entity_description.read(engine, router_id)


class TrafficClientSensor(_TrafficSensor):
    """Wi-Fi traffic of one selected client at its AP (never "internet")."""

    _attr_device_class = SensorDeviceClass.DATA_RATE
    _attr_state_class = SensorStateClass.MEASUREMENT
    _attr_native_unit_of_measurement = UnitOfDataRate.BITS_PER_SECOND
    _attr_suggested_unit_of_measurement = UnitOfDataRate.MEGABITS_PER_SECOND
    _attr_suggested_display_precision = 1

    def __init__(self, client_ref: str, direction: str) -> None:
        self._client_ref = client_ref
        self._direction = direction
        self._attr_unique_id = client_unique_id(client_ref, direction)
        self._attr_translation_key = f"traffic_client_{direction}"
        self._attr_translation_placeholders = {"client": client_ref}

    def _read(self, engine: Any) -> Reading | None:
        if self._client_ref not in engine.client_sensor_refs:
            return None
        return _client(engine, self._client_ref, self._direction)


# --- hosting --------------------------------------------------------------------------


@dataclass(slots=True)
class _Hosts:
    """What is created where (entry ids, unique ids and pseudonyms only)."""

    anchor: str | None = None
    created: dict[str, set[str]] = field(default_factory=dict)
    clients: set[str] = field(default_factory=set)
    cleaned: set[str] = field(default_factory=set)  # entries cleaned while off
    was_active: bool = False
    unsub: Callable[[], None] | None = None
    syncing: bool = False


def _hosts(hass: HomeAssistant) -> _Hosts:
    hosts = hass.data.get(DATA_TRAFFIC_ENTITIES)
    if not isinstance(hosts, _Hosts):
        hosts = _Hosts()
        hass.data[DATA_TRAFFIC_ENTITIES] = hosts
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


def router_keys(engine: Any, router_id: str) -> list[str]:
    """Keys a router gets now: WAN only on a gateway, uplink only if known."""
    keys: list[str] = []
    if engine.wan_point(router_id) is not None:
        keys.extend(WAN_KEYS)
    point, _kind = engine.uplink_point(router_id)
    if point is not None:
        link = engine.link_facts().get(point.point_id)
        if getattr(link, "link_mbps", None):
            keys.append(KEY_UPLINK_LOAD)
        keys.extend(UPLINK_KEYS)
    return keys


def _wanted(hass: HomeAssistant, engine: Any) -> dict[str, list[str]]:
    """Entry -> missing router keys (traffic on, device exists, platform loaded)."""
    hosts = _hosts(hass)
    sensors = _sensor_platforms(hass)
    out: dict[str, list[str]] = {}
    for entry_id in sorted(engine.enabled_entries):
        router_id = engine.router_id_for_entry(entry_id)
        if router_id is None or entry_id not in sensors:
            continue
        done = hosts.created.get(entry_id, set())
        missing = [
            k
            for k in router_keys(engine, router_id)
            if router_unique_id(entry_id, k) not in done
        ]
        if missing and _device_exists(hass, entry_id):
            out[entry_id] = missing
    return out


def _wanted_clients(engine: Any) -> set[str]:
    return set(list(engine.client_sensor_refs)[:TRAFFIC_CLIENT_SENSORS_MAX])


def _all_entries_off(hass: HomeAssistant) -> bool:
    """No config entry of the domain has traffic on (read only)."""
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
        return not any(
            getattr(e, "options", {}).get(OPTION_TRAFFIC_ENABLED) is True
            for e in entries
        )
    except Exception:  # noqa: BLE001 - unknown: remove nothing
        return False


async def async_sync_traffic_entities(hass: HomeAssistant) -> None:
    """Create the set where traffic is on; remove it where it is off.

    Before the engine is loaded nothing happens. Registry entries of an
    entry are removed only for that entry's own switch being off (an entry
    not loaded yet keeps its entries), the fleet and client sensors only on
    an on -> off change or when every entry of the domain has traffic off.
    """
    engine = _engine(hass)
    if engine is None or not getattr(engine, "loaded", False):
        return
    hosts = _hosts(hass)
    if hosts.unsub is None:

        @callback
        def _receiver() -> None:
            # @callback: HA runs it on the loop (a lambda is an executor job)
            _on_update(hass)

        hosts.unsub = async_dispatcher_connect(
            hass, SIGNAL_TRAFFIC_ANALYTICS, _receiver
        )
    for entry_id in engine.entry_ids:
        if engine.entry_enabled(entry_id):
            hosts.cleaned.discard(entry_id)
        elif entry_id not in hosts.cleaned:
            hosts.created.pop(entry_id, None)
            _remove_router(hass, entry_id)
            hosts.cleaned.add(entry_id)
    if not _active(engine):
        if hosts.was_active or hosts.anchor is not None or _all_entries_off(hass):
            _remove_fleet(hass, hosts.clients)
        hosts.anchor = None
        hosts.clients.clear()
        hosts.was_active = False
        return
    hosts.was_active = True
    sensors = _sensor_platforms(hass)
    if sensors and (hosts.anchor is None or hosts.anchor not in sensors):
        anchor = min(sensors)
        hosts.anchor = anchor
        hosts.clients.clear()  # they lived on the old anchor's platform
        await sensors[anchor].async_add_entities(
            [TrafficFleetSensor(d) for d in FLEET_SENSORS]
        )
    if hosts.anchor is not None:
        wanted = _wanted_clients(engine)
        gone = hosts.clients - wanted
        if gone:
            _remove_clients(hass, gone)
            hosts.clients -= gone
        new = sorted(wanted - hosts.clients)
        if new:
            hosts.clients.update(new)
            await sensors[hosts.anchor].async_add_entities(
                [TrafficClientSensor(r, d) for r in new for d in CLIENT_DIRECTIONS]
            )
    for entry_id, keys in _wanted(hass, engine).items():
        hosts.created.setdefault(entry_id, set()).update(
            router_unique_id(entry_id, k) for k in keys
        )
        await sensors[entry_id].async_add_entities(
            [TrafficRouterSensor(entry_id, ROUTER_SENSORS[k]) for k in keys]
        )


def _needs_sync(hass: HomeAssistant, engine: Any, hosts: _Hosts) -> bool:
    if any(
        not engine.entry_enabled(e) and e not in hosts.cleaned for e in engine.entry_ids
    ):
        return True
    if not _active(engine):
        return hosts.was_active or hosts.anchor is not None
    if hosts.anchor is None and _sensor_platforms(hass):
        return True
    if hosts.anchor is not None and hosts.clients != _wanted_clients(engine):
        return True
    return bool(_wanted(hass, engine))


@callback
def _on_update(hass: HomeAssistant) -> None:
    """After a poll or a change: create what is missing, remove what is off."""
    hosts = hass.data.get(DATA_TRAFFIC_ENTITIES)
    engine = _engine(hass)
    if not isinstance(hosts, _Hosts) or engine is None or hosts.syncing:
        return
    try:
        if not _needs_sync(hass, engine, hosts):
            return
    except Exception as err:  # noqa: BLE001 - next update tries again
        _LOGGER.debug("Traffic entity check failed (%s)", type(err).__name__)
        return
    hosts.syncing = True

    async def run() -> None:
        try:
            await async_sync_traffic_entities(hass)
        except Exception as err:  # noqa: BLE001 - next update tries again
            _LOGGER.warning("Traffic entities not updated (%s)", type(err).__name__)
        finally:
            hosts.syncing = False

    job = run()
    try:
        hass.async_create_task(job, name="openwrt_router traffic entities")
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


def _remove_unique_ids(hass: HomeAssistant, unique_ids: list[str]) -> None:
    """Remove exactly these unique ids (HA removes live entities too)."""
    registry = _registry(hass)
    if registry is None:
        return
    for unique_id in unique_ids:
        entity_id = registry.async_get_entity_id(SENSOR_DOMAIN, DOMAIN, unique_id)
        if entity_id is not None:
            registry.async_remove(entity_id)


def _remove_router(hass: HomeAssistant, entry_id: str) -> None:
    """Traffic off on one router: drop its known entities (exact ids only)."""
    _remove_unique_ids(hass, [router_unique_id(entry_id, k) for k in ROUTER_KEYS])


def _remove_clients(hass: HomeAssistant, refs: set[str]) -> None:
    _remove_unique_ids(
        hass, [client_unique_id(r, d) for r in sorted(refs) for d in CLIENT_DIRECTIONS]
    )


def _remove_fleet(hass: HomeAssistant, known_clients: set[str]) -> None:
    """Traffic off everywhere: drop the fleet and every client sensor."""
    _remove_unique_ids(hass, list(FLEET_UNIQUE_IDS))
    _remove_clients(hass, known_clients)
    registry = _registry(hass)
    if registry is None:
        return
    for entity in list(registry.entities.values()):
        if (
            entity.platform == DOMAIN
            and entity.domain == SENSOR_DOMAIN
            and isinstance(entity.unique_id, str)
            and entity.unique_id.startswith(UID_FLEET_TRAFFIC_CLIENT_PREFIX)
        ):
            registry.async_remove(entity.entity_id)


async def async_entry_released(
    hass: HomeAssistant, entry_id: str, *, last: bool
) -> None:
    """The entry is unloaded (its platforms are gone): move the fleet host.

    ``last``: no entry is left; the registry entries stay for the next
    start (the routers' switches decide then).
    """
    hosts = hass.data.get(DATA_TRAFFIC_ENTITIES)
    if not isinstance(hosts, _Hosts):
        return
    hosts.created.pop(entry_id, None)
    hosts.cleaned.discard(entry_id)
    if last:
        if hosts.unsub is not None:
            hosts.unsub()
        hass.data.pop(DATA_TRAFFIC_ENTITIES, None)
        return
    if hosts.anchor == entry_id:
        hosts.anchor = None
        hosts.clients.clear()
        await async_sync_traffic_entities(hass)


__all__ = [
    "FLEET_SENSORS",
    "FLEET_UNIQUE_IDS",
    "ROUTER_KEYS",
    "ROUTER_SENSORS",
    "TrafficClientSensor",
    "TrafficFleetSensor",
    "TrafficRouterSensor",
    "async_entry_released",
    "async_sync_traffic_entities",
    "client_unique_id",
    "platforms_of",
    "router_keys",
    "router_unique_id",
]
