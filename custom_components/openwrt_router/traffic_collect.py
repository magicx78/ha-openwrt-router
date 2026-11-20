"""Traffic data collection (plan 2026-11-20, §6).

Two parts, no Home Assistant import:

* **Stage A-standard** (0 extra router calls): :func:`snapshot_from_data`
  copies the few fields traffic needs out of one ``coordinator.data``
  (synchronously, in the coordinator listener) into a small frozen
  :class:`Snapshot`; :func:`samples_from_snapshot` turns it into samples.
  Client MACs are turned into ``client_ref`` (module key) during the copy,
  so no MAC, IP or host name ever enters a traffic structure. Without the
  module key no station is copied ("not ready", never a silent fallback).
* **Stage A-switchable**: :class:`ExtraCallPlanner` decides whether one of
  the three optional calls (station detail, sysfs fallback, offload probe)
  may run now and runs it with the limits of §6.2: at most one traffic call
  per router, at most two overall (semaphore), a hard timeout, never while
  the router's poll runs, while it is throttled or on the SSH fallback, and
  a one-hour pause after three failures in a row. The calls themselves are
  methods of ``api.py``; this module only passes callables through.

Everything is O(devices + stations) per poll and holds no large copies.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from .core_masking import pseudonymise_identifier
from .traffic_const import (
    BLOCK_BUSY,
    BLOCK_COVERED,
    BLOCK_DISABLED,
    BLOCK_NOT_DUE,
    BLOCK_PAUSED,
    BLOCK_POLL_RUNNING,
    BLOCK_POLL_SOON,
    BLOCK_SSH_FALLBACK,
    BLOCK_THROTTLED,
    CONNTRACK_SOURCE_COUNT_FILE,
    EXTRA_CALL_POLL_MARGIN_S,
    EXTRA_CALL_TIMEOUT_S,
    EXTRA_FAILURES_BEFORE_PAUSE,
    EXTRA_PAUSE_S,
    INTERVAL_OF_OPTION,
    MAX_AP_INTERFACES,
    MAX_DEVICES_PER_ROUTER,
    MAX_EXTRA_CALLS_TOTAL,
    MAX_STATIONS_PER_REPLY,
    MAX_STATIONS_PER_ROUTER,
    MAX_SYSFS_DEVICES,
    MAX_UPLINK_PORTS,
    VLAN_NETDEV_RE,
)
from .traffic_counters import as_counter, finite_time, known_uptime
from .traffic_model import (
    COUNTER_FIELDS,
    MeasurementPoint,
    Sample,
    Scope,
    Source,
    valid_device_name,
)

_LOGGER = logging.getLogger(__name__)

_SPEED_RE: Final = re.compile(r"^([0-9]{1,7})([FfHh]?)$")


def parse_speed(raw: Any) -> tuple[int | None, str | None]:
    """``(Mbit/s, duplex)`` from a netifd speed (``"1000F"``); unknown -> None."""
    if isinstance(raw, bool):
        return None, None
    if isinstance(raw, int):
        return (raw if raw > 0 else None), None
    if not isinstance(raw, str):
        return None, None
    match = _SPEED_RE.fullmatch(raw.strip())
    if match is None:
        return None, None
    mbps = int(match.group(1))
    duplex = {"f": "full", "h": "half"}.get(match.group(2).lower())
    return (mbps if mbps > 0 else None), duplex


def vlan_id_of(device: str) -> int | None:
    """VLAN id of a VLAN netdev name (``br-lan.10`` -> 10), else None."""
    match = VLAN_NETDEV_RE.fullmatch(device)
    if match is None:
        return None
    vid = int(match.group(1))
    return vid if 1 <= vid <= 4094 else None


def client_ref_of(mac: Any, module_key: bytes) -> str | None:
    """Core pseudonym ``cli_<16 hex>`` of a client MAC, None if not a MAC."""
    if not isinstance(mac, str) or not mac:
        return None
    try:
        return pseudonymise_identifier("client", mac, module_key)
    except (TypeError, ValueError):
        return None


# --- snapshot (copied in the coordinator listener) ------------------------------------


@dataclass(frozen=True, slots=True)
class DeviceCounters:
    """Raw counters of one netdev of one poll (``COUNTER_FIELDS`` order)."""

    name: str
    counters: tuple[int | None, ...]
    link_mbps: int | None = None
    duplex: str | None = None
    up: bool | None = None
    carrier: bool | None = None


@dataclass(frozen=True, slots=True)
class StationCounters:
    """Byte counters of one Wi-Fi station at one AP interface (pseudonymised)."""

    radio_id: str
    client_ref: str
    rx_bytes: int | None
    tx_bytes: int | None
    rx_packets: int | None = None
    tx_packets: int | None = None


@dataclass(frozen=True, slots=True)
class Snapshot:
    """What traffic takes from one poll of one router (plan §6.1).

    ``devices`` is None when the poll brought no netdev counters (source
    missing), ``stations`` is None when the module key is missing (not
    ready). ``conntrack_count`` is only set when the count came from the
    count file (§14.1 F2), never from a table scan or an error default.
    """

    router_id: str
    mono_s: float | None
    wall_s: float | None
    uptime_s: int | None
    stale: bool
    wan_device: str | None
    devices: tuple[DeviceCounters, ...] | None
    port_names: frozenset[str] = frozenset()
    stations: tuple[StationCounters, ...] | None = None
    stations_total: int = 0
    stations_without_bytes: int = 0
    stations_dropped: int = 0
    invalid_items: int = 0
    ap_interfaces: tuple[str, ...] = ()
    interface_devices: tuple[str, ...] = ()
    conntrack_count: int | None = None
    # Ports of this router that lead to another router (topology trunk
    # ports, names only); None when the poll carried no topology field.
    uplink_ports: frozenset[str] | None = None

    @property
    def device_names(self) -> frozenset[str]:
        """Netdevs with counters in this poll."""
        return frozenset(d.name for d in self.devices or ())


def _bool_or_none(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _devices_from(
    raw: Any, port_links: Mapping[str, tuple[int | None, str | None]]
) -> tuple[tuple[DeviceCounters, ...] | None, int]:
    if not isinstance(raw, Mapping) or not raw:
        return None, 0
    out: list[DeviceCounters] = []
    invalid = 0
    for name in sorted(n for n in raw if isinstance(n, str))[:MAX_DEVICES_PER_ROUTER]:
        dev = raw.get(name)
        if not valid_device_name(name) or not isinstance(dev, Mapping):
            invalid += 1
            continue
        link, duplex = port_links.get(name) or parse_speed(dev.get("speed"))
        out.append(
            DeviceCounters(
                name=name,
                counters=tuple(as_counter(dev.get(f)) for f in COUNTER_FIELDS),
                link_mbps=link,
                duplex=duplex,
                up=_bool_or_none(dev.get("up")),
                carrier=_bool_or_none(dev.get("carrier")),
            )
        )
    return tuple(out), invalid


def _port_links(port_stats: Any) -> dict[str, tuple[int | None, str | None]]:
    links: dict[str, tuple[int | None, str | None]] = {}
    for port in port_stats if isinstance(port_stats, list) else ():
        if not isinstance(port, Mapping):
            continue
        name = port.get("name")
        if not valid_device_name(name):
            continue
        mbps = port.get("speed_mbps")
        duplex = port.get("duplex")
        links[name] = (
            mbps
            if isinstance(mbps, int) and not isinstance(mbps, bool) and mbps > 0
            else None,
            duplex if duplex in ("full", "half") else None,
        )
    return links


def _uplink_ports(trunk_map: Any) -> frozenset[str] | None:
    """Port names of the topology trunk map (its keys are hosts: not copied).

    # Entscheidung: ``trunk_port_map`` (gateway port per downstream AP) is
    # the topology's answer to "which port leads to another router"; an
    # empty map means "none known", a missing field means "unknown".
    """
    if not isinstance(trunk_map, Mapping):
        return None
    ports = sorted({p for p in trunk_map.values() if valid_device_name(p)})
    return frozenset(ports[:MAX_UPLINK_PORTS])


def _names(items: Any, key: str) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for item in items if isinstance(items, list) else ():
        name = item.get(key) if isinstance(item, Mapping) else None
        if valid_device_name(name):
            seen.setdefault(name, None)
    return tuple(seen)


def _stations_from(
    clients: Any, module_key: bytes
) -> tuple[tuple[StationCounters, ...], int, int, int, int]:
    """(stations, total, without bytes, dropped over the cap, invalid)."""
    out: list[StationCounters] = []
    total = without = dropped = invalid = 0
    for client in clients if isinstance(clients, list) else ():
        if not isinstance(client, Mapping):
            invalid += 1
            continue
        total += 1
        rx = as_counter(client.get("rx_bytes"))
        tx = as_counter(client.get("tx_bytes"))
        if rx is None and tx is None:
            without += 1  # iwinfo/SSH fallback: no bytes, "not available"
            continue
        if len(out) >= MAX_STATIONS_PER_ROUTER:
            dropped += 1
            continue
        radio = client.get("radio")
        ref = client_ref_of(client.get("mac"), module_key)
        if not valid_device_name(radio) or ref is None:
            invalid += 1
            continue
        out.append(
            StationCounters(radio_id=radio, client_ref=ref, rx_bytes=rx, tx_bytes=tx)
        )
    return tuple(out), total, without, dropped, invalid


def snapshot_from_data(
    data: Any,
    *,
    router_id: str,
    module_key: bytes | None,
    wall_s: float | None,
) -> Snapshot:
    """Copy the traffic inputs of one ``coordinator.data`` (sync, O(n)).

    Reads only attributes; a missing or malformed attribute gives None /
    empty, never an exception. Large structures are not copied: per device
    one tuple of eight ints, per station two refs and two ints.
    """
    port_stats = getattr(data, "port_stats", None)
    port_links = _port_links(port_stats)
    devices, invalid = _devices_from(getattr(data, "device_counters", None), port_links)
    wan = getattr(data, "wan_status", None)
    wan_device = wan.get("l3_device") if isinstance(wan, Mapping) else None
    if not valid_device_name(wan_device):
        wan_device = None
    stations: tuple[StationCounters, ...] | None = None
    total = without = dropped = 0
    if module_key is not None:
        stations, total, without, dropped, bad = _stations_from(
            getattr(data, "clients", None), module_key
        )
        invalid += bad
    else:
        clients = getattr(data, "clients", None)
        total = len(clients) if isinstance(clients, list) else 0
    conntrack = None
    if getattr(data, "active_connections_source", None) == CONNTRACK_SOURCE_COUNT_FILE:
        conntrack = as_counter(getattr(data, "active_connections", None))
    return Snapshot(
        router_id=router_id,
        mono_s=finite_time(getattr(data, "counters_sampled_mono", None)),
        wall_s=finite_time(wall_s),
        uptime_s=known_uptime(getattr(data, "uptime", None)),
        stale=getattr(data, "vlans_stale", False) is True,
        wan_device=wan_device,
        devices=devices,
        port_names=frozenset(port_links),
        stations=stations,
        stations_total=total,
        stations_without_bytes=without,
        stations_dropped=dropped,
        invalid_items=invalid,
        ap_interfaces=_names(getattr(data, "ap_interfaces", None), "ifname"),
        interface_devices=_names(
            getattr(data, "network_interfaces", None), "interface"
        ),
        conntrack_count=conntrack,
        uplink_ports=_uplink_ports(getattr(data, "trunk_port_map", None)),
    )


def scope_of(name: str, *, wan_device: str | None, port_names: frozenset[str]) -> Scope:
    """Scope of a netdev: WAN device, VLAN netdev, switch port or interface."""
    if wan_device is not None and name == wan_device:
        return Scope.WAN
    if vlan_id_of(name) is not None:
        return Scope.VLAN
    if name in port_names:
        return Scope.PORT
    return Scope.INTERFACE


def device_point(
    router_id: str, name: str, *, wan_device: str | None, port_names: frozenset[str]
) -> MeasurementPoint:
    """Measuring point of a netdev (a VLAN netdev carries its VLAN id)."""
    scope = scope_of(name, wan_device=wan_device, port_names=port_names)
    return MeasurementPoint(
        router_id,
        scope,
        device=name,
        vlan_id=vlan_id_of(name) if scope is Scope.VLAN else None,
    )


def samples_from_snapshot(snapshot: Snapshot) -> list[Sample]:
    """Samples of all netdevs and stations of ``snapshot``.

    The WAN device comes first, so the per-router quota never refuses it.
    """
    samples: list[Sample] = []
    devices = sorted(
        snapshot.devices or (), key=lambda d: (d.name != snapshot.wan_device, d.name)
    )
    for dev in devices:
        point = device_point(
            snapshot.router_id,
            dev.name,
            wan_device=snapshot.wan_device,
            port_names=snapshot.port_names,
        )
        samples.append(
            Sample(
                point,
                snapshot.mono_s,
                snapshot.wall_s,
                *dev.counters,
                link_mbps=dev.link_mbps,
                duplex=dev.duplex,
                source=Source.NETDEV,
                router_uptime_s=snapshot.uptime_s,
            )
        )
    for sta in snapshot.stations or ():
        samples.append(
            station_sample(snapshot.router_id, sta, snapshot, Source.HOSTAPD)
        )
    return samples


def station_sample(
    router_id: str,
    sta: StationCounters,
    timing: Snapshot | ExtraTiming,
    source: Source,
) -> Sample:
    """Sample of one station (perspective: the AP's view of the client)."""
    point = MeasurementPoint(
        router_id, Scope.STATION, radio_id=sta.radio_id, client_ref=sta.client_ref
    )
    return Sample(
        point,
        timing.mono_s,
        timing.wall_s,
        rx_bytes=sta.rx_bytes,
        tx_bytes=sta.tx_bytes,
        rx_packets=sta.rx_packets,
        tx_packets=sta.tx_packets,
        source=source,
        router_uptime_s=timing.uptime_s,
    )


# --- results of the switchable calls --------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExtraTiming:
    """Time of an extra call's reply (monotonic, wall, estimated uptime)."""

    mono_s: float | None
    wall_s: float | None
    uptime_s: int | None


def estimated_uptime(snapshot: Snapshot | None, mono_s: float) -> int | None:
    """Router uptime at ``mono_s`` from the last snapshot (None if unknown).

    # Entscheidung: extra calls carry no uptime of their own; the last
    # poll's uptime plus the elapsed monotonic time keeps rule 4 working.
    """
    if snapshot is None or snapshot.uptime_s is None or snapshot.mono_s is None:
        return None
    elapsed = mono_s - snapshot.mono_s
    if elapsed < 0:
        return None
    return snapshot.uptime_s + int(elapsed)


def stations_from_detail(
    reply: Mapping[str, Any], module_key: bytes, *, skip_refs: Iterable[str] = ()
) -> tuple[list[StationCounters], int]:
    """Stations of an ``async_traffic_station_detail`` reply (pseudonymised).

    Stations that already have hostapd bytes this poll (``skip_refs``) are
    left out, so one point never alternates between two sources. Returns
    (stations, invalid items).
    """
    skip = set(skip_refs)
    out: list[StationCounters] = []
    invalid = 0
    for radio, entries in reply.items() if isinstance(reply, Mapping) else ():
        if not valid_device_name(radio) or not isinstance(entries, list):
            invalid += 1
            continue
        for entry in entries[:MAX_STATIONS_PER_REPLY]:
            if not isinstance(entry, Mapping):
                invalid += 1
                continue
            ref = client_ref_of(entry.get("mac"), module_key)
            if ref is None:
                invalid += 1
                continue
            if ref in skip:
                continue
            rx, tx = (
                as_counter(entry.get("rx_bytes")),
                as_counter(entry.get("tx_bytes")),
            )
            if rx is None and tx is None:
                continue
            out.append(
                StationCounters(
                    radio_id=radio,
                    client_ref=ref,
                    rx_bytes=rx,
                    tx_bytes=tx,
                    rx_packets=as_counter(entry.get("rx_packets")),
                    tx_packets=as_counter(entry.get("tx_packets")),
                )
            )
    return out, invalid


def sysfs_samples(
    router_id: str,
    reply: Mapping[str, Any],
    timing: ExtraTiming,
    *,
    wan_device: str | None,
    port_names: frozenset[str],
) -> list[Sample]:
    """Samples of an ``async_traffic_sysfs_counters`` reply (source sysfs)."""
    samples: list[Sample] = []
    for name, counters in reply.items() if isinstance(reply, Mapping) else ():
        if not valid_device_name(name) or not isinstance(counters, Mapping):
            continue
        point = device_point(
            router_id, name, wan_device=wan_device, port_names=port_names
        )
        samples.append(
            Sample(
                point,
                timing.mono_s,
                timing.wall_s,
                *(as_counter(counters.get(f)) for f in COUNTER_FIELDS),
                source=Source.SYSFS,
                router_uptime_s=timing.uptime_s,
            )
        )
    return samples


@dataclass(frozen=True, slots=True)
class OffloadState:
    """Flow offloading of the router's firewall (None = unknown)."""

    software: bool | None
    hardware: bool | None

    @property
    def known(self) -> bool:
        """True when both values are known."""
        return self.software is not None and self.hardware is not None


def offload_from_reply(reply: Any) -> OffloadState:
    """``OffloadState`` from an ``async_traffic_offload_state`` reply."""
    if not isinstance(reply, Mapping):
        return OffloadState(None, None)
    sw, hw = reply.get("flow_offloading"), reply.get("flow_offloading_hw")
    return OffloadState(_bool_or_none(sw), _bool_or_none(hw))


def sysfs_candidates(snapshot: Snapshot) -> tuple[str, ...]:
    """Netdevs the sysfs fallback may read: known but without Q1 counters.

    Only names from the poll's own interface list and its WAN device (never
    from user input); at most ``MAX_SYSFS_DEVICES``.
    """
    have = snapshot.device_names
    wanted: dict[str, None] = {}
    if snapshot.wan_device is not None:
        wanted[snapshot.wan_device] = None
    for name in snapshot.interface_devices:
        wanted.setdefault(name, None)
    out = [n for n in wanted if n not in have and valid_device_name(n)]
    return tuple(out[:MAX_SYSFS_DEVICES])


def detail_candidates(snapshot: Snapshot) -> tuple[str, ...]:
    """AP interfaces for the station detail call (at most ``MAX_AP_INTERFACES``)."""
    return tuple(n for n in snapshot.ap_interfaces if valid_device_name(n))[
        :MAX_AP_INTERFACES
    ]


# --- planner of the switchable calls ----------------------------------------------------


@dataclass(slots=True)
class CallState:
    """State of one switchable call of one router (memory only)."""

    last_start_mono: float | None = None
    last_ok_mono: float | None = None
    failures: int = 0
    paused_until: float | None = None
    last_error: str | None = None  # exception type name only
    runs: int = 0

    def paused(self, now_mono: float) -> bool:
        """True while the one-hour pause after repeated failures runs."""
        return self.paused_until is not None and now_mono < self.paused_until


@dataclass(frozen=True, slots=True)
class PollState:
    """What the planner needs to know about a router's poll right now."""

    poll_running: bool
    throttled: bool
    ssh_fallback: bool
    seconds_to_next_poll: float | None


@dataclass(slots=True)
class CallOutcome:
    """Result of :meth:`ExtraCallPlanner.run`."""

    ok: bool
    value: Any = None
    error: str | None = None
    permission_denied: bool = False


@dataclass(slots=True)
class ExtraCallPlanner:
    """Limits of the switchable calls (plan §6.2), shared by all routers."""

    max_parallel: int = MAX_EXTRA_CALLS_TOTAL
    timeout_s: float = EXTRA_CALL_TIMEOUT_S
    states: dict[tuple[str, str], CallState] = field(default_factory=dict)
    busy: set[str] = field(default_factory=set)
    in_flight: int = 0
    peak_in_flight: int = 0
    counters: dict[str, int] = field(
        default_factory=lambda: {
            "extra_calls": 0,
            "extra_failures": 0,
            "extra_pauses": 0,
        }
    )
    _semaphore: asyncio.Semaphore | None = None

    def state(self, router_id: str, option: str) -> CallState:
        """State of ``option`` for ``router_id`` (created on first use)."""
        key = (router_id, option)
        state = self.states.get(key)
        if state is None:
            state = self.states[key] = CallState()
        return state

    def peek(self, router_id: str, option: str) -> CallState | None:
        """State if one exists (never creates one)."""
        return self.states.get((router_id, option))

    def blocked_reason(
        self,
        router_id: str,
        option: str,
        now_mono: float,
        *,
        enabled: bool,
        poll: PollState,
        covered: bool = False,
    ) -> str | None:
        """Why ``option`` may not run now for ``router_id`` (None: it may).

        Checked in this order: switched off, covered by another module,
        paused, SSH fallback, throttled, poll running, next poll too close,
        another traffic call of the router in flight, not due yet.
        """
        if not enabled:
            return BLOCK_DISABLED
        if covered:
            return BLOCK_COVERED
        state = self.peek(router_id, option)
        if state is not None and state.paused(now_mono):
            return BLOCK_PAUSED
        if poll.ssh_fallback:
            return BLOCK_SSH_FALLBACK
        if poll.throttled:
            return BLOCK_THROTTLED
        if poll.poll_running:
            return BLOCK_POLL_RUNNING
        if (
            poll.seconds_to_next_poll is None
            or poll.seconds_to_next_poll < EXTRA_CALL_POLL_MARGIN_S
        ):
            return BLOCK_POLL_SOON
        if router_id in self.busy:
            return BLOCK_BUSY
        interval = INTERVAL_OF_OPTION.get(option)
        if interval is None:
            return BLOCK_DISABLED
        if (
            state is not None
            and state.last_start_mono is not None
            and 0 <= now_mono - state.last_start_mono < interval
        ):
            return BLOCK_NOT_DUE
        return None

    def reserve(self, router_id: str, option: str, now_mono: float) -> None:
        """Mark the router busy and the call started (before any await)."""
        self.busy.add(router_id)
        state = self.state(router_id, option)
        state.last_start_mono = now_mono
        state.runs += 1

    async def run(
        self,
        router_id: str,
        option: str,
        call: Callable[[], Awaitable[Any]],
        *,
        clock: Callable[[], float],
        permission_errors: Sequence[type[BaseException]] = (),
    ) -> CallOutcome:
        """Run one reserved call within the global limit and the timeout.

        Never raises (cancellation excepted): an error is counted, and the
        third failure in a row pauses the option for an hour.
        """
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.max_parallel)
        state = self.state(router_id, option)
        try:
            async with self._semaphore:
                self.in_flight += 1
                self.peak_in_flight = max(self.peak_in_flight, self.in_flight)
                try:
                    async with asyncio.timeout(self.timeout_s):
                        value = await call()
                finally:
                    self.in_flight -= 1
        except asyncio.CancelledError:
            raise
        except Exception as err:  # noqa: BLE001 - counted, never reaches the poll
            name = type(err).__name__
            self.counters["extra_failures"] += 1
            state.failures += 1
            state.last_error = name
            if state.failures >= EXTRA_FAILURES_BEFORE_PAUSE:
                state.paused_until = clock() + EXTRA_PAUSE_S
                self.counters["extra_pauses"] += 1
            denied = bool(permission_errors) and isinstance(
                err, tuple(permission_errors)
            )
            return CallOutcome(False, error=name, permission_denied=denied)
        finally:
            self.busy.discard(router_id)
        self.counters["extra_calls"] += 1
        state.failures = 0
        state.paused_until = None
        state.last_error = None
        state.last_ok_mono = clock()
        return CallOutcome(True, value)

    def drop_router(self, router_id: str) -> None:
        """Forget the call states of an unloaded router."""
        for key in [k for k in self.states if k[0] == router_id]:
            del self.states[key]
        self.busy.discard(router_id)
