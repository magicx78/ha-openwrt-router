"""Traffic accounting: measuring areas, RX/TX meaning, coverage, sums (Phase C).

Plan 2026-11-20 §3.5, matrix §4/§5. Pure functions plus one bounded book;
no Home Assistant import, no I/O, no clock reads (times come from the rates).

**Seven measuring areas** (``Scope``), kept apart on purpose:

========== ==================================================================
interface  a router netdev (``br-lan``, ``eth0``, a Wi-Fi netdev)
port       a switch/Ethernet port (DSA user port)
station    one Wi-Fi association as the AP counts it (hostapd/iwinfo)
client     a client as a whole (all its associations, Phase D)
vlan       a measured VLAN netdev (``br-lan.10``), never configuration
flow       a flow record (needs a flow source, Phase E)
wan        the WAN ``l3_device`` of a gateway
========== ==================================================================

**RX/TX** always mean what the counting device saw (:func:`direction_map`):
router netdevs and ports count from the router's side, stations from the
AP's side of the client. Download/upload exist only where the mapping is
unambiguous: WAN (download = RX), station/client (download = TX, the AP
sends to the client), a port only with a known role. Bridges, VLAN netdevs
and plain interfaces give RX/TX only (bridged port-to-port traffic never
crosses the bridge device, routed inter-VLAN traffic crosses two of them).

**Coverage** (:func:`classify`) of a valid rate:

* WAN, interface, VLAN: hardware flow offloading moves packets past the
  kernel netdevs. Offload state unknown -> ``partial``/``hw_offload_unknown``;
  hardware offload on -> ``partial``/``hw_offload_on``; known off -> ``full``.
* port: ``full`` (the switch counts the port; whether DSA counts hardware
  switched frames is an assumption, sums carry a note).
* station/client: ``partial``/``station_counters_only`` (the AP's view of
  one association; local Wi-Fi traffic included, roaming losses not).
* flow: ``unavailable``/``needs_flow_source`` until a flow source exists.
* NAT: WAN counters show the traffic at the line after NAT. Which client
  caused it can only come from a flow source: :func:`wan_client_attribution`
  is ``unavailable``/``needs_flow_source``.

**Sums** (:func:`sum_rates`) only inside one area and without overlap: WAN
across gateways (one WAN point per router), ports of one router when none
is a known trunk port to another router, distinct clients or stations.
Station + port, interface + VLAN, client + WAN and bridge + ports are
refused with their own reason; every other mix with ``mixed_scopes``. A sum
never adds RX and TX together and always says how many points contributed,
how many were left out (and why) and what coverage the result has.

**Duplicate sightings** (:class:`SightingBook`): a client listed at two
associations within ``SIGHTING_WINDOW_S`` counts only at one of them: the
router the client registry names as current, else the newest association.
The other rate becomes ``stale_source`` (no values, nothing is added).

Plausibility checks and their limits
------------------------------------

Checked (here and in ``traffic_counters``):

* every counter is an ``int >= 0``; a decrease is a reset (or a plausible
  32-bit wrap for station counters), never a negative rate;
* a rate above the link limit (``link x 1.05``; start values without link
  speed) is ``implausible`` and dropped, half duplex counts RX + TX;
* intervals below 5 s are skipped, above 900 s or over a stale poll are a
  gap; a router restart resets every point of the router;
* one client counts at one association per sighting window only;
* sums never cross areas, never repeat a point, a WAN router or a client,
  and never add up overlapping interfaces or VLAN netdevs.

Not checked / limits of accuracy:

* offloaded flows are missing from netdev counters to an unknown extent
  (only flagged, never estimated);
* station counters include 802.11 overhead and local Wi-Fi traffic
  (station to station is RX at one AP and TX at the other); hostapd
  direction and bit width are assumptions not checked on a device;
* bytes between the last read and a roam or a reset are lost (gap);
* a poll interval of 60-300 s averages bursts: peaks shorter than one
  interval are invisible;
* the link limit is a ceiling, not a model: values just below it pass;
* the topology trunk map is the only uplink source; an unlisted trunk port
  is not detected.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from .traffic_collect import OffloadState
from .traffic_const import (
    DIR_AMBIGUOUS_BRIDGE,
    DIR_FLOW_DIRECTION,
    DIR_PORT_ROLE_UNKNOWN,
    MAX_ASSOC_PER_CLIENT,
    MAX_SIGHTING_CLIENTS,
    NOTE_DIRECTION_MISSING,
    NOTE_POINTS_OMITTED,
    NOTE_PORT_COUNTERS_UNVERIFIED,
    NOTE_RX_TX_SEPARATE,
    PORT_ROLE_DOWNLINK,
    PORT_ROLE_UPLINK,
    SIGHTING_WINDOW_S,
    SUM_BRIDGE_PLUS_PORTS,
    SUM_CLIENT_PLUS_WAN,
    SUM_DUPLICATE_CLIENT,
    SUM_DUPLICATE_POINT,
    SUM_INTERFACE_PLUS_VLAN,
    SUM_INTERFACES_OVERLAP,
    SUM_MIXED_SCOPES,
    SUM_NEEDS_FLOW_SOURCE,
    SUM_NO_POINTS,
    SUM_PORT_IS_UPLINK,
    SUM_PORTS_OF_SEVERAL_ROUTERS,
    SUM_STATION_PLUS_PORT,
    SUM_UPLINKS_UNKNOWN,
    SUM_VLAN_NETDEVS_OVERLAP,
    SUM_WAN_SAME_ROUTER,
)
from .traffic_model import (
    RATE_QUALITIES,
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Perspective,
    Quality,
    Rate,
    Scope,
)

_LOGGER = logging.getLogger(__name__)

# The seven measuring areas of the task (§4), in its order.
MEASURING_SCOPES: Final = (
    Scope.INTERFACE,
    Scope.PORT,
    Scope.STATION,
    Scope.CLIENT,
    Scope.VLAN,
    Scope.FLOW,
    Scope.WAN,
)
# Router netdevs whose counters hardware offloading can bypass.
OFFLOAD_SCOPES: Final = frozenset({Scope.WAN, Scope.INTERFACE, Scope.VLAN})
CLIENT_SCOPES: Final = frozenset({Scope.STATION, Scope.CLIENT})
# Pairs that are never added up, with their named refusal (plan §3.5).
FORBIDDEN_PAIRS: Final = {
    frozenset({Scope.STATION, Scope.PORT}): SUM_STATION_PLUS_PORT,
    frozenset({Scope.INTERFACE, Scope.VLAN}): SUM_INTERFACE_PLUS_VLAN,
    frozenset({Scope.CLIENT, Scope.WAN}): SUM_CLIENT_PLUS_WAN,
}
_BRIDGE_PREFIX: Final = "br-"

# An association: (router_id, radio_id) of one station point.
Assoc = tuple[str | None, str | None]


def is_bridge(point: MeasurementPoint) -> bool:
    """True for a bridge netdev (``br-lan``); VLAN netdevs are scope VLAN."""
    return (
        point.scope is Scope.INTERFACE
        and point.device is not None
        and point.device.startswith(_BRIDGE_PREFIX)
    )


# --- RX/TX semantics (matrix §4) -------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DirectionMap:
    """What RX and TX mean at a point and where download/upload come from.

    ``download``/``upload`` name the counter (``"rx"``/``"tx"``) or are
    None with ``reason`` when the mapping is not unambiguous.
    """

    perspective: Perspective
    rx_means: str
    tx_means: str
    download: str | None
    upload: str | None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "perspective": self.perspective.value,
            "rx_means": self.rx_means,
            "tx_means": self.tx_means,
            "download": self.download,
            "upload": self.upload,
            "reason": self.reason,
        }


def direction_map(
    point: MeasurementPoint, *, port_role: str | None = None
) -> DirectionMap:
    """RX/TX meaning of ``point`` (``port_role``: uplink/downlink, ports only)."""
    scope = point.scope
    if scope is Scope.WAN:
        return DirectionMap(
            Perspective.ROUTER,
            "received_from_the_line",
            "sent_to_the_line",
            download="rx",
            upload="tx",
        )
    if scope in CLIENT_SCOPES:
        return DirectionMap(
            Perspective.STATION,
            "received_from_the_client",
            "sent_to_the_client",
            download="tx",
            upload="rx",
        )
    if scope is Scope.FLOW:
        return DirectionMap(
            Perspective.FLOW_ORIG,
            "originator_direction",
            "reply_direction",
            download=None,
            upload=None,
            reason=DIR_FLOW_DIRECTION,
        )
    if scope is Scope.PORT:
        if port_role == PORT_ROLE_UPLINK:
            down, up, reason = "rx", "tx", None
        elif port_role == PORT_ROLE_DOWNLINK:
            down, up, reason = "tx", "rx", None
        else:
            down, up, reason = None, None, DIR_PORT_ROLE_UNKNOWN
        return DirectionMap(
            Perspective.ROUTER,
            "received_from_the_cable",
            "sent_to_the_cable",
            download=down,
            upload=up,
            reason=reason,
        )
    # interface / VLAN netdev: only traffic to or through the router itself
    return DirectionMap(
        Perspective.ROUTER,
        "received_by_the_router",
        "sent_by_the_router",
        download=None,
        upload=None,
        reason=DIR_AMBIGUOUS_BRIDGE,
    )


def down_up(
    rate: Rate, *, port_role: str | None = None
) -> tuple[float | None, float | None]:
    """``(download bit/s, upload bit/s)`` of a valid rate; None where unknown."""
    if rate.quality not in RATE_QUALITIES:
        return None, None
    mapping = direction_map(rate.point, port_role=port_role)
    values = {"rx": rate.rx_bps, "tx": rate.tx_bps}
    down = values[mapping.download] if mapping.download else None
    up = values[mapping.upload] if mapping.upload else None
    return down, up


# --- coverage -----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Availability:
    """State of a value that is not a rate: coverage plus a named reason."""

    coverage: Coverage
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"coverage": self.coverage.value, "reason": self.reason}


def offload_coverage(
    offload: OffloadState | None,
) -> tuple[Coverage, CoverageReason | None]:
    """Coverage of WAN/bridge/VLAN counters for an offload state.

    Only hardware offloading matters: with software offloading the packets
    still pass the netdev counters (matrix Q1, assumption).
    """
    hardware = None if offload is None else offload.hardware
    if hardware is None:
        return Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_UNKNOWN
    if hardware:
        return Coverage.PARTIAL, CoverageReason.HW_OFFLOAD_ON
    return Coverage.FULL, None


def coverage_of(
    point: MeasurementPoint, *, offload: OffloadState | None
) -> tuple[Coverage, CoverageReason | None]:
    """Coverage a valid rate of ``point`` has (see the module docstring)."""
    scope = point.scope
    if scope in CLIENT_SCOPES:
        return Coverage.PARTIAL, CoverageReason.STATION_COUNTERS_ONLY
    if scope is Scope.PORT:
        return Coverage.FULL, None
    if scope is Scope.FLOW:
        return Coverage.UNAVAILABLE, CoverageReason.NEEDS_FLOW_SOURCE
    return offload_coverage(offload)


def classify(rate: Rate, *, offload: OffloadState | None) -> Rate:
    """``rate`` with the coverage of its area; invalid rates stay unavailable."""
    if rate.quality not in RATE_QUALITIES:
        return rate
    coverage, reason = coverage_of(rate.point, offload=offload)
    if coverage is rate.coverage and reason is rate.coverage_reason:
        return rate
    return _replace(rate, coverage=coverage, coverage_reason=reason)


def _replace(rate: Rate, **changes: Any) -> Rate:
    values = {name: getattr(rate, name) for name in Rate.__dataclass_fields__}
    values.update(changes)
    return Rate(**values)


def stale(rate: Rate) -> Rate:
    """``rate`` as ``stale_source``: no values, nothing may be added."""
    return Rate(
        rate.point,
        Quality.STALE_SOURCE,
        interval_s=rate.interval_s,
        coverage=Coverage.UNAVAILABLE,
        source=rate.source,
        mono_s=rate.mono_s,
        wall_s=rate.wall_s,
    )


def wan_client_attribution() -> Availability:
    """Which client caused WAN traffic: not without a flow source (NAT)."""
    return Availability(Coverage.UNAVAILABLE, CoverageReason.NEEDS_FLOW_SOURCE.value)


# --- sums ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TrafficSum:
    """Result of :func:`sum_rates`: values only when not ``refused``.

    RX and TX stay separate (no combined total). ``contributing`` points
    had a valid rate, ``omitted`` had none (``omitted_by_quality``).
    """

    scope: Scope | None
    refused: str | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    coverage: Coverage = Coverage.UNAVAILABLE
    coverage_reasons: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    contributing: int = 0
    omitted: int = 0
    omitted_by_quality: Mapping[str, int] = field(default_factory=dict)
    routers: int = 0

    @property
    def ok(self) -> bool:
        """True when the sum was allowed (its values may still be unknown)."""
        return self.refused is None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "scope": None if self.scope is None else self.scope.value,
            "refused": self.refused,
            "rx_bps": self.rx_bps,
            "tx_bps": self.tx_bps,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "notes": list(self.notes),
            "contributing": self.contributing,
            "omitted": self.omitted,
            "omitted_by_quality": dict(self.omitted_by_quality),
            "routers": self.routers,
        }


def _refuse(scope: Scope | None, reason: str, rates: list[Rate]) -> TrafficSum:
    return TrafficSum(
        scope,
        refused=reason,
        omitted=len(rates),
        routers=len({r.point.router_id for r in rates}),
    )


def _mixed_refusal(rates: list[Rate], scopes: set[Scope]) -> str:
    if Scope.PORT in scopes and any(is_bridge(r.point) for r in rates):
        return SUM_BRIDGE_PLUS_PORTS
    for pair, reason in FORBIDDEN_PAIRS.items():
        if pair <= scopes:
            return reason
    return SUM_MIXED_SCOPES


def _scope_refusal(
    scope: Scope,
    rates: list[Rate],
    valid: list[Rate],
    uplink_ports: Mapping[str, frozenset[str] | None] | None,
) -> str | None:
    routers = [r.point.router_id for r in rates]
    if scope is Scope.FLOW:
        return SUM_NEEDS_FLOW_SOURCE
    if scope is Scope.INTERFACE and len(rates) > 1:
        return SUM_INTERFACES_OVERLAP
    if scope is Scope.VLAN and len(rates) > 1:
        return SUM_VLAN_NETDEVS_OVERLAP
    if scope is Scope.WAN and len(set(routers)) != len(routers):
        return SUM_WAN_SAME_ROUTER
    if scope is Scope.PORT:
        if len(set(routers)) > 1:
            return SUM_PORTS_OF_SEVERAL_ROUTERS
        known = None if uplink_ports is None else uplink_ports.get(routers[0] or "")
        if known is None:
            return SUM_UPLINKS_UNKNOWN
        if any(r.point.device in known for r in rates):
            return SUM_PORT_IS_UPLINK
    if scope in CLIENT_SCOPES:
        refs = [r.point.client_ref for r in valid]
        if len(set(refs)) != len(refs):
            return SUM_DUPLICATE_CLIENT
    return None


def _sum_coverage(
    valid: list[Rate], omitted: int, missing_direction: bool
) -> tuple[Coverage, tuple[str, ...]]:
    reasons = sorted(
        {r.coverage_reason.value for r in valid if r.coverage_reason is not None}
    )
    if not valid:
        return Coverage.UNAVAILABLE, tuple(reasons)
    if any(r.coverage is Coverage.UNKNOWN for r in valid):
        return Coverage.UNKNOWN, tuple(reasons)
    if all(r.coverage is Coverage.FULL for r in valid) and not (
        omitted or missing_direction
    ):
        return Coverage.FULL, tuple(reasons)
    return Coverage.PARTIAL, tuple(reasons)


def sum_rates(
    rates: Iterable[Rate],
    *,
    uplink_ports: Mapping[str, frozenset[str] | None] | None = None,
) -> TrafficSum:
    """Sum of current rates inside one area, or a named refusal.

    ``uplink_ports`` maps ``router_id`` to its known trunk ports (empty set:
    none; missing/None: unknown); needed for port sums only. Points without
    a valid rate are left out and counted; the sum of a direction no
    contributing point knows is None.
    """
    items = list(rates)
    if not items:
        return TrafficSum(None, refused=SUM_NO_POINTS)
    pids = [r.point.point_id for r in items]
    scopes = {r.point.scope for r in items}
    scope = next(iter(scopes)) if len(scopes) == 1 else None
    if len(set(pids)) != len(pids):
        return _refuse(scope, SUM_DUPLICATE_POINT, items)
    if scope is None:
        return _refuse(None, _mixed_refusal(items, scopes), items)
    valid = [r for r in items if r.quality in RATE_QUALITIES]
    refusal = _scope_refusal(scope, items, valid, uplink_ports)
    if refusal is not None:
        return _refuse(scope, refusal, items)
    omitted = Counter(r.quality.value for r in items if r.quality not in RATE_QUALITIES)
    n_omitted = sum(omitted.values())

    def total(name: str) -> tuple[Any, bool]:
        values = [getattr(r, name) for r in valid]
        known = [v for v in values if v is not None]
        return (sum(known) if known else None), len(known) != len(values)

    rx_bps, miss_rx = total("rx_bps")
    tx_bps, miss_tx = total("tx_bps")
    rx_bytes, _ = total("rx_delta")
    tx_bytes, _ = total("tx_delta")
    missing = bool(valid) and (miss_rx or miss_tx)
    coverage, reasons = _sum_coverage(valid, n_omitted, missing)
    notes = [NOTE_RX_TX_SEPARATE]
    if scope is Scope.PORT:
        notes.append(NOTE_PORT_COUNTERS_UNVERIFIED)
    if n_omitted:
        notes.append(NOTE_POINTS_OMITTED)
    if missing:
        notes.append(NOTE_DIRECTION_MISSING)
    return TrafficSum(
        scope,
        rx_bps=rx_bps,
        tx_bps=tx_bps,
        rx_bytes=rx_bytes,
        tx_bytes=tx_bytes,
        coverage=coverage,
        coverage_reasons=reasons,
        notes=tuple(notes),
        contributing=len(valid),
        omitted=n_omitted,
        omitted_by_quality=dict(omitted),
        routers=len({r.point.router_id for r in items}),
    )


# --- duplicate sightings ----------------------------------------------------------------


@dataclass(slots=True)
class _Sighting:
    first_mono: float
    last_mono: float


class SightingBook:
    """Recent associations per client, for the duplicate decision (bounded).

    Holds only ``client_ref`` and ``(router_id, radio_id)``; entries older
    than the window are pruned, so its size follows the live stations. At
    most ``max_clients`` clients (more are not tracked and counted as
    ``untracked_sightings``) and ``max_assoc`` associations per client (the
    oldest one makes room).
    """

    def __init__(
        self,
        *,
        window_s: float = SIGHTING_WINDOW_S,
        max_clients: int = MAX_SIGHTING_CLIENTS,
        max_assoc: int = MAX_ASSOC_PER_CLIENT,
    ) -> None:
        """Empty book."""
        self.window_s = window_s
        self._max_clients = max_clients
        self._max_assoc = max_assoc
        self._clients: dict[str, dict[Assoc, _Sighting]] = {}
        self.counters: dict[str, int] = {"untracked_sightings": 0}

    def __len__(self) -> int:
        """Clients with a live sighting."""
        return len(self._clients)

    def see(self, client_ref: str, assoc: Assoc, t: float) -> bool:
        """Record a sighting at ``t``; False if the client quota refused it."""
        table = self._clients.get(client_ref)
        if table is None:
            if len(self._clients) >= self._max_clients:
                self.prune(t)
            if len(self._clients) >= self._max_clients:
                self.counters["untracked_sightings"] += 1
                return False
            table = self._clients[client_ref] = {}
        entry = table.get(assoc)
        if entry is None or t - entry.last_mono > self.window_s:
            if entry is None and len(table) >= self._max_assoc:
                oldest = min(table, key=lambda a: table[a].last_mono)
                del table[oldest]
            table[assoc] = _Sighting(t, t)
            return True
        entry.last_mono = max(entry.last_mono, t)
        return True

    def winner(
        self, client_ref: str, t: float, registry_router: str | None = None
    ) -> Assoc | None:
        """The association a sighting at ``t`` counts at (None: not tracked).

        Candidates are the associations seen within the window before or
        after ``t``. The registry's current router wins; else (or among
        several radios of that router) the newest association; ties go to
        the smallest ``(router_id, radio_id)``.

        # Entscheidung: when the registry names a router none of the
        # candidates is at, the winner is ``(that router, None)``: every
        # sighting elsewhere is stale. This keeps the decision independent
        # of the order in which the routers' polls are processed; it costs
        # at most the first poll after a roam, which has no rate anyway.
        """
        table = self._clients.get(client_ref)
        if not table:
            return None
        live = {
            assoc: s
            for assoc, s in table.items()
            if abs(t - s.last_mono) <= self.window_s or s.first_mono <= t <= s.last_mono
        }
        if not live:
            return None
        if registry_router is not None:
            at_registry = {a: s for a, s in live.items() if a[0] == registry_router}
            if not at_registry:
                return (registry_router, None)
            live = at_registry

        def rank(assoc: Assoc) -> float:
            return live[assoc].first_mono

        best = max(rank(a) for a in live)
        tied = [a for a in live if rank(a) == best]
        return min(tied, key=lambda a: (a[0] or "", a[1] or ""))

    def prune(self, now: float) -> int:
        """Drop associations last seen more than the window before ``now``."""
        dropped = 0
        for ref in list(self._clients):
            table = self._clients[ref]
            for assoc in [
                a for a, s in table.items() if now - s.last_mono > self.window_s
            ]:
                del table[assoc]
                dropped += 1
            if not table:
                del self._clients[ref]
        return dropped

    def drop_router(self, router_id: str | None) -> None:
        """Forget the sightings at ``router_id``."""
        for ref in list(self._clients):
            table = self._clients[ref]
            for assoc in [a for a in table if a[0] == router_id]:
                del table[assoc]
            if not table:
                del self._clients[ref]

    def clear(self) -> None:
        """Forget everything (the counters stay)."""
        self._clients.clear()


def _time_of(rate: Rate) -> float | None:
    return rate.mono_s


class TrafficAccounting:
    """Runs every new rate through coverage and the duplicate rule.

    The engine calls :meth:`account` before a rate becomes visible (latest
    rates, later buckets). O(rates) per call plus one prune of the book.
    """

    def __init__(self, sightings: SightingBook | None = None) -> None:
        """Fresh accounting with its own sighting book."""
        self.sightings = SightingBook() if sightings is None else sightings
        self.counters: Counter[str] = Counter()

    def account(
        self,
        rates: Iterable[Rate],
        *,
        offload: OffloadState | None,
        registry_router: Mapping[str, str | None] | None = None,
    ) -> list[Rate]:
        """Accounted copies of ``rates`` (same order).

        ``offload``: offload state of the rates' router (None: unknown).
        ``registry_router``: ``client_ref`` -> router the client registry
        names as current (missing/None: unknown).
        """
        out = [classify(r, offload=offload) for r in rates]
        times = [t for t in (_time_of(r) for r in out) if t is not None]
        if times:
            self.sightings.prune(max(times))
        stations: list[tuple[int, str, Assoc, float]] = []
        for i, rate in enumerate(out):
            point = rate.point
            t = _time_of(rate)
            ref = point.client_ref
            if point.scope is not Scope.STATION or ref is None or t is None:
                continue
            assoc: Assoc = (point.router_id, point.radio_id)
            if self.sightings.see(ref, assoc, t):
                stations.append((i, ref, assoc, t))
        registry = registry_router or {}
        for i, ref, assoc, t in stations:
            win = self.sightings.winner(ref, t, registry.get(ref))
            if win is not None and win != assoc:
                out[i] = stale(out[i])
                self.counters["duplicate_sightings"] += 1
        return out

    def drop_router(self, router_id: str | None) -> None:
        """Forget the sightings of an unloaded router."""
        self.sightings.drop_router(router_id)

    def clear(self) -> None:
        """Forget everything (module switched off)."""
        self.sightings.clear()

    def summary(self) -> dict[str, int]:
        """Counts only (no client id)."""
        return {
            "duplicate_sightings": self.counters["duplicate_sightings"],
            "untracked_sightings": self.sightings.counters["untracked_sightings"],
            "sighting_clients": len(self.sightings),
        }
