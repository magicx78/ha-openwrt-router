"""VLAN traffic view (plan 2026-11-20, §4 "VLAN", task §7; Phase D).

Two things are kept strictly apart:

* **measured**: traffic of a VLAN exists only where a VLAN netdev
  (``br-lan.10``, ``lan1.10``) is counted (matrix Q1). Its RX/TX are the
  router's view of that netdev (traffic to and through the router; frames
  bridged between two ports of the VLAN never reach it). With one VLAN
  netdev the view shows its rate; with several netdevs of one VLAN on a
  router the values overlap and no total is formed; a fleet-wide VLAN total
  is never formed (inter-router traffic would be counted twice).
* **configured**: which ports carry the VLAN (``port_vlan_map``). Shown
  only, never turned into traffic.

Nothing is derived from client sums (station counters carry no VLAN tag).
Inter-VLAN and WAN-related VLAN traffic need a flow source:
``unavailable``/``needs_flow_source``. The number of active clients is only
given where it can be shown: wired MACs the bridge FDB saw on a port with
exactly one configured VLAN (``bridge_fdb_single_vlan_port``); Wi-Fi
clients have no VLAN mapping, so the count is ``partial`` on routers with
access points, and missing (None) without FDB evidence.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .traffic_accounting import (
    Availability,
    DirectionMap,
    TrafficSum,
    direction_map,
    sum_rates,
)
from .traffic_const import (
    BASIS_FDB_SINGLE_VLAN_PORT,
    REASON_NO_CLIENT_VLAN_SOURCE,
    REASON_NO_VLAN_NETDEV,
    REASON_NO_WIFI_VLAN_MAPPING,
    REASON_PORT_VLAN_AMBIGUOUS,
    REASON_PORT_VLAN_UNKNOWN,
    REASON_VLAN_NOT_CONFIGURED,
    SUM_NO_FLEET_VLAN_TOTAL,
)
from .traffic_model import (
    RATE_QUALITIES,
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)

_LOGGER = logging.getLogger(__name__)

# RX/TX meaning of any VLAN netdev (router view, no download/upload).
_VLAN_DIRECTION = direction_map(MeasurementPoint(None, Scope.VLAN, vlan_id=1))


def _needs_flow() -> Availability:
    return Availability(Coverage.UNAVAILABLE, CoverageReason.NEEDS_FLOW_SOURCE.value)


@dataclass(frozen=True, slots=True)
class VlanDevice:
    """One measured VLAN netdev and its latest rate (router perspective)."""

    point_id: str
    device: str | None
    quality: str
    rx_bps: float | None
    tx_bps: float | None
    rx_bytes: int | None
    tx_bytes: int | None
    coverage: Coverage
    coverage_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "point_id": self.point_id,
            "device": self.device,
            "quality": self.quality,
            "rx_bps": self.rx_bps,
            "tx_bps": self.tx_bps,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "coverage": self.coverage.value,
            "coverage_reason": self.coverage_reason,
        }


@dataclass(frozen=True, slots=True)
class VlanView:
    """Measured traffic and configured membership of one VLAN on one router.

    ``rx_bps``/``tx_bps`` come from the single measured netdev only; every
    None value has its reason in ``unavailable``.
    """

    router_id: str
    vlan_id: int
    measured: tuple[VlanDevice, ...]
    rx_bps: float | None
    tx_bps: float | None
    rx_bytes: int | None
    tx_bytes: int | None
    coverage: Coverage
    coverage_reasons: tuple[str, ...]
    direction: DirectionMap
    configured_ports: tuple[str, ...]
    inter_vlan: Availability
    wan_related: Availability
    active_clients: int | None
    active_clients_coverage: Coverage
    active_clients_basis: str | None
    unavailable: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (no client ids at all)."""
        return {
            "router_id": self.router_id,
            "vlan_id": self.vlan_id,
            "measured": [d.to_dict() for d in self.measured],
            "rx_bps": self.rx_bps,
            "tx_bps": self.tx_bps,
            "rx_bytes": self.rx_bytes,
            "tx_bytes": self.tx_bytes,
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "direction": self.direction.to_dict(),
            "configured_ports": list(self.configured_ports),
            "inter_vlan": self.inter_vlan.to_dict(),
            "wan_related": self.wan_related.to_dict(),
            "active_clients": self.active_clients,
            "active_clients_coverage": self.active_clients_coverage.value,
            "active_clients_basis": self.active_clients_basis,
            "unavailable": dict(self.unavailable),
        }


def _device(rate: Rate) -> VlanDevice:
    valid = rate.quality in RATE_QUALITIES
    return VlanDevice(
        point_id=rate.point.point_id,
        device=rate.point.device,
        quality=rate.quality.value,
        rx_bps=rate.rx_bps if valid else None,
        tx_bps=rate.tx_bps if valid else None,
        rx_bytes=rate.rx_delta if valid else None,
        tx_bytes=rate.tx_delta if valid else None,
        coverage=rate.coverage,
        coverage_reason=(
            None if rate.coverage_reason is None else rate.coverage_reason.value
        ),
    )


def _measured_values(
    rates: list[Rate], unavailable: dict[str, str]
) -> tuple[TrafficSum | None, Coverage, tuple[str, ...]]:
    if not rates:
        for name in ("rx_bps", "tx_bps", "rx_bytes", "tx_bytes"):
            unavailable[name] = REASON_NO_VLAN_NETDEV
        return None, Coverage.UNAVAILABLE, (REASON_NO_VLAN_NETDEV,)
    result = sum_rates(rates)
    if not result.ok:
        reason = result.refused or ""
        for name in ("rx_bps", "tx_bps", "rx_bytes", "tx_bytes"):
            unavailable[name] = reason
        return None, Coverage.UNAVAILABLE, (reason,)
    if result.contributing == 0:
        reason = rates[0].quality.value
        for name in ("rx_bps", "tx_bps", "rx_bytes", "tx_bytes"):
            unavailable[name] = reason
        return result, Coverage.UNAVAILABLE, (reason,)
    for name in ("rx_bps", "tx_bps", "rx_bytes", "tx_bytes"):
        if getattr(result, name) is None:
            unavailable[name] = Quality.SOURCE_MISSING.value
    return result, result.coverage, result.coverage_reasons


def _active_clients(
    vlan_id: int,
    port_vlans: Mapping[str, tuple[int, ...]],
    wired_ports: Mapping[str, str] | None,
    has_wifi: bool,
) -> tuple[int | None, Coverage, str | None, str | None]:
    """(count, coverage, basis, reason when None) for one VLAN."""
    if not wired_ports:
        return None, Coverage.UNAVAILABLE, None, REASON_NO_CLIENT_VLAN_SOURCE
    single = {p for p, vids in port_vlans.items() if vids == (vlan_id,)}
    if not single:
        return None, Coverage.UNAVAILABLE, None, REASON_NO_CLIENT_VLAN_SOURCE
    count = sum(1 for port in wired_ports.values() if port in single)
    ambiguous = any(
        len(port_vlans.get(port, ())) != 1 and vlan_id in port_vlans.get(port, ())
        for port in wired_ports.values()
    )
    coverage = Coverage.PARTIAL if has_wifi or ambiguous else Coverage.FULL
    return count, coverage, BASIS_FDB_SINGLE_VLAN_PORT, None


def vlan_views(
    router_id: str,
    rates: Iterable[Rate],
    *,
    port_vlans: Iterable[tuple[str, tuple[int, ...]]] | None,
    wired_ports: Mapping[str, str] | None = None,
    has_wifi: bool = False,
) -> list[VlanView]:
    """VLAN views of one router, sorted by VLAN id.

    ``rates``: the router's latest rates (only VLAN-scope ones are used).
    ``port_vlans``: configured VLANs per port (None: unknown).
    ``wired_ports``: ``client_ref`` -> port of wired FDB sightings that are
    not Wi-Fi clients (None: not available). ``has_wifi``: the router has
    access points (their clients cannot be placed in a VLAN).
    """
    measured: dict[int, list[Rate]] = {}
    for rate in rates:
        point = rate.point
        if (
            point.scope is Scope.VLAN
            and point.router_id == router_id
            and point.vlan_id is not None
        ):
            measured.setdefault(point.vlan_id, []).append(rate)
    configured = dict(port_vlans) if port_vlans is not None else None
    vids = set(measured)
    for vlan_list in (configured or {}).values():
        vids.update(vlan_list)
    views: list[VlanView] = []
    for vid in sorted(vids):
        unavailable: dict[str, str] = {}
        rates_of_vid = sorted(measured.get(vid, []), key=lambda r: r.point.device or "")
        result, coverage, reasons = _measured_values(rates_of_vid, unavailable)
        ports: tuple[str, ...] = ()
        if configured is None or not configured:
            unavailable["configured_ports"] = REASON_PORT_VLAN_UNKNOWN
        else:
            ports = tuple(sorted(p for p, v in configured.items() if vid in v))
            if not ports:
                unavailable["configured_ports"] = REASON_VLAN_NOT_CONFIGURED
        count, count_cov, basis, count_reason = _active_clients(
            vid, configured or {}, wired_ports, has_wifi
        )
        if count_reason is not None:
            unavailable["active_clients"] = count_reason
        elif count_cov is Coverage.PARTIAL:
            unavailable["active_clients_wifi"] = (
                REASON_NO_WIFI_VLAN_MAPPING if has_wifi else REASON_PORT_VLAN_AMBIGUOUS
            )
        inter, wan_rel = _needs_flow(), _needs_flow()
        unavailable["inter_vlan"] = inter.reason or ""
        unavailable["wan_related"] = wan_rel.reason or ""
        views.append(
            VlanView(
                router_id=router_id,
                vlan_id=vid,
                measured=tuple(_device(r) for r in rates_of_vid),
                rx_bps=None if result is None else result.rx_bps,
                tx_bps=None if result is None else result.tx_bps,
                rx_bytes=None if result is None else result.rx_bytes,
                tx_bytes=None if result is None else result.tx_bytes,
                coverage=coverage,
                coverage_reasons=reasons,
                direction=(
                    direction_map(rates_of_vid[0].point)
                    if rates_of_vid
                    else _VLAN_DIRECTION
                ),
                configured_ports=ports,
                inter_vlan=inter,
                wan_related=wan_rel,
                active_clients=count,
                active_clients_coverage=count_cov,
                active_clients_basis=basis,
                unavailable=unavailable,
            )
        )
    return views


def fleet_vlan_total(views: Iterable[VlanView]) -> TrafficSum:
    """A VLAN total over several routers: always refused (overlap)."""
    count = sum(1 for _ in views)
    return TrafficSum(Scope.VLAN, refused=SUM_NO_FLEET_VLAN_TOTAL, omitted=count)
