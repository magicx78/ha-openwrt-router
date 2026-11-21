"""Data model of Traffic Analytics (plan 2026-11-20, §3.1-3.3).

Frozen dataclasses and StrEnums only, no Home Assistant import and no I/O.
Phase B fills ``MeasurementPoint``, ``Sample`` and ``Rate``; ``Bucket``,
``FlowRecord`` and ``AnomalyCandidate`` are defined now so later phases
(history, flows, anomalies) build on one stable model.

Naming: identities are ``router_id``, ``radio_id`` and ``client_ref``, never
``*_key`` (the core masks ``*_key`` fields as identifiers). No MAC, IP or
host name is ever a field value here; a client is only its ``client_ref``.
Unknown is ``None``, never 0.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from .traffic_const import DEVICE_NAME_RE

_LOGGER = logging.getLogger(__name__)

POINT_ID_PREFIX: Final = "tpt_"
POINT_ID_HEX: Final = 16
_ROUTER_ID_RE: Final = re.compile(r"rtr_[0-9a-f]{32}")
_CLIENT_REF_RE: Final = re.compile(r"cli_[0-9a-f]{16}")
_POINT_ID_RE: Final = re.compile(r"tpt_[0-9a-f]{16}")
_RADIO_ID_RE: Final = DEVICE_NAME_RE  # E7: AP netdev name until W6


class Scope(StrEnum):
    """Measuring scope of a point (plan §3.2); scopes are never added up."""

    INTERFACE = "interface"
    PORT = "port"
    STATION = "station"
    CLIENT = "client"
    VLAN = "vlan"
    FLOW = "flow"
    WAN = "wan"


class Coverage(StrEnum):
    """How much of the traffic of a point a value covers."""

    FULL = "full"
    PARTIAL = "partial"
    ESTIMATED = "estimated"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class Quality(StrEnum):
    """Outcome of one counter delta (plan §3.4)."""

    OK = "ok"
    FIRST_SAMPLE = "first_sample"
    GAP = "gap"
    TIME_NOT_ADVANCING = "time_not_advancing"
    ROUTER_RESTART = "router_restart"
    COUNTER_RESET = "counter_reset"
    WRAP_32 = "wrap_32"
    IMPLAUSIBLE = "implausible"
    STALE_SOURCE = "stale_source"
    SOURCE_MISSING = "source_missing"


# A delta of these qualities carries a rate; every other one has none.
RATE_QUALITIES: Final = frozenset({Quality.OK, Quality.WRAP_32})


class Perspective(StrEnum):
    """Whose RX/TX a value is (matrix §4)."""

    ROUTER = "router"  # netdev: RX = received by the router
    STATION = "station"  # AP view of a client: RX = client upload
    FLOW_ORIG = "flow_orig"


class Source(StrEnum):
    """Where a value came from (matrix Q-numbers)."""

    NETDEV = "netdev"  # Q1 network.device status
    SYSFS = "sysfs"  # Q2 /sys/class/net/<dev>/statistics
    HOSTAPD = "hostapd"  # Q7
    IWINFO = "iwinfo"  # Q8
    CONNTRACK_COUNT = "conntrack_count"  # Q6a
    COLLECTOR = "collector"  # Q12
    DERIVED = "derived"


# Sources whose byte counters may be 32 bit (E6: station counters only).
WRAP_32_SOURCES: Final = frozenset({Source.HOSTAPD, Source.IWINFO})


class CoverageReason(StrEnum):
    """Why a value is not ``full``."""

    STATION_COUNTERS_ONLY = "station_counters_only"
    ROAMING_GAP = "roaming_gap"
    HW_OFFLOAD_UNKNOWN = "hw_offload_unknown"
    HW_OFFLOAD_ON = "hw_offload_on"
    NO_WIRED_CLIENT_SOURCE = "no_wired_client_source"
    NEEDS_FLOW_SOURCE = "needs_flow_source"
    SOURCE_DISABLED = "source_disabled"
    MODULE_MISSING = "module_missing"


class FlowKind(StrEnum):
    """How a flow record was obtained (plan §3.3)."""

    OBSERVED = "observed"
    AGGREGATED = "aggregated"
    ESTIMATED_CATEGORY = "estimated_category"
    UNKNOWN = "unknown"


class FlowDirection(StrEnum):
    """Direction field of a flow record (collector schema §8)."""

    ORIG = "orig"
    REPLY = "reply"
    IN = "in"
    OUT = "out"


class CandidateState(StrEnum):
    """Life cycle of an anomaly candidate (no incident life cycle)."""

    OPEN = "open"
    ENDED = "ended"


def _opt_counter(value: Any, name: str) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative int or None")


def _opt_finite(value: Any, name: str, *, minimum: float | None = None) -> None:
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"{name} must be a number or None")
    if not math.isfinite(value) or (minimum is not None and value < minimum):
        raise ValueError(f"{name} out of range")


def valid_device_name(value: Any) -> bool:
    """True for a netdev name the module accepts (no path parts)."""
    return (
        isinstance(value, str)
        and DEVICE_NAME_RE.fullmatch(value) is not None
        and ".." not in value
        and value not in (".", "..")
    )


def valid_router_id(value: Any) -> bool:
    """True for a core router id (``rtr_`` + 32 lower-case hex)."""
    return isinstance(value, str) and _ROUTER_ID_RE.fullmatch(value) is not None


def valid_client_ref(value: Any) -> bool:
    """True for a core client pseudonym (``cli_`` + 16 hex)."""
    return isinstance(value, str) and _CLIENT_REF_RE.fullmatch(value) is not None


def valid_point_id(value: Any) -> bool:
    """True for a point id (``tpt_`` + 16 hex)."""
    return isinstance(value, str) and _POINT_ID_RE.fullmatch(value) is not None


# --- 3.1 measuring point --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class MeasurementPoint:
    """One place where traffic is counted (plan §3.1).

    ``point_id`` is ``tpt_`` + sha256 of the canonical fields (E5): stable
    across restarts and independent of the module key; the inputs are
    already pseudonyms or not secret. Another ``device`` is another point.
    """

    router_id: str | None
    scope: Scope
    device: str | None = None
    vlan_id: int | None = None
    radio_id: str | None = None
    client_ref: str | None = None
    point_id: str = field(init=False, compare=False, repr=False)

    def __post_init__(self) -> None:
        """Validate and derive ``point_id``."""
        object.__setattr__(self, "scope", Scope(self.scope))
        if self.router_id is not None and not valid_router_id(self.router_id):
            raise ValueError("router_id must be rtr_<32 hex> or None")
        if self.device is not None and not valid_device_name(self.device):
            raise ValueError("device is not a valid netdev name")
        if self.vlan_id is not None and (
            isinstance(self.vlan_id, bool)
            or not isinstance(self.vlan_id, int)
            or not 1 <= self.vlan_id <= 4094
        ):
            raise ValueError("vlan_id must be 1..4094 or None")
        if self.radio_id is not None and not valid_device_name(self.radio_id):
            raise ValueError("radio_id is not a valid radio identity")
        if self.client_ref is not None and not valid_client_ref(self.client_ref):
            raise ValueError("client_ref must be cli_<16 hex> or None")
        object.__setattr__(self, "point_id", point_id_of(self))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (no raw identifiers exist in a point)."""
        return {
            "point_id": self.point_id,
            "router_id": self.router_id,
            "scope": self.scope.value,
            "device": self.device,
            "vlan_id": self.vlan_id,
            "radio_id": self.radio_id,
            "client_ref": self.client_ref,
        }


def point_from_dict(raw: Any) -> MeasurementPoint | None:
    """A point from its ``to_dict`` form (None: not a valid point).

    A ``point_id`` in ``raw`` must match the one derived from the fields.
    """
    if not isinstance(raw, Mapping):
        return None
    try:
        point = MeasurementPoint(
            raw.get("router_id"),
            Scope(raw.get("scope")),
            device=raw.get("device"),
            vlan_id=raw.get("vlan_id"),
            radio_id=raw.get("radio_id"),
            client_ref=raw.get("client_ref"),
        )
    except (TypeError, ValueError):
        return None
    stored = raw.get("point_id")
    if stored is not None and stored != point.point_id:
        return None
    return point


def point_id_of(point: MeasurementPoint) -> str:
    """Deterministic id of a point from its canonical fields."""
    canonical = "\x1f".join(
        "" if value is None else str(value)
        for value in (
            "v1",
            point.router_id,
            point.scope.value,
            point.device,
            point.vlan_id,
            point.radio_id,
            point.client_ref,
        )
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return POINT_ID_PREFIX + digest[:POINT_ID_HEX]


# --- 3.3 records ------------------------------------------------------------------


COUNTER_FIELDS: Final = (
    "rx_bytes",
    "tx_bytes",
    "rx_packets",
    "tx_packets",
    "rx_errors",
    "tx_errors",
    "rx_dropped",
    "tx_dropped",
)


@dataclass(frozen=True, slots=True)
class Sample:
    """Raw counters of one point at one moment (plan §3.3).

    ``mono_s`` is the monotonic time of the read in the poll (E4), ``wall_s``
    the wall clock of it (only for rule 8 after an HA restart). Counters are
    taken as delivered: ``None`` = unknown. Validation is lenient on purpose:
    an invalid counter becomes ``None`` in ``traffic_collect`` before a
    sample is built, so a malformed router reply never raises here.
    """

    point: MeasurementPoint
    mono_s: float | None
    wall_s: float | None
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_packets: int | None = None
    tx_packets: int | None = None
    rx_errors: int | None = None
    tx_errors: int | None = None
    rx_dropped: int | None = None
    tx_dropped: int | None = None
    link_mbps: int | None = None
    duplex: str | None = None  # "full" | "half" | None
    source: Source = Source.NETDEV
    router_uptime_s: int | None = None

    @property
    def perspective(self) -> Perspective:
        """RX/TX perspective of the sample (matrix §4)."""
        if self.point.scope is Scope.STATION:
            return Perspective.STATION
        return Perspective.ROUTER


@dataclass(frozen=True, slots=True)
class Rate:
    """Result of one counter delta (plan §3.3).

    ``rx_bps``/``tx_bps`` are bits per second (like ``wan_traffic``), the
    deltas are bytes/packets/errors/drops. Every value is ``None`` unless
    ``quality`` is in ``RATE_QUALITIES``; a single direction may still be
    ``None`` when its counter was unknown.
    """

    point: MeasurementPoint
    quality: Quality
    interval_s: float | None = None
    rx_bps: float | None = None
    tx_bps: float | None = None
    rx_delta: int | None = None
    tx_delta: int | None = None
    rx_packets_delta: int | None = None
    tx_packets_delta: int | None = None
    rx_errors_delta: int | None = None
    tx_errors_delta: int | None = None
    rx_dropped_delta: int | None = None
    tx_dropped_delta: int | None = None
    coverage: Coverage = Coverage.UNKNOWN
    coverage_reason: CoverageReason | None = None
    source: Source = Source.NETDEV
    # Poll times of the sample that ended this delta (accounting, history).
    mono_s: float | None = None
    wall_s: float | None = None

    @property
    def has_rate(self) -> bool:
        """True if the delta produced a rate."""
        return self.quality in RATE_QUALITIES

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "point_id": self.point.point_id,
            "quality": self.quality.value,
            "interval_s": self.interval_s,
            "rx_bps": self.rx_bps,
            "tx_bps": self.tx_bps,
            "rx_delta": self.rx_delta,
            "tx_delta": self.tx_delta,
            "rx_packets_delta": self.rx_packets_delta,
            "tx_packets_delta": self.tx_packets_delta,
            "rx_errors_delta": self.rx_errors_delta,
            "tx_errors_delta": self.tx_errors_delta,
            "rx_dropped_delta": self.rx_dropped_delta,
            "tx_dropped_delta": self.tx_dropped_delta,
            "coverage": self.coverage.value,
            "coverage_reason": (
                None if self.coverage_reason is None else self.coverage_reason.value
            ),
            "source": self.source.value,
        }


@dataclass(frozen=True, slots=True)
class RegistryFacts:
    """What the client registry (client engine) said about one station.

    Taken while the poll is copied (the MAC never leaves that step):
    ``known`` - the registry tracks the client; ``state`` its live state;
    ``router_id`` the router of its current AP (only while online or in
    grace, None when unknown); ``band`` its band. No MAC, IP or host name.
    """

    known: bool
    state: str | None = None
    router_id: str | None = None
    band: str | None = None

    def __post_init__(self) -> None:
        """Only a valid router id is kept."""
        if self.router_id is not None and not valid_router_id(self.router_id):
            object.__setattr__(self, "router_id", None)


HIST_CLASSES: Final = 12


@dataclass(frozen=True, slots=True)
class Bucket:
    """Aggregate of one point over one aligned interval (filled in Phase I).

    Coverage is ``covered_s / resolution_s``; below 0.5 the bucket is
    "lückenhaft" and counts in neither P95 nor baselines (plan §3.3).
    """

    start: int  # aligned unix seconds
    resolution_s: int
    rx_bytes: int | None = None
    tx_bytes: int | None = None
    rx_peak_bps: float | None = None
    tx_peak_bps: float | None = None
    covered_s: float = 0.0
    samples: int = 0
    quality_mask: int = 0  # bit per Quality value seen (quality_bit)
    hist_rx: tuple[int, ...] | None = None  # HIST_CLASSES log classes
    hist_tx: tuple[int, ...] | None = None

    def __post_init__(self) -> None:
        """Basic range checks."""
        if self.resolution_s <= 0:
            raise ValueError("resolution_s must be positive")
        if self.start % self.resolution_s:
            raise ValueError("start must be aligned to resolution_s")
        _opt_counter(self.rx_bytes, "rx_bytes")
        _opt_counter(self.tx_bytes, "tx_bytes")
        _opt_finite(self.rx_peak_bps, "rx_peak_bps", minimum=0)
        _opt_finite(self.tx_peak_bps, "tx_peak_bps", minimum=0)
        _opt_finite(self.covered_s, "covered_s", minimum=0)
        for name in ("hist_rx", "hist_tx"):
            hist = getattr(self, name)
            if hist is not None and len(hist) != HIST_CLASSES:
                raise ValueError(f"{name} must have {HIST_CLASSES} classes")

    @property
    def coverage_ratio(self) -> float:
        """Covered share of the interval (0..1)."""
        return max(0.0, min(1.0, self.covered_s / self.resolution_s))

    @property
    def gappy(self) -> bool:
        """True below half coverage: not used for P95 or baselines."""
        return self.coverage_ratio < 0.5


def quality_bit(quality: Quality) -> int:
    """Bit of ``quality`` in ``Bucket.quality_mask`` (stable enum order)."""
    return 1 << list(Quality).index(quality)


@dataclass(frozen=True, slots=True)
class FlowRecord:
    """One flow from a flow source (Phase E; RAM only, E8).

    ``src``/``dst`` are only ever held in memory for admins (plan §7); they
    are never persisted (only anonymised aggregates are, plan §8).
    """

    router_id: str | None
    client_ref: str | None
    vlan_id: int | None
    proto: str
    src: str | None
    dst: str | None
    src_port: int | None
    dst_port: int | None
    start: float
    end: float
    bytes: int | None
    packets: int | None
    direction: FlowDirection
    kind: FlowKind
    source: Source
    nat_seen: bool | None = None

    def __post_init__(self) -> None:
        """Basic checks; the collector schema (Phase K) validates in depth."""
        object.__setattr__(self, "direction", FlowDirection(self.direction))
        object.__setattr__(self, "kind", FlowKind(self.kind))
        object.__setattr__(self, "source", Source(self.source))
        if self.router_id is not None and not valid_router_id(self.router_id):
            raise ValueError("router_id must be rtr_<32 hex> or None")
        if self.client_ref is not None and not valid_client_ref(self.client_ref):
            raise ValueError("client_ref must be cli_<16 hex> or None")
        _opt_counter(self.bytes, "bytes")
        _opt_counter(self.packets, "packets")
        _opt_finite(self.start, "start")
        _opt_finite(self.end, "end")
        if self.end < self.start:
            raise ValueError("end before start")


@dataclass(frozen=True, slots=True)
class AnomalyCandidate:
    """A traffic anomaly candidate (Phase F); never an incident (plan §10)."""

    candidate_id: str
    point_id: str
    router_id: str | None
    client_ref: str | None
    kind: str
    observed: float
    baseline_median: float | None
    baseline_mad: float | None
    threshold: float | None
    window_s: int
    confidence: float
    coverage: Coverage
    started: float
    last_seen: float
    state: CandidateState = CandidateState.OPEN
    suppressed_reason: str | None = None
    incident_ref: str | None = None

    def __post_init__(self) -> None:
        """Basic checks."""
        object.__setattr__(self, "coverage", Coverage(self.coverage))
        object.__setattr__(self, "state", CandidateState(self.state))
        if not valid_point_id(self.point_id):
            raise ValueError("point_id must be tpt_<16 hex>")
        if self.router_id is not None and not valid_router_id(self.router_id):
            raise ValueError("router_id must be rtr_<32 hex> or None")
        if self.client_ref is not None and not valid_client_ref(self.client_ref):
            raise ValueError("client_ref must be cli_<16 hex> or None")
        _opt_finite(self.confidence, "confidence", minimum=0)
        if self.confidence > 1:
            raise ValueError("confidence must be 0..1")
