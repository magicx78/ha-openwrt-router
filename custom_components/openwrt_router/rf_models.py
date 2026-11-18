"""RF capability model: measured values and what a radio can report (pure, no HA).

Every RF value carries its state and its source so that a missing value can
never be mistaken for a measured zero:

- ``measured``: supported, value present and fresh;
- ``no_data``: supported (or support unknown) and the source answered, but
  without this value right now;
- ``unsupported``: known not to be supported by this radio/driver/release;
- ``unreachable``: the source (ubus object, method, ACL) did not answer;
- ``stale``: a value exists but is older than allowed.

No clock, no I/O: time always comes in as a parameter. ``router_key`` is
the Core router id and ``radio_key`` the UCI radio name, both supplied by
the caller (see :mod:`.rf_identity`). This state model is per radio and
richer than the Core's per-router ``available/unavailable/unknown``;
:mod:`.rf_capabilities` maps it onto the Core model without loss.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from types import MappingProxyType
from typing import Any

_LOGGER = logging.getLogger(__name__)


class CapabilityState(StrEnum):
    """State of one metric of one radio."""

    MEASURED = "measured"
    NO_DATA = "no_data"
    UNSUPPORTED = "unsupported"
    UNREACHABLE = "unreachable"
    STALE = "stale"


# States in which a Metric carries a value.
_VALUE_STATES = frozenset({CapabilityState.MEASURED, CapabilityState.STALE})

# Sources (ubus object.method) named in the plan document, section 2.
SOURCE_HOSTAPD_STATUS = "hostapd.get_status"
SOURCE_IWINFO_SURVEY = "iwinfo.survey"
SOURCE_IWINFO_ASSOCLIST = "iwinfo.assoclist"
SOURCE_IWINFO_INFO = "iwinfo.info"
SOURCE_IWINFO_FREQLIST = "iwinfo.freqlist"
SOURCE_IWINFO_TXPOWERLIST = "iwinfo.txpowerlist"
SOURCE_IWINFO_SCAN = "iwinfo.scan"

# Fixed metric names of the capability matrix (order is the contract order).
METRIC_CHANNEL = "channel"
METRIC_WIDTH = "width"
METRIC_TXPOWER = "txpower"
METRIC_TXPOWER_MAX = "txpower_max"
METRIC_NOISE = "noise"
METRIC_BUSY_TIME = "busy_time"
METRIC_ACTIVE_TIME = "active_time"
METRIC_RX_TIME = "rx_time"
METRIC_TX_TIME = "tx_time"
METRIC_UTILIZATION = "utilization"
METRIC_CLIENT_AIRTIME = "client_airtime"
METRIC_CLIENTS = "clients"
METRIC_RSSI = "rssi"
METRIC_RATE = "rate"
METRIC_RETRIES = "retries"
METRIC_FAILED = "failed"
METRIC_CONNECTED_TIME = "connected_time"
METRIC_FREQLIST = "freqlist"
METRIC_COUNTRY = "country"
METRIC_SCAN = "scan"

ALL_METRICS: tuple[str, ...] = (
    METRIC_CHANNEL,
    METRIC_WIDTH,
    METRIC_TXPOWER,
    METRIC_TXPOWER_MAX,
    METRIC_NOISE,
    METRIC_BUSY_TIME,
    METRIC_ACTIVE_TIME,
    METRIC_RX_TIME,
    METRIC_TX_TIME,
    METRIC_UTILIZATION,
    METRIC_CLIENT_AIRTIME,
    METRIC_CLIENTS,
    METRIC_RSSI,
    METRIC_RATE,
    METRIC_RETRIES,
    METRIC_FAILED,
    METRIC_CONNECTED_TIME,
    METRIC_FREQLIST,
    METRIC_COUNTRY,
    METRIC_SCAN,
)
_METRIC_SET = frozenset(ALL_METRICS)

MetricValue = float | int | str | None


def _has_value(value: Any) -> bool:
    """True for a usable value; None, NaN and bools are not measurements."""
    if value is None or isinstance(value, bool):
        return False
    return not (isinstance(value, float) and math.isnan(value))


@dataclass(frozen=True)
class Metric:
    """One value with its state, source and measurement time.

    Invariant: ``value`` is set exactly for ``measured`` and ``stale``.
    """

    value: MetricValue
    state: CapabilityState
    source: str
    measured_at: float | None = None

    def __post_init__(self) -> None:
        needs_value = self.state in _VALUE_STATES
        if needs_value and not _has_value(self.value):
            raise ValueError(f"{self.state} metric needs a value")
        if not needs_value and self.value is not None:
            raise ValueError(f"{self.state} metric must not carry a value")

    @property
    def is_measured(self) -> bool:
        """True only for a fresh measured value."""
        return self.state is CapabilityState.MEASURED

    def as_dict(self) -> dict[str, Any]:
        """Return the metric as a plain dict."""
        return {
            "value": self.value,
            "state": self.state.value,
            "source": self.source,
            "measured_at": self.measured_at,
        }


def metric_measured(
    value: MetricValue, source: str, *, measured_at: float | None
) -> Metric:
    """Return a measured metric; None/NaN raise instead of becoming a value."""
    if not _has_value(value):
        raise ValueError(f"no measured value from {source}")
    return Metric(value, CapabilityState.MEASURED, source, measured_at)


def metric_missing(state: CapabilityState, source: str) -> Metric:
    """Return a metric without value (no_data, unsupported, unreachable)."""
    if state in _VALUE_STATES:
        raise ValueError(f"{state} is not a missing state")
    return Metric(None, state, source, None)


def with_staleness(metric: Metric, now: float, max_age_s: float) -> Metric:
    """Return the metric marked stale when it is older than ``max_age_s``.

    A measured metric without ``measured_at`` cannot prove it is fresh and
    becomes stale. Metrics without a value are returned unchanged.
    """
    if metric.state is not CapabilityState.MEASURED:
        return metric
    if metric.measured_at is None or now - metric.measured_at > max_age_s:
        return replace(metric, state=CapabilityState.STALE)
    return metric


def classify(
    *,
    present: bool,
    value: Any,
    source_ok: bool,
    supported: bool | None,
    age_s: float | None,
    max_age_s: float | None,
) -> CapabilityState:
    """Derive the capability state of one metric.

    Order: known unsupported, then unreachable source, then absent value,
    then age. ``supported=None`` (unknown) never ends as ``unsupported``.
    With ``max_age_s`` set, an unknown age counts as stale.
    """
    if supported is False:
        return CapabilityState.UNSUPPORTED
    if not source_ok:
        return CapabilityState.UNREACHABLE
    if not present or not _has_value(value):
        return CapabilityState.NO_DATA
    if max_age_s is not None and (age_s is None or age_s > max_age_s):
        return CapabilityState.STALE
    return CapabilityState.MEASURED


@dataclass(frozen=True)
class RadioCapabilities:
    """Capability matrix of one radio: metric name → state.

    Metrics missing from ``states`` are "not assessed" (``state()`` returns
    None) and count as not covered. ``excluded`` metrics are deliberately
    out of scope for this radio and leave the coverage denominator.
    """

    router_key: str
    radio_key: str
    states: Mapping[str, CapabilityState]
    excluded: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        unknown = (set(self.states) | set(self.excluded)) - _METRIC_SET
        if unknown:
            raise ValueError(f"unknown metric names: {sorted(unknown)}")
        object.__setattr__(self, "states", MappingProxyType(dict(self.states)))
        object.__setattr__(self, "excluded", frozenset(self.excluded))

    def state(self, metric: str) -> CapabilityState | None:
        """Return the state of a metric, None when not assessed."""
        return self.states.get(metric)

    def coverage(self) -> float | None:
        """Share of in-scope metrics that are measured; None if none in scope."""
        in_scope = [m for m in ALL_METRICS if m not in self.excluded]
        if not in_scope:
            return None
        measured = sum(
            1 for m in in_scope if self.states.get(m) is CapabilityState.MEASURED
        )
        return measured / len(in_scope)

    def as_dict(self) -> dict[str, Any]:
        """Return the matrix as a plain dict with every metric listed."""
        return {
            "router_key": self.router_key,
            "radio_key": self.radio_key,
            "states": {
                m: (self.states[m].value if m in self.states else None)
                for m in ALL_METRICS
            },
            "excluded": sorted(self.excluded),
            "coverage": self.coverage(),
        }
