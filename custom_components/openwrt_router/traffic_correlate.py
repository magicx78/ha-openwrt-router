"""Correlation of traffic with diagnostics, WiFi RF, NI and security (Phase H).

Task §12 (traffic quality and congestion), §13 (security intelligence),
acceptance criterion 11 (other modules use the same measurements); plan §10.

**Bottleneck narrowing** (:class:`TrafficCorrelator`). Per infrastructure
point and the recent hour it collects observations, each with its value,
threshold, window and source, grouped in independent *families*:

========================  =================================  ==============
family                    indicators                         source
========================  =================================  ==============
``utilization``           share of buckets >= 80 % of link   traffic
``interface_counters``    drops, errors (own deltas)         traffic
``connectivity``          link down/carrier lost, router     traffic, NI
                          restart, NI connectivity incident
``path_quality``          latency, packet loss               net_diagnostics
``wifi_rf``               airtime, retransmissions           wifi_rf
========================  =================================  ==============

High utilisation alone is at most ``high_utilization_observed`` (never a
bottleneck, never "confirmed"); only together with a second, independent
family it becomes ``possible_bottleneck`` / ``possible_uplink_bottleneck``.
Every assessment is worded "possible"; there is no "confirmed" level at
all. Recommendations are only given with a sound data base
(``RECOMMEND_MIN_BUCKETS`` usable buckets, ``RECOMMEND_MIN_COVERAGE`` time
coverage, at least one independent family); otherwise the finding says why
none is given. No finding never means "all fine": the report carries a
verdict (``nothing_detected_in_covered_data`` / ``insufficient_data``) and
the state of every source.

**Optional modules** are reached at run time only, through narrow adapters
(:class:`DiagnosticsAdapter`, :class:`WifiRfAdapter`) over a lookup into
``hass.data``; nothing of them is imported. A missing module, a module that
is off or not ready, a changed interface or an empty answer is a
:class:`SourceStatus` (``module_missing`` / ``not_ready`` / ``no_data``)
with its reason, never a silent "ok".

**Network Intelligence** is read only: the engine listens to its bus event
(``openwrt_router_incident_event``) and keeps incident ids and types of
connectivity incidents as notes; a finding links them (``incident_refs``),
nothing is changed, suppressed or re-detected there.

**Security indicators** (:class:`SecurityIndicators`): open anomaly
candidates of volume kinds become ``traffic_analytics.indicator`` core
events with a stable ``evidence_ref`` (``evr_`` + 16 hex, HMAC of the
candidate with the module key). The evidence (point, window, bucket excerpt
of the hour before) is kept in a bounded book (100 entries, every discard
counted) and resolved by :meth:`EvidenceBook.resolve`. Indicators that need
a flow source say ``unavailable``/``needs_flow_source``. A traffic anomaly
is a statistical deviation and never called an attack. The Security Center
takes these events as timeline notes with the ``evidence_ref`` (wish W2,
1.49.1); the link state is read at run time from the center
(``accepts_traffic_indicators``): ``ready`` while it takes them,
``not_ready``/``module_disabled`` while it is off, ``module_missing``
without it. Traffic never suppresses or deduplicates events of
another module: it only emits its own, with its own dedup keys.

**Read API** (:class:`TrafficReadApi`, version 1): plain dicts with
pseudonyms only (``router_id``, ``point_id``, ``client_ref``,
``radio_id``) - latest rates, window totals with coverage, the congestion
report and evidence - so diagnostics and security can use the same
measurements without knowing traffic internals.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import math
import re
from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .traffic_capacity import LinkFacts, bucket_rate, link_bps
from .traffic_const import (
    AIRTIME_HIGH_PCT,
    ASSESS_BOTTLENECK,
    ASSESS_HIGH_UTIL,
    ASSESS_LINK_QUALITY,
    ASSESS_UPLINK_BOTTLENECK,
    ASSESS_WIFI_CONGESTION,
    ASSESS_WIFI_SINGLE,
    CONNECTIVITY_INCIDENT_TYPES,
    CONNTRACK_SOURCE_COUNT_FILE,
    CORR_BASE_CONFIDENCE,
    CORR_FAMILY_CONFIDENCE,
    CORR_MAX_CONFIDENCE,
    CORR_MIN_BUCKETS,
    CORR_WINDOW_S,
    DIAG_LATENCY_KINDS,
    DIAG_MIN_COVERAGE,
    DIAG_MIN_SAMPLES,
    DROP_MIN_COUNT,
    DROP_MIN_RATIO,
    ERROR_MIN_COUNT,
    EVENT_INDICATOR,
    EVIDENCE_EXCERPT_S,
    EVIDENCE_HEX,
    EVIDENCE_PREFIX,
    HIGH_UTIL_PCT,
    HIGH_UTIL_SHARE,
    IND_CONNECTION_RATE,
    IND_INTER_VLAN,
    IND_NEW_DESTINATIONS,
    IND_OUTBOUND,
    IND_PROTOCOL_MIX,
    IND_UNUSUAL_VOLUME,
    INDICATOR_BUDGET_PER_HOUR,
    INDICATOR_CLASSIFICATION,
    INDICATOR_POINT_KIND_S,
    INDICATOR_WORDING,
    INDICATORS,
    LATENCY_ELEVATED_FACTOR,
    LATENCY_ELEVATED_MIN_MS,
    LOSS_ELEVATED_PCT,
    MAX_CORR_POINTS,
    MAX_EVIDENCE,
    MAX_EVIDENCE_ROWS,
    MAX_LINK_DEVICES,
    MAX_LINK_SAMPLES,
    MAX_NI_NOTES,
    MAX_QUALITY_SAMPLES,
    MODULE_NAME,
    READ_API_VERSION,
    READ_WINDOWS,
    REASON_DISABLED,
    REASON_FLOW_HISTORY_NOT_BUILT,
    REASON_INSUFFICIENT_DATA,
    REASON_INTERFACE_MISMATCH,
    REASON_LOOKUP_FAILED,
    REASON_MODULE_DISABLED,
    REASON_MODULE_KEY_MISSING,
    REASON_MODULE_NOT_LOADED,
    REASON_NI_RULE,
    REASON_NO_COUNTER_DATA,
    REASON_NO_DATA_YET,
    REASON_NO_INDICATOR_INTAKE,
    REASON_NO_LINK_DATA,
    REASON_NO_LINK_SPEED,
    REASON_NO_REFERENCE,
    REASON_NO_ROUTER_SERIES,
    REASON_NOT_A_BOTTLENECK_ALONE,
    REASON_NOT_LISTENING,
    REASON_NOT_PUBLISHED,
    REASON_READ_FAILED,
    REASON_SINGLE_INDICATOR,
    REASON_TOO_FEW_SAMPLES,
    REASON_UNKNOWN_POINT,
    REASON_UNKNOWN_STATE,
    REASON_UNKNOWN_WINDOW,
    RECOMMEND_MIN_BUCKETS,
    RECOMMEND_MIN_COVERAGE,
    RECOMMEND_MIN_FAMILIES,
    RETRY_HIGH_RATE,
    RETRY_HIGH_SHARE,
    RF_MIN_VALID,
    SOURCE_MODULE_MISSING,
    SOURCE_NO_DATA,
    SOURCE_NOT_CONNECTED,
    SOURCE_NOT_READY,
    SOURCE_READY,
    SRC_DIAG,
    SRC_NI,
    SRC_SECURITY,
    SRC_TRAFFIC,
    SRC_WIFI_RF,
    VERDICT_FINDINGS,
    VERDICT_INSUFFICIENT,
    VERDICT_NOTHING_IN_COVERED,
    VOLUME_INDICATOR_KINDS,
)
from .traffic_model import (
    RATE_QUALITIES,
    AnomalyCandidate,
    Bucket,
    CandidateState,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
    quality_bit,
    valid_client_ref,
    valid_point_id,
    valid_router_id,
)
from .traffic_series import BucketSource, SeriesWindow

_LOGGER = logging.getLogger(__name__)

CORRELATED_SCOPES = frozenset({Scope.WAN, Scope.INTERFACE, Scope.PORT, Scope.VLAN})
FAMILY_UTILIZATION = "utilization"
FAMILY_COUNTERS = "interface_counters"
FAMILY_CONNECTIVITY = "connectivity"
FAMILY_PATH = "path_quality"
FAMILY_WIFI = "wifi_rf"
_EVIDENCE_RE = re.compile(rf"{EVIDENCE_PREFIX}[0-9a-f]{{{EVIDENCE_HEX}}}")
_TOKEN_RE = re.compile(r"[A-Za-z0-9._:-]{1,64}")
_TYPE_RE = re.compile(r"[a-z0-9_]{1,48}")
_GAP_BITS = quality_bit(Quality.GAP)
_RESTART_BITS = quality_bit(Quality.ROUTER_RESTART)


def valid_evidence_ref(value: Any) -> bool:
    """True for an evidence reference (``evr_`` + 16 hex)."""
    return isinstance(value, str) and _EVIDENCE_RE.fullmatch(value) is not None


def _num(value: Any) -> float | None:
    """A finite number or None (bool is no number here)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


# --- source status ----------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SourceStatus:
    """State of one correlation source; never "ok" without data."""

    module: str
    state: str
    reason: str | None = None

    @property
    def ready(self) -> bool:
        """True only for ``ready``."""
        return self.state == SOURCE_READY

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {"module": self.module, "state": self.state, "reason": self.reason}


# --- adapter: Network Diagnostics ---------------------------------------------------------


class DiagnosticsLike(Protocol):
    """What the adapter needs from Network Diagnostics (read only)."""

    def history_view(self) -> Mapping[str, Any]:
        """``{state, reasons, windows, series:[{point, kind, windows:{..}}]}``."""


@dataclass(frozen=True, slots=True)
class LatencyFacts:
    """Path quality of one router over the recent hour (worst latency series)."""

    mean_ms: float | None
    reference_ms: float | None
    loss_pct: float | None
    samples: int
    coverage: float
    series: int
    latency_elevated: bool | None
    loss_elevated: bool | None
    latency_reason: str | None = None


def _summary(raw: Any) -> dict[str, float] | None:
    """The numbers of a ``LatencySummary`` dict (None: not one)."""
    if not isinstance(raw, Mapping):
        return None
    answered, lost = _num(raw.get("answered")), _num(raw.get("lost"))
    if answered is None or lost is None:
        return None
    return {
        "samples": answered + lost,
        "coverage": _num(raw.get("coverage")) or 0.0,
        "mean_ms": _num(raw.get("mean_ms")),  # type: ignore[dict-item]
        "loss_pct": _num(raw.get("loss_pct")),  # type: ignore[dict-item]
    }


class DiagnosticsAdapter:
    """Reads latency and packet loss per router from Network Diagnostics.

    Ausgerichtet an main 1.48.0 (geprüft gegen den gemergten Code):
    ``hass.data[const.DATA_NET_DIAGNOSTICS]`` holds a
    ``diag_runtime.NetDiagnostics`` whose ``history_view()`` returns
    ``{"state": "off"|"not_ready"|"ready", "reasons": [...],
    "windows": ["1h","24h","7d","30d"], "series": [{"point": <router_id or
    "ha">, "target_id", "kind": "icmp"|"tcp"|"http"|"dns"|"fact", "family",
    "windows": {"1h": LatencySummary|None, ...}}]}`` with the fields of
    ``diag_stats.LatencySummary`` (``answered``, ``lost``,
    ``coverage``, ``mean_ms``, ``loss_pct``, ...). Nothing of that module is
    imported; a different shape is ``not_ready``/``interface_mismatch``.
    """

    def __init__(self, lookup: Callable[[], Any]) -> None:
        """Adapter over ``lookup`` (returns the module object or None)."""
        self.lookup = lookup
        self.counters: Counter[str] = Counter()

    def _status(self, state: str, reason: str | None) -> SourceStatus:
        self.counters[f"{state}:{reason}"] += 1
        return SourceStatus(SRC_DIAG, state, reason)

    def view(self) -> tuple[SourceStatus, Mapping[str, Any] | None]:
        """Module state and its history view (None unless ready)."""
        try:
            module = self.lookup()
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("Diagnostics lookup failed (%s)", type(err).__name__)
            return self._status(SOURCE_NOT_READY, REASON_LOOKUP_FAILED), None
        if module is None:
            return self._status(SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED), None
        read = getattr(module, "history_view", None)
        if not callable(read):
            return self._status(SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH), None
        try:
            view = read()
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("Diagnostics read failed (%s)", type(err).__name__)
            return self._status(SOURCE_NOT_READY, REASON_READ_FAILED), None
        if not isinstance(view, Mapping):
            return self._status(SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH), None
        state = view.get("state")
        if state == "off":
            return self._status(SOURCE_NOT_READY, REASON_MODULE_DISABLED), None
        if state == "not_ready":
            reasons = view.get("reasons")
            first = reasons[0] if isinstance(reasons, list) and reasons else None
            reason = first if isinstance(first, str) else REASON_UNKNOWN_STATE
            return self._status(SOURCE_NOT_READY, reason[:64]), None
        if state != "ready" or not isinstance(view.get("series"), list):
            return self._status(SOURCE_NOT_READY, REASON_UNKNOWN_STATE), None
        return SourceStatus(SRC_DIAG, SOURCE_READY), view

    def latency(
        self, router_id: str, view: Mapping[str, Any] | None = None
    ) -> tuple[SourceStatus, LatencyFacts | None]:
        """Path quality of ``router_id`` (the worst usable latency series)."""
        if view is None:
            status, view = self.view()
            if view is None:
                return status, None
        series = [
            s
            for s in view.get("series") or ()
            if isinstance(s, Mapping)
            and s.get("point") == router_id
            and s.get("kind") in DIAG_LATENCY_KINDS
        ]
        if not series:
            return self._status(SOURCE_NO_DATA, REASON_NO_ROUTER_SERIES), None
        usable: list[tuple[dict[str, float], dict[str, float] | None]] = []
        for item in series:
            windows = item.get("windows")
            if not isinstance(windows, Mapping):
                continue
            hour = _summary(windows.get("1h"))
            if (
                hour is None
                or hour["samples"] < DIAG_MIN_SAMPLES
                or hour["coverage"] < DIAG_MIN_COVERAGE
            ):
                continue
            usable.append((hour, _summary(windows.get("7d"))))
        if not usable:
            return self._status(SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES), None
        means = [(h["mean_ms"], ref) for h, ref in usable if h["mean_ms"] is not None]
        mean, ref_summary = max(means, key=lambda m: m[0]) if means else (None, None)
        reference = None if ref_summary is None else ref_summary["mean_ms"]
        latency_elevated: bool | None = None
        latency_reason: str | None = None
        if mean is not None and reference is not None and reference > 0:
            latency_elevated = (
                mean >= LATENCY_ELEVATED_FACTOR * reference
                and mean - reference >= LATENCY_ELEVATED_MIN_MS
            )
        elif mean is not None:
            latency_reason = REASON_NO_REFERENCE
        losses = [h["loss_pct"] for h, _ref in usable if h["loss_pct"] is not None]
        loss = max(losses) if losses else None
        return SourceStatus(SRC_DIAG, SOURCE_READY), LatencyFacts(
            mean_ms=None if mean is None else round(mean, 2),
            reference_ms=None if reference is None else round(reference, 2),
            loss_pct=None if loss is None else round(loss, 2),
            samples=int(sum(h["samples"] for h, _ref in usable)),
            coverage=round(min(h["coverage"] for h, _ref in usable), 3),
            series=len(usable),
            latency_elevated=latency_elevated,
            loss_elevated=None if loss is None else loss >= LOSS_ELEVATED_PCT,
            latency_reason=latency_reason,
        )


# --- adapter: WiFi RF ---------------------------------------------------------------------


class WifiRfLike(Protocol):
    """The WiFi RF read API (W6, ``rf_center.RfCenter``, version 1)."""

    status: str

    def radio_utilization(
        self, router_id: str, window_s: float, interfaces: Iterable[str] = ()
    ) -> Mapping[str, Mapping[str, Any]]:
        """radio_id -> utilization entry (``measured_at``, ``interfaces``)."""

    def client_retry_rates(
        self, router_id: str, window_s: float
    ) -> Mapping[str, Mapping[str, Any]]:
        """client_ref -> retry rate entry (``radio_id``, ``measured_at``)."""


# Station point ids named per radio at most (the count is always complete).
MAX_RF_POINT_IDS = 16


@dataclass(frozen=True, slots=True)
class RadioRfFacts:
    """Airtime and retransmissions of one radio, linked to traffic points.

    ``radio_id`` is WiFi RF's radio identity (UCI radio name, unique with
    the router id); ``point_ids`` are the traffic station points measured
    at the radio's AP interfaces (pseudonyms only, at most
    :data:`MAX_RF_POINT_IDS`; ``points_linked`` is the full count).
    """

    radio_id: str
    band: str | None
    state: str
    reason: str | None
    measured_at: float | None
    airtime_mean_pct: float | None
    airtime_high: bool | None
    sustained_overload: bool | None
    clients_measured: int
    clients_high_retry: int
    point_ids: tuple[str, ...] = ()
    points_linked: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Plain dict (pseudonyms and figures only)."""
        return {
            "radio_id": self.radio_id,
            "band": self.band,
            "state": self.state,
            "reason": self.reason,
            "measured_at": self.measured_at,
            "airtime_mean_pct": self.airtime_mean_pct,
            "airtime_high": self.airtime_high,
            "sustained_overload": self.sustained_overload,
            "clients_measured": self.clients_measured,
            "clients_high_retry": self.clients_high_retry,
            "point_ids": list(self.point_ids),
            "points_linked": self.points_linked,
        }


@dataclass(frozen=True, slots=True)
class RfFacts:
    """Airtime and retransmissions of one router's radios."""

    radios: int
    busiest_radio: str | None
    airtime_mean_pct: float | None
    airtime_high: bool | None
    clients_measured: int
    clients_high_retry: int
    retries_high: bool | None
    per_radio: tuple[RadioRfFacts, ...] = ()


def _short(value: Any) -> str | None:
    return value[:32] if isinstance(value, str) and value else None


class WifiRfAdapter:
    """Reads airtime and retransmissions per radio from the WiFi RF center.

    Uses the center's read API (W6, ``rf_center.RfCenter`` in
    ``hass.data[const.DATA_WIFI_RF_CENTER]``): ``status`` /
    ``not_ready_reasons()`` for the module state, ``radio_utilization`` and
    ``client_retry_rates`` for the figures. Both only read the center's last
    evaluation: no extra router call.

    **Link to traffic points.** Traffic station points carry the AP
    interface name they were measured at. The adapter hands these names to
    ``radio_utilization`` (``interfaces``); the center answers per radio
    with the names that belong to it, so every radio gets the ids of its
    station points. Only pseudonyms (``point_id``, ``client_ref``) and RF's
    radio id leave the adapter; no interface name, no MAC.

    A center without the read API is ``not_ready``/``interface_mismatch``;
    nothing of WiFi RF is imported.
    """

    def __init__(self, lookup: Callable[[], Any]) -> None:
        """Adapter over ``lookup`` (returns the center object or None)."""
        self.lookup = lookup
        self.counters: Counter[str] = Counter()

    def _status(self, state: str, reason: str | None) -> SourceStatus:
        self.counters[f"{state}:{reason}"] += 1
        return SourceStatus(SRC_WIFI_RF, state, reason)

    @staticmethod
    def _has_w6(center: Any) -> bool:
        return callable(getattr(center, "radio_utilization", None)) and callable(
            getattr(center, "client_retry_rates", None)
        )

    def module(self) -> tuple[SourceStatus, Any]:
        """Module state and the center (None unless it looks usable)."""
        try:
            center = self.lookup()
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("WiFi RF lookup failed (%s)", type(err).__name__)
            return self._status(SOURCE_NOT_READY, REASON_LOOKUP_FAILED), None
        if center is None:
            return self._status(SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED), None
        try:
            if not self._has_w6(center):
                return self._status(SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH), None
            state = getattr(center, "status", None)
            if state is None:  # no state to read: the switch alone
                if getattr(center, "enabled", True) is False:
                    return self._status(SOURCE_NOT_READY, REASON_MODULE_DISABLED), None
                return SourceStatus(SRC_WIFI_RF, SOURCE_READY), center
            if not isinstance(state, str):
                return self._status(SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH), None
            if state == "off":
                return self._status(SOURCE_NOT_READY, REASON_MODULE_DISABLED), None
            if state == "not_ready":
                read = getattr(center, "not_ready_reasons", None)
                reasons = read() if callable(read) else None
                first = reasons[0] if isinstance(reasons, list) and reasons else None
                reason = first if isinstance(first, str) else REASON_UNKNOWN_STATE
                return self._status(SOURCE_NOT_READY, reason[:64]), None
            if state != "ready":
                return self._status(SOURCE_NOT_READY, REASON_UNKNOWN_STATE), None
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("WiFi RF state failed (%s)", type(err).__name__)
            return self._status(SOURCE_NOT_READY, REASON_READ_FAILED), None
        return SourceStatus(SRC_WIFI_RF, SOURCE_READY), center

    @staticmethod
    def _radio(
        radio_id: str,
        entry: Mapping[str, Any],
        retries: Sequence[Mapping[str, Any]],
        interfaces: Mapping[str, Sequence[str]],
    ) -> RadioRfFacts:
        mean = _num(entry.get("mean"))
        valid = _num(entry.get("valid_count")) or 0
        overload = entry.get("sustained_overload")
        overload = overload if isinstance(overload, bool) else None
        usable = mean is not None and valid >= RF_MIN_VALID
        airtime_high: bool | None = None
        if usable or overload is True:
            airtime_high = overload is True or (
                mean is not None and mean >= AIRTIME_HIGH_PCT
            )
        measured = high = 0
        for metric in retries:
            value = _num(metric.get("value"))
            if metric.get("state") != "measured" or value is None:
                continue
            measured += 1
            if value >= RETRY_HIGH_RATE:
                high += 1
        points: list[str] = []
        for name in entry.get("interfaces") or ():
            for pid in interfaces.get(name, ()) if isinstance(name, str) else ():
                if valid_point_id(pid) and pid not in points:
                    points.append(pid)
        points.sort()
        state = entry.get("state")
        reason = entry.get("reason")
        if mean is not None and not usable and reason is None:
            reason = REASON_TOO_FEW_SAMPLES
        return RadioRfFacts(
            radio_id=radio_id[:32],
            band=_short(entry.get("band")),
            state=_short(state) or "unknown",
            reason=_short(reason),
            measured_at=_num(entry.get("measured_at")),
            airtime_mean_pct=round(mean, 2) if usable and mean is not None else None,
            airtime_high=airtime_high,
            sustained_overload=overload,
            clients_measured=measured,
            clients_high_retry=high,
            point_ids=tuple(points[:MAX_RF_POINT_IDS]),
            points_linked=len(points),
        )

    def facts(
        self,
        router_id: str,
        window_s: int = CORR_WINDOW_S,
        interfaces: Mapping[str, Sequence[str]] | None = None,
    ) -> tuple[SourceStatus, RfFacts | None]:
        """Airtime/retries of ``router_id`` over ``window_s``, per radio.

        ``interfaces``: AP interface name -> traffic station point ids of
        this router (for the link; the names never leave the adapter).
        """
        status, center = self.module()
        if center is None:
            return status, None
        links = interfaces or {}
        try:
            radios = center.radio_utilization(router_id, window_s, sorted(links))
            by_ref = center.client_retry_rates(router_id, window_s)
            if not isinstance(radios, Mapping) or not isinstance(by_ref, Mapping):
                return (
                    self._status(SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH),
                    None,
                )
            retries: dict[str | None, list[Mapping[str, Any]]] = {}
            for ref, metric in by_ref.items():
                if valid_client_ref(ref) and isinstance(metric, Mapping):
                    radio = metric.get("radio_id")
                    key = radio if isinstance(radio, str) and radio in radios else None
                    retries.setdefault(key, []).append(metric)
            per_radio = tuple(
                self._radio(rid, entry, retries.get(rid, ()), links)
                for rid, entry in sorted(radios.items())
                if isinstance(rid, str) and isinstance(entry, Mapping)
            )
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("WiFi RF read failed (%s)", type(err).__name__)
            return self._status(SOURCE_NOT_READY, REASON_READ_FAILED), None
        busiest: tuple[float, str] | None = None
        overload = False
        for radio in per_radio:
            if radio.sustained_overload is True:
                overload = True
            mean = radio.airtime_mean_pct
            if mean is not None and (busiest is None or mean > busiest[0]):
                busiest = (mean, radio.radio_id)
        unassigned = WifiRfAdapter._radio("", {}, retries.get(None, ()), {})
        measured = unassigned.clients_measured + sum(
            r.clients_measured for r in per_radio
        )
        high = unassigned.clients_high_retry + sum(
            r.clients_high_retry for r in per_radio
        )
        if busiest is None and not overload and measured == 0:
            return self._status(SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES), None
        airtime_high: bool | None = None
        if busiest is not None or overload:
            airtime_high = overload or (
                busiest is not None and busiest[0] >= AIRTIME_HIGH_PCT
            )
        return SourceStatus(SRC_WIFI_RF, SOURCE_READY), RfFacts(
            radios=len(per_radio),
            busiest_radio=None if busiest is None else busiest[1],
            airtime_mean_pct=None if busiest is None else busiest[0],
            airtime_high=airtime_high,
            clients_measured=measured,
            clients_high_retry=high,
            retries_high=None
            if measured == 0
            else high >= 1 and high / measured >= RETRY_HIGH_SHARE,
            per_radio=per_radio,
        )


def _station_interfaces(
    points: Iterable[MeasurementPoint],
) -> dict[str, dict[str, list[str]]]:
    """router_id -> AP interface name -> station point ids (for the RF link)."""
    out: dict[str, dict[str, list[str]]] = {}
    for point in points:
        if (
            point.scope is not Scope.STATION
            or point.router_id is None
            or point.radio_id is None
        ):
            continue
        out.setdefault(point.router_id, {}).setdefault(point.radio_id, []).append(
            point.point_id
        )
    return out


# --- findings --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Observation:
    """One measured indicator with its value, threshold and window."""

    indicator: str
    family: str
    elevated: bool
    value: float | None
    unit: str
    threshold: float | None
    window_s: int
    start: float
    end: float
    source: str
    detail: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "indicator": self.indicator,
            "family": self.family,
            "elevated": self.elevated,
            "value": self.value,
            "unit": self.unit,
            "threshold": self.threshold,
            "window_s": self.window_s,
            "start": self.start,
            "end": self.end,
            "source": self.source,
            "detail": dict(self.detail),
        }


@dataclass(frozen=True, slots=True)
class CongestionFinding:
    """A possible bottleneck or quality issue (never a confirmed one)."""

    finding_id: str
    router_id: str | None
    point_id: str | None
    scope: str
    assessment: str
    observations: tuple[Observation, ...]
    independent_families: tuple[str, ...]
    possible_causes: tuple[str, ...]
    recommendations: tuple[str, ...]
    recommendation_withheld: str | None
    confidence: float
    coverage: Mapping[str, Any]
    unmeasured: Mapping[str, str]
    incident_refs: tuple[str, ...]
    window_s: int
    start: float
    end: float
    wording: str = "possible"

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (pseudonyms only)."""
        return {
            "finding_id": self.finding_id,
            "router_id": self.router_id,
            "point_id": self.point_id,
            "scope": self.scope,
            "assessment": self.assessment,
            "wording": self.wording,
            "observations": [o.to_dict() for o in self.observations],
            "independent_families": list(self.independent_families),
            "possible_causes": list(self.possible_causes),
            "recommendations": list(self.recommendations),
            "recommendation_withheld": self.recommendation_withheld,
            "confidence": self.confidence,
            "coverage": dict(self.coverage),
            "unmeasured": dict(self.unmeasured),
            "incident_refs": list(self.incident_refs),
            "window_s": self.window_s,
            "start": self.start,
            "end": self.end,
        }


@dataclass(frozen=True, slots=True)
class CorrelationReport:
    """All findings of one evaluation, the verdict and the source states."""

    generated_at: float
    verdict: str
    findings: tuple[CongestionFinding, ...]
    sources: tuple[SourceStatus, ...]
    points_evaluated: int
    points_insufficient: int

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "v": READ_API_VERSION,
            "generated_at": self.generated_at,
            "verdict": self.verdict,
            "findings": [f.to_dict() for f in self.findings],
            "sources": [s.to_dict() for s in self.sources],
            "points_evaluated": self.points_evaluated,
            "points_insufficient": self.points_insufficient,
        }


def finding_id(*parts: Any) -> str:
    """Deterministic id of a finding (``tcf_`` + 16 hex)."""
    text = "\x1f".join("" if p is None else str(p) for p in parts)
    return "tcf_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def confidence_of(families: int, time_coverage: float) -> float:
    """0.3 + 0.2 per independent family, times time coverage, at most 0.8."""
    base = min(
        CORR_MAX_CONFIDENCE, CORR_BASE_CONFIDENCE + CORR_FAMILY_CONFIDENCE * families
    )
    return round(max(0.0, min(1.0, time_coverage)) * base, 2)


@dataclass(slots=True)
class _Quality:
    """Error/drop/packet deltas of one point (bounded, RAM)."""

    router_id: str | None
    samples: deque[tuple[float, tuple[int | None, ...]]] = field(
        default_factory=lambda: deque(maxlen=MAX_QUALITY_SAMPLES)
    )


def _sum_known(values: Iterable[int | None]) -> int | None:
    known = [v for v in values if v is not None]
    return sum(known) if known else None


class TrafficCorrelator:
    """Bottleneck narrowing from several indicators (see the module docstring)."""

    def __init__(self) -> None:
        """Empty correlator (RAM only, bounded)."""
        self._quality: OrderedDict[str, _Quality] = OrderedDict()
        self._links: OrderedDict[tuple[str, str], deque[tuple[float, bool]]] = (
            OrderedDict()
        )
        self._incidents: deque[tuple[float, str, str, str, str]] = deque(
            maxlen=MAX_NI_NOTES
        )
        self.ni_listening = False
        self.counters: Counter[str] = Counter()

    # -- feeding ------------------------------------------------------------------------

    def observe_rates(self, rates: Iterable[Rate]) -> None:
        """Keep the error/drop/packet deltas of valid infrastructure rates."""
        for rate in rates:
            point = rate.point
            if (
                point.scope not in CORRELATED_SCOPES
                or rate.quality not in RATE_QUALITIES
            ):
                continue
            wall = rate.wall_s
            if wall is None or not math.isfinite(wall):
                continue
            entry = self._quality.get(point.point_id)
            if entry is None:
                if len(self._quality) >= MAX_CORR_POINTS:
                    self.counters["dropped_quality_points"] += 1
                    continue
                entry = self._quality[point.point_id] = _Quality(point.router_id)
            entry.samples.append(
                (
                    wall,
                    (
                        rate.rx_errors_delta,
                        rate.tx_errors_delta,
                        rate.rx_dropped_delta,
                        rate.tx_dropped_delta,
                        rate.rx_packets_delta,
                        rate.tx_packets_delta,
                    ),
                )
            )

    def observe_links(
        self, router_id: str, devices: Iterable[Any] | None, wall: float | None
    ) -> None:
        """Keep up/carrier per device of one poll (``DeviceCounters``)."""
        if devices is None or wall is None or not math.isfinite(wall):
            return
        for device in devices:
            name = getattr(device, "name", None)
            up, carrier = getattr(device, "up", None), getattr(device, "carrier", None)
            if not isinstance(name, str) or (up is None and carrier is None):
                continue
            ok = up is not False and carrier is not False
            key = (router_id, name)
            ring = self._links.get(key)
            if ring is None:
                if len(self._links) >= MAX_LINK_DEVICES:
                    self.counters["dropped_link_devices"] += 1
                    continue
                ring = self._links[key] = deque(maxlen=MAX_LINK_SAMPLES)
            ring.append((wall, ok))

    def observe_incident(
        self, data: Any, router_id_of_entry: Callable[[str], str | None], wall: float
    ) -> bool:
        """Note an NI incident bus event (ids and type only); True if kept."""
        if not isinstance(data, Mapping):
            return False
        kind, state, inc_id = (
            data.get("type"),
            data.get("state"),
            data.get("incident_id"),
        )
        if not (
            isinstance(kind, str)
            and _TYPE_RE.fullmatch(kind)
            and isinstance(inc_id, str)
            and _TOKEN_RE.fullmatch(inc_id)
            and isinstance(state, str)
            and _TYPE_RE.fullmatch(state)
        ):
            self.counters["ni_events_invalid"] += 1
            return False
        kept = False
        entries = data.get("entry_ids")
        for entry_id in entries if isinstance(entries, list) else ():
            if not isinstance(entry_id, str):
                continue
            try:
                rid = router_id_of_entry(entry_id)
            except Exception:  # noqa: BLE001 - unknown entry: not kept
                rid = None
            if not valid_router_id(rid):
                continue
            self._incidents.append((wall, rid, kind, state, inc_id))  # type: ignore[arg-type]
            kept = True
        self.counters["ni_events_kept" if kept else "ni_events_unmapped"] += 1
        return kept

    # -- maintenance ------------------------------------------------------------------------

    def drop_router(self, router_id: str | None) -> None:
        """Forget a router."""
        for pid in [p for p, q in self._quality.items() if q.router_id == router_id]:
            del self._quality[pid]
        for key in [k for k in self._links if k[0] == router_id]:
            del self._links[key]
        kept = [n for n in self._incidents if n[1] != router_id]
        self._incidents.clear()
        self._incidents.extend(kept)

    def clear(self) -> None:
        """Forget everything (module off)."""
        self._quality.clear()
        self._links.clear()
        self._incidents.clear()
        self.ni_listening = False

    def summary(self) -> dict[str, Any]:
        """Counts only."""
        return {
            "quality_points": len(self._quality),
            "link_devices": len(self._links),
            "ni_notes": len(self._incidents),
            "ni_listening": self.ni_listening,
            **dict(self.counters),
        }

    # -- indicators -------------------------------------------------------------------------

    def _utilization(
        self, point: MeasurementPoint, window: SeriesWindow, link: LinkFacts | None
    ) -> tuple[Observation | None, str | None, int]:
        usable = [b for b in window.buckets if not b.gappy]
        start, end = window.end - window.window_s, window.end
        speed = (
            None
            if point.scope is Scope.VLAN or link is None
            else link_bps(link.link_mbps)
        )
        if speed is None:
            return None, REASON_NO_LINK_SPEED, len(usable)
        if len(usable) < CORR_MIN_BUCKETS:
            return None, REASON_INSUFFICIENT_DATA, len(usable)
        half = link is not None and link.duplex == "half"
        loads: list[float] = []
        for bucket in usable:
            known = [
                v
                for v in (bucket_rate(bucket, "rx"), bucket_rate(bucket, "tx"))
                if v is not None
            ]
            if known:
                loads.append(sum(known) if half else max(known))
        if len(loads) < CORR_MIN_BUCKETS:
            return None, REASON_INSUFFICIENT_DATA, len(usable)
        pcts = [100.0 * v / speed for v in loads]
        share = sum(1 for p in pcts if p >= HIGH_UTIL_PCT) / len(pcts)
        return (
            Observation(
                indicator="utilization_high",
                family=FAMILY_UTILIZATION,
                elevated=share >= HIGH_UTIL_SHARE,
                value=round(sum(pcts) / len(pcts), 2),
                unit="pct_of_link",
                threshold=HIGH_UTIL_PCT,
                window_s=window.window_s,
                start=start,
                end=end,
                source=SRC_TRAFFIC,
                detail={
                    "peak_pct": round(max(pcts), 2),
                    "share_of_buckets_high": round(share, 3),
                    "required_share": HIGH_UTIL_SHARE,
                    "usable_buckets": len(loads),
                    "link_mbps": None if link is None else link.link_mbps,
                    "duplex": None if link is None else link.duplex,
                },
            ),
            None,
            len(usable),
        )

    def _counters(
        self, point: MeasurementPoint, start: float, end: float, window_s: int
    ) -> tuple[list[Observation], str | None]:
        entry = self._quality.get(point.point_id)
        rows = [v for t, v in (entry.samples if entry else ()) if start < t <= end]
        if not rows:
            return [], REASON_NO_COUNTER_DATA
        errors = _sum_known(v for r in rows for v in r[0:2])
        drops = _sum_known(v for r in rows for v in r[2:4])
        packets = _sum_known(v for r in rows for v in r[4:6])
        out: list[Observation] = []
        for name, value, minimum in (
            ("interface_drops", drops, DROP_MIN_COUNT),
            ("interface_errors", errors, ERROR_MIN_COUNT),
        ):
            if value is None:
                continue
            ratio = None if not packets else value / packets
            elevated = value >= minimum and (ratio is None or ratio >= DROP_MIN_RATIO)
            out.append(
                Observation(
                    indicator=name,
                    family=FAMILY_COUNTERS,
                    elevated=elevated,
                    value=float(value),
                    unit="count",
                    threshold=float(minimum),
                    window_s=window_s,
                    start=start,
                    end=end,
                    source=SRC_TRAFFIC,
                    detail={
                        "packets": packets,
                        "ratio": None if ratio is None else round(ratio, 6),
                        "min_ratio": DROP_MIN_RATIO,
                        "rates": len(rows),
                    },
                )
            )
        return out, None if out else REASON_NO_COUNTER_DATA

    def _connectivity(
        self,
        point: MeasurementPoint,
        window: SeriesWindow,
        start: float,
        end: float,
    ) -> tuple[list[Observation], tuple[str, ...], str | None]:
        out: list[Observation] = []
        reason: str | None = None
        ring = (
            self._links.get((point.router_id or "", point.device))
            if point.device is not None
            else None
        )
        seen = [ok for t, ok in (ring or ()) if start < t <= end]
        if seen:
            down = sum(1 for ok in seen if not ok)
            out.append(
                Observation(
                    indicator="link_down_observed",
                    family=FAMILY_CONNECTIVITY,
                    elevated=down > 0,
                    value=float(down),
                    unit="polls",
                    threshold=1.0,
                    window_s=window.window_s,
                    start=start,
                    end=end,
                    source=SRC_TRAFFIC,
                    detail={"polls": len(seen)},
                )
            )
        else:
            reason = REASON_NO_LINK_DATA
        restarts = sum(1 for b in window.buckets if b.quality_mask & _RESTART_BITS)
        if restarts:
            out.append(
                Observation(
                    indicator="router_restart",
                    family=FAMILY_CONNECTIVITY,
                    elevated=True,
                    value=float(restarts),
                    unit="buckets",
                    threshold=1.0,
                    window_s=window.window_s,
                    start=start,
                    end=end,
                    source=SRC_TRAFFIC,
                    detail={
                        "gap_buckets": sum(
                            1 for b in window.buckets if b.quality_mask & _GAP_BITS
                        )
                    },
                )
            )
        refs: list[str] = []
        notes = [
            n
            for n in self._incidents
            if n[1] == point.router_id
            and n[2] in CONNECTIVITY_INCIDENT_TYPES
            and start - CORR_WINDOW_S < n[0] <= end
        ]
        if notes:
            refs = sorted({n[4] for n in notes})
            out.append(
                Observation(
                    indicator="connectivity_incident",
                    family=FAMILY_CONNECTIVITY,
                    elevated=True,
                    value=float(len(refs)),
                    unit="incidents",
                    threshold=1.0,
                    window_s=window.window_s,
                    start=start,
                    end=end,
                    source=SRC_NI,
                    detail={"types": sorted({n[2] for n in notes})},
                )
            )
        return out, tuple(refs), reason

    @staticmethod
    def _path(
        facts: LatencyFacts, window_s: int, start: float, end: float
    ) -> list[Observation]:
        out: list[Observation] = []
        if facts.latency_elevated is not None:
            out.append(
                Observation(
                    indicator="latency_elevated",
                    family=FAMILY_PATH,
                    elevated=facts.latency_elevated,
                    value=facts.mean_ms,
                    unit="ms",
                    threshold=None
                    if facts.reference_ms is None
                    else round(
                        max(
                            LATENCY_ELEVATED_FACTOR * facts.reference_ms,
                            facts.reference_ms + LATENCY_ELEVATED_MIN_MS,
                        ),
                        2,
                    ),
                    window_s=window_s,
                    start=start,
                    end=end,
                    source=SRC_DIAG,
                    detail={
                        "reference_ms_7d": facts.reference_ms,
                        "samples": facts.samples,
                        "series": facts.series,
                        "coverage": facts.coverage,
                    },
                )
            )
        if facts.loss_elevated is not None:
            out.append(
                Observation(
                    indicator="packet_loss",
                    family=FAMILY_PATH,
                    elevated=facts.loss_elevated,
                    value=facts.loss_pct,
                    unit="pct",
                    threshold=LOSS_ELEVATED_PCT,
                    window_s=window_s,
                    start=start,
                    end=end,
                    source=SRC_DIAG,
                    detail={"samples": facts.samples, "coverage": facts.coverage},
                )
            )
        return out

    # -- evaluation -------------------------------------------------------------------------

    def evaluate(
        self,
        source: BucketSource,
        *,
        now: float,
        links: Mapping[str, LinkFacts] | None = None,
        uplink_ports: Mapping[str, frozenset[str] | None] | None = None,
        diagnostics: DiagnosticsAdapter | None = None,
        wifi_rf: WifiRfAdapter | None = None,
        router_id: str | None = None,
    ) -> CorrelationReport:
        """Findings of every infrastructure point (and radios) over the last hour."""
        findings: list[CongestionFinding] = []
        evaluated = insufficient = 0
        diag_status = SourceStatus(
            SRC_DIAG, SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED
        )
        diag_view: Mapping[str, Any] | None = None
        if diagnostics is not None:
            diag_status, diag_view = diagnostics.view()
        points = sorted(
            (
                p
                for p in source.points()
                if p.scope in CORRELATED_SCOPES
                and (router_id is None or p.router_id == router_id)
            ),
            key=lambda p: (
                p.router_id or "",
                p.scope.value,
                p.device or "",
                p.vlan_id or 0,
            ),
        )[:MAX_CORR_POINTS]
        routers = sorted({p.router_id for p in points if p.router_id is not None})
        diag_facts: dict[str, tuple[SourceStatus, LatencyFacts | None]] = {}
        for point in points:
            window = source.window(point.point_id, CORR_WINDOW_S, end=now)
            if window is None:
                continue
            evaluated += 1
            uplink = _is_uplink(point, uplink_ports)
            path: tuple[SourceStatus, LatencyFacts | None] | None = None
            if uplink and point.router_id is not None:
                if diagnostics is None or diag_view is None:
                    path = (diag_status, None)
                else:
                    path = diag_facts.get(point.router_id)
                    if path is None:
                        path = diag_facts[point.router_id] = diagnostics.latency(
                            point.router_id, diag_view
                        )
            finding, enough = self._point_finding(
                point,
                window,
                link=(links or {}).get(point.point_id),
                uplink=uplink,
                path=path,
                now=now,
            )
            if not enough:
                insufficient += 1
            if finding is not None:
                findings.append(finding)
        rf_statuses: list[SourceStatus] = []
        if wifi_rf is not None:
            stations = _station_interfaces(source.points())
            for rid in routers:
                status, facts = wifi_rf.facts(rid, interfaces=stations.get(rid))
                rf_statuses.append(status)
                if facts is not None:
                    found = self._rf_finding(rid, facts, now, status)
                    if found is not None:
                        findings.append(found)
        if wifi_rf is None:
            rf_default = SourceStatus(
                SRC_WIFI_RF, SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED
            )
        else:
            # No router asked yet: still name the module state, never "no data"
            # for a module that is not even there.
            module_status, _center = wifi_rf.module()
            rf_default = (
                SourceStatus(SRC_WIFI_RF, SOURCE_NO_DATA, REASON_NO_DATA_YET)
                if module_status.ready
                else module_status
            )
        rf_status = _merge_status(rf_statuses, rf_default)
        diag_routers = [s for s, _f in diag_facts.values()]
        sources = (
            SourceStatus(
                SRC_TRAFFIC,
                SOURCE_READY if evaluated else SOURCE_NO_DATA,
                None if evaluated else REASON_NO_DATA_YET,
            ),
            _merge_status(diag_routers, diag_status) if diag_view else diag_status,
            rf_status,
            SourceStatus(
                SRC_NI,
                SOURCE_READY if self.ni_listening else SOURCE_NOT_CONNECTED,
                None if self.ni_listening else REASON_NOT_LISTENING,
            ),
        )
        if findings:
            verdict = VERDICT_FINDINGS
        elif evaluated == 0 or insufficient == evaluated:
            verdict = VERDICT_INSUFFICIENT
        else:
            verdict = VERDICT_NOTHING_IN_COVERED
        return CorrelationReport(
            generated_at=now,
            verdict=verdict,
            findings=tuple(findings),
            sources=sources,
            points_evaluated=evaluated,
            points_insufficient=insufficient,
        )

    def _point_finding(
        self,
        point: MeasurementPoint,
        window: SeriesWindow,
        *,
        link: LinkFacts | None,
        uplink: bool | None,
        path: tuple[SourceStatus, LatencyFacts | None] | None,
        now: float,
    ) -> tuple[CongestionFinding | None, bool]:
        start, end = window.end - window.window_s, min(window.end, now)
        observations: list[Observation] = []
        unmeasured: dict[str, str] = {}
        util, util_reason, usable = self._utilization(point, window, link)
        if util is not None:
            observations.append(util)
        else:
            unmeasured[FAMILY_UTILIZATION] = util_reason or REASON_INSUFFICIENT_DATA
        counters, counter_reason = self._counters(point, start, end, window.window_s)
        observations.extend(counters)
        if counter_reason is not None:
            unmeasured[FAMILY_COUNTERS] = counter_reason
        conn, refs, conn_reason = self._connectivity(point, window, start, end)
        observations.extend(conn)
        if conn_reason is not None and not conn:
            unmeasured[FAMILY_CONNECTIVITY] = conn_reason
        diag_state: dict[str, Any] | None = None
        if path is not None:
            status, facts = path
            diag_state = status.to_dict()
            if facts is not None:
                observations.extend(self._path(facts, window.window_s, start, end))
                if facts.latency_reason is not None:
                    unmeasured[FAMILY_PATH] = facts.latency_reason
            else:
                unmeasured[FAMILY_PATH] = f"{status.state}:{status.reason}"
        enough = usable >= CORR_MIN_BUCKETS
        elevated = [o for o in observations if o.elevated]
        if not elevated:
            return None, enough
        families = sorted(
            {o.family for o in elevated if o.family != FAMILY_UTILIZATION}
        )
        high_util = util is not None and util.elevated
        if high_util and families:
            assessment = ASSESS_UPLINK_BOTTLENECK if uplink else ASSESS_BOTTLENECK
        elif high_util:
            assessment = ASSESS_HIGH_UTIL
        else:
            assessment = ASSESS_LINK_QUALITY
        causes: list[str] = []
        recommendations: list[str] = []
        if high_util:
            causes.append("high_demand")
        if assessment in (ASSESS_BOTTLENECK, ASSESS_UPLINK_BOTTLENECK):
            causes.extend(("capacity_exhausted", "queueing_or_bufferbloat"))
            if uplink:
                causes.append("upstream_congestion")
                recommendations.extend(
                    ("check_wan_capacity", "check_sqm_configuration")
                )
            else:
                recommendations.append("check_link_capacity")
        names = {o.indicator for o in elevated}
        if "interface_errors" in names:
            causes.append("cable_or_port_fault")
            recommendations.append("check_cabling_and_port")
        if "interface_drops" in names:
            causes.append("queue_overflow")
        if FAMILY_CONNECTIVITY in families:
            causes.append("unstable_link_or_upstream")
        if FAMILY_PATH in families and not high_util:
            causes.append("upstream_or_isp_issue")
            recommendations.append("check_upstream_line")
        if assessment != ASSESS_HIGH_UTIL:
            recommendations.append("add_measuring_points")
        withheld: str | None = None
        if assessment == ASSESS_HIGH_UTIL:
            withheld = REASON_NOT_A_BOTTLENECK_ALONE
        elif len(families) < RECOMMEND_MIN_FAMILIES:
            withheld = REASON_SINGLE_INDICATOR
        elif (
            usable < RECOMMEND_MIN_BUCKETS
            or window.time_coverage < RECOMMEND_MIN_COVERAGE
        ):
            withheld = REASON_INSUFFICIENT_DATA
        if withheld is not None:
            recommendations = []
        coverage: dict[str, Any] = {
            SRC_TRAFFIC: {
                "time_coverage": round(window.time_coverage, 4),
                "area": window.coverage.value,
                "reasons": list(window.coverage_reasons),
                "usable_buckets": usable,
            },
            SRC_NI: SourceStatus(
                SRC_NI,
                SOURCE_READY if self.ni_listening else SOURCE_NOT_CONNECTED,
                None if self.ni_listening else REASON_NOT_LISTENING,
            ).to_dict(),
        }
        if diag_state is not None:
            coverage[SRC_DIAG] = diag_state
        return (
            CongestionFinding(
                finding_id=finding_id(point.point_id, assessment, int(end // 300)),
                router_id=point.router_id,
                point_id=point.point_id,
                scope=point.scope.value,
                assessment=assessment,
                observations=tuple(observations),
                independent_families=tuple(families),
                possible_causes=tuple(dict.fromkeys(causes)),
                recommendations=tuple(dict.fromkeys(recommendations)),
                recommendation_withheld=withheld,
                confidence=confidence_of(len(families), window.time_coverage),
                coverage=coverage,
                unmeasured=unmeasured,
                incident_refs=refs,
                window_s=window.window_s,
                start=start,
                end=end,
            ),
            enough,
        )

    @staticmethod
    def _rf_finding(
        router_id: str, facts: RfFacts, now: float, status: SourceStatus
    ) -> CongestionFinding | None:
        start, end = now - CORR_WINDOW_S, now
        observations: list[Observation] = []
        if facts.airtime_high is not None:
            observations.append(
                Observation(
                    indicator="airtime_high",
                    family=FAMILY_WIFI,
                    elevated=facts.airtime_high,
                    value=facts.airtime_mean_pct,
                    unit="pct_busy",
                    threshold=AIRTIME_HIGH_PCT,
                    window_s=CORR_WINDOW_S,
                    start=start,
                    end=end,
                    source=SRC_WIFI_RF,
                    detail={
                        "radio_id": facts.busiest_radio,
                        "radios": facts.radios,
                        "per_radio": [r.to_dict() for r in facts.per_radio],
                    },
                )
            )
        if facts.retries_high is not None:
            observations.append(
                Observation(
                    indicator="retransmissions_high",
                    family="wifi_retries",
                    elevated=facts.retries_high,
                    value=float(facts.clients_high_retry),
                    unit="clients",
                    threshold=RETRY_HIGH_RATE,
                    window_s=CORR_WINDOW_S,
                    start=start,
                    end=end,
                    source=SRC_WIFI_RF,
                    detail={"clients_measured": facts.clients_measured},
                )
            )
        elevated = [o for o in observations if o.elevated]
        if not elevated:
            return None
        both = len(elevated) == 2
        assessment = ASSESS_WIFI_CONGESTION if both else ASSESS_WIFI_SINGLE
        return CongestionFinding(
            finding_id=finding_id(router_id, assessment, int(end // 300)),
            router_id=router_id,
            point_id=None,
            scope="radio",
            assessment=assessment,
            observations=tuple(observations),
            independent_families=tuple(sorted({o.family for o in elevated}))
            if both
            else (),
            possible_causes=("airtime_saturation", "interference_or_weak_clients")
            if both
            else ("airtime_saturation",)
            if facts.airtime_high
            else ("weak_or_distant_clients",),
            recommendations=("check_channel_plan_and_airtime",) if both else (),
            recommendation_withheld=None if both else REASON_SINGLE_INDICATOR,
            confidence=confidence_of(1 if both else 0, 1.0),
            coverage={SRC_WIFI_RF: status.to_dict()},
            unmeasured={},
            incident_refs=(),
            window_s=CORR_WINDOW_S,
            start=start,
            end=end,
        )


def _is_uplink(
    point: MeasurementPoint, uplink_ports: Mapping[str, frozenset[str] | None] | None
) -> bool | None:
    if point.scope is Scope.WAN:
        return True
    if point.scope is not Scope.PORT:
        return False
    known = None if uplink_ports is None else uplink_ports.get(point.router_id or "")
    return None if known is None else point.device in known


def _merge_status(
    statuses: Sequence[SourceStatus], default: SourceStatus
) -> SourceStatus:
    """Ready if any router answered, else the most telling other state."""
    if not statuses:
        return default
    for state in (
        SOURCE_READY,
        SOURCE_NOT_READY,
        SOURCE_NO_DATA,
        SOURCE_MODULE_MISSING,
    ):
        for status in statuses:
            if status.state == state:
                return status
    return statuses[0]


# --- evidence and security indicators --------------------------------------------------------


def evidence_ref_of(key: bytes, candidate_id: str) -> str:
    """Stable ``evr_`` reference of a candidate (HMAC with the module key)."""
    digest = hmac.new(key, f"v1|{candidate_id}".encode(), hashlib.sha256).hexdigest()
    return EVIDENCE_PREFIX + digest[:EVIDENCE_HEX]


def _bucket_row(bucket: Bucket) -> list[Any]:
    return [
        bucket.start,
        bucket.rx_bytes,
        bucket.tx_bytes,
        None if bucket.rx_peak_bps is None else round(bucket.rx_peak_bps, 1),
        None if bucket.tx_peak_bps is None else round(bucket.tx_peak_bps, 1),
        round(bucket.covered_s, 1),
    ]


EVIDENCE_ROW_FIELDS = (
    "start",
    "rx_bytes",
    "tx_bytes",
    "rx_peak_bps",
    "tx_peak_bps",
    "covered_s",
)


class EvidenceBook:
    """Bounded evidence (``MAX_EVIDENCE``); the oldest falls, counted."""

    def __init__(self, max_entries: int = MAX_EVIDENCE) -> None:
        """Empty book."""
        self._max = max_entries
        self._entries: OrderedDict[str, dict[str, Any]] = OrderedDict()
        self.counters: Counter[str] = Counter()

    def __len__(self) -> int:
        """Entries held."""
        return len(self._entries)

    def __contains__(self, ref: object) -> bool:
        """True if ``ref`` is held."""
        return ref in self._entries

    def add(self, ref: str, entry: Mapping[str, Any]) -> None:
        """Keep ``entry`` under ``ref`` (replaces an older one of the same ref)."""
        if not valid_evidence_ref(ref):
            raise ValueError("invalid evidence_ref")
        self._entries.pop(ref, None)
        self._entries[ref] = {**entry, "evidence_ref": ref}
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
            self.counters["evidence_dropped"] += 1
        self.counters["evidence_added"] += 1

    def resolve(self, ref: Any) -> dict[str, Any] | None:
        """The evidence behind ``ref`` (a copy), None if unknown or invalid."""
        if not valid_evidence_ref(ref):
            self.counters["resolve_invalid"] += 1
            return None
        entry = self._entries.get(ref)
        if entry is None:
            self.counters["resolve_unknown"] += 1
            return None
        self.counters["resolved"] += 1
        return {
            **entry,
            "point": dict(entry.get("point") or {}),
            "rows": [list(r) for r in entry.get("rows") or ()],
        }

    def refs(self) -> list[str]:
        """Held references, oldest first."""
        return list(self._entries)

    def drop_client(self, client_ref: str) -> int:
        """Forget the evidence of one client; returns how many."""
        gone = [
            r for r, e in self._entries.items() if e.get("client_ref") == client_ref
        ]
        for ref in gone:
            del self._entries[ref]
        return len(gone)

    def drop_router(self, router_id: str | None) -> None:
        """Forget the evidence of one router."""
        for ref in [
            r for r, e in self._entries.items() if e.get("router_id") == router_id
        ]:
            del self._entries[ref]

    def clear(self) -> None:
        """Forget everything; counters stay."""
        self._entries.clear()

    def export(self) -> list[dict[str, Any]]:
        """Entries for the store (oldest first)."""
        return [dict(e) for e in self._entries.values()]

    def restore(self, rows: Iterable[Any]) -> int:
        """Take stored entries back (invalid ones are skipped and counted)."""
        taken = 0
        for raw in rows:
            entry = evidence_from_store(raw)
            if entry is None:
                self.counters["evidence_invalid_on_load"] += 1
                continue
            self._entries[entry["evidence_ref"]] = entry
            taken += 1
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)
            self.counters["evidence_dropped"] += 1
        return taken


def evidence_from_store(raw: Any) -> dict[str, Any] | None:
    """A validated evidence entry from the store (None: unusable)."""
    if not isinstance(raw, Mapping):
        return None
    ref, point = raw.get("evidence_ref"), raw.get("point")
    if not valid_evidence_ref(ref) or not isinstance(point, Mapping):
        return None
    if not valid_point_id(point.get("point_id")):
        return None
    router_id, client_ref = raw.get("router_id"), raw.get("client_ref")
    if router_id is not None and not valid_router_id(router_id):
        return None
    if client_ref is not None and not valid_client_ref(client_ref):
        return None
    rows = raw.get("rows")
    if not isinstance(rows, list) or len(rows) > MAX_EVIDENCE_ROWS:
        return None
    clean_rows: list[list[Any]] = []
    for row in rows:
        if (
            not isinstance(row, list)
            or len(row) != len(EVIDENCE_ROW_FIELDS)
            or not all(v is None or _num(v) is not None for v in row)
        ):
            return None
        clean_rows.append(list(row))
    out = {k: raw.get(k) for k in _EVIDENCE_KEYS}
    out["point"] = {
        k: point.get(k)
        for k in (
            "point_id",
            "router_id",
            "scope",
            "device",
            "vlan_id",
            "radio_id",
            "client_ref",
        )
    }
    out["rows"] = clean_rows
    for name in ("indicator", "kind", "candidate_id", "coverage"):
        if not isinstance(out.get(name), str) or len(out[name]) > 64:
            return None
    return out


_EVIDENCE_KEYS = (
    "evidence_ref",
    "indicator",
    "kind",
    "candidate_id",
    "router_id",
    "client_ref",
    "observed",
    "threshold",
    "window_s",
    "coverage",
    "confidence",
    "started",
    "created_at",
    "excerpt_start",
    "excerpt_end",
    "resolution_s",
    "wording",
)


def indicator_of(candidate: AnomalyCandidate) -> str | None:
    """Security indicator of an anomaly candidate (None: not one)."""
    if candidate.state is not CandidateState.OPEN or candidate.suppressed_reason:
        return None
    if candidate.client_ref is None and not candidate.point_id:
        return None
    if any(candidate.kind.endswith(s) for s in VOLUME_INDICATOR_KINDS):
        return IND_UNUSUAL_VOLUME
    return None


def indicator_availability(
    *,
    has_candidates_source: bool,
    flow_ready: bool,
    conntrack_sources: Mapping[str, str | None] | None,
    key_ready: bool,
) -> dict[str, dict[str, str | None]]:
    """What each indicator can say now and why not (never "ok" by default)."""
    flows = (
        {"state": "learning", "reason": REASON_FLOW_HISTORY_NOT_BUILT}
        if flow_ready
        else {"state": "unavailable", "reason": CoverageReason.NEEDS_FLOW_SOURCE.value}
    )
    if not key_ready:
        volume: dict[str, str | None] = {
            "state": "not_ready",
            "reason": REASON_MODULE_KEY_MISSING,
        }
    elif has_candidates_source:
        volume = {"state": "active", "reason": None}
    else:
        volume = {"state": "unavailable", "reason": REASON_NO_DATA_YET}
    sources = set((conntrack_sources or {}).values())
    rate = (
        {
            "state": "covered_by_network_intelligence",
            "reason": f"{REASON_NI_RULE}:system_conntrack_jump",
        }
        if CONNTRACK_SOURCE_COUNT_FILE in sources
        else {"state": "unavailable", "reason": CoverageReason.NEEDS_FLOW_SOURCE.value}
    )
    out = {
        IND_OUTBOUND: dict(flows),
        IND_UNUSUAL_VOLUME: volume,
        IND_NEW_DESTINATIONS: dict(flows),
        IND_PROTOCOL_MIX: dict(flows),
        IND_INTER_VLAN: dict(flows),
        IND_CONNECTION_RATE: rate,
    }
    return {name: out[name] for name in INDICATORS}


class SecurityIndicators:
    """Turns open volume candidates into indicator events with evidence."""

    def __init__(
        self,
        emit: Callable[..., Any] | None = None,
        security: Callable[[], Any] | None = None,
    ) -> None:
        """Publisher over ``emit`` (``ConfigurationApi.emit``; None: unbound).

        ``security`` looks up the Security Center (None: not loaded).
        """
        self.emit = emit
        self.security = security
        self.evidence = EvidenceBook()
        self._indicated: OrderedDict[str, str] = OrderedDict()
        self._hour: deque[float] = deque()
        self._point_kind: dict[tuple[str, str], float] = {}
        self.counters: Counter[str] = Counter()
        self.last_availability: dict[str, dict[str, str | None]] = (
            indicator_availability(
                has_candidates_source=False,
                flow_ready=False,
                conntrack_sources=None,
                key_ready=False,
            )
        )

    def security_status(self) -> SourceStatus:
        """Whether the Security Center takes the indicators now (W2)."""
        try:
            center = None if self.security is None else self.security()
            if center is None:
                return SourceStatus(
                    SRC_SECURITY, SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED
                )
            accepts = getattr(center, "accepts_traffic_indicators", None)
            if not isinstance(accepts, bool):
                return SourceStatus(
                    SRC_SECURITY, SOURCE_NOT_CONNECTED, REASON_NO_INDICATOR_INTAKE
                )
        except Exception as err:  # noqa: BLE001 - optional module
            _LOGGER.debug("Security Center lookup failed (%s)", type(err).__name__)
            return SourceStatus(SRC_SECURITY, SOURCE_NOT_READY, REASON_LOOKUP_FAILED)
        if not accepts:
            return SourceStatus(SRC_SECURITY, SOURCE_NOT_READY, REASON_MODULE_DISABLED)
        return SourceStatus(SRC_SECURITY, SOURCE_READY)

    def _budget(self, point_id: str, indicator: str, now: float) -> bool:
        while self._hour and now - self._hour[0] >= 3600:
            self._hour.popleft()
        if len(self._hour) >= INDICATOR_BUDGET_PER_HOUR:
            self.counters["dropped_events_budget"] += 1
            return False
        last = self._point_kind.get((point_id, indicator))
        if last is not None and 0 <= now - last < INDICATOR_POINT_KIND_S:
            self.counters["dropped_events_point_kind"] += 1
            return False
        return True

    def evaluate(
        self,
        candidates: Iterable[AnomalyCandidate],
        source: BucketSource,
        *,
        now: float,
        key: bytes | None,
        flow_ready: bool = False,
        conntrack_sources: Mapping[str, str | None] | None = None,
        has_points: bool = False,
    ) -> list[str]:
        """Publish indicators of new open candidates; returns new evidence refs."""
        self.last_availability = indicator_availability(
            has_candidates_source=has_points,
            flow_ready=flow_ready,
            conntrack_sources=conntrack_sources,
            key_ready=key is not None,
        )
        if key is None:
            self.counters["not_ready_no_key"] += 1
            return []
        new: list[str] = []
        for candidate in candidates:
            indicator = indicator_of(candidate)
            if indicator is None or candidate.candidate_id in self._indicated:
                continue
            if not self._budget(candidate.point_id, indicator, now):
                self._remember(candidate.candidate_id, "")
                continue
            ref = evidence_ref_of(key, candidate.candidate_id)
            self.evidence.add(ref, self._evidence(candidate, indicator, source, now))
            self._remember(candidate.candidate_id, ref)
            self._hour.append(now)
            self._point_kind[(candidate.point_id, indicator)] = now
            self._publish(candidate, indicator, ref)
            new.append(ref)
        for pk in [
            k for k, t in self._point_kind.items() if now - t >= INDICATOR_POINT_KIND_S
        ]:
            del self._point_kind[pk]
        return new

    def _remember(self, candidate_id: str, ref: str) -> None:
        self._indicated[candidate_id] = ref
        while len(self._indicated) > 4 * MAX_EVIDENCE:
            self._indicated.popitem(last=False)

    @staticmethod
    def _evidence(
        candidate: AnomalyCandidate, indicator: str, source: BucketSource, now: float
    ) -> dict[str, Any]:
        window = source.window(candidate.point_id, EVIDENCE_EXCERPT_S, end=now)
        buckets = () if window is None else window.buckets[-MAX_EVIDENCE_ROWS:]
        point = (
            window.point.to_dict()
            if window is not None
            else {
                "point_id": candidate.point_id,
                "router_id": candidate.router_id,
                "scope": None,
                "device": None,
                "vlan_id": None,
                "radio_id": None,
                "client_ref": candidate.client_ref,
            }
        )
        return {
            "indicator": indicator,
            "kind": candidate.kind,
            "candidate_id": candidate.candidate_id,
            "router_id": candidate.router_id,
            "client_ref": candidate.client_ref,
            "point": point,
            "observed": candidate.observed,
            "threshold": candidate.threshold,
            "window_s": candidate.window_s,
            "coverage": candidate.coverage.value,
            "confidence": candidate.confidence,
            "started": candidate.started,
            "created_at": now,
            "excerpt_start": None if window is None else window.end - window.window_s,
            "excerpt_end": None if window is None else window.end,
            "resolution_s": None if window is None else window.resolution_s,
            "rows": [_bucket_row(b) for b in buckets],
            "wording": INDICATOR_WORDING,
        }

    def _publish(self, candidate: AnomalyCandidate, indicator: str, ref: str) -> bool:
        if self.emit is None:
            self.counters["not_published"] += 1
            return False
        from .net_events import Severity

        try:
            self.emit(
                EVENT_INDICATOR,
                source=MODULE_NAME,
                router_id=candidate.router_id,
                severity=Severity.INFO,
                dedup_key=f"{candidate.point_id}:{indicator}",
                data={
                    "v": READ_API_VERSION,
                    "indicator": indicator,
                    "evidence_ref": ref,
                    "candidate_id": candidate.candidate_id,
                    "point": candidate.point_id,
                    "kind": candidate.kind,
                    "observed": candidate.observed,
                    "threshold": candidate.threshold,
                    "window_s": candidate.window_s,
                    "coverage": candidate.coverage.value,
                    "wording": INDICATOR_WORDING,
                    "security_center": self.security_status().state,
                },
                # Entscheidung: not security_relevant - a statistical
                # deviation must not crowd real security events out of the
                # core's security ring; the Security Center gets every core
                # event through ``subscribe`` anyway (W2).
                security_relevant=False,
                client_ref=candidate.client_ref,
                confidence=candidate.confidence,
                classification=INDICATOR_CLASSIFICATION,
            )
        except Exception as err:  # noqa: BLE001 - publishing never breaks traffic
            self.counters["publish_failed"] += 1
            _LOGGER.debug("Traffic indicator event failed (%s)", type(err).__name__)
            return False
        self.counters["published"] += 1
        return True

    def drop_client(self, client_ref: str) -> int:
        """Forget the evidence of a client (deletion route)."""
        return self.evidence.drop_client(client_ref)

    def drop_router(self, router_id: str | None) -> None:
        """Forget a router's evidence."""
        self.evidence.drop_router(router_id)

    def clear(self) -> None:
        """Forget everything (module off); counters stay."""
        self.evidence.clear()
        self._indicated.clear()
        self._hour.clear()
        self._point_kind.clear()

    def summary(self) -> dict[str, Any]:
        """Counts only, the indicator states and the Security Center link."""
        return {
            "evidence": len(self.evidence),
            "evidence_max": MAX_EVIDENCE,
            "published": self.counters["published"],
            "not_published": self.counters["not_published"],
            "not_published_reason": REASON_NOT_PUBLISHED if self.emit is None else None,
            "security_center": self.security_status().to_dict(),
            "indicators": {k: dict(v) for k, v in self.last_availability.items()},
            **dict(self.counters),
            **dict(self.evidence.counters),
        }


# --- read API for other modules ----------------------------------------------------------------


def window_dict(window: SeriesWindow | None, point: MeasurementPoint) -> dict[str, Any]:
    """Totals, mean/peak rates and coverage of one window (plain dict)."""
    from .traffic_accounting import direction_map

    base: dict[str, Any] = {"v": READ_API_VERSION, **point.to_dict()}
    if window is None:
        return {**base, "state": "unavailable", "reason": REASON_NO_DATA_YET}
    rx, tx = window.total("rx_bytes"), window.total("tx_bytes")
    covered = window.covered_s

    def avg(total: int | None) -> float | None:
        return None if total is None or covered <= 0 else round(total * 8 / covered, 3)

    def peak(name: str) -> float | None:
        values = [
            getattr(b, name) for b in window.buckets if getattr(b, name) is not None
        ]
        return max(values) if values else None

    mapping = direction_map(point)
    return {
        **base,
        "state": "available" if covered > 0 else "unavailable",
        "reason": window.reason,
        "window_s": window.window_s,
        "end": window.end,
        "resolution_s": window.resolution_s,
        "rx_bytes": rx,
        "tx_bytes": tx,
        "avg_rx_bps": avg(rx),
        "avg_tx_bps": avg(tx),
        "peak_rx_bps": peak("rx_peak_bps"),
        "peak_tx_bps": peak("tx_peak_bps"),
        "download": mapping.download,
        "upload": mapping.upload,
        "perspective": mapping.perspective.value,
        "time_coverage": round(window.time_coverage, 4),
        "coverage": window.coverage.value,
        "reasons": list(window.coverage_reasons),
    }


class TrafficReadApi:
    """Stable read API (version 1) for diagnostics, security and others.

    Every answer is a plain dict with ``"v": 1`` and pseudonyms only. While
    traffic analytics is off or not ready the state says so and values are
    None, never 0. Get it with :func:`async_get_traffic_read_api`.
    """

    version = READ_API_VERSION

    def __init__(self, engine: Any) -> None:
        """API over a running ``TrafficEngine``."""
        self._engine = engine

    def status(self) -> dict[str, Any]:
        """``{"v", "state": off|not_ready|ready, "reason"}``."""
        engine = self._engine
        if not engine.active:
            return {"v": READ_API_VERSION, "state": "off", "reason": REASON_DISABLED}
        reason = engine.not_ready_reason
        return {
            "v": READ_API_VERSION,
            "state": "ready" if reason is None else "not_ready",
            "reason": reason,
        }

    def _off(self) -> bool:
        return not self._engine.active

    def points(self, router_id: str | None = None) -> list[dict[str, Any]]:
        """Measuring points (ids and scope only)."""
        if self._off():
            return []
        return [
            p.to_dict()
            for p in self._engine.history_source.points()
            if router_id is None or p.router_id == router_id
        ]

    def latest(self, router_id: str) -> list[dict[str, Any]]:
        """Latest rate per point of ``router_id``."""
        from .traffic_accounting import direction_map

        if self._off() or not valid_router_id(router_id):
            return []
        out = []
        for rate in self._engine.rates_of(router_id):
            mapping = direction_map(rate.point)
            values = {"rx": rate.rx_bps, "tx": rate.tx_bps}
            out.append(
                {
                    "v": READ_API_VERSION,
                    **rate.point.to_dict(),
                    "quality": rate.quality.value,
                    "rx_bps": rate.rx_bps,
                    "tx_bps": rate.tx_bps,
                    "down_bps": None
                    if mapping.download is None
                    else values[mapping.download],
                    "up_bps": None
                    if mapping.upload is None
                    else values[mapping.upload],
                    "interval_s": rate.interval_s,
                    "wall_s": rate.wall_s,
                    "coverage": rate.coverage.value,
                    "coverage_reason": None
                    if rate.coverage_reason is None
                    else rate.coverage_reason.value,
                }
            )
        return out

    def window(self, point_id: str, window: str = "1h") -> dict[str, Any]:
        """Totals and coverage of one point over a named window."""
        state = self.status()
        base = {"v": READ_API_VERSION, "point_id": point_id}
        if state["state"] == "off":
            return {**base, "state": "unavailable", "reason": REASON_DISABLED}
        seconds = READ_WINDOWS.get(window)
        if seconds is None:
            return {**base, "state": "unavailable", "reason": REASON_UNKNOWN_WINDOW}
        if not valid_point_id(point_id):
            return {**base, "state": "unavailable", "reason": REASON_UNKNOWN_POINT}
        source = self._engine.history_source
        point = next((p for p in source.points() if p.point_id == point_id), None)
        if point is None:
            return {**base, "state": "unavailable", "reason": REASON_UNKNOWN_POINT}
        return window_dict(
            source.window(point_id, seconds, end=self._engine.wall()), point
        )

    def router_window(self, router_id: str, window: str = "1h") -> dict[str, Any]:
        """The WAN points of a router over a window (plus the point count)."""
        base = {"v": READ_API_VERSION, "router_id": router_id}
        if self._off():
            return {**base, "state": "unavailable", "reason": REASON_DISABLED}
        if not valid_router_id(router_id):
            return {**base, "state": "unavailable", "reason": REASON_UNKNOWN_POINT}
        points = [
            p for p in self._engine.history_source.points() if p.router_id == router_id
        ]
        return {
            **base,
            "state": "available" if points else "unavailable",
            "reason": None if points else REASON_NO_DATA_YET,
            "points": len(points),
            "wan": [
                self.window(p.point_id, window) for p in points if p.scope is Scope.WAN
            ],
        }

    def congestion(self, router_id: str | None = None) -> dict[str, Any]:
        """The congestion report (see :class:`TrafficCorrelator`)."""
        if self._off():
            return {
                "v": READ_API_VERSION,
                "state": "unavailable",
                "reason": REASON_DISABLED,
                "findings": [],
            }
        return self._engine.congestion(router_id).to_dict()

    def evidence(self, evidence_ref: str) -> dict[str, Any] | None:
        """The evidence behind an ``evr_`` reference (None: unknown)."""
        if self._off():
            return None
        return self._engine.indicators.evidence.resolve(evidence_ref)


def async_get_traffic_read_api(hass: Any) -> TrafficReadApi | None:
    """The read API of the running traffic engine (None: not loaded)."""
    try:
        from .traffic_engine import async_get_traffic_engine

        engine = async_get_traffic_engine(hass)
    except Exception as err:  # noqa: BLE001 - optional for callers
        _LOGGER.debug("Traffic read API lookup failed (%s)", type(err).__name__)
        return None
    return None if engine is None else engine.read_api
