"""Channel utilization from survey counters or hostapd BSS load (pure, no HA).

Two sources, never mixed:

(A) ``iwinfo survey``: running millisecond counters per frequency
    (``active_time``, ``busy_time``, ``rx_time``, ``tx_time``). A share needs
    two samples; :func:`utilization_from_delta` returns either a value or a
    named :class:`UnknownReason`, never 0 % as a stand-in.
(B) ``hostapd get_status`` → ``airtime`` (busy only). V1 source. The
    share comes from the delta of the running ``time``/``time_busy``
    counters between two polls (:func:`bss_load_from_get_status`,
    :meth:`BssLoad.as_sample`, :func:`utilization_from_delta`). The
    ``utilization`` byte (0–255, :func:`utilization_from_bss_load`) covers
    only the last ``bss_load_update_period`` and jumped between 0 and 255
    within seconds in the live check of 2026-11-18.

A sample pair from two different sources is unknown (``source_mismatch``).
:func:`summarize` evaluates a window of percentages (from either source,
one source per call) without turning unknown points into numbers.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .rf_models import (
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_SURVEY,
    CapabilityState,
    Metric,
    metric_measured,
    metric_missing,
)

_LOGGER = logging.getLogger(__name__)

# Longest gap between two survey samples that still gives a meaningful share.
# Startwert, nicht kalibriert: 10 polls at the 60 s default interval.
DEFAULT_MAX_GAP_S = 600.0
# Minimum on-channel time between two samples (ms). Below this a share is
# dominated by counter granularity. Startwert, nicht kalibriert.
DEFAULT_MIN_ACTIVE_MS = 1000
# Allowed difference between router uptime delta and wall-clock delta before
# the pair counts as "router restarted in between". Uptime is whole seconds
# and the poll itself takes a few seconds. Startwert, nicht kalibriert.
DEFAULT_UPTIME_TOLERANCE_S = 15.0

# hostapd scales the BSS load to 0..255 (bss_load.c).
BSS_LOAD_MAX = 255

PART_BUSY = "busy"
PART_RX = "rx"
PART_TX = "tx"
PART_OTHER_BUSY = "other_busy"

NOTE_UPTIME_UNAVAILABLE = "uptime_unavailable"


class UnknownReason(StrEnum):
    """Why a utilization share could not be computed."""

    NO_PREVIOUS = "no_previous"
    RADIO_MISMATCH = "radio_mismatch"
    SOURCE_MISMATCH = "source_mismatch"  # survey and get_status never mixed
    TIME_NOT_ADVANCING = "time_not_advancing"
    GAP_TOO_LARGE = "gap_too_large"
    ROUTER_RESTART = "router_restart"  # uptime went back
    UPTIME_MISMATCH = "uptime_mismatch"  # uptime delta ≠ elapsed time
    CHANNEL_CHANGED = "channel_changed"
    COUNTER_RESET = "counter_reset"  # radio restart or wrap; not recomputed
    MISSING_FIELD = "missing_field"
    ACTIVE_TOO_SMALL = "active_too_small"
    IMPLAUSIBLE = "implausible"


@dataclass(frozen=True)
class SurveySample:
    """One ``iwinfo survey`` entry for the radio's operating frequency.

    Counter fields are milliseconds as reported (running totals); each may be
    None when the driver does not fill it. ``noise`` is dBm as already
    converted by the caller (rpcd reports it unsigned, e.g. 161 for -95,
    see :func:`survey_noise_dbm`). ``source`` is ``hostapd.get_status`` for
    samples built from its ``airtime`` counters (:meth:`BssLoad.as_sample`).
    """

    radio_id: str
    mhz: int
    taken_at: float
    uptime_s: float | None
    active_ms: int | None
    busy_ms: int | None
    rx_ms: int | None
    tx_ms: int | None
    noise: int | None = None
    source: str = SOURCE_IWINFO_SURVEY


@dataclass(frozen=True)
class UtilizationResult:
    """Shares of the on-channel time between two survey samples.

    ``reason`` is set when the whole pair is unusable; then every share is
    None. ``part_reasons`` names why an individual share is None.
    """

    radio_id: str
    busy_pct: float | None = None
    rx_pct: float | None = None
    tx_pct: float | None = None
    other_busy_pct: float | None = None
    reason: UnknownReason | None = None
    part_reasons: Mapping[str, UnknownReason] = field(default_factory=dict)
    interval_s: float | None = None
    measured_at: float | None = None
    notes: tuple[str, ...] = ()
    source: str = SOURCE_IWINFO_SURVEY

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "part_reasons", MappingProxyType(dict(self.part_reasons))
        )

    @property
    def known(self) -> bool:
        """True when the busy share (the headline figure) is known."""
        return self.busy_pct is not None

    def busy_metric(self) -> Metric:
        """Return the busy share as a Metric (no_data when unknown)."""
        if self.busy_pct is None:
            return metric_missing(CapabilityState.NO_DATA, self.source)
        return metric_measured(self.busy_pct, self.source, measured_at=self.measured_at)

    def as_dict(self) -> dict[str, Any]:
        """Return the result as a plain dict."""
        return {
            "radio_id": self.radio_id,
            "source": self.source,
            "busy_pct": self.busy_pct,
            "rx_pct": self.rx_pct,
            "tx_pct": self.tx_pct,
            "other_busy_pct": self.other_busy_pct,
            "reason": self.reason.value if self.reason else None,
            "part_reasons": {k: v.value for k, v in self.part_reasons.items()},
            "interval_s": self.interval_s,
            "measured_at": self.measured_at,
            "notes": list(self.notes),
        }


def _delta(prev: int | None, cur: int | None) -> int | None:
    if prev is None or cur is None:
        return None
    return cur - prev


def _pair_reason(
    prev: SurveySample, cur: SurveySample, max_gap_s: float, tolerance_s: float
) -> UnknownReason | None:
    """Reasons that invalidate the whole pair, most specific first."""
    if prev.radio_id != cur.radio_id:
        return UnknownReason.RADIO_MISMATCH
    if prev.source != cur.source:
        return UnknownReason.SOURCE_MISMATCH
    elapsed = cur.taken_at - prev.taken_at
    if elapsed <= 0:
        return UnknownReason.TIME_NOT_ADVANCING
    if elapsed > max_gap_s:
        return UnknownReason.GAP_TOO_LARGE
    if prev.uptime_s is not None and cur.uptime_s is not None:
        uptime_delta = cur.uptime_s - prev.uptime_s
        if uptime_delta < 0:
            return UnknownReason.ROUTER_RESTART
        if abs(uptime_delta - elapsed) > tolerance_s:
            return UnknownReason.UPTIME_MISMATCH
    if prev.mhz != cur.mhz:
        return UnknownReason.CHANNEL_CHANGED
    counters = ("active_ms", "busy_ms", "rx_ms", "tx_ms")
    for name in counters:
        d = _delta(getattr(prev, name), getattr(cur, name))
        # A smaller counter is a reset or a wrap. A 32-bit wrap cannot be told
        # apart from a radio restart with the data at hand, so no recompute.
        if d is not None and d < 0:
            return UnknownReason.COUNTER_RESET
    return None


def utilization_from_delta(
    prev: SurveySample | None,
    cur: SurveySample,
    *,
    max_gap_s: float = DEFAULT_MAX_GAP_S,
    min_active_ms: int = DEFAULT_MIN_ACTIVE_MS,
    uptime_tolerance_s: float = DEFAULT_UPTIME_TOLERANCE_S,
) -> UtilizationResult:
    """Return busy/rx/tx shares of the active time between two samples."""
    unknown = UtilizationResult(
        radio_id=cur.radio_id, measured_at=cur.taken_at, source=cur.source
    )
    if prev is None:
        return _with_reason(unknown, UnknownReason.NO_PREVIOUS)
    reason = _pair_reason(prev, cur, max_gap_s, uptime_tolerance_s)
    if reason is not None:
        return _with_reason(unknown, reason)
    active = _delta(prev.active_ms, cur.active_ms)
    if active is None:
        return _with_reason(unknown, UnknownReason.MISSING_FIELD)
    if active == 0 or active < min_active_ms:
        return _with_reason(unknown, UnknownReason.ACTIVE_TOO_SMALL)
    deltas = {
        PART_BUSY: _delta(prev.busy_ms, cur.busy_ms),
        PART_RX: _delta(prev.rx_ms, cur.rx_ms),
        PART_TX: _delta(prev.tx_ms, cur.tx_ms),
    }
    if any(d is not None and d > active for d in deltas.values()):
        # More busy/rx/tx time than on-channel time: the counters disagree,
        # so even the denominator is suspect. Unknown, not capped at 100 %.
        return _with_reason(unknown, UnknownReason.IMPLAUSIBLE)
    return _shares(cur, prev, active, deltas)


def _with_reason(result: UtilizationResult, reason: UnknownReason) -> UtilizationResult:
    return UtilizationResult(
        radio_id=result.radio_id,
        measured_at=result.measured_at,
        reason=reason,
        source=result.source,
    )


def _shares(
    cur: SurveySample,
    prev: SurveySample,
    active: int,
    deltas: Mapping[str, int | None],
) -> UtilizationResult:
    part_reasons: dict[str, UnknownReason] = {}
    pct: dict[str, float | None] = {}
    for part, d in deltas.items():
        pct[part] = None if d is None else 100.0 * d / active
        if d is None:
            part_reasons[part] = UnknownReason.MISSING_FIELD
    other: float | None = None
    busy, rx, tx = deltas[PART_BUSY], deltas[PART_RX], deltas[PART_TX]
    if busy is None or rx is None or tx is None:
        part_reasons[PART_OTHER_BUSY] = UnknownReason.MISSING_FIELD
    elif busy - rx - tx < 0:
        part_reasons[PART_OTHER_BUSY] = UnknownReason.IMPLAUSIBLE
    else:
        other = 100.0 * (busy - rx - tx) / active
    notes: tuple[str, ...] = ()
    if prev.uptime_s is None or cur.uptime_s is None:
        notes = (NOTE_UPTIME_UNAVAILABLE,)
    return UtilizationResult(
        radio_id=cur.radio_id,
        busy_pct=pct[PART_BUSY],
        rx_pct=pct[PART_RX],
        tx_pct=pct[PART_TX],
        other_busy_pct=other,
        part_reasons=part_reasons,
        interval_s=cur.taken_at - prev.taken_at,
        measured_at=cur.taken_at,
        notes=notes,
        source=cur.source,
    )


def _as_whole_number(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and (math.isnan(value) or not value.is_integer()):
        return None
    return int(value)


def utilization_from_bss_load(
    raw: Any,
    *,
    channel_time: Any = None,
    measured_at: float | None = None,
) -> Metric:
    """Return hostapd's BSS load (``airtime.utilization``) in percent.

    Values outside 0..255 or of the wrong type are no_data. When the caller
    passes ``airtime.time`` as ``channel_time`` and it is 0, hostapd has
    never computed a load (``bss_load_update_period`` 0 or not yet run) and
    its 0 is not a measurement.
    """
    load = _as_whole_number(raw)
    if load is None or not 0 <= load <= BSS_LOAD_MAX:
        return metric_missing(CapabilityState.NO_DATA, SOURCE_HOSTAPD_STATUS)
    if channel_time is not None:
        time = _as_whole_number(channel_time)
        if time is None or time <= 0:
            return metric_missing(CapabilityState.NO_DATA, SOURCE_HOSTAPD_STATUS)
    return metric_measured(
        100.0 * load / BSS_LOAD_MAX, SOURCE_HOSTAPD_STATUS, measured_at=measured_at
    )


# =====================================================================
# Raw ubus parsing
# =====================================================================

# Signed 8-bit range of the noise value (dBm).
_NOISE_SIGNED_MIN = -128
_NOISE_UNSIGNED_MIN = 128
_NOISE_UNSIGNED_MAX = 255


def survey_noise_dbm(raw: Any) -> int | None:
    """Return survey noise in dBm; None when unknown.

    rpcd reports the survey noise as an unsigned byte (164 means -92 dBm,
    seen live 2026-11-18); 0 means "not reported". 1..127 would be a
    positive noise floor and is unknown. Values that are already negative
    are taken as they are.
    """
    value = _as_whole_number(raw)
    if value is None:
        return None
    if _NOISE_UNSIGNED_MIN <= value <= _NOISE_UNSIGNED_MAX:
        return value - 256
    if _NOISE_SIGNED_MIN <= value < 0:
        return value
    return None


def _survey_entries(raw: Any) -> list[Any]:
    if isinstance(raw, dict):
        raw = raw.get("results")
    return raw if isinstance(raw, list) else []


def survey_samples_from_iwinfo(
    raw: Any,
    radio_id: str,
    taken_at: float,
    uptime_s: float | None,
    *,
    mhz: int | None = None,
) -> tuple[SurveySample, ...]:
    """Parse ``iwinfo survey`` into samples, one per frequency with data.

    Entries whose ``active_time`` is missing or 0 were never visited and are
    no measurement. There is no "in use" field: the caller passes the
    radio's operating ``mhz``, because off-channel entries can hold small
    leftover counts (up to about 160 ms, seen on mt76, ath10k-ct and ath9k)
    that are no live measurement.
    """
    samples = []
    for entry in _survey_entries(raw):
        if not isinstance(entry, dict):
            continue
        freq = _as_whole_number(entry.get("mhz"))
        active = _as_whole_number(entry.get("active_time"))
        if freq is None or freq <= 0 or active is None or active <= 0:
            continue
        if mhz is not None and freq != mhz:
            continue
        samples.append(
            SurveySample(
                radio_id=radio_id,
                mhz=freq,
                taken_at=taken_at,
                uptime_s=uptime_s,
                active_ms=active,
                busy_ms=_as_whole_number(entry.get("busy_time")),
                rx_ms=_as_whole_number(entry.get("rx_time")),
                tx_ms=_as_whole_number(entry.get("tx_time")),
                noise=survey_noise_dbm(entry.get("noise")),
            )
        )
    return tuple(samples)


@dataclass(frozen=True)
class BssLoad:
    """``airtime`` and channel of one ``hostapd get_status`` answer.

    ``time_ms``/``busy_ms`` are hostapd's running channel time counters
    (milliseconds, per radio, refreshed every ``bss_load_update_period``
    beacons). ``load_byte`` is ``airtime.utilization`` (0..255); live it
    jumped between 0 and 255 within seconds, so the share is taken from the
    counter delta (:meth:`as_sample` plus :func:`utilization_from_delta`).
    """

    freq: int | None
    channel: int | None
    time_ms: int
    busy_ms: int
    load_byte: int | None
    cac_active: bool | None

    def as_sample(
        self, radio_id: str, taken_at: float, uptime_s: float | None
    ) -> SurveySample:
        """Return the counters as a sample (busy only, no rx/tx split)."""
        return SurveySample(
            radio_id=radio_id,
            mhz=self.freq or 0,
            taken_at=taken_at,
            uptime_s=uptime_s,
            active_ms=self.time_ms,
            busy_ms=self.busy_ms,
            rx_ms=None,
            tx_ms=None,
            source=SOURCE_HOSTAPD_STATUS,
        )


def bss_load_from_get_status(raw: Any) -> BssLoad | None:
    """Parse ``hostapd.<if> get_status``; None without usable counters."""
    if not isinstance(raw, dict):
        return None
    airtime = raw.get("airtime")
    if not isinstance(airtime, dict):
        return None
    time = _as_whole_number(airtime.get("time"))
    busy = _as_whole_number(airtime.get("time_busy"))
    if time is None or busy is None or time < 0 or busy < 0:
        return None
    load = _as_whole_number(airtime.get("utilization"))
    if load is not None and not 0 <= load <= BSS_LOAD_MAX:
        load = None
    dfs = raw.get("dfs")
    cac = dfs.get("cac_active") if isinstance(dfs, dict) else None
    return BssLoad(
        freq=_as_whole_number(raw.get("freq")),
        channel=_as_whole_number(raw.get("channel")),
        time_ms=time,
        busy_ms=busy,
        load_byte=load,
        cac_active=cac if isinstance(cac, bool) else None,
    )


# =====================================================================
# Window summary
# =====================================================================


@dataclass(frozen=True)
class UtilizationThresholds:
    """Thresholds for :func:`summarize`."""

    # Same raise level as the NI rule wifi_channel_busy (net_rules.py, 70 %).
    warn_pct: float = 70.0
    # Share of valid points at/over warn_pct for "sustained". Startwert,
    # nicht kalibriert.
    sustained_share: float = 0.8
    # Minimum share of valid points in the window before any verdict.
    # Startwert, nicht kalibriert.
    min_coverage: float = 0.75
    # Minimum valid points before any verdict; matches the 3 samples of the
    # NI rule wifi_channel_busy.
    min_valid_points: int = 3


@dataclass(frozen=True)
class OverloadPhase:
    """Consecutive valid points at or above the warning threshold."""

    start: float
    end: float
    peak: float
    points: int

    def as_dict(self) -> dict[str, Any]:
        """Return the phase as a plain dict."""
        return {
            "start": self.start,
            "end": self.end,
            "peak": self.peak,
            "points": self.points,
        }


@dataclass(frozen=True)
class UtilizationSummary:
    """Figures of one window; None where there is nothing to say."""

    current: float | None
    mean: float | None
    peak: float | None
    valid_count: int
    invalid_count: int
    coverage: float | None
    phases: tuple[OverloadPhase, ...]
    sustained_overload: bool | None

    def as_dict(self) -> dict[str, Any]:
        """Return the summary as a plain dict."""
        return {
            "current": self.current,
            "mean": self.mean,
            "peak": self.peak,
            "valid_count": self.valid_count,
            "invalid_count": self.invalid_count,
            "coverage": self.coverage,
            "phases": [p.as_dict() for p in self.phases],
            "sustained_overload": self.sustained_overload,
        }


def _valid_pct(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if math.isnan(value) or not 0.0 <= value <= 100.0:
        return None
    return float(value)


def _phases(
    points: Sequence[tuple[float, float | None]], warn_pct: float
) -> tuple[OverloadPhase, ...]:
    phases: list[OverloadPhase] = []
    run: list[tuple[float, float]] = []
    for ts, pct in [*points, (math.inf, None)]:  # sentinel closes the last run
        if pct is not None and pct >= warn_pct:
            run.append((ts, pct))
            continue
        if run:
            peak = max(p for _, p in run)
            phases.append(OverloadPhase(run[0][0], run[-1][0], peak, len(run)))
            run = []
    return tuple(phases)


def summarize(
    samples: Sequence[tuple[float, float | None]],
    *,
    now: float,
    window_s: float,
    thresholds: UtilizationThresholds,
    expected_interval_s: float,
) -> UtilizationSummary:
    """Summarize utilization points (timestamp, percent or None) of a window.

    Unknown points (None, NaN, outside 0..100) count as invalid: they lower
    the coverage, break overload phases and never enter mean or peak.
    Missing points lower the coverage too: the denominator is the larger of
    the points in the window and ``window_s / expected_interval_s`` (the
    poll interval that fed the samples).
    """
    if not math.isfinite(expected_interval_s) or expected_interval_s <= 0:
        raise ValueError(f"expected_interval_s must be > 0: {expected_interval_s}")
    in_window = sorted(
        ((ts, _valid_pct(pct)) for ts, pct in samples if now - window_s <= ts <= now),
        key=lambda p: p[0],
    )
    valid = [pct for _, pct in in_window if pct is not None]
    total = len(in_window)
    expected = max(float(total), window_s / expected_interval_s)
    coverage = min(1.0, len(valid) / expected) if expected > 0 else None
    sustained: bool | None = None
    if (
        coverage is not None
        and coverage >= thresholds.min_coverage
        and len(valid) >= thresholds.min_valid_points
    ):
        over = sum(1 for pct in valid if pct >= thresholds.warn_pct)
        sustained = over / len(valid) >= thresholds.sustained_share
    return UtilizationSummary(
        current=in_window[-1][1] if in_window else None,
        mean=sum(valid) / len(valid) if valid else None,
        peak=max(valid) if valid else None,
        valid_count=len(valid),
        invalid_count=total - len(valid),
        coverage=coverage,
        phases=_phases(in_window, thresholds.warn_pct),
        sustained_overload=sustained,
    )
