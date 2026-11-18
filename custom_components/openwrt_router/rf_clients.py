"""Signal and retry assessment per WiFi client (pure, no HA, not wired up yet).

Client Stability (``client_history``/``client_analysis``) already scores the
signal, roaming and AP comparison. This module does not repeat that: its
input :class:`ClientRfWindow` takes the figures Client Stability already
has (``rssi_mean``, ``weak_share``, ``rate_tx_trend``, disconnects) as given
and adds what only RF data can say (retries/failures from
``iwinfo assoclist``, SNR from the radio's noise).

Rules:

- Missing values stay unknown (Metric state, ``missing``), never 0 or "good".
- RSSI alone never makes a ``warning``: a second piece of evidence is needed
  (share over time plus retries/rate/disconnects), or the context
  mobile + high demand together with a persistent weak share.
- Retry and failure counters of different drivers are not comparable (mt76
  counts retries inside ``tx_failed``, ath10k does not; mt76 reports retries
  only without WED). Rates are only compared within one driver family
  (:func:`retry_comparable`); an unknown driver compares with nothing.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .client_analysis import score_signal
from .client_history import WEAK_SIGNAL_DBM
from .rf_conflicts import RadioRef, Severity
from .rf_models import (
    SOURCE_IWINFO_ASSOCLIST,
    SOURCE_IWINFO_INFO,
    CapabilityState,
    Metric,
    metric_measured,
    metric_missing,
)

_LOGGER = logging.getLogger(__name__)

# Evidence source for figures computed by Client Stability (client_history
# buckets: rssi_n/sum/min, weak_s, rate_tx_sum, dc_*).
SOURCE_CLIENT_HISTORY = "client_history"

MOBILITY_STATIONARY = "stationary"
MOBILITY_MOBILE = "mobile"
DEMAND_LOW = "low"
DEMAND_HIGH = "high"

FAMILY_MT76 = "mt76"
FAMILY_ATH10K = "ath10k"

_MISSING_STATES = frozenset(
    {CapabilityState.NO_DATA, CapabilityState.UNSUPPORTED, CapabilityState.UNREACHABLE}
)


class FindingKind(StrEnum):
    """Kinds of client findings (declaration order is the output order)."""

    WEAK_SIGNAL_PERSISTENT = "weak_signal_persistent"
    RSSI_UNSTABLE = "rssi_unstable"
    RATE_DECLINING = "rate_declining"
    RETRY_RATE_HIGH = "retry_rate_high"
    DISCONNECTS_AT_WEAK_SIGNAL = "disconnects_at_weak_signal"
    POOR_LINK_DESPITE_SIGNAL = "poor_link_despite_signal"


@dataclass(frozen=True)
class ClientThresholds:
    """Thresholds for :func:`assess_client`. All overridable."""

    # Weak-signal level by context. The neutral value is Client Stability's
    # WEAK_SIGNAL_DBM (-75), the level ``weak_share`` is measured against.
    # The other two are Startwerte, nicht kalibriert.
    weak_rssi_sensitive_dbm: float = -70.0  # mobile or high demand
    weak_rssi_neutral_dbm: float = float(WEAK_SIGNAL_DBM)  # context unknown
    weak_rssi_tolerant_dbm: float = -80.0  # stationary and low demand (IoT)
    # Share of the window below the weak level for "persistent".
    # Startwert, nicht kalibriert.
    persistent_weak_share: float = 0.5
    # RSSI standard deviation (dB) for "unstable". Startwert, nicht kalibriert.
    unstable_stddev_db: float = 8.0
    # Change of the mean TX rate against the previous window, in percent.
    # Startwert, nicht kalibriert.
    rate_decline_pct: float = -30.0
    # Retries per sent packet (MPDU). Startwert, nicht kalibriert.
    retry_high: float = 0.25
    # Final failures per sent packet. Startwert, nicht kalibriert.
    failure_high: float = 0.05
    # Fewer packets in the window give no rate at all. Startwert.
    min_packets: int = 200
    # Disconnects at weak signal before a finding. Startwert.
    min_weak_disconnects: int = 2
    # At or above this RSSI the signal counts as good. Startwert.
    good_rssi_dbm: float = -65.0
    # Mean TX rate (kbit/s, as client_engine reports it) that is low for a
    # good signal. Startwert, nicht kalibriert.
    low_rate_kbps: float = 12_000.0
    # Samples for full confidence; fewer scale confidence down linearly.
    full_confidence_samples: int = 30
    # Confidence factor when mobility or demand is unknown.
    context_unknown_factor: float = 0.7
    # Confidence factor for retry findings when the driver is unknown.
    driver_unknown_factor: float = 0.7
    # Driver families whose ``tx_failed`` excludes retries (source read in
    # the plan, section 2). mt76 counts retries in it; others not read.
    failed_independent_families: frozenset[str] = frozenset({FAMILY_ATH10K})


DEFAULT_THRESHOLDS = ClientThresholds()


@dataclass(frozen=True)
class ClientRfWindow:
    """RF view of one client on one radio over one window.

    Filled later from Client Stability (``rssi_*``, ``weak_share``,
    ``rate_tx_*``, ``disconnects*``: client_history buckets) and from
    ``iwinfo assoclist`` deltas (``tx_*``, see :func:`counter_delta`).
    ``weak_share`` is the share of observed time below Client Stability's
    WEAK_SIGNAL_DBM. ``rate_tx_trend`` is the change of the mean TX rate
    against the previous window in percent; None without a previous window.
    ``driver`` is the kernel driver name (e.g. ``mt7915e``, ``ath10k-ct``).
    """

    client_key: str
    radio: RadioRef
    band: str | None
    driver: str | None
    window_s: float
    rssi_mean: float | None
    rssi_min: float | None
    rssi_stddev: float | None
    weak_share: float | None
    noise: Metric | None
    rate_tx_mean: float | None
    rate_tx_trend: float | None
    tx_packets: int | None
    tx_retries: int | None
    tx_failed: int | None
    disconnects: int | None
    disconnects_weak: int | None
    mobility: str | None
    demand: str | None
    samples: int


@dataclass(frozen=True)
class ClientFinding:
    """One finding with evidence and a confidence of 0..1."""

    kind: FindingKind
    severity: Severity
    evidence: tuple[str, ...]
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        """Return the finding as a plain dict."""
        return {
            "kind": self.kind.value,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ClientAssessment:
    """Result of :func:`assess_client`.

    ``signal_quality`` is Client Stability's ``score_signal`` (0..100) and
    None unless both ``rssi_mean`` and ``weak_share`` are known. ``missing``
    names the inputs that were unknown.
    """

    client_key: str
    radio: RadioRef
    driver_family: str | None
    findings: tuple[ClientFinding, ...]
    signal_quality: float | None
    retry_rate: Metric
    failure_rate: Metric
    snr: Metric
    tx_packets: int | None
    tx_retries: int | None
    missing: tuple[str, ...]
    samples: int

    @property
    def is_problem(self) -> bool:
        """True when at least one finding is a warning."""
        return any(f.severity is Severity.WARNING for f in self.findings)

    def has(self, kind: FindingKind) -> bool:
        """True when a finding of this kind is present."""
        return any(f.kind is kind for f in self.findings)

    def as_dict(self) -> dict[str, Any]:
        """Return the assessment as a plain dict."""
        return {
            "client_key": self.client_key,
            "radio": self.radio.as_dict(),
            "driver_family": self.driver_family,
            "findings": [f.as_dict() for f in self.findings],
            "signal_quality": self.signal_quality,
            "retry_rate": self.retry_rate.as_dict(),
            "failure_rate": self.failure_rate.as_dict(),
            "snr": self.snr.as_dict(),
            "missing": list(self.missing),
            "samples": self.samples,
        }


# =====================================================================
# Counters, rates, SNR
# =====================================================================


def counter_delta(prev: int | None, cur: int | None) -> int | None:
    """Return ``cur - prev``; None when unknown or the counter went back.

    A smaller counter means a reconnect (new station entry) or a driver
    reset; the delta is unknown then, not recomputed.
    """
    if prev is None or cur is None or cur < prev:
        return None
    return cur - prev


def _per_packet(
    count: int | None, packets: int | None, min_packets: int, measured_at: float | None
) -> Metric:
    if count is None or packets is None or count < 0:
        return metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST)
    if packets <= 0 or packets < min_packets:
        return metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST)
    return metric_measured(
        count / packets, SOURCE_IWINFO_ASSOCLIST, measured_at=measured_at
    )


def retry_rate(
    tx_retries: int | None,
    tx_packets: int | None,
    *,
    min_packets: int,
    measured_at: float | None = None,
) -> Metric:
    """Retries per sent packet; no_data with missing counters or few packets."""
    return _per_packet(tx_retries, tx_packets, min_packets, measured_at)


def failure_rate(
    tx_failed: int | None,
    tx_packets: int | None,
    *,
    min_packets: int,
    measured_at: float | None = None,
) -> Metric:
    """Failed packets per sent packet (mt76: includes retries, see module)."""
    return _per_packet(tx_failed, tx_packets, min_packets, measured_at)


def _number(metric: Metric | None) -> float | None:
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def snr(rssi: float | None, noise_metric: Metric | None) -> Metric:
    """Return RSSI minus noise; unknown unless noise is freshly measured.

    iwinfo reports noise 0 when the driver gave none; 0 and positive values
    are therefore unknown, not a noise floor.
    """
    source = noise_metric.source if noise_metric is not None else SOURCE_IWINFO_INFO
    if noise_metric is not None and noise_metric.state in _MISSING_STATES:
        return metric_missing(noise_metric.state, source)
    noise = _number(noise_metric)
    if rssi is None or noise is None or noise >= 0:
        return metric_missing(CapabilityState.NO_DATA, source)
    measured_at = noise_metric.measured_at if noise_metric else None
    return metric_measured(rssi - noise, source, measured_at=measured_at)


_MT76_RE = re.compile(r"^mt7\d")


def driver_family(driver: str | None) -> str | None:
    """Map a driver name to its counter family; None when unknown."""
    if not driver:
        return None
    name = driver.strip().lower()
    if name.startswith("mt76") or _MT76_RE.match(name):
        return FAMILY_MT76
    for family in (FAMILY_ATH10K, "ath11k", "ath12k", "ath9k"):
        if name.startswith(family):
            return family
    return name


def retry_comparable(driver_a: str | None, driver_b: str | None) -> bool:
    """True only when both drivers are known and of the same family."""
    family_a, family_b = driver_family(driver_a), driver_family(driver_b)
    return family_a is not None and family_a == family_b


# =====================================================================
# Assessment
# =====================================================================


@dataclass(frozen=True)
class _Ctx:
    """Derived facts shared by the finding rules."""

    w: ClientRfWindow
    th: ClientThresholds
    family: str | None
    weak_level: float
    context: str
    context_known: bool
    retry: float | None
    failure: float | None  # only when independent of retries
    sample_factor: float
    completeness: float
    base_evidence: tuple[str, ...] = field(default=())


def _weak_level(w: ClientRfWindow, th: ClientThresholds) -> float:
    if w.mobility == MOBILITY_STATIONARY and w.demand == DEMAND_LOW:
        return th.weak_rssi_tolerant_dbm
    if w.mobility == MOBILITY_MOBILE or w.demand == DEMAND_HIGH:
        return th.weak_rssi_sensitive_dbm
    return th.weak_rssi_neutral_dbm


def _missing(w: ClientRfWindow) -> tuple[str, ...]:
    names = (
        "rssi_mean",
        "weak_share",
        "rssi_stddev",
        "rate_tx_mean",
        "rate_tx_trend",
        "tx_packets",
        "tx_retries",
        "tx_failed",
        "disconnects",
        "disconnects_weak",
        "mobility",
        "demand",
        "driver",
    )
    out = [n for n in names if getattr(w, n) is None]
    if w.samples <= 0:
        out.append("samples")
    return tuple(out)


def _context(w: ClientRfWindow, th: ClientThresholds) -> _Ctx:
    family = driver_family(w.driver)
    retry = _number(retry_rate(w.tx_retries, w.tx_packets, min_packets=th.min_packets))
    failure = None
    if family in th.failed_independent_families:
        failure = _number(
            failure_rate(w.tx_failed, w.tx_packets, min_packets=th.min_packets)
        )
    core = (w.rssi_mean, w.weak_share, retry, w.rate_tx_mean, w.disconnects)
    known = (w.mobility is not None) and (w.demand is not None)
    return _Ctx(
        w=w,
        th=th,
        family=family,
        weak_level=_weak_level(w, th),
        context=f"context:{w.mobility}+{w.demand}" if known else "context_unknown",
        context_known=known,
        retry=retry,
        failure=failure,
        sample_factor=min(1.0, max(0, w.samples) / th.full_confidence_samples),
        completeness=sum(1 for v in core if v is not None) / len(core),
        base_evidence=(f"samples:{w.samples}",),
    )


def _confidence(ctx: _Ctx, *, signal: bool = False, counters: bool = False) -> float:
    value = ctx.sample_factor * (0.5 + 0.5 * ctx.completeness)
    if signal and not ctx.context_known:
        value *= ctx.th.context_unknown_factor
    if counters and ctx.family is None:
        value *= ctx.th.driver_unknown_factor
    return round(max(0.0, min(1.0, value)), 3)


def _retry_evidence(ctx: _Ctx) -> list[str]:
    out = []
    if ctx.retry is not None:
        out.append(f"retry_rate:{ctx.retry:.3f}:{SOURCE_IWINFO_ASSOCLIST}")
    if ctx.failure is not None:
        out.append(f"failure_rate:{ctx.failure:.3f}:{SOURCE_IWINFO_ASSOCLIST}")
    if ctx.family is None:
        out.append("driver_unknown")
    else:
        out.append(f"driver_family:{ctx.family}")
    return out


def _retry_high(ctx: _Ctx) -> bool:
    high_retry = ctx.retry is not None and ctx.retry >= ctx.th.retry_high
    high_fail = ctx.failure is not None and ctx.failure >= ctx.th.failure_high
    return high_retry or high_fail


def _rate_declining(ctx: _Ctx) -> bool:
    trend = ctx.w.rate_tx_trend
    return trend is not None and trend <= ctx.th.rate_decline_pct


def _rssi_text(w: ClientRfWindow) -> str:
    return f"rssi_mean:{w.rssi_mean:.1f}dBm:{SOURCE_CLIENT_HISTORY}"


def _weak_signal(ctx: _Ctx) -> ClientFinding | None:
    w, th = ctx.w, ctx.th
    if w.rssi_mean is None or w.weak_share is None:
        return None  # "persistent" needs the share over time
    if w.rssi_mean > ctx.weak_level or w.weak_share < th.persistent_weak_share:
        return None
    evidence = [
        _rssi_text(w),
        f"weak_share:{w.weak_share:.2f}:{SOURCE_CLIENT_HISTORY}",
        f"weak_threshold:{ctx.weak_level:g}dBm",
        ctx.context,
    ]
    second = []
    if _retry_high(ctx):
        second.extend(_retry_evidence(ctx))
    if _rate_declining(ctx):
        second.append(f"rate_tx_trend:{w.rate_tx_trend:.1f}%:{SOURCE_CLIENT_HISTORY}")
    if w.disconnects_weak:
        second.append(f"disconnects_weak:{w.disconnects_weak}:{SOURCE_CLIENT_HISTORY}")
    critical_context = w.mobility == MOBILITY_MOBILE and w.demand == DEMAND_HIGH
    warn = bool(second) or critical_context
    severity = Severity.WARNING if warn else Severity.INFO
    return ClientFinding(
        FindingKind.WEAK_SIGNAL_PERSISTENT,
        severity,
        tuple(evidence + second + list(ctx.base_evidence)),
        _confidence(ctx, signal=True),
    )


def _unstable(ctx: _Ctx) -> ClientFinding | None:
    sd = ctx.w.rssi_stddev
    if sd is None or sd < ctx.th.unstable_stddev_db:
        return None
    evidence = (f"rssi_stddev:{sd:.1f}dB:{SOURCE_CLIENT_HISTORY}", *ctx.base_evidence)
    # RSSI only: info at most.
    return ClientFinding(
        FindingKind.RSSI_UNSTABLE, Severity.INFO, evidence, _confidence(ctx)
    )


def _declining(ctx: _Ctx) -> ClientFinding | None:
    if not _rate_declining(ctx):
        return None
    w = ctx.w
    evidence = [f"rate_tx_trend:{w.rate_tx_trend:.1f}%:{SOURCE_CLIENT_HISTORY}"]
    if w.rate_tx_mean is not None:
        evidence.append(f"rate_tx_mean:{w.rate_tx_mean:g}kbps:{SOURCE_CLIENT_HISTORY}")
    return ClientFinding(
        FindingKind.RATE_DECLINING,
        Severity.INFO,
        (*evidence, *ctx.base_evidence),
        _confidence(ctx),
    )


def _retries(ctx: _Ctx) -> ClientFinding | None:
    if not _retry_high(ctx):
        return None
    return ClientFinding(
        FindingKind.RETRY_RATE_HIGH,
        Severity.WARNING,
        (*_retry_evidence(ctx), *ctx.base_evidence),
        _confidence(ctx, counters=True),
    )


def _weak_disconnects(ctx: _Ctx) -> ClientFinding | None:
    w = ctx.w
    if w.disconnects_weak is None or w.disconnects_weak < ctx.th.min_weak_disconnects:
        return None
    total = "?" if w.disconnects is None else str(w.disconnects)
    evidence = [
        f"disconnects_weak:{w.disconnects_weak}/{total}:{SOURCE_CLIENT_HISTORY}"
    ]
    if w.rssi_mean is not None:
        evidence.append(_rssi_text(w))
    evidence.append(ctx.context)
    return ClientFinding(
        FindingKind.DISCONNECTS_AT_WEAK_SIGNAL,
        Severity.WARNING,
        (*evidence, *ctx.base_evidence),
        _confidence(ctx, signal=True),
    )


def _poor_link(ctx: _Ctx) -> ClientFinding | None:
    w = ctx.w
    if w.rssi_mean is None or w.rssi_mean < ctx.th.good_rssi_dbm:
        return None
    if _retry_high(ctx):
        evidence = [_rssi_text(w), *_retry_evidence(ctx), *ctx.base_evidence]
        return ClientFinding(
            FindingKind.POOR_LINK_DESPITE_SIGNAL,
            Severity.WARNING,
            tuple(evidence),
            _confidence(ctx, counters=True),
        )
    low_rate = w.rate_tx_mean is not None and w.rate_tx_mean < ctx.th.low_rate_kbps
    if low_rate and w.demand != DEMAND_LOW:  # idle IoT devices send slowly
        evidence = [
            _rssi_text(w),
            f"rate_tx_mean:{w.rate_tx_mean:g}kbps:{SOURCE_CLIENT_HISTORY}",
            *ctx.base_evidence,
        ]
        return ClientFinding(
            FindingKind.POOR_LINK_DESPITE_SIGNAL,
            Severity.INFO,
            tuple(evidence),
            _confidence(ctx),
        )
    return None


_RULES = (_weak_signal, _unstable, _declining, _retries, _weak_disconnects, _poor_link)


def assess_client(
    window: ClientRfWindow, thresholds: ClientThresholds = DEFAULT_THRESHOLDS
) -> ClientAssessment:
    """Assess one client window; findings ordered like :class:`FindingKind`."""
    th = thresholds
    ctx = _context(window, th)
    findings: list[ClientFinding] = []
    if window.samples > 0:
        findings = [f for rule in _RULES if (f := rule(ctx)) is not None]
    quality = None
    if window.rssi_mean is not None and window.weak_share is not None:
        quality = round(score_signal(window.rssi_mean, window.weak_share), 1)
    return ClientAssessment(
        client_key=window.client_key,
        radio=window.radio,
        driver_family=ctx.family,
        findings=tuple(findings),
        signal_quality=quality,
        retry_rate=retry_rate(
            window.tx_retries, window.tx_packets, min_packets=th.min_packets
        ),
        failure_rate=failure_rate(
            window.tx_failed, window.tx_packets, min_packets=th.min_packets
        ),
        snr=snr(window.rssi_mean, window.noise),
        tx_packets=window.tx_packets,
        tx_retries=window.tx_retries,
        missing=_missing(window),
        samples=window.samples,
    )


# =====================================================================
# Radio summary
# =====================================================================


@dataclass(frozen=True)
class RadioClientSummary:
    """Clients of one radio in figures; coverage says how many were known."""

    radio: RadioRef | None
    client_count: int
    problem_clients: int
    flagged_clients: int
    weak_persistent_clients: int
    signal_quality_mean: float | None
    signal_coverage: float | None
    retry_rate: Metric
    retry_coverage: float | None
    driver_family: str | None
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the summary as a plain dict."""
        return {
            "radio": self.radio.as_dict() if self.radio else None,
            "client_count": self.client_count,
            "problem_clients": self.problem_clients,
            "flagged_clients": self.flagged_clients,
            "weak_persistent_clients": self.weak_persistent_clients,
            "signal_quality_mean": self.signal_quality_mean,
            "signal_coverage": self.signal_coverage,
            "retry_rate": self.retry_rate.as_dict(),
            "retry_coverage": self.retry_coverage,
            "driver_family": self.driver_family,
            "evidence": list(self.evidence),
        }


def _weighted_retry(
    assessments: Sequence[ClientAssessment],
) -> tuple[Metric, int, list[str]]:
    measured = [a for a in assessments if a.retry_rate.is_measured]
    families = {a.driver_family for a in measured}
    if len(families) > 1:
        # One radio has one driver; differing families mean the inputs are
        # inconsistent, and their counters are not comparable.
        missing = metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST)
        return missing, len(measured), ["mixed_driver_families"]
    packets = sum(a.tx_packets or 0 for a in measured)
    if not measured or packets <= 0:
        missing = metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST)
        return missing, 0, []
    retries = sum(a.tx_retries or 0 for a in measured)
    metric = metric_measured(
        retries / packets, SOURCE_IWINFO_ASSOCLIST, measured_at=None
    )
    return metric, len(measured), [f"retry_weighted_by_packets:{packets}"]


def summarize_radio_clients(
    assessments: Sequence[ClientAssessment],
) -> RadioClientSummary:
    """Summarize the assessments of one radio (mixed radios raise ValueError).

    Clients with unknown figures do not enter means as 0; they lower the
    coverage instead. The retry rate is weighted by sent packets.
    """
    radios = {a.radio for a in assessments}
    if len(radios) > 1:
        raise ValueError("assessments of more than one radio")
    total = len(assessments)
    qualities = [a.signal_quality for a in assessments if a.signal_quality is not None]
    retry, retry_known, evidence = _weighted_retry(assessments)
    families = {a.driver_family for a in assessments}
    return RadioClientSummary(
        radio=next(iter(radios)) if radios else None,
        client_count=total,
        problem_clients=sum(1 for a in assessments if a.is_problem),
        flagged_clients=sum(1 for a in assessments if a.findings),
        weak_persistent_clients=sum(
            1 for a in assessments if a.has(FindingKind.WEAK_SIGNAL_PERSISTENT)
        ),
        signal_quality_mean=sum(qualities) / len(qualities) if qualities else None,
        signal_coverage=len(qualities) / total if total else None,
        retry_rate=retry,
        retry_coverage=retry_known / total if total else None,
        driver_family=next(iter(families)) if len(families) == 1 else None,
        evidence=tuple(evidence),
    )
