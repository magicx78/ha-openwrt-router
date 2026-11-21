"""Load per AP and client distribution between APs (pure, no HA).

Only observations; recommendation texts are made in :mod:`rf_recommend`.

Rules:

- A high client count alone is never ``overloaded`` (only the hint
  ``many_clients``). ``overloaded`` needs a measured high utilization (or a
  measured high retry rate while the load is not measured low) plus a
  second piece of evidence.
- Without a utilization measurement the status is ``unknown``, or at most
  ``elevated`` with ``utilization_unknown`` when there are hints; never
  ``ok``.
- Distribution verdicts need the client counts of every radio; whether
  2.4 GHz clients could use 5 GHz is unknown unless the caller says so.
"""

from __future__ import annotations

import logging
import statistics
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .rf_clients import driver_family
from .rf_conflicts import RadioRef, Severity
from .rf_models import CapabilityState, Metric

_LOGGER = logging.getLogger(__name__)

BAND_24 = "2.4g"

FINDING_UNEVEN = "uneven_client_distribution"
FINDING_BAND_IMBALANCE = "band_imbalance"


class LoadStatus(StrEnum):
    """Load verdict of a radio or AP."""

    OK = "ok"
    ELEVATED = "elevated"
    OVERLOADED = "overloaded"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LoadThresholds:
    """Thresholds for :func:`assess_load` and :func:`distribution`."""

    # Same raise level as the NI rule wifi_channel_busy (70 %).
    high_utilization_pct: float = 70.0
    # Startwerte, nicht kalibriert:
    elevated_utilization_pct: float = 50.0
    high_retry_rate: float = 0.25  # retries per packet, as rf_clients
    many_clients: int = 25  # per radio
    top_client_airtime_pct: float = 50.0
    problem_clients: int = 3
    weak_rssi_mean_dbm: float = -72.0
    # Distribution: no verdict below this many clients in total.
    min_total_clients: int = 10
    # Largest AP share times number of APs (1.0 = perfectly even).
    uneven_factor: float = 1.6
    # band_imbalance: share of 2.4 GHz clients known to be 5 GHz capable.
    band_capable_share: float = 0.5


DEFAULT_LOAD_THRESHOLDS = LoadThresholds()


@dataclass(frozen=True)
class RadioLoad:
    """Load figures of one radio.

    ``utilization`` and ``airtime_share_top_client`` are percent;
    ``retry_rate`` is retries per sent packet (``rf_clients``); byte rates
    are bytes per second. Any of them may be missing.
    """

    ref: RadioRef
    band: str
    client_count: int | None
    utilization: Metric | None
    airtime_share_top_client: Metric | None
    rssi_mean: Metric | None
    retry_rate: Metric | None
    driver: str | None
    tx_bytes_rate: float | None
    rx_bytes_rate: float | None
    problem_clients: int | None


@dataclass(frozen=True)
class ApLoadInput:
    """All radios of one router."""

    router_id: str
    radios: Sequence[RadioLoad]


@dataclass(frozen=True)
class RadioLoadAssessment:
    """Load verdict of one radio."""

    ref: RadioRef
    status: LoadStatus
    evidence: tuple[str, ...]
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        """Return the assessment as a plain dict."""
        return {
            "ref": self.ref.as_dict(),
            "status": self.status.value,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class ApLoadAssessment:
    """Load verdict of one AP: the worst radio; unknown radios block ``ok``."""

    router_id: str
    status: LoadStatus
    radios: tuple[RadioLoadAssessment, ...]
    evidence: tuple[str, ...]
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        """Return the assessment as a plain dict."""
        return {
            "router_id": self.router_id,
            "status": self.status.value,
            "radios": [r.as_dict() for r in self.radios],
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class LoadReport:
    """Load verdicts of all APs."""

    aps: tuple[ApLoadAssessment, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the report as a plain dict."""
        return {"aps": [a.as_dict() for a in self.aps]}


def _number(metric: Metric | None) -> float | None:
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _hints(r: RadioLoad, th: LoadThresholds) -> list[str]:
    hints = []
    if r.client_count is not None and r.client_count >= th.many_clients:
        hints.append(f"many_clients:{r.ref}:{r.client_count}")
    top = _number(r.airtime_share_top_client)
    if top is not None and top >= th.top_client_airtime_pct:
        hints.append(f"top_client_airtime:{r.ref}:{top:.1f}%")
    if r.problem_clients is not None and r.problem_clients >= th.problem_clients:
        hints.append(f"problem_clients:{r.ref}:{r.problem_clients}")
    rssi = _number(r.rssi_mean)
    if rssi is not None and rssi <= th.weak_rssi_mean_dbm:
        hints.append(f"rssi_mean_weak:{r.ref}:{rssi:g}dBm")
    return hints


def _base_evidence(r: RadioLoad, util: float | None, retry: float | None) -> list[str]:
    evidence = []
    if util is None:
        state = r.utilization.state.value if r.utilization else "none"
        evidence.append(f"utilization_unknown:{r.ref}:{state}")
    else:
        source = r.utilization.source if r.utilization else ""
        evidence.append(f"utilization:{r.ref}:{util:.1f}%:{source}")
    if retry is not None:
        source = r.retry_rate.source if r.retry_rate else ""
        family = driver_family(r.driver) or "unknown"
        evidence.append(f"retry_rate:{r.ref}:{retry:.3f}:{source}")
        evidence.append(f"driver_family:{family}")
    if r.client_count is None:
        evidence.append(f"client_count_unknown:{r.ref}")
    return evidence


def _radio_status(
    util: float | None, retry: float | None, hints: Sequence[str], th: LoadThresholds
) -> tuple[LoadStatus, float, list[str]]:
    high_util = util is not None and util >= th.high_utilization_pct
    high_retry = retry is not None and retry >= th.high_retry_rate
    low_util = util is not None and util < th.elevated_utilization_pct
    extra: list[str] = []
    if high_util and (high_retry or hints):
        return LoadStatus.OVERLOADED, 0.8, extra
    if high_retry and not low_util and hints:
        return LoadStatus.OVERLOADED, 0.6, extra
    if low_util:
        if high_retry:
            extra.append("retry_rate_high_without_load")
        return LoadStatus.OK, 0.7, extra
    if util is not None:  # elevated or high without a second evidence
        return LoadStatus.ELEVATED, 0.6, extra
    if high_retry or hints:
        return LoadStatus.ELEVATED, 0.4, extra
    return LoadStatus.UNKNOWN, 0.0, extra


def _assess_radio(r: RadioLoad, th: LoadThresholds) -> RadioLoadAssessment:
    util = _number(r.utilization)
    retry = _number(r.retry_rate)
    hints = _hints(r, th)
    status, confidence, extra = _radio_status(util, retry, hints, th)
    evidence = [*_base_evidence(r, util, retry), *hints]
    evidence.extend(f"{e}:{r.ref}" for e in extra)
    return RadioLoadAssessment(r.ref, status, tuple(evidence), confidence)


_SEVERITY_ORDER = (LoadStatus.OVERLOADED, LoadStatus.ELEVATED)


def _ap_status(radios: Sequence[RadioLoadAssessment]) -> tuple[LoadStatus, float]:
    for status in _SEVERITY_ORDER:
        hits = [r.confidence for r in radios if r.status is status]
        if hits:
            return status, max(hits)
    if radios and all(r.status is LoadStatus.OK for r in radios):
        return LoadStatus.OK, min(r.confidence for r in radios)
    return LoadStatus.UNKNOWN, 0.0


def assess_load(
    aps: Sequence[ApLoadInput], thresholds: LoadThresholds = DEFAULT_LOAD_THRESHOLDS
) -> LoadReport:
    """Assess the load of every radio and AP (see module rules)."""
    out = []
    for ap in aps:
        radios = tuple(_assess_radio(r, thresholds) for r in ap.radios)
        status, confidence = _ap_status(radios)
        unknown = [str(r.ref) for r in radios if r.status is LoadStatus.UNKNOWN]
        evidence = tuple(f"radio_unknown:{ref}" for ref in unknown)
        out.append(ApLoadAssessment(ap.router_id, status, radios, evidence, confidence))
    return LoadReport(tuple(out))


# =====================================================================
# Distribution
# =====================================================================


@dataclass(frozen=True)
class DistributionFinding:
    """One distribution finding (always info: an observation)."""

    kind: str
    severity: Severity
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the finding as a plain dict."""
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class DistributionReport:
    """Client counts by AP and band, imbalance figures and findings.

    ``per_ap`` is None for an AP without any known count; ``coverage`` is the
    share of radios with a known count.
    """

    per_ap: dict[str, int | None]
    per_band: dict[str, int]
    total: int
    coverage: float | None
    largest_ap: str | None
    largest_share: float | None
    max_over_median: float | None
    findings: tuple[DistributionFinding, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the report as a plain dict."""
        return {
            "per_ap": dict(self.per_ap),
            "per_band": dict(self.per_band),
            "total": self.total,
            "coverage": self.coverage,
            "largest_ap": self.largest_ap,
            "largest_share": self.largest_share,
            "max_over_median": self.max_over_median,
            "findings": [f.as_dict() for f in self.findings],
            "evidence": list(self.evidence),
        }


def _counts(
    aps: Sequence[ApLoadInput],
) -> tuple[dict[str, int | None], dict[str, int], int, int]:
    per_ap: dict[str, int | None] = {}
    per_band: dict[str, int] = defaultdict(int)
    radios = known = 0
    for ap in aps:
        counts = [r.client_count for r in ap.radios if r.client_count is not None]
        per_ap[ap.router_id] = sum(counts) if counts else None
        for r in ap.radios:
            radios += 1
            if r.client_count is not None:
                known += 1
                per_band[r.band] += r.client_count
    return per_ap, dict(sorted(per_band.items())), radios, known


def _uneven(
    per_ap: dict[str, int | None], total: int, th: LoadThresholds
) -> tuple[str | None, float | None, float | None, DistributionFinding | None]:
    counts = {k: v for k, v in per_ap.items() if v is not None}
    if not counts or total <= 0:
        return None, None, None, None
    largest = max(sorted(counts), key=lambda k: counts[k])
    share = counts[largest] / total
    median = statistics.median(counts.values())
    ratio = counts[largest] / median if median > 0 else None
    factor = share * len(counts)
    finding = None
    if len(counts) >= 2 and factor >= th.uneven_factor:
        evidence = [
            f"largest:{largest}:{counts[largest]}/{total}",
            f"fair_share_factor:{factor:.2f}",
            f"aps:{len(counts)}",
        ]
        if ratio is not None:
            evidence.append(f"max_over_median:{ratio:.2f}")
        finding = DistributionFinding(FINDING_UNEVEN, Severity.INFO, tuple(evidence))
    return largest, share, ratio, finding


def _band_finding(
    per_band: dict[str, int], capable: int | None, th: LoadThresholds
) -> tuple[DistributionFinding | None, list[str]]:
    on_24 = per_band.get(BAND_24, 0)
    if capable is None:
        return None, ["band_capability_unknown"]
    if on_24 <= 0 or capable / on_24 < th.band_capable_share:
        return None, [f"capable_5g_on_24:{capable}/{on_24}"]
    evidence = (f"capable_5g_on_24:{capable}/{on_24}", "source:caller")
    finding = DistributionFinding(FINDING_BAND_IMBALANCE, Severity.INFO, evidence)
    return finding, []


def distribution(
    aps: Sequence[ApLoadInput],
    thresholds: LoadThresholds = DEFAULT_LOAD_THRESHOLDS,
    *,
    capable_5g_on_24: int | None = None,
) -> DistributionReport:
    """Show how clients spread over APs and bands; judge only on full data.

    ``capable_5g_on_24`` is the number of 2.4 GHz clients known to support
    5 GHz (later from client capabilities); without it the band shares are
    shown without a verdict.
    """
    th = thresholds
    per_ap, per_band, radios, known = _counts(aps)
    total = sum(per_band.values())
    coverage = known / radios if radios else None
    largest, share, ratio, uneven = _uneven(per_ap, total, th)
    findings: list[DistributionFinding] = []
    evidence: list[str] = []
    if coverage is not None and coverage < 1.0:
        evidence.append("client_counts_incomplete")
    elif total < th.min_total_clients:
        evidence.append(f"total_below_minimum:{total}<{th.min_total_clients}")
    elif uneven is not None:
        findings.append(uneven)
    band, band_evidence = _band_finding(per_band, capable_5g_on_24, th)
    evidence.extend(band_evidence)
    if band is not None and coverage == 1.0:
        findings.append(band)
    return DistributionReport(
        per_ap=per_ap,
        per_band=per_band,
        total=total,
        coverage=coverage,
        largest_ap=largest,
        largest_share=share,
        max_over_median=ratio,
        findings=tuple(findings),
        evidence=tuple(evidence),
    )
