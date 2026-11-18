"""Channel, width, TX power and load recommendations (pure, no HA).

Recommendations are data only: codes plus parameters, translated later by
the frontend. Nothing here changes a radio; :class:`SelfHealingAction` is a
type for a later phase and has no executor.

Rules:

- Channel candidates come only from :func:`rf_spectrum.candidate_blocks` of
  the radio's reported list. Without a list there is no channel or width
  change (``collect_channel_list``, low priority, only when there is
  something to fix).
- "Change channel" needs a measured, sustained high utilization on the
  current channel. A potential conflict alone gives ``review_channel_plan``
  with low confidence.
- "Lower observed utilization" is only argued with comparison data for the
  candidate (``per_channel_utilization``). Without it the basis is purely
  planning (``fewer_managed_radios_on_channel``), confidence capped and the
  effect ``unknown_no_comparison_data``.
- Backhaul radios never get a channel or width change, only a review hint
  (risk ``uplink_loss_on_change``).
- Every change carries the risk ``clients_reconnect_on_change``; DFS
  candidates add ``dfs_radar_may_force_change`` and ``dfs_cac_outage``.
- TX power hints are capped in confidence while there is no environment
  measurement; a dBm value is given only inside the reported limits.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .channel_plan import BAND_24, STANDARD_24_CHANNELS
from .rf_clients import RadioClientSummary
from .rf_conflicts import Conflict, ConflictStatus, RadioRef, RadioView
from .rf_load import FINDING_BAND_IMBALANCE, DistributionReport, LoadReport, LoadStatus
from .rf_models import CapabilityState, Metric
from .rf_roaming import RoamingScore, RoamStatus, StickyAssessment, StickyStatus
from .rf_spectrum import (
    REASON_NO_CHANNEL_LIST,
    Block,
    OverlapKind,
    allowed,
    block_dfs,
    block_for,
    candidate_blocks,
    classify_overlap,
    overlap_mhz,
)
from .rf_utilization import UtilizationSummary

_LOGGER = logging.getLogger(__name__)

KIND_CHANNEL = "channel"
KIND_WIDTH = "width"
KIND_TX_POWER = "tx_power"
KIND_LOAD = "load"

PRIORITY_NORMAL = "normal"
PRIORITY_LOW = "low"

RISK_RECONNECT = "clients_reconnect_on_change"
RISK_DFS_RADAR = "dfs_radar_may_force_change"
RISK_DFS_CAC = "dfs_cac_outage"
RISK_UPLINK = "uplink_loss_on_change"
RISK_UPLINK_NOT_FIXED = "ap_power_does_not_fix_client_uplink"
RISK_COVERAGE_GAPS = "coverage_gaps_possible"
RISK_MORE_INTERFERENCE = "more_co_channel_interference"
RISK_LOWER_PEAK = "lower_peak_throughput"

BASIS_OBSERVED = "lower_observed_utilization"
BASIS_PLANNING = "fewer_managed_radios_on_channel"


@dataclass(frozen=True)
class RecommendThresholds:
    """Thresholds and caps for all recommendations."""

    # Candidate must be at least this much lower (percentage points) than
    # the current mean. Startwert, nicht kalibriert.
    min_improvement_pct: float = 15.0
    comparison_confidence: float = 0.7
    planning_confidence_cap: float = 0.4
    review_confidence: float = 0.3
    collect_confidence: float = 0.2
    width_confidence: float = 0.5
    # Same raise level as the NI rule wifi_channel_busy (70 %).
    high_utilization_pct: float = 70.0
    # TX power. Startwerte, nicht kalibriert.
    tx_min_sticky: int = 2
    tx_min_weak_clients: int = 3
    tx_step_db: int = 3
    tx_confidence_cap: float = 0.4  # no environment measurement
    tx_confidence_env_cap: float = 0.6  # neighbor signal measured
    load_confidence_cap: float = 0.6


DEFAULT_RECOMMEND_THRESHOLDS = RecommendThresholds()


@dataclass(frozen=True)
class Recommendation:
    """One recommendation; all texts are codes.

    ``target`` is a radio or a router key. ``basis`` names the argument
    (e.g. ``lower_observed_utilization``), ``priority`` is ``normal`` or
    ``low``. ``requires`` lists data that would make it stronger.
    """

    kind: str
    target: RadioRef | str
    problem: str
    evidence: tuple[str, ...]
    action: str
    action_params: Mapping[str, Any]
    expected_effect: str
    confidence: float
    risk: tuple[str, ...]
    requires: tuple[str, ...] = ()
    basis: str | None = None
    priority: str = PRIORITY_NORMAL

    def __post_init__(self) -> None:
        params = MappingProxyType(dict(self.action_params))
        object.__setattr__(self, "action_params", params)
        object.__setattr__(self, "confidence", round(self.confidence, 3))

    def as_dict(self) -> dict[str, Any]:
        """Return the recommendation as a plain dict."""
        target = (
            self.target.as_dict()
            if isinstance(self.target, RadioRef)
            else {"router_key": self.target}
        )
        return {
            "kind": self.kind,
            "target": target,
            "problem": self.problem,
            "evidence": list(self.evidence),
            "action": self.action,
            "action_params": dict(self.action_params),
            "expected_effect": self.expected_effect,
            "confidence": self.confidence,
            "risk": list(self.risk),
            "requires": list(self.requires),
            "basis": self.basis,
            "priority": self.priority,
        }


@dataclass(frozen=True)
class SelfHealingAction:
    """Type of a future automatic action — nicht implementiert.

    In dieser Phase wird nichts ausgeführt: there is no function that applies
    or executes this. It only fixes the shape (``kind``, ``target``,
    ``params``, ``preconditions``, ``rollback``) for a later, separately
    approved phase.
    """

    kind: str
    target: RadioRef | str
    params: Mapping[str, Any] = field(default_factory=dict)
    preconditions: tuple[str, ...] = ()
    rollback: Mapping[str, Any] = field(default_factory=dict)


# =====================================================================
# Helpers
# =====================================================================


def _block(view: RadioView, width: int | None = None) -> Block | None:
    return block_for(
        view.band,
        view.channel,
        width or view.width_mhz,
        center_channel=None if width else view.center_channel,
        htmode=view.htmode,
    )


def _number(metric: Metric | None) -> float | None:
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _overlapping(
    radio: RadioView, block: Block | None, others: Sequence[RadioView]
) -> list[tuple[RadioView, OverlapKind]]:
    if block is None:
        return []
    found = []
    for other in others:
        if other.ref == radio.ref or other.band != radio.band:
            continue
        other_block = _block(other)
        if other_block is None:
            continue
        kind = classify_overlap(block, other_block)
        if kind is not OverlapKind.NONE:
            found.append((other, kind))
    return found


def _usage(cand: Block, radio: RadioView, others: Sequence[RadioView]) -> int:
    return len(_overlapping(radio, cand, others))


def _sustained(summary: UtilizationSummary | None) -> bool:
    return summary is not None and summary.sustained_overload is True


def _channel_rec(radio: RadioView, **kw: Any) -> Recommendation:
    return Recommendation(kind=KIND_CHANNEL, target=radio.ref, **kw)


def _review(
    radio: RadioView,
    problem: str,
    evidence: Sequence[str],
    th: RecommendThresholds,
    action: str = "review_channel_plan",
    risk: tuple[str, ...] = (),
) -> Recommendation:
    return _channel_rec(
        radio,
        problem=problem,
        evidence=tuple(evidence),
        action=action,
        action_params={},
        expected_effect="none_without_admin_review",
        confidence=th.review_confidence,
        risk=risk,
        priority=PRIORITY_LOW,
    )


def _collect_list(
    radio: RadioView,
    kind: str,
    problem: str,
    evidence: Sequence[str],
    th: RecommendThresholds,
) -> Recommendation:
    return Recommendation(
        kind=kind,
        target=radio.ref,
        problem=problem,
        evidence=(*evidence, REASON_NO_CHANNEL_LIST),
        action="collect_channel_list",
        action_params={},
        expected_effect="enables_channel_recommendation",
        confidence=th.collect_confidence,
        risk=(),
        requires=("freqlist",),
        priority=PRIORITY_LOW,
    )


# =====================================================================
# Channel
# =====================================================================


def _comparison(
    cand: Block, per_channel: Mapping[int, UtilizationSummary] | None
) -> tuple[float, float] | None:
    """(max mean, min coverage) over the block; None unless all channels known."""
    if not per_channel:
        return None
    means, coverages = [], []
    for ch in cand.channels:
        summary = per_channel.get(ch)
        if summary is None or summary.mean is None:
            return None
        means.append(summary.mean)
        coverages.append(summary.coverage or 0.0)
    return max(means), min(coverages)


def _candidates(radio: RadioView, current: Block) -> list[Block]:
    found = candidate_blocks(radio.band, radio.width_mhz, radio.regulatory).blocks
    out = []
    for cand in found:
        if radio.band == BAND_24 and cand.primary not in STANDARD_24_CHANNELS:
            continue  # never an off-grid 2.4 GHz channel
        if overlap_mhz(cand, current) > 0:
            continue
        out.append(cand)
    return out


def _dfs_risk(cand: Block) -> tuple[str, ...]:
    if block_dfs(cand).dfs:
        return (RISK_RECONNECT, RISK_DFS_RADAR, RISK_DFS_CAC)
    return (RISK_RECONNECT,)


def _change(
    radio: RadioView,
    cand: Block,
    evidence: list[str],
    *,
    basis: str,
    effect: str,
    confidence: float,
    requires: tuple[str, ...] = (),
) -> Recommendation:
    params = {"channel": cand.primary, "width_mhz": cand.width_mhz, "basis": basis}
    return _channel_rec(
        radio,
        problem="sustained_high_utilization",
        evidence=(*evidence, f"rationale:{basis}"),
        action="change_channel",
        action_params=params,
        expected_effect=effect,
        confidence=confidence,
        risk=_dfs_risk(cand),
        requires=requires,
        basis=basis,
    )


def _pick_observed(
    cands: Sequence[Block],
    per_channel: Mapping[int, UtilizationSummary] | None,
    current: UtilizationSummary,
    th: RecommendThresholds,
) -> tuple[list[tuple[float, bool, float, Block, float]], list[Block]]:
    """Split candidates into (better by data, without data)."""
    better, no_data = [], []
    current_mean = current.mean if current.mean is not None else 0.0
    for cand in cands:
        comp = _comparison(cand, per_channel)
        if comp is None:
            no_data.append(cand)
        elif comp[0] <= current_mean - th.min_improvement_pct:
            dfs = bool(block_dfs(cand).dfs)
            better.append((comp[0], dfs, cand.low_mhz, cand, comp[1]))
    better.sort(key=lambda x: (x[0], x[1], x[2]))
    return better, no_data


def _choose(
    radio: RadioView,
    current_block: Block,
    summary: UtilizationSummary,
    others: Sequence[RadioView],
    per_channel: Mapping[int, UtilizationSummary] | None,
    th: RecommendThresholds,
    evidence: list[str],
) -> Recommendation:
    cands = _candidates(radio, current_block)
    better, no_data = _pick_observed(cands, per_channel, summary, th)
    if better:
        value, _, _, cand, coverage = better[0]
        conf = th.comparison_confidence * min(coverage, summary.coverage or 0.0)
        return _change(
            radio,
            cand,
            [*evidence, f"utilization:ch{cand.primary}:{value:.1f}%"],
            basis=BASIS_OBSERVED,
            effect="lower_channel_utilization",
            confidence=conf,
        )
    current_usage = _usage(current_block, radio, others)
    planned = sorted(
        (
            (_usage(c, radio, others), bool(block_dfs(c).dfs), c.low_mhz, c)
            for c in no_data
        ),
        key=lambda x: x[:3],
    )
    if planned and planned[0][0] < current_usage:
        usage, _, _, cand = planned[0]
        plan_evidence = [
            *evidence,
            f"managed_radios:ch{radio.channel}:{current_usage}",
            f"managed_radios:ch{cand.primary}:{usage}",
            f"no_comparison_data:ch{cand.primary}",
        ]
        return _change(
            radio,
            cand,
            plan_evidence,
            basis=BASIS_PLANNING,
            effect="unknown_no_comparison_data",
            confidence=th.planning_confidence_cap * 0.75,
            requires=("per_channel_utilization",),
        )
    return _review(
        radio, "sustained_high_utilization", [*evidence, "no_better_candidate"], th
    )


def recommend_channel(
    radio: RadioView,
    summary: UtilizationSummary | None,
    others: Sequence[RadioView],
    per_channel_utilization: Mapping[int, UtilizationSummary] | None,
    thresholds: RecommendThresholds = DEFAULT_RECOMMEND_THRESHOLDS,
) -> Recommendation | None:
    """Recommend a channel for one radio, or a review/collect hint, or None.

    ``per_channel_utilization`` maps a 20 MHz channel number to an observed
    summary (another own radio on it or a survey); a wide candidate needs
    data for every sub-channel. DECIDED: without a reported list and with a
    problem the result is ``collect_channel_list`` (low priority), without a
    problem None.
    """
    th = thresholds
    current_block = _block(radio)
    overlaps = _overlapping(radio, current_block, others)
    evidence = [f"channel:{radio.channel}/{radio.width_mhz}MHz:{radio.band}"]
    if summary is not None and summary.mean is not None:
        evidence.append(f"utilization:ch{radio.channel}:{summary.mean:.1f}%")
        evidence.append(f"sustained_overload:{summary.sustained_overload}")
    else:
        evidence.append("utilization_unknown")
    overlap_evidence = [f"potential_overlap:{o.ref}:{k.value}" for o, k in overlaps]
    sustained = _sustained(summary)
    if radio.backhaul:
        if not (sustained or overlaps):
            return None
        return _review(
            radio,
            "sustained_high_utilization" if sustained else "potential_overlap",
            [*evidence, *overlap_evidence, f"backhaul:{radio.ref}"],
            th,
            action="review_backhaul_channel",
            risk=(RISK_UPLINK, RISK_RECONNECT),
        )
    if not sustained:
        if not overlaps:
            return None
        return _review(radio, "potential_overlap", [*evidence, *overlap_evidence], th)
    if radio.regulatory is None or not radio.regulatory.channels:
        return _collect_list(
            radio, KIND_CHANNEL, "sustained_high_utilization", evidence, th
        )
    if current_block is None or summary is None:
        # Impossible channel/width combination: nothing to compare against.
        return _review(
            radio, "sustained_high_utilization", [*evidence, "block_unknown"], th
        )
    evidence.extend(overlap_evidence)
    return _choose(
        radio, current_block, summary, others, per_channel_utilization, th, evidence
    )


# =====================================================================
# Width
# =====================================================================


def _width_rec(
    radio: RadioView, new: Block, evidence: list[str], th: RecommendThresholds
) -> Recommendation:
    risk = (
        (RISK_RECONNECT,)
        if radio.band == BAND_24
        else (RISK_RECONNECT, RISK_LOWER_PEAK)
    )
    return Recommendation(
        kind=KIND_WIDTH,
        target=radio.ref,
        problem="wide_channel_overlap",
        evidence=tuple(evidence),
        action="change_width",
        action_params={"width_mhz": new.width_mhz, "channel": new.primary},
        expected_effect="less_overlap",
        confidence=th.width_confidence,
        risk=risk,
    )


def _narrower_reason(
    radio: RadioView,
    summary: UtilizationSummary | None,
    overlaps: Sequence[tuple[RadioView, OverlapKind]],
    th: RecommendThresholds,
) -> list[str] | None:
    if radio.band == BAND_24:
        return ["band_24_wide_channel"] if radio.width_mhz >= 40 else None
    if radio.width_mhz <= 20 or not overlaps:
        return None
    if _sustained(summary):
        return ["overlap_with_sustained_high_utilization"]
    loud = [
        o
        for o, _ in overlaps
        if (_number(o.utilization) or 0.0) >= th.high_utilization_pct
    ]
    if loud:
        return [f"overlap_with_high_utilization:{o.ref}" for o in loud]
    return None


def recommend_width(
    radio: RadioView,
    summary: UtilizationSummary | None,
    others: Sequence[RadioView],
    thresholds: RecommendThresholds = DEFAULT_RECOMMEND_THRESHOLDS,
) -> Recommendation | None:
    """2.4 GHz 40 MHz → 20 MHz; 5 GHz half width only with measured overlap
    and high load. A width is only named when ``allowed`` confirms it."""
    th = thresholds
    block = _block(radio)
    overlaps = _overlapping(radio, block, others)
    reason = _narrower_reason(radio, summary, overlaps, th)
    if reason is None:
        return None
    evidence = [
        f"width_mhz:{radio.width_mhz}",
        *reason,
        *(f"overlaps:{o.ref}:{k.value}" for o, k in overlaps),
    ]
    if radio.backhaul:
        return Recommendation(
            kind=KIND_WIDTH,
            target=radio.ref,
            problem="wide_channel_overlap",
            evidence=(*evidence, f"backhaul:{radio.ref}"),
            action="review_backhaul_width",
            action_params={},
            expected_effect="none_without_admin_review",
            confidence=th.review_confidence,
            risk=(RISK_UPLINK, RISK_RECONNECT),
            priority=PRIORITY_LOW,
        )
    new_width = 20 if radio.band == BAND_24 else radio.width_mhz // 2
    new = _block(radio, new_width)
    if new is None:
        return None
    verdict = allowed(new, radio.regulatory)
    if verdict.reasons == (REASON_NO_CHANNEL_LIST,):
        return _collect_list(radio, KIND_WIDTH, "wide_channel_overlap", evidence, th)
    if verdict.ok is not True:
        return None
    return _width_rec(radio, new, evidence, th)


# =====================================================================
# TX power
# =====================================================================


def _tx_value(
    current: float | None,
    limits: tuple[int, int] | None,
    direction: str,
    step: int,
) -> int | None:
    if current is None or limits is None:
        return None
    low, high = limits
    target = current - step if direction == "lower" else current + step
    return int(max(low, min(high, round(target))))


def _tx_rec(
    radio: RadioView,
    direction: str,
    current: float | None,
    limits: tuple[int, int] | None,
    evidence: list[str],
    confidence: float,
    th: RecommendThresholds,
) -> Recommendation:
    requires = []
    if current is None:
        requires.append("txpower")
    if limits is None:
        requires.append("txpowerlist")
    value = _tx_value(current, limits, direction, th.tx_step_db)
    lower = direction == "lower"
    risk = (
        (RISK_COVERAGE_GAPS,)
        if lower
        else (RISK_UPLINK_NOT_FIXED, RISK_MORE_INTERFERENCE)
    )
    if value is not None and current is not None and round(current) == value:
        return Recommendation(
            kind=KIND_TX_POWER,
            target=radio.ref,
            problem="cell_too_large_suspected"
            if lower
            else "weak_clients_at_power_limit",
            evidence=(*evidence, f"tx_power_at_limit:{value}dBm"),
            action="review_ap_placement",
            action_params={},
            expected_effect="none_without_admin_review",
            confidence=confidence,
            risk=risk,
        )
    params: dict[str, Any] = {"direction": direction}
    if value is not None:
        params["dbm"] = value
    return Recommendation(
        kind=KIND_TX_POWER,
        target=radio.ref,
        problem="cell_too_large_suspected" if lower else "coverage_too_weak_suspected",
        evidence=tuple(evidence),
        action="adjust_tx_power",
        action_params=params,
        expected_effect="fewer_sticky_clients"
        if lower
        else "better_downlink_for_weak_clients",
        confidence=confidence,
        risk=risk,
        requires=tuple(requires),
    )


def recommend_tx_power(
    radio: RadioView,
    current_dbm: Metric,
    limits: tuple[int, int] | None,
    client_summary: RadioClientSummary | None,
    sticky: Sequence[StickyAssessment],
    overlap_conflicts: Sequence[Conflict],
    roaming: Sequence[RoamingScore] = (),
    thresholds: RecommendThresholds = DEFAULT_RECOMMEND_THRESHOLDS,
) -> Recommendation | None:
    """TX power hint: "lower" for several sticky clients plus a measured
    overlap, "raise" for many persistently weak clients without alternative.

    ``limits`` is :func:`rf_spectrum.tx_power_limits`. Sticky clients with
    a measured overlap next to many weak clients contradict each other
    (lowering would hurt the weak ones) and give no hint. ``roaming``
    (scores of this radio's clients) only adds evidence.
    """
    th = thresholds
    ref = radio.ref
    here = [s for s in sticky if s.radio == ref]
    suspected = [
        s
        for s in here
        if s.status in (StickyStatus.SUSPECTED, StickyStatus.SUPPORTED_BY_MEASUREMENT)
    ]
    measured = [
        c
        for c in overlap_conflicts
        if ref in c.members and c.status is ConflictStatus.MEASURED
    ]
    env = any(e.startswith("neighbor_signal:") for c in measured for e in c.evidence)
    cap = th.tx_confidence_env_cap if env else th.tx_confidence_cap
    weak = client_summary.weak_persistent_clients if client_summary else 0
    many_weak = weak >= th.tx_min_weak_clients
    too_high = len(suspected) >= th.tx_min_sticky and bool(measured)
    too_low = many_weak and not suspected  # no alternative AP seen
    if too_high and many_weak:
        return None  # contradicting evidence
    if not (too_high or too_low):
        return None
    current = _number(current_dbm)
    evidence = [
        f"tx_power:{current:g}dBm:{current_dbm.source}"
        if current is not None
        else f"tx_power_unknown:{current_dbm.state.value}",
        f"tx_power_limits:{limits[0]}-{limits[1]}dBm"
        if limits
        else "tx_power_limits_unknown",
        "environment_measured" if env else "no_environment_measurement",
    ]
    poor_roaming = [
        r for r in roaming if r.status is RoamStatus.SCORED and (r.score or 0) < 50
    ]
    if poor_roaming:
        evidence.append(f"poor_roaming_clients:{len(poor_roaming)}")
    if too_high:
        evidence.append(f"sticky_clients:{len(suspected)}")
        evidence.extend(
            f"measured_overlap:{'+'.join(map(str, c.members))}" for c in measured
        )
        confidence = min(cap, 0.2 + 0.1 * len(suspected))
        return _tx_rec(radio, "lower", current, limits, evidence, confidence, th)
    evidence.append(f"weak_persistent_clients:{weak}")
    evidence.append("no_alternative_ap_seen")
    confidence = min(cap, 0.1 + 0.05 * weak)
    return _tx_rec(radio, "raise", current, limits, evidence, confidence, th)


# =====================================================================
# Load
# =====================================================================


def _load_rec(
    router_key: str,
    action: str,
    problem: str,
    evidence: Sequence[str],
    confidence: float,
    priority: str = PRIORITY_NORMAL,
    requires: tuple[str, ...] = (),
) -> Recommendation:
    return Recommendation(
        kind=KIND_LOAD,
        target=router_key,
        problem=problem,
        evidence=tuple(evidence),
        action=action,
        action_params={},
        expected_effect="none_without_admin_review",
        confidence=confidence,
        risk=(),
        requires=requires,
        priority=priority,
    )


def recommend_load(
    report: LoadReport,
    distribution: DistributionReport,
    thresholds: RecommendThresholds = DEFAULT_RECOMMEND_THRESHOLDS,
) -> list[Recommendation]:
    """Review tasks for the admin; the system never moves clients itself."""
    th = thresholds
    out: list[Recommendation] = []
    for ap in report.aps:
        evidence = [e for r in ap.radios for e in r.evidence]
        conf = min(th.load_confidence_cap, ap.confidence)
        if ap.status is LoadStatus.OVERLOADED:
            out.append(
                _load_rec(
                    ap.router_key, "review_ap_load", "ap_overloaded", evidence, conf
                )
            )
        elif ap.status is LoadStatus.ELEVATED:
            if any(e.startswith("utilization_unknown") for e in evidence):
                out.append(
                    _load_rec(
                        ap.router_key,
                        "collect_utilization",
                        "load_hints_without_utilization",
                        evidence,
                        conf,
                        PRIORITY_LOW,
                        ("utilization",),
                    )
                )
            else:
                out.append(
                    _load_rec(
                        ap.router_key,
                        "review_ap_load",
                        "ap_load_elevated",
                        evidence,
                        conf,
                        PRIORITY_LOW,
                    )
                )
    for finding in distribution.findings:
        if finding.kind == FINDING_BAND_IMBALANCE:
            target = distribution.largest_ap or ""
            action, problem = "review_band_settings", "band_imbalance"
        else:
            target = distribution.largest_ap or ""
            action, problem = "review_client_distribution", finding.kind
        out.append(
            _load_rec(
                target,
                action,
                problem,
                finding.evidence,
                th.review_confidence,
                PRIORITY_LOW,
            )
        )
    return out
