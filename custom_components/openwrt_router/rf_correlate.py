"""Multi-AP load correlation (pure, no HA, not wired up yet).

Compares the utilization series of radio pairs bucket by bucket. When both
radios are highly loaded in the same buckets often enough (share of joint
high buckets among all high buckets of either radio, with a minimum number
of common valid points):

* overlapping blocks give ``shared_channel_load`` (warning): the radios
  likely compete for the same spectrum;
* blocks without overlap give ``simultaneous_load_no_overlap`` (info): busy
  at the same time, but not because of each other.

A finding is a correlation, not a proven cause; it carries ``evidence``
only. Too few common valid points or an unknown block give no finding.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from itertools import combinations
from typing import Any

from .rf_aggregate import roll_up
from .rf_conflicts import RadioRef, Severity
from .rf_spectrum import Block, OverlapKind, classify_overlap, overlap_mhz

_LOGGER = logging.getLogger(__name__)


class CorrelationKind(StrEnum):
    """What a correlation finding says."""

    SHARED_CHANNEL_LOAD = "shared_channel_load"
    SIMULTANEOUS_LOAD_NO_OVERLAP = "simultaneous_load_no_overlap"


@dataclass(frozen=True)
class CorrelateThresholds:
    """Thresholds for :func:`correlate_radios`."""

    # Same raise level as the NI rule wifi_channel_busy (net_rules.py, 70 %).
    high_pct: float = 70.0
    # Bucket size for the comparison. Startwert, nicht kalibriert.
    bucket_s: int = 300
    # One hour of 5-minute buckets. Startwert, nicht kalibriert.
    min_common_points: int = 12
    # Startwert, nicht kalibriert.
    min_joint_high: int = 3
    # Joint high buckets / buckets where either is high. Startwert, nicht
    # kalibriert.
    min_joint_share: float = 0.5


DEFAULT_CORRELATE_THRESHOLDS = CorrelateThresholds()


@dataclass(frozen=True)
class SharedLoadFinding:
    """Two radios that are highly loaded at the same times."""

    kind: CorrelationKind
    members: tuple[RadioRef, RadioRef]
    overlap: OverlapKind
    common_points: int
    joint_high: int
    union_high: int
    share: float
    severity: Severity
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the finding as a plain dict."""
        return {
            "kind": self.kind.value,
            "members": [m.as_dict() for m in self.members],
            "overlap": self.overlap.value,
            "common_points": self.common_points,
            "joint_high": self.joint_high,
            "union_high": self.union_high,
            "share": self.share,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
        }


def _bucket_means(
    series: Sequence[tuple[float, float | None]], bucket_s: int
) -> dict[int, float]:
    """Mean per bucket; buckets without a valid value are left out."""
    return {
        ts: mean
        for ts, agg in roll_up(series, bucket_s).items()
        if (mean := agg.mean) is not None
    }


def _block_text(ref: RadioRef, block: Block) -> str:
    """Evidence entry for a radio's block."""
    return f"block:{ref}:{block.band}:{block.primary}/{block.width_mhz}MHz"


def _pair(
    refs: tuple[RadioRef, RadioRef],
    means: tuple[dict[int, float], dict[int, float]],
    blocks: tuple[Block, Block],
    thresholds: CorrelateThresholds,
) -> SharedLoadFinding | None:
    """Correlate one pair; None when the data does not support a finding."""
    common = sorted(set(means[0]) & set(means[1]))
    if len(common) < thresholds.min_common_points:
        return None
    high = [{ts for ts in common if m[ts] >= thresholds.high_pct} for m in means]
    joint = high[0] & high[1]
    union = high[0] | high[1]
    if len(joint) < thresholds.min_joint_high:
        return None
    share = len(joint) / len(union)
    if share < thresholds.min_joint_share:
        return None
    overlap = classify_overlap(*blocks)
    shared = overlap is not OverlapKind.NONE
    evidence = (
        f"common_points:{len(common)}",
        f"joint_high:{len(joint)}/{len(union)}",
        f"high_threshold:{thresholds.high_pct:g}%",
        f"bucket:{thresholds.bucket_s}s",
        f"joint_high_span:{min(joint)}-{max(joint)}",
        f"overlap:{overlap.value}:{overlap_mhz(*blocks):g}MHz",
        _block_text(refs[0], blocks[0]),
        _block_text(refs[1], blocks[1]),
    )
    return SharedLoadFinding(
        kind=(
            CorrelationKind.SHARED_CHANNEL_LOAD
            if shared
            else CorrelationKind.SIMULTANEOUS_LOAD_NO_OVERLAP
        ),
        members=refs,
        overlap=overlap,
        common_points=len(common),
        joint_high=len(joint),
        union_high=len(union),
        share=share,
        severity=Severity.WARNING if shared else Severity.INFO,
        evidence=evidence,
    )


def _sort_key(ref: RadioRef) -> tuple[str, str]:
    return (ref.router_id, ref.radio_id)


def correlate_radios(
    series_by_radio: Mapping[RadioRef, Sequence[tuple[float, float | None]]],
    blocks: Mapping[RadioRef, Block],
    thresholds: CorrelateThresholds = DEFAULT_CORRELATE_THRESHOLDS,
) -> list[SharedLoadFinding]:
    """Return load correlations for every radio pair with enough data.

    ``series_by_radio`` holds ``(ts, utilization %)`` points; None and other
    unknown values are not counted as common points. Radios without a block
    are skipped (overlap unknown).
    """
    refs = sorted((r for r in series_by_radio if blocks.get(r)), key=_sort_key)
    means = {r: _bucket_means(series_by_radio[r], thresholds.bucket_s) for r in refs}
    findings: list[SharedLoadFinding] = []
    for a, b in combinations(refs, 2):
        finding = _pair(
            (a, b), (means[a], means[b]), (blocks[a], blocks[b]), thresholds
        )
        if finding is not None:
            findings.append(finding)
    return findings
