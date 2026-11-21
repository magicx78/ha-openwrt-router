"""Capacity planning per interface, port, WAN and VLAN (task §11; Phase G).

Reads only the history interface (``traffic_series.BucketSource``).

**Data rate of a bucket** = bytes x 8 / covered seconds (the average over
the time the bucket really measured). Buckets below half coverage are
"lückenhaft" and are left out of every statistic here (counted as
``gappy_buckets``).

**P95 definition** (:func:`p95`): nearest rank on the usable bucket rates of
the window: sort ascending ``v[1..n]`` and take ``v[ceil(0.95 x n)]``. It is
always an observed value (no interpolation); equal values give that value;
fewer than ``P95_MIN_POINTS`` (20) usable buckets give None
(``insufficient_data``). From buckets coarser than 5 min the P95 is marked
``p95_estimated`` (``p95_from_coarse_buckets``).

**Utilisation** is against the real link speed and duplex of the point
(from the poll); without a known speed it is None with
``link_speed_unknown`` and nothing is compared against an assumed value.
Full duplex: each direction against the link. Half duplex: RX and TX share
the medium, so their sum of rates per bucket is compared (that is the only
place RX and TX meet, and only inside one point).

**Assessment** (never a "confirmed" bottleneck: high bandwidth alone proves
no bottleneck): ``insufficient_data``, ``no_link_speed``, ``headroom``,
``approaching_capacity`` (P95 >= 70 %), ``possible_bottleneck`` (P95 >= 90 %
or near capacity (>= 80 %) for >= 2 consecutive buckets on >= 2 days),
``possible_uplink_bottleneck`` (the same at a WAN or a known uplink port).

**Trend** (:func:`trend`): Theil-Sen slope (median of pairwise slopes,
robust to single outlier days) of the daily mean rate, only with at least
14 usable days covering at least 70 % of the span; else
``insufficient_data``. Always ``estimate: true`` with its data base and a
confidence of at most 0.8; it is never called a forecast. The days until
80 % of the link are only given for a rising trend within a year.
"""

from __future__ import annotations

import logging
import math
import statistics
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, tzinfo
from typing import Any, Final

from .traffic_accounting import direction_map
from .traffic_const import (
    APPROACHING_PCT,
    BYTES_PER_S_PER_MBPS,
    CAP_STATE_APPROACHING,
    CAP_STATE_HEADROOM,
    CAP_STATE_INSUFFICIENT,
    CAP_STATE_NO_LINK,
    CAP_STATE_POSSIBLE_BOTTLENECK,
    CAP_STATE_POSSIBLE_UPLINK_BOTTLENECK,
    CAPACITY_WINDOW_S,
    GAPPY_BELOW,
    HIGH_P95_PCT,
    MAX_CAPACITY_ROWS,
    NEAR_CAPACITY_PCT,
    NEAR_MIN_BUCKETS,
    P95_EXACT_RESOLUTION_S,
    P95_MIN_POINTS,
    P95_QUANTILE,
    REASON_BEYOND_HORIZON,
    REASON_HALF_DUPLEX_SHARED,
    REASON_INSUFFICIENT_DATA,
    REASON_NO_LINK_SPEED,
    REASON_NOT_RISING,
    REASON_P95_FROM_COARSE,
    REASON_TREND_LOW_COVERAGE,
    REASON_TREND_TOO_SHORT,
    RECURRING_MIN_DAYS,
    TREND_HORIZON_DAYS,
    TREND_LOOKBACK_S,
    TREND_MAX_CONFIDENCE,
    TREND_METHOD,
    TREND_MIN_COVERAGE,
    TREND_MIN_DAYS,
)
from .traffic_model import Bucket, MeasurementPoint, Scope
from .traffic_series import BucketSource, SeriesWindow

_LOGGER = logging.getLogger(__name__)

CAPACITY_SCOPES: Final = frozenset({Scope.INTERFACE, Scope.PORT, Scope.WAN, Scope.VLAN})
DAY_S: Final = 86400


# --- statistics ---------------------------------------------------------------------------


def bucket_rate(bucket: Bucket, counter: str) -> float | None:
    """Average bit/s of a bucket over its covered time (None: unknown)."""
    value = bucket.rx_bytes if counter == "rx" else bucket.tx_bytes
    if value is None or bucket.covered_s <= 0:
        return None
    return value * 8 / bucket.covered_s


def p95(values: Sequence[float]) -> float | None:
    """Nearest-rank 95th percentile (None below ``P95_MIN_POINTS`` values)."""
    if len(values) < P95_MIN_POINTS:
        return None
    ordered = sorted(values)
    rank = math.ceil(P95_QUANTILE * len(ordered))
    return ordered[rank - 1]


def link_bps(link_mbps: int | None) -> float | None:
    """Link speed in bit/s (None: unknown or not positive)."""
    if isinstance(link_mbps, bool) or not isinstance(link_mbps, int) or link_mbps <= 0:
        return None
    return float(link_mbps * BYTES_PER_S_PER_MBPS * 8)


def theil_sen(points: Sequence[tuple[float, float]]) -> tuple[float, float] | None:
    """(slope, intercept) by Theil-Sen; None for fewer than two x values."""
    slopes = [
        (y2 - y1) / (x2 - x1)
        for i, (x1, y1) in enumerate(points)
        for x2, y2 in points[i + 1 :]
        if x2 != x1
    ]
    if not slopes:
        return None
    slope = statistics.median(slopes)
    intercept = statistics.median([y - slope * x for x, y in points])
    return float(slope), float(intercept)


# --- results --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LinkFacts:
    """Link speed (Mbit/s) and duplex of one point (None: unknown)."""

    link_mbps: int | None
    duplex: str | None


@dataclass(frozen=True, slots=True)
class DirectionStats:
    """Mean, peak and P95 of one counter, as bit/s and percent of the link."""

    counter: str
    meaning: str | None
    avg_bps: float | None
    peak_bps: float | None
    p95_bps: float | None
    avg_pct: float | None
    peak_pct: float | None
    p95_pct: float | None
    unavailable: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "counter": self.counter,
            "meaning": self.meaning,
            "avg_bps": self.avg_bps,
            "peak_bps": self.peak_bps,
            "p95_bps": self.p95_bps,
            "avg_pct": self.avg_pct,
            "peak_pct": self.peak_pct,
            "p95_pct": self.p95_pct,
            "unavailable": dict(self.unavailable),
        }


@dataclass(frozen=True, slots=True)
class Trend:
    """A cautious linear estimate (never a forecast)."""

    state: str
    reason: str | None
    method: str = TREND_METHOD
    estimate: bool = True
    basis_days: int = 0
    span_days: int = 0
    slope_bps_per_day: float | None = None
    slope_pct_per_week: float | None = None
    level_bps: float | None = None
    days_to_near_capacity: float | None = None
    days_to_near_capacity_reason: str | None = None
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "state": self.state,
            "reason": self.reason,
            "method": self.method,
            "estimate": self.estimate,
            "basis_days": self.basis_days,
            "span_days": self.span_days,
            "slope_bps_per_day": self.slope_bps_per_day,
            "slope_pct_per_week": self.slope_pct_per_week,
            "level_bps": self.level_bps,
            "days_to_near_capacity": self.days_to_near_capacity,
            "days_to_near_capacity_reason": self.days_to_near_capacity_reason,
            "confidence": self.confidence,
        }


@dataclass(frozen=True, slots=True)
class CapacityRow:
    """Capacity view of one point."""

    point_id: str
    scope: Scope
    router_id: str | None
    device: str | None
    vlan_id: int | None
    link_mbps: int | None
    duplex: str | None
    uplink: bool | None
    window_s: int
    usable_buckets: int
    gappy_buckets: int
    time_coverage: float
    p95_estimated: bool
    directions: tuple[DirectionStats, ...]
    shared_p95_pct: float | None
    near_capacity_days: int
    state: str
    reasons: tuple[str, ...]
    trend: Trend

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (pseudonyms only)."""
        return {
            "point_id": self.point_id,
            "scope": self.scope.value,
            "router_id": self.router_id,
            "device": self.device,
            "vlan_id": self.vlan_id,
            "link_mbps": self.link_mbps,
            "duplex": self.duplex,
            "uplink": self.uplink,
            "window_s": self.window_s,
            "usable_buckets": self.usable_buckets,
            "gappy_buckets": self.gappy_buckets,
            "time_coverage": self.time_coverage,
            "p95_estimated": self.p95_estimated,
            "directions": [d.to_dict() for d in self.directions],
            "shared_p95_pct": self.shared_p95_pct,
            "near_capacity_days": self.near_capacity_days,
            "state": self.state,
            "reasons": list(self.reasons),
            "trend": self.trend.to_dict(),
        }


# --- evaluation -------------------------------------------------------------------------------


def _pct(value: float | None, link: float | None) -> float | None:
    if value is None or link is None:
        return None
    return round(100.0 * value / link, 2)


def direction_stats(
    point: MeasurementPoint, usable: Sequence[Bucket], counter: str, link: float | None
) -> DirectionStats:
    """Mean, peak and P95 of ``counter`` over usable buckets."""
    mapping = direction_map(point)
    meaning = (
        "download"
        if mapping.download == counter
        else "upload"
        if mapping.upload == counter
        else None
    )
    rates = [r for r in (bucket_rate(b, counter) for b in usable) if r is not None]
    unavailable: dict[str, str] = {}
    avg = statistics.fmean(rates) if rates else None
    peaks = [
        p
        for p in ((b.rx_peak_bps if counter == "rx" else b.tx_peak_bps) for b in usable)
        if p is not None
    ]
    peak = max(peaks) if peaks else (max(rates) if rates else None)
    value_p95 = p95(rates)
    if avg is None:
        unavailable["avg_bps"] = REASON_INSUFFICIENT_DATA
        unavailable["peak_bps"] = REASON_INSUFFICIENT_DATA
    if value_p95 is None:
        unavailable["p95_bps"] = REASON_INSUFFICIENT_DATA
    if link is None:
        for name in ("avg_pct", "peak_pct", "p95_pct"):
            unavailable[name] = REASON_NO_LINK_SPEED
    elif value_p95 is None:
        unavailable["p95_pct"] = REASON_INSUFFICIENT_DATA
    return DirectionStats(
        counter=counter,
        meaning=meaning,
        avg_bps=None if avg is None else round(avg, 3),
        peak_bps=peak,
        p95_bps=value_p95,
        avg_pct=_pct(avg, link),
        peak_pct=_pct(peak, link),
        p95_pct=_pct(value_p95, link),
        unavailable=unavailable,
    )


def _load_series(
    usable: Sequence[Bucket], half_duplex: bool
) -> list[tuple[int, float]]:
    """(start, rate) per bucket that counts against the link.

    Full duplex: the higher direction; half duplex: RX + TX together.
    """
    out = []
    for bucket in usable:
        rx, tx = bucket_rate(bucket, "rx"), bucket_rate(bucket, "tx")
        known = [v for v in (rx, tx) if v is not None]
        if not known:
            continue
        out.append((bucket.start, sum(known) if half_duplex else max(known)))
    return out


def near_capacity_days(
    series: Sequence[tuple[int, float]], link: float, res: int, tz: tzinfo = UTC
) -> int:
    """Distinct days with >= NEAR_MIN_BUCKETS consecutive buckets >= 80 %."""
    from datetime import datetime

    limit = NEAR_CAPACITY_PCT / 100.0 * link
    days: set[str] = set()
    run = 0
    previous: int | None = None
    for start, rate in series:
        if previous is not None and start - previous != res:
            run = 0
        previous = start
        if rate >= limit:
            run += 1
            if run >= NEAR_MIN_BUCKETS:
                days.add(datetime.fromtimestamp(start, tz).date().isoformat())
        else:
            run = 0
    return len(days)


def trend(
    window: SeriesWindow | None, link: float | None, *, half_duplex: bool = False
) -> Trend:
    """Theil-Sen trend of the daily mean load (see the module docstring)."""
    if window is None or not window.buckets:
        return Trend(CAP_STATE_INSUFFICIENT, REASON_TREND_TOO_SHORT)
    per_day: dict[int, list[float]] = {}
    covered: dict[int, float] = {}
    for bucket in window.buckets:
        if bucket.gappy:
            continue
        day = bucket.start // DAY_S
        covered[day] = covered.get(day, 0.0) + bucket.covered_s
        for _start, rate in _load_series([bucket], half_duplex):
            per_day.setdefault(day, []).append(rate)
    days = sorted(d for d in per_day if covered[d] >= GAPPY_BELOW * DAY_S)
    if len(days) < TREND_MIN_DAYS:
        return Trend(
            CAP_STATE_INSUFFICIENT, REASON_TREND_TOO_SHORT, basis_days=len(days)
        )
    span = days[-1] - days[0] + 1
    if len(days) / span < TREND_MIN_COVERAGE:
        return Trend(
            CAP_STATE_INSUFFICIENT,
            REASON_TREND_LOW_COVERAGE,
            basis_days=len(days),
            span_days=span,
        )
    points = [(float(d - days[0]), statistics.fmean(per_day[d])) for d in days]
    fitted = theil_sen(points)
    if fitted is None:
        return Trend(
            CAP_STATE_INSUFFICIENT, REASON_TREND_TOO_SHORT, basis_days=len(days)
        )
    slope, intercept = fitted
    level = intercept + slope * points[-1][0]
    residuals = [abs(y - (intercept + slope * x)) for x, y in points]
    scale = statistics.median([y for _x, y in points]) or 1.0
    noise = min(1.0, statistics.median(residuals) / scale)
    confidence = round(
        min(TREND_MAX_CONFIDENCE, len(days) / 60.0 + 0.3) * (1.0 - noise), 2
    )
    to_near: float | None = None
    to_near_reason: str | None = None
    if link is None:
        to_near_reason = REASON_NO_LINK_SPEED
    elif slope <= 0:
        to_near_reason = REASON_NOT_RISING
    else:
        days_left = (NEAR_CAPACITY_PCT / 100.0 * link - level) / slope
        if days_left <= 0:
            to_near = 0.0
        elif days_left > TREND_HORIZON_DAYS:
            to_near_reason = REASON_BEYOND_HORIZON
        else:
            to_near = round(days_left, 1)
    return Trend(
        state="estimated",
        reason=None,
        basis_days=len(days),
        span_days=span,
        slope_bps_per_day=round(slope, 3),
        slope_pct_per_week=None if link is None else round(700.0 * slope / link, 3),
        level_bps=round(level, 3),
        days_to_near_capacity=to_near,
        days_to_near_capacity_reason=to_near_reason,
        confidence=max(0.0, confidence),
    )


def capacity_row(
    point: MeasurementPoint,
    window: SeriesWindow,
    *,
    link: LinkFacts | None,
    uplink: bool | None,
    trend_window: SeriesWindow | None,
    tz: tzinfo = UTC,
) -> CapacityRow:
    """Capacity view of one point over ``window``."""
    usable = [b for b in window.buckets if not b.gappy]
    gappy = sum(1 for b in window.buckets if b.gappy and b.covered_s > 0)
    speed = None
    duplex = None
    if point.scope is not Scope.VLAN and link is not None:
        speed = link_bps(link.link_mbps)
        duplex = link.duplex
    half = duplex == "half"
    reasons: set[str] = set(window.coverage_reasons)
    directions = tuple(
        direction_stats(point, usable, counter, None if half else speed)
        for counter in ("rx", "tx")
    )
    load = _load_series(usable, half)
    shared = None
    if half:
        reasons.add(REASON_HALF_DUPLEX_SHARED)
        shared = _pct(p95([r for _s, r in load]), speed)
    res = window.resolution_s
    estimated = res > P95_EXACT_RESOLUTION_S
    if estimated:
        reasons.add(REASON_P95_FROM_COARSE)
    near_days = 0
    if speed is None:
        reasons.add(REASON_NO_LINK_SPEED)
        state = CAP_STATE_NO_LINK
    elif len(load) < P95_MIN_POINTS:
        reasons.add(REASON_INSUFFICIENT_DATA)
        state = CAP_STATE_INSUFFICIENT
    else:
        load_p95 = p95([r for _s, r in load]) or 0.0
        pct95 = 100.0 * load_p95 / speed
        near_days = near_capacity_days(load, speed, res, tz)
        if pct95 >= HIGH_P95_PCT or near_days >= RECURRING_MIN_DAYS:
            state = (
                CAP_STATE_POSSIBLE_UPLINK_BOTTLENECK
                if uplink
                else CAP_STATE_POSSIBLE_BOTTLENECK
            )
        elif pct95 >= APPROACHING_PCT:
            state = CAP_STATE_APPROACHING
        else:
            state = CAP_STATE_HEADROOM
    if len(usable) < P95_MIN_POINTS and state == CAP_STATE_NO_LINK:
        reasons.add(REASON_INSUFFICIENT_DATA)
    return CapacityRow(
        point_id=point.point_id,
        scope=point.scope,
        router_id=point.router_id,
        device=point.device,
        vlan_id=point.vlan_id,
        link_mbps=None if speed is None or link is None else link.link_mbps,
        duplex=duplex,
        uplink=uplink,
        window_s=window.window_s,
        usable_buckets=len(usable),
        gappy_buckets=gappy,
        time_coverage=round(window.time_coverage, 4),
        p95_estimated=estimated,
        directions=directions,
        shared_p95_pct=shared,
        near_capacity_days=near_days,
        state=state,
        reasons=tuple(sorted(reasons)),
        trend=trend(trend_window, speed, half_duplex=half),
    )


def _is_uplink(
    point: MeasurementPoint, uplink_ports: Mapping[str, frozenset[str] | None] | None
) -> bool | None:
    if point.scope is Scope.WAN:
        return True
    if point.scope is not Scope.PORT:
        return False if point.scope is Scope.VLAN else None
    known = None if uplink_ports is None else uplink_ports.get(point.router_id or "")
    if known is None:
        return None
    return point.device in known


def capacity_rows(
    source: BucketSource,
    *,
    end: float,
    links: Mapping[str, LinkFacts] | None = None,
    router_id: str | None = None,
    uplink_ports: Mapping[str, frozenset[str] | None] | None = None,
    window_s: int = CAPACITY_WINDOW_S,
    trend_s: int = TREND_LOOKBACK_S,
    tz: tzinfo = UTC,
) -> list[CapacityRow]:
    """Capacity rows of every interface/port/WAN/VLAN point (bounded, sorted).

    ``links``: ``point_id`` -> link facts from the latest poll (missing:
    unknown speed). Sorted by router, scope and device; at most
    ``MAX_CAPACITY_ROWS``.
    """
    rows: list[CapacityRow] = []
    points: Iterable[MeasurementPoint] = sorted(
        (
            p
            for p in source.points()
            if p.scope in CAPACITY_SCOPES
            and (router_id is None or p.router_id == router_id)
        ),
        key=lambda p: (
            p.router_id or "",
            p.scope.value,
            p.device or "",
            p.vlan_id or 0,
        ),
    )
    for point in points:
        if len(rows) >= MAX_CAPACITY_ROWS:
            break
        window = source.window(point.point_id, window_s, end=end)
        if window is None:
            continue
        rows.append(
            capacity_row(
                point,
                window,
                link=(links or {}).get(point.point_id),
                uplink=_is_uplink(point, uplink_ports),
                trend_window=source.window(point.point_id, trend_s, end=end),
                tz=tz,
            )
        )
    return rows
