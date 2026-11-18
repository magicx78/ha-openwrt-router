"""Historical roll-up of RF time series (pure, no HA, no storage, no clock).

Raw points are rolled up into hourly and daily buckets of :class:`Agg`
(count, total, minimum, maximum, invalid). Unknown values (None, NaN,
infinity, bools, non-numbers) are counted in ``invalid`` and never enter the
mean. :func:`series_for_window` picks a resolution for 1h/24h/7d/30d (or any
window in seconds), returns empty buckets as None (never 0) and never
returns more than :data:`MAX_POINTS` points. Buckets are aligned to UTC
epoch multiples of their size. The caller passes ``now``; this module
stores nothing.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

_LOGGER = logging.getLogger(__name__)

RAW_RESOLUTION_S = 60
HOUR_S = 3600
DAY_S = 86400
# Hard limit of points per returned series (keeps payloads for the panel
# small). Startwert, nicht kalibriert.
MAX_POINTS = 500

WINDOWS: Mapping[str, int] = {
    "1h": HOUR_S,
    "24h": DAY_S,
    "7d": 7 * DAY_S,
    "30d": 30 * DAY_S,
}

SOURCE_RAW = "raw"
SOURCE_HOURLY = "hourly"
SOURCE_DAILY = "daily"


def _valid(value: Any) -> bool:
    """True for a finite real number (bools are not numbers here)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return False
    return math.isfinite(value)


def _pick(a: float | None, b: float | None, chooser: Any) -> float | None:
    """Combine two optional extremes with ``min`` or ``max``."""
    if a is None:
        return b
    if b is None:
        return a
    return chooser(a, b)


@dataclass(frozen=True)
class Agg:
    """Aggregate of numeric values; every operation returns a new Agg."""

    count: int = 0
    total: float = 0.0
    minimum: float | None = None
    maximum: float | None = None
    invalid: int = 0

    def add(self, value: Any) -> Agg:
        """Return a new Agg with ``value`` added (unknown goes to ``invalid``)."""
        if not _valid(value):
            return Agg(
                self.count, self.total, self.minimum, self.maximum, self.invalid + 1
            )
        number = float(value)
        return Agg(
            count=self.count + 1,
            total=self.total + number,
            minimum=_pick(self.minimum, number, min),
            maximum=_pick(self.maximum, number, max),
            invalid=self.invalid,
        )

    def merge(self, other: Agg) -> Agg:
        """Return the combination of two aggregates."""
        return Agg(
            count=self.count + other.count,
            total=self.total + other.total,
            minimum=_pick(self.minimum, other.minimum, min),
            maximum=_pick(self.maximum, other.maximum, max),
            invalid=self.invalid + other.invalid,
        )

    @property
    def mean(self) -> float | None:
        """Mean of the valid values; None without any."""
        if self.count == 0:
            return None
        return self.total / self.count


@dataclass(frozen=True)
class Retention:
    """How long each resolution is kept, in seconds."""

    raw_s: int = 2 * HOUR_S
    hourly_s: int = 8 * DAY_S
    daily_s: int = 31 * DAY_S


DEFAULT_RETENTION = Retention()


@dataclass(frozen=True)
class SeriesPoint:
    """One point of a series; ``mean`` None means no valid value (a gap)."""

    ts: int
    mean: float | None
    minimum: float | None
    maximum: float | None
    count: int
    invalid: int


@dataclass(frozen=True)
class Series:
    """A series for one window at one resolution."""

    window_s: int
    resolution_s: int
    source: str
    points: tuple[SeriesPoint, ...]

    @property
    def values(self) -> tuple[float | None, ...]:
        """Return the means, gaps as None."""
        return tuple(p.mean for p in self.points)

    @property
    def coverage(self) -> float:
        """Share of points with a valid value."""
        if not self.points:
            return 0.0
        return sum(1 for p in self.points if p.mean is not None) / len(self.points)

    def as_dict(self) -> dict[str, Any]:
        """Return the series as a plain dict."""
        return {
            "window_s": self.window_s,
            "resolution_s": self.resolution_s,
            "source": self.source,
            "coverage": self.coverage,
            "points": [
                {
                    "ts": p.ts,
                    "mean": p.mean,
                    "min": p.minimum,
                    "max": p.maximum,
                    "count": p.count,
                    "invalid": p.invalid,
                }
                for p in self.points
            ],
        }


def bucket_start(ts: float, size_s: int) -> int:
    """Return the start of the bucket of ``size_s`` seconds that holds ``ts``."""
    if size_s <= 0:
        raise ValueError(f"bucket size must be positive: {size_s}")
    return int(math.floor(ts / size_s) * size_s)


def roll_up(points: Iterable[tuple[float, Any]], size_s: int) -> dict[int, Agg]:
    """Roll ``(ts, value)`` points into buckets, sorted by bucket start."""
    buckets: dict[int, Agg] = {}
    for ts, value in points:
        key = bucket_start(ts, size_s)
        buckets[key] = buckets.get(key, Agg()).add(value)
    return dict(sorted(buckets.items()))


def merge_buckets(buckets: Mapping[int, Agg], size_s: int = DAY_S) -> dict[int, Agg]:
    """Merge buckets into coarser ones (default: hourly into daily)."""
    merged: dict[int, Agg] = {}
    for ts, agg in buckets.items():
        key = bucket_start(ts, size_s)
        merged[key] = merged.get(key, Agg()).merge(agg)
    return dict(sorted(merged.items()))


def prune(buckets: Mapping[int, Agg], now: float, keep_s: int) -> dict[int, Agg]:
    """Return the buckets that start at or after ``now - keep_s``."""
    cutoff = now - keep_s
    return {ts: agg for ts, agg in buckets.items() if ts >= cutoff}


def _window_seconds(window: str | int) -> int:
    """Translate a window name or a number of seconds."""
    if isinstance(window, str):
        if window not in WINDOWS:
            raise ValueError(f"unknown window: {window!r}")
        return WINDOWS[window]
    if isinstance(window, bool) or not isinstance(window, int) or window <= 0:
        raise ValueError(f"window must be a positive number of seconds: {window!r}")
    return window


def _resolution(window_s: int, retention: Retention) -> tuple[str, int]:
    """Pick the finest kept resolution that stays within MAX_POINTS."""
    if window_s <= retention.raw_s and _count(window_s, RAW_RESOLUTION_S) <= MAX_POINTS:
        return SOURCE_RAW, RAW_RESOLUTION_S
    if window_s <= retention.hourly_s and _count(window_s, HOUR_S) <= MAX_POINTS:
        return SOURCE_HOURLY, HOUR_S
    days = _count(window_s, DAY_S)
    return SOURCE_DAILY, max(1, math.ceil(days / MAX_POINTS)) * DAY_S


def _count(window_s: int, resolution_s: int) -> int:
    """Number of buckets for a window."""
    return math.ceil(window_s / resolution_s)


def _point(ts: int, agg: Agg | None) -> SeriesPoint:
    """Turn a bucket (or a missing one) into a series point."""
    if agg is None:
        return SeriesPoint(ts, None, None, None, 0, 0)
    return SeriesPoint(ts, agg.mean, agg.minimum, agg.maximum, agg.count, agg.invalid)


def series_for_window(
    raw: Iterable[tuple[float, Any]],
    hourly: Mapping[int, Agg],
    daily: Mapping[int, Agg],
    *,
    now: float,
    window: str | int,
    retention: Retention = DEFAULT_RETENTION,
) -> Series:
    """Return the series for a window ending at ``now``.

    The resolution is the finest one that is still kept for the whole window
    and stays within :data:`MAX_POINTS`; daily buckets are merged further when
    needed. Missing buckets are None, never 0.
    """
    window_s = _window_seconds(window)
    source, resolution = _resolution(window_s, retention)
    count = _count(window_s, resolution)
    end = bucket_start(now, resolution)
    start = end - (count - 1) * resolution
    if source == SOURCE_RAW:
        buckets = roll_up(((ts, v) for ts, v in raw if ts >= start), resolution)
    else:
        buckets = merge_buckets(
            hourly if source == SOURCE_HOURLY else daily, resolution
        )
    points = tuple(
        _point(ts, buckets.get(ts)) for ts in range(start, end + resolution, resolution)
    )
    return Series(window_s, resolution, source, points)
