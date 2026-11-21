"""History read interface of Traffic Analytics and its interim memory ring.

Plan 2026-11-20 §3.3, §5. The durable history store (buckets, compaction,
retention) is ``traffic_history.TrafficHistory`` (Phase I), which extends
the ring below. Top talkers, anomalies and capacity (Phases E-G)
read only through :class:`BucketSource`, the same pattern as
``traffic_clients.ClientWindowSource``. Until the store exists
:class:`MemoryBucketRing` fills the interface from accounted rates, bounded
and RAM only; Phase I replaces it (or feeds it) without touching E-G.

**Contract of** :meth:`BucketSource.window`:

* buckets are aligned to ``resolution_s`` and sorted by ``start``; the
  window is aligned too: it ends at ``end`` rounded up to the resolution and
  holds the buckets starting at or after ``aligned_end - window_s``;
* a bucket that saw no valid delta has ``covered_s == 0`` and ``None`` bytes
  (unknown, never 0); a bucket below half coverage is "lückenhaft"
  (``Bucket.gappy``) and counts in neither P95 nor baselines;
* a window the source cannot (fully) answer names why in ``reason``
  (``no_data_yet``, ``history_shorter_than_window``,
  ``window_beyond_retention``); the time coverage is ``covered_s /
  window_s``, never padded;
* ``area_coverage`` is the coverage of the measuring area (offload, station
  counters, Phase C), separate from the time coverage.

**Memory ring.** Infrastructure points (interface, port, VLAN, WAN) and
client points have separate quotas (32 per router / 160 in total, 200
clients); no point displaces one of the other kind. A client point idle for
more than 24 h may make room for a new one, an active one never. Station
rates are kept per client (``Scope.CLIENT``, ``client_ref``, no router):
the accounting already turned duplicate sightings into ``stale_source``, so
the valid deltas of all associations of one client add up to its traffic
without double counting (plan §4 "Roaming"). Every refused point, late rate
and rate without wall time is counted. Columns are ``array`` values, not
Python objects (plan §5 RAM estimate).
"""

from __future__ import annotations

import logging
import math
from array import array
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

from .traffic_const import (
    CLIENT_POINT_IDLE_S,
    FULL_TIME_COVERAGE,
    MAX_POINTS_CLIENT,
    MAX_POINTS_INFRA_PER_ROUTER,
    MAX_POINTS_INFRA_TOTAL,
    REASON_BEYOND_RETENTION,
    REASON_HISTORY_NOT_BUILT,
    REASON_HISTORY_SHORT,
    REASON_NO_DATA_YET,
    REASON_TIME_PARTIAL,
    SERIES_MAX_BUCKETS_CLIENT,
    SERIES_MAX_BUCKETS_INFRA,
    SERIES_RESOLUTION_S,
)
from .traffic_model import (
    RATE_QUALITIES,
    Bucket,
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
    quality_bit,
)

_LOGGER = logging.getLogger(__name__)

INFRA_SCOPES = frozenset({Scope.INTERFACE, Scope.PORT, Scope.VLAN, Scope.WAN})
_NONE_INT = -1


@dataclass(frozen=True, slots=True)
class SeriesWindow:
    """Buckets of one point over one window, with time and area coverage."""

    point: MeasurementPoint
    window_s: int
    end: float
    resolution_s: int
    buckets: tuple[Bucket, ...]
    depth_s: float
    area_coverage: Coverage
    area_reasons: tuple[str, ...] = ()
    reason: str | None = None

    @property
    def covered_s(self) -> float:
        """Covered seconds inside the window (capped at the window)."""
        return min(float(self.window_s), sum(b.covered_s for b in self.buckets))

    @property
    def time_coverage(self) -> float:
        """Covered share of the window (0..1)."""
        return self.covered_s / self.window_s if self.window_s > 0 else 0.0

    def total(self, counter: str) -> int | None:
        """Sum of ``rx_bytes``/``tx_bytes`` (None: no bucket knows it)."""
        values = [getattr(b, counter) for b in self.buckets]
        known = [v for v in values if v is not None]
        return sum(known) if known else None

    @property
    def coverage(self) -> Coverage:
        """Combined coverage: unavailable without time, full only if both are."""
        if self.covered_s <= 0:
            return Coverage.UNAVAILABLE
        if self.area_coverage is Coverage.UNKNOWN:
            return Coverage.UNKNOWN
        if (
            self.time_coverage >= FULL_TIME_COVERAGE
            and self.area_coverage is Coverage.FULL
        ):
            return Coverage.FULL
        return Coverage.PARTIAL

    @property
    def coverage_reasons(self) -> tuple[str, ...]:
        """Area reasons, the time gap and the window reason (sorted)."""
        reasons = set(self.area_reasons)
        if 0 < self.time_coverage < FULL_TIME_COVERAGE:
            reasons.add(REASON_TIME_PARTIAL)
        if self.reason is not None:
            reasons.add(self.reason)
        return tuple(sorted(reasons))


class BucketSource(Protocol):
    """What Phase I implements: buckets per point and window, with coverage.

    ``version`` changes whenever data changed (cache key for readers);
    ``dropped`` names every visible discard (quota, late, no wall time).
    """

    @property
    def version(self) -> int:
        """Changes whenever any bucket changed."""

    @property
    def resolution_s(self) -> int:
        """Finest bucket resolution the source has."""

    def points(self) -> Sequence[MeasurementPoint]:
        """Every point the source holds data for (sorted by ``point_id``)."""

    def window(
        self,
        point_id: str,
        window_s: int,
        *,
        end: float,
        resolution_s: int | None = None,
    ) -> SeriesWindow | None:
        """Buckets of ``point_id`` in the window ending at ``end`` (None: unknown).

        ``resolution_s`` asks for one tier (Phase I: 300, 3600 or 86400); a
        source without it answers with the resolution it has. Without it
        the source picks the resolution from the window.
        """

    def dropped(self) -> Mapping[str, int]:
        """Visible discard counters."""


class NoHistory:
    """The source while no history exists at all: no point, no window."""

    version = 0
    resolution_s = SERIES_RESOLUTION_S

    def points(self) -> Sequence[MeasurementPoint]:
        """Nothing."""
        return ()

    def window(
        self,
        point_id: str,
        window_s: int,
        *,
        end: float,
        resolution_s: int | None = None,
    ) -> SeriesWindow | None:
        """Always None (``history_not_built``)."""
        return None

    def dropped(self) -> Mapping[str, int]:
        """Nothing dropped."""
        return {}

    @property
    def reason(self) -> str:
        """Why there is nothing."""
        return REASON_HISTORY_NOT_BUILT


# --- memory ring ----------------------------------------------------------------------


class _Ring:
    """Contiguous aligned buckets of one point in columns (RAM only)."""

    __slots__ = (
        "area_coverage",
        "area_reason",
        "cov",
        "first_start",
        "last_wall",
        "mask",
        "max_buckets",
        "point",
        "rx",
        "rxp",
        "samples",
        "tx",
        "txp",
    )

    def __init__(self, point: MeasurementPoint, max_buckets: int) -> None:
        self.point = point
        self.max_buckets = max_buckets
        self.first_start: int | None = None
        self.last_wall: float = -math.inf
        self.area_coverage = Coverage.UNKNOWN
        self.area_reason: str | None = None
        self.rx = array("q")
        self.tx = array("q")
        self.rxp = array("d")
        self.txp = array("d")
        self.cov = array("d")
        self.samples = array("l")
        self.mask = array("q")

    def __len__(self) -> int:
        return len(self.cov)

    def _append_empty(self, count: int) -> None:
        self.rx.extend([_NONE_INT] * count)
        self.tx.extend([_NONE_INT] * count)
        self.rxp.extend([math.nan] * count)
        self.txp.extend([math.nan] * count)
        self.cov.extend([0.0] * count)
        self.samples.extend([0] * count)
        self.mask.extend([0] * count)

    def _trim_front(self, count: int, res: int) -> None:
        for column in (
            self.rx,
            self.tx,
            self.rxp,
            self.txp,
            self.cov,
            self.samples,
            self.mask,
        ):
            del column[:count]
        assert self.first_start is not None
        self.first_start += count * res

    def index(self, start: int, res: int) -> int | None:
        """Index of the bucket at ``start``, grown as needed (None: too old)."""
        if self.first_start is None or (start - self.first_start) // res >= (
            len(self) + self.max_buckets
        ):
            # first bucket or a gap longer than the ring: start over
            self.first_start = start
            for column in (
                self.rx,
                self.tx,
                self.rxp,
                self.txp,
                self.cov,
                self.samples,
                self.mask,
            ):
                del column[:]
            self._append_empty(1)
            return 0
        idx = (start - self.first_start) // res
        if idx < 0:
            return None
        if idx >= len(self):
            self._append_empty(idx - len(self) + 1)
            over = len(self) - self.max_buckets
            if over > 0:
                self._trim_front(over, res)
                idx -= over
        return idx

    def bucket(self, i: int, res: int) -> Bucket:
        assert self.first_start is not None
        rx, tx = self.rx[i], self.tx[i]
        rxp, txp = self.rxp[i], self.txp[i]
        return Bucket(
            start=self.first_start + i * res,
            resolution_s=res,
            rx_bytes=None if rx == _NONE_INT else rx,
            tx_bytes=None if tx == _NONE_INT else tx,
            rx_peak_bps=None if math.isnan(rxp) else rxp,
            tx_peak_bps=None if math.isnan(txp) else txp,
            covered_s=min(float(res), self.cov[i]),
            samples=self.samples[i],
            quality_mask=self.mask[i],
        )


def _add(column: array[int], i: int, value: int | None) -> None:
    if value is None:
        return
    old = column[i]
    column[i] = value if old == _NONE_INT else old + value


def _peak(column: array[float], i: int, value: float | None) -> None:
    if value is None:
        return
    old = column[i]
    if math.isnan(old) or value > old:
        column[i] = value


def _split(total: int | None, parts: list[float]) -> list[int | None]:
    """Split ``total`` bytes by the overlap shares; the last part takes the rest."""
    if total is None:
        return [None] * len(parts)
    whole = sum(parts)
    out: list[int | None] = []
    given = 0
    for n, part in enumerate(parts):
        if n == len(parts) - 1:
            out.append(total - given)
        else:
            share = int(total * part // whole) if whole > 0 else 0
            out.append(share)
            given += share
    return out


class MemoryBucketRing:
    """Bounded in-memory :class:`BucketSource` fed with accounted rates."""

    def __init__(
        self,
        *,
        resolution_s: int = SERIES_RESOLUTION_S,
        max_buckets_infra: int = SERIES_MAX_BUCKETS_INFRA,
        max_buckets_client: int = SERIES_MAX_BUCKETS_CLIENT,
        max_infra_per_router: int = MAX_POINTS_INFRA_PER_ROUTER,
        max_infra_total: int = MAX_POINTS_INFRA_TOTAL,
        max_clients: int = MAX_POINTS_CLIENT,
        client_idle_s: float = CLIENT_POINT_IDLE_S,
    ) -> None:
        """Empty ring with its quotas."""
        if resolution_s <= 0:
            raise ValueError("resolution_s must be positive")
        self._res = resolution_s
        self._max_buckets = {True: max_buckets_infra, False: max_buckets_client}
        self._max_infra_router = max_infra_per_router
        self._max_infra = max_infra_total
        self._max_clients = max_clients
        self._idle_s = client_idle_s
        self._rings: dict[str, _Ring] = {}
        self._infra_per_router: dict[str | None, int] = {}
        self._clients = 0
        self._version = 0
        self.counters: dict[str, int] = {
            "dropped_points_infra": 0,
            "dropped_points_client": 0,
            "replaced_client_points": 0,
            "late_rates": 0,
            "rates_without_wall": 0,
            "rates_not_kept": 0,
        }

    # -- interface ------------------------------------------------------------------

    @property
    def version(self) -> int:
        """Changes on every accepted rate."""
        return self._version

    @property
    def resolution_s(self) -> int:
        """Bucket resolution."""
        return self._res

    def points(self) -> Sequence[MeasurementPoint]:
        """Every held point (sorted by ``point_id``)."""
        return tuple(self._rings[p].point for p in sorted(self._rings))

    def dropped(self) -> Mapping[str, int]:
        """Discard counters (quota, late, no wall time)."""
        return dict(self.counters)

    def __len__(self) -> int:
        """Held points."""
        return len(self._rings)

    def window(
        self,
        point_id: str,
        window_s: int,
        *,
        end: float,
        resolution_s: int | None = None,
    ) -> SeriesWindow | None:
        """See :meth:`BucketSource.window` (None for an unknown point).

        The ring has one resolution; ``resolution_s`` is accepted and ignored.
        """
        ring = self._rings.get(point_id)
        if ring is None or window_s <= 0:
            return None
        res = self._res
        aligned_end = math.ceil(end / res) * res
        first_wanted = aligned_end - window_s
        buckets: list[Bucket] = []
        depth = 0.0
        if ring.first_start is not None and len(ring):
            lo = max(0, math.ceil((first_wanted - ring.first_start) / res))
            hi = min(len(ring), (aligned_end - ring.first_start) // res)
            buckets = [ring.bucket(i, res) for i in range(lo, hi)]
            depth = max(0.0, float(aligned_end - ring.first_start))
        reason: str | None = None
        if not any(b.covered_s > 0 for b in buckets):
            reason = REASON_NO_DATA_YET
        elif depth < window_s:
            reason = (
                REASON_BEYOND_RETENTION
                if len(ring) >= ring.max_buckets
                else REASON_HISTORY_SHORT
            )
        return SeriesWindow(
            point=ring.point,
            window_s=window_s,
            end=float(aligned_end),
            resolution_s=res,
            buckets=tuple(buckets),
            depth_s=depth,
            area_coverage=ring.area_coverage,
            area_reasons=() if ring.area_reason is None else (ring.area_reason,),
            reason=reason,
        )

    # -- feeding ----------------------------------------------------------------------

    def add_rates(self, rates: Iterable[Rate]) -> None:
        """Take accounted rates (see :meth:`add_rate`)."""
        for rate in rates:
            self.add_rate(rate)

    def add_rate(self, rate: Rate) -> bool:
        """Take one accounted rate; False when it was not kept (counted)."""
        point = self._target(rate.point)
        if point is None or rate.quality is Quality.STALE_SOURCE:
            return False  # flow / duplicate sighting: nothing to keep
        wall = rate.wall_s
        if wall is None or not math.isfinite(wall):
            self.counters["rates_without_wall"] += 1
            return False
        ring = self._ring(point, wall)
        if ring is None:
            return False
        res = self._res
        valid = rate.quality in RATE_QUALITIES and (rate.interval_s or 0) > 0
        if not valid:
            idx = ring.index(int(wall // res) * res, res)
            if idx is None:
                self.counters["late_rates"] += 1
                return False
            ring.mask[idx] |= quality_bit(rate.quality)
            ring.last_wall = max(ring.last_wall, wall)
            self._version += 1
            return True
        interval = float(rate.interval_s or 0.0)
        t0, t1 = wall - interval, wall
        starts: list[int] = []
        parts: list[float] = []
        start = int(t0 // res) * res
        while start < t1:
            overlap = min(t1, start + res) - max(t0, start)
            if overlap > 0:
                starts.append(start)
                parts.append(overlap)
            start += res
        rx = _split(rate.rx_delta, parts)
        tx = _split(rate.tx_delta, parts)
        kept = False
        for n, bucket_start in enumerate(starts):
            idx = ring.index(bucket_start, res)
            if idx is None:
                self.counters["late_rates"] += 1
                continue
            kept = True
            _add(ring.rx, idx, rx[n])
            _add(ring.tx, idx, tx[n])
            _peak(ring.rxp, idx, rate.rx_bps)
            _peak(ring.txp, idx, rate.tx_bps)
            ring.cov[idx] = min(float(res), ring.cov[idx] + parts[n])
            ring.samples[idx] += 1
            ring.mask[idx] |= quality_bit(rate.quality)
        if not kept:
            return False
        ring.last_wall = max(ring.last_wall, wall)
        ring.area_coverage = rate.coverage
        reason = rate.coverage_reason
        ring.area_reason = reason.value if isinstance(reason, CoverageReason) else None
        self._version += 1
        return True

    def _target(self, point: MeasurementPoint) -> MeasurementPoint | None:
        if point.scope in INFRA_SCOPES or point.scope is Scope.CLIENT:
            return point
        if point.scope is Scope.STATION and point.client_ref is not None:
            return MeasurementPoint(None, Scope.CLIENT, client_ref=point.client_ref)
        return None

    def _ring(self, point: MeasurementPoint, wall: float) -> _Ring | None:
        ring = self._rings.get(point.point_id)
        if ring is not None:
            return ring
        infra = point.scope in INFRA_SCOPES
        if infra:
            rid = point.router_id
            if (
                self._infra_per_router.get(rid, 0) >= self._max_infra_router
                or self._infra_total() >= self._max_infra
            ):
                self.counters["dropped_points_infra"] += 1
                self.counters["rates_not_kept"] += 1
                return None
            self._infra_per_router[rid] = self._infra_per_router.get(rid, 0) + 1
        else:
            if self._clients >= self._max_clients and not self._free_client(wall):
                self.counters["dropped_points_client"] += 1
                self.counters["rates_not_kept"] += 1
                return None
            self._clients += 1
        ring = self._rings[point.point_id] = _Ring(point, self._max_buckets[infra])
        return ring

    def _infra_total(self) -> int:
        return sum(self._infra_per_router.values())

    def _free_client(self, wall: float) -> bool:
        idle = [
            (r.last_wall, pid)
            for pid, r in self._rings.items()
            if r.point.scope is Scope.CLIENT and wall - r.last_wall > self._idle_s
        ]
        if not idle:
            return False
        self._remove(min(idle)[1])
        self.counters["replaced_client_points"] += 1
        return True

    def _remove(self, point_id: str) -> None:
        ring = self._rings.pop(point_id, None)
        if ring is None:
            return
        if ring.point.scope in INFRA_SCOPES:
            rid = ring.point.router_id
            left = self._infra_per_router.get(rid, 1) - 1
            if left > 0:
                self._infra_per_router[rid] = left
            else:
                self._infra_per_router.pop(rid, None)
        else:
            self._clients -= 1
        self._version += 1

    # -- maintenance ----------------------------------------------------------------------

    def drop_router(self, router_id: str | None) -> None:
        """Forget the infrastructure points of an unloaded router."""
        for pid in [
            p
            for p, r in self._rings.items()
            if r.point.scope in INFRA_SCOPES and r.point.router_id == router_id
        ]:
            self._remove(pid)

    def clear(self) -> None:
        """Forget every point (module switched off); counters stay."""
        self._rings.clear()
        self._infra_per_router.clear()
        self._clients = 0
        self._version += 1

    def summary(self) -> dict[str, Any]:
        """Counts only (no point ids, no client ids)."""
        return {
            "points_infra": self._infra_total(),
            "points_client": self._clients,
            "buckets": sum(len(r) for r in self._rings.values()),
            "resolution_s": self._res,
            **self.counters,
        }
