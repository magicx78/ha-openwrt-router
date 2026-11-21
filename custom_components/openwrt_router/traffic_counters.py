"""Counter deltas of Traffic Analytics (plan 2026-11-20, §3.4).

Pure functions and one bounded book of baselines; no Home Assistant import,
no I/O, no clock reads (every time comes in as an argument).

:func:`delta` applies the rules of §3.4 in their order; the first rule that
applies decides:

1. valid counter (``int >= 0``, no ``bool``), else ``source_missing``;
2. time: ``dt = mono - prev.mono`` (poll time, E4); ``dt <= 0`` or no
   usable time -> ``time_not_advancing``; ``dt < 5 s`` -> skipped, the old
   baseline stays;
3. gap: ``dt > 900 s`` or a stale poll -> ``gap``, new baseline, no rate;
4. router restart (uptime known and smaller than before, or smaller than
   ``dt``) -> ``router_restart``; uptime 0 means unknown, not restart;
5. a decrease without restart: ``wrap_32`` only for station sources whose
   previous value fits 32 bit and only if plausible (rate limit of rule 6
   and at most half the 32-bit range), else ``counter_reset``;
6. plausibility per direction (half duplex: RX + TX together), above it
   ``implausible``;
7. another device, router, radio or source is another point / a new
   baseline (no comparison);
8. after an HA restart (baseline restored, no monotonic time) a delta is
   only valid if ``|delta uptime - delta wall| <= 10 s`` and
   ``delta wall <= 900 s``, else ``gap``.

Rates are never negative and never invented: without a valid delta the
rate is ``None``.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .traffic_const import (
    BASELINE_TTL_S,
    BYTES_PER_S_PER_MBPS,
    CLIENT_POINT_IDLE_S,
    COUNTER_32_RANGE,
    DEFAULT_LIMIT_STATION_BPS,
    DEFAULT_LIMIT_WIRED_BPS,
    MAX_INTERVAL_S,
    MAX_POINTS_CLIENT,
    MAX_POINTS_INFRA_PER_ROUTER,
    MAX_POINTS_INFRA_TOTAL,
    MIN_INTERVAL_S,
    PLAUSIBILITY_MARGIN,
    UPTIME_MISMATCH_S,
    WRAP_32_MAX_DELTA,
)
from .traffic_model import (
    COUNTER_FIELDS,
    RATE_QUALITIES,
    WRAP_32_SOURCES,
    Coverage,
    CoverageReason,
    MeasurementPoint,
    Quality,
    Rate,
    Sample,
    Scope,
    Source,
    point_from_dict,
    valid_point_id,
)

_LOGGER = logging.getLogger(__name__)

CLIENT_SCOPES = frozenset({Scope.STATION, Scope.CLIENT})


# --- small validators -------------------------------------------------------------


def as_counter(value: Any) -> int | None:
    """``value`` if it is a counter (``int >= 0``, not ``bool``), else None (rule 1)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def known_uptime(value: Any) -> int | None:
    """Router uptime in s if known: ``int > 0``; 0, negative, bool -> None."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def finite_time(value: Any) -> float | None:
    """A usable clock value (finite number, not bool), else None."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def router_restarted(prev_uptime: Any, cur_uptime: Any, dt: float) -> bool:
    """Rule 4: the router restarted between two reads ``dt`` seconds apart.

    True if the current uptime is known and smaller than the previous one
    (also known), or smaller than ``dt``. Unknown uptime (0/None) is never a
    restart.
    """
    cur = known_uptime(cur_uptime)
    if cur is None:
        return False
    prev = known_uptime(prev_uptime)
    if prev is not None and cur < prev:
        return True
    return cur < dt


def plausibility_limit(sample: Sample) -> tuple[float, bool]:
    """Rule 6: ``(bytes per second, combined)`` for ``sample``.

    ``link_mbps x 125 000 x 1.05`` per direction; half duplex: one limit for
    RX + TX together (``combined``). Without a link speed the start values
    (not calibrated): station 2.4 Gbit/s, everything else 10 Gbit/s.
    """
    link = sample.link_mbps
    combined = sample.duplex == "half"
    if isinstance(link, int) and not isinstance(link, bool) and link > 0:
        return link * BYTES_PER_S_PER_MBPS * PLAUSIBILITY_MARGIN, combined
    if sample.point.scope in CLIENT_SCOPES:
        return float(DEFAULT_LIMIT_STATION_BPS), combined
    return float(DEFAULT_LIMIT_WIRED_BPS), combined


def default_coverage(point: MeasurementPoint) -> tuple[Coverage, CoverageReason | None]:
    """Coverage of a valid rate before accounting (Phase C refines it).

    Station counters are always partial (matrix §5); every other scope is
    ``unknown`` until accounting knows offload and overlap.
    """
    if point.scope in CLIENT_SCOPES:
        return Coverage.PARTIAL, CoverageReason.STATION_COUNTERS_ONLY
    return Coverage.UNKNOWN, None


# --- baseline -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Baseline:
    """Last counter state of one point.

    ``mono_s`` is None after a restore from a store (the monotonic clock of
    the previous HA run means nothing now, rule 8); ``restored`` marks it.
    ``counters`` follows ``COUNTER_FIELDS``.
    """

    point_id: str
    source: Source
    mono_s: float | None
    wall_s: float | None
    router_uptime_s: int | None
    counters: tuple[int | None, ...]
    restored: bool = False

    @property
    def rx_bytes(self) -> int | None:
        """Previous RX bytes."""
        return self.counters[0]

    @property
    def tx_bytes(self) -> int | None:
        """Previous TX bytes."""
        return self.counters[1]

    def to_dict(self) -> dict[str, Any]:
        """Stored form (rule 8: wall time and uptime, no monotonic time)."""
        return {
            "point_id": self.point_id,
            "source": self.source.value,
            "wall_s": self.wall_s,
            "router_uptime_s": self.router_uptime_s,
            "counters": list(self.counters),
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Baseline | None:
        """Restored baseline (``restored=True``), None if unusable."""
        if not isinstance(raw, Mapping):
            return None
        point_id = raw.get("point_id")
        counters = raw.get("counters")
        try:
            source = Source(raw.get("source"))
        except ValueError:
            return None
        if not valid_point_id(point_id) or not isinstance(counters, list):
            return None
        if len(counters) != len(COUNTER_FIELDS):
            return None
        return cls(
            point_id=point_id,
            source=source,
            mono_s=None,
            wall_s=finite_time(raw.get("wall_s")),
            router_uptime_s=known_uptime(raw.get("router_uptime_s")),
            counters=tuple(as_counter(v) for v in counters),
            restored=True,
        )


def counters_of(sample: Sample) -> tuple[int | None, ...]:
    """Valid counters of ``sample`` in ``COUNTER_FIELDS`` order (rule 1)."""
    return tuple(as_counter(getattr(sample, name)) for name in COUNTER_FIELDS)


def baseline_of(sample: Sample, counters: tuple[int | None, ...]) -> Baseline:
    """New baseline from ``sample`` (its mono time must be valid)."""
    return Baseline(
        point_id=sample.point.point_id,
        source=sample.source,
        mono_s=finite_time(sample.mono_s),
        wall_s=finite_time(sample.wall_s),
        router_uptime_s=known_uptime(sample.router_uptime_s),
        counters=counters,
    )


@dataclass(frozen=True, slots=True)
class DeltaResult:
    """Outcome of :func:`delta`.

    ``rate`` is None only when the sample was skipped (``dt < 5 s``).
    ``baseline`` is what the point keeps afterwards (the old one when it
    stays, None when the point has none).
    """

    rate: Rate | None
    baseline: Baseline | None
    skipped: bool = False


def restored_interval(prev: Baseline, sample: Sample) -> float | None:
    """Rule 8: the interval over an HA restart, None if it is not valid.

    Needs both wall times and both uptimes; valid only if
    ``0 < delta wall <= 900 s`` and ``|delta uptime - delta wall| <= 10 s``.
    """
    prev_wall, cur_wall = prev.wall_s, finite_time(sample.wall_s)
    prev_up, cur_up = (
        known_uptime(prev.router_uptime_s),
        known_uptime(sample.router_uptime_s),
    )
    if prev_wall is None or cur_wall is None or prev_up is None or cur_up is None:
        return None
    d_wall = cur_wall - prev_wall
    if not 0 < d_wall <= MAX_INTERVAL_S:
        return None
    if abs((cur_up - prev_up) - d_wall) > UPTIME_MISMATCH_S:
        return None
    return d_wall


def _plain_delta(prev: int | None, cur: int | None, wrap: bool) -> int | None:
    """Delta of a secondary counter (packets, errors, drops); never negative."""
    if prev is None or cur is None:
        return None
    if cur >= prev:
        return cur - prev
    if wrap and prev < COUNTER_32_RANGE and cur < COUNTER_32_RANGE:
        return cur + COUNTER_32_RANGE - prev
    return None


def delta(
    prev: Baseline | None,
    sample: Sample,
    *,
    router_restart: bool = False,
    stale: bool = False,
    coverage: Coverage | None = None,
    coverage_reason: CoverageReason | None = None,
) -> DeltaResult:
    """Apply the rules of §3.4 to ``sample`` against ``prev``.

    ``router_restart``: the caller saw the restart router-wide (rule 4 holds
    for every point of the router). ``stale``: the poll used cached data
    (``vlans_stale``), counted as a gap. ``coverage``/``coverage_reason``
    of a valid rate default to :func:`default_coverage`.
    """
    point = sample.point
    source = sample.source
    times = {
        "mono_s": finite_time(sample.mono_s),
        "wall_s": finite_time(sample.wall_s),
    }

    def no_rate(quality: Quality, keep: Baseline | None) -> DeltaResult:
        return DeltaResult(
            Rate(point, quality, coverage=Coverage.UNAVAILABLE, source=source, **times),
            keep,
        )

    counters = counters_of(sample)
    # 1. valid counter
    if counters[0] is None and counters[1] is None:
        return no_rate(Quality.SOURCE_MISSING, prev)
    # 2. time (part 1): a sample without a usable time changes nothing
    cur_mono = finite_time(sample.mono_s)
    if cur_mono is None:
        return no_rate(Quality.TIME_NOT_ADVANCING, prev)
    fresh = baseline_of(sample, counters)
    # 7. another point or another source: new baseline, no comparison
    if prev is None or prev.point_id != point.point_id or prev.source != source:
        return no_rate(Quality.FIRST_SAMPLE, fresh)
    # 2. time (part 2) / 8. over an HA restart
    if prev.restored:
        dt = restored_interval(prev, sample)
        if dt is None:
            return no_rate(Quality.GAP, fresh)
    else:
        prev_mono = prev.mono_s
        if prev_mono is None:
            return no_rate(Quality.GAP, fresh)
        dt = cur_mono - prev_mono
        if dt <= 0:
            return no_rate(Quality.TIME_NOT_ADVANCING, prev)
    if dt < MIN_INTERVAL_S:
        return DeltaResult(None, prev, skipped=True)
    # 3. gap
    if dt > MAX_INTERVAL_S or stale:
        return no_rate(Quality.GAP, fresh)
    # 4. router restart
    if router_restart or router_restarted(
        prev.router_uptime_s, sample.router_uptime_s, dt
    ):
        return no_rate(Quality.ROUTER_RESTART, fresh)
    # 5. decrease without restart
    limit, combined = plausibility_limit(sample)
    wrap_ok = source in WRAP_32_SOURCES
    quality = Quality.OK
    byte_deltas: list[int | None] = []
    for prev_v, cur_v in (
        (prev.counters[0], counters[0]),
        (prev.counters[1], counters[1]),
    ):
        if prev_v is None or cur_v is None:
            byte_deltas.append(None)
            continue
        if cur_v >= prev_v:
            byte_deltas.append(cur_v - prev_v)
            continue
        if wrap_ok and prev_v < COUNTER_32_RANGE and cur_v < COUNTER_32_RANGE:
            candidate = cur_v + COUNTER_32_RANGE - prev_v
            if candidate <= WRAP_32_MAX_DELTA and candidate / dt <= limit:
                byte_deltas.append(candidate)
                quality = Quality.WRAP_32
                continue
        return no_rate(Quality.COUNTER_RESET, fresh)
    rx_d, tx_d = byte_deltas
    if rx_d is None and tx_d is None:
        # the previous read knew neither direction now known: start here
        return no_rate(Quality.FIRST_SAMPLE, fresh)
    # 6. plausibility
    if combined:
        if ((rx_d or 0) + (tx_d or 0)) / dt > limit:
            return no_rate(Quality.IMPLAUSIBLE, fresh)
    elif any(d is not None and d / dt > limit for d in byte_deltas):
        return no_rate(Quality.IMPLAUSIBLE, fresh)
    wrapped = quality is Quality.WRAP_32
    secondary = [
        _plain_delta(prev.counters[i], counters[i], wrapped)
        for i in range(2, len(COUNTER_FIELDS))
    ]
    if coverage is None:
        coverage, coverage_reason = default_coverage(point)
    rate = Rate(
        point,
        quality,
        interval_s=dt,
        rx_bps=None if rx_d is None else rx_d * 8 / dt,
        tx_bps=None if tx_d is None else tx_d * 8 / dt,
        rx_delta=rx_d,
        tx_delta=tx_d,
        rx_packets_delta=secondary[0],
        tx_packets_delta=secondary[1],
        rx_errors_delta=secondary[2],
        tx_errors_delta=secondary[3],
        rx_dropped_delta=secondary[4],
        tx_dropped_delta=secondary[5],
        coverage=coverage,
        coverage_reason=coverage_reason,
        source=source,
        **times,
    )
    return DeltaResult(rate, fresh)


# --- bounded baseline book ----------------------------------------------------------


@dataclass(slots=True)
class _Entry:
    baseline: Baseline
    router_id: str | None
    seen_mono: float
    point: MeasurementPoint | None = None


class BaselineBook:
    """Baselines of all points with separate quotas (plan §5).

    Infrastructure points (interface, port, VLAN, WAN, flow): at most
    ``infra_per_router`` per router and ``infra_total`` overall; a new point
    over the quota is refused (``dropped_points_infra``). Client points
    (station, client): at most ``client_max``; a point idle for more than
    24 h may be replaced by a new one, an active one never; otherwise the
    new point is refused (``dropped_points_client``). No quota displaces
    another.
    """

    def __init__(
        self,
        *,
        infra_per_router: int = MAX_POINTS_INFRA_PER_ROUTER,
        infra_total: int = MAX_POINTS_INFRA_TOTAL,
        client_max: int = MAX_POINTS_CLIENT,
        client_idle_s: float = CLIENT_POINT_IDLE_S,
    ) -> None:
        """Empty book."""
        self._infra_per_router = infra_per_router
        self._infra_total = infra_total
        self._client_max = client_max
        self._client_idle_s = client_idle_s
        self._infra: dict[str, _Entry] = {}
        self._client: dict[str, _Entry] = {}
        self._per_router: dict[str | None, int] = {}
        self.counters: dict[str, int] = {
            "dropped_points_infra": 0,
            "dropped_points_client": 0,
            "replaced_points_client": 0,
            "pruned_points": 0,
        }

    def __len__(self) -> int:
        """Number of points with a baseline."""
        return len(self._infra) + len(self._client)

    @property
    def infra_count(self) -> int:
        """Infrastructure points held."""
        return len(self._infra)

    @property
    def client_count(self) -> int:
        """Client points held."""
        return len(self._client)

    def get(self, point_id: str) -> Baseline | None:
        """Baseline of ``point_id`` or None."""
        entry = self._infra.get(point_id) or self._client.get(point_id)
        return None if entry is None else entry.baseline

    def has(self, point_id: str) -> bool:
        """True if the point holds a baseline (no quota check needed)."""
        return point_id in self._infra or point_id in self._client

    def admit(self, point: MeasurementPoint, now_mono: float) -> bool:
        """True if ``point`` may hold a baseline (frees an idle client slot).

        Counts a refusal. Known points are always admitted.
        """
        pid = point.point_id
        if self.has(pid):
            return True
        if point.scope in CLIENT_SCOPES:
            if len(self._client) < self._client_max:
                return True
            idle_id = self._oldest_idle_client(now_mono)
            if idle_id is None:
                self.counters["dropped_points_client"] += 1
                return False
            del self._client[idle_id]
            self.counters["replaced_points_client"] += 1
            return True
        if (
            len(self._infra) >= self._infra_total
            or self._per_router.get(point.router_id, 0) >= self._infra_per_router
        ):
            self.counters["dropped_points_infra"] += 1
            return False
        return True

    def _oldest_idle_client(self, now_mono: float) -> str | None:
        oldest: tuple[float, str] | None = None
        for pid, entry in self._client.items():
            if now_mono - entry.seen_mono <= self._client_idle_s:
                continue
            if oldest is None or entry.seen_mono < oldest[0]:
                oldest = (entry.seen_mono, pid)
        return None if oldest is None else oldest[1]

    def put(
        self, point: MeasurementPoint, baseline: Baseline | None, now_mono: float
    ) -> None:
        """Store (or with None remove) the baseline of an admitted point."""
        pid = point.point_id
        client = point.scope in CLIENT_SCOPES
        table = self._client if client else self._infra
        if baseline is None:
            self._remove(pid)
            return
        entry = table.get(pid)
        if entry is None:
            table[pid] = _Entry(baseline, point.router_id, now_mono, point)
            if not client:
                self._per_router[point.router_id] = (
                    self._per_router.get(point.router_id, 0) + 1
                )
            return
        entry.baseline = baseline
        entry.seen_mono = now_mono
        entry.point = point

    def _remove(self, pid: str) -> None:
        if self._client.pop(pid, None) is not None:
            return
        entry = self._infra.pop(pid, None)
        if entry is None:
            return
        left = self._per_router.get(entry.router_id, 0) - 1
        if left > 0:
            self._per_router[entry.router_id] = left
        else:
            self._per_router.pop(entry.router_id, None)

    def prune(self, now_mono: float, ttl_s: float = BASELINE_TTL_S) -> int:
        """Drop baselines not seen for ``ttl_s``; returns how many."""
        old = [
            pid
            for table in (self._infra, self._client)
            for pid, entry in table.items()
            if now_mono - entry.seen_mono > ttl_s
        ]
        for pid in old:
            self._remove(pid)
        self.counters["pruned_points"] += len(old)
        return len(old)

    def drop_router(self, router_id: str | None) -> int:
        """Forget every point of ``router_id`` (entry unloaded)."""
        gone = [
            pid
            for table in (self._infra, self._client)
            for pid, entry in table.items()
            if entry.router_id == router_id
        ]
        for pid in gone:
            self._remove(pid)
        return len(gone)

    def export(self) -> list[dict[str, Any]]:
        """Stored form of every baseline with its point (rule 8, plan §5)."""
        out: list[dict[str, Any]] = []
        for table in (self._infra, self._client):
            for pid in sorted(table):
                entry = table[pid]
                if entry.point is None:
                    continue
                out.append(
                    {
                        "point": entry.point.to_dict(),
                        "baseline": entry.baseline.to_dict(),
                    }
                )
        return out

    def restore(self, items: Any, *, now_mono: float) -> int:
        """Take stored baselines after an HA restart; returns how many.

        Each comes back with ``restored=True`` (no monotonic time), so the
        first delta needs rule 8 (uptime and wall time agree). Unusable
        items and points the quotas refuse are skipped; never raises.
        """
        if not isinstance(items, list):
            return 0
        restored = 0
        for item in items:
            if not isinstance(item, Mapping):
                continue
            point = point_from_dict(item.get("point"))
            baseline = Baseline.from_dict(item.get("baseline"))
            if point is None or baseline is None or baseline.point_id != point.point_id:
                continue
            if self.has(point.point_id) or not self.admit(point, now_mono):
                continue
            self.put(point, baseline, now_mono)
            restored += 1
        return restored

    def clear(self) -> None:
        """Forget everything (module switched off); the counters stay."""
        self._infra.clear()
        self._client.clear()
        self._per_router.clear()


def process_samples(
    book: BaselineBook,
    samples: Iterable[Sample],
    *,
    now_mono: float,
    router_restart: bool = False,
    stale: bool = False,
) -> list[Rate]:
    """Run :func:`delta` for every sample and keep the baselines in ``book``.

    O(samples). A point the quotas refuse yields no rate (it is counted in
    the book). Skipped samples (``dt < 5 s``) yield nothing.
    """
    rates: list[Rate] = []
    for sample in samples:
        point = sample.point
        if not book.admit(point, now_mono):
            continue
        result = delta(
            book.get(point.point_id),
            sample,
            router_restart=router_restart,
            stale=stale,
        )
        if result.baseline is not None or book.has(point.point_id):
            book.put(point, result.baseline, now_mono)
        if result.rate is not None:
            rates.append(result.rate)
    return rates


def rate_is_valid(rate: Rate) -> bool:
    """True if ``rate`` carries values (quality ok or accepted wrap)."""
    return rate.quality in RATE_QUALITIES
