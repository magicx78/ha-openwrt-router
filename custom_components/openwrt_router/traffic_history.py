"""Durable traffic history: tiers, rollup, retention, quotas (Phase I).

Task §14, plan 2026-11-20 §5. :class:`TrafficHistory` is the
:class:`traffic_series.BucketSource` of the engine from Phase I on. It
extends the bounded memory ring of Phase E (same point quotas, same rate
splitting, same "unknown stays None") by two coarser tiers and a store
format:

* **Tiers.** 5-minute buckets (the ring), hourly and daily buckets. Daily
  buckets are UTC days (``Bucket.start`` must be aligned to its
  resolution; a local day would not be). Raw per-poll values are not kept
  here: the engine holds the latest rate per point (``latest``).
* **Rollup.** A fine bucket is added once to its hour and its day, as soon
  as it ended ``HISTORY_ROLLUP_DELAY_S`` ago (rates span at most the gap
  limit, so it cannot change any more). Bytes and samples add up, peaks
  take the maximum, covered seconds add up (capped at the resolution),
  quality bits are or-ed. A rate that still reaches a rolled bucket is
  counted (``late_after_rollup``), never rolled twice. Reading an hourly or
  daily window also adds the fine buckets not rolled yet, so the newest
  hour is never missing.
* **Retention** per profile (:data:`PROFILES`) and kind (infrastructure /
  client): every tier has a fixed bucket count; buckets older than the
  tier's retention go; a point idle for longer than its longest tier goes
  (``expired_points``). The point quotas of the ring stay (32 infrastructure
  points per router, 160 in total, 200 clients).
* **Queries.** Without an explicit resolution the window picks the finest
  tier that covers it with at most ``HISTORY_MAX_QUERY_POINTS`` buckets
  (1 h -> 5 min, 24 h -> 5 min or 1 h, 7 d -> 1 h, 30/90 d -> 1 d).
* **Entry unload** (``drop_router``) keeps the history: an entry reload
  must not lose evidence. ``forget_router`` deletes a router's points.
* **Store format** (:meth:`export_fine`, :meth:`export_coarse`,
  :meth:`import_payload`): one entry per point with its identity fields
  (no MAC, no IP, no host name; only router id, netdev names and the
  pseudonymous ``client_ref``) and one comma-separated string per column
  (``-`` for unknown; peaks in whole bit/s, covered time in 0.1 s),
  because HA writes store files indented (a JSON array would cost one line
  per number). Anything that does not parse is skipped and counted; a
  foreign format version is ignored. Nothing here raises on stored data.

No Home Assistant import (the store and its size check are in
``traffic_store``).
"""

from __future__ import annotations

import heapq
import logging
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .traffic_const import (
    CLIENT_POINT_IDLE_S,
    DEFAULT_HISTORY_PROFILE,
    HIST_DAY_S,
    HIST_FINE_S,
    HIST_HOUR_S,
    HISTORY_FORMAT_VERSION,
    HISTORY_MAX_QUERY_POINTS,
    HISTORY_PART_CLIENT,
    HISTORY_PART_INFRA,
    HISTORY_PART_REST,
    HISTORY_PROFILE_COMPACT,
    HISTORY_PROFILE_STANDARD,
    HISTORY_ROLLUP_DELAY_S,
    MAX_POINTS_CLIENT,
    MAX_POINTS_INFRA_PER_ROUTER,
    MAX_POINTS_INFRA_TOTAL,
    REASON_BEYOND_RETENTION,
    REASON_HISTORY_SHORT,
    REASON_NO_DATA_YET,
)
from .traffic_model import (
    RATE_QUALITIES,
    Bucket,
    Coverage,
    MeasurementPoint,
    Rate,
    point_from_dict,
)
from .traffic_series import (
    _NONE_INT,
    INFRA_SCOPES,
    MemoryBucketRing,
    SeriesWindow,
    _Ring,
)

_LOGGER = logging.getLogger(__name__)

COARSE_RESOLUTIONS = (HIST_HOUR_S, HIST_DAY_S)
RESOLUTIONS = (HIST_FINE_S, *COARSE_RESOLUTIONS)
STORE_FINE = "fine"
STORE_COARSE = "coarse"
_TIER_KEY = {HIST_FINE_S: "f", HIST_HOUR_S: "h", HIST_DAY_S: "d"}
_COLUMNS = ("rx", "tx", "rxp", "txp", "cov", "samples", "mask")
_INT_COLUMNS = frozenset({"rx", "tx", "samples", "mask"})
# Token of an unknown value in a stored column (never 0).
_UNKNOWN = "-"
_PART_COUNTER = {
    HISTORY_PART_INFRA: "store_trimmed_infra",
    HISTORY_PART_CLIENT: "store_trimmed_client",
    HISTORY_PART_REST: "store_trimmed_rest",
}


# --- profiles ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TierLimits:
    """Retention in seconds per tier (0: the tier is not kept)."""

    fine_s: int
    hour_s: int
    day_s: int

    def retention(self, resolution_s: int) -> int:
        """Retention of the tier with ``resolution_s``."""
        return {
            HIST_FINE_S: self.fine_s,
            HIST_HOUR_S: self.hour_s,
            HIST_DAY_S: self.day_s,
        }.get(resolution_s, 0)

    def max_buckets(self, resolution_s: int) -> int:
        """Fixed bucket count of the tier (one more for the running bucket)."""
        keep = self.retention(resolution_s)
        return keep // resolution_s + 1 if keep > 0 else 0

    @property
    def longest_s(self) -> int:
        """Longest retention of all tiers."""
        return max(self.fine_s, self.hour_s, self.day_s)


@dataclass(frozen=True, slots=True)
class HistoryProfile:
    """Retention of infrastructure and client points, and what goes to disk."""

    name: str
    infra: TierLimits
    client: TierLimits
    persist_clients: bool

    def limits(self, point: MeasurementPoint) -> TierLimits:
        """Limits of ``point``'s kind."""
        return self.infra if point.scope in INFRA_SCOPES else self.client


_H = 3600
_D = 86400
PROFILES: Mapping[str, HistoryProfile] = {
    # Vorgabe 2026-11-21: hourly values 14 days in compact (baselines need two
    # weeks); infrastructure only on disk, 5 min for 6 h (plan §12.5).
    HISTORY_PROFILE_COMPACT: HistoryProfile(
        HISTORY_PROFILE_COMPACT,
        infra=TierLimits(6 * _H, 14 * _D, 31 * _D),
        client=TierLimits(6 * _H, 2 * _D, 0),
        persist_clients=False,
    ),
    # Plan §5 table.
    HISTORY_PROFILE_STANDARD: HistoryProfile(
        HISTORY_PROFILE_STANDARD,
        infra=TierLimits(1 * _D, 7 * _D, 90 * _D),
        client=TierLimits(6 * _H, 2 * _D, 30 * _D),
        persist_clients=True,
    ),
}


def profile_of(value: Any) -> HistoryProfile:
    """The profile for a name or profile (unknown: the default)."""
    if isinstance(value, HistoryProfile):
        return value
    return PROFILES.get(value, PROFILES[DEFAULT_HISTORY_PROFILE])


# --- encoding ---------------------------------------------------------------------------


def _encode_column(name: str, values: Sequence[float]) -> str:
    out: list[str] = []
    for value in values:
        if name in ("rx", "tx"):
            out.append(_UNKNOWN if value == _NONE_INT else str(int(value)))
        elif name in ("rxp", "txp"):
            out.append(_UNKNOWN if math.isnan(value) else str(round(value)))
        elif name == "cov":
            out.append(str(round(value, 1)).removesuffix(".0"))
        else:
            out.append(str(int(value)))
    return ",".join(out)


def _decode_column(name: str, raw: Any, length: int | None) -> list[float] | None:
    if not isinstance(raw, str) or len(raw) > 1_000_000:
        return None
    parts = raw.split(",") if raw else []
    if length is not None and len(parts) != length:
        return None
    out: list[float] = []
    for part in parts:
        if part == _UNKNOWN:
            if name in ("rx", "tx"):
                out.append(_NONE_INT)
            elif name in ("rxp", "txp"):
                out.append(math.nan)
            else:
                return None
            continue
        try:
            value = int(part) if name in _INT_COLUMNS else float(part)
        except ValueError:
            return None
        if not math.isfinite(value) or value < 0:
            return None
        out.append(value)
    return out


def _encode_ring(ring: _Ring) -> list[Any]:
    return [
        ring.first_start,
        *(_encode_column(name, getattr(ring, name)) for name in _COLUMNS),
    ]


def _decode_ring(
    point: MeasurementPoint, raw: Any, resolution_s: int, max_buckets: int
) -> _Ring | None:
    """A ring from its stored list (None: not usable)."""
    if not isinstance(raw, list) or len(raw) != 1 + len(_COLUMNS):
        return None
    first = raw[0]
    if isinstance(first, bool) or not isinstance(first, int) or first < 0:
        return None
    if first % resolution_s:
        return None
    columns: dict[str, list[float]] = {}
    length: int | None = None
    for name, value in zip(_COLUMNS, raw[1:], strict=True):
        decoded = _decode_column(name, value, length)
        if decoded is None:
            return None
        length = len(decoded)
        columns[name] = decoded
    ring = _Ring(point, max_buckets)
    if not length:
        return ring
    ring.first_start = first
    for name, values in columns.items():
        getattr(ring, name).extend(values)
    for i in range(length):
        ring.cov[i] = min(float(resolution_s), ring.cov[i])
    over = len(ring) - max_buckets
    if over > 0:
        ring._trim_front(over, resolution_s)
    return ring


def _point_list(point: MeasurementPoint) -> list[Any]:
    return [
        point.router_id,
        point.scope.value,
        point.device,
        point.vlan_id,
        point.radio_id,
        point.client_ref,
    ]


def _point_from_list(raw: Any) -> MeasurementPoint | None:
    if not isinstance(raw, list) or len(raw) != 6:
        return None
    keys = ("router_id", "scope", "device", "vlan_id", "radio_id", "client_ref")
    return point_from_dict(dict(zip(keys, raw, strict=True)))


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


# --- merged buckets ---------------------------------------------------------------------


class _Acc:
    """One coarse bucket while it is merged from stored and pending buckets."""

    __slots__ = ("cov", "mask", "rx", "rxp", "samples", "tx", "txp")

    def __init__(self) -> None:
        self.rx: int | None = None
        self.tx: int | None = None
        self.rxp: float | None = None
        self.txp: float | None = None
        self.cov = 0.0
        self.samples = 0
        self.mask = 0

    def add(self, bucket: Bucket) -> None:
        if bucket.rx_bytes is not None:
            self.rx = bucket.rx_bytes + (self.rx or 0)
        if bucket.tx_bytes is not None:
            self.tx = bucket.tx_bytes + (self.tx or 0)
        if bucket.rx_peak_bps is not None:
            self.rxp = max(self.rxp or 0.0, bucket.rx_peak_bps)
        if bucket.tx_peak_bps is not None:
            self.txp = max(self.txp or 0.0, bucket.tx_peak_bps)
        self.cov += bucket.covered_s
        self.samples += bucket.samples
        self.mask |= bucket.quality_mask

    def bucket(self, start: int, res: int) -> Bucket:
        return Bucket(
            start=start,
            resolution_s=res,
            rx_bytes=self.rx,
            tx_bytes=self.tx,
            rx_peak_bps=self.rxp,
            tx_peak_bps=self.txp,
            covered_s=min(float(res), self.cov),
            samples=self.samples,
            quality_mask=self.mask,
        )


def _has_content(ring: _Ring, i: int) -> bool:
    return bool(
        ring.cov[i] > 0
        or ring.mask[i]
        or ring.rx[i] != _NONE_INT
        or ring.tx[i] != _NONE_INT
    )


# --- history ----------------------------------------------------------------------------


class TrafficHistory(MemoryBucketRing):
    """Bounded fine/hour/day history with a store format (``BucketSource``)."""

    def __init__(
        self,
        *,
        profile: Any = DEFAULT_HISTORY_PROFILE,
        max_infra_per_router: int = MAX_POINTS_INFRA_PER_ROUTER,
        max_infra_total: int = MAX_POINTS_INFRA_TOTAL,
        max_clients: int = MAX_POINTS_CLIENT,
        client_idle_s: float = CLIENT_POINT_IDLE_S,
    ) -> None:
        """Empty history with the limits of ``profile``."""
        prof = profile_of(profile)
        super().__init__(
            resolution_s=HIST_FINE_S,
            max_buckets_infra=prof.infra.max_buckets(HIST_FINE_S),
            max_buckets_client=prof.client.max_buckets(HIST_FINE_S),
            max_infra_per_router=max_infra_per_router,
            max_infra_total=max_infra_total,
            max_clients=max_clients,
            client_idle_s=client_idle_s,
        )
        self._profile = prof
        self._coarse: dict[str, dict[int, _Ring]] = {}
        self._rolled: dict[str, int] = {}
        self._coarse_dirty = False
        self.counters.update(
            {
                "late_after_rollup": 0,
                "rolled_buckets": 0,
                "expired_points": 0,
                "load_invalid": 0,
                "store_trimmed_infra": 0,
                "store_trimmed_client": 0,
                "store_trimmed_rest": 0,
            }
        )

    # -- profile ----------------------------------------------------------------------

    @property
    def profile(self) -> HistoryProfile:
        """The active profile."""
        return self._profile

    def set_profile(self, profile: Any) -> None:
        """Switch the profile; every tier is trimmed to its new limits."""
        prof = profile_of(profile)
        if prof is self._profile:
            return
        self._profile = prof
        self._max_buckets = {
            True: prof.infra.max_buckets(HIST_FINE_S),
            False: prof.client.max_buckets(HIST_FINE_S),
        }
        for pid, ring in self._rings.items():
            limits = prof.limits(ring.point)
            self._resize(ring, HIST_FINE_S, limits.max_buckets(HIST_FINE_S))
            tiers = self._coarse.get(pid, {})
            for res in list(tiers):
                size = limits.max_buckets(res)
                if size <= 0:
                    del tiers[res]
                else:
                    self._resize(tiers[res], res, size)
        self._version += 1
        self._coarse_dirty = True

    @staticmethod
    def _resize(ring: _Ring, res: int, size: int) -> None:
        ring.max_buckets = max(1, size)
        over = len(ring) - ring.max_buckets
        if over > 0:
            ring._trim_front(over, res)

    # -- feeding ----------------------------------------------------------------------

    def add_rate(self, rate: Rate) -> bool:
        """Like the ring; then rolls the point's finished fine buckets."""
        point = self._target(rate.point)
        wall = rate.wall_s
        if (
            point is not None
            and wall is not None
            and math.isfinite(wall)
            and rate.quality in RATE_QUALITIES
        ):
            rolled = self._rolled.get(point.point_id)
            if rolled is not None and wall - float(rate.interval_s or 0.0) < rolled:
                self.counters["late_after_rollup"] += 1
        kept = super().add_rate(rate)
        if kept and point is not None and wall is not None:
            self._roll(point.point_id, wall)
        return kept

    def _roll(self, pid: str, now: float) -> bool:
        """Roll the finished fine buckets of one point; True if any content."""
        ring = self._rings.get(pid)
        if ring is None or ring.first_start is None or not len(ring):
            return False
        res = HIST_FINE_S
        first = ring.first_start
        start_from = max(self._rolled.get(pid, first), first)
        i0 = (start_from - first) // res
        end_excl = min(
            len(ring), math.floor((now - HISTORY_ROLLUP_DELAY_S - first) / res)
        )
        if end_excl <= i0:
            return False
        limits = self._profile.limits(ring.point)
        tiers = self._coarse.setdefault(pid, {})
        rolled_any = False
        targets: list[tuple[int, _Ring]] = []
        for coarse_res in COARSE_RESOLUTIONS:
            size = limits.max_buckets(coarse_res)
            if size <= 0:
                continue
            target = tiers.get(coarse_res)
            if target is None:
                target = tiers[coarse_res] = _Ring(ring.point, size)
            targets.append((coarse_res, target))
        for i in range(i0, end_excl):
            if not _has_content(ring, i):
                continue
            start = first + i * res
            for coarse_res, target in targets:
                idx = target.index(start // coarse_res * coarse_res, coarse_res)
                if idx is None:
                    self.counters["late_rates"] += 1
                    continue
                self._merge_columns(target, idx, ring, i, coarse_res)
            self.counters["rolled_buckets"] += 1
            rolled_any = True
        self._rolled[pid] = first + end_excl * res
        if rolled_any:
            self._coarse_dirty = True
        return rolled_any

    @staticmethod
    def _merge_columns(target: _Ring, idx: int, src: _Ring, i: int, res: int) -> None:
        """Add fine bucket ``i`` of ``src`` to coarse bucket ``idx``."""
        for name in ("rx", "tx"):
            value = getattr(src, name)[i]
            if value != _NONE_INT:
                column = getattr(target, name)
                old = column[idx]
                column[idx] = value + (0 if old == _NONE_INT else old)
        for name in ("rxp", "txp"):
            value = getattr(src, name)[i]
            column = getattr(target, name)
            if not math.isnan(value) and (
                math.isnan(column[idx]) or value > column[idx]
            ):
                column[idx] = value
        target.cov[idx] = min(
            float(res), target.cov[idx] + min(float(HIST_FINE_S), src.cov[i])
        )
        target.samples[idx] += src.samples[i]
        target.mask[idx] |= src.mask[i]

    # -- maintenance ------------------------------------------------------------------

    def compact(self, now: float) -> bool:
        """Roll every point, apply retention, expire idle points.

        True when the hourly/daily tiers changed since the previous call
        (the coarse store needs a write).
        """
        for pid in list(self._rings):
            ring = self._rings[pid]
            limits = self._profile.limits(ring.point)
            if now - ring.last_wall > limits.longest_s:
                self._remove(pid)
                self.counters["expired_points"] += 1
                self._coarse_dirty = True
                continue
            self._roll(pid, now)
            self._trim_before(ring, HIST_FINE_S, now - limits.fine_s)
            for res, tier in self._coarse.get(pid, {}).items():
                if self._trim_before(tier, res, now - limits.retention(res)):
                    self._coarse_dirty = True
        changed, self._coarse_dirty = self._coarse_dirty, False
        if changed:
            self._version += 1
        return changed

    @staticmethod
    def _trim_before(ring: _Ring, res: int, cutoff: float) -> int:
        """Drop buckets that ended before ``cutoff``; returns how many."""
        if ring.first_start is None or not len(ring):
            return 0
        count = min(len(ring), max(0, math.floor((cutoff - ring.first_start) / res)))
        if count > 0:
            ring._trim_front(count, res)
        return count

    def _remove(self, point_id: str) -> None:
        super()._remove(point_id)
        self._coarse.pop(point_id, None)
        self._rolled.pop(point_id, None)

    def drop_router(self, router_id: str | None) -> None:
        """Entry unloaded: the history stays (reload must not lose evidence)."""

    def forget_router(self, router_id: str | None) -> None:
        """Delete every infrastructure point of ``router_id`` with all tiers."""
        super().drop_router(router_id)

    def clear(self) -> None:
        """Forget everything in memory (the store keeps what was written)."""
        super().clear()
        self._coarse.clear()
        self._rolled.clear()
        self._coarse_dirty = False

    def trim_oldest(self, store: str, part: str, count: int) -> int:
        """Drop the ``count`` oldest buckets of one store part; returns how many.

        ``store`` is ``fine`` (5-min tier) or ``coarse`` (hour and day),
        ``part`` is ``infra`` or ``client``; nothing of another part moves.
        """
        infra = part == HISTORY_PART_INFRA
        rings: list[tuple[int, _Ring]] = []
        for pid, ring in self._rings.items():
            if (ring.point.scope in INFRA_SCOPES) != infra:
                continue
            if store == STORE_FINE:
                rings.append((HIST_FINE_S, ring))
            else:
                rings.extend(self._coarse.get(pid, {}).items())
        heap = [
            (r.first_start, n, res, r)
            for n, (res, r) in enumerate(rings)
            if r.first_start is not None and len(r)
        ]
        heapq.heapify(heap)
        removed = 0
        while heap and removed < count:
            _start, n, res, ring = heapq.heappop(heap)
            ring._trim_front(1, res)
            removed += 1
            if len(ring):
                heapq.heappush(heap, (ring.first_start, n, res, ring))
        if removed:
            self.counters[_PART_COUNTER[part]] += removed
            self._version += 1
        return removed

    def bucket_count(self, store: str, part: str) -> int:
        """Buckets held for one store part (the trimming estimate)."""
        infra = part == HISTORY_PART_INFRA
        total = 0
        for pid, ring in self._rings.items():
            if (ring.point.scope in INFRA_SCOPES) != infra:
                continue
            if store == STORE_FINE:
                total += len(ring)
            else:
                total += sum(len(t) for t in self._coarse.get(pid, {}).values())
        return total

    def count_trimmed(self, part: str, count: int = 1) -> None:
        """Count something of ``part`` left out of a store write."""
        self.counters[_PART_COUNTER[part]] += count

    # -- reading ----------------------------------------------------------------------

    def _choose(self, limits: TierLimits, window_s: int, wanted: int | None) -> int:
        kept = [res for res in RESOLUTIONS if limits.retention(res) > 0]
        if wanted in kept:
            return wanted  # type: ignore[return-value]
        for res in kept:
            if (
                limits.retention(res) >= window_s
                and window_s / res <= HISTORY_MAX_QUERY_POINTS
            ):
                return res
        best = HIST_FINE_S
        best_span = -1
        for res in kept:
            span = min(window_s, limits.retention(res))
            if span / res <= HISTORY_MAX_QUERY_POINTS and span > best_span:
                best, best_span = res, span
        return best

    def window(
        self,
        point_id: str,
        window_s: int,
        *,
        end: float,
        resolution_s: int | None = None,
    ) -> SeriesWindow | None:
        """See ``BucketSource.window``; the resolution follows the window."""
        ring = self._rings.get(point_id)
        if ring is None or window_s <= 0:
            return None
        limits = self._profile.limits(ring.point)
        res = self._choose(limits, window_s, resolution_s)
        if res == HIST_FINE_S:
            return super().window(point_id, window_s, end=end)
        aligned_end = math.ceil(end / res) * res
        first_wanted = aligned_end - window_s
        merged: dict[int, _Acc] = {}
        origins: list[int] = []
        tier = self._coarse.get(point_id, {}).get(res)
        if tier is not None and tier.first_start is not None and len(tier):
            origins.append(tier.first_start)
            for i in range(len(tier)):
                start = tier.first_start + i * res
                if first_wanted <= start < aligned_end:
                    merged.setdefault(start, _Acc()).add(tier.bucket(i, res))
        if ring.first_start is not None and len(ring):
            origins.append(ring.first_start // res * res)
            first = ring.first_start
            rolled = max(self._rolled.get(point_id, first), first)
            for i in range((rolled - first) // HIST_FINE_S, len(ring)):
                if not _has_content(ring, i):
                    continue
                fine = ring.bucket(i, HIST_FINE_S)
                start = fine.start // res * res
                if first_wanted <= start < aligned_end:
                    merged.setdefault(start, _Acc()).add(fine)
        origin = min(origins) if origins else None
        buckets: list[Bucket] = []
        depth = 0.0
        if origin is not None:
            start = max(origin, first_wanted)
            while start < aligned_end:
                acc = merged.get(start)
                buckets.append(
                    acc.bucket(start, res)
                    if acc is not None
                    else Bucket(start=start, resolution_s=res)
                )
                start += res
            depth = max(0.0, float(aligned_end - origin))
        reason: str | None = None
        if not any(b.covered_s > 0 for b in buckets):
            reason = REASON_NO_DATA_YET
        elif depth < window_s:
            reason = (
                REASON_BEYOND_RETENTION
                if window_s > limits.retention(res)
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

    # -- store format -----------------------------------------------------------------

    def _persisted(self, point: MeasurementPoint) -> bool:
        return point.scope in INFRA_SCOPES or self._profile.persist_clients

    def export_fine(self) -> dict[str, Any]:
        """Fine store section: identities, area, roll state and 5-min buckets."""
        points: dict[str, Any] = {}
        for pid in sorted(self._rings):
            ring = self._rings[pid]
            if not self._persisted(ring.point):
                continue
            entry: dict[str, Any] = {
                "p": _point_list(ring.point),
                "a": ring.area_coverage.value,
                "ar": ring.area_reason,
                "lw": ring.last_wall if math.isfinite(ring.last_wall) else None,
                "ru": self._rolled.get(pid),
            }
            if ring.first_start is not None and len(ring):
                entry["f"] = _encode_ring(ring)
            points[pid] = entry
        return {
            "v": HISTORY_FORMAT_VERSION,
            "profile": self._profile.name,
            "points": points,
        }

    def export_coarse(self) -> dict[str, Any]:
        """Coarse store section: hourly and daily buckets per point."""
        points: dict[str, Any] = {}
        for pid in sorted(self._coarse):
            ring = self._rings.get(pid)
            if ring is None or not self._persisted(ring.point):
                continue
            entry: dict[str, Any] = {"p": _point_list(ring.point)}
            for res, tier in sorted(self._coarse[pid].items()):
                if tier.first_start is not None and len(tier):
                    entry[_TIER_KEY[res]] = _encode_ring(tier)
            if len(entry) > 1:
                points[pid] = entry
        return {
            "v": HISTORY_FORMAT_VERSION,
            "profile": self._profile.name,
            "points": points,
        }

    @staticmethod
    def _section(raw: Any) -> Mapping[str, Any] | None:
        if not isinstance(raw, Mapping) or raw.get("v") != HISTORY_FORMAT_VERSION:
            return None
        points = raw.get("points")
        return points if isinstance(points, Mapping) else None

    def import_payload(self, fine: Any, coarse: Any) -> int:
        """Restore both sections (after a restart); returns the invalid count.

        Never raises: a missing section is nothing, a foreign or broken one
        is ignored (counted as one invalid), a point that does not parse,
        whose id does not match its fields or that the quotas refuse is
        skipped (counted). Points of a kind the profile does not keep on
        disk are ignored.
        """
        invalid = 0
        sections: list[tuple[Mapping[str, Any], bool]] = []
        for raw, is_fine in ((fine, True), (coarse, False)):
            if raw is None:
                continue
            section = self._section(raw)
            if section is None:
                invalid += 1
                continue
            sections.append((section, is_fine))
        for section, is_fine in sections:
            for pid, entry in section.items():
                if not self._import_point(pid, entry, is_fine):
                    invalid += 1
        self.counters["load_invalid"] += invalid
        if invalid:
            _LOGGER.debug("Traffic history: %d stored entries skipped", invalid)
        self._version += 1
        return invalid

    def _import_point(self, pid: Any, entry: Any, is_fine: bool) -> bool:
        if not isinstance(entry, Mapping):
            return False
        point = _point_from_list(entry.get("p"))
        if point is None or point.point_id != pid:
            return False
        if not self._persisted(point):
            return True  # not kept on disk in this profile: ignored, not broken
        limits = self._profile.limits(point)
        wall = _finite(entry.get("lw")) if is_fine else None
        ring = self._rings.get(pid)
        if ring is None:
            ring = self._ring(point, wall if wall is not None else -math.inf)
            if ring is None:
                return False
        if is_fine:
            if wall is not None:
                ring.last_wall = max(ring.last_wall, wall)
            try:
                ring.area_coverage = Coverage(entry.get("a", Coverage.UNKNOWN.value))
            except ValueError:
                ring.area_coverage = Coverage.UNKNOWN
            reason = entry.get("ar")
            ring.area_reason = reason[:64] if isinstance(reason, str) else None
            rolled = entry.get("ru")
            if isinstance(rolled, int) and not isinstance(rolled, bool):
                self._rolled[pid] = rolled
            raw = entry.get("f")
            if raw is not None:
                decoded = _decode_ring(
                    point, raw, HIST_FINE_S, limits.max_buckets(HIST_FINE_S)
                )
                if decoded is None:
                    return False
                for name in ("first_start", *_COLUMNS):
                    setattr(ring, name, getattr(decoded, name))
            return True
        ok = True
        for res in COARSE_RESOLUTIONS:
            raw = entry.get(_TIER_KEY[res])
            size = limits.max_buckets(res)
            if raw is None or size <= 0:
                continue
            decoded = _decode_ring(point, raw, res, size)
            if decoded is None:
                ok = False
                continue
            self._coarse.setdefault(pid, {})[res] = decoded
        if ring.last_wall == -math.inf:
            # no fine entry: the newest coarse bucket stands for the last data
            ends = [
                t.first_start + len(t) * res
                for res, t in self._coarse.get(pid, {}).items()
                if t.first_start is not None and len(t)
            ]
            if ends:
                ring.last_wall = float(max(ends))
        return ok

    # -- summary ----------------------------------------------------------------------

    def summary(self) -> dict[str, Any]:
        """Counts only (no point ids, no client ids)."""
        out = super().summary()
        out["profile"] = self._profile.name
        out["buckets_hour"] = sum(
            len(t[HIST_HOUR_S]) for t in self._coarse.values() if HIST_HOUR_S in t
        )
        out["buckets_day"] = sum(
            len(t[HIST_DAY_S]) for t in self._coarse.values() if HIST_DAY_S in t
        )
        return out


__all__ = [
    "PROFILES",
    "STORE_COARSE",
    "STORE_FINE",
    "HistoryProfile",
    "TierLimits",
    "TrafficHistory",
    "point_from_dict",
    "profile_of",
]
