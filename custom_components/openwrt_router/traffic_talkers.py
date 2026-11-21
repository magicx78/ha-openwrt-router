"""Top talkers and heavy hitters (plan 2026-11-20 §2.1; task §6; Phase E).

Rankings per window (5 min, 1 h, 24 h, 7 d, 30 d) and per measuring area,
never across areas: clients, interfaces, VLANs, WAN and ports each have
their own list. Three kinds of list:

* :func:`rank_window` - observed bytes in a window per direction
  (``download``/``upload`` where the area maps them unambiguously, else
  ``rx``/``tx``, see ``traffic_accounting.direction_map``);
* :func:`rank_current` - highest current bandwidth from the latest
  accounted rates;
* :func:`rank_recurring_peaks` - points with repeated peak episodes in a
  window (a bucket whose peak rate is at least ``PEAK_FACTOR`` times the
  median average rate of the window and at least ``PEAK_MIN_BPS``;
  consecutive peak buckets form one episode).

**No double counting.** A client is ranked once, as its ``Scope.CLIENT``
point (``client_ref``): the history keeps the valid deltas of all its
associations there, and the accounting already turned duplicate sightings
at a second AP into ``stale_source``. Station points are never ranked
(``station_counts_per_association_use_client``); for the current ranking
the newest valid association rate of a client counts.

**Rows** carry the observed bytes (or bit/s), the measuring area, the
coverage (area and time) and a share in percent only where it means
something: same area, the reference total is an allowed sum
(``traffic_accounting.sum_rates``) and that total is fully covered; else the
share is None with the reason. Client values are Wi-Fi traffic at the AP
(``wlan_traffic_at_ap``), never internet use, so their share is always None.

**Partial.** A list is ``partial`` with reasons when any row is not fully
covered, a point was left out (no direction, too little data) or the source
dropped points by quota. A window without any data is ``unavailable`` with a
reason, never an empty "no traffic" list.

**Bounds.** At most ``MAX_TALKERS`` rows, ``heapq`` top-N (O(n log k)),
deterministic order (value descending, then ``point_id``), and a small cache
keyed by the source version.
"""

from __future__ import annotations

import heapq
import logging
import statistics
from collections import Counter, OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .traffic_accounting import TrafficSum, direction_map, sum_rates
from .traffic_const import (
    CLIENT_VALUE_KIND,
    DEFAULT_TALKERS,
    MAX_TALKERS,
    PEAK_FACTOR,
    PEAK_MIN_BPS,
    PEAK_MIN_BUCKETS,
    REASON_INSUFFICIENT_DATA,
    REASON_NO_DATA_FOR_WINDOW,
    REASON_POINTS_DROPPED,
    REASON_POINTS_OMITTED,
    REASON_SCOPE_NOT_RANKED,
    REASON_SHARE_REFERENCE_NOT_FULL,
    REASON_SHARE_REFERENCE_ZERO,
    REASON_UNKNOWN_DIRECTION,
    REASON_UNKNOWN_WINDOW,
    REASON_USE_CLIENT_SCOPE,
    TALKER_CACHE_SIZE,
    TALKER_DIRECTIONS,
    TALKER_WINDOWS,
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
)
from .traffic_series import BucketSource, SeriesWindow

_LOGGER = logging.getLogger(__name__)

RANKED_SCOPES = frozenset(
    {Scope.CLIENT, Scope.INTERFACE, Scope.VLAN, Scope.WAN, Scope.PORT}
)
METRIC_BYTES = "bytes"
METRIC_BPS = "bps"
METRIC_PEAK_EPISODES = "peak_episodes"
STATE_OK = "ok"
STATE_UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class TalkerRow:
    """One ranked point; ``value`` is bytes, bit/s or episodes (``metric``)."""

    rank: int
    point_id: str
    scope: Scope
    router_id: str | None
    client_ref: str | None
    device: str | None
    vlan_id: int | None
    counter: str
    value: float
    observed_bytes: int | None
    peak_bps: float | None
    measuring_area: str
    coverage: Coverage
    coverage_reasons: tuple[str, ...]
    time_coverage: float | None
    share_pct: float | None
    share_reason: str | None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (pseudonyms only)."""
        return {
            "rank": self.rank,
            "point_id": self.point_id,
            "scope": self.scope.value,
            "router_id": self.router_id,
            "client_ref": self.client_ref,
            "device": self.device,
            "vlan_id": self.vlan_id,
            "counter": self.counter,
            "value": self.value,
            "observed_bytes": self.observed_bytes,
            "peak_bps": self.peak_bps,
            "measuring_area": self.measuring_area,
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "time_coverage": self.time_coverage,
            "share_pct": self.share_pct,
            "share_reason": self.share_reason,
        }


@dataclass(frozen=True, slots=True)
class TalkerList:
    """A bounded ranking of one area, window and direction."""

    scope: Scope
    window: str | None
    window_s: int | None
    direction: str
    metric: str
    state: str
    reason: str | None = None
    partial: bool = True
    partial_reasons: tuple[str, ...] = ()
    rows: tuple[TalkerRow, ...] = ()
    considered: int = 0
    omitted: Mapping[str, int] = field(default_factory=dict)
    total: TrafficSum | None = None
    limit: int = DEFAULT_TALKERS

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "scope": self.scope.value,
            "window": self.window,
            "window_s": self.window_s,
            "direction": self.direction,
            "metric": self.metric,
            "state": self.state,
            "reason": self.reason,
            "partial": self.partial,
            "partial_reasons": list(self.partial_reasons),
            "rows": [r.to_dict() for r in self.rows],
            "considered": self.considered,
            "omitted": dict(self.omitted),
            "total": None if self.total is None else self.total.to_dict(),
            "limit": self.limit,
        }


def _unavailable(
    scope: Scope,
    window: str | None,
    direction: str,
    metric: str,
    reason: str,
    limit: int,
    omitted: Mapping[str, int] | None = None,
) -> TalkerList:
    return TalkerList(
        scope=scope,
        window=window,
        window_s=TALKER_WINDOWS.get(window or ""),
        direction=direction,
        metric=metric,
        state=STATE_UNAVAILABLE,
        reason=reason,
        partial=True,
        partial_reasons=(reason,),
        omitted=dict(omitted or {}),
        limit=limit,
    )


def clamp_limit(limit: Any) -> int:
    """``limit`` as an int in 1..MAX_TALKERS (default for anything invalid)."""
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        return DEFAULT_TALKERS
    return min(limit, MAX_TALKERS)


def counter_for(point: MeasurementPoint, direction: str) -> str | None:
    """``"rx"``/``"tx"`` behind ``direction`` at ``point`` (None: not mapped)."""
    if direction in ("rx", "tx"):
        return direction
    mapping = direction_map(point)
    return mapping.download if direction == "download" else mapping.upload


def measuring_area(point: MeasurementPoint, counter: str) -> str:
    """What a value of ``point`` is (``wlan_traffic_at_ap`` for clients)."""
    if point.scope is Scope.CLIENT or point.scope is Scope.STATION:
        return CLIENT_VALUE_KIND
    mapping = direction_map(point)
    means = mapping.rx_means if counter == "rx" else mapping.tx_means
    return f"{point.scope.value}:{means}"


def _scope_check(scope: Scope, direction: str) -> str | None:
    if scope is Scope.STATION:
        return REASON_USE_CLIENT_SCOPE
    if scope is Scope.FLOW:
        return CoverageReason.NEEDS_FLOW_SOURCE.value
    if scope not in RANKED_SCOPES:
        return REASON_SCOPE_NOT_RANKED
    if direction not in TALKER_DIRECTIONS:
        return REASON_UNKNOWN_DIRECTION
    if direction in ("download", "upload"):
        probe = {
            Scope.INTERFACE: MeasurementPoint(None, Scope.INTERFACE, device="x"),
            Scope.VLAN: MeasurementPoint(None, Scope.VLAN, vlan_id=1),
        }.get(scope)
        if probe is not None:
            return direction_map(probe).reason
    return None


def _reason_enum(reasons: Iterable[str]) -> CoverageReason | None:
    for reason in reasons:
        try:
            return CoverageReason(reason)
        except ValueError:
            continue
    return None


def _shares(
    candidates: list[
        tuple[
            MeasurementPoint, int | None, int | None, Coverage, tuple[str, ...], float
        ]
    ],
    counter: str,
    *,
    time_full: bool,
    omitted: int,
    uplink_ports: Mapping[str, frozenset[str] | None] | None,
) -> tuple[TrafficSum, int | None, str | None]:
    """Reference total via ``sum_rates``; (sum, total of counter, refusal).

    The window totals become synthetic rates (average bit/s over the covered
    time) so the sum rules of the accounting decide; nothing is added here.
    """

    def avg(value: int | None, covered: float) -> float | None:
        return None if value is None or covered <= 0 else value * 8 / covered

    rates = [
        Rate(
            point,
            Quality.OK,
            interval_s=covered,
            rx_bps=avg(rx, covered),
            tx_bps=avg(tx, covered),
            rx_delta=rx,
            tx_delta=tx,
            coverage=coverage,
            coverage_reason=_reason_enum(reasons),
        )
        for point, rx, tx, coverage, reasons, covered in candidates
    ]
    total = sum_rates(rates, uplink_ports=uplink_ports)
    if not total.ok:
        return total, None, total.refused
    value = total.rx_bytes if counter == "rx" else total.tx_bytes
    if total.coverage is not Coverage.FULL or not time_full or omitted:
        return total, value, REASON_SHARE_REFERENCE_NOT_FULL
    if not value:
        return total, value, REASON_SHARE_REFERENCE_ZERO
    return total, value, None


def _avg_bps(bucket: Bucket, counter: str) -> float | None:
    value = bucket.rx_bytes if counter == "rx" else bucket.tx_bytes
    if value is None or bucket.covered_s <= 0:
        return None
    return value * 8 / bucket.covered_s


def peak_episodes(buckets: Iterable[Bucket], counter: str) -> tuple[int, float] | None:
    """(episodes, highest peak) of a window; None below ``PEAK_MIN_BUCKETS``.

    Only buckets with at least half coverage count; a peak bucket has a
    peak rate >= ``PEAK_FACTOR`` x the median average rate and >=
    ``PEAK_MIN_BPS``; consecutive peak buckets are one episode.
    """
    usable = [b for b in buckets if not b.gappy]
    averages = [a for a in (_avg_bps(b, counter) for b in usable) if a is not None]
    if len(averages) < PEAK_MIN_BUCKETS:
        return None
    limit = max(PEAK_FACTOR * statistics.median(averages), PEAK_MIN_BPS)
    episodes = 0
    in_peak = False
    highest = 0.0
    previous_start: int | None = None
    for bucket in usable:
        peak = bucket.rx_peak_bps if counter == "rx" else bucket.tx_peak_bps
        contiguous = (
            previous_start is not None
            and bucket.start - previous_start == bucket.resolution_s
        )
        previous_start = bucket.start
        if peak is not None and peak >= limit:
            if not (in_peak and contiguous):
                episodes += 1
            in_peak = True
            highest = max(highest, peak)
        else:
            in_peak = False
    return episodes, highest


class TalkerBoard:
    """Talker rankings over one :class:`BucketSource` with a small cache."""

    def __init__(self, source: BucketSource) -> None:
        """Board over ``source``."""
        self.source = source
        self._cache: OrderedDict[tuple[Any, ...], TalkerList] = OrderedDict()
        self.counters: Counter[str] = Counter()

    def _cached(self, key: tuple[Any, ...], build: Any) -> TalkerList:
        version = getattr(self.source, "version", None)
        full_key = (version, *key)
        hit = self._cache.get(full_key) if version is not None else None
        if hit is not None:
            self._cache.move_to_end(full_key)
            self.counters["cache_hits"] += 1
            return hit
        result: TalkerList = build()
        if version is not None:
            self._cache[full_key] = result
            while len(self._cache) > TALKER_CACHE_SIZE:
                self._cache.popitem(last=False)
        return result

    def _windows(self, scope: Scope, window_s: int, end: float) -> list[SeriesWindow]:
        out = []
        for point in self.source.points():
            if point.scope is not scope:
                continue
            win = self.source.window(point.point_id, window_s, end=end)
            if win is not None:
                out.append(win)
        return out

    def _dropped_reason(self, scope: Scope) -> str | None:
        dropped = self.source.dropped()
        name = (
            "dropped_points_client" if scope is Scope.CLIENT else "dropped_points_infra"
        )
        return REASON_POINTS_DROPPED if dropped.get(name, 0) else None

    def rank_window(
        self,
        scope: Scope,
        window: str,
        direction: str,
        *,
        end: float,
        limit: int = DEFAULT_TALKERS,
        uplink_ports: Mapping[str, frozenset[str] | None] | None = None,
    ) -> TalkerList:
        """Observed bytes per point in ``window`` (see the module docstring)."""
        limit = clamp_limit(limit)
        res = max(1, int(getattr(self.source, "resolution_s", 1)))
        key = ("window", scope, window, direction, int(end // res), limit)
        return self._cached(
            key,
            lambda: self._rank_window(
                scope, window, direction, end, limit, uplink_ports
            ),
        )

    def _rank_window(
        self,
        scope: Scope,
        window: str,
        direction: str,
        end: float,
        limit: int,
        uplink_ports: Mapping[str, frozenset[str] | None] | None,
    ) -> TalkerList:
        scope = Scope(scope)
        if window not in TALKER_WINDOWS:
            return _unavailable(
                scope, None, direction, METRIC_BYTES, REASON_UNKNOWN_WINDOW, limit
            )
        refused = _scope_check(scope, direction)
        if refused is not None:
            return _unavailable(scope, window, direction, METRIC_BYTES, refused, limit)
        window_s = TALKER_WINDOWS[window]
        omitted: Counter[str] = Counter()
        partial: set[str] = set()
        entries: list[tuple[SeriesWindow, str, int]] = []
        candidates = []
        for win in self._windows(scope, window_s, end):
            counter = counter_for(win.point, direction)
            if counter is None:
                omitted[
                    direction_map(win.point).reason or REASON_UNKNOWN_DIRECTION
                ] += 1
                continue
            if win.covered_s <= 0:
                omitted[win.reason or REASON_NO_DATA_FOR_WINDOW] += 1
                continue
            value = win.total(f"{counter}_bytes")
            if value is None:
                omitted[Quality.SOURCE_MISSING.value] += 1
                continue
            entries.append((win, counter, value))
            candidates.append(
                (
                    win.point,
                    win.total("rx_bytes"),
                    win.total("tx_bytes"),
                    win.coverage,
                    win.area_reasons,
                    win.covered_s,
                )
            )
            if win.coverage is not Coverage.FULL:
                partial.update(win.coverage_reasons or (win.coverage.value,))
        if not entries:
            return _unavailable(
                scope,
                window,
                direction,
                METRIC_BYTES,
                REASON_NO_DATA_FOR_WINDOW,
                limit,
                omitted,
            )
        if omitted:
            partial.add(REASON_POINTS_OMITTED)
        dropped = self._dropped_reason(scope)
        if dropped:
            partial.add(dropped)
        counter0 = entries[0][1]
        same_counter = all(c == counter0 for _w, c, _v in entries)
        time_full = all(w.coverage is Coverage.FULL for w, _c, _v in entries)
        total, ref, share_refusal = _shares(
            candidates,
            counter0,
            time_full=time_full and same_counter,
            omitted=sum(omitted.values()) + (1 if dropped else 0),
            uplink_ports=uplink_ports,
        )
        top = heapq.nsmallest(
            limit, entries, key=lambda e: (-e[2], e[0].point.point_id)
        )
        rows = []
        for rank, (win, counter, value) in enumerate(top, start=1):
            share = None
            if share_refusal is None and ref:
                share = round(100.0 * value / ref, 2)
            peaks = [
                (b.rx_peak_bps if counter == "rx" else b.tx_peak_bps)
                for b in win.buckets
            ]
            known = [p for p in peaks if p is not None]
            rows.append(
                TalkerRow(
                    rank=rank,
                    point_id=win.point.point_id,
                    scope=scope,
                    router_id=win.point.router_id,
                    client_ref=win.point.client_ref,
                    device=win.point.device,
                    vlan_id=win.point.vlan_id,
                    counter=counter,
                    value=float(value),
                    observed_bytes=value,
                    peak_bps=max(known) if known else None,
                    measuring_area=measuring_area(win.point, counter),
                    coverage=win.coverage,
                    coverage_reasons=win.coverage_reasons,
                    time_coverage=round(win.time_coverage, 4),
                    share_pct=share,
                    share_reason=share_refusal if share is None else None,
                )
            )
        return TalkerList(
            scope=scope,
            window=window,
            window_s=window_s,
            direction=direction,
            metric=METRIC_BYTES,
            state=STATE_OK,
            partial=bool(partial),
            partial_reasons=tuple(sorted(partial)),
            rows=tuple(rows),
            considered=len(entries),
            omitted=dict(omitted),
            total=total,
            limit=limit,
        )

    def rank_recurring_peaks(
        self,
        scope: Scope,
        window: str,
        direction: str,
        *,
        end: float,
        limit: int = DEFAULT_TALKERS,
    ) -> TalkerList:
        """Points with the most peak episodes in ``window``."""
        limit = clamp_limit(limit)
        res = max(1, int(getattr(self.source, "resolution_s", 1)))
        key = ("peaks", scope, window, direction, int(end // res), limit)
        return self._cached(
            key, lambda: self._rank_peaks(scope, window, direction, end, limit)
        )

    def _rank_peaks(
        self, scope: Scope, window: str, direction: str, end: float, limit: int
    ) -> TalkerList:
        scope = Scope(scope)
        metric = METRIC_PEAK_EPISODES
        if window not in TALKER_WINDOWS:
            return _unavailable(
                scope, None, direction, metric, REASON_UNKNOWN_WINDOW, limit
            )
        refused = _scope_check(scope, direction)
        if refused is not None:
            return _unavailable(scope, window, direction, metric, refused, limit)
        window_s = TALKER_WINDOWS[window]
        omitted: Counter[str] = Counter()
        partial: set[str] = set()
        entries: list[tuple[SeriesWindow, str, int, float]] = []
        considered = 0
        for win in self._windows(scope, window_s, end):
            counter = counter_for(win.point, direction)
            if counter is None:
                omitted[
                    direction_map(win.point).reason or REASON_UNKNOWN_DIRECTION
                ] += 1
                continue
            found = peak_episodes(win.buckets, counter)
            if found is None:
                omitted[REASON_INSUFFICIENT_DATA] += 1
                continue
            considered += 1
            if win.coverage is not Coverage.FULL:
                partial.update(win.coverage_reasons or (win.coverage.value,))
            episodes, highest = found
            if episodes:
                entries.append((win, counter, episodes, highest))
        if not considered:
            return _unavailable(
                scope,
                window,
                direction,
                metric,
                REASON_INSUFFICIENT_DATA,
                limit,
                omitted,
            )
        if omitted:
            partial.add(REASON_POINTS_OMITTED)
        dropped = self._dropped_reason(scope)
        if dropped:
            partial.add(dropped)
        top = heapq.nsmallest(
            limit, entries, key=lambda e: (-e[2], -e[3], e[0].point.point_id)
        )
        rows = tuple(
            TalkerRow(
                rank=rank,
                point_id=win.point.point_id,
                scope=scope,
                router_id=win.point.router_id,
                client_ref=win.point.client_ref,
                device=win.point.device,
                vlan_id=win.point.vlan_id,
                counter=counter,
                value=float(episodes),
                observed_bytes=win.total(f"{counter}_bytes"),
                peak_bps=highest,
                measuring_area=measuring_area(win.point, counter),
                coverage=win.coverage,
                coverage_reasons=win.coverage_reasons,
                time_coverage=round(win.time_coverage, 4),
                share_pct=None,
                share_reason=METRIC_PEAK_EPISODES,
            )
            for rank, (win, counter, episodes, highest) in enumerate(top, start=1)
        )
        return TalkerList(
            scope=scope,
            window=window,
            window_s=window_s,
            direction=direction,
            metric=metric,
            state=STATE_OK,
            partial=bool(partial),
            partial_reasons=tuple(sorted(partial)),
            rows=rows,
            considered=considered,
            omitted=dict(omitted),
            limit=limit,
        )


def rank_current(
    rates: Iterable[Rate],
    scope: Scope,
    direction: str,
    *,
    limit: int = DEFAULT_TALKERS,
    uplink_ports: Mapping[str, frozenset[str] | None] | None = None,
) -> TalkerList:
    """Highest current bandwidth (bit/s) from the latest accounted rates.

    For ``Scope.CLIENT`` the station rates are used, one per ``client_ref``
    (the newest valid one; duplicates are ``stale_source`` already).
    """
    limit = clamp_limit(limit)
    scope = Scope(scope)
    metric = METRIC_BPS
    refused = _scope_check(scope, direction)
    if refused is not None:
        return _unavailable(scope, None, direction, metric, refused, limit)
    omitted: Counter[str] = Counter()
    chosen: dict[str, Rate] = {}
    for rate in rates:
        point = rate.point
        if scope is Scope.CLIENT:
            if point.scope is not Scope.STATION or point.client_ref is None:
                continue
            if rate.quality is Quality.STALE_SOURCE:
                continue  # the same client counts at its current AP
            ident = point.client_ref
        elif point.scope is scope:
            ident = point.point_id
        else:
            continue
        if rate.quality not in RATE_QUALITIES:
            if ident not in chosen:
                omitted[rate.quality.value] += 1
            continue
        old = chosen.get(ident)
        if old is None or (rate.mono_s or 0) > (old.mono_s or 0):
            chosen[ident] = rate
    entries: list[tuple[Rate, str, float]] = []
    for rate in chosen.values():
        counter = counter_for(rate.point, direction)
        if counter is None:
            omitted[direction_map(rate.point).reason or REASON_UNKNOWN_DIRECTION] += 1
            continue
        value = rate.rx_bps if counter == "rx" else rate.tx_bps
        if value is None:
            omitted[Quality.SOURCE_MISSING.value] += 1
            continue
        entries.append((rate, counter, value))
    if not entries:
        return _unavailable(
            scope, None, direction, metric, REASON_NO_DATA_FOR_WINDOW, limit, omitted
        )
    partial: set[str] = set()
    for rate, _c, _v in entries:
        if rate.coverage is not Coverage.FULL:
            partial.add(
                rate.coverage_reason.value
                if rate.coverage_reason is not None
                else rate.coverage.value
            )
    if omitted:
        partial.add(REASON_POINTS_OMITTED)
    total = sum_rates([e[0] for e in entries], uplink_ports=uplink_ports)
    counter0 = entries[0][1]
    ref = total.rx_bps if counter0 == "rx" else total.tx_bps
    share_refusal: str | None = None
    if not total.ok:
        share_refusal = total.refused
    elif (
        total.coverage is not Coverage.FULL
        or omitted
        or any(c != counter0 for _r, c, _v in entries)
    ):
        share_refusal = REASON_SHARE_REFERENCE_NOT_FULL
    elif not ref:
        share_refusal = REASON_SHARE_REFERENCE_ZERO

    def ident_of(rate: Rate) -> str:
        return rate.point.client_ref or rate.point.point_id

    top = heapq.nsmallest(limit, entries, key=lambda e: (-e[2], ident_of(e[0])))
    rows = []
    for rank, (rate, counter, value) in enumerate(top, start=1):
        point = rate.point
        if scope is Scope.CLIENT:
            point = MeasurementPoint(None, Scope.CLIENT, client_ref=point.client_ref)
        share = None
        if share_refusal is None and ref:
            share = round(100.0 * value / ref, 2)
        delta = rate.rx_delta if counter == "rx" else rate.tx_delta
        rows.append(
            TalkerRow(
                rank=rank,
                point_id=point.point_id,
                scope=scope,
                router_id=rate.point.router_id,
                client_ref=point.client_ref,
                device=point.device,
                vlan_id=point.vlan_id,
                counter=counter,
                value=float(value),
                observed_bytes=delta,
                peak_bps=value,
                measuring_area=measuring_area(point, counter),
                coverage=rate.coverage,
                coverage_reasons=(
                    ()
                    if rate.coverage_reason is None
                    else (rate.coverage_reason.value,)
                ),
                time_coverage=None,
                share_pct=share,
                share_reason=share_refusal if share is None else None,
            )
        )
    return TalkerList(
        scope=scope,
        window=None,
        window_s=None,
        direction=direction,
        metric=metric,
        state=STATE_OK,
        partial=bool(partial),
        partial_reasons=tuple(sorted(partial)),
        rows=tuple(rows),
        considered=len(entries),
        omitted=dict(omitted),
        total=total,
        limit=limit,
    )
