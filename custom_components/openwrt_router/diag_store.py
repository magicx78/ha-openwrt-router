"""Network diagnostics: persistence of history, baselines and settings.

Two layers:

* :class:`DiagHistory` -- the bounded in-memory history (pure, no Home
  Assistant): hour and day buckets per series (``diag_stats``), baselines per
  (series, metric) (``diag_baseline``), per-router restart memory and the
  restart gap records. It serialises to plain data and back.
* :class:`DiagStore` -- the Home Assistant ``Store`` around it (versioned,
  private, delayed save, flush on the last unload, tolerant load).

Bounds and quotas (``const.DIAG_*``). Every drop is counted and shown in
:meth:`DiagHistory.status`; nothing is dropped silently and nothing evicts
anything else:

* The Home Assistant point has its own series quota (``DIAG_MAX_SERIES_HA``),
  every router point its own (``DIAG_MAX_SERIES_PER_ROUTER``). A full point
  refuses NEW series of that point only (counted per point); its existing
  series and every other point keep recording.
* At most ``DIAG_MAX_POINTS`` router points; a further router is refused
  (counted), the known ones are never evicted.
* Hour buckets are kept 7 days, day buckets 30 days (``diag_stats``
  retention). The hard caps per series (``DIAG_MAX_HOUR_BUCKETS``,
  ``DIAG_MAX_DAY_BUCKETS``) only bite on odd timestamps; what they drop is
  counted.
* A sample older than the newest one of its series (or than the hours
  already folded into a day) is dropped and counted (buckets need time order).
* Restart gap records are bounded (``DIAG_MAX_GAP_RECORDS``, oldest dropped,
  counted).

Load is tolerant: a damaged bucket is dropped and counted, a damaged series
or baseline as well; a damaged section starts empty (counted). An unreadable
store is kept as ``.bak`` and the module starts empty (``load_failed``).

Restart semantics (binding):

* Home Assistant restart: the history and the baselines are restored. The
  downtime (``saved_at`` .. now) is a GAP -- one gap record plus one gap
  sample per series, never a loss -- and every baseline's hysteresis
  counters restart (``diag_baseline.on_restart``); the learned baselines are
  kept. Done once by the runtime on activation (:meth:`DiagStore.take_restart`).
* Router restart: the same for that router's series only.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import fields as dc_fields
from typing import Any

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.storage import Store

from .const import (
    DATA_NET_DIAGNOSTICS,
    DIAG_MAX_DAY_BUCKETS,
    DIAG_MAX_GAP_RECORDS,
    DIAG_MAX_HOUR_BUCKETS,
    DIAG_MAX_POINTS,
    DIAG_MAX_SERIES_HA,
    DIAG_MAX_SERIES_PER_ROUTER,
    DIAG_SAVE_DELAY_SECONDS,
    DIAG_STORE_KEY,
    DIAG_STORE_MINOR_VERSION,
    DIAG_STORE_VERSION,
)
from .diag_baseline import (
    METRICS,
    PHASE_DEGRADED,
    PHASE_LEARNING,
    PHASE_NORMAL,
    BaselineState,
    on_restart,
)
from .diag_core import HA_POINT_KEY, ForgetPlan
from .diag_stats import (
    DAY_RETENTION_S,
    DAY_S,
    HOUR_RETENTION_S,
    HOUR_S,
    Bucket,
    LatencySummary,
    Sample,
    SeriesKey,
    add_sample,
    align,
    empty_bucket,
    fold_into_days,
    prune_history,
    window_summaries,
)

_LOGGER = logging.getLogger(__name__)

STORE_FORMAT = 1
FLUSH_KEY = f"{DATA_NET_DIAGNOSTICS}_flush"

# Compact bucket rows: Bucket fields in this order (a list per bucket).
BUCKET_FIELDS: tuple[str, ...] = tuple(f.name for f in dc_fields(Bucket))
_BASELINE_FIELDS = (
    "phase",
    "mean",
    "dev",
    "learned",
    "above",
    "below",
    "outliers",
    "last_outlier_ts",
    "phase_since",
    "last_ts",
    "reference",
)
_PHASES = frozenset({PHASE_LEARNING, PHASE_NORMAL, PHASE_DEGRADED})

# Restart reasons of gap records.
GAP_HA_RESTART = "ha_restart"
GAP_ROUTER_RESTART = "router_restart"
GAP_REASONS = frozenset({GAP_HA_RESTART, GAP_ROUTER_RESTART})

COUNTERS: tuple[str, ...] = (
    "points_refused",  # a router point beyond DIAG_MAX_POINTS
    "series_refused",  # a new series of a full point (also per point)
    "samples_recorded",
    "samples_out_of_order",
    "hours_dropped",  # hard cap per series
    "days_dropped",  # hard cap per series
    "gaps_dropped",  # oldest restart gap records beyond the cap
    "buckets_damaged",  # dropped while loading
    "series_damaged",
    "baselines_damaged",
    "routers_damaged",
    "sections_damaged",
    "routers_forgotten",
    # 1.47.0 review: quota slots given back
    "series_expired",  # no bucket left after the retention
    "series_removed",  # HA series of a target id that no longer exists
)


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value) if math.isfinite(value) else None


def _count(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def key_to_list(key: SeriesKey) -> list[str]:
    """Plain form of a series key."""
    return [key.point, key.target, key.kind, key.family]


def key_from_list(raw: Any) -> SeriesKey:
    """Series key from :func:`key_to_list`; ValueError/TypeError if damaged."""
    if not isinstance(raw, list | tuple) or len(raw) != 4:
        raise ValueError("damaged series key")
    return SeriesKey(*raw)


def bucket_to_row(bucket: Bucket) -> list[Any]:
    """Compact plain form of a bucket (a list in ``BUCKET_FIELDS`` order)."""
    return [getattr(bucket, name) for name in BUCKET_FIELDS]


def bucket_from_row(row: Any) -> Bucket:
    """Bucket from :func:`bucket_to_row`; ValueError if damaged."""
    if not isinstance(row, list | tuple) or len(row) != len(BUCKET_FIELDS):
        raise ValueError("damaged bucket row")
    return Bucket.from_dict(dict(zip(BUCKET_FIELDS, row, strict=True)))


def baseline_to_dict(state: BaselineState) -> dict[str, Any]:
    """Plain form of a baseline state."""
    out: dict[str, Any] = {"key": key_to_list(state.key), "metric": state.metric}
    out.update({name: getattr(state, name) for name in _BASELINE_FIELDS})
    return out


def baseline_from_dict(raw: Any) -> BaselineState:
    """Baseline state from :func:`baseline_to_dict`; ValueError if damaged."""
    if not isinstance(raw, Mapping):
        raise TypeError("damaged baseline")
    key = key_from_list(raw.get("key"))
    metric = raw.get("metric")
    if metric not in METRICS or raw.get("phase") not in _PHASES:
        raise ValueError("damaged baseline")
    values: dict[str, Any] = {}
    for name in (
        "mean",
        "dev",
        "last_outlier_ts",
        "phase_since",
        "last_ts",
        "reference",
    ):
        value = raw.get(name)
        if value is not None and _num(value) is None:
            raise ValueError("damaged baseline")
        values[name] = None if value is None else float(value)
    for name in ("learned", "above", "below", "outliers"):
        count = _count(raw.get(name))
        if count is None:
            raise ValueError("damaged baseline")
        values[name] = count
    if (values["mean"] is None) != (values["dev"] is None):
        raise ValueError("damaged baseline")
    if raw["phase"] != PHASE_LEARNING and values["mean"] is None:
        raise ValueError("damaged baseline")
    return BaselineState(key=key, metric=metric, phase=raw["phase"], **values)


class SeriesHistory:
    """Hour and day buckets of one series (oldest first)."""

    __slots__ = ("days", "folded_until", "hours", "key", "since")

    def __init__(self, key: SeriesKey, *, since: float) -> None:
        """Empty history; ``since`` = first sample (coverage starts there)."""
        self.key = key
        self.since = since
        self.hours: list[Bucket] = []
        self.days: list[Bucket] = []
        self.folded_until: float | None = None  # end of the newest folded hour

    @property
    def last_ts(self) -> float | None:
        """Newest sample time (any outcome) or None."""
        for bucket in reversed(self.hours):
            if bucket.last_ts is not None:
                return bucket.last_ts
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": key_to_list(self.key),
            "since": self.since,
            "folded_until": self.folded_until,
            "hours": [bucket_to_row(b) for b in self.hours],
            "days": [bucket_to_row(b) for b in self.days],
        }


class DiagHistory:
    """Bounded history of every series, baselines and restart memory (pure)."""

    def __init__(
        self,
        *,
        max_points: int = DIAG_MAX_POINTS,
        max_series_ha: int = DIAG_MAX_SERIES_HA,
        max_series_router: int = DIAG_MAX_SERIES_PER_ROUTER,
        max_hours: int = DIAG_MAX_HOUR_BUCKETS,
        max_days: int = DIAG_MAX_DAY_BUCKETS,
        max_gaps: int = DIAG_MAX_GAP_RECORDS,
    ) -> None:
        """Empty history with the given bounds."""
        self.max_points = max_points
        self.max_series_ha = max_series_ha
        self.max_series_router = max_series_router
        self.max_hours = max_hours
        self.max_days = max_days
        self.max_gaps = max_gaps
        self.series: dict[SeriesKey, SeriesHistory] = {}
        self.baselines: dict[tuple[SeriesKey, str], BaselineState] = {}
        # router id -> {"last_uptime", "restarts", "last_restart"}
        self.routers: dict[str, dict[str, Any]] = {}
        self.gaps: list[dict[str, Any]] = []
        self.counters: dict[str, int] = dict.fromkeys(COUNTERS, 0)
        self.point_refusals: dict[str, int] = {}  # point -> refused new series

    # -- quotas ---------------------------------------------------------------------

    def _points(self) -> set[str]:
        return {k.point for k in self.series} - {HA_POINT_KEY}

    def series_count(self, point: str) -> int:
        """Series of one measurement point."""
        return sum(1 for k in self.series if k.point == point)

    def _quota(self, point: str) -> int:
        return self.max_series_ha if point == HA_POINT_KEY else self.max_series_router

    def _admit(self, key: SeriesKey) -> bool:
        """May a NEW series of ``key.point`` be created? Counts a refusal."""
        point = key.point
        points = self._points()
        if (
            point != HA_POINT_KEY
            and point not in points
            and len(points) >= self.max_points
        ):
            self.counters["points_refused"] += 1
            return False
        if self.series_count(point) >= self._quota(point):
            self.counters["series_refused"] += 1
            self.point_refusals[point] = self.point_refusals.get(point, 0) + 1
            return False
        return True

    # -- samples --------------------------------------------------------------------

    def record(self, key: SeriesKey, sample: Sample, *, outlier: bool = False) -> bool:
        """Add one sample to its series; False when refused or dropped (counted)."""
        history = self.series.get(key)
        if history is None:
            if not self._admit(key):
                return False
            history = SeriesHistory(key, since=sample.ts)
            self.series[key] = history
        hour = align(sample.ts, HOUR_S)
        last = history.hours[-1] if history.hours else None
        too_old = (
            last is not None and last.last_ts is not None and sample.ts < last.last_ts
        ) or (history.folded_until is not None and sample.ts < history.folded_until)
        if too_old or (last is not None and hour < last.start):
            self.counters["samples_out_of_order"] += 1
            return False
        if last is not None and last.start == hour:
            history.hours[-1] = add_sample(last, sample, outlier=outlier)
        else:
            history.hours.append(
                add_sample(empty_bucket(hour, HOUR_S), sample, outlier=outlier)
            )
            excess = len(history.hours) - self.max_hours
            if excess > 0:
                self._fold_series(history, history.hours[excess - 1].end)
                del history.hours[:excess]
                self.counters["hours_dropped"] += excess
        self.counters["samples_recorded"] += 1
        return True

    def _fold_series(self, history: SeriesHistory, until: float) -> None:
        """Fold every complete hour ending at or before ``until`` once."""
        done = history.folded_until
        todo = [
            h
            for h in history.hours
            if h.end <= until and (done is None or h.start >= done)
        ]
        if not todo:
            return
        history.days = list(fold_into_days(todo, history.days))
        history.folded_until = todo[-1].end
        excess = len(history.days) - self.max_days
        if excess > 0:
            del history.days[:excess]
            self.counters["days_dropped"] += excess

    def fold(self, now: float) -> None:
        """Fold completed hours into days and apply the retention.

        A series without any bucket left gives its quota slot back (with
        its baselines); counted as ``series_expired``.
        """
        empty: list[SeriesKey] = []
        for key, history in self.series.items():
            self._fold_series(history, now)
            hours, days = prune_history(
                history.hours,
                history.days,
                now=now,
                hour_retention_s=HOUR_RETENTION_S,
                day_retention_s=DAY_RETENTION_S,
            )
            history.hours, history.days = list(hours), list(days)
            if not history.hours and not history.days:
                empty.append(key)
        if empty:
            self._drop_series(empty)
            self.counters["series_expired"] += len(empty)

    def _drop_series(self, keys: Iterable[SeriesKey]) -> None:
        gone = set(keys)
        for key in gone:
            self.series.pop(key, None)
        for item in [i for i in self.baselines if i[0] in gone]:
            del self.baselines[item]

    def drop_ha_targets(self, keep: Iterable[str]) -> list[SeriesKey]:
        """Drop the HA series (and baselines) of target ids not in ``keep``."""
        wanted = set(keep)
        gone = [
            k for k in self.series if k.point == HA_POINT_KEY and k.target not in wanted
        ]
        gone += [
            item[0]
            for item in self.baselines
            if item[0].point == HA_POINT_KEY
            and item[0].target not in wanted
            and item[0] not in gone
        ]
        gone = list(dict.fromkeys(gone))
        if gone:
            self._drop_series(gone)
            self.counters["series_removed"] += len(gone)
        return gone

    def summaries(
        self,
        key: SeriesKey,
        *,
        now: float,
        interval_s: float | None = None,
        probes_per_round: int = 1,
    ) -> dict[str, LatencySummary] | None:
        """Window summaries (1h/24h/7d/30d) of one series, None if unknown."""
        history = self.series.get(key)
        if history is None:
            return None
        return window_summaries(
            history.hours,
            history.days,
            now=now,
            interval_s=interval_s,
            probes_per_round=probes_per_round,
            since=history.since,
        )

    # -- baselines ------------------------------------------------------------------

    def baseline(self, key: SeriesKey, metric: str) -> BaselineState | None:
        """Stored baseline of (series, metric), or None."""
        return self.baselines.get((key, metric))

    def set_baseline(self, state: BaselineState) -> bool:
        """Keep a baseline; only for a series the history holds (quota)."""
        if state.key not in self.series:
            return False
        self.baselines[(state.key, state.metric)] = state
        return True

    # -- restarts -------------------------------------------------------------------

    def mark_restart(
        self, *, start: float, end: float, reason: str, point: str | None = None
    ) -> int:
        """Record a downtime as a GAP for every series (of ``point``).

        One gap record, one gap sample per series at ``end`` and every
        baseline's streaks restarted (learned values kept). Returns the
        number of series that got the gap sample.
        """
        if reason not in GAP_REASONS:
            raise ValueError("unknown gap reason")
        start = min(start, end)
        self.gaps.append({"start": start, "end": end, "reason": reason, "point": point})
        excess = len(self.gaps) - self.max_gaps
        if excess > 0:
            del self.gaps[:excess]
            self.counters["gaps_dropped"] += excess
        marked = 0
        for key in list(self.series):
            if point is not None and key.point != point:
                continue
            last = self.series[key].last_ts
            if last is None or end >= last:
                marked += int(self.record(key, Sample.gap(end)))
        for item, state in list(self.baselines.items()):
            if point is not None and state.key.point != point:
                continue
            if state.last_ts is None or end >= state.last_ts:
                self.baselines[item] = on_restart(state, ts=end)
        return marked

    def router_memory(self, router_id: str) -> dict[str, Any]:
        """Restart memory of a router (created on first use)."""
        return self.routers.setdefault(
            router_id, {"last_uptime": None, "restarts": 0, "last_restart": None}
        )

    # -- forgetting -----------------------------------------------------------------

    def series_keys(self) -> tuple[SeriesKey, ...]:
        return tuple(self.series)

    def baseline_states(self) -> tuple[BaselineState, ...]:
        return tuple(self.baselines.values())

    def forget(self, plan: ForgetPlan) -> bool:
        """Apply ``diag_core.forget_plan``: drop that router's state only."""
        found = (
            bool(plan.series_keys or plan.baselines) or plan.router_id in self.routers
        )
        for key in plan.series_keys:
            self.series.pop(key, None)
        for item in plan.baselines:
            self.baselines.pop(item, None)
        self.routers.pop(plan.router_id, None)
        self.point_refusals.pop(plan.router_id, None)
        self.gaps = [g for g in self.gaps if g.get("point") != plan.router_id]
        if found:
            self.counters["routers_forgotten"] += 1
        return found

    def router_ids(self) -> set[str]:
        """Router ids the history keeps state of."""
        return self._points() | set(self.routers)

    # -- status / plain data ---------------------------------------------------------

    def status(self) -> dict[str, Any]:
        """Counters and fill levels (no identities beyond router ids)."""
        per_point: dict[str, int] = {}
        for key in self.series:
            per_point[key.point] = per_point.get(key.point, 0) + 1
        return {
            "series": len(self.series),
            "baselines": len(self.baselines),
            "router_points": len(self._points()),
            "gap_records": len(self.gaps),
            "series_per_point": per_point,
            "series_refused_per_point": dict(self.point_refusals),
            "quota_ha": self.max_series_ha,
            "quota_router": self.max_series_router,
            "max_points": self.max_points,
            "counters": dict(self.counters),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "series": [h.to_dict() for h in self.series.values()],
            "baselines": [baseline_to_dict(s) for s in self.baselines.values()],
            "routers": {rid: dict(mem) for rid, mem in self.routers.items()},
            "gaps": [dict(g) for g in self.gaps],
            "counters": dict(self.counters),
            "point_refusals": dict(self.point_refusals),
        }

    def restore(self, raw: Mapping[str, Any]) -> None:
        """Fill from :meth:`to_dict` output, tolerantly (damage is counted)."""
        sections: tuple[tuple[str, Callable[[Any], None]], ...] = (
            ("counters", self._restore_counters),
            ("series", self._restore_series),
            ("baselines", self._restore_baselines),
            ("routers", self._restore_routers),
            ("gaps", self._restore_gaps),
            ("point_refusals", self._restore_refusals),
        )
        for name, restore in sections:
            try:
                restore(raw.get(name))
            except Exception as err:  # noqa: BLE001 - tolerant per section
                self.counters["sections_damaged"] += 1
                _LOGGER.warning(
                    "Network diagnostics store section %s unreadable (%s); empty",
                    name,
                    type(err).__name__,
                )

    def _restore_counters(self, raw: Any) -> None:
        if not isinstance(raw, Mapping):
            return
        for name in COUNTERS:
            value = _count(raw.get(name))
            if value is not None:
                self.counters[name] = value

    def _restore_refusals(self, raw: Any) -> None:
        if not isinstance(raw, Mapping):
            return
        for point, value in raw.items():
            count = _count(value)
            if isinstance(point, str) and count is not None:
                self.point_refusals[point] = count

    def _restore_series(self, raw: Any) -> None:
        for item in raw if isinstance(raw, list) else ():
            try:
                history = self._series_from(item)
            except (TypeError, ValueError):
                self.counters["series_damaged"] += 1
                continue
            if history.key in self.series:
                self.counters["series_damaged"] += 1
                continue
            if not self._admit(history.key):  # counted as a refusal
                continue
            self.series[history.key] = history

    def _series_from(self, item: Any) -> SeriesHistory:
        if not isinstance(item, Mapping):
            raise TypeError("damaged series")
        key = key_from_list(item.get("key"))
        since = _num(item.get("since"))
        if since is None:
            raise ValueError("damaged series")
        history = SeriesHistory(key, since=since)
        history.hours = self._buckets(item.get("hours"), HOUR_S, self.max_hours)
        history.days = self._buckets(item.get("days"), DAY_S, self.max_days)
        folded = item.get("folded_until")
        history.folded_until = _num(folded)
        if history.days and history.folded_until is None:
            history.folded_until = history.days[-1].end
        return history

    def _buckets(self, raw: Any, span: float, cap: int) -> list[Bucket]:
        """Valid, ordered, non-overlapping buckets; damaged ones are counted."""
        out: list[Bucket] = []
        for row in raw if isinstance(raw, list) else ():
            try:
                bucket = bucket_from_row(row)
            except (TypeError, ValueError):
                self.counters["buckets_damaged"] += 1
                continue
            slot = align(bucket.start, span)
            fits = (
                bucket.end <= slot + span
                and (
                    span != HOUR_S
                    or (bucket.start == slot and bucket.end == slot + span)
                )
                and (not out or out[-1].end <= bucket.start)
            )
            if not fits:
                self.counters["buckets_damaged"] += 1
                continue
            out.append(bucket)
        if len(out) > cap:
            dropped = len(out) - cap
            self.counters["hours_dropped" if span == HOUR_S else "days_dropped"] += (
                dropped
            )
            out = out[dropped:]
        return out

    def _restore_baselines(self, raw: Any) -> None:
        for item in raw if isinstance(raw, list) else ():
            try:
                state = baseline_from_dict(item)
            except (TypeError, ValueError):
                self.counters["baselines_damaged"] += 1
                continue
            if not self.set_baseline(state):
                self.counters["baselines_damaged"] += 1

    def _restore_routers(self, raw: Any) -> None:
        if not isinstance(raw, Mapping):
            return
        for rid, mem in raw.items():
            if not isinstance(rid, str) or not isinstance(mem, Mapping):
                self.counters["routers_damaged"] += 1
                continue
            uptime = mem.get("last_uptime")
            self.routers[rid] = {
                "last_uptime": _num(uptime) if uptime is not None else None,
                "restarts": _count(mem.get("restarts")) or 0,
                "last_restart": _num(mem.get("last_restart")),
            }

    def _restore_gaps(self, raw: Any) -> None:
        for item in raw if isinstance(raw, list) else ():
            if not isinstance(item, Mapping) or item.get("reason") not in GAP_REASONS:
                continue
            start, end = _num(item.get("start")), _num(item.get("end"))
            point = item.get("point")
            if (
                start is None
                or end is None
                or not (point is None or isinstance(point, str))
            ):
                continue
            self.gaps.append(
                {"start": start, "end": end, "reason": item["reason"], "point": point}
            )
        self.gaps = self.gaps[-self.max_gaps :]


def _backup_file(path: Any) -> bool:
    from .net_engine import _backup_file as backup

    return backup(path)


class DiagStore:
    """Home Assistant store of the module: settings, history, ``saved_at``.

    ``parse_settings`` turns stored settings into valid ones (the runtime's
    validator; damaged settings fall back to the defaults there).
    """

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        parse_settings: Callable[[Any], dict[str, Any]],
        history_factory: Callable[[], DiagHistory] = DiagHistory,
    ) -> None:
        """Empty store; ``async_load`` reads it."""
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(
            hass,
            DIAG_STORE_VERSION,
            DIAG_STORE_KEY,
            minor_version=DIAG_STORE_MINOR_VERSION,
            private=True,
        )
        self._parse_settings = parse_settings
        self._history_factory = history_factory
        self._lock = asyncio.Lock()
        self.settings: dict[str, Any] = parse_settings(None)
        self.history = history_factory()
        self.saved_at: float | None = None
        self._restart_from: float | None = None  # saved_at of the last run
        self.loaded = False
        self.load_failed = False
        self.load_errors = 0
        self.dirty = False
        self.saves = 0
        self._save_pending = False
        self._closed = False
        self.clock: Callable[[], float] = time.time

    async def async_load(self) -> None:
        """Read the store once; an unreadable one is kept as ``.bak``."""
        async with self._lock:
            if self.loaded:
                return
            pending = self.hass.data.get(FLUSH_KEY)
            if isinstance(pending, asyncio.Future) and not pending.done():
                await pending
            try:
                stored = await self._store.async_load()
            except Exception as err:  # noqa: BLE001 - start empty, keep a copy
                self.load_errors += 1
                _LOGGER.warning(
                    "Network diagnostics store unreadable (%s); starting empty",
                    type(err).__name__,
                )
                stored = None
                self.load_failed = True
            if stored is not None and not isinstance(stored, dict):
                _LOGGER.warning("Network diagnostics store has an unknown format")
                self.load_errors += 1
                stored = None
                self.load_failed = True
            if stored:
                self._restore(stored)
            if self.load_failed:
                await self._async_backup()
            self.loaded = True

    def _restore(self, stored: Mapping[str, Any]) -> None:
        try:
            self.settings = self._parse_settings(stored.get("settings"))
        except Exception as err:  # noqa: BLE001 - defaults then
            self.load_errors += 1
            self.settings = self._parse_settings(None)
            _LOGGER.warning(
                "Network diagnostics settings unreadable (%s); defaults",
                type(err).__name__,
            )
        history = stored.get("history")
        if isinstance(history, Mapping):
            self.history.restore(history)
        elif history is not None:
            self.load_errors += 1
        saved = _num(stored.get("saved_at"))
        self.saved_at = saved
        self._restart_from = saved

    async def _async_backup(self) -> None:
        path = getattr(self._store, "path", None)
        try:
            copied = await self.hass.async_add_executor_job(_backup_file, path)
        except Exception as err:  # noqa: BLE001 - the next save replaces it
            _LOGGER.debug("Network diagnostics store backup (%s)", type(err).__name__)
            return
        if copied:
            _LOGGER.warning("Network diagnostics kept a copy of its unreadable store")

    def take_restart(self) -> float | None:
        """``saved_at`` of the previous run, once (the HA restart gap start)."""
        start, self._restart_from = self._restart_from, None
        return start

    @callback
    def schedule_save(self, *, enabled: bool, force: bool = False) -> None:
        """Mark a change; write at most ``DIAG_SAVE_DELAY_SECONDS`` from now.

        Off (``enabled`` False): nothing is written unless ``force`` (a
        settings change, so turning the module off is kept).
        """
        if not enabled and not force:
            return
        self.dirty = True
        if self._save_pending or self._closed:
            return
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, DIAG_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the store now."""
        await self._store.async_save(self._data_to_save())

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        self._save_pending = False
        self.dirty = False
        self.saves += 1
        self.saved_at = self.clock()
        return {
            "format": STORE_FORMAT,
            "settings": dict(self.settings),
            "history": self.history.to_dict(),
            "saved_at": self.saved_at,
        }

    @callback
    def close(self) -> None:
        """No delayed write is scheduled after this."""
        self._closed = True

    def status(self) -> dict[str, Any]:
        """Store state for the runtime status (counters only)."""
        return {
            "loaded": self.loaded,
            "load_failed": self.load_failed,
            "load_errors": self.load_errors,
            "saves": self.saves,
            "dirty": self.dirty,
            "history": self.history.status(),
        }


async def async_final_flush(hass: HomeAssistant, store: DiagStore) -> None:
    """Close the store and write it now under a claim a new load waits for."""
    store.close()
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[FLUSH_KEY] = claim
    try:
        if store.dirty:
            await store.async_flush()
    finally:
        claim.set_result(None)
        if hass.data.get(FLUSH_KEY) is claim:
            hass.data.pop(FLUSH_KEY, None)
