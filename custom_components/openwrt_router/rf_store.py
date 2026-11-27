"""History of WiFi RF Intelligence (1.48.0): hourly and daily buckets.

Pattern of Client Stability's store (``client_engine``): one HA ``Store``
for the whole installation, delayed save, an explicit flush on the last
unload, a damaged file is kept as ``.bak``. What is kept:

* per radio (Core router id + UCI radio name) and series
  (:data:`SERIES`) hourly and daily :class:`.rf_aggregate.Agg` buckets;
  raw points only in memory (they feed the 1 h window);
* numbers only: no SSID, BSSID, MAC, host name or client reference.

Limits are hard and separate per series: at most ``max_radios`` radios,
``max_hourly``/``max_daily`` buckets per radio and series, and a byte limit
for the file. A new radio or bucket that does not fit its quota is dropped
and counted in :attr:`RfStore.drops` (shown in the status and the
diagnostics). Daily buckets follow Home Assistant's local time zone
(DECIDED: a "day" is the user's calendar day); hourly buckets stay UTC
(``rf_aggregate`` aligns them to epoch multiples).

Writing (1.52.3; since 1.48.0 the history was written only at shutdown and
could be reset there):

* one delayed write at a time (``_save_pending``, pattern of
  ``net_engine``/``client_engine``): HA's ``async_delay_save`` moves a
  pending write back on every call, and every poll calls ``schedule_save``;
* over the byte limit the oldest buckets are trimmed, fair by time across
  all radios (hourly first, then daily; the newest bucket of every series
  stays) to ``WIFI_RF_TRIM_HEADROOM`` below the limit, in memory too
  (``trimmed``; pattern of ``tm_store``);
* a payload that still does not fit keeps the file as loaded until the
  first good write of the run (pattern of ``traffic_store``); after that
  copy is released, such a payload is written over the limit; the history
  is never written empty because of its size;
* HA builds and serialises the payload in its executor
  (``serialize_in_event_loop=False``): the loop only copies the bucket
  dicts and applies the trim (8 MB of indented JSON took 25 to 35 ms);
* atomic writes (temporary file, then rename, like ``tm_store`` and
  ``traffic_store``): a crash during one of up to 96 writes a day never
  leaves a cut-off file;
* a router forgotten while a write is under way is written out at once.

Known limit: HA's ``Store`` catches a failed write (``WriteError``), logs
it and reports nothing back. The store then counts the write as done
(``dirty`` cleared, ``last_save_bytes`` set) although the file is older.
The next poll marks the history dirty again and arms the next write, so the
file catches up one delay later; only a failure in the last write before
an unload or shutdown is not retried.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .const import (
    WIFI_RF_MAX_DAILY_BUCKETS,
    WIFI_RF_MAX_HOURLY_BUCKETS,
    WIFI_RF_MAX_RADIOS,
    WIFI_RF_MAX_RAW_POINTS,
    WIFI_RF_MAX_STORE_BYTES,
    WIFI_RF_SAVE_DELAY_SECONDS,
    WIFI_RF_STORE_KEY,
    WIFI_RF_STORE_VERSION,
    WIFI_RF_TRIM_HEADROOM,
)
from .rf_aggregate import (
    DAY_S,
    DEFAULT_RETENTION,
    HOUR_S,
    Agg,
    bucket_start,
    series_for_window,
)
from .rf_identity import RadioRef, require_radio_id, require_router_id

_LOGGER = logging.getLogger(__name__)

SERIES_UTILIZATION = "utilization"
SERIES_NOISE = "noise"
SERIES_CLIENTS = "clients"
SERIES_RETRY_RATE = "retry_rate"
SERIES_HEALTH = "health"
SERIES_ROAMS = "roams"
SERIES_CHANNEL_CHANGES = "channel_changes"
SERIES = (
    SERIES_UTILIZATION,
    SERIES_NOISE,
    SERIES_CLIENTS,
    SERIES_RETRY_RATE,
    SERIES_HEALTH,
    SERIES_ROAMS,
    SERIES_CHANNEL_CHANGES,
)
# Counters: one value per poll; a bucket's sum is the count of the period.
COUNTER_SERIES = frozenset({SERIES_ROAMS, SERIES_CHANNEL_CHANGES})
_DROP_KEYS = (
    "radio_quota",
    "hourly_quota",
    "daily_quota",
    "raw_quota",
    "save_over_size",
    "load_invalid",
    "load_failed",
    # 1.52.3: buckets dropped to fit the file limit (1.52.2 ignores the key)
    "trimmed",
)
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
_REF_SEP = "/"
_BUCKET_FIELDS = 5
_HOURLY = "h"
_DAILY = "d"
# Rounds per part: each one re-measures and drops by the new estimate.
_TRIM_ROUNDS = 8

type _Series = dict[str, dict[int, Agg]]
# (store key, radio, hourly, daily): copies taken once per write
type _Snapshot = list[tuple[str, RadioRef, _Series, _Series]]
type _Cut = tuple[str, RadioRef, str, int]  # part, radio, series, bucket


def ref_key(ref: RadioRef) -> str:
    """Store key of a radio (``rtr_…/radio0``; ``/`` is never in a radio id)."""
    return (
        f"{require_router_id(ref.router_id)}{_REF_SEP}{require_radio_id(ref.radio_id)}"
    )


def parse_ref_key(key: Any) -> RadioRef | None:
    """The radio of a store key, None for anything else."""
    if not isinstance(key, str) or key.count(_REF_SEP) != 1:
        return None
    router_id, radio_id = key.split(_REF_SEP)
    try:
        return RadioRef(require_router_id(router_id), require_radio_id(radio_id))
    except ValueError:
        return None


def local_day_key(ts: float, tz: Any = None) -> int:
    """Daily bucket key: the local calendar day as a UTC-aligned day start.

    ``rf_aggregate`` aligns buckets to multiples of 86400; the local date's
    ordinal times 86400 is such a multiple, so its helpers work unchanged
    and a day never splits at UTC midnight (DST days included).
    """
    zone = tz or dt_util.get_default_time_zone()
    day = datetime.fromtimestamp(ts, UTC).astimezone(zone).date()
    return (day.toordinal() - _EPOCH_ORDINAL) * DAY_S


def local_day_start(key: int, tz: Any = None) -> float:
    """Epoch seconds of local midnight of a daily key (inverse of the above)."""
    zone = tz or dt_util.get_default_time_zone()
    day = date.fromordinal(key // DAY_S + _EPOCH_ORDINAL)
    return datetime.combine(day, time(0), zone).timestamp()


def _agg_to_list(agg: Agg) -> list[Any]:
    return [agg.count, agg.total, agg.minimum, agg.maximum, agg.invalid]


def _number(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _agg_from_list(raw: Any) -> Agg | None:
    if not isinstance(raw, list) or len(raw) != _BUCKET_FIELDS:
        return None
    count, total, low, high, invalid = raw
    if not (isinstance(count, int) and isinstance(invalid, int)) or isinstance(
        count, bool
    ):
        return None
    if count < 0 or invalid < 0 or not _number(total):
        return None
    if (low is None) != (high is None) or (low is not None and not _number(low)):
        return None
    if high is not None and not _number(high):
        return None
    return Agg(count, float(total), low, high, invalid)


def _buckets_from_raw(raw: Any) -> dict[int, Agg] | None:
    if not isinstance(raw, dict):
        return None
    out: dict[int, Agg] = {}
    for ts, value in raw.items():
        if not isinstance(ts, str) or not ts.isdigit():
            return None
        agg = _agg_from_list(value)
        if agg is None:
            return None
        out[int(ts)] = agg
    return out


def _series_out(series: _Series) -> dict[str, Any]:
    return {
        name: {str(ts): _agg_to_list(a) for ts, a in sorted(buckets.items())}
        for name, buckets in sorted(series.items())
    }


def _build(snapshot: _Snapshot, drops: Mapping[str, int]) -> dict[str, Any]:
    """The store payload of a snapshot (sorted by store key)."""
    return {
        "radios": {
            key: {"h": _series_out(hourly), "d": _series_out(daily)}
            for key, _ref, hourly, daily in snapshot
        },
        "drops": dict(drops),
    }


def _trim(
    snapshot: _Snapshot, drops: dict[str, int], size: int, target: int
) -> tuple[dict[str, Any] | None, int, list[_Cut]]:
    """Drop the oldest buckets of the snapshot until it is at ``target``.

    Hourly first, then daily; within a part strictly by bucket time across
    every radio and series (never radio by radio), and the newest bucket of
    each series always stays. Each round drops the excess divided by the
    mean bytes per bucket of the whole file (the per-radio overhead makes
    that a little high, so a round rather trims too little than too much)
    and re-measures. Daily buckets go only once no hourly one is left to
    drop. Works on the snapshot's own copies; ``drops["trimmed"]`` counts
    the cuts. Returns the new payload (None: nothing dropped), its size and
    the cuts.
    """
    payload: dict[str, Any] | None = None
    cuts: list[_Cut] = []
    for part in (_HOURLY, _DAILY):
        for _round in range(_TRIM_ROUNDS):
            if size <= target:
                return payload, size, cuts
            total = 0
            candidates: list[tuple[int, str, str, RadioRef, dict[int, Agg]]] = []
            for key, ref, hourly, daily in snapshot:
                for series_part, series in ((_HOURLY, hourly), (_DAILY, daily)):
                    for name, buckets in series.items():
                        total += len(buckets)
                        if series_part != part or len(buckets) < 2:
                            continue
                        newest = max(buckets)
                        candidates.extend(
                            (ts, key, name, ref, buckets)
                            for ts in buckets
                            if ts != newest
                        )
            if not candidates:
                break
            per = max(1.0, size / total)
            drop = min(len(candidates), math.ceil((size - target) / per))
            candidates.sort(key=lambda c: (c[0], c[1], c[2]))
            for ts, _key, name, ref, buckets in candidates[:drop]:
                del buckets[ts]
                cuts.append((part, ref, name, ts))
            drops["trimmed"] = drops.get("trimmed", 0) + drop
            payload = _build(snapshot, drops)
            size = store_size(payload)
        else:
            # rounds used up with hourly buckets left: no daily bucket goes
            # (the payload may sit between the target and the limit)
            return payload, size, cuts
    return payload, size, cuts


@dataclass(slots=True)
class _Prepared:
    """What one write produced (built off the loop, applied in it)."""

    payload: dict[str, Any]
    size: int
    generation: int
    cuts: list[_Cut] = field(default_factory=list)
    fresh: bool = True  # False: the last good payload is written again
    over: bool = False  # still over the limit after trimming


class _RadioHistory:
    """Buckets of one radio: series -> {bucket start -> Agg}."""

    def __init__(self) -> None:
        self.hourly: dict[str, dict[int, Agg]] = {}
        self.daily: dict[str, dict[int, Agg]] = {}
        self.raw: dict[str, deque[tuple[float, float | None]]] = {}


class RfStore:
    """Hourly/daily RF history of every radio with hard, separate quotas."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        max_radios: int = WIFI_RF_MAX_RADIOS,
        max_hourly: int = WIFI_RF_MAX_HOURLY_BUCKETS,
        max_daily: int = WIFI_RF_MAX_DAILY_BUCKETS,
        max_raw: int = WIFI_RF_MAX_RAW_POINTS,
        max_bytes: int = WIFI_RF_MAX_STORE_BYTES,
        tz: Callable[[], Any] | None = None,
    ) -> None:
        """Empty history; :meth:`async_load` reads the file."""
        self.hass = hass
        # serialize_in_event_loop=False: HA calls _data_to_save and writes
        # the JSON in its executor (up to 8 MB; see the module docstring).
        # atomic_writes: temporary file + rename, never a cut-off file.
        self._store: Store[dict[str, Any]] = Store(
            hass,
            WIFI_RF_STORE_VERSION,
            WIFI_RF_STORE_KEY,
            private=True,
            atomic_writes=True,
            serialize_in_event_loop=False,
        )
        self.max_radios = max_radios
        self.max_hourly = max_hourly
        self.max_daily = max_daily
        self.max_raw = max_raw
        self.max_bytes = max_bytes
        self._tz = tz or dt_util.get_default_time_zone
        self.radios: dict[RadioRef, _RadioHistory] = {}
        self.drops: dict[str, int] = dict.fromkeys(_DROP_KEYS, 0)
        self.loaded = False
        self.dirty = False
        self.last_save_bytes: int | None = None
        # The file as loaded: written again when a payload cannot be trimmed
        # under the limit; released after the first good write (several MB).
        self._last_payload: dict[str, Any] | None = None
        # True while a delayed write is armed: HA's async_delay_save moves a
        # pending write back on every call, so it is called once (1.52.3).
        self._save_pending = False
        # Counts changes: a write clears ``dirty`` only if nothing changed
        # since its snapshot.
        self._generation = 0
        # generation of the last forget_router that removed something
        self._forgot_at = -1
        self._trim_warned = False
        self._lock = asyncio.Lock()

    # -- load / save -------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the file once; a damaged file is kept as ``.bak``."""
        async with self._lock:
            if self.loaded:
                return
            try:
                raw = await self._store.async_load()
            except Exception as err:  # noqa: BLE001 - start empty, keep the file
                self.drops["load_failed"] += 1
                _LOGGER.warning(
                    "WiFi RF history unreadable (%s); kept as .bak, starting empty",
                    type(err).__name__,
                )
                await self._async_backup()
                raw = None
            self._apply(raw)
            self.loaded = True

    async def _async_backup(self) -> None:
        from .net_engine import _backup_file

        try:
            await self.hass.async_add_executor_job(
                _backup_file, getattr(self._store, "path", None)
            )
        except Exception as err:  # noqa: BLE001 - the backup is best effort
            _LOGGER.debug("WiFi RF history backup failed (%s)", type(err).__name__)

    def _apply(self, raw: Any) -> None:
        if not isinstance(raw, dict):
            return
        # The file as read counts as the last good payload: a first write
        # over the limit keeps it instead of an empty history (1.52.3).
        self._last_payload = dict(raw)
        drops = raw.get("drops")
        if isinstance(drops, dict):
            for key in _DROP_KEYS:
                value = drops.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                    self.drops[key] = value
        radios = raw.get("radios")
        if not isinstance(radios, dict):
            return
        for key, entry in radios.items():
            ref = parse_ref_key(key)
            history = self._history_from_raw(entry)
            if ref is None or history is None or len(self.radios) >= self.max_radios:
                self.drops["load_invalid"] += 1
                continue
            self.radios[ref] = history

    def _history_from_raw(self, entry: Any) -> _RadioHistory | None:
        if not isinstance(entry, dict):
            return None
        history = _RadioHistory()
        for part, target, limit in (
            ("h", history.hourly, self.max_hourly),
            ("d", history.daily, self.max_daily),
        ):
            series = entry.get(part, {})
            if not isinstance(series, dict):
                return None
            for name, raw_buckets in series.items():
                buckets = _buckets_from_raw(raw_buckets)
                if name not in SERIES or buckets is None or len(buckets) > limit:
                    return None
                target[name] = buckets
        return history

    def _snapshot(self) -> _Snapshot:
        """Copies of every bucket dict, sorted by store key.

        Safe from HA's executor thread: each ``list(...)``/``dict(...)`` copy
        is one C call under the GIL and an :class:`Agg` is immutable, so a
        copy is never torn by a poll; the series of one radio may be one poll
        apart, which the next write evens out.
        """
        out: _Snapshot = []
        for ref, history in list(self.radios.items()):
            out.append(
                (
                    ref_key(ref),
                    ref,
                    {n: dict(b) for n, b in list(history.hourly.items())},
                    {n: dict(b) for n, b in list(history.daily.items())},
                )
            )
        out.sort(key=lambda item: item[0])
        return out

    def _payload(self) -> dict[str, Any]:
        return _build(self._snapshot(), self.drops)

    def _prepare(
        self, snapshot: _Snapshot, drops: dict[str, int], generation: int
    ) -> _Prepared:
        """Payload of a snapshot, trimmed to the limit (no state change)."""
        payload = _build(snapshot, drops)
        size = store_size(payload)
        cuts: list[_Cut] = []
        if size > self.max_bytes:
            target = int(self.max_bytes * (1 - WIFI_RF_TRIM_HEADROOM))
            trimmed, size, cuts = _trim(snapshot, drops, size, target)
            payload = trimmed or payload
        if size <= self.max_bytes:
            return _Prepared(payload, size, generation, cuts)
        if self._last_payload is not None:
            return _Prepared(
                self._last_payload, size, generation, fresh=False, over=True
            )
        # Nothing on disk to keep: write the history rather than an empty one.
        drops["save_over_size"] = drops.get("save_over_size", 0) + 1
        payload = _build(snapshot, drops)
        return _Prepared(payload, store_size(payload), generation, cuts, over=True)

    def _data_to_save(self) -> dict[str, Any]:
        """The payload, trimmed to the limit; never empty because of size.

        HA calls it in its executor (``serialize_in_event_loop=False``),
        :meth:`async_flush` too; the trim and the counters are applied in the
        event loop afterwards (directly when called from the loop).
        """
        self._save_pending = False
        generation = self._generation
        prepared = self._prepare(self._snapshot(), dict(self.drops), generation)
        self._in_loop(self._saved, prepared)
        return prepared.payload

    def _in_loop(self, func: Callable[[_Prepared], None], prepared: _Prepared) -> None:
        try:
            asyncio.get_running_loop()
        except RuntimeError:  # HA's executor thread
            try:
                self.hass.loop.call_soon_threadsafe(func, prepared)
            except RuntimeError:  # loop closed (after the final write)
                _LOGGER.debug("WiFi RF history: loop closed after the write")
            return
        func(prepared)

    def _saved(self, prepared: _Prepared) -> None:
        """Apply a write's result in the loop: trim memory as the file was."""
        removed = 0
        for part, ref, name, ts in prepared.cuts:
            history = self.radios.get(ref)
            if history is None:
                continue
            series = history.hourly if part == _HOURLY else history.daily
            buckets = series.get(name)
            # an overlapping write may have removed it already: count once
            if buckets is not None and buckets.pop(ts, None) is not None:
                removed += 1
        if removed:
            self.drops["trimmed"] += removed
            _LOGGER.log(
                logging.DEBUG if self._trim_warned else logging.WARNING,
                "WiFi RF history over %d bytes; the oldest %d buckets were dropped "
                "(hourly first); later trims are logged at debug level",
                self.max_bytes,
                removed,
            )
            self._trim_warned = True
        if prepared.over:
            self.drops["save_over_size"] += 1
            _LOGGER.warning(
                "WiFi RF history still over %d bytes after trimming; %s",
                self.max_bytes,
                "the last good file is kept"
                if not prepared.fresh
                else "written over the limit",
            )
        if prepared.fresh:
            self.last_save_bytes = prepared.size
            # A good payload reached the writer: the loaded copy (several MB)
            # is no longer needed. A later payload that cannot be trimmed is
            # written over the limit instead, never an empty one.
            self._last_payload = None
            if self._generation == prepared.generation:
                self.dirty = False
        if self._forgot_at > prepared.generation:
            # A router was forgotten after this write's snapshot, so the file
            # still has it: write again now, not in a delay (privacy).
            self._arm(0)

    def _changed(self) -> None:
        self.dirty = True
        self._generation += 1

    def _arm(self, delay: float) -> None:
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, delay)

    def schedule_save(self) -> None:
        """Arm one delayed write (none while one is pending)."""
        self._changed()
        if self._save_pending:
            return
        self._arm(WIFI_RF_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write now (last unload); the payload is built in the executor."""
        payload = await self.hass.async_add_executor_job(self._data_to_save)
        await self._store.async_save(payload)

    # -- record ------------------------------------------------------------------

    def record(self, ref: RadioRef, values: Mapping[str, Any], ts: float) -> None:
        """Add one poll's values (None = unknown, counted as invalid)."""
        history = self.radios.get(ref)
        if history is None:
            if len(self.radios) >= self.max_radios:
                self.drops["radio_quota"] += 1
                return
            history = self.radios[ref] = _RadioHistory()
        hour = bucket_start(ts, HOUR_S)
        day = local_day_key(ts, self._tz())
        for name in SERIES:
            if name not in values:
                continue
            value = values[name]
            self._add(
                history.hourly,
                name,
                hour,
                value,
                ts,
                DEFAULT_RETENTION.hourly_s,
                self.max_hourly,
                "hourly_quota",
            )
            self._add_daily(history, name, day, value)
            self._add_raw(history, name, ts, value)
        self._changed()

    def _add(
        self,
        series: dict[str, dict[int, Agg]],
        name: str,
        key: int,
        value: Any,
        now: float,
        keep_s: int,
        limit: int,
        drop: str,
    ) -> None:
        buckets = series.setdefault(name, {})
        cutoff = now - keep_s
        for old in [ts for ts in buckets if ts < cutoff]:
            del buckets[old]
        if key not in buckets and len(buckets) >= limit:
            self.drops[drop] += 1
            return
        buckets[key] = buckets.get(key, Agg()).add(value)

    def _add_daily(
        self, history: _RadioHistory, name: str, day: int, value: Any
    ) -> None:
        buckets = history.daily.setdefault(name, {})
        cutoff = day - (self.max_daily - 1) * DAY_S
        for old in [ts for ts in buckets if ts < cutoff]:
            del buckets[old]
        if day not in buckets and len(buckets) >= self.max_daily:
            self.drops["daily_quota"] += 1
            return
        buckets[day] = buckets.get(day, Agg()).add(value)

    def _add_raw(
        self, history: _RadioHistory, name: str, ts: float, value: Any
    ) -> None:
        points = history.raw.setdefault(name, deque())
        cutoff = ts - DEFAULT_RETENTION.raw_s
        while points and points[0][0] < cutoff:
            points.popleft()
        if len(points) >= self.max_raw:
            self.drops["raw_quota"] += 1
            return
        points.append((ts, value if _number(value) else None))

    # -- read ----------------------------------------------------------------------

    def series(
        self, ref: RadioRef, name: str, window: str, now: float
    ) -> dict[str, Any]:
        """One series of a radio for a window (gaps are None, never 0)."""
        if name not in SERIES:
            raise ValueError(f"unknown series: {name!r}")
        history = self.radios.get(ref) or _RadioHistory()
        raw = list(history.raw.get(name, ()))
        hourly = history.hourly.get(name, {})
        daily = history.daily.get(name, {})
        tz = self._tz()
        probe = series_for_window(raw, hourly, {}, now=now, window=window)
        if probe.source != "daily":
            out = probe.as_dict()
        else:
            # Daily keys are local days: shift "now" onto the same scale.
            today = local_day_key(now, tz)
            local_now = today + (now - local_day_start(today, tz))
            out = series_for_window(
                raw, hourly, daily, now=local_now, window=window
            ).as_dict()
            for point in out["points"]:
                point["ts"] = local_day_start(point["ts"], tz)
        if name in COUNTER_SERIES:
            for point in out["points"]:
                mean = point["mean"]
                point["total"] = None if mean is None else round(mean * point["count"])
        out["series"] = name
        return out

    def latest(self, ref: RadioRef, name: str) -> float | None:
        """Newest raw value of a series (None when unknown)."""
        history = self.radios.get(ref)
        points = history.raw.get(name) if history else None
        return points[-1][1] if points else None

    def routers(self) -> set[str]:
        """Router ids with history."""
        return {ref.router_id for ref in self.radios}

    def forget_router(self, router_id: str) -> bool:
        """Drop every radio of a router; True if something was dropped."""
        gone = [ref for ref in self.radios if ref.router_id == router_id]
        for ref in gone:
            del self.radios[ref]
        # the kept last good payload must not bring the router back (1.52.3)
        last = self._last_payload
        radios = last.get("radios") if last is not None else None
        kept_it = False
        if isinstance(radios, dict):
            prefix = f"{router_id}{_REF_SEP}"
            left = {
                k: v
                for k, v in radios.items()
                if not (isinstance(k, str) and k.startswith(prefix))
            }
            kept_it = len(left) < len(radios)
            self._last_payload = {**last, "radios": left}
        if gone or kept_it:
            # privacy: the router leaves the file now, not after a delay
            self._changed()
            self._forgot_at = self._generation
            self._arm(0)
        return bool(gone)

    def stats(self) -> dict[str, Any]:
        """Sizes and drop counters (no ids)."""
        return {
            "radios": len(self.radios),
            "max_radios": self.max_radios,
            "last_save_bytes": self.last_save_bytes,
            "max_bytes": self.max_bytes,
            "drops": dict(self.drops),
        }


def store_size(payload: Mapping[str, Any]) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    # HA's own file wrapper: its field names are no RF output fields (a dict
    # literal would put HA's "key" into the RF field-name check)
    wrapped = dict(  # noqa: C408
        version=WIFI_RF_STORE_VERSION,
        minor_version=1,
        key=WIFI_RF_STORE_KEY,
        data=payload,
    )
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


__all__ = [
    "COUNTER_SERIES",
    "SERIES",
    "RfStore",
    "local_day_key",
    "local_day_start",
    "parse_ref_key",
    "ref_key",
    "store_size",
]
