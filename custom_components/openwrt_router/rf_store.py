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
for the file. Nothing is evicted to make room; whatever does not fit is
dropped and counted in :attr:`RfStore.drops` (shown in the status and the
diagnostics). Daily buckets follow Home Assistant's local time zone
(DECIDED: a "day" is the user's calendar day); hourly buckets stay UTC
(``rf_aggregate`` aligns them to epoch multiples).
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections import deque
from collections.abc import Callable, Mapping
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
)
_EPOCH_ORDINAL = date(1970, 1, 1).toordinal()
_REF_SEP = "/"
_BUCKET_FIELDS = 5


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
        self._store: Store[dict[str, Any]] = Store(
            hass, WIFI_RF_STORE_VERSION, WIFI_RF_STORE_KEY, private=True
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
        self._last_payload: dict[str, Any] | None = None
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

    def _payload(self) -> dict[str, Any]:
        radios: dict[str, Any] = {}
        for ref, history in sorted(self.radios.items(), key=lambda kv: ref_key(kv[0])):
            radios[ref_key(ref)] = {
                "h": {
                    name: {str(ts): _agg_to_list(a) for ts, a in sorted(b.items())}
                    for name, b in sorted(history.hourly.items())
                },
                "d": {
                    name: {str(ts): _agg_to_list(a) for ts, a in sorted(b.items())}
                    for name, b in sorted(history.daily.items())
                },
            }
        return {"radios": radios, "drops": dict(self.drops)}

    def _data_to_save(self) -> dict[str, Any]:
        """The payload; one over the byte limit keeps the last good one."""
        payload = self._payload()
        size = store_size(payload)
        if size > self.max_bytes:
            self.drops["save_over_size"] += 1
            _LOGGER.warning(
                "WiFi RF history over %d bytes; new data not written", self.max_bytes
            )
            return self._last_payload or {"radios": {}, "drops": dict(self.drops)}
        self.last_save_bytes = size
        self._last_payload = payload
        self.dirty = False
        return payload

    def schedule_save(self) -> None:
        """Write later (one write per delay at most)."""
        self.dirty = True
        self._store.async_delay_save(self._data_to_save, WIFI_RF_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write now (last unload)."""
        await self._store.async_save(self._data_to_save())

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
        self.dirty = True

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
        if gone:
            self.schedule_save()
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
