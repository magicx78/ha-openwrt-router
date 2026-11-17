"""Client stability API of the topology panel (B5): builders and routes.

Read-only views over the client stability engine (``client_engine``): the
client table, one client's detail with series, the AP comparison and the
settings. Same access rules as the network intelligence routes (P7): admin
or every user while an entry opens the panel to all, 410 after the last
unload, writing admin only; 503 while the engine has not read its store.

The builders are pure functions of the engine state and make no router call.
Like the topology panel they show MACs, IPs and hostnames to the panel user;
nothing of that goes to the log.
"""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import fields, is_dataclass
from typing import Any

import voluptuous as vol
from aiohttp import web
from homeassistant.core import HomeAssistant
from homeassistant.helpers.http import KEY_HASS
from homeassistant.util import dt as dt_util

from .client_analysis import (
    CLASS_CRITICAL,
    CLASS_NOTICEABLE,
    CLASS_STABLE,
    CLASS_UNKNOWN,
    CLASS_UNSTABLE,
    CLASS_VERY_STABLE,
    PARTS,
    WINDOW_7D,
    WINDOW_24H,
    WINDOW_30D,
    WINDOWS,
    ApReconnects,
    ClientFindings,
    ScoreResult,
    WindowStats,
    ap_comparison,
    ap_pattern,
    ap_reconnects,
    attribute_disconnects,
    data_days,
    disconnect_ends,
    notable_events,
    recommend_aps,
    recommend_client,
    roam_burst,
    roam_steps,
    score_trend,
    score_window,
    signal_trend,
    time_pattern,
    timeline_segments,
)
from .client_engine import ClientStability, async_get_client_engine, default_settings
from .client_history import (
    RETENTION_DAYS_MAX,
    STATE_OFFLINE,
    STATES,
    Bucket,
    ClientLive,
    LastDisconnect,
    Transition,
    band_key,
    band_online,
    normalize_mac,
    session_histogram,
    sum_buckets,
)
from .const import CLIENT_ENTITY_MAX
from .net_query import QueryError
from .topology_panel import _INTEL_URL, _IntelView, _NameOf, _router_names

_LOGGER = logging.getLogger(__name__)

_HOUR = 3600
_DAY = 86400

TABLE_LIMIT_DEFAULT = 100
TABLE_LIMIT_MAX = 500
_CURSOR_MAX = 1_000_000
_PARAM_MAX = 64
SERIES_MAX = 720
SLEEPY_MAX = 1000
STORE_MB_RANGE = (1, 8)

WINDOW_1H = "1h"
DETAIL_WINDOWS = (WINDOW_1H, WINDOW_24H, WINDOW_7D, WINDOW_30D)
_WINDOW_S = {
    WINDOW_1H: _HOUR,
    WINDOW_24H: _DAY,
    WINDOW_7D: 7 * _DAY,
    WINDOW_30D: 30 * _DAY,
}
_WINDOW_HOURS = {WINDOW_1H: 1, WINDOW_24H: 24, WINDOW_7D: 168}
CLASSES = (
    CLASS_VERY_STABLE,
    CLASS_STABLE,
    CLASS_NOTICEABLE,
    CLASS_UNSTABLE,
    CLASS_CRITICAL,
    CLASS_UNKNOWN,
)

# Table sort keys -> row value (None sorts last in both directions).
_SORTS: dict[str, Callable[[Mapping[str, Any]], Any]] = {
    "score": lambda r: r["score"],
    "name": lambda r: (r["name"] or r["mac"]).casefold(),
    "availability": lambda r: r["availability_24h"],
    "coverage": lambda r: r["coverage"],
    "reconnects": lambda r: r["reconnects_24h"],
    "last_disconnect": lambda r: (r["last_disconnect"] or {}).get("ts"),
    "last_seen": lambda r: r["last_seen"],
    # [CS 1.43] AP (by name), 7-day availability, trend and last problem
    "router": lambda r: (r["router_name"] or r["router"] or "").casefold() or None,
    "availability_7d": lambda r: r["availability_7d"],
    "trend": lambda r: r["trend_delta"],
    "last_problem": lambda r: (r["last_problem"] or {}).get("ts"),
}
# Sort keys that need the 7-day values of every row (hourly cache).
_WEEK_SORTS = frozenset({"availability_7d", "trend"})


# --- request parsing -------------------------------------------------------------


def _text(query: Mapping[str, str], name: str) -> str | None:
    value = query.get(name)
    if value is None or value == "":
        return None
    if len(value) > _PARAM_MAX:
        raise QueryError(f"{name}: too long")
    return value


def _choice(query: Mapping[str, str], name: str, allowed: Iterable[str]) -> str | None:
    value = _text(query, name)
    if value is not None and value not in tuple(allowed):
        raise QueryError(f"{name}: unknown value")
    return value


def _count(
    query: Mapping[str, str], name: str, default: int, low: int, high: int
) -> int:
    raw = _text(query, name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise QueryError(f"{name}: integer expected") from None
    if not low <= value <= high:
        raise QueryError(f"{name}: must be between {low} and {high}")
    return value


def parse_table_query(query: Mapping[str, str]) -> dict[str, Any]:
    """Filters, sort and page of ``GET clients``."""
    band_raw = _text(query, "band")
    band = band_key(band_raw) if band_raw is not None else None
    if band_raw is not None and band is None:
        raise QueryError("band: unknown value")
    sort = _text(query, "sort") or "score"
    desc = sort.startswith("-")
    key = sort[1:] if desc else sort
    if key not in _SORTS:
        raise QueryError("sort: unknown value")
    search = _text(query, "q")
    return {
        "router": _text(query, "router"),
        "band": band,
        "ssid": _text(query, "ssid"),
        "cls": _choice(query, "class", CLASSES),
        "state": _choice(query, "state", sorted(STATES)),
        "search": search.casefold() if search is not None else None,
        "sort": key,
        "desc": desc,
        "limit": _count(query, "limit", TABLE_LIMIT_DEFAULT, 1, TABLE_LIMIT_MAX),
        "offset": _count(query, "cursor", 0, 0, _CURSOR_MAX),
    }


def parse_mac(value: str) -> str:
    """The client MAC of a route path."""
    mac = normalize_mac(value)
    if mac is None:
        raise QueryError("mac: not a MAC address")
    return mac


def parse_window(
    query: Mapping[str, str], allowed: tuple[str, ...], default: str = WINDOW_24H
) -> str:
    """The ``window`` parameter (``1h``/``24h``/``7d``/``30d``)."""
    return _choice(query, "window", allowed) or default


# --- small serializers ---------------------------------------------------------------


def _round(value: float | None, digits: int = 1) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return round(float(value), digits)


def plain(value: Any) -> Any:
    """Dataclasses, mappings and tuples as JSON values (floats rounded)."""
    if is_dataclass(value) and not isinstance(value, type):
        return {f.name: plain(getattr(value, f.name)) for f in fields(value)}
    if isinstance(value, Mapping):
        return {str(k): plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(v) for v in value]
    if isinstance(value, float):
        return _round(value, 3)
    return value


def _last_disconnect(last: LastDisconnect | None) -> dict[str, Any] | None:
    if last is None:
        return None
    return {
        "ts": last.ts,
        "reason": last.reason,
        "class": last.cls,
        "timed": last.timed,
    }


def _last_problem(live: ClientLive) -> dict[str, Any] | None:
    """The newer of the last disconnect and the last auth, association or
    DHCP failure (1.43)."""
    dc, fail = live.last_disconnect, live.last_failure
    if fail is not None and (dc is None or fail.ts > dc.ts):
        return {"ts": fail.ts, "kind": fail.kind, "class": None, "reason": None}
    if dc is not None:
        return {"ts": dc.ts, "kind": "disconnect", "class": dc.cls, "reason": dc.reason}
    return None


def _score(result: ScoreResult) -> dict[str, Any]:
    return {
        "score": _round(result.score),
        "class": result.cls,
        "coverage": _round(result.coverage, 2),
        "parts": {part: plain(value) for part, value in result.parts.items()},
    }


def _stats(stats: WindowStats) -> dict[str, Any]:
    b = stats.bucket
    online = float(b.online_s)
    has_rssi = b.rssi_n > 0
    finished = sum(stats.session_hist)
    return {
        "start": stats.start,
        "memory_from": stats.memory_from,
        "window_s": _round(stats.window_s, 0),
        "observed_s": b.observed_s,
        "online_s": b.online_s,
        "gap_s": b.gap_s,
        "coverage": _round(stats.coverage, 3),
        "availability": _round(stats.availability, 3),
        "sessions": b.sessions,
        "longest_stable_s": b.longest_stable_s,
        "ongoing_h": _round(stats.ongoing_h, 2),
        "disconnects": {
            "error": b.dc_error,
            "unknown": b.dc_unknown,
            "inactivity": b.dc_inactivity,
            "leave": b.dc_leave,
            "infra": b.dc_infra,
        },
        "reconnects": b.reconnects,
        "roams_in": b.roams_in,
        "roams_out": b.roams_out,
        "roam_flaps": b.roam_flaps,
        "band_changes": b.band_changes,
        "auth_fail": b.auth_fail,
        "assoc_fail": b.assoc_fail,
        "dhcp_fail": b.dhcp_fail,
        "rssi_n": b.rssi_n,
        "rssi_mean": _round(b.rssi_sum / b.rssi_n) if has_rssi else None,
        "rssi_min": b.rssi_min if has_rssi else None,
        "rssi_max": b.rssi_max if has_rssi else None,
        "weak_share": _round(min(1.0, b.weak_s / online), 3) if online > 0 else None,
        "rate_rx_kbit": round(b.rate_rx_sum / b.rate_n) if b.rate_n else None,
        "rate_tx_kbit": round(b.rate_tx_sum / b.rate_n) if b.rate_n else None,
        "log_coverage": _round(stats.log_coverage, 2),
        # [CS 1.43] finished sessions and their mean length, the share of
        # samples with a known IP (not end-to-end reachability; denominator:
        # samples with a signal value) and the notable events
        "finished_sessions": finished,
        "session_mean_s": round(b.session_s_sum / finished) if finished else None,
        "ip_visible_share": (
            _round(min(1.0, b.ip_visible_n / b.rssi_n), 3) if has_rssi else None
        ),
        "notable_events": notable_events(b),
    }


def _main_ap(items: list[tuple[str, Bucket]]) -> tuple[str | None, str | None]:
    """AP with the most online time in a series point and its main band
    (None when the band was not reported)."""
    online: dict[str, int] = {}
    bands: dict[str, dict[str, int]] = {}
    for ap, b in items:
        if not ap or b.online_s <= 0:
            continue
        online[ap] = online.get(ap, 0) + b.online_s
        per = bands.setdefault(ap, {})
        for band, secs in band_online(b).items():
            per[band] = per.get(band, 0) + secs
    if not online:
        return None, None
    ap = max(sorted(online), key=lambda a: online[a])
    known = {band: secs for band, secs in bands[ap].items() if secs > 0}
    return ap, max(sorted(known), key=lambda k: known[k]) if known else None


def _point(t: float, items: list[tuple[str, Bucket]]) -> dict[str, Any]:
    """One series point (an hour or a day) from the buckets of all APs."""
    b = sum_buckets(bucket for _ap, bucket in items)
    has_rssi = b.rssi_n > 0
    ap, band = _main_ap(items)
    return {
        "t": t,
        "aps": sorted({ap for ap, _b in items if ap}),
        "ap": ap,
        "band": band,
        "observed_s": b.observed_s,
        "online_s": b.online_s,
        "gap_s": b.gap_s,
        "disconnects": b.dc_error + b.dc_unknown + b.dc_inactivity,
        "infra": b.dc_infra,
        "leaves": b.dc_leave,
        "reconnects": b.reconnects,
        "roams": b.roams_in,
        "flaps": b.roam_flaps,
        "auth_fail": b.auth_fail + b.assoc_fail,
        "dhcp_fail": b.dhcp_fail,
        "rssi_n": b.rssi_n,
        "rssi_mean": _round(b.rssi_sum / b.rssi_n) if has_rssi else None,
        "rssi_min": b.rssi_min if has_rssi else None,
        "rssi_max": b.rssi_max if has_rssi else None,
    }


# --- table -------------------------------------------------------------------------


def _base_row(
    cs: ClientStability,
    live: ClientLive,
    name_of: _NameOf,
    now: float,
    entity: frozenset[str],
    sleepy: frozenset[str],
) -> dict[str, Any] | None:
    """The table values every client needs for filtering and sorting."""
    found = cs.window(live.mac, now, 24)
    if found is None:
        return None
    stats, result = found
    offline = live.state == STATE_OFFLINE
    return {
        "mac": live.mac,
        "name": live.hostname,
        "ip": live.ip,
        "private_mac": live.private_mac,
        "router": live.ap,
        "router_name": name_of(live.ap) if live.ap else None,
        "band": live.band,
        "ssid": cs.ssid(live.mac),
        "state": live.state,
        "rssi": None if offline else live.rssi,
        "since": live.since,
        "session_start": None if offline else live.session_start,
        "last_seen": live.last_seen,
        "score": _round(result.score),
        "class": result.cls,
        "score_coverage": _round(result.coverage, 2),
        "coverage": _round(stats.coverage, 2),
        "availability_24h": _round(stats.availability, 3),
        "reconnects_24h": (
            int(stats.bucket.reconnects) if cs.log_coverage(live.ap) else None
        ),
        "last_disconnect": _last_disconnect(live.last_disconnect),
        "last_problem": _last_problem(live),
        "entity": live.mac in entity,
        "sleepy": live.mac in sleepy,
    }


def _matches(row: Mapping[str, Any], params: Mapping[str, Any]) -> bool:
    for key, field_name in (
        ("router", "router"),
        ("band", "band"),
        ("ssid", "ssid"),
        ("cls", "class"),
        ("state", "state"),
    ):
        wanted = params.get(key)
        if wanted is not None and row[field_name] != wanted:
            return False
    search = params.get("search")
    if search:
        hay = (row["mac"], row["name"] or "", row["ip"] or "")
        if not any(search in text.casefold() for text in hay):
            return False
    return True


def _sorted(rows: list[dict[str, Any]], key: str, desc: bool) -> list[dict[str, Any]]:
    value = _SORTS[key]
    known = [r for r in rows if value(r) is not None]
    missing = [r for r in rows if value(r) is None]
    known.sort(key=lambda r: (value(r), r["mac"]), reverse=desc)
    missing.sort(key=lambda r: r["mac"])
    return known + missing


def _page_row(cs: ClientStability, row: dict[str, Any], now: float) -> dict[str, Any]:
    """Seven-day values and the trend (the rows of the page, or every row
    when sorting by them; cached per hour by the engine)."""
    week = cs.week_values(row["mac"], now)
    previous = week.score_previous_24h if week is not None else None
    score = row["score"]
    return {
        **row,
        "score_7d": _round(week.score_7d) if week is not None else None,
        "availability_7d": _round(week.availability_7d, 3) if week else None,
        "score_previous_24h": _round(previous),
        "trend": score_trend(score, previous),
        "trend_delta": (
            _round(score - previous)
            if score is not None and previous is not None
            else None
        ),
    }


def clients_table(
    cs: ClientStability, name_of: _NameOf, now: float, params: Mapping[str, Any]
) -> dict[str, Any]:
    """``GET clients``: one page of the client table, worst first."""
    entity = frozenset(cs.settings["entity_macs"])
    sleepy = frozenset(cs.settings["sleepy_macs"])
    rows: list[dict[str, Any]] = []
    routers: set[str] = set()
    ssids: set[str] = set()
    for mac in cs.history.macs():
        live = cs.history.live(mac)
        if live is None:
            continue
        row = _base_row(cs, live, name_of, now, entity, sleepy)
        if row is None:
            continue
        if row["router"]:
            routers.add(row["router"])
        if row["ssid"]:
            ssids.add(row["ssid"])
        if _matches(row, params):
            rows.append(row)
    week_sort = params["sort"] in _WEEK_SORTS
    if week_sort:
        rows = [_page_row(cs, row, now) for row in rows]
    rows = _sorted(rows, params["sort"], params["desc"])
    offset, limit = params["offset"], params["limit"]
    page = [
        row if week_sort else _page_row(cs, row, now)
        for row in rows[offset : offset + limit]
    ]
    end = offset + limit
    return {
        "now": now,
        "enabled": cs.settings["enabled"],
        "total": len(rows),
        "clients": page,
        "next_cursor": str(end) if end < len(rows) else None,
        "routers": [{"id": r, "name": name_of(r)} for r in sorted(routers)],
        "ssids": sorted(ssids),
    }


# --- detail ------------------------------------------------------------------------


def _hour_series(
    cs: ClientStability, mac: str, first_hour: int, last_hour: int
) -> list[dict[str, Any]]:
    grouped: dict[int, list[tuple[str, Bucket]]] = {}
    for h in cs.history.hours(mac, first_hour, last_hour):
        grouped.setdefault(h.hour, []).append((h.ap, h.bucket))
    return [_point(hour * _HOUR, items) for hour, items in sorted(grouped.items())][
        -SERIES_MAX:
    ]


def _day_series(cs: ClientStability, mac: str, first_day: int) -> list[dict[str, Any]]:
    grouped: dict[int, list[tuple[str, Bucket]]] = {}
    for d in cs.history.days(mac, first_day):
        grouped.setdefault(d.day, []).append((d.ap, d.bucket))
    for h in cs.history.hours(mac, first_day * 24, open_only=True):
        grouped.setdefault(h.hour // 24, []).append((h.ap, h.bucket))
    return [_point(day * _DAY, items) for day, items in sorted(grouped.items())][
        -SERIES_MAX:
    ]


def _series(
    cs: ClientStability, mac: str, now: float, window: str
) -> list[dict[str, Any]]:
    """Merged buckets per hour (up to 7 d) or per day (30 d)."""
    if window == WINDOW_30D:
        return _day_series(cs, mac, int(now // _DAY) - 29)
    last = math.ceil(now / _HOUR) - 1
    return _hour_series(cs, mac, last - _WINDOW_HOURS[window] + 1, last)


def _score_series(
    cs: ClientStability, live: ClientLive, now: float, window: str
) -> list[dict[str, Any]]:
    """Score history: trailing 24 h per hour (24 h) or per day (7 d), the
    score of each day (30 d); none for 1 h."""
    mac = live.mac
    first = live.first_seen if live.first_seen is not None else now
    if window == WINDOW_30D:
        return _day_scores(cs, live, now, first)
    if window == WINDOW_24H:
        last = math.ceil(now / _HOUR) - 1
        ends = [(last - k) * _HOUR for k in range(23, 0, -1)] + [now]
    elif window == WINDOW_7D:
        ends = [now - k * _DAY for k in range(6, -1, -1)]
    else:
        return []
    out: list[dict[str, Any]] = []
    for end in ends:
        if end <= first:
            continue
        result = cs.score(mac, now, 24, end=end)
        if result is not None:
            out.append({"t": end, "score": _round(result.score), "class": result.cls})
    return out[-SERIES_MAX:]


def _day_scores(
    cs: ClientStability, live: ClientLive, now: float, first: float
) -> list[dict[str, Any]]:
    settings = cs.score_settings(live.mac)
    patterns = cs.patterns(live.mac, now) or 0
    days = data_days(cs.history, live.mac)
    log_cov = cs.log_coverage(live.ap)
    out: list[dict[str, Any]] = []
    for point in _day_series(cs, live.mac, int(now // _DAY) - 29):
        start = max(float(point["t"]), first)
        end = min(float(point["t"]) + _DAY, now)
        bucket = _bucket_of(cs, live.mac, int(point["t"] // _DAY))
        stats = WindowStats(
            window_s=max(0.0, end - start),
            bucket=bucket,
            session_hist=session_histogram(bucket),
            log_coverage=log_cov,
            patterns=patterns,
            data_days=days,
        )
        result = score_window(stats, settings)
        out.append(
            {"t": point["t"], "score": _round(result.score), "class": result.cls}
        )
    return out


def _bucket_of(cs: ClientStability, mac: str, day: int) -> Bucket:
    items = [d.bucket for d in cs.history.days(mac, day, day)]
    items += [
        h.bucket for h in cs.history.hours(mac, day * 24, day * 24 + 23, open_only=True)
    ]
    return sum_buckets(items)


def _timeline(
    transitions: Iterable[Transition],
    start: float,
    now: float,
    live: ClientLive | None = None,
) -> list[dict[str, Any]]:
    """Online/offline/gap segments of ``[start, now]`` from the transitions
    (24 h stored; see ``client_analysis.timeline_segments``)."""
    return [
        {"start": a, "end": b, "state": state}
        for a, b, state in timeline_segments(transitions, start, now, live)
    ]


def _strip(
    points: list[dict[str, Any]], first: int, count: int, span: int, now: float
) -> list[dict[str, Any]]:
    """[CS 1.43] Coarse timeline of the 7 d and 30 d windows: per hour or day
    the online, offline, gap and unknown shares of the bucket and its
    disconnect, roam and flap counts. Built from the series (no new data);
    an hour or day without a bucket is unknown, never offline."""
    by_t = {int(p["t"]): p for p in points}
    out: list[dict[str, Any]] = []
    for index in range(first, first + count):
        t = index * span
        length = min(float(span), now - t)
        if length <= 0:
            break
        p = by_t.get(t, {})
        online = float(p.get("online_s", 0))
        offline = max(0.0, float(p.get("observed_s", 0)) - online)
        gap = float(p.get("gap_s", 0))
        scale = min(1.0, length / (online + offline + gap or 1.0)) / length
        shares = [_round(v * scale, 3) or 0.0 for v in (online, offline, gap)]
        out.append(
            {
                "t": t,
                "span_s": round(length),
                "online": shares[0],
                "offline": shares[1],
                "gap": shares[2],
                "unknown": _round(max(0.0, 1.0 - sum(shares)), 3),
                "disconnects": p.get("disconnects", 0),
                "infra": p.get("infra", 0),
                "roams": p.get("roams", 0),
                "flaps": p.get("flaps", 0),
            }
        )
    return out


def _transition(tr: Transition, name_of: _NameOf) -> dict[str, Any]:
    return {
        "ts": tr.ts,
        "kind": tr.kind,
        "router": tr.ap or None,
        "router_name": name_of(tr.ap) if tr.ap else None,
        "reason": tr.reason,
        "class": tr.cls,
        "incident_id": tr.incident_id,
        "timed": tr.timed,
    }


def _live(cs: ClientStability, live: ClientLive, name_of: _NameOf) -> dict[str, Any]:
    offline = live.state == STATE_OFFLINE
    return {
        "state": live.state,
        "since": live.since,
        "router": live.ap,
        "router_name": name_of(live.ap) if live.ap else None,
        "band": live.band,
        "ssid": cs.ssid(live.mac),
        "rssi": None if offline else live.rssi,
        "session_start": None if offline else live.session_start,
        "session_start_known": live.session_start_known,
        "first_seen": live.first_seen,
        "last_seen": live.last_seen,
        "last_disconnect": _last_disconnect(live.last_disconnect),
        "hostname": live.hostname,
        "ip": live.ip,
        "private_mac": live.private_mac,
    }


def client_detail(
    cs: ClientStability, mac: str, name_of: _NameOf, now: float, window: str
) -> dict[str, Any] | None:
    """``GET clients/{mac}``: detail and series of one window (None = unknown)."""
    live = cs.history.live(mac)
    if live is None:
        return None
    if window == WINDOW_30D:
        found = cs.window_days(mac, now, 30)
    elif window == WINDOW_1H:
        # [CS 1.43] the real last 60 minutes, not the clock hour bucket
        found = cs.window_trailing_hour(mac, now)
    else:
        found = cs.window(mac, now, _WINDOW_HOURS[window])
    day = cs.window(mac, now, 24)
    if found is None or day is None:
        return None
    stats, result = found
    start = now - _WINDOW_S[window]
    stored = cs.history.transitions(mac)
    shown = [tr for tr in stored if start <= tr.ts <= now]
    # [CS-Entscheidung] attribution and recommendations always cover the
    # last 24 h: the transitions (with the NI incident ids) are kept 24 h.
    ends = disconnect_ends(cs.history, mac, now - _DAY, now)
    refs = cs.incident_refs(
        {tr.incident_id for tr in (*shown, *ends) if tr.incident_id}
    )
    attribution = attribute_disconnects(ends, refs)
    tz = dt_util.get_default_time_zone()
    patterns = {
        "time": time_pattern(cs.history, mac, tz),
        "signal": signal_trend(cs.history, mac, now),
        "ap": ap_pattern(cs.history, mac, now),
    }
    findings = ClientFindings(
        mac=mac,
        stats_24h=day[0],
        time_pattern=patterns["time"],
        ap_pattern=patterns["ap"],
        roam_burst=roam_burst(roam_steps(stored)),
        attribution=attribution,
    )
    ring = [
        {
            "t": e.ts,
            "rssi": e.rssi,
            "router": e.ap or None,
            "band": e.band,
            "state": e.state,
        }
        for e in cs.history.ring(mac)
        if start <= e.ts <= now
    ]
    series = _series(cs, mac, now, window)
    if window == WINDOW_30D:
        strip = _strip(series, int(now // _DAY) - 29, 30, _DAY, now)
    elif window == WINDOW_7D:
        last = math.ceil(now / _HOUR) - 1
        strip = _strip(series, last - 167, 168, _HOUR, now)
    else:
        strip = []
    aps = {p["router"] for p in ring if p["router"]}
    aps.update(ap for p in series for ap in p["aps"])
    aps.update(tr.ap for tr in shown if tr.ap)
    if live.ap:
        aps.add(live.ap)
    return {
        "now": now,
        "mac": mac,
        "window": window,
        "live": _live(cs, live, name_of),
        "score": _score(result),
        "stats": _stats(stats),
        "series": series,
        "score_series": _score_series(cs, live, now, window),
        "rssi": ring[-SERIES_MAX:],
        # [CS 1.43] exact segments for 1 h and 24 h (transitions are kept
        # 24 h); the long windows get the coarse strip instead
        "timeline": _timeline(stored, start, now, live) if not strip else [],
        "strip": strip,
        "routers": {ap: name_of(ap) for ap in sorted(aps)},
        "transitions": [_transition(tr, name_of) for tr in shown],
        "incidents": [plain(ref) for _id, ref in sorted(refs.items())],
        "attribution": {**plain(attribution), "total": attribution.total},
        "patterns": {key: plain(value) for key, value in patterns.items()},
        "recommendations": [plain(r) for r in recommend_client(findings)],
        "entity": mac in cs.settings["entity_macs"],
        "sleepy": mac in cs.settings["sleepy_macs"],
    }


# --- AP comparison -------------------------------------------------------------------


def ap_view(
    cs: ClientStability, name_of: _NameOf, now: float, window: str
) -> dict[str, Any]:
    """``GET clients/aps``: AP comparison of one window with recommendations."""
    scores: dict[str, float | None] = {}
    for mac in cs.history.macs():
        if window == WINDOW_30D:
            found = cs.window_days(mac, now, 30)
        else:
            found = cs.window(mac, now, 24 if window == WINDOW_24H else 168)
        scores[mac] = found[1].score if found is not None else None
    comparison = ap_comparison(cs.history, now, window, scores=scores)
    infra = cs.infra_routers(now)
    hours = 24 if window == WINDOW_24H else 168
    # [CS-Entscheidung] An AP "had a root" when NI has one there now or the
    # window holds disconnects B1 tagged as infrastructure there.
    groups = []
    for ap, per in sorted(ap_reconnects(cs.history, now, hours).items()):
        stats = comparison.aps.get(ap)
        tagged = stats is not None and stats.infra_disconnects > 0
        groups.append(ApReconnects(ap, per, ap in infra or tagged))
    return {
        "now": now,
        "window": window,
        "aps": [
            {**plain(stats), "name": name_of(ap)}
            for ap, stats in sorted(comparison.aps.items())
        ],
        "ranking": list(comparison.ranking),
        "recommendations": [plain(r) for r in recommend_aps(groups)],
    }


# --- settings ----------------------------------------------------------------------


def settings_view(cs: ClientStability, can_edit: bool) -> dict[str, Any]:
    """``GET clients/settings``: settings, defaults, limits and store status."""
    return {
        "settings": cs.settings,
        "defaults": default_settings(),
        "can_edit": can_edit,
        "limits": {
            "entity_max": CLIENT_ENTITY_MAX,
            "sleepy_max": SLEEPY_MAX,
            "retention_days_max": RETENTION_DAYS_MAX,
            "store_mb_min": STORE_MB_RANGE[0],
            "store_mb_max": STORE_MB_RANGE[1],
            "parts": list(PARTS),
            "classes": list(CLASSES),
        },
        "status": cs.diagnostics(),
    }


# --- routes ------------------------------------------------------------------------


def _now(cs: ClientStability) -> float:
    """The wall clock, never behind the history's last poll."""
    wall = time.time()
    last = cs.last_now
    return wall if last is None else max(wall, last)


class _ClientView(_IntelView):
    """Access checks of the NI routes, on the client stability engine."""

    @staticmethod
    def _client_engine(hass: HomeAssistant) -> ClientStability | None:
        cs = async_get_client_engine(hass)
        return cs if cs is not None and cs.loaded else None

    def _unavailable(self) -> web.Response:
        return self.json_message("Client stability is not running yet", status_code=503)

    async def _client_read(
        self,
        request: web.Request,
        build: Callable[[ClientStability, _NameOf, float], Any],
    ) -> web.Response:
        """Shared GET; ``None`` from ``build`` is an unknown client (404)."""
        if (blocked := self._check(request)) is not None:
            return blocked
        hass: HomeAssistant = request.app[KEY_HASS]
        cs = self._client_engine(hass)
        if cs is None:
            return self._unavailable()
        try:
            body = build(cs, _router_names(hass), _now(cs))
        except QueryError as err:
            return self.json_message(str(err), status_code=400)
        except Exception as err:
            # Only the type: the message may carry client data.
            _LOGGER.warning("Client stability request failed: %s", type(err).__name__)
            _LOGGER.debug("Client stability request failed", exc_info=True)
            return self._failed(err)
        if body is None:
            return self.json_message("Unknown client", status_code=404)
        return self.json(body)


class OpenWrtClientsView(_ClientView):
    """Client table: filters ``router``, ``band``, ``ssid``, ``class``,
    ``state``, search ``q``, ``sort`` (``-`` = descending), ``limit`` <= 500,
    ``cursor``."""

    url = f"{_INTEL_URL}/clients"
    name = "api:openwrt_topology:intelligence:clients"

    async def get(self, request: web.Request) -> web.Response:
        """Return one page of the client table."""
        query = request.query

        def build(cs: ClientStability, name_of: _NameOf, now: float) -> Any:
            return clients_table(cs, name_of, now, parse_table_query(query))

        return await self._client_read(request, build)


class OpenWrtClientApsView(_ClientView):
    """AP comparison; ``window`` = ``24h`` (default), ``7d`` or ``30d``."""

    url = f"{_INTEL_URL}/clients/aps"
    name = "api:openwrt_topology:intelligence:client_aps"

    async def get(self, request: web.Request) -> web.Response:
        """Return the AP comparison."""
        query = request.query

        def build(cs: ClientStability, name_of: _NameOf, now: float) -> Any:
            return ap_view(cs, name_of, now, parse_window(query, WINDOWS))

        return await self._client_read(request, build)


class OpenWrtClientSettingsView(_ClientView):
    """Client stability settings: GET for readers, POST admin only."""

    url = f"{_INTEL_URL}/clients/settings"
    name = "api:openwrt_topology:intelligence:client_settings"

    async def get(self, request: web.Request) -> web.Response:
        """Return the settings with defaults and limits."""
        is_admin = self._is_admin(request)

        def build(cs: ClientStability, _name_of: _NameOf, _now: float) -> Any:
            return settings_view(cs, is_admin)

        return await self._client_read(request, build)

    async def post(self, request: web.Request) -> web.Response:
        """Apply a partial change; 400 with ``errors`` if invalid."""
        if (blocked := self._check(request, write=True)) is not None:
            return blocked
        cs = self._client_engine(request.app[KEY_HASS])
        if cs is None:
            return self._unavailable()
        try:
            update = await self._body(request)
        except QueryError as err:
            return self.json_message(str(err), status_code=400)
        try:
            cs.update_settings(update)
        except vol.Invalid as err:
            return self.json(
                {"message": "Invalid settings", "errors": [str(err)]},
                status_code=400,
            )
        return self.json(settings_view(cs, True))


class OpenWrtClientView(_ClientView):
    """One client; ``window`` = ``1h``, ``24h`` (default), ``7d`` or ``30d``."""

    url = f"{_INTEL_URL}/clients/{{mac}}"
    name = "api:openwrt_topology:intelligence:client"

    async def get(self, request: web.Request, mac: str) -> web.Response:
        """Return the client detail with series."""
        query = request.query

        def build(cs: ClientStability, name_of: _NameOf, now: float) -> Any:
            client = parse_mac(mac)
            window = parse_window(query, DETAIL_WINDOWS)
            return client_detail(cs, client, name_of, now, window)

        return await self._client_read(request, build)


def client_api_views() -> tuple[_ClientView, ...]:
    """The client routes; the fixed paths before ``clients/{mac}`` (aiohttp
    matches in registration order)."""
    return (
        OpenWrtClientsView(),
        OpenWrtClientApsView(),
        OpenWrtClientSettingsView(),
        OpenWrtClientView(),
    )
