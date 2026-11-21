"""Answers of the traffic dashboard routes (Phase J, plan 2026-11-20 §7, task §15).

Pure builders over a running :class:`traffic_engine.TrafficEngine`, called
by ``traffic_views`` after the access checks (same split as ``rf_output`` /
``rf_views``). Every answer is a plain dict with ``"v": 1`` and
``status`` (``off`` / ``not_ready`` / ``ready``) plus ``reasons``.

Rules of every answer:

* **Off.** While the engine is not active the builders return the bare
  status (:func:`off_answer`): no history, no rate, no store, no router.
* **Pseudonyms only.** Router ids (``rtr_…``), point ids (``tpt_…``) and
  client references (``cli_…``) are the only identities; no MAC, IP or
  host name exists in the engine at all. The AP's netdev name
  (``radio_id``) is left out as well, as WiFi RF keeps kernel interface
  names inside its module; netdev names of ports and interfaces
  (``device``) stay, the topology panel shows them already.
* **Unknown stays None** with its reason; nothing is filled with 0.
* **Bounded.** Points at most :data:`MAX_POINTS`, a series at most
  ``HISTORY_MAX_QUERY_POINTS`` buckets, talkers at most ``MAX_TALKERS``,
  anomalies at most :data:`MAX_ANOMALIES`, clients at most
  :data:`MAX_CLIENTS`, VLANs at most :data:`MAX_VLANS`.
* **Measuring areas are never added** across areas; the only sum shown is
  the engine's own accounting sum over the WAN points (one area).

No Home Assistant import, no network.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from .traffic_accounting import direction_map
from .traffic_const import (
    HISTORY_MAX_QUERY_POINTS,
    MAX_TALKERS,
    READ_API_VERSION,
    READ_WINDOWS,
    TALKER_DIRECTIONS,
    TALKER_WINDOWS,
)
from .traffic_correlate import window_dict
from .traffic_model import MeasurementPoint, Rate, Scope
from .traffic_series import INFRA_SCOPES
from .traffic_talkers import rank_current

_LOGGER = logging.getLogger(__name__)

MAX_POINTS = 500
MAX_CLIENTS = 200
MAX_VLANS = 64
MAX_ANOMALIES = 100
MAX_INTERFACES = 16
OVERVIEW_TALKERS = 5
# History windows of the series route (5 minutes is the talkers' window only).
SERIES_WINDOWS: Mapping[str, int] = {k: v for k, v in READ_WINDOWS.items() if k != "5m"}
TALKER_KINDS = ("window", "current", "peaks")
TALKER_SCOPES = tuple(s.value for s in (Scope.CLIENT, *sorted(INFRA_SCOPES)))
ANOMALY_STATES = ("open", "ended", "suppressed")
DAY_S = 86400

REASON_DISABLED = "disabled"
REASON_LINK_UNKNOWN = "link_speed_unknown"
REASON_NO_FLOW_SOURCE = "needs_flow_source"
REASON_NOT_OFFERED = "not_offered_unbounded"
REASON_COLLECTOR_NOT_BUILT = "collector_interface_not_built"
REASON_NO_RATE = "no_rate_yet"


# --- status -------------------------------------------------------------------------------


def status_of(engine: Any) -> tuple[str, list[str]]:
    """``off`` / ``not_ready`` / ``ready`` and the reasons (tokens)."""
    if not getattr(engine, "active", False):
        return "off", [REASON_DISABLED]
    reason = engine.not_ready_reason
    return ("ready", []) if reason is None else ("not_ready", [reason])


def is_off(engine: Any) -> bool:
    """True while the engine is not active (the builders touch nothing)."""
    return status_of(engine)[0] == "off"


def _base(engine: Any) -> dict[str, Any]:
    status, reasons = status_of(engine)
    out: dict[str, Any] = {"v": READ_API_VERSION, "status": status, "reasons": reasons}
    if status != "off":
        out["generated_at"] = engine.wall()
    return out


def off_answer(engine: Any, **extra: Any) -> dict[str, Any]:
    """The bare status of a switched-off module (nothing else is read)."""
    return {**_base(engine), **extra}


# --- shared pieces ------------------------------------------------------------------------


def point_dict(point: MeasurementPoint) -> dict[str, Any]:
    """A point without the AP netdev name (see the module docstring)."""
    out = point.to_dict()
    out.pop("radio_id", None)
    return out


def _routers(engine: Any) -> list[str]:
    rids = {
        p.router_id for p in engine.history_source.points() if p.router_id is not None
    }
    rids.update(r for r in engine.status if r)
    return sorted(rids)


def _rate_dict(rate: Rate) -> dict[str, Any]:
    mapping = direction_map(rate.point)
    values = {"rx": rate.rx_bps, "tx": rate.tx_bps}
    return {
        **point_dict(rate.point),
        "rx_bps": rate.rx_bps,
        "tx_bps": rate.tx_bps,
        "down_bps": None if mapping.download is None else values[mapping.download],
        "up_bps": None if mapping.upload is None else values[mapping.upload],
        "direction": mapping.to_dict(),
        "quality": rate.quality.value,
        "coverage": rate.coverage.value,
        "coverage_reason": None
        if rate.coverage_reason is None
        else rate.coverage_reason.value,
        "interval_s": rate.interval_s,
        "wall_s": rate.wall_s,
    }


def _source_dict(status: Any) -> dict[str, Any] | None:
    try:
        return status.to_dict()
    except Exception as err:  # noqa: BLE001 - one source never breaks the answer
        _LOGGER.debug("Traffic source state failed (%s)", type(err).__name__)
        return None


def correlation_sources(engine: Any) -> list[dict[str, Any]]:
    """State of every module traffic correlates with (never "ok" without data)."""
    out: list[dict[str, Any]] = []
    try:
        out.append(_source_dict(engine.diagnostics.view()[0]))
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("Diagnostics state failed (%s)", type(err).__name__)
    try:
        out.append(_source_dict(engine.wifi_rf.module()[0]))
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug("WiFi RF state failed (%s)", type(err).__name__)
    security = engine.indicators.summary().get("security_center")
    if isinstance(security, Mapping):
        out.append(dict(security))
    out.append(
        {
            "module": "network_intelligence",
            "state": "ready" if engine.correlator.ni_listening else "not_connected",
            "reason": None if engine.correlator.ni_listening else "not_listening",
        }
    )
    anomalies = engine.anomalies.summary()
    out.append(
        {
            "module": "incident_engine",
            "state": anomalies.get("incident_engine"),
            "reason": anomalies.get("incident_engine_reason"),
        }
    )
    return [s for s in out if s is not None]


def flow_sources(engine: Any) -> list[dict[str, Any]]:
    """Flow sources: none in this build (collector: Phase K; snapshots: unbounded)."""
    conntrack = [
        rid for rid, st in engine.status.items() if st.conntrack_count is not None
    ]
    return [
        {
            "source": "collector",
            "state": "unavailable",
            "reason": REASON_COLLECTOR_NOT_BUILT,
        },
        {
            "source": "conntrack_snapshot",
            "state": "unavailable",
            "reason": REASON_NOT_OFFERED,
        },
        {
            "source": "conntrack_count",
            "state": "available" if conntrack else "unavailable",
            "reason": None if conntrack else "count_file_not_seen",
            "routers": len(conntrack),
            "note": "count_only_no_flows",
        },
    ]


def _coverage(rates: Iterable[Rate]) -> dict[str, Any]:
    by: Counter[str] = Counter()
    reasons: Counter[str] = Counter()
    for rate in rates:
        by[rate.coverage.value] += 1
        if rate.coverage_reason is not None:
            reasons[rate.coverage_reason.value] += 1
    total = sum(by.values())
    return {
        "points": total,
        "full": by.get("full", 0),
        "partial": by.get("partial", 0),
        "estimated": by.get("estimated", 0),
        "unavailable": by.get("unavailable", 0),
        "unknown": by.get("unknown", 0),
        "full_share": None if total == 0 else round(by.get("full", 0) / total, 4),
        "reasons": dict(sorted(reasons.items())),
    }


def interface_load(engine: Any, rates: Iterable[Rate]) -> list[dict[str, Any]]:
    """Current utilisation of infrastructure points with a known link speed."""
    links = engine.link_facts()
    rows: list[dict[str, Any]] = []
    for rate in rates:
        if rate.point.scope not in INFRA_SCOPES or rate.point.scope is Scope.VLAN:
            continue
        link = links.get(rate.point.point_id)
        mbps = getattr(link, "link_mbps", None)
        known = [v for v in (rate.rx_bps, rate.tx_bps) if v is not None]
        pct = None
        reason = None
        if not mbps:
            reason = REASON_LINK_UNKNOWN
        elif not known:
            reason = REASON_NO_RATE
        else:
            pct = round(max(known) / (mbps * 1_000_000) * 100, 2)
        rows.append(
            {
                **_rate_dict(rate),
                "link_mbps": mbps,
                "duplex": getattr(link, "duplex", None),
                "utilization_pct": pct,
                "utilization_reason": reason,
            }
        )
    rows.sort(
        key=lambda r: (
            r["utilization_pct"] is None,
            -(r["utilization_pct"] or 0),
            r["point_id"],
        )
    )
    return rows[:MAX_INTERFACES]


def _vlan_rows(engine: Any, router_id: str | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rid in [router_id] if router_id else _routers(engine):
        for view in engine.vlan_views(rid):
            rows.append(view.to_dict())
            if len(rows) >= MAX_VLANS:
                return rows
    return rows


def _talker_rows(engine: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Talker answer with the current AP router, VLAN and last activity."""
    views = {v.client_ref: v for v in engine.client_views()}
    for row in data.get("rows", ()):
        row.pop("radio_id", None)
        view = views.get(row.get("client_ref")) if row.get("client_ref") else None
        rate = engine.latest.get(row.get("point_id"))
        if view is not None:
            row["router_id"] = row.get("router_id") or view.router_id
            if row.get("vlan_id") is None:
                row["vlan_id"] = view.vlan_id
            row["last_active"] = view.last_seen_wall
        else:
            row["last_active"] = None if rate is None else rate.wall_s
    return data


# --- builders ---------------------------------------------------------------------------


def overview(engine: Any) -> dict[str, Any]:
    """Network traffic overview (task §15 "Network Traffic Overview")."""
    if is_off(engine):
        return off_answer(engine)
    rates = list(engine.latest.values())
    wan = [r for r in rates if r.point.scope is Scope.WAN]
    wan_sum = engine.sum_latest([r.point.point_id for r in wan]) if wan else None
    wan_24h = [
        window_dict(
            engine.history_source.window(r.point.point_id, DAY_S, end=engine.wall()),
            r.point,
        )
        for r in wan
    ]
    for item in wan_24h:
        item.pop("radio_id", None)
    talkers = engine.talkers.rank_window(
        Scope.CLIENT,
        "1h",
        "download",
        end=engine.wall(),
        limit=OVERVIEW_TALKERS,
        uplink_ports=engine.uplink_ports(),
    ).to_dict()
    anomalies = engine.anomalies.summary()
    store = engine.store.stats()
    return {
        **_base(engine),
        "coverage": _coverage(rates),
        "wan": [_rate_dict(r) for r in wan],
        "wan_total": None if wan_sum is None else wan_sum.to_dict(),
        "wan_24h": wan_24h,
        "talkers_top": _talker_rows(engine, talkers),
        "anomalies": {
            "open": anomalies.get("open"),
            "ended": anomalies.get("ended"),
            "suppressed": anomalies.get("suppressed"),
            "families": anomalies.get("families", {}),
        },
        "interfaces": interface_load(engine, rates),
        "vlans": _vlan_rows(engine),
        "flow_sources": flow_sources(engine),
        "correlation_sources": correlation_sources(engine),
        "routers": [
            {
                "router_id": rid,
                "devices": st.devices,
                "stations": st.stations,
                "conntrack_count": st.conntrack_count,
            }
            for rid, st in sorted(engine.status.items())
        ],
        "drops": {
            **dict(engine.series.dropped()),
            "dropped_snapshots": engine.counters.get("dropped_snapshots", 0),
            "stations_dropped": engine.counters.get("stations_dropped", 0),
        },
        "history": {
            "profile": engine.history_profile,
            "fine_bytes": store.get("fine_bytes"),
            "coarse_bytes": store.get("coarse_bytes"),
            "day_boundary": "utc",
        },
    }


def points(
    engine: Any, *, router_id: str | None = None, scope: str | None = None
) -> dict[str, Any]:
    """Measuring points (ids, scope, coverage of the latest rate)."""
    if is_off(engine):
        return off_answer(engine, points=[])
    rows: list[dict[str, Any]] = []
    total = 0
    for point in sorted(
        engine.history_source.points(),
        key=lambda p: (p.router_id or "", p.scope.value, p.device or "", p.point_id),
    ):
        if router_id is not None and point.router_id != router_id:
            continue
        if scope is not None and point.scope.value != scope:
            continue
        total += 1
        if len(rows) >= MAX_POINTS:
            continue
        rate = engine.latest.get(point.point_id)
        rows.append(
            {
                **point_dict(point),
                "coverage": None if rate is None else rate.coverage.value,
                "quality": None if rate is None else rate.quality.value,
                "last_seen": None if rate is None else rate.wall_s,
            }
        )
    return {
        **_base(engine),
        "points": rows,
        "total": total,
        "truncated": total > len(rows),
    }


def series(engine: Any, *, point_id: str, window: str) -> dict[str, Any]:
    """Buckets of one point over a named window (at most 500)."""
    if is_off(engine):
        return off_answer(engine, point_id=point_id, window=window, buckets=[])
    seconds = SERIES_WINDOWS[window]
    source = engine.history_source
    point = next((p for p in source.points() if p.point_id == point_id), None)
    base = {**_base(engine), "point_id": point_id, "window": window}
    if point is None:
        return {
            **base,
            "state": "unavailable",
            "reason": "unknown_point",
            "buckets": [],
        }
    win = source.window(point_id, seconds, end=engine.wall())
    summary = window_dict(win, point)
    summary.pop("radio_id", None)
    for key in ("v", "point_id"):
        summary.pop(key, None)
    # the envelope's status/reasons are the module's; the window's own
    # reasons travel under their own key so they never overwrite them
    summary["window_reasons"] = summary.pop("reasons", [])
    summary.pop("status", None)
    buckets = [] if win is None else list(win.buckets)[-HISTORY_MAX_QUERY_POINTS:]
    resolution = None if win is None else win.resolution_s
    return {
        **base,
        **summary,
        "point": point_dict(point),
        "direction": direction_map(point).to_dict(),
        "utc_days": resolution == DAY_S,
        "buckets": [
            {
                "ts": b.start,
                "rx_bytes": b.rx_bytes,
                "tx_bytes": b.tx_bytes,
                "rx_peak_bps": b.rx_peak_bps,
                "tx_peak_bps": b.tx_peak_bps,
                "coverage": round(b.coverage_ratio, 3),
            }
            for b in buckets
        ],
    }


def talkers(
    engine: Any,
    *,
    window: str,
    scope: str,
    direction: str,
    limit: int,
    kind: str = "window",
) -> dict[str, Any]:
    """Top talkers of one area, window and direction (bounded)."""
    if is_off(engine):
        return off_answer(engine, rows=[])
    area = Scope(scope)
    limit = max(1, min(int(limit), MAX_TALKERS))
    if kind == "current":
        result = rank_current(
            engine.latest.values(),
            area,
            direction,
            limit=limit,
            uplink_ports=engine.uplink_ports(),
        )
    elif kind == "peaks":
        result = engine.talkers.rank_recurring_peaks(
            area, window, direction, end=engine.wall(), limit=limit
        )
    else:
        result = engine.talkers.rank_window(
            area,
            window,
            direction,
            end=engine.wall(),
            limit=limit,
            uplink_ports=engine.uplink_ports(),
        )
    rows = _talker_rows(engine, result.to_dict())
    return {**rows, **_base(engine), "kind": kind}


def clients(engine: Any) -> dict[str, Any]:
    """Traffic of every tracked client (WLAN station counters, pseudonyms)."""
    if is_off(engine):
        return off_answer(engine, clients=[])
    views = sorted(
        engine.client_views(),
        key=lambda v: (-(v.last_seen_wall or 0), v.client_ref),
    )
    rows = []
    for view in views[:MAX_CLIENTS]:
        row = view.to_dict()
        row.pop("radio_id", None)
        rows.append(row)
    return {
        **_base(engine),
        "clients": rows,
        "total": len(views),
        "truncated": len(views) > MAX_CLIENTS,
    }


def vlans(engine: Any, *, router_id: str | None = None) -> dict[str, Any]:
    """Measured and configured VLANs per router (never a computed total)."""
    if is_off(engine):
        return off_answer(engine, vlans=[])
    return {**_base(engine), "vlans": _vlan_rows(engine, router_id)}


def capacity(engine: Any, *, router_id: str | None = None) -> dict[str, Any]:
    """Utilisation, peak, P95 and cautious trends per infrastructure point."""
    if is_off(engine):
        return off_answer(engine, rows=[])
    rows = [r.to_dict() for r in engine.capacity(router_id)][:MAX_POINTS]
    for row in rows:
        row.pop("radio_id", None)
    return {**_base(engine), "rows": rows}


def _candidate(c: Any) -> dict[str, Any]:
    return {
        "candidate_id": c.candidate_id,
        "point_id": c.point_id,
        "router_id": c.router_id,
        "client_ref": c.client_ref,
        "kind": c.kind,
        "observed": c.observed,
        "baseline_median": c.baseline_median,
        "threshold": c.threshold,
        "window_s": c.window_s,
        "confidence": c.confidence,
        "coverage": c.coverage.value,
        "started": c.started,
        "last_seen": c.last_seen,
        "state": c.state.value,
        "suppressed_reason": c.suppressed_reason,
        "incident_ref": c.incident_ref,
    }


def anomalies(engine: Any, *, state: str | None, limit: int) -> dict[str, Any]:
    """Anomaly candidates (never incidents) and what can be detected."""
    if is_off(engine):
        return off_answer(engine, rows=[])
    limit = max(1, min(int(limit), MAX_ANOMALIES))
    items = engine.anomalies.book.candidates(state=state)
    summary = engine.anomalies.summary()
    return {
        **_base(engine),
        "rows": [_candidate(c) for c in items[:limit]],
        "total": len(items),
        "families": summary.get("families", {}),
        "incident_engine": {
            "state": summary.get("incident_engine"),
            "reason": summary.get("incident_engine_reason"),
        },
    }


def recommendations(engine: Any, *, router_id: str | None = None) -> dict[str, Any]:
    """Possible bottlenecks with measurements, confidence and causes."""
    if is_off(engine):
        return off_answer(engine, findings=[])
    report = engine.congestion(router_id).to_dict()
    report.pop("v", None)
    return {**report, **_base(engine)}


def flows(engine: Any) -> dict[str, Any]:
    """Flow explorer: no flow source exists in this build (empty is not "none")."""
    if is_off(engine):
        return off_answer(engine, rows=[])
    store = getattr(engine, "flows", None)
    if store is not None and callable(getattr(store, "query", None)):
        # A later flow source (Phase K) answers here; nothing is invented.
        return {**_base(engine), **store.query().to_dict()}  # pragma: no cover
    return {
        **_base(engine),
        "source": {
            "state": "unavailable",
            "reason": REASON_NO_FLOW_SOURCE,
            "feeds": 0,
            "records": 0,
        },
        "rows": [],
        "complete": False,
        "notes": ["empty_is_not_no_traffic", "invisible_is_unknown"],
        "sources": flow_sources(engine),
    }


def evidence(engine: Any, *, evidence_ref: str) -> dict[str, Any] | None:
    """The bucket excerpt behind an ``evr_`` reference (None: unknown)."""
    if is_off(engine):
        return off_answer(engine, evidence=None)
    found = engine.read_api.evidence(evidence_ref)
    if found is None:
        return None
    return {**_base(engine), "evidence_ref": evidence_ref, "evidence": found}


def settings(engine: Any) -> dict[str, Any]:
    """The module settings, read only (the switch is a later route)."""
    current = engine.settings
    return {
        **_base(engine),
        "enabled": current.get("enabled") is True,
        "history_profile": engine.history_profile,
        "routers": {
            rid: dict(opts) for rid, opts in sorted(current.get("routers", {}).items())
        },
        "writable": False,
    }


__all__ = [
    "ANOMALY_STATES",
    "MAX_ANOMALIES",
    "MAX_CLIENTS",
    "MAX_POINTS",
    "SERIES_WINDOWS",
    "TALKER_DIRECTIONS",
    "TALKER_KINDS",
    "TALKER_SCOPES",
    "TALKER_WINDOWS",
    "anomalies",
    "capacity",
    "clients",
    "evidence",
    "flows",
    "is_off",
    "overview",
    "points",
    "recommendations",
    "series",
    "settings",
    "status_of",
    "talkers",
    "vlans",
]
