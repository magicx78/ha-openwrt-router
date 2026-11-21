"""Route payloads of WiFi RF Intelligence (release 1.48.0 part 1, pure).

Each function reads the center's memory (no router, no store write) and
returns one masked payload (``RfCenter.mask``: Core pseudonyms with the
``wifi_rf`` module key, then Core masking). Every payload carries
``schema``, ``status`` (``off`` / ``not_ready`` / ``ready``), ``reasons``
and ``generated_at``, and always the same keys whatever the status
(pinned by test case 28), so "off" and "not ready" are never errors.

Ratings: a health score is shown only while the status is ``ready``;
otherwise ``score`` is None and ``grade`` ``unknown`` with the reasons in
``withheld``. Unknown metrics stay ``None`` with their state, never 0.
"""

from __future__ import annotations

import logging
from typing import Any

from .rf_aggregate import WINDOWS
from .rf_identity import RadioRef
from .rf_load import RadioLoadAssessment
from .rf_store import SERIES

_LOGGER = logging.getLogger(__name__)

SCHEMA_VERSION = 1
TIMELINE_WINDOWS = tuple(WINDOWS)
ROAM_COUNT_WINDOW_S = 3600.0
RESTRICTED_ADMIN_ONLY = "admin_only"


def _base(center: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "status": center.status,
        "reasons": center.not_ready_reasons(),
        "generated_at": center.clock(),
    }


def _health(center: Any, health: Any, *, components: bool = False) -> dict[str, Any]:
    """Score only while ready; otherwise withheld (never an all-clear)."""
    reasons = center.not_ready_reasons()
    if center.status != "ready" or health is None:
        return {
            "score": None,
            "grade": "unknown",
            "coverage": None,
            "capped": False,
            "withheld": reasons or ["no_evaluation"],
        }
    out = {
        "score": health.score,
        "grade": health.grade,
        "coverage": health.coverage,
        "capped": health.capped,
        "withheld": [],
    }
    if components:
        out["components"] = [c.as_dict() for c in health.components]
        out["evidence"] = list(health.evidence)
    return out


def _results(center: Any) -> list[Any]:
    if center.status == "off":
        return []
    return [center.results[ref] for ref in sorted(center.results, key=str)]


def overview(center: Any) -> dict[str, Any]:
    """Fleet status, monitoring coverage, network health, counts."""
    out = _base(center)
    results = _results(center)
    fleet = center.fleet
    routers = []
    if center.status != "off":
        for state in center.routers.values():
            if state.router_id is None:
                continue
            routers.append(
                {
                    "router_id": state.router_id,
                    "enabled": state.options.enabled,
                    "status": state.status,
                    "reason": state.reason,
                    "radios": sum(
                        1 for r in results if r.ref.router_id == state.router_id
                    ),
                    "reads": sorted(state.options.kinds),
                    "every_n_polls": state.options.every_n_polls,
                    "last_poll_at": state.last_poll_at,
                    "health": _health(center, fleet.ap_health.get(state.router_id)),
                }
            )
    out.update(
        {
            "routers": routers,
            "monitoring_coverage": round(fleet.coverage, 4) if results else None,
            "network_health": _health(center, fleet.network if results else None),
            "counts": {
                "radios": len(results),
                "clients": sum(r.client_count for r in results),
                "conflicts": len(fleet.conflicts) if results else 0,
                "conflicts_measured": sum(
                    1 for c in fleet.conflicts if c.status.value == "measured"
                )
                if results
                else 0,
                "recommendations": len(fleet.recommendations) if results else 0,
            },
        }
    )
    return center.mask(out)


def _load_of(center: Any, ref: RadioRef) -> dict[str, Any] | None:
    for ap in center.fleet.load.aps:
        for radio in ap.radios:
            if isinstance(radio, RadioLoadAssessment) and radio.ref == ref:
                return radio.as_dict()
    return None


def _radio(center: Any, result: Any, now: float) -> dict[str, Any]:
    radio = result.radio
    summary = result.client_summary
    util = result.utilization
    return {
        "router_id": result.ref.router_id,
        "radio_id": result.ref.radio_id,
        "radio_id_source": radio.radio_id_source,
        "band": radio.band,
        "channel": radio.channel,
        "width_mhz": radio.width,
        "center_channel": radio.center,
        "htmode": radio.htmode,
        "backhaul": radio.backhaul,
        "country": radio.country,
        "interfaces": len(radio.devices),
        "measured_at": result.measured_at,
        "metrics": {
            name: metric.as_dict() if metric is not None else None
            for name, metric in result.metrics.items()
        },
        "utilization": {
            "reason": util.reason.value if util and util.reason else None,
            "summary": result.summary.as_dict() if result.summary else None,
        },
        "clients": {
            "count": result.client_count,
            "problem_clients": summary.problem_clients,
            "flagged_clients": summary.flagged_clients,
            "weak_persistent_clients": summary.weak_persistent_clients,
            "signal_coverage": summary.signal_coverage,
            "retry_coverage": summary.retry_coverage,
        },
        "capabilities": result.caps.as_dict(),
        "health": _health(center, center.fleet.health.get(result.ref), components=True),
        "load": _load_of(center, result.ref),
        "sources": {k: dict(v) for k, v in result.sources.items()},
        "roams_1h": center.roam_count(result.ref, now, ROAM_COUNT_WINDOW_S),
    }


def radios(center: Any) -> dict[str, Any]:
    """Every radio with metrics, capability matrix, health and load."""
    out = _base(center)
    now = center.clock()
    out["radios"] = [_radio(center, r, now) for r in _results(center)]
    return center.mask(out)


def channel_map(center: Any) -> dict[str, Any]:
    """Radios per band with channel, width and utilization; all conflicts."""
    out = _base(center)
    bands: dict[str, list[dict[str, Any]]] = {}
    results = _results(center)
    for result in results:
        view = result.view
        bands.setdefault(view.band, []).append(
            {
                "router_id": view.router_id,
                "radio_id": view.radio_id,
                "channel": view.channel,
                "width_mhz": view.width_mhz,
                "center_channel": view.center_channel,
                "backhaul": view.backhaul,
                "client_count": view.client_count,
                "utilization": view.utilization.as_dict() if view.utilization else None,
            }
        )
    out["bands"] = dict(sorted(bands.items()))
    out["conflicts"] = [c.as_dict() for c in center.fleet.conflicts] if results else []
    return center.mask(out)


def timeline(
    center: Any,
    *,
    window: str,
    radio_id: str | None = None,
    router_id: str | None = None,
    series: str | None = None,
) -> dict[str, Any]:
    """Stored history of the radios (gaps are None, never 0)."""
    if window not in WINDOWS:
        raise ValueError("unknown window")
    out = _base(center)
    out["window"] = window
    names = [series] if series else list(SERIES)
    now = center.clock()
    entries = []
    if center.status != "off":
        for ref in sorted(center.store.radios, key=str):
            if radio_id is not None and ref.radio_id != radio_id:
                continue
            if router_id is not None and ref.router_id != router_id:
                continue
            entries.append(
                {
                    "router_id": ref.router_id,
                    "radio_id": ref.radio_id,
                    "series": {
                        n: center.store.series(ref, n, window, now) for n in names
                    },
                }
            )
    out["radios"] = entries
    return center.mask(out)


def roaming(
    center: Any, *, events: list[dict[str, Any]] | None, restricted: str | None
) -> dict[str, Any]:
    """Roam counts per radio; the client history only after approval."""
    out = _base(center)
    now = center.clock()
    out["window_s"] = ROAM_COUNT_WINDOW_S
    out["per_radio"] = [
        {
            "router_id": r.ref.router_id,
            "radio_id": r.ref.radio_id,
            "roams": center.roam_count(r.ref, now, ROAM_COUNT_WINDOW_S),
        }
        for r in _results(center)
    ]
    out["events"] = events
    out["events_restricted"] = restricted
    return center.mask(out)


def recommendations(center: Any) -> dict[str, Any]:
    """Recommendations (codes only), load verdicts and client distribution."""
    out = _base(center)
    results = _results(center)
    fleet = center.fleet
    out["recommendations"] = (
        [r.as_dict() for r in fleet.recommendations] if results else []
    )
    out["load"] = fleet.load.as_dict() if results else {"aps": []}
    out["distribution"] = fleet.distribution.as_dict() if results else None
    return center.mask(out)
