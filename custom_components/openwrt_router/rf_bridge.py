"""WiFi RF Intelligence links to the existing modules (release 1.48.0, part 2).

Read-only adapters between the RF center (``rf_center``) and modules that
existed before it. Nothing here calls a router or writes a store.

Channel plan (``channel_plan.analyze`` / ``fleet.ChannelPlanMonitor``):
:func:`channel_plan_evidence` gives the measured evidence of one
same_channel/overlap pair. A pair is ``downgraded`` (Repairs issue -> info)
only when the RF finding of exactly this pair is ``acceptable`` AND the
channel utilization of BOTH radios is freshly measured and below
``ConflictThresholds.low_utilization_pct``. Unknown, unsupported, stale,
not ready or RF off: never downgraded (the Repairs issue stays as before).
The RF "acceptable" of a known uplink pair without measurements does not
count; ``channel_plan`` skips backhaul pairs anyway (unchanged).
"""

from __future__ import annotations

import logging
from typing import Any

from .channel_plan import PairEvidence, Radio
from .rf_conflicts import DEFAULT_THRESHOLDS, ConflictKind, ConflictStatus
from .rf_models import CapabilityState, Metric

_LOGGER = logging.getLogger(__name__)

_PAIR_KINDS = frozenset({ConflictKind.CO_CHANNEL, ConflictKind.ADJACENT_OVERLAP})
REASON_NOT_READY = "not_ready"
REASON_NOT_MONITORED = "radio_not_monitored"
REASON_NO_FINDING = "no_rf_finding"
REASON_UNKNOWN = "utilization_unknown"
REASON_NOT_LOW = "utilization_not_low"
REASON_MEASURED = "measured_conflict"
REASON_LOW = "measured_low"
REASON_ERROR = "error"


def _center(hass: Any) -> Any:
    from .rf_center import async_get_rf_center

    return async_get_rf_center(hass)


def channel_plan_evidence_of(hass: Any) -> PairEvidence | None:
    """The pair callback for ``channel_plan.analyze``; None while RF is off."""
    center = _center(hass)
    if center is None or not center.enabled:
        return None
    return lambda a, b: channel_plan_evidence(center, a, b)


def _result_of(center: Any, radio: Radio) -> Any:
    """The RF result of a channel plan radio (entry, phy, band), or None."""
    state = center.routers.get(radio.entry_id)
    if state is None or not state.options.enabled or state.router_id is None:
        return None
    for result in center.results.values():
        if (
            result.ref.router_id == state.router_id
            and result.radio.phy == radio.phy
            and result.radio.band == radio.band
        ):
            return result
    return None


def _measured_pct(metric: Metric | None) -> float | None:
    """A fresh measured utilization in percent; anything else is None."""
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _radio_evidence(result: Any) -> tuple[float | None, dict[str, Any]]:
    metric = result.metrics.get("utilization") if result is not None else None
    pct = _measured_pct(metric)
    return pct, {
        "utilization_pct": None if pct is None else round(pct, 1),
        "state": metric.state.value if metric is not None else None,
        "source": metric.source if metric is not None else None,
        "measured_at": metric.measured_at if metric is not None else None,
    }


def _status(
    found: str, downgraded: bool, reason: str, radios: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "status": found,
        "downgraded": downgraded,
        "reason": reason,
        "threshold_pct": DEFAULT_THRESHOLDS.low_utilization_pct,
        "radios": radios,
    }


def _pair_status(center: Any, a: Radio, b: Radio) -> dict[str, Any]:
    results = [_result_of(center, a), _result_of(center, b)]
    evidence = [_radio_evidence(r) for r in results]
    radios = [e[1] for e in evidence]
    if any(r is None for r in results):
        return _status("unknown", False, REASON_NOT_MONITORED, radios)
    if center.status != "ready":
        return _status("unknown", False, REASON_NOT_READY, radios)
    refs = {results[0].ref, results[1].ref}
    conflict = next(
        (
            c
            for c in center.fleet.conflicts
            if c.kind in _PAIR_KINDS and set(c.members) == refs
        ),
        None,
    )
    if conflict is None:
        return _status("unknown", False, REASON_NO_FINDING, radios)
    pcts = [e[0] for e in evidence]
    low = DEFAULT_THRESHOLDS.low_utilization_pct
    found = conflict.status.value
    if conflict.status is ConflictStatus.MEASURED:
        return _status(found, False, REASON_MEASURED, radios)
    if any(p is None for p in pcts):
        return _status(found, False, REASON_UNKNOWN, radios)
    all_low = all(p is not None and p < low for p in pcts)
    if conflict.status is ConflictStatus.ACCEPTABLE and all_low:
        return _status(found, True, REASON_LOW, radios)
    return _status(found, False, REASON_NOT_LOW, radios)


def channel_plan_evidence(center: Any, a: Radio, b: Radio) -> dict[str, Any]:
    """Evidence of one channel plan pair (finding order); never raises."""
    try:
        return _pair_status(center, a, b)
    except Exception as err:  # noqa: BLE001 - the plan runs on, as before
        _LOGGER.debug("WiFi RF channel plan evidence failed (%s)", type(err).__name__)
        return _status("unknown", False, REASON_ERROR, [])


__all__ = [
    "channel_plan_evidence",
    "channel_plan_evidence_of",
]
