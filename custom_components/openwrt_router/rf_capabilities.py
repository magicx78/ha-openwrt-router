"""RF capability matrix on the Core capability model (pure, no I/O).

The Core knows capabilities per router with three states
(``available``/``unavailable``/``unknown``); RF knows them per radio with
five (``measured``/``no_data``/``unsupported``/``unreachable``/``stale``).
:func:`to_core_capabilities` turns the RF matrices of one router into one
:class:`CapabilityStatus` per metric; :func:`from_core_capabilities` is its
exact inverse (tested), because every radio's state is kept in ``detail``.

Names: the Core gives module ``wifi_rf`` the namespace ``rf.``
(``MODULE_CAPABILITY_NAMESPACES``) and owns ``rf.txpowerlist``,
``rf.survey`` and ``rf.scan`` itself (facts about the deployed ACL,
``CORE_OWNED_MODULE_CAPABILITIES``). RF metrics therefore live below
``rf.metric.`` (``rf.metric.noise``, ``rf.metric.scan``, …) and never clash
with the Core's names.

State mapping (top-level ``state``/``reason`` of the router):

==============  ===========  ============
RF (any radio)  Core state   Core reason
==============  ===========  ============
measured        available    ok
unsupported     unavailable  not_detected (all assessed radios)
no_data, stale  unknown      no_data_yet
unreachable     unknown      not_checked
not assessed    unknown      not_checked
all excluded    unavailable  disabled
==============  ===========  ============

``no_data``/``stale``/``unreachable`` map to ``unknown`` on purpose: the
Core's merge keeps the last known state for ``unknown``, so a poll gap is
not reported as a capability change. ``scan`` is ``unsupported`` until it
is proven on a radio (:data:`.rf_scan_policy.DEFAULT_SCAN_CAPABILITY`).

Nothing here probes a router. :func:`capability_detector` builds the
synchronous, I/O-free detector the Core's registry runs on poll data.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping, Sequence
from datetime import datetime
from typing import Any

from .core_models import (
    MODULE_CAPABILITY_NAMESPACES,
    Capability,
    CapabilityReason,
    CapabilityStatus,
)
from .core_models import CapabilityState as CoreState
from .rf_identity import require_radio_key, require_router_id
from .rf_models import ALL_METRICS, METRIC_SCAN, CapabilityState, RadioCapabilities
from .rf_scan_policy import DEFAULT_SCAN_CAPABILITY

_LOGGER = logging.getLogger(__name__)

RF_MODULE = "wifi_rf"
CAPABILITY_PREFIX = MODULE_CAPABILITY_NAMESPACES[RF_MODULE]
METRIC_CAPABILITY_PREFIX = f"{CAPABILITY_PREFIX}metric."
# CapabilityStatus.source: what the status was derived from.
RF_CAPABILITY_SOURCE = f"module:{RF_MODULE}"

_DETAIL_RADIOS = "radios"
_METRIC_SET = frozenset(ALL_METRICS)
_BY_NAME = {f"{METRIC_CAPABILITY_PREFIX}{m}": m for m in ALL_METRICS}


def capability_name(metric: str) -> str:
    """Return the Core capability name of an RF metric (``rf.metric.<m>``)."""
    if metric not in _METRIC_SET:
        raise ValueError(f"unknown metric: {metric!r}")
    return f"{METRIC_CAPABILITY_PREFIX}{metric}"


def _effective(metric: str, state: CapabilityState | None) -> CapabilityState | None:
    if state is None and metric == METRIC_SCAN:
        return DEFAULT_SCAN_CAPABILITY
    return state


def _aggregate(
    metric: str, caps: Sequence[RadioCapabilities]
) -> tuple[CoreState, CapabilityReason]:
    in_scope = [c for c in caps if metric not in c.excluded]
    if caps and not in_scope:
        return CoreState.UNAVAILABLE, CapabilityReason.DISABLED
    states = [_effective(metric, c.state(metric)) for c in in_scope]
    if CapabilityState.MEASURED in states:
        return CoreState.AVAILABLE, CapabilityReason.OK
    if states and all(s is CapabilityState.UNSUPPORTED for s in states):
        return CoreState.UNAVAILABLE, CapabilityReason.NOT_DETECTED
    if any(s in (CapabilityState.NO_DATA, CapabilityState.STALE) for s in states):
        return CoreState.UNKNOWN, CapabilityReason.NO_DATA_YET
    return CoreState.UNKNOWN, CapabilityReason.NOT_CHECKED


def _radio_detail(caps: RadioCapabilities, metric: str) -> dict[str, Any]:
    state = caps.state(metric)
    return {
        "state": None if state is None else state.value,
        "excluded": metric in caps.excluded,
    }


def _check(caps: Sequence[RadioCapabilities], router_id: str) -> None:
    seen: set[str] = set()
    for item in caps:
        if item.router_key != router_id:
            raise ValueError("every radio must belong to router_id")
        require_radio_key(item.radio_key)
        if item.radio_key in seen:
            raise ValueError(f"radio listed twice: {item.radio_key}")
        seen.add(item.radio_key)


def to_core_capabilities(
    caps: Sequence[RadioCapabilities], *, router_id: str, now: datetime
) -> dict[str, CapabilityStatus]:
    """Return one Core status per RF metric for the radios of one router.

    ``now`` must be timezone-aware (the Core refuses naive times).
    """
    require_router_id(router_id)
    _check(caps, router_id)
    result: dict[str, CapabilityStatus] = {}
    for metric in ALL_METRICS:
        state, reason = _aggregate(metric, caps)
        name = capability_name(metric)
        result[name] = CapabilityStatus(
            capability=name,
            state=state,
            reason=reason,
            source=RF_CAPABILITY_SOURCE,
            detected_at=now,
            detail={
                _DETAIL_RADIOS: {c.radio_key: _radio_detail(c, metric) for c in caps}
            },
        )
    return result


def _radio_entries(status: CapabilityStatus) -> Iterable[tuple[str, Mapping[str, Any]]]:
    radios = status.detail.get(_DETAIL_RADIOS)
    if not isinstance(radios, Mapping):
        return ()
    return ((str(k), v) for k, v in radios.items() if isinstance(v, Mapping))


def from_core_capabilities(
    statuses: Mapping[str, CapabilityStatus], *, router_id: str
) -> list[RadioCapabilities]:
    """Inverse of :func:`to_core_capabilities`; other names are ignored."""
    require_router_id(router_id)
    states: dict[str, dict[str, CapabilityState]] = {}
    excluded: dict[str, set[str]] = {}
    for name, status in statuses.items():
        metric = _BY_NAME.get(str(name))
        if metric is None:
            continue
        for radio, entry in _radio_entries(status):
            states.setdefault(radio, {})
            excluded.setdefault(radio, set())
            if entry.get("state") is not None:
                states[radio][metric] = CapabilityState(entry["state"])
            if entry.get("excluded") is True:
                excluded[radio].add(metric)
    return [
        RadioCapabilities(router_id, radio, states[radio], frozenset(excluded[radio]))
        for radio in states
    ]


def scan_capability(
    acl_status: CapabilityStatus | None, proven: CapabilityState | None
) -> CapabilityState:
    """Scan state of one radio for :func:`.rf_scan_policy.decide_scan`.

    ``acl_status`` is the Core's ``rf.scan`` (does the deployed ACL allow
    ``iwinfo scan``); ``proven`` is what RF found on this radio. Not proven
    stays ``unsupported``; proven but not allowed by the ACL (or unknown) is
    ``unreachable``, which decide_scan refuses as ``scan_unavailable``.
    """
    if acl_status is not None and acl_status.capability != Capability.RF_SCAN:
        raise ValueError("acl_status must be the Core rf.scan capability")
    if proven is None or proven is CapabilityState.UNSUPPORTED:
        return CapabilityState.UNSUPPORTED
    if acl_status is None or not acl_status.available:
        return CapabilityState.UNREACHABLE
    return proven


def capability_detector(
    extract: Callable[[Any], Sequence[RadioCapabilities] | None],
    *,
    clock: Callable[[], datetime],
) -> Callable[[Any, Any], dict[str, CapabilityStatus]]:
    """Build ``detect(record, data)`` for ``register_capability_detector``.

    ``extract(data)`` reads the RF matrices from poll data the Core already
    has (no I/O); None means "no RF data" and reports nothing.
    """

    def detect(record: Any, data: Any) -> dict[str, CapabilityStatus]:
        caps = extract(data)
        if caps is None:
            return {}
        return to_core_capabilities(caps, router_id=record.router_id, now=clock())

    return detect
