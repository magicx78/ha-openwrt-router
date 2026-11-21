"""WiFi RF findings in Network Intelligence (release 1.48.0, part 2).

The RF center hands measured findings to the EXISTING incident engine
through its public finding source hook (``net_engine.add_finding_source``),
the way the network diagnostics feed theirs. Nothing in ``net_*`` changes.

What goes in, per router and radio, as an observed Wi-Fi event
(``Finding(event=True, rule=None)``):

- ``rf.channel_conflict``: a channel conflict the RF evaluation MEASURED
  (busy or a neighbour heard loud), not a potential or acceptable one;
- ``rf.channel_busy``: channel utilization sustained high
  (``UtilizationSummary.sustained_overload``);
- ``rf.retry_high``: the radio's freshly measured retry rate at or above
  ``LoadThresholds.high_retry_rate``, with at least ``RETRY_MIN_COVERAGE``
  of its clients measured (1.49.3).

Events only: no incident type, no rule, no root. So they never open,
raise, suppress or excuse anything, never change a score (the NI health
areas come from incidents) and never mark a client disconnect as
infrastructure (Client Stability takes its infrastructure from roots). The
existing correlation links them as follow-ups (``wifi_radio_change`` of
the same radio via ``subject.iface``, a router outage via the router).

Only on a change (a key new since the router's previous poll), at most
``RF_EVENTS_PER_POLL_MAX`` per poll, a key again only after
``RF_REPEAT_HOLD_S``. Only while RF is on for the router and the module
is ready, and only from measured values: unknown is never an event.
Subject and params carry the interface name, band, UCI radio name,
values, source and measurement time; no MAC, SSID, BSSID or router id.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Final

from .net_events import Category, Severity, Source
from .net_rules import Finding
from .rf_conflicts import ConflictStatus
from .rf_load import DEFAULT_LOAD_THRESHOLDS
from .rf_models import CapabilityState, Metric

_LOGGER = logging.getLogger(__name__)

RF_CONFLICT_KIND: Final = "rf.channel_conflict"
RF_BUSY_KIND: Final = "rf.channel_busy"
RF_RETRY_KIND: Final = "rf.retry_high"
RF_EVENT_KINDS: Final = frozenset({RF_CONFLICT_KIND, RF_BUSY_KIND, RF_RETRY_KIND})
RF_EVENTS_PER_POLL_MAX: Final = 6
RF_REPEAT_HOLD_S: Final = 3600.0
# rf.retry_high only when at least this share of the radio's clients has a
# measured retry rate (1.49.3): a rate of one client in ten is no radio rate.
RETRY_MIN_COVERAGE: Final = 0.5
# Keys remembered for the repeat hold (oldest go first beyond this).
_HELD_MAX: Final = 512


@dataclass(frozen=True)
class _Candidate:
    ident: tuple[Any, ...]
    kind: str
    subject: dict[str, Any]
    params: dict[str, Any]
    severity: Severity = Severity.WARNING


@dataclass
class RfIncidentFeed:
    """The RF finding source of one RF center (memory only)."""

    center: Any
    _active: dict[str, frozenset[tuple[Any, ...]]] = field(default_factory=dict)
    _held: dict[tuple[Any, ...], float] = field(default_factory=dict)
    _engine: Any = None
    _unsub: Callable[[], None] | None = None

    # -- engine -------------------------------------------------------------------

    def attach(self, hass: Any) -> None:
        """Register at the running NI engine (again after it was replaced)."""
        from .net_engine import add_finding_source, async_get_engine

        engine = async_get_engine(hass)
        if engine is self._engine:
            return
        self.detach()
        if engine is not None:
            self._engine = engine
            self._unsub = add_finding_source(engine, self.findings)

    def detach(self) -> None:
        """Leave the engine; the memory is cleared."""
        unsub, self._unsub, self._engine = self._unsub, None, None
        self._active.clear()
        self._held.clear()
        if unsub is not None:
            try:
                unsub()
            except Exception:  # leaving never fails the caller
                _LOGGER.debug("WiFi RF: finding source removal raised", exc_info=True)

    # -- the source ---------------------------------------------------------------

    def findings(self, entry_id: str, _data: Any, now: float) -> list[Finding]:
        """New RF events of one router's poll; [] while off or not ready."""
        try:
            return self._findings(entry_id, now)
        except Exception as err:  # noqa: BLE001 - the NI poll goes on
            _LOGGER.debug("WiFi RF findings failed (%s)", type(err).__name__)
            return []

    def _findings(self, entry_id: str, now: float) -> list[Finding]:
        router_id = self._router_id(entry_id)
        if router_id is None:
            self._active.pop(entry_id, None)
            return []
        found = {c.ident: c for c in candidates(self.center, router_id)}
        before = self._active.get(entry_id, frozenset())
        self._active[entry_id] = frozenset(found)
        out: list[Finding] = []
        for key, cand in sorted(found.items(), key=lambda kv: repr(kv[0])):
            if key in before or now - self._held.get(key, -RF_REPEAT_HOLD_S) < (
                RF_REPEAT_HOLD_S
            ):
                continue
            if len(out) >= RF_EVENTS_PER_POLL_MAX:
                break
            self._held[key] = now
            out.append(_finding(cand))
        self._trim()
        return out

    def _router_id(self, entry_id: str) -> str | None:
        center = self.center
        state = center.routers.get(entry_id)
        if state is None or not state.options.enabled or center.status != "ready":
            return None
        return state.router_id

    def _trim(self) -> None:
        while len(self._held) > _HELD_MAX:
            oldest = min(self._held, key=self._held.__getitem__)
            del self._held[oldest]


def _finding(cand: _Candidate) -> Finding:
    return Finding(
        kind=cand.kind,
        category=Category.WIFI,
        source=Source.POLL,
        event=True,
        severity=cand.severity,
        subject=dict(cand.subject),
        params=dict(cand.params),
    )


# --- candidates (pure) ---------------------------------------------------------------


def _measured(metric: Metric | None) -> float | None:
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _subject(result: Any) -> dict[str, Any]:
    devices = tuple(getattr(result.radio, "devices", ()) or ())
    subject: dict[str, Any] = {"band": result.radio.band}
    if devices:
        subject["iface"] = devices[0]
        if len(devices) > 1:
            subject["ifaces"] = list(devices)
    return subject


def _base(result: Any, metric: Metric | None) -> dict[str, Any]:
    return {
        "radio_id": result.ref.radio_id,
        "source": metric.source if metric is not None else None,
        "measured_at": metric.measured_at if metric is not None else None,
    }


def _busy(result: Any) -> _Candidate | None:
    summary = result.summary
    if summary is None or summary.sustained_overload is not True:
        return None
    metric = result.metrics.get("utilization")
    return _Candidate(
        ident=(RF_BUSY_KIND, result.ref),
        kind=RF_BUSY_KIND,
        subject=_subject(result),
        params={
            **_base(result, metric),
            "current_pct": summary.current,
            "mean_pct": summary.mean,
            "peak_pct": summary.peak,
        },
    )


def _retry(result: Any) -> _Candidate | None:
    metric = result.metrics.get("retry_rate")
    rate = _measured(metric)
    threshold = DEFAULT_LOAD_THRESHOLDS.high_retry_rate
    if rate is None or rate < threshold:
        return None
    summary = getattr(result, "client_summary", None)
    if summary is not None:
        coverage = getattr(summary, "retry_coverage", None)
        if not isinstance(coverage, int | float) or coverage < RETRY_MIN_COVERAGE:
            return None
    return _Candidate(
        ident=(RF_RETRY_KIND, result.ref),
        kind=RF_RETRY_KIND,
        subject=_subject(result),
        params={
            **_base(result, metric),
            "retry_rate": round(rate, 3),
            "threshold": threshold,
        },
    )


def _conflicts(center: Any, results: dict[Any, Any]) -> Iterable[_Candidate]:
    for conflict in center.fleet.conflicts:
        if conflict.status is not ConflictStatus.MEASURED:
            continue
        own = [m for m in conflict.members if m in results]
        routers = {m.router_id for m in conflict.members}
        for ref in own:
            result = results[ref]
            yield _Candidate(
                ident=(RF_CONFLICT_KIND, ref, conflict.kind.value, conflict.members),
                kind=RF_CONFLICT_KIND,
                subject=_subject(result),
                params={
                    "radio_id": ref.radio_id,
                    "conflict": conflict.kind.value,
                    "band": conflict.band,
                    "radios": len(conflict.members),
                    "cross_router": len(routers) > 1,
                    "evidence_codes": sorted(
                        {e.split(":", 1)[0] for e in conflict.evidence}
                    ),
                },
            )


def candidates(center: Any, router_id: str) -> list[_Candidate]:
    """Everything notable on one router's radios right now (measured only)."""
    results = {
        ref: result
        for ref, result in center.results.items()
        if ref.router_id == router_id
    }
    out: list[_Candidate] = []
    for result in results.values():
        out.extend(c for c in (_busy(result), _retry(result)) if c is not None)
    out.extend(_conflicts(center, results))
    return out


__all__ = [
    "RF_BUSY_KIND",
    "RF_CONFLICT_KIND",
    "RF_EVENTS_PER_POLL_MAX",
    "RF_EVENT_KINDS",
    "RF_REPEAT_HOLD_S",
    "RF_RETRY_KIND",
    "RfIncidentFeed",
    "candidates",
]
