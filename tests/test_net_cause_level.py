"""Tests for the cause level (RT6): how sure a cause is, derived, never stored.

``cause_level`` grades a cause from its status, its confidence and the
independent source families among the evidence (plan 5.2). ``likely`` needs
two families; a single source, however sure, is at most ``possible``. The
store keeps no new field; the bus event, the panel and the diagnostics carry
the level in addition to the old keys. Router names are roles, MACs locally
administered test values.
"""

from __future__ import annotations

from typing import Any

import pytest
from test_net_p6 import (  # noqa: F401  (fixtures)
    MAC,
    SETTLE,
    T0,
    clock,
    fired,
    intel,
    reconnects,
    step,
    timers,
)

from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    Incident,
    NetEvent,
    Scope,
    Source,
)
from custom_components.openwrt_router.net_query import incident_dict
from custom_components.openwrt_router.net_rules import (
    CauseLevel,
    cause_families,
    cause_level,
    incident_cause_level,
)

LOG = frozenset({"log"})
TWO = frozenset({"log", "poll"})


@pytest.mark.parametrize(
    ("cause", "status", "confidence", "families", "expected"),
    [
        ("weak_signal", CauseStatus.CONFIRMED, 0.2, LOG, CauseLevel.CONFIRMED),
        ("weak_signal", CauseStatus.CONFIRMED, 1.0, frozenset(), CauseLevel.CONFIRMED),
        ("weak_signal", CauseStatus.HYPOTHESIS, 0.9, TWO, CauseLevel.LIKELY),
        ("weak_signal", CauseStatus.HYPOTHESIS, 0.7, TWO, CauseLevel.LIKELY),
        # one source family, however sure: at most possible
        ("weak_signal", CauseStatus.HYPOTHESIS, 0.9, LOG, CauseLevel.POSSIBLE),
        # an inferred topology edge caps at 0.6: never likely (AK6)
        ("uplink_down", CauseStatus.HYPOTHESIS, 0.6, TWO, CauseLevel.POSSIBLE),
        ("weak_signal", CauseStatus.HYPOTHESIS, 0.4, LOG, CauseLevel.POSSIBLE),
        ("weak_signal", CauseStatus.HYPOTHESIS, 0.3, TWO, CauseLevel.UNKNOWN),
        (None, CauseStatus.CONFIRMED, 1.0, TWO, CauseLevel.UNKNOWN),
        (None, None, 1.0, TWO, CauseLevel.UNKNOWN),
        ("weak_signal", None, 1.0, TWO, CauseLevel.UNKNOWN),
    ],
)
def test_cause_level_table(
    cause: str | None,
    status: CauseStatus | None,
    confidence: float,
    families: frozenset[str],
    expected: CauseLevel,
) -> None:
    assert cause_level(cause, status, confidence, families) is expected


def ev(eid: str, source: Source, params: dict[str, Any] | None = None) -> NetEvent:
    return NetEvent(
        id=eid,
        ts=T0,
        router="ap1",
        category=Category.WIFI,
        kind="wifi.reconnect",
        source=source,
        params=params or {},
    )


def incident(*ids: str, parent: str | None = None, **kw: Any) -> Incident:
    return Incident(
        id="inc1",
        type="wifi_reconnect_storm",
        scope=Scope.CLIENT,
        scope_key=MAC,
        cause=kw.get("cause", "weak_signal"),
        cause_status=kw.get("status", CauseStatus.HYPOTHESIS),
        confidence=kw.get("confidence", 0.8),
        evidence=[{"ts": T0, "id": i, "kind": "wifi.reconnect"} for i in ids],
        parent_id=parent,
    )


def test_log_lines_of_one_process_are_one_family() -> None:
    """hostapd, netifd and procd write to the log: one indicator, not three."""
    events = {
        e.id: e
        for e in (
            ev("e1", Source.LOG),
            ev("e2", Source.HOSTAPD),
            ev("e3", Source.NETIFD),
            ev("e4", Source.PROCD),
        )
    }
    inc = incident("e1", "e2", "e3", "e4")
    assert cause_families(inc, events) == {"log"}
    assert incident_cause_level(inc, events) is CauseLevel.POSSIBLE


def test_independent_sources_make_a_hypothesis_likely() -> None:
    events = {e.id: e for e in (ev("e1", Source.HOSTAPD), ev("e2", Source.POLL))}
    inc = incident("e1", "e2")
    assert cause_families(inc, events) == {"log", "poll"}
    assert incident_cause_level(inc, events) is CauseLevel.LIKELY


@pytest.mark.parametrize(
    ("source", "family"),
    [
        (Source.USTEER, "usteer"),
        (Source.LLDP, "topology"),
        (Source.TOPOLOGY, "topology"),
        (Source.FLEET, "fleet"),
    ],
)
def test_source_families(source: Source, family: str) -> None:
    events = {"e1": ev("e1", source)}
    assert cause_families(incident("e1"), events) == {family}


def test_a_root_link_counts_as_one_more_family() -> None:
    """A child explained by its root (correlation) has a second indicator."""
    events = {"e1": ev("e1", Source.HOSTAPD)}
    inc = incident("e1", parent="root1")
    assert cause_families(inc, events) == {"log", "correlation"}
    assert incident_cause_level(inc, events) is CauseLevel.LIKELY


def test_evidence_no_longer_stored_gives_no_family() -> None:
    """An evidence id whose event left the ring tells nothing: the level
    only falls, never rises, by what is no longer known."""
    inc = incident("gone1", "gone2")
    assert cause_families(inc, {}) == frozenset()
    assert incident_cause_level(inc, {}) is CauseLevel.POSSIBLE


def test_cause_level_is_not_stored() -> None:
    inc = incident("e1")
    assert "cause_level" not in inc.to_dict()
    assert "cause_level" not in inc.to_dict(compact=True)
    restored = Incident.from_dict(inc.to_dict(compact=True))
    assert restored == inc


def test_panel_incident_uses_the_families() -> None:
    events = {e.id: e for e in (ev("e1", Source.HOSTAPD), ev("e2", Source.POLL))}
    inc = incident("e1", "e2")
    alone = incident_dict(inc, str, T0)
    assert alone["cause_level"] == "possible"  # no events known: one guess
    full = incident_dict(inc, str, T0, events=events)
    assert full["cause_level"] == "likely"


async def test_bus_event_carries_the_cause_level(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Additive: the old keys stay, ``cause_level`` is new."""
    step(intel, T0, *reconnects(5))
    step(intel, T0 + SETTLE)
    [event] = fired(intel)
    assert event["cause_status"] is None
    assert event["cause_level"] == "unknown"


async def test_diagnostics_count_open_incidents_by_level(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    step(intel, T0, *reconnects(5))
    diag = intel.diagnostics("ap1", T0 + 1)
    assert diag["active_by_cause_level"] == {"unknown": 1}
