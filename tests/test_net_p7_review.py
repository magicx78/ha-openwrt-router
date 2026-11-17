"""Regression tests for the P7 review (network intelligence).

The reviewer's probes, inverted: a child of a recovered root stays silent
without evidence of its own (E12), the reload of a router that is down
starts no after-window for its children (E13), a MAC with dashes is
excluded, the 400 message lists the categories, ignoring an announced
incident closes it on the bus (E15), fleet incidents lower the fleet score
(E14) and an ignored incident whose condition ended stops its duration.
Router names are roles.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from test_net_correlation import T0, A, B, G, level, observed_tree
from test_net_p6 import (  # noqa: F401
    SETTLE,
    clock,
    fired,
    intel,
    reconnects,
    states,
    step,
    timers,
)

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.const import EVENT_INCIDENT
from custom_components.openwrt_router.logbook import async_describe_events
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import (
    ROUTER_REMOVED,
    Category,
    Incident,
    IncidentStatus,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_query import (
    QueryError,
    incident_dict,
    parse_events_query,
)
from custom_components.openwrt_router.net_rules import (
    CHILD_RELEASE_AFTER,
    AlarmMachine,
    AreaInput,
    child_release_time,
    counted_incidents,
    fleet_score,
    merge_settings,
    router_score,
    suppressed_child,
)

AFTER = 180.0  # router_unreachable after-window (_ROOT_WINDOWS)


def _storm(intel: NetIntelligence) -> Any:  # noqa: F811
    [s] = [i for i in intel.machine.peek() if i.type == "wifi_reconnect_storm"]
    return s


def _storm_child_of_recovered_ap(intel: NetIntelligence) -> float:  # noqa: F811
    """Reconnect storm at A, then A's outage: the storm is its child; A is
    back at T0+300. Returns the end of A's after-window."""
    step(intel, T0, *reconnects(5))
    step(intel, T0 + 60, level("router_unreachable", A, since=T0 - 30))
    step(intel, T0 + 200, level("router_unreachable", A))
    assert _storm(intel).parent_id is not None
    step(intel, T0 + 300, level("router_unreachable", A, value=0))  # AP back
    [ap] = [i for i in intel.machine.peek() if i.type == "router_unreachable"]
    assert ap.status is IncidentStatus.RESOLVED
    return ap.resolved_at + AFTER


# --- E12: a child counts again only with evidence of its own ----------------------


async def test_child_without_own_evidence_stays_silent_after_the_window(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Probe e8_window_child_fires_opened_after_root_recovered, inverted:
    no reconnect after the outage, so no "opened" with the root's cause."""
    _storm_child_of_recovered_ap(intel)
    t = T0 + 300
    while t < T0 + 300 + AFTER + SETTLE + 120:
        t += 30
        step(intel, t)  # no new reconnects at all
    storm = _storm(intel)
    assert storm.status is IncidentStatus.ACTIVE  # clears only after 1800 s
    assert [e for e in fired(intel) if e["type"] == "wifi_reconnect_storm"] == []
    known = {i.id: i for i in intel.machine.peek()}
    assert incident_dict(storm, str, t, known=known)["child"] is True
    assert storm not in counted_incidents(intel.machine.peek(), t)
    assert intel.view.routers[A].incidents_active == 0


async def test_child_with_own_evidence_after_the_window_counts(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """New reconnects after the after-window: the storm is a root again."""
    end = _storm_child_of_recovered_ap(intel)
    t = T0 + 300
    while t < end + 30:
        t += 30
        step(intel, t)
    step(intel, t + 30, *reconnects(1, start=100))
    storm = _storm(intel)
    assert storm.last_seen > end
    t += 30
    while t < end + SETTLE + 120:
        t += 30
        step(intel, t)
    assert [
        e["state"] for e in fired(intel) if e["type"] == "wifi_reconnect_storm"
    ] == ["opened"]
    known = {i.id: i for i in intel.machine.peek()}
    assert incident_dict(storm, str, t, known=known)["child"] is False


def test_suppressed_child_needs_last_seen_past_the_window() -> None:
    parent = Incident(
        id="p", type="router_unreachable", scope=Scope.ROUTER, scope_key=A,
        status=IncidentStatus.RESOLVED, first_seen=T0, last_seen=T0 + 100,
        resolved_at=T0 + 100,
    )  # fmt: skip
    child = Incident(
        id="c", type="wifi_reconnect_storm", scope=Scope.CLIENT, scope_key="m",
        parent_id="p", first_seen=T0, last_seen=T0 + 100,
    )  # fmt: skip
    known = {"p": parent, "c": child}
    end = T0 + 100 + AFTER
    assert child_release_time(child, known) == end
    assert suppressed_child(child, known, end + 3000)  # no evidence of its own
    child.last_seen = end  # at the edge: still the root's window
    assert suppressed_child(child, known, end + 1)
    child.last_seen = end + 1
    assert suppressed_child(child, known, end - 1)  # window still running
    assert not suppressed_child(child, known, end + 1)


# --- E13: router_removed starts no after-window ------------------------------------


async def test_reload_of_a_down_uplink_keeps_its_children_silent(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Probe e9_reload_of_down_uplink_announces_its_children, inverted."""
    intel.register(B)
    with patch.object(intel, "_build_topology", lambda now: observed_tree()):
        step(intel, T0, level("router_unreachable", G, since=T0))
        step(intel, T0 + 10, level("router_unreachable", B, since=T0 + 10))
        t = T0 + 10
        while t < T0 + 400:
            t += 30
            step(
                intel, t, level("router_unreachable", G), level("router_unreachable", B)
            )
        before = list(states(intel))
        intel.unregister(G)  # reload while down (ConfigEntryNotReady)
        reload_at = t
        [gw] = [
            i
            for i in intel.machine.peek()
            if i.type == "router_unreachable" and i.scope_key == G
        ]
        assert gw.resolve_reason == ROUTER_REMOVED
        while t < reload_at + AFTER + SETTLE + 120:
            t += 30
            step(intel, t, level("router_unreachable", B))
        after = [s for s in states(intel) if s not in before]
        assert after == []
        assert intel.view.routers[B].incidents_active == 0
        # the E6 release (an hour after the window) lets it count on its own
        release = gw.resolved_at + AFTER + CHILD_RELEASE_AFTER
        while t < release + SETTLE + 120:
            t += 30
            step(intel, t, level("router_unreachable", B))
    after = [s for s in states(intel) if s not in before]
    assert [(s, typ) for s, typ, _i in after] == [("opened", "router_unreachable")]
    assert intel.view.routers[B].incidents_active == 1


def test_router_removed_root_releases_children_only_after_e6() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.update(T0 + 10, [level("router_unreachable", B, since=T0 + 10)])
    m.correlate(T0 + 10, observed_tree())
    m.resolve_router(G, T0 + 100)
    known = {i.id: i for i in m.peek()}
    [gw] = [i for i in known.values() if i.scope_key == G]
    [ap2] = [i for i in known.values() if i.scope_key == B]
    assert ap2.parent_id == gw.id
    assert gw.resolve_reason == ROUTER_REMOVED
    ap2.last_seen = T0 + 5000  # evidence of its own does not matter here
    assert suppressed_child(ap2, known, T0 + 100 + AFTER + 60)
    assert suppressed_child(ap2, known, T0 + 3000)
    assert child_release_time(ap2, known) == T0 + 100 + AFTER + CHILD_RELEASE_AFTER


def test_resolve_reason_is_stored_and_cleared_on_reopen() -> None:
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.resolve_router(G, T0 + 100)
    restored = AlarmMachine.from_dict(m.to_dict(compact=True))
    [gw] = restored.peek()
    assert gw.resolve_reason == ROUTER_REMOVED
    restored.update(T0 + 200, [level("router_unreachable", G, since=T0 + 200)])
    [gw] = restored.peek()
    assert gw.status is IncidentStatus.ACTIVE
    assert gw.resolve_reason is None


# --- MAC exclusions with dashes ----------------------------------------------------


async def test_dashed_mac_is_excluded(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Probe dashed_mac_accepted_but_never_excluded, inverted."""
    errors = intel.apply_settings({"exclusions": {"macs": ["02-00-5e-10-00-01"]}})
    assert errors == []
    assert "02:00:5E:10:00:01" in intel._excluded_macs()
    assert intel.settings["exclusions"]["macs"] == ["02:00:5E:10:00:01"]


def test_stored_dashed_mac_is_normalised_on_load() -> None:
    settings = merge_settings({"exclusions": {"macs": [" 02-00-5e-10-00-01 "]}})
    assert settings["exclusions"]["macs"] == ["02:00:5E:10:00:01"]


# --- 400 message of a choice -------------------------------------------------------


def test_category_error_message_lists_the_categories() -> None:
    """Probe category_error_message_lists_nothing, inverted."""
    try:
        parse_events_query({"category": "weather"})
    except QueryError as err:
        message = str(err)
    else:
        raise AssertionError("no QueryError")
    assert message != "category: one of  expected"
    for category in Category:
        assert category.value in message


# --- E15: ignoring closes an announced incident on the bus ------------------------


async def test_ignore_fires_resolved_and_reactivate_reopens(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Probe ignore_then_reactivate_fires_reopened_never_resolved, inverted."""
    step(intel, T0, level("wan_down", G))
    step(intel, T0 + SETTLE, level("wan_down", G))
    [wan] = [i for i in intel.machine.peek() if i.type == "wan_down"]
    assert [s[0] for s in states(intel)] == ["opened"]
    assert intel.set_incident_status(wan.id, "ignored") is True
    assert [s[0] for s in states(intel)] == ["opened", "resolved"]
    assert fired(intel)[-1]["reason"] == "ignored"
    step(intel, T0 + SETTLE + 30, level("wan_down", G))
    assert intel.set_incident_status(wan.id, "active") is True
    step(intel, T0 + 2 * SETTLE + 60, level("wan_down", G))
    step(intel, T0 + 3 * SETTLE + 120, level("wan_down", G))
    assert [s[0] for s in states(intel)] == ["opened", "resolved", "reopened"]
    assert wan.reopen_count == 0
    # ignore again and let it clear: the ignore closed it, nothing hangs
    assert intel.set_incident_status(wan.id, "ignored", ignore_days=0.001) is True
    t = T0 + 3 * SETTLE + 120
    for _ in range(40):
        t += 60
        step(intel, t, level("wan_down", G, value=0))
    assert wan.status is IncidentStatus.RESOLVED
    seq = [(e["state"], e["reason"]) for e in fired(intel)]
    assert seq == [
        ("opened", None),
        ("resolved", "ignored"),
        ("reopened", None),
        ("resolved", "ignored"),
    ]


async def test_reactivated_incident_never_announced_fires_opened(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """Ignored before its announcement: silent; re-activated: "opened"."""
    step(intel, T0, level("wan_down", G))
    [wan] = [i for i in intel.machine.peek() if i.type == "wan_down"]
    assert intel.set_incident_status(wan.id, "ignored") is True
    step(intel, T0 + SETTLE, level("wan_down", G))
    assert fired(intel) == []
    assert intel.set_incident_status(wan.id, "active") is True
    step(intel, T0 + SETTLE + 30, level("wan_down", G))
    step(intel, T0 + 2 * SETTLE + 60, level("wan_down", G))
    assert [(e["state"], e["reason"]) for e in fired(intel)] == [("opened", None)]


# --- E14: fleet incidents lower the fleet score ------------------------------------


def _wave(status: IncidentStatus = IncidentStatus.ACTIVE) -> Incident:
    return Incident(
        id="wave", type="wifi_auth_wave", scope=Scope.FLEET,
        scope_key="fleet:wifi_auth_wave", status=status,
        severity=Severity.CRITICAL, confidence=1.0, routers=[G, A],
    )  # fmt: skip


def _areas() -> dict[str, AreaInput]:
    return {
        "wifi": AreaInput(fresh=2, total=2),
        "system": AreaInput(fresh=5, total=5),
        "lan": AreaInput(applicable=False),
        "wan": AreaInput(applicable=False),
        "dhcp_dns": AreaInput(applicable=False),
    }


def test_fleet_incident_lowers_the_fleet_score_only() -> None:
    """Probe e10_fleet_incident_lowers_no_score_at_all, inverted (E14)."""
    settings = merge_settings(None)
    wave = _wave()
    with_wave = {r: router_score(r, _areas(), [wave], settings, now=T0) for r in (G, A)}
    without = {r: router_score(r, _areas(), [], settings, now=T0) for r in (G, A)}
    assert {r: s.score for r, s in with_wave.items()} == {G: 100, A: 100}  # E10
    assert fleet_score(without, settings) == (100, 1.0)
    # critical 40 x confidence 1 x wifi weight share 30/100
    assert fleet_score(with_wave, settings, [wave], T0) == (88, 1.0)
    acked = _wave(IncidentStatus.ACKNOWLEDGED)
    assert fleet_score(with_wave, settings, [acked], T0) == (94, 1.0)
    ignored = _wave(IncidentStatus.IGNORED)
    assert fleet_score(with_wave, settings, [ignored], T0) == (100, 1.0)


def test_router_incident_does_not_lower_the_fleet_score_twice() -> None:
    settings = merge_settings(None)
    wan = Incident(
        id="w", type="wan_down", scope=Scope.ROUTER, scope_key=G,
        severity=Severity.CRITICAL, routers=[G],
    )  # fmt: skip
    scores = {G: router_score(G, _areas(), [], settings, now=T0)}
    assert fleet_score(scores, settings, [wan], T0) == (100, 1.0)


async def test_engine_fleet_score_counts_the_fleet_incident(
    intel: NetIntelligence,  # noqa: F811
) -> None:
    """The fleet entity's score drops, the router views stay at 100; a
    fleet incident of routers that are all excluded counts nowhere."""
    intel.register(G)
    intel.register(A)

    def publish(incidents: list[Incident]) -> tuple[Any, ...]:
        with (
            patch.object(intel.machine, "peek", lambda: incidents),
            patch.object(net_engine, "area_inputs", lambda *a, **kw: _areas()),
        ):
            intel._publish(T0)
        view = intel.view
        return (
            view.fleet.score,
            view.routers[G].score.score,
            view.routers[A].score.score,
        )

    assert publish([]) == (100, 100, 100)
    assert publish([_wave()]) == (88, 100, 100)
    assert intel.view.fleet.incidents_active == 1
    intel.apply_settings({"exclusions": {"routers": [G]}})
    assert publish([_wave()]) == (88, 100, 100)  # A still counts
    assert intel._fleet_counts(_wave())
    intel.apply_settings({"exclusions": {"routers": [G, A]}})
    assert not intel._fleet_counts(_wave())
    assert publish([_wave()])[0] is None  # no router left in the fleet score


# --- duration of an ignored incident whose condition ended -------------------------


def test_duration_of_ignored_but_ended_incident_stops() -> None:
    """Probe duration_of_ignored_but_ended_incident_keeps_growing, inverted."""
    inc = Incident(
        id="x", type="wan_down", scope=Scope.ROUTER, scope_key=G,
        status=IncidentStatus.IGNORED, severity=Severity.CRITICAL,
        routers=[G], first_seen=T0, last_seen=T0 + 60, resolved_at=T0 + 60,
    )  # fmt: skip
    assert incident_dict(inc, str, T0 + 3600)["duration_s"] == 60
    assert incident_dict(inc, str, T0 + 86400)["duration_s"] == 60
    inc.resolved_at = None  # still present: it keeps growing
    assert incident_dict(inc, str, T0 + 3600)["duration_s"] == 3600


def test_logbook_marks_the_resolve_of_an_ignored_incident() -> None:
    described: dict[str, Any] = {}
    async_describe_events(
        MagicMock(), lambda domain, name, fn: described.__setitem__(name, fn)
    )
    event = SimpleNamespace(
        data={
            "state": "resolved",
            "reason": "ignored",
            "type": "wan_down",
            "severity": "critical",
            "routers": ["Router gw"],
        }
    )
    assert described[EVENT_INCIDENT](event)["message"] == (
        "incident resolved (ignored): wan down (critical)"
    )
