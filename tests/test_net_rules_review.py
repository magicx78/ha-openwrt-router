"""Regression tests for the P1 review findings on net_rules.py / net_events.py.

Each test names the review item it pins (P1-x, P2-x, P3). Time is always
passed in; the tests use small absolute second values.
"""

from __future__ import annotations

import json
import math
from typing import Any

from custom_components.openwrt_router.net_events import (
    Category,
    EventCounters,
    EventRing,
    IncidentStatus,
    NetEvent,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_rules import (
    AlarmMachine,
    Evidence,
    Transition,
    TransitionState,
    merge_settings,
)

MAC = "AA:BB:CC:DD:EE:01"
DAY = 86400
OPENED = TransitionState.OPENED
RESOLVED = TransitionState.RESOLVED
REOPENED = TransitionState.REOPENED
UPDATED = TransitionState.UPDATED


def ev(type_: str = "wifi_reconnect_storm", key: str = MAC, **kw: Any) -> Evidence:
    kw.setdefault("scope", Scope.CLIENT)
    kw.setdefault("kind", "wifi.reconnect")
    return Evidence(type=type_, scope_key=key, **kw)


def lvl(
    value: float, type_: str = "system_cpu_high", key: str = "r1", **kw: Any
) -> Evidence:
    return Evidence(
        type=type_, scope_key=key, scope=Scope.ROUTER, value=value, kind="poll", **kw
    )


def restart(key: str = "r1:dnsmasq") -> Evidence:
    return ev("system_service_restart", key, scope=Scope.ROUTER, kind="svc")


def feed(m: AlarmMachine, now: float, *evidence: Evidence) -> list[Transition]:
    return m.update(now, evidence)


def states(transitions: list[Transition]) -> list[TransitionState]:
    return [t.state for t in transitions]


def open_storm(m: AlarmMachine, start: float = 0.0, key: str = MAC) -> str:
    """Five reconnects 100 s apart; returns the incident id."""
    out: list[Transition] = []
    for i in range(5):
        out = feed(m, start + 100 * i, ev(key=key, event_id=f"{key}:{start}:{i}"))
    assert states(out) == [OPENED]
    return out[0].incident.id


def live(m: AlarmMachine, inc_id: str) -> Any:
    inc = m.get(inc_id)
    assert inc is not None
    return inc


# --- P1-1: small backward clock steps --------------------------------------------


def test_p1_1_small_backward_step_keeps_stored_times() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # evidence 0..400, last_now 400
    assert feed(m, 399) == []  # one second back
    assert feed(m, 100) == []  # 300 s back: still within the skew limit
    inc = live(m, inc_id)
    assert (inc.first_seen, inc.last_seen) == (0, 400)
    # timers unchanged: resolves exactly 1800 s after the last evidence
    assert feed(m, 2199) == []
    out = feed(m, 2200)
    assert states(out) == [RESOLVED]
    assert out[0].incident.resolved_at == 2200


def test_p1_1_evidence_during_a_small_step_back_counts_as_no_time_passed() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    feed(m, 350, ev())  # 50 s back: stamped at the last seen time
    inc = live(m, inc_id)
    assert inc.last_seen == 400
    assert inc.occurrences == 6


def test_p1_1_sync_clock_reports_effective_time_and_shift() -> None:
    m = AlarmMachine()
    assert m.sync_clock(1000).now == 1000
    step = m.sync_clock(999)
    assert (step.now, step.shift) == (1000, 0)
    step = m.sync_clock(1000 - DAY)
    assert (step.now, step.shift) == (1000 - DAY, -DAY)


def test_p1_1_large_step_back_still_shifts_everything() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    feed(m, 400 - 1000)  # beyond the skew limit
    inc = live(m, inc_id)
    assert (inc.first_seen, inc.last_seen) == (-1000, -600)


# --- P1-2: severity raised by evidence -----------------------------------------


def test_p1_2_evidence_severity_on_open_incident_reports_update() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    out = feed(m, 450, ev(severity=Severity.CRITICAL))
    assert states(out) == [UPDATED]
    assert out[0].reason == "severity"
    assert out[0].incident.severity is Severity.CRITICAL
    assert live(m, inc_id).severity is Severity.CRITICAL
    # same severity again: nothing to report
    assert feed(m, 460, ev(severity=Severity.CRITICAL)) == []


def test_p1_2_level_evidence_severity_reports_update_too() -> None:
    m = AlarmMachine()
    for t in (0, 60, 120):
        feed(m, t, lvl(90))
    out = feed(m, 180, lvl(90, severity=Severity.CRITICAL))
    assert states(out) == [UPDATED]
    assert out[0].incident.severity is Severity.CRITICAL


def test_p1_2_acknowledged_incident_stays_silent_on_severity() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    m.acknowledge(inc_id)
    assert feed(m, 450, ev(severity=Severity.CRITICAL)) == []
    assert live(m, inc_id).severity is Severity.CRITICAL


# --- P2-1: maintenance breaks a series -------------------------------------------


def test_p2_1_maintenance_resets_a_level_debounce_series() -> None:
    m = AlarmMachine()
    feed(m, 0, lvl(95))
    feed(m, 60, lvl(95))
    for t in range(120, 1261, 60):
        assert feed(m, t, lvl(95, maintenance=True)) == []
    assert feed(m, 1320, lvl(95)) == []  # series starts again
    assert feed(m, 1380, lvl(95)) == []
    assert states(feed(m, 1440, lvl(95))) == [OPENED]


def test_p2_1_maintenance_resets_a_window_series() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev())
    feed(m, 350, ev(maintenance=True))
    assert feed(m, 400, ev()) == []
    assert m.incidents() == []


def test_p2_1_maintenance_leaves_an_open_incident_alone() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    feed(m, 450, ev(maintenance=True))
    feed(m, 500, ev())
    inc = live(m, inc_id)
    assert inc.status is IncidentStatus.ACTIVE
    assert inc.occurrences == 6


# --- P2-2: reopen counts only evidence after the resolve -------------------------


def test_p2_2_reopen_counts_only_new_evidence() -> None:
    m = AlarmMachine()
    out = feed(m, 0, restart())
    assert states(out) == [OPENED]
    assert out[0].incident.occurrences == 1
    assert states(feed(m, 600)) == [RESOLVED]  # clear 600 < window 3600
    out = feed(m, 1000, restart())  # inside the 900 s cooldown
    assert states(out) == [REOPENED]
    assert out[0].incident.occurrences == 2
    assert len(out[0].incident.evidence) == 2


def test_p2_2_escalation_still_counts_the_whole_window() -> None:
    m = AlarmMachine()
    feed(m, 0, restart())
    feed(m, 600)
    feed(m, 1000, restart())
    out = feed(m, 1100, restart())  # third restart within an hour
    assert states(out) == [UPDATED]
    assert out[0].incident.severity is Severity.CRITICAL


# --- P2-3: ignored type+target stays silent until ignore_until -------------------


def test_p2_3_ignored_incident_returning_after_cooldown_stays_silent() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # cooldown 3600
    assert m.ignore(inc_id, now=450, until=7000)
    assert feed(m, 2300) == []  # resolved silently at 2200
    out: list[Transition] = []
    for i in range(5):
        out += feed(m, 6000 + 50 * i, ev())  # 6000 > 2200 + 3600
    assert out == []
    inc = live(m, inc_id)
    assert inc.status is IncidentStatus.IGNORED
    assert inc.reopen_count == 1
    assert len(m.incidents()) == 1
    # the ignore ends while the condition holds: normal again
    out = feed(m, 7000)
    assert states(out) == [UPDATED]
    assert out[0].incident.status is IncidentStatus.ACTIVE


def test_p2_3_after_ignore_expired_a_new_incident_opens_normally() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    m.ignore(inc_id, now=450, until=3000)
    feed(m, 3001)  # cleared and expired: resolved
    assert live(m, inc_id).status is IncidentStatus.RESOLVED
    out: list[Transition] = []
    for i in range(5):
        out += feed(m, 9000 + 50 * i, ev())
    assert states(out) == [OPENED]
    assert out[0].incident.id != inc_id


# --- P2-4: no retention prune in a forward-jump update --------------------------


def test_p2_4_forward_jump_resolves_but_does_not_prune_in_that_update() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    out = feed(m, 400 + 40 * DAY)
    assert states(out) == [RESOLVED]
    assert m.prune_held is True
    assert m.get(inc_id) is not None  # history kept in the jump update
    # repeated update at the same time: still held
    feed(m, 400 + 40 * DAY)
    assert m.get(inc_id) is not None
    # time moves on normally: retention applies again
    feed(m, 400 + 40 * DAY + 60)
    assert m.prune_held is False
    assert m.get(inc_id) is None


# --- P2-5: restored resolved incidents keep reopen-in-cooldown --------------------


def test_p2_5_restore_without_tracks_still_reopens_within_cooldown() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    feed(m, 2300)  # resolved at 2200
    data = json.loads(json.dumps(m.to_dict()))
    data["tracks"] = []
    restored = AlarmMachine.from_dict(data)
    out: list[Transition] = []
    for i in range(5):
        out += feed(restored, 3000 + 10 * i, ev())
    assert states(out) == [REOPENED]
    assert out[0].incident.id == inc_id


def test_p2_5_restore_points_the_track_at_the_newest_incident() -> None:
    m = AlarmMachine()
    first = open_storm(m)
    feed(m, 2300)
    second = open_storm(m, start=10_000)  # after the cooldown: a new incident
    assert second != first
    feed(m, 13_000)  # resolved at 12_200
    data = json.loads(json.dumps(m.to_dict()))
    data["tracks"] = []
    restored = AlarmMachine.from_dict(data)
    out: list[Transition] = []
    for i in range(5):
        out += feed(restored, 13_100 + 10 * i, ev())
    assert states(out) == [REOPENED]
    assert out[0].incident.id == second


def test_p2_5_full_round_trip_keeps_reopen() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    feed(m, 2300)
    restored = AlarmMachine.from_dict(json.loads(json.dumps(m.to_dict())))
    out: list[Transition] = []
    for i in range(5):
        out += feed(restored, 3000 + 10 * i, ev())
    assert states(out) == [REOPENED]
    assert out[0].incident.id == inc_id


# --- P2-6: settings bounds and int coercion ---------------------------------------


def test_p2_6_merge_settings_coerces_ints_and_enforces_bounds() -> None:
    s = merge_settings(
        {
            "max_events": 3000.0,
            "retention_days": -5,
            "score": {"min_coverage": 1.5, "weights": {"wifi": -1}},
            "thresholds": {
                "wifi_reconnect_storm": {
                    "window": -600,
                    "cooldown": -1,
                    "count": 0,
                    "clear": 0,
                },
                "auto_resolve": {"clear": 0},
                "ignored": {"duration": -1},
                "system_cpu_high": {"debounce": 2.0, "clear": 50, "hold": -5},
                "dhcp_pool_full": {"escalate": {"count": 0, "value": 99}},
            },
        }
    )
    assert s["max_events"] == 3000
    assert type(s["max_events"]) is int
    assert s["retention_days"] == 30
    assert s["score"]["min_coverage"] == 0.5
    assert s["score"]["weights"]["wifi"] == 30
    storm = s["thresholds"]["wifi_reconnect_storm"]
    assert (storm["window"], storm["cooldown"], storm["count"], storm["clear"]) == (
        600,
        3600,
        5,
        1800,
    )
    assert s["thresholds"]["auto_resolve"]["clear"] == 1800
    assert s["thresholds"]["ignored"]["duration"] == 7 * DAY
    cpu = s["thresholds"]["system_cpu_high"]
    assert cpu["debounce"] == 2 and type(cpu["debounce"]) is int
    assert cpu["clear"] == 50  # a level threshold, not a duration
    assert "hold" not in cpu  # not a key of this rule: dropped
    pool = s["thresholds"]["dhcp_pool_full"]["escalate"]
    assert pool["value"] == 99
    assert "count" not in pool


def test_p2_6_bounds_reject_fractional_and_too_large_values() -> None:
    s = merge_settings(
        {
            "max_events": 3000.5,
            "retention_days": 10_000,
            "thresholds": {"system_ram_high": {"hold": -1, "cooldown": 0}},
        }
    )
    assert s["max_events"] == 3000
    assert s["retention_days"] == 30
    assert s["thresholds"]["system_ram_high"]["hold"] == 900
    assert s["thresholds"]["system_ram_high"]["cooldown"] == 0


def test_p2_6_merged_settings_build_a_ring() -> None:
    s = merge_settings({"max_events": 50.0, "retention_days": 2.0})
    ring = EventRing(s["max_events"], s["retention_days"] * DAY)
    assert ring.max_count == 50


# --- P2-7: debounce counts polls, not evidence ------------------------------------


def test_p2_7_three_evidence_in_one_poll_are_one_observation() -> None:
    m = AlarmMachine()
    assert feed(m, 0, lvl(95), lvl(95), lvl(95)) == []
    assert m.incidents() == []
    assert feed(m, 60, lvl(95)) == []
    assert states(feed(m, 120, lvl(95))) == [OPENED]


def test_p2_7_second_observation_in_the_same_poll_is_ignored() -> None:
    m = AlarmMachine()
    for t in (0, 60, 120):
        out = feed(m, t, lvl(95))
    assert states(out) == [OPENED]
    # a clear value in the same poll does not undo the raising one
    assert feed(m, 120, lvl(10)) == []
    assert m.incidents()[0].status is IncidentStatus.ACTIVE


# --- P2-8: types without a rule fall back to auto_resolve ------------------------


def _stored_incident(type_: str, last_seen: float) -> dict[str, Any]:
    return {
        "seq": 1,
        "last_now": last_seen,
        "incidents": [
            {
                "id": "inc-1",
                "type": type_,
                "scope": "router",
                "scope_key": "r1",
                "status": "active",
                "severity": "critical",
                "first_seen": last_seen,
                "last_seen": last_seen,
            }
        ],
        "tracks": [],
    }


def test_p2_8_loaded_incident_without_rule_auto_resolves() -> None:
    for type_ in ("router_unreachable", "lan_unreachable", "something_new"):
        m = AlarmMachine.from_dict(_stored_incident(type_, 100))
        assert feed(m, 100 + 1799) == [], type_
        out = feed(m, 100 + 1800)
        assert states(out) == [RESOLVED], type_
        assert out[0].reason == "quiet"


def test_p2_8_evidence_for_a_type_without_rule_is_still_ignored() -> None:
    m = AlarmMachine()
    assert feed(m, 0, ev("router_unreachable", "r1")) == []
    assert m.incidents() == []


# --- P3 (cheap input checks) ------------------------------------------------------


def test_p3_ignore_rejects_bad_times() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    for now, until in (
        (math.nan, None),
        (math.inf, None),
        (450, math.nan),
        (450, math.inf),
        (450, 450),  # not in the future
        (450, 100),
        ("now", None),
        (True, None),
    ):
        assert m.ignore(inc_id, now, until) is False, (now, until)  # type: ignore[arg-type]
    assert live(m, inc_id).status is IncidentStatus.ACTIVE
    assert m.ignore(inc_id, 450, 451) is True


def test_p3_negative_or_zero_evidence_count_counts_as_one() -> None:
    m = AlarmMachine()
    out: list[Transition] = []
    for i in range(5):
        out = feed(m, 100 * i, ev(count=-3 if i % 2 else 0))
    assert states(out) == [OPENED]
    assert out[0].incident.occurrences == 5


def test_p3_counters_ignore_bad_input() -> None:
    c = EventCounters()
    c.add("r1", "k", 3600, -2)
    c.add("r1", "k", 3600, 0)
    c.add("r1", "k", math.nan)
    c.add("r1", "k", math.inf)
    c.add("r1", "k", 3600, True)  # type: ignore[arg-type]
    assert c.to_dict() == {}
    c.add("r1", "k", 3600, 2)
    assert c.hourly("r1", "k", 3600, 1) == 2


def test_p3_stored_event_with_negative_count_is_clamped() -> None:
    event = NetEvent.from_dict(
        {
            "id": "e1",
            "ts": 1.0,
            "router": "r1",
            "category": "wifi",
            "kind": "k",
            "count": -4,
        }
    )
    assert event is not None
    assert event.count == 1
    assert event.category is Category.WIFI


def test_p3_stored_track_entries_with_bad_counts_are_skipped() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev(event_id=f"e{i}"))
    data = json.loads(json.dumps(m.to_dict()))
    data["tracks"][0]["entries"] += [[350, -7, None, ""], [360, 0, None, ""]]
    restored = AlarmMachine.from_dict(data)
    assert states(feed(restored, 400, ev(event_id="e4"))) == [OPENED]


def test_p1_1_ring_shift_moves_event_times_like_the_machine() -> None:
    ring = EventRing(max_count=5, max_age=DAY)
    ring.add(
        NetEvent(
            id="e1",
            ts=1000.0,
            router="r1",
            category=Category.WIFI,
            kind="k",
            src_ts=990.0,
        )
    )
    ring.shift(-500)
    [event] = list(ring)
    assert event.ts == 500
    assert event.src_ts == 990  # router time is not ours to move
    assert ring.max_count == 5
    ring.shift(0)
    assert next(iter(ring)).ts == 500
