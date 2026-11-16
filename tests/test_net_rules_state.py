"""Tests for net_rules.py (P1 part): default settings and the alarm state machine.

Time is always passed in; the tests use small absolute second values.
"""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest

from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_rules import (
    DEFAULT_SETTINGS,
    AlarmMachine,
    Evidence,
    Transition,
    TransitionState,
    merge_settings,
)

MAC = "AA:BB:CC:DD:EE:01"
OPENED = TransitionState.OPENED
RESOLVED = TransitionState.RESOLVED
REOPENED = TransitionState.REOPENED
UPDATED = TransitionState.UPDATED

STORM = "wifi_reconnect_storm"

C7_RULES = (
    "wifi_reconnect_storm",
    "wifi_auth_failures",
    "wifi_auth_wave",
    "wifi_mass_disconnect",
    "wifi_no_ip",
    "wifi_dhcp_after_connect",
    "wifi_band_flapping",
    "wifi_roam_flapping",
    "wifi_weak_clients",
    "wifi_channel_busy",
    "system_cpu_high",
    "system_ram_high",
    "system_reboot",
    "system_service_restart",
    "system_clock_skew",
    "system_conntrack_jump",
    "lan_port_flap",
    "lan_port_speed_drop",
    "lan_port_errors",
    "lan_port_load",
    "lan_uplink_down",
    "lan_lldp_change",
    "wan_down",
    "wan_unstable",
    "wan_ip_changed",
    "dhcp_pool_full",
    "dhcp_conflict",
    "auto_resolve",
    "ignored",
)


def ev(type_: str = STORM, key: str = MAC, **kw: Any) -> Evidence:
    kw.setdefault("scope", Scope.CLIENT)
    kw.setdefault("kind", "wifi.reconnect")
    return Evidence(type=type_, scope_key=key, **kw)


def feed(m: AlarmMachine, now: float, *evidence: Evidence) -> list[Transition]:
    return m.update(now, evidence)


def states(transitions: list[Transition]) -> list[TransitionState]:
    return [t.state for t in transitions]


def open_storm(m: AlarmMachine, start: float = 0.0, key: str = MAC) -> str:
    """Five reconnects 100 s apart; returns the incident id."""
    out: list[Transition] = []
    for i in range(5):
        out = feed(m, start + 100 * i, ev(key=key, event_id=f"r1:{i}"))
    assert states(out) == [OPENED]
    return out[0].incident.id


# --- settings -----------------------------------------------------------------


def test_defaults_have_one_entry_per_c7_rule() -> None:
    thresholds = DEFAULT_SETTINGS["thresholds"]
    assert set(C7_RULES) <= set(thresholds)
    for name in C7_RULES:
        assert isinstance(thresholds[name], dict), name


def test_defaults_top_level_matches_plan_c8() -> None:
    assert DEFAULT_SETTINGS["schema"] == 1
    assert DEFAULT_SETTINGS["retention_days"] == 30
    assert DEFAULT_SETTINGS["max_events"] == 3000
    assert DEFAULT_SETTINGS["notify_min_severity"] == "warning"
    assert DEFAULT_SETTINGS["score"]["weights"] == {
        "wifi": 30,
        "system": 25,
        "lan": 15,
        "wan": 20,
        "dhcp_dns": 10,
    }
    assert DEFAULT_SETTINGS["score"]["penalty"] == {
        "critical": 40,
        "warning": 15,
        "info": 3,
    }
    assert DEFAULT_SETTINGS["exclusions"] == {
        "macs": [],
        "ssids": [],
        "routers": [],
        "incident_types": [],
    }
    assert DEFAULT_SETTINGS["maintenance"] == {"fleet_until": None}
    assert DEFAULT_SETTINGS["optional_sources"] == {"hostapd_status": False}


def test_default_rules_are_well_formed() -> None:
    for name, rule in DEFAULT_SETTINGS["thresholds"].items():
        if name in ("auto_resolve", "ignored"):
            continue
        assert rule["mode"] in ("window", "level", "event"), name
        Severity(rule["severity"])
        assert rule["cooldown"] >= 0, name
        if rule["mode"] == "window":
            assert {"count", "window", "clear"} <= set(rule), name
        if rule["mode"] == "level":
            assert {"raise", "clear", "debounce"} <= set(rule), name
            assert rule["clear"] <= rule["raise"], name


def test_default_values_match_plan_table_c7() -> None:
    t = DEFAULT_SETTINGS["thresholds"]
    storm = t[STORM]
    assert (storm["count"], storm["window"], storm["clear"], storm["cooldown"]) == (
        5,
        600,
        1800,
        3600,
    )
    assert storm["severity"] == "warning"
    assert (t["system_cpu_high"]["raise"], t["system_cpu_high"]["clear"]) == (80, 65)
    assert t["system_cpu_high"]["debounce"] == 3
    assert (t["dhcp_pool_full"]["raise"], t["dhcp_pool_full"]["clear"]) == (90, 85)
    assert t["dhcp_pool_full"]["escalate"] == {"severity": "critical", "value": 98}
    assert t["system_service_restart"]["escalate"] == {
        "severity": "critical",
        "count": 3,
        "window": 3600,
    }
    assert t["wifi_weak_clients"]["hold"] == 600
    assert t["wifi_mass_disconnect"]["mode"] == "event"
    assert t["system_reboot"]["mode"] == "event"
    assert t["wan_down"]["severity"] == "critical"
    assert t["auto_resolve"]["clear"] == 1800
    assert t["ignored"]["duration"] == 7 * 86400


def test_merge_settings_returns_defaults_for_junk() -> None:
    for junk in (None, "x", 5, [], {}):
        assert merge_settings(junk) == DEFAULT_SETTINGS


def test_merge_settings_overlays_valid_values() -> None:
    merged = merge_settings(
        {
            "retention_days": 7,
            "notify_min_severity": "critical",
            "thresholds": {STORM: {"count": 8, "window": 300.5}},
            "exclusions": {"macs": [MAC]},
            "maintenance": {"fleet_until": 12345},
        }
    )
    assert merged["retention_days"] == 7
    assert merged["notify_min_severity"] == "critical"
    assert merged["thresholds"][STORM]["count"] == 8
    assert merged["thresholds"][STORM]["window"] == 300.5
    assert merged["thresholds"][STORM]["clear"] == 1800  # untouched default
    assert merged["exclusions"]["macs"] == [MAC]
    assert merged["maintenance"]["fleet_until"] == 12345


def test_merge_settings_discards_wrong_types_and_unknown_keys() -> None:
    merged = merge_settings(
        {
            "unknown_top": 1,
            "schema": 99,
            "retention_days": "thirty",
            "max_events": True,
            "notify_min_severity": "loud",
            "thresholds": {
                STORM: {
                    "count": "five",
                    "window": float("nan"),
                    "nope": 1,
                    "severity": "meh",
                },
                "invented_rule": {"count": 1},
                "system_cpu_high": "not a dict",
                "dhcp_pool_full": {"escalate": {"value": "x", "severity": "info"}},
            },
            "exclusions": {"macs": [MAC, 5, None], "ssids": "nope"},
            "score": {"weights": {"wifi": "heavy", "bogus": 1}},
        }
    )
    assert merged["schema"] == 1
    assert merged["retention_days"] == 30
    assert merged["max_events"] == 3000
    assert merged["notify_min_severity"] == "warning"
    assert "unknown_top" not in merged
    assert merged["thresholds"][STORM] == DEFAULT_SETTINGS["thresholds"][STORM]
    assert "invented_rule" not in merged["thresholds"]
    assert (
        merged["thresholds"]["system_cpu_high"]
        == DEFAULT_SETTINGS["thresholds"]["system_cpu_high"]
    )
    assert merged["thresholds"]["dhcp_pool_full"]["escalate"] == {
        "severity": "info",
        "value": 98,
    }
    assert merged["exclusions"]["macs"] == [MAC]
    assert merged["exclusions"]["ssids"] == []
    assert merged["score"]["weights"] == DEFAULT_SETTINGS["score"]["weights"]


def test_merge_settings_cannot_change_rule_mode() -> None:
    merged = merge_settings({"thresholds": {STORM: {"mode": "level"}}})
    assert merged["thresholds"][STORM]["mode"] == "window"


def test_merge_settings_does_not_touch_defaults_or_share_state() -> None:
    before = copy.deepcopy(DEFAULT_SETTINGS)
    merged = merge_settings({"thresholds": {STORM: {"count": 9}}})
    merged["thresholds"][STORM]["window"] = 1
    merged["exclusions"]["macs"].append("x")
    merged["thresholds"]["dhcp_pool_full"]["escalate"]["value"] = 1
    assert DEFAULT_SETTINGS == before
    assert merge_settings(None) == before


def test_machine_uses_overridden_threshold() -> None:
    m = AlarmMachine({"thresholds": {STORM: {"count": 2}}})
    assert feed(m, 0, ev()) == []
    assert states(feed(m, 10, ev())) == [OPENED]


# --- window rules: threshold, dedup, auto-resolve, cooldown, reopen -------------


def test_window_rule_needs_count_within_window() -> None:
    m = AlarmMachine()
    for i in range(4):
        assert feed(m, 100 * i, ev()) == []
    # a fifth one after the window has moved on does not complete the storm:
    assert feed(m, 100 * 4 + 400, ev()) == []
    assert m.incidents() == []


def test_storm_example_ak3() -> None:
    """AK3: 5 reconnects in 600 s open; more only raise occurrences; quiet resolves;
    a new storm inside the cooldown reopens the same incident."""
    m = AlarmMachine()
    for i in range(4):
        assert feed(m, 100 * i, ev(event_id=f"r1:{i}")) == []
    opened = feed(m, 400, ev(event_id="r1:4"))
    assert states(opened) == [OPENED]
    inc = opened[0].incident
    assert inc.type == STORM
    assert inc.scope_key == MAC
    assert inc.status is IncidentStatus.ACTIVE
    assert inc.severity is Severity.WARNING
    assert inc.occurrences == 5
    assert inc.first_seen == 0.0
    assert inc.last_seen == 400.0
    assert [e["id"] for e in inc.evidence] == [f"r1:{i}" for i in range(5)]

    # more evidence: no transition, occurrences grow
    assert feed(m, 450, ev()) == []
    assert feed(m, 500, ev()) == []
    live = m.get(inc.id)
    assert live is not None
    assert live.occurrences == 7
    assert live.last_seen == 500
    assert live.reopen_count == 0

    # quiet for 1800 s resolves (exactly at last evidence + clear)
    assert feed(m, 2299) == []
    resolved = feed(m, 2300)
    assert states(resolved) == [RESOLVED]
    assert resolved[0].incident.id == inc.id
    assert resolved[0].incident.status is IncidentStatus.RESOLVED
    assert resolved[0].incident.resolved_at == 2300

    # new storm inside the cooldown (3600 after resolve) reopens the SAME incident
    for i in range(4):
        assert feed(m, 2400 + 50 * i, ev()) == []
    reopened = feed(m, 2600, ev())
    assert states(reopened) == [REOPENED]
    assert reopened[0].incident.id == inc.id
    assert reopened[0].incident.reopen_count == 1
    assert reopened[0].incident.status is IncidentStatus.ACTIVE
    assert reopened[0].incident.resolved_at is None
    assert len(m.incidents()) == 1


def test_new_incident_after_cooldown() -> None:
    m = AlarmMachine()
    first = open_storm(m)  # last evidence 400 -> resolves 2200
    assert states(feed(m, 2200)) == [RESOLVED]
    start = 2200 + 3600  # cooldown over
    for i in range(4):
        assert feed(m, start + 50 * i, ev()) == []
    out = feed(m, start + 200, ev())
    assert states(out) == [OPENED]
    assert out[0].incident.id != first
    assert out[0].incident.reopen_count == 0
    assert len(m.incidents()) == 2


def test_distinct_scope_keys_are_separate_incidents() -> None:
    m = AlarmMachine()
    a = open_storm(m, key="AA:00")
    b = open_storm(m, key="BB:00")
    assert a != b
    assert len(m.incidents()) == 2


def test_evidence_list_keeps_at_most_20_entries() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    for i in range(50):
        feed(m, 401 + i, ev(event_id=f"x:{i}"))
    inc = m.get(inc_id)
    assert inc is not None
    assert len(inc.evidence) == 20
    assert inc.evidence[-1]["id"] == "x:49"
    assert inc.occurrences == 55


def test_evidence_count_field_counts_toward_threshold_and_occurrences() -> None:
    m = AlarmMachine()
    out = feed(m, 0, ev(count=5, event_id="r1:1"))
    assert states(out) == [OPENED]
    assert out[0].incident.occurrences == 5


def test_auth_wave_clears_only_below_two_in_clear_window() -> None:
    m = AlarmMachine()
    out = feed(
        m, 0, *[ev("wifi_auth_wave", "fleet", scope=Scope.FLEET) for _ in range(10)]
    )
    assert states(out) == [OPENED]
    assert feed(m, 1000, ev("wifi_auth_wave", "fleet", scope=Scope.FLEET)) == []
    # at 1800 the burst at t=0 has left the window; one evidence (< 2) remains
    assert states(feed(m, 1800)) == [RESOLVED]


def test_one_shot_event_rule_opens_on_first_evidence_and_ages_out() -> None:
    m = AlarmMachine()
    out = feed(
        m, 0, ev("system_reboot", "r1", scope=Scope.ROUTER, kind="system.reboot")
    )
    assert states(out) == [OPENED]
    assert out[0].incident.severity is Severity.WARNING
    assert feed(m, 1799) == []
    assert states(feed(m, 1800)) == [RESOLVED]  # general auto-resolve, no clear key
    # no cooldown: the next reboot is a new incident, not a reopen
    out = feed(m, 1900, ev("system_reboot", "r1", scope=Scope.ROUTER))
    assert states(out) == [OPENED]
    assert len(m.incidents()) == 2


def test_one_shot_with_cooldown_reopens() -> None:
    m = AlarmMachine()
    scope = {"scope": Scope.ROUTER}
    first = feed(m, 0, ev("wifi_mass_disconnect", "r1:phy0", **scope))
    assert states(first) == [OPENED]
    assert states(feed(m, 1800)) == [RESOLVED]
    again = feed(m, 2000, ev("wifi_mass_disconnect", "r1:phy0", **scope))  # < 600 after
    assert states(again) == [REOPENED]
    assert again[0].incident.id == first[0].incident.id


def test_unknown_rule_type_is_ignored() -> None:
    m = AlarmMachine()
    assert feed(m, 0, ev("not_a_rule"), ev("auto_resolve"), ev("ignored")) == []
    assert m.incidents() == []


# --- level rules: debounce, hold, hysteresis ------------------------------------


def lvl(value: float, type_: str = "system_cpu_high", key: str = "r1") -> Evidence:
    return Evidence(
        type=type_, scope_key=key, scope=Scope.ROUTER, value=value, kind="poll"
    )


def weak(value: float) -> Evidence:
    return lvl(value, "wifi_weak_clients", "ap1")


def pool(value: float) -> Evidence:
    return lvl(value, "dhcp_pool_full", "r1:lan")


def restart(key: str = "r1:dnsmasq") -> Evidence:
    return ev("system_service_restart", key, scope=Scope.ROUTER)


def test_level_rule_debounces_over_consecutive_polls() -> None:
    m = AlarmMachine()
    assert feed(m, 0, lvl(85)) == []
    assert feed(m, 60, lvl(90)) == []
    out = feed(m, 120, lvl(81))
    assert states(out) == [OPENED]
    assert out[0].incident.occurrences == 3
    assert out[0].incident.severity is Severity.WARNING


def test_level_debounce_streak_resets_on_a_good_poll() -> None:
    m = AlarmMachine()
    feed(m, 0, lvl(85))
    feed(m, 60, lvl(85))
    assert feed(m, 120, lvl(40)) == []  # below clear: streak gone
    assert feed(m, 180, lvl(85)) == []
    assert feed(m, 240, lvl(85)) == []
    assert states(feed(m, 300, lvl(85))) == [OPENED]


def test_level_value_in_hysteresis_band_breaks_the_streak_but_keeps_open_incident() -> (
    None
):
    m = AlarmMachine()
    feed(m, 0, lvl(85))
    feed(m, 60, lvl(85))
    assert feed(m, 120, lvl(70)) == []  # band 65..80: not "raised"
    assert feed(m, 180, lvl(85)) == []
    assert feed(m, 240, lvl(85)) == []
    inc = feed(m, 300, lvl(85))[0].incident
    # open incident: band value neither resolves nor counts as evidence
    assert feed(m, 360, lvl(70)) == []
    live = m.get(inc.id)
    assert live is not None
    assert live.status is IncidentStatus.ACTIVE
    assert live.occurrences == 3
    # only a value below the clear level resolves
    assert feed(m, 420, lvl(65)) == []
    assert states(feed(m, 480, lvl(64.9))) == [RESOLVED]


def test_level_cooldown_reopens_then_new_incident() -> None:
    m = AlarmMachine()
    for t in (0, 60, 120):
        out = feed(m, t, lvl(90))
    first = out[0].incident.id
    assert states(feed(m, 180, lvl(10))) == [RESOLVED]
    for t in (240, 300):
        assert feed(m, t, lvl(90)) == []
    reopened = feed(m, 360, lvl(90))  # 180 s after resolve, cooldown is 900
    assert states(reopened) == [REOPENED]
    assert reopened[0].incident.id == first
    assert reopened[0].incident.reopen_count == 1
    assert states(feed(m, 420, lvl(10))) == [RESOLVED]
    late = 420 + 900  # cooldown over
    feed(m, late, lvl(90))
    feed(m, late + 60, lvl(90))
    out = feed(m, late + 120, lvl(90))
    assert states(out) == [OPENED]
    assert out[0].incident.id != first


def test_level_hold_time_must_pass_before_opening() -> None:
    m = AlarmMachine()
    assert feed(m, 0, weak(3)) == []
    assert feed(m, 300, weak(4)) == []
    assert feed(m, 599, weak(4)) == []
    assert states(feed(m, 600, weak(3))) == [OPENED]


def test_level_hold_restarts_after_condition_drops() -> None:
    m = AlarmMachine()
    feed(m, 0, weak(3))
    assert feed(m, 300, weak(1)) == []
    assert feed(m, 400, weak(3)) == []
    assert feed(m, 900, weak(3)) == []  # only 500 s since 400
    assert states(feed(m, 1000, weak(3))) == [OPENED]


def test_level_incident_resolves_when_observations_stop() -> None:
    m = AlarmMachine()
    for t in (0, 60, 120):
        feed(m, t, lvl(90))
    assert feed(m, 120 + 1799) == []
    assert states(feed(m, 120 + 1800)) == [RESOLVED]


def test_boolean_condition_rule_wan_down_opens_on_first_poll() -> None:
    m = AlarmMachine()
    out = feed(m, 0, lvl(1, "wan_down", "gw"))
    assert states(out) == [OPENED]
    assert out[0].incident.severity is Severity.CRITICAL
    assert states(feed(m, 60, lvl(0, "wan_down", "gw"))) == [RESOLVED]


# --- severity escalation --------------------------------------------------------


def test_dhcp_pool_full_escalates_to_critical_at_98_percent() -> None:
    m = AlarmMachine()
    feed(m, 0, pool(92))
    out = feed(m, 60, pool(93))
    assert states(out) == [OPENED]
    assert out[0].incident.severity is Severity.WARNING
    esc = feed(m, 120, pool(98))
    assert states(esc) == [UPDATED]
    assert esc[0].incident.severity is Severity.CRITICAL
    # does not flap back down while the incident is open
    assert feed(m, 180, pool(91)) == []
    live = m.incidents()[0]
    assert live.severity is Severity.CRITICAL


def test_dhcp_pool_full_can_open_directly_as_critical() -> None:
    m = AlarmMachine()
    feed(m, 0, pool(99))
    out = feed(m, 60, pool(99))
    assert out[0].incident.severity is Severity.CRITICAL


def test_service_restart_escalates_at_three_in_an_hour() -> None:
    m = AlarmMachine()
    first = feed(m, 0, restart())
    assert states(first) == [OPENED]
    assert first[0].incident.severity is Severity.WARNING
    assert feed(m, 100, restart()) == []
    esc = feed(m, 200, restart())
    assert states(esc) == [UPDATED]
    assert esc[0].incident.severity is Severity.CRITICAL


def test_service_restarts_spread_over_more_than_an_hour_do_not_escalate() -> None:
    m = AlarmMachine()
    out = feed(m, 0, restart())
    out += feed(m, 600)  # 600 s stable: resolved
    out += feed(m, 700, restart())  # inside the cooldown: reopened, 2 in the hour
    out += feed(m, 1300)
    out += feed(m, 5000, restart())  # cooldown over: new incident, 1 in the hour
    assert states(out) == [OPENED, RESOLVED, REOPENED, RESOLVED, OPENED]
    assert all(t.incident.severity is Severity.WARNING for t in out)


def test_evidence_severity_raises_incident_severity() -> None:
    m = AlarmMachine()
    out = feed(
        m, 0, ev("wifi_no_ip", scope=Scope.CLIENT, value=1, severity=Severity.WARNING)
    )
    assert out == []  # debounce: 2 polls
    out = feed(
        m, 60, ev("wifi_no_ip", scope=Scope.CLIENT, value=1, severity=Severity.WARNING)
    )
    assert out[0].incident.severity is Severity.WARNING  # rule default is info


def test_inferred_evidence_caps_confidence() -> None:
    m = AlarmMachine()
    out = feed(
        m,
        0,
        ev(
            "lan_uplink_down",
            "r1:lan1",
            scope=Scope.PORT,
            value=1,
            origin=Origin.INFERRED,
            confidence=0.95,
            cause="uplink_down",
            cause_status=CauseStatus.HYPOTHESIS,
        ),
    )
    inc = out[0].incident
    assert inc.origin is Origin.INFERRED
    assert inc.confidence == pytest.approx(0.6)
    assert inc.cause == "uplink_down"
    assert inc.cause_status is CauseStatus.HYPOTHESIS


def test_observed_evidence_keeps_confidence_and_routers() -> None:
    m = AlarmMachine()
    out = feed(
        m,
        0,
        ev(
            "system_reboot",
            "r1",
            scope=Scope.ROUTER,
            confidence=0.8,
            router="r1",
            affected=3,
        ),
    )
    inc = out[0].incident
    assert inc.origin is Origin.OBSERVED
    assert inc.confidence == pytest.approx(0.8)
    assert inc.routers == ["r1"]
    assert inc.affected == 3


# --- acknowledge / ignore ---------------------------------------------------------


def test_acknowledged_stays_until_resolved_without_new_transitions() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    assert m.acknowledge(inc_id) is True
    live = m.get(inc_id)
    assert live is not None and live.status is IncidentStatus.ACKNOWLEDGED
    assert feed(m, 450, ev()) == []
    assert feed(m, 500, ev()) == []
    live = m.get(inc_id)
    assert live is not None
    assert live.status is IncidentStatus.ACKNOWLEDGED
    assert live.occurrences == 7
    resolved = feed(m, 2300)
    assert states(resolved) == [RESOLVED]
    assert resolved[0].incident.status is IncidentStatus.RESOLVED


def test_acknowledged_incident_gets_no_updated_transition_on_escalation() -> None:
    m = AlarmMachine()
    inc_id = feed(m, 0, restart("r1:x"))[0].incident.id
    assert m.acknowledge(inc_id) is True
    feed(m, 100, restart("r1:x"))
    assert feed(m, 200, restart("r1:x")) == []
    live = m.get(inc_id)
    assert live is not None and live.severity is Severity.CRITICAL


def test_acknowledge_requires_an_active_incident() -> None:
    m = AlarmMachine()
    assert m.acknowledge("nope") is False
    inc_id = open_storm(m)
    feed(m, 2300)  # resolved
    assert m.acknowledge(inc_id) is False
    assert m.acknowledge(inc_id) is False


def test_ignored_is_suppressed_and_applies_again_after_expiry() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    assert m.ignore(inc_id, now=450, until=1000) is True
    live = m.get(inc_id)
    assert live is not None
    assert live.status is IncidentStatus.IGNORED
    assert live.ignore_until == 1000
    assert feed(m, 500, ev()) == []  # suppressed, but counted
    assert feed(m, 900, ev()) == []
    live = m.get(inc_id)
    assert live is not None and live.occurrences == 7
    # expiry: still live -> behaves like normal again
    out = feed(m, 1001)
    assert states(out) == [UPDATED]
    assert out[0].incident.status is IncidentStatus.ACTIVE
    # and from then on normal: resolves 1800 after the last evidence (900)
    assert states(feed(m, 2700)) == [RESOLVED]


def test_ignore_default_duration_is_seven_days() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    assert m.ignore(inc_id, now=1000) is True
    live = m.get(inc_id)
    assert live is not None and live.ignore_until == 1000 + 7 * 86400


def test_ignored_incident_resolving_silently_then_expiring() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    m.ignore(inc_id, now=450, until=3000)
    assert feed(m, 2300) == []  # condition cleared, but suppressed
    live = m.get(inc_id)
    assert live is not None and live.status is IncidentStatus.IGNORED
    assert feed(m, 3001) == []  # expiry of a cleared incident: silently resolved
    live = m.get(inc_id)
    assert live is not None and live.status is IncidentStatus.RESOLVED


def test_ignore_survives_a_reopen_inside_the_cooldown() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    m.ignore(inc_id, now=450, until=5000)
    feed(m, 2300)  # cleared silently
    out: list[Transition] = []
    for i in range(5):
        out += feed(m, 2400 + 50 * i, ev())
    assert out == []  # reopened, but silently
    live = m.get(inc_id)
    assert live is not None
    assert live.status is IncidentStatus.IGNORED
    assert live.reopen_count == 1


def test_ignore_requires_open_incident() -> None:
    m = AlarmMachine()
    assert m.ignore("nope", now=0) is False
    inc_id = open_storm(m)
    feed(m, 2300)
    assert m.ignore(inc_id, now=2400) is False


# --- maintenance -------------------------------------------------------------------


def test_maintenance_evidence_never_opens_an_incident() -> None:
    m = AlarmMachine()
    for i in range(20):
        assert feed(m, i, ev(maintenance=True)) == []
    assert m.incidents() == []


def test_maintenance_evidence_does_not_count_towards_threshold() -> None:
    m = AlarmMachine()
    for i in range(3):
        feed(m, i, ev(maintenance=True))
    for i in range(4):
        assert feed(m, 10 + i, ev()) == []
    assert states(feed(m, 20, ev())) == [OPENED]
    assert m.incidents()[0].occurrences == 5


def test_maintenance_evidence_does_not_feed_an_open_incident() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # last real evidence at 400
    assert feed(m, 1500, ev(maintenance=True)) == []
    live = m.get(inc_id)
    assert live is not None and live.occurrences == 5 and live.last_seen == 400
    assert states(feed(m, 2200)) == [RESOLVED]


def test_maintenance_level_observation_is_skipped() -> None:
    m = AlarmMachine()
    feed(m, 0, lvl(90))
    feed(m, 60, lvl(90))
    maint = Evidence(
        type="system_cpu_high",
        scope_key="r1",
        scope=Scope.ROUTER,
        value=90,
        maintenance=True,
    )
    assert feed(m, 120, maint) == []
    assert m.incidents() == []


# --- clock jumps -------------------------------------------------------------------


def test_clock_going_backwards_opens_and_resolves_nothing() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev())  # 4 of 5
    assert feed(m, 300 - 86400) == []  # jump back a day
    assert m.incidents() == []


def test_clock_going_backwards_keeps_open_incident_and_its_timers() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # last evidence 400
    base = 400 - 86400
    assert feed(m, base) == []  # jump back a day
    live = m.get(inc_id)
    assert live is not None and live.status is IncidentStatus.ACTIVE
    assert feed(m, base + 1799) == []
    assert states(feed(m, base + 1800)) == [RESOLVED]


def test_clock_going_backwards_a_little_is_harmless() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    for t in (390, 380, 400, 399):
        assert feed(m, t) == []
    live = m.get(inc_id)
    assert live is not None and live.status is IncidentStatus.ACTIVE


def test_clock_jump_back_keeps_level_streak_without_opening() -> None:
    m = AlarmMachine()
    feed(m, 1000, lvl(90))
    feed(m, 1060, lvl(90))
    assert feed(m, 5) == []  # jump back, no new poll: nothing happens
    assert m.incidents() == []
    out = feed(m, 65, lvl(90))  # the third consecutive poll
    assert states(out) == [OPENED]


def test_clock_jump_back_does_not_crash_with_acked_and_ignored_incidents() -> None:
    m = AlarmMachine()
    a = open_storm(m, key="A")
    b = open_storm(m, start=1000, key="B")
    m.acknowledge(a)
    m.ignore(b, now=1400, until=3000)
    for t in (1200, 1100, 10000, 5):
        feed(m, t)
    assert len(m.incidents()) == 2


# --- persistence ---------------------------------------------------------------------


def snapshot(m: AlarmMachine) -> list[dict[str, Any]]:
    return [i.to_dict() for i in m.incidents()]


def test_state_round_trip_preserves_behaviour() -> None:
    m = AlarmMachine()
    open_storm(m, start=0, key="A")  # resolves at 2200
    open_storm(m, start=500, key="B")  # resolves at 2700
    feed(m, 2250)
    feed(m, 2260, lvl(90))  # level track mid-streak
    feed(m, 2320, lvl(90))
    acked = open_storm(m, start=3000, key="C")  # last evidence 3400
    m.acknowledge(acked)

    data = json.loads(json.dumps(m.to_dict()))
    restored = AlarmMachine.from_dict(data)
    assert snapshot(restored) == snapshot(m)

    script: list[tuple[float, list[Evidence]]] = [
        (3500, [lvl(90)]),  # completes the debounce: opens
        (3600, [ev(key="A")]),  # one reconnect for a resolved incident
        (5300, []),  # C and the level incident resolve
        (5400, [ev(key="B")]),
        (9000, []),
    ]
    seen: list[TransitionState] = []
    for now, items in script:
        a = m.update(now, items)
        b = restored.update(now, items)
        assert [(t.state, t.incident.to_dict()) for t in a] == [
            (t.state, t.incident.to_dict()) for t in b
        ]
        seen += states(a)
    assert OPENED in seen and RESOLVED in seen
    assert snapshot(restored) == snapshot(m)


def test_restored_ids_do_not_collide_with_new_ones() -> None:
    m = AlarmMachine()
    open_storm(m, key="A")
    restored = AlarmMachine.from_dict(json.loads(json.dumps(m.to_dict())))
    new_id = open_storm(restored, start=1000, key="B")
    assert new_id not in {i.id for i in m.incidents()}


def test_from_dict_survives_damaged_state() -> None:
    for junk in (None, "x", [], {}, {"incidents": "no", "tracks": 5}):
        m = AlarmMachine.from_dict(junk)
        assert m.incidents() == []
    data = AlarmMachine().to_dict()
    data["incidents"] = [{"id": "broken"}, None, 5]
    data["tracks"] = [{"type": STORM}, "junk", None]
    assert AlarmMachine.from_dict(data).incidents() == []


def test_restored_open_incident_without_track_still_auto_resolves() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # last_seen 400
    data = m.to_dict()
    data["tracks"] = []
    restored = AlarmMachine.from_dict(data)
    assert feed(restored, 400 + 1799) == []
    out = feed(restored, 400 + 1800)
    assert states(out) == [RESOLVED]
    assert out[0].incident.id == inc_id


def test_restore_with_earlier_clock_is_treated_as_jump_back() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    restored = AlarmMachine.from_dict(json.loads(json.dumps(m.to_dict())))
    assert restored.update(100, []) == []
    live = restored.get(inc_id)
    assert live is not None and live.status is IncidentStatus.ACTIVE


# --- caps ------------------------------------------------------------------------------


def test_active_incidents_are_never_dropped_by_the_cap() -> None:
    m = AlarmMachine(max_incidents=5)
    for i in range(12):
        feed(m, 0, ev("system_reboot", f"r{i}", scope=Scope.ROUTER))
    assert len(m.incidents()) == 12  # all active: cap does not apply
    assert all(i.status is IncidentStatus.ACTIVE for i in m.incidents())
    # resolve ten of them, keep two alive with fresh evidence
    feed(
        m,
        1700,
        ev("system_reboot", "r0", scope=Scope.ROUTER),
        ev("system_reboot", "r1", scope=Scope.ROUTER),
    )
    out = feed(m, 1800)
    assert len(out) == 10
    kept = m.incidents()
    assert {i.scope_key for i in kept if i.status is IncidentStatus.ACTIVE} == {
        "r0",
        "r1",
    }
    assert len(kept) == 5  # 2 active + 3 newest resolved
    assert all(
        i.status is IncidentStatus.ACTIVE for i in kept if i.scope_key in ("r0", "r1")
    )


def test_acknowledged_incidents_survive_the_cap_too() -> None:
    m = AlarmMachine(max_incidents=1)
    ids = [
        feed(m, 0, ev("system_reboot", f"r{i}", scope=Scope.ROUTER))[0].incident.id
        for i in range(3)
    ]
    for inc_id in ids:
        m.acknowledge(inc_id)
    feed(m, 10)
    assert len(m.incidents()) == 3


def test_resolved_incidents_beyond_retention_are_dropped() -> None:
    m = AlarmMachine()
    feed(m, 0, ev("system_reboot", "r1", scope=Scope.ROUTER))
    feed(m, 1800)  # resolved
    assert len(m.incidents()) == 1
    feed(m, 1800 + 31 * 86400)
    assert m.incidents() == []


# --- evidence helper ---------------------------------------------------------------------


def test_evidence_from_event_copies_relevant_fields() -> None:
    event = NetEvent(
        id="r1:5",
        ts=10.0,
        router="r1",
        category=Category.WIFI,
        kind="wifi.reconnect",
        count=2,
        cause="ap_reboot",
        cause_status=CauseStatus.CONFIRMED,
        confidence=0.9,
        origin=Origin.INFERRED,
        maintenance=True,
    )
    e = Evidence.from_event(event, STORM, Scope.CLIENT, MAC)
    assert (e.type, e.scope, e.scope_key) == (STORM, Scope.CLIENT, MAC)
    assert (e.event_id, e.kind, e.router, e.count) == (
        "r1:5",
        "wifi.reconnect",
        "r1",
        2,
    )
    assert e.cause == "ap_reboot"
    assert e.cause_status is CauseStatus.CONFIRMED
    assert e.confidence == 0.9
    assert e.origin is Origin.INFERRED
    assert e.maintenance is True


# --- dedup by event id -------------------------------------------------------------------


def test_same_event_id_fed_twice_counts_once() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev(event_id=f"r1:{i}"))
    # the fourth line re-read (log re-ingest): no fifth reconnect
    assert feed(m, 350, ev(event_id="r1:3")) == []
    assert m.incidents() == []
    assert states(feed(m, 400, ev(event_id="r1:4"))) == [OPENED]


def test_duplicate_event_id_does_not_raise_occurrences_of_open_incident() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # ids r1:0 .. r1:4
    assert feed(m, 450, ev(event_id="r1:4"), ev(event_id="r1:2")) == []
    live = m.get(inc_id)
    assert live is not None
    assert live.occurrences == 5
    assert live.last_seen == 400  # a duplicate is not fresh evidence either


def test_evidence_without_event_id_is_never_deduplicated() -> None:
    m = AlarmMachine()
    out: list[Transition] = []
    for t in range(5):
        out += feed(m, t, ev())
    assert states(out) == [OPENED]


# --- clock jumps forward -------------------------------------------------------------------


def test_clock_jump_forward_resolves_at_the_moment_the_condition_cleared() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)  # last evidence 400
    out = feed(m, 400 + 86400)  # jump a day ahead
    assert states(out) == [RESOLVED]
    assert out[0].incident.id == inc_id
    assert out[0].incident.resolved_at == 400 + 1800  # not the jumped clock
    assert feed(m, 400 + 86400 + 60) == []  # reported exactly once


def test_clock_jump_forward_lets_partial_window_age_out() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev())  # 4 of 5
    assert feed(m, 86400, ev()) == []  # the fifth, a day later
    assert m.incidents() == []


def test_clock_jump_forward_does_not_satisfy_level_hold_or_debounce() -> None:
    m = AlarmMachine()
    assert feed(m, 0, weak(3)) == []  # hold starts
    assert feed(m, 86400, weak(3)) == []  # jump: hold restarts, does not open
    assert m.incidents() == []
    assert states(feed(m, 86400 + 600, weak(3))) == [OPENED]

    m = AlarmMachine()
    feed(m, 0, lvl(90))
    feed(m, 60, lvl(90))
    assert feed(m, 60 + 86400, lvl(90)) == []  # streak restarted by the gap
    assert m.incidents() == []


def test_clock_jump_forward_then_back_is_harmless() -> None:
    m = AlarmMachine()
    a = open_storm(m, key="A")
    for t in (10_000, 100_000, 600, 700):  # NTP fix after a forward jump
        feed(m, t)
    inc = m.get(a)
    assert inc is not None and inc.status is IncidentStatus.RESOLVED
    # a fresh storm well after the corrected clock: no crash, opens normally
    out: list[Transition] = []
    for i in range(5):
        out += feed(m, 800 + 10 * i, ev(key="A"))
    assert states(out) in ([OPENED], [REOPENED])
    assert len([i for i in m.incidents() if i.status is IncidentStatus.ACTIVE]) == 1


def test_update_with_invalid_time_changes_nothing() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    before = snapshot(m)
    for bad in (float("nan"), float("inf"), None, "now", True):
        assert m.update(bad, [ev()]) == []  # type: ignore[arg-type]
    assert snapshot(m) == before
    assert m.get(inc_id) is not None


# --- unknown fields on load -----------------------------------------------------------------


def test_from_dict_tolerates_unknown_keys_everywhere() -> None:
    m = AlarmMachine()
    inc_id = open_storm(m)
    data = json.loads(json.dumps(m.to_dict()))
    data["future_top"] = {"x": 1}
    for inc in data["incidents"]:
        inc["future_incident_field"] = [1, 2]
    for track in data["tracks"]:
        track["future_track_field"] = "y"
    restored = AlarmMachine.from_dict(data)
    assert snapshot(restored) == snapshot(m)
    assert states(feed(restored, 2200)) == [RESOLVED]
    assert restored.get(inc_id) is not None


def test_from_dict_skips_damaged_track_entries() -> None:
    m = AlarmMachine()
    for i in range(4):
        feed(m, 100 * i, ev(event_id=f"r1:{i}"))
    data = json.loads(json.dumps(m.to_dict()))
    data["tracks"][0]["entries"] += [
        ["x", 1, None, ""],
        [1.0],
        "junk",
        [5, True, None, ""],
    ]
    restored = AlarmMachine.from_dict(data)
    # the four valid entries survive: one more reconnect completes the storm
    assert states(feed(restored, 400, ev(event_id="r1:4"))) == [OPENED]
