"""Tests for net_events.py: model round trips, ring, counters, redaction."""

from __future__ import annotations

import json
from typing import Any

from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    EventCounters,
    EventRing,
    Incident,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Severity,
    Source,
    prune_incidents,
    redact_event,
    redact_incident,
    redact_record,
)

MAC = "AA:BB:CC:DD:EE:01"
HOUR = 3600
DAY = 86400


def make_event(seq: int = 1, ts: float = 1000.0, **kw: Any) -> NetEvent:
    base: dict[str, Any] = {
        "id": f"r1:{seq}",
        "ts": ts,
        "router": "r1",
        "category": Category.WIFI,
        "kind": "wifi.reconnect",
    }
    base.update(kw)
    return NetEvent(**base)


def full_event() -> NetEvent:
    return NetEvent(
        id="r1:7",
        ts=1234.5,
        router="r1",
        category=Category.WIFI,
        kind="wifi.auth_failed",
        origin=Origin.INFERRED,
        source=Source.HOSTAPD,
        subject={"mac": MAC, "ssid": "HomeNet", "band": "5g"},
        signal=-71,
        count=3,
        severity=Severity.WARNING,
        cause="psk_wrong",
        cause_status=CauseStatus.HYPOTHESIS,
        confidence=0.6,
        msg_key="wifi_auth_failed",
        params={"n": 3, "nested": {"a": [1, 2]}},
        maintenance=True,
        src_ts=1200.0,
        clock_skew=True,
    )


def full_incident() -> Incident:
    return Incident(
        id="inc-1",
        type="wifi_reconnect_storm",
        scope=Scope.CLIENT,
        scope_key=MAC,
        status=IncidentStatus.IGNORED,
        severity=Severity.CRITICAL,
        confidence=0.7,
        origin=Origin.INFERRED,
        cause="ap_reboot",
        cause_status=CauseStatus.CONFIRMED,
        evidence=[{"id": "r1:1", "ts": 10.0, "kind": "wifi.reconnect"}],
        parent_id="inc-0",
        children=2,
        routers=["r1", "r2"],
        affected=4,
        first_seen=10.0,
        last_seen=50.0,
        resolved_at=60.0,
        reopen_count=2,
        occurrences=9,
        ignore_until=999.0,
    )


# --- round trip --------------------------------------------------------------


def test_event_round_trip_is_lossless_through_json() -> None:
    event = full_event()
    stored = json.loads(json.dumps(event.to_dict()))
    assert NetEvent.from_dict(stored) == event


def test_event_to_dict_uses_plain_strings_and_copies() -> None:
    event = full_event()
    data = event.to_dict()
    assert type(data["category"]) is str
    assert data["category"] == "wifi"
    data["subject"]["mac"] = "changed"
    data["params"]["nested"]["a"].append(3)
    assert event.subject["mac"] == MAC
    assert event.params["nested"]["a"] == [1, 2]


def test_incident_round_trip_is_lossless_through_json() -> None:
    incident = full_incident()
    stored = json.loads(json.dumps(incident.to_dict()))
    assert Incident.from_dict(stored) == incident


def test_incident_copy_is_independent() -> None:
    incident = full_incident()
    clone = incident.copy()
    clone.evidence.append({"id": "x"})
    clone.routers.append("r3")
    assert clone != incident
    assert len(incident.evidence) == 1
    assert incident.routers == ["r1", "r2"]


# --- unknown / missing / invalid --------------------------------------------


def test_event_from_dict_ignores_unknown_keys() -> None:
    data = full_event().to_dict()
    data["future_field"] = {"x": 1}
    assert NetEvent.from_dict(data) == full_event()


def test_event_from_dict_fills_defaults_for_missing_optional_keys() -> None:
    event = NetEvent.from_dict(
        {
            "id": "r1:1",
            "ts": 5,
            "router": "r1",
            "category": "lan",
            "kind": "lan.port_flap",
        }
    )
    assert event is not None
    assert event.ts == 5.0
    assert event.origin is Origin.OBSERVED
    assert event.severity is Severity.INFO
    assert event.count == 1
    assert event.subject == {}
    assert event.cause_status is None
    assert event.maintenance is False
    assert event.src_ts is None


def test_event_wrong_type_in_optional_key_falls_back_to_default() -> None:
    data = full_event().to_dict()
    data["count"] = "many"
    data["subject"] = "not a dict"
    data["confidence"] = 7.5
    event = NetEvent.from_dict(data)
    assert event is not None
    assert event.count == 1
    assert event.subject == {}
    assert event.confidence == 1.0  # clamped


def test_event_from_dict_returns_none_for_missing_required_key() -> None:
    for key in ("id", "ts", "router", "category", "kind"):
        data = full_event().to_dict()
        del data[key]
        assert NetEvent.from_dict(data) is None, key


def test_event_from_dict_returns_none_for_invalid_enum_or_type() -> None:
    for key, bad in (
        ("category", "bogus"),
        ("severity", "fatal"),
        ("origin", 5),
        ("source", "carrier pigeon"),
        ("cause_status", "maybe"),
        ("ts", "yesterday"),
        ("ts", float("nan")),
        ("id", 12),
    ):
        data = full_event().to_dict()
        data[key] = bad
        assert NetEvent.from_dict(data) is None, key
    assert NetEvent.from_dict("garbage") is None
    assert NetEvent.from_dict(None) is None


def test_incident_from_dict_unknown_missing_and_invalid() -> None:
    data = full_incident().to_dict()
    data["unknown"] = 1
    assert Incident.from_dict(data) == full_incident()

    minimal = Incident.from_dict(
        {
            "id": "i",
            "type": "t",
            "scope": "router",
            "scope_key": "r1",
            "status": "active",
            "first_seen": 5,
        }
    )
    assert minimal is not None
    assert minimal.last_seen == 5.0
    assert minimal.severity is Severity.INFO
    assert minimal.evidence == []
    assert minimal.ignore_until is None

    for key in ("id", "type", "scope", "scope_key", "status", "first_seen"):
        broken = full_incident().to_dict()
        del broken[key]
        assert Incident.from_dict(broken) is None, key
    for key, bad in (("status", "gone"), ("scope", "galaxy"), ("severity", "meh")):
        broken = full_incident().to_dict()
        broken[key] = bad
        assert Incident.from_dict(broken) is None, key
    assert Incident.from_dict([]) is None


def test_incident_from_dict_caps_evidence_and_drops_junk() -> None:
    data = full_incident().to_dict()
    data["evidence"] = [{"id": f"e{i}"} for i in range(30)] + ["junk", 5]
    incident = Incident.from_dict(data)
    assert incident is not None
    assert len(incident.evidence) == 20
    assert incident.evidence[-1] == {"id": "e29"}


def test_ring_load_skips_invalid_records_without_exception() -> None:
    good = make_event(1).to_dict()
    records = [good, {"id": "broken"}, "junk", None, dict(good, category="bogus")]
    ring = EventRing.from_list(records)
    assert [e.id for e in ring] == ["r1:1"]
    assert len(EventRing.from_list("not a list")) == 0


# --- ring --------------------------------------------------------------------


def test_ring_caps_by_count_dropping_oldest() -> None:
    ring = EventRing(max_count=3, max_age=DAY)
    for i in range(5):
        ring.add(make_event(i, ts=100.0 + i))
    assert [e.id for e in ring] == ["r1:2", "r1:3", "r1:4"]  # newest last


def test_ring_prune_drops_by_age() -> None:
    ring = EventRing(max_count=10, max_age=100)
    for ts in (0.0, 50.0, 150.0, 190.0):
        ring.add(make_event(int(ts), ts=ts))
    assert ring.prune(now=200.0) == 2
    assert [e.ts for e in ring] == [150.0, 190.0]
    assert ring.prune(now=200.0) == 0


def test_ring_prune_keeps_events_when_clock_goes_backwards() -> None:
    ring = EventRing(max_count=10, max_age=100)
    ring.add(make_event(1, ts=1000.0))
    assert ring.prune(now=10.0) == 0
    assert len(ring) == 1


def test_ring_filter_by_each_criterion_and_limit() -> None:
    ring = EventRing()
    ring.add(make_event(1, ts=10, router="r1", subject={"mac": MAC}))
    ring.add(
        make_event(
            2,
            ts=20,
            router="r2",
            category=Category.LAN,
            kind="lan.port_flap",
            severity=Severity.WARNING,
        )
    )
    ring.add(make_event(3, ts=30, router="r1", severity=Severity.CRITICAL))
    ids = lambda **kw: [e.id for e in ring.filter(**kw)]  # noqa: E731
    assert ids(router="r2") == ["r1:2"]
    assert ids(category=Category.LAN) == ["r1:2"]
    assert ids(category="lan") == ["r1:2"]
    assert ids(severity=Severity.CRITICAL) == ["r1:3"]
    assert ids(kind="wifi.reconnect") == ["r1:1", "r1:3"]
    assert ids(since=20) == ["r1:2", "r1:3"]
    assert ids(until=30) == ["r1:1", "r1:2"]
    assert ids(mac=MAC.lower()) == ["r1:1"]
    assert ids(kind="wifi.reconnect", limit=1) == ["r1:3"]
    assert ids(limit=0) == []
    assert ids() == ["r1:1", "r1:2", "r1:3"]


def test_ring_remove_router() -> None:
    ring = EventRing()
    ring.add(make_event(1, router="r1"))
    ring.add(make_event(2, router="r2"))
    ring.add(make_event(3, router="r1"))
    assert ring.remove_router("r1") == 2
    assert [e.router for e in ring] == ["r2"]
    assert ring.remove_router("nope") == 0


def test_ring_round_trip() -> None:
    ring = EventRing()
    ring.add(full_event())
    restored = EventRing.from_list(json.loads(json.dumps(ring.to_list())))
    assert list(restored) == [full_event()]


# --- counters ----------------------------------------------------------------


def test_counters_hourly_counts_and_window() -> None:
    c = EventCounters()
    now = 100 * HOUR + 5
    c.add("r1", "wifi.connected", now)
    c.add("r1", "wifi.connected", now - HOUR, n=2)
    c.add("r1", "wifi.connected", now - 5 * HOUR)
    assert c.hourly("r1", "wifi.connected", now, 1) == 1
    assert c.hourly("r1", "wifi.connected", now, 2) == 3
    assert c.hourly("r1", "wifi.connected", now, 24) == 4
    assert c.hourly("r1", "other", now, 24) == 0
    assert c.hourly("rX", "wifi.connected", now, 24) == 0


def test_counters_fold_hourly_into_daily_after_48_hours() -> None:
    c = EventCounters(retention_days=30)
    t0 = 10 * DAY + 3 * HOUR
    c.add("r1", "k", t0, n=2)
    c.add("r1", "k", t0 + HOUR)
    now = t0 + 47 * HOUR
    c.prune(now)
    assert c.to_dict()["r1"]["k"]["d"] == {}  # still hourly
    now = t0 + 60 * HOUR
    c.prune(now)
    data = c.to_dict()["r1"]["k"]
    assert data["h"] == {}
    assert data["d"] == {str(t0 // DAY): 3}
    assert c.daily("r1", "k", now, 5) == 3
    assert c.hourly("r1", "k", now, 48) == 0


def test_counters_drop_days_beyond_retention() -> None:
    c = EventCounters(retention_days=30)
    c.add("r1", "k", 5 * DAY)
    c.add("r1", "k", 40 * DAY)
    c.prune(now=45 * DAY)
    c.prune(now=45 * DAY)  # idempotent
    assert c.daily("r1", "k", 45 * DAY, 60) == 1  # only the day-40 count is left
    c.prune(now=100 * DAY)
    assert c.to_dict() == {}


def test_counters_daily_includes_unfolded_hours() -> None:
    c = EventCounters()
    now = 50 * DAY + 10 * HOUR
    c.add("r1", "k", now)
    c.add("r1", "k", now - 2 * DAY)
    assert c.daily("r1", "k", now, 1) == 1
    assert c.daily("r1", "k", now, 3) == 2


def test_counters_prune_survives_clock_going_backwards() -> None:
    c = EventCounters()
    c.add("r1", "k", 50 * DAY)
    c.prune(now=1 * DAY)
    assert c.daily("r1", "k", 50 * DAY, 1) == 1


def test_counters_remove_router_and_round_trip() -> None:
    c = EventCounters()
    c.add("r1", "k", 5 * HOUR)
    c.add("r2", "k", 6 * HOUR, n=4)
    c.prune(now=5 * HOUR + 60 * HOUR)  # folds to daily
    restored = EventCounters.from_dict(json.loads(json.dumps(c.to_dict())))
    assert restored.to_dict() == c.to_dict()
    restored.remove_router("r1")
    assert list(restored.to_dict()) == ["r2"]


def test_counters_from_dict_is_lenient() -> None:
    data = {
        "r1": {
            "k": {
                "h": {"100": 2, "x": 1, "101": "no", "102": -3},
                "d": {"4": 5},
                "z": 1,
            },
            "bad": "nope",
        },
        "r2": [],
        7: {},
    }
    c = EventCounters.from_dict(data)
    assert c.to_dict() == {"r1": {"k": {"h": {"100": 2}, "d": {"4": 5}}}}
    assert EventCounters.from_dict("junk").to_dict() == {}


# --- incident cap -------------------------------------------------------------


def _inc(i: int, status: IncidentStatus, last_seen: float) -> Incident:
    return Incident(
        id=f"i{i}",
        type="t",
        scope=Scope.ROUTER,
        scope_key=f"k{i}",
        status=status,
        first_seen=last_seen,
        last_seen=last_seen,
    )


def test_prune_incidents_never_drops_active_or_acknowledged() -> None:
    now = 100 * DAY
    items = [_inc(i, IncidentStatus.ACTIVE, 1.0) for i in range(30)]
    items += [_inc(100 + i, IncidentStatus.ACKNOWLEDGED, 1.0) for i in range(5)]
    items += [_inc(200 + i, IncidentStatus.RESOLVED, now - i) for i in range(10)]
    kept = prune_incidents(items, now, max_count=10, retention_days=30)
    kept_ids = {i.id for i in kept}
    assert all(f"i{i}" in kept_ids for i in range(30))
    assert all(f"i{100 + i}" in kept_ids for i in range(5))
    assert len(kept) == 35  # cap exceeded by open ones only, all resolved gone


def test_prune_incidents_drops_old_resolved_then_oldest_over_cap() -> None:
    now = 100 * DAY
    old = _inc(1, IncidentStatus.RESOLVED, now - 40 * DAY)
    old_ignored = _inc(2, IncidentStatus.IGNORED, now - 40 * DAY)
    fresh = [_inc(10 + i, IncidentStatus.RESOLVED, now - 100 + i) for i in range(4)]
    active = _inc(99, IncidentStatus.ACTIVE, now)
    kept = prune_incidents([old, old_ignored, *fresh, active], now, max_count=3)
    assert [i.id for i in kept] == [
        "i12",
        "i13",
        "i99",
    ]  # oldest fresh resolved dropped


def test_prune_incidents_handles_clock_going_backwards() -> None:
    inc = _inc(1, IncidentStatus.RESOLVED, 5000.0)
    assert prune_incidents([inc], now=10.0) == [inc]


# --- redaction -----------------------------------------------------------------


IDENTITY = ("AA:BB:CC", "HomeNet", "192.168.1.5", "Living Room AP", "r1", "myhost")


def _assert_no_identity(data: Any) -> None:
    text = json.dumps(data)
    for needle in IDENTITY:
        assert needle not in text, needle


def test_redact_event_removes_identity_keeps_signal_fields() -> None:
    event = NetEvent(
        id="r1:9",
        ts=50.0,
        router="r1",
        category=Category.WIFI,
        kind="wifi.reconnect",
        subject={"mac": MAC, "ssid": "HomeNet", "ip": "192.168.1.5"},
        params={"hostname": "myhost", "router_name": "Living Room AP"},
        severity=Severity.WARNING,
        count=4,
    )
    out = redact_event(event.to_dict())
    _assert_no_identity(out)
    for key in ("subject", "params", "router", "id"):
        assert key not in out
    assert out["kind"] == "wifi.reconnect"
    assert out["category"] == "wifi"
    assert out["severity"] == "warning"
    assert out["ts"] == 50.0
    assert out["count"] == 4


def test_redact_incident_removes_identity_keeps_counts_and_times() -> None:
    incident = full_incident()
    incident.scope_key = MAC
    incident.evidence = [
        {"id": "r1:1", "ts": 10.0, "kind": "wifi.reconnect", "mac": MAC}
    ]
    out = redact_incident(incident.to_dict())
    _assert_no_identity(out)
    assert "scope_key" not in out
    assert "routers" not in out
    assert out["router_count"] == 2
    assert out["type"] == "wifi_reconnect_storm"
    assert out["severity"] == "critical"
    assert out["occurrences"] == 9
    assert out["first_seen"] == 10.0
    assert out["evidence"] == [{"kind": "wifi.reconnect", "ts": 10.0}]


def test_redact_record_dispatches_and_ignores_unknown_keys() -> None:
    assert "type" in redact_record(full_incident().to_dict())
    event = redact_record(dict(full_event().to_dict(), future={"mac": MAC}))
    assert "future" not in event
    assert "kind" in event
