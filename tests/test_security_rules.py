"""Tests for security_rules (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest

from custom_components.openwrt_router.log_parser import LogEvent
from custom_components.openwrt_router.net_events import Category, NetEvent
from custom_components.openwrt_router.security_baseline import BaselineBook
from custom_components.openwrt_router.security_model import (
    Assessment,
    Availability,
    DataSource,
    SecCategory,
    SecurityEvent,
    Severity,
    SourceStatus,
    event_type,
    make_event_id,
    source_status,
)
from custom_components.openwrt_router.security_rules import (
    DetectorSet,
    DistinctWindow,
    DnsManyDomainsDetector,
    DnsNxdomainDetector,
    DnsTunnelHintDetector,
    FirewallBlockedDetector,
    FirewallInterVlanDetector,
    FirewallMgmtAccessDetector,
    FirewallPortScanDetector,
    IncidentRef,
    RestartGuard,
    VlanDriftDetector,
    WifiAssocBurstDetector,
    WifiAuthManyClientsDetector,
    WifiAuthRepeatDetector,
    WifiDeauthClusterDetector,
    WifiMultiApAuthDetector,
    WifiSignal,
    WindowCounter,
    check_sources,
    correlate,
    counter_delta,
    dedup_events,
    default_detectors,
    results_events,
    unavailable,
    wifi_signal,
)

T0 = 1_700_000_000.0
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
R3 = "rtr_" + "3" * 32
MAC_A = "aa:bb:cc:00:00:0a"
MAC_B = "aa:bb:cc:00:00:0b"
ALL_SOURCES = tuple(DataSource)


@dataclass(frozen=True)
class Rec:
    """Minimal ``SecLogRecord`` stand-in (router, ts, kind, fields)."""

    router: str
    ts: float
    kind: str
    fields: Mapping[str, Any] = field(default_factory=dict)


def statuses(
    *routers: str, now: float = T0, sources: Iterable[str] = ALL_SOURCES
) -> dict[str, dict[str, SourceStatus]]:
    srcs = tuple(sources)
    return {
        r: {s: source_status(s, now=now, last_ok=now) for s in srcs} for r in routers
    }


def sig(
    kind: str,
    ts: float,
    client: str | None = MAC_A,
    router: str = R1,
    ap: str = "wlan0",
) -> WifiSignal:
    return WifiSignal(ts=ts, router_id=router, kind=kind, client=client, ap=ap)


def run(
    det: Any, items: Iterable[Any], now: float, st: Mapping[str, Any]
) -> list[SecurityEvent]:
    for item in items:
        det.feed(item)
    return results_events(det.evaluate(now, st))


def fw(router: str, ts: float, **fields: Any) -> Rec:
    return Rec(router, ts, "fw.drop", fields)


def dns(router: str, ts: float, client: str, name: str, rcode: str = "noerror") -> Rec:
    return Rec(
        router, ts, "dns.query", {"client": client, "name": name, "rcode": rcode}
    )


# --- windows ----------------------------------------------------------------


def test_window_counter_bounded_and_expiring() -> None:
    win = WindowCounter(600)
    for i in range(10_000):
        win.add(T0 + i)
    assert len(win) <= 32
    assert win.count(T0 + 9_999) == pytest.approx(600, abs=21)
    assert win.count(T0 + 20_000) == 0
    win.add(T0)  # far older than the newest bucket: dropped
    assert win.count(T0 + 20_000) == 0


def test_distinct_window_bounded_and_saturates() -> None:
    win = DistinctWindow(300, max_items=10)
    for i in range(50):
        win.add(f"p{i}", T0 + i)
    assert win.count(T0 + 50) == 10 and win.saturated
    assert win.count(T0 + 1000) == 0
    win.add("r1/x", T0 + 1000)
    win.add("r2/x", T0 + 1000)
    win.discard_prefix("r1/")
    assert win.items(T0 + 1000) == ("r2/x",)


def test_counter_delta_and_restart_guard() -> None:
    assert counter_delta(10, 15) == 5
    assert counter_delta(15, 3) is None  # rollback: restart, not negative traffic
    assert counter_delta(None, 3) is None
    guard = RestartGuard()
    assert not guard.observe(R1, 1000)
    assert not guard.observe(R1, 1300)
    assert guard.observe(R1, 20)
    assert not guard.observe(R1, None)


def test_case18_ha_restart_windows_roundtrip() -> None:
    win = WindowCounter(600)
    seen = DistinctWindow(300, max_items=5)
    for i in range(40):
        win.add(T0 + i * 10)
        seen.add(f"port{i}", T0 + i * 10)
    win2 = WindowCounter.from_dict(json.loads(json.dumps(win.to_dict())))
    seen2 = DistinctWindow.from_dict(json.loads(json.dumps(seen.to_dict())))
    assert win2 is not None and seen2 is not None
    assert win2.count(T0 + 400) == win.count(T0 + 400)
    assert seen2.items(T0 + 400) == seen.items(T0 + 400)
    assert seen2.saturated
    assert WindowCounter.from_dict({"window_s": "x"}) is None
    assert DistinctWindow.from_dict(None) is None


# --- inputs -----------------------------------------------------------------


def test_wifi_signal_from_net_event_log_event_and_mapping() -> None:
    net = NetEvent(
        id="n1",
        ts=T0,
        router=R1,
        category=Category.WIFI,
        kind="wifi.psk_mismatch",
        subject={"mac": "AA-BB-CC-00-00-0A", "iface": "phy0-ap0"},
    )
    s1 = wifi_signal(net)
    assert s1 is not None and s1.client == MAC_A and s1.ap == "phy0-ap0"
    log = LogEvent(
        category="wifi",
        kind="psk_mismatch",
        log_id=1,
        time_ms=int(T0 * 1000),
        mac=MAC_A,
    )
    s2 = wifi_signal(log, router_id=R2)
    assert s2 is not None and s2.kind == "wifi.psk_mismatch" and s2.router_id == R2
    assert wifi_signal(log) is None  # no router: dropped, not guessed
    assert wifi_signal({"kind": "wifi.roam", "ts": T0, "router": R1}) is not None
    assert wifi_signal({"kind": "", "ts": T0, "router": R1}) is None


def test_check_sources() -> None:
    st = statuses(R1, sources=[DataSource.WIFI_EVENTS])[R1]
    assert check_sources([DataSource.WIFI_EVENTS], st) == (Availability.AVAILABLE, ())
    assert check_sources([DataSource.FIREWALL_LOG], st)[0] is Availability.NOT_AVAILABLE
    stale = {
        DataSource.FIREWALL_LOG: source_status(
            DataSource.FIREWALL_LOG, now=T0, last_ok=T0 - 9999
        )
    }
    assert check_sources([DataSource.FIREWALL_LOG], stale)[0] is Availability.STALE


# --- case 10/11: Wi-Fi ------------------------------------------------------


def test_case10_wifi_auth_failures() -> None:
    det = WifiAuthRepeatDetector()
    items = [sig("wifi.psk_mismatch", T0 + i * 10) for i in range(6)]
    events = run(det, items, T0 + 70, statuses(R1))
    assert len(events) == 1
    event = events[0]
    assert event.type == event_type("wifi_auth_repeat")
    assert event.severity is Severity.WARNING
    assert event.assessment is Assessment.NOTICEABLE
    assert event.client == MAC_A and event.router_id == R1
    # cooldown per key: not re-reported in the same window
    assert run(det, [], T0 + 80, statuses(R1, now=T0 + 80)) == []


def test_case10_typo_then_success_stays_normal() -> None:
    det = WifiAuthRepeatDetector()
    items = [sig("wifi.psk_mismatch", T0), sig("wifi.connected", T0 + 5)]
    assert run(det, items, T0 + 10, statuses(R1)) == []
    many = WifiAuthManyClientsDetector()
    assert run(many, items, T0 + 10, statuses(R1)) == []


def test_case10_many_clients_failing_at_one_ap() -> None:
    det = WifiAuthManyClientsDetector()
    items = [
        sig("wifi.sae_failed", T0 + i, client=f"aa:bb:cc:00:01:{i:02x}")
        for i in range(6)
    ]
    events = run(det, items, T0 + 10, statuses(R1))
    assert len(events) == 1 and events[0].client is None
    assert "clients=6" in events[0].evidence


def test_case10_frequent_associations_and_deauth_indicator() -> None:
    assoc = WifiAssocBurstDetector()
    items = [sig("wifi.connected", T0 + i * 5) for i in range(25)]
    assert len(run(assoc, items, T0 + 130, statuses(R1))) == 1
    deauth = WifiDeauthClusterDetector()
    items = [
        sig("wifi.deauth", T0 + i, client=f"aa:bb:cc:00:02:{i:02x}") for i in range(20)
    ]
    events = run(deauth, items, T0 + 21, statuses(R1))
    assert len(events) == 1
    text = (deauth.describe() + " ".join(events[0].evidence) + events[0].type).lower()
    assert "attack" not in text and "indicator" in deauth.describe()
    assert events[0].assessment is not Assessment.CONFIRMED


def test_case11_normal_roaming_produces_no_finding() -> None:
    dets = default_detectors()
    items = []
    ts = T0
    for hop in range(6):  # roams between three routers over half an hour
        router = (R1, R2, R3)[hop % 3]
        items.append(sig("wifi.disconnected", ts, router=router))
        items.append(sig("wifi.roam", ts + 1, router=router))
        items.append(sig("wifi.connected", ts + 2, router=router))
        ts += 300
    dets.feed_wifi(items)
    results = dets.evaluate(ts, statuses(R1, R2, R3, now=ts))
    assert results_events(results) == []


def test_case11_roaming_never_hides_auth_failures() -> None:
    det = WifiAuthRepeatDetector()
    items = [sig("wifi.psk_mismatch", T0 + i) for i in range(5)]
    items.append(sig("wifi.roam", T0 + 6))
    events = run(det, items, T0 + 10, statuses(R1))
    assert len(events) == 1  # reported, only lowered to info
    assert events[0].severity is Severity.INFO
    assert "connected_after=True" in events[0].evidence


# --- case 12: several routers -----------------------------------------------


def test_case12_several_routers_at_once() -> None:
    dets = default_detectors()
    items = [
        sig("wifi.psk_mismatch", T0 + i, client=MAC_A, router=R1) for i in range(5)
    ]
    items += [
        sig("wifi.psk_mismatch", T0 + i, client=MAC_B, router=R2) for i in range(5)
    ]
    items += [sig("wifi.psk_mismatch", T0 + 6, client=MAC_A, router=R2, ap="wlan1")]
    dets.feed_wifi(items)
    results = dets.evaluate(T0 + 10, statuses(R1, R2))
    events = results_events(results)
    repeat = [e for e in events if e.name == "wifi_auth_repeat"]
    assert {(e.router_id, e.client) for e in repeat} == {(R1, MAC_A), (R2, MAC_B)}
    multi = [e for e in events if e.name == "wifi_multi_ap_auth"]
    assert len(multi) == 1 and multi[0].router_id is None and multi[0].client == MAC_A
    assert "pattern=indicator" in multi[0].evidence
    groups = correlate(events)
    by_client = {g.client: g for g in groups}
    assert set(by_client[MAC_A].router_ids) == {R1}
    assert len(by_client[MAC_A].events) == 2  # repeat + fleet pattern
    assert by_client[MAC_B].correlation_id != by_client[MAC_A].correlation_id


def test_case12_one_router_missing_source_does_not_blind_the_others() -> None:
    det = WifiAuthRepeatDetector()
    for r in (R1, R2):
        for i in range(5):
            det.feed(sig("wifi.psk_mismatch", T0 + i, router=r))
    st = statuses(R1) | statuses(R2, sources=[])
    results = det.evaluate(T0 + 10, st)
    by_router = {r.router_id: r for r in results}
    assert by_router[R1].available and len(by_router[R1].events) == 1
    assert by_router[R2].status is Availability.NOT_AVAILABLE
    assert DataSource.WIFI_EVENTS in by_router[R2].missing
    # a router with stored state but no reported status is not judged either
    results = det.evaluate(T0 + 10, statuses(R1))
    assert {r.router_id: r.status for r in results}[R2] is Availability.NOT_AVAILABLE


# --- case 4/5/9: firewall ---------------------------------------------------


def test_case04_suspicious_firewall_connections() -> None:
    scan = FirewallPortScanDetector()
    items = [
        fw(R1, T0 + i, zone="guest", src="192.168.30.50", dpt=1000 + i, dir="in")
        for i in range(25)
    ]
    events = run(scan, items, T0 + 30, statuses(R1))
    assert len(events) == 1
    assert events[0].src is not None and events[0].src.zone == "guest"
    assert "distinct_ports=25" in events[0].evidence
    mgmt = FirewallMgmtAccessDetector(mgmt_addrs=["192.168.1.1"])
    items = [
        fw(
            R1,
            T0 + i,
            zone="iot",
            src="192.168.50.9",
            dst="192.168.1.1",
            dpt=443,
            dir="forward",
        )
        for i in range(3)
    ]
    items += [
        fw(R1, T0 + 5, zone="guest", src="192.168.30.7", dpt=22, dir="in")
        for _ in range(3)
    ]
    events = run(mgmt, items, T0 + 10, statuses(R1))
    assert {e.src.zone for e in events if e.src} == {"iot", "guest"}
    # a non-watched zone is ignored
    lan = FirewallMgmtAccessDetector()
    assert (
        run(lan, [fw(R1, T0, zone="lan", dpt=22, dir="in")] * 5, T0 + 1, statuses(R1))
        == []
    )


def _blocked_windows(
    det: FirewallBlockedDetector,
    windows: int,
    per_window: int,
    start: float = T0,
    router: str = R1,
) -> tuple[list[SecurityEvent], float, list[bool]]:
    events: list[SecurityEvent] = []
    learning: list[bool] = []
    ts = start
    for _ in range(windows):
        for j in range(per_window):
            det.feed(
                fw(
                    router,
                    ts + j * 300 / per_window,
                    zone="wan",
                    src="203.0.113.5",
                    dpt=23,
                )
            )
        ts += 300
        results = det.evaluate(ts, statuses(router, now=ts))
        events += results_events(results)
        learning += [r.learning for r in results]
    return events, ts, learning


def test_case05_normal_firewall_blocks() -> None:
    det = FirewallBlockedDetector()
    events, ts, learning = _blocked_windows(det, 100, 120)
    assert events == []  # steady WAN noise becomes the baseline
    assert learning[0] and not learning[-1]
    # internet port scans of the WAN zone are not a port-scan finding
    scan = FirewallPortScanDetector()
    items = [fw(R1, T0 + i, zone="wan", src="203.0.113.9", dpt=i) for i in range(500)]
    assert run(scan, items, T0 + 100, statuses(R1)) == []
    # a spike against the learned baseline is reported
    spike, _, _ = _blocked_windows(det, 1, 2000, start=ts)
    assert len(spike) == 1 and "zone=wan" in spike[0].evidence


def test_case09_inter_vlan() -> None:
    det = FirewallInterVlanDetector(allowed_pairs=[("lan", "iot")])
    items = [
        fw(
            R1,
            T0 + i,
            zone="iot",
            dest_zone="lan",
            src="192.168.50.20",
            dir="forward",
            dpt=445,
        )
        for i in range(6)
    ]
    items += [
        fw(R1, T0 + i, zone="lan", dest_zone="iot", src="192.168.1.5", dir="forward")
        for i in range(9)
    ]
    items += [
        fw(R1, T0 + i, zone="lan", dest_zone="wan", src="192.168.1.5", dir="forward")
        for i in range(9)
    ]
    events = run(det, items, T0 + 10, statuses(R1))
    assert len(events) == 1
    event = events[0]
    assert event.category is SecCategory.VLAN
    assert event.src is not None and event.src.zone == "iot"
    assert event.dst is not None and event.dst.zone == "lan"


def test_case09_vlan_drift_needs_drift_input() -> None:
    det = VlanDriftDetector()
    drift = [
        Rec(R1, T0, "config.drift", {"area": "firewall.forwarding", "critical": True})
    ]
    drift.append(Rec(R1, T0, "config.drift", {"area": "system.ntp"}))
    no_drift = statuses(
        R1, sources=[s for s in ALL_SOURCES if s != DataSource.CONFIG_DRIFT]
    )
    for item in drift:
        det.feed(item)
    results = det.evaluate(T0 + 1, no_drift)
    assert unavailable(results) and results_events(results) == []
    events = results_events(det.evaluate(T0 + 1, statuses(R1)))
    assert len(events) == 1 and events[0].severity is Severity.WARNING


# --- case 6/7: DNS ----------------------------------------------------------


def test_case06_dns_anomalies() -> None:
    nx = DnsNxdomainDetector()
    items = [
        dns(R1, T0 + i, "192.168.1.30", f"x{i}.badcdn.example", "NXDOMAIN")
        for i in range(35)
    ]
    items += [
        dns(R1, T0 + i, "192.168.1.30", "ok.example", "NOERROR") for i in range(10)
    ]
    events = run(nx, items, T0 + 40, statuses(R1))
    assert len(events) == 1 and events[0].category is SecCategory.DNS
    assert not any("example" in e for e in events[0].evidence)  # names not kept
    many = DnsManyDomainsDetector()
    items = [
        dns(R1, T0 + i * 0.5, "192.168.1.31", f"site{i}.example.org")
        for i in range(250)
    ]
    assert len(run(many, items, T0 + 130, statuses(R1))) == 1
    stored = json.dumps([s.distinct.to_dict() for s in many._slots.values()])
    assert "example" not in stored  # only digests in memory
    tunnel = DnsTunnelHintDetector()
    label = "mzxw6ytboi4dqojsgq2tmnzyhe3tqmrzgaytenbvgy3dooa"
    items = [
        dns(R1, T0 + i, "192.168.1.32", f"{label}{i:03d}.t.example.net")
        for i in range(12)
    ]
    items += [dns(R1, T0 + i, "192.168.1.33", "www.example.net") for i in range(100)]
    events = run(tunnel, items, T0 + 20, statuses(R1))
    assert len(events) == 1
    assert "tunnelling=hint" in events[0].evidence
    assert events[0].assessment is not Assessment.CONFIRMED
    assert not tunnel.is_odd("mail.google.com")


def test_case06_keep_names_only_on_request() -> None:
    nx = DnsNxdomainDetector(keep_names=True, threshold=3)
    items = [dns(R1, T0 + i, "c1", f"n{i}.bad.example", "3") for i in range(5)]
    events = run(nx, items, T0 + 10, statuses(R1))
    examples = [e for e in events[0].evidence if e.startswith("example=")]
    assert 0 < len(examples) <= 3
    assert "bad.example" not in json.dumps(events[0].redacted())


def test_case07_missing_dns_logs() -> None:
    dets = default_detectors()
    items = [
        dns(R1, T0 + i, "192.168.1.30", f"x{i}.example", "NXDOMAIN") for i in range(100)
    ]
    dets.feed_records(items)
    no_dns = statuses(
        R1, sources=[s for s in ALL_SOURCES if s != DataSource.DNS_QUERY_LOG]
    )
    results = [
        r for r in dets.evaluate(T0 + 120, no_dns) if r.detector_id.startswith("dns_")
    ]
    assert len(results) == 4
    for result in results:
        assert result.status is Availability.NOT_AVAILABLE
        assert result.events == ()
        assert result.missing == (DataSource.DNS_QUERY_LOG,)
    stale = statuses(
        R1, sources=[s for s in ALL_SOURCES if s != DataSource.DNS_QUERY_LOG]
    )
    stale[R1][DataSource.DNS_QUERY_LOG] = source_status(
        DataSource.DNS_QUERY_LOG, now=T0 + 5000, last_ok=T0
    )
    results = [
        r for r in dets.evaluate(T0 + 120, stale) if r.detector_id.startswith("dns_")
    ]
    assert {r.status for r in results} == {Availability.STALE}


# --- case 13 and alarm suppression -----------------------------------------


def _ev(
    name: str, ts: float, router: str | None = R1, client: str | None = MAC_A, **kw: Any
) -> SecurityEvent:
    return SecurityEvent(
        event_id=make_event_id(name, router, client, ts),
        ts=ts,
        type=event_type(name),
        router_id=router,
        category=SecCategory.WIFI,
        client=client,
        **kw,
    )


def test_case13_incident_correlation_links_without_replacing() -> None:
    incident = IncidentRef(
        incident_id="inc_42",
        start=T0 - 60,
        end=T0 + 60,
        router_ids=(R1,),
        clients=(MAC_A.upper(),),
    )
    router_wide = IncidentRef(incident_id="inc_7", start=T0, router_ids=(R2,))
    before = (incident, router_wide)
    events = [
        _ev("wifi_auth_repeat", T0, linked_incident_ids=("inc_1",)),
        _ev("wifi_auth_repeat", T0, client=MAC_B),
        _ev("fw_blocked", T0 + 10, router=R2, client=None),
    ]
    groups = correlate(events, incidents=before)
    out = {(e.router_id, e.client): e for g in groups for e in g.events}
    assert out[(R1, MAC_A)].linked_incident_ids == ("inc_1", "inc_42")
    assert out[(R1, MAC_B)].linked_incident_ids == ()
    assert out[(R2, None)].linked_incident_ids == ("inc_7",)
    assert before == (incident, router_wide)  # incidents untouched
    assert all(
        e.correlation_id and e.correlation_id.startswith("cor_") for e in out.values()
    )
    late = correlate([_ev("wifi_auth_repeat", T0 + 9999)], incidents=before)
    assert late[0].events[0].linked_incident_ids == ()


def test_correlation_merges_duplicates_and_splits_by_time() -> None:
    events = [_ev("wifi_auth_repeat", T0 + i) for i in range(4)]
    events.append(_ev("wifi_auth_repeat", T0 + 5000))
    groups = correlate(events, gap_s=300)
    assert [g.count for g in groups] == [4, 1]
    assert len(groups[0].events) == 1 and groups[0].events[0].count == 4
    assert groups[0].correlation_id != groups[1].correlation_id


def test_no_rule_silently_suppresses_another_alarm() -> None:
    same_time = [
        _ev("wifi_auth_repeat", T0, client=MAC_A),
        _ev("wifi_auth_repeat", T0, client=MAC_B),
        _ev("wifi_auth_repeat", T0, router=R2, client=MAC_A),
        _ev("fw_blocked", T0, client=None),
        _ev("fw_blocked", T0, router=R2, client=None),
    ]
    merged = dedup_events(same_time, cooldown_s=3600)
    assert len(merged) == 5 and all(e.count == 1 for e in merged)
    groups = correlate(same_time)
    assert sum(g.count for g in groups) == 5
    assert sum(len(g.events) for g in groups) == 5
    router_groups = [g for g in groups if g.client is None]
    assert len(router_groups) == 2  # two routers without a shared client stay apart
    # detector cooldown is per key: client A's report never holds back client B
    det = WifiAuthRepeatDetector()
    run(
        det, [sig("wifi.psk_mismatch", T0 + i) for i in range(5)], T0 + 10, statuses(R1)
    )
    later = [sig("wifi.psk_mismatch", T0 + 20 + i, client=MAC_B) for i in range(5)]
    events = run(det, later, T0 + 30, statuses(R1))
    assert [e.client for e in events] == [MAC_B]
    # a success of client A does not lower client B's finding
    det2 = WifiAuthRepeatDetector()
    items = [sig("wifi.psk_mismatch", T0 + i, client=MAC_B) for i in range(5)]
    items.append(sig("wifi.connected", T0 + 6, client=MAC_A))
    events = run(det2, items, T0 + 10, statuses(R1))
    assert events[0].severity is Severity.WARNING


# --- case 17: router restart ------------------------------------------------


def test_case17_router_restart() -> None:
    dets = default_detectors()
    fwd = next(d for d in dets.detectors if d.id == "fw_blocked")
    assert isinstance(fwd, FirewallBlockedDetector)
    _, ts, _ = _blocked_windows(fwd, 90, 100)
    _blocked_windows(fwd, 90, 100, router=R2)
    dets.feed_wifi([sig("wifi.psk_mismatch", ts - 50 + i, router=R1) for i in range(4)])
    dets.feed_wifi(
        [
            sig("wifi.psk_mismatch", ts - 50 + i, client=MAC_B, router=R2)
            for i in range(5)
        ]
    )
    assert not dets.note_uptime(R1, 500_000)
    assert dets.note_uptime(R1, 30)  # uptime went backwards: restart
    # boot burst on R1 right after the restart: no false anomaly
    for j in range(3000):
        fwd.feed(fw(R1, ts + j * 0.1, zone="wan"))
    dets.feed_wifi([sig("wifi.psk_mismatch", ts + 1, router=R1)])
    events = results_events(dets.evaluate(ts + 300, statuses(R1, R2, now=ts + 300)))
    assert [(e.name, e.router_id) for e in events] == [("wifi_auth_repeat", R2)]
    assert fwd.baseline.get(f"{R2}|fw_blocked|wan") is not None


# --- case 20: high load -----------------------------------------------------


def test_case20_high_load_stays_bounded_and_fast() -> None:
    dets = default_detectors(max_keys=512)
    routers = [f"rtr_{i:032x}" for i in range(6)]
    kinds = ("wifi.psk_mismatch", "wifi.connected", "wifi.deauth", "wifi.roam")
    start = time.perf_counter()
    signals = (
        WifiSignal(
            ts=T0 + i * 0.01,
            router_id=routers[i % 6],
            kind=kinds[i % 4],
            client=f"02:00:00:{(i >> 16) & 255:02x}:{(i >> 8) & 255:02x}:{i & 255:02x}",
            ap=f"wlan{i % 3}",
        )
        for i in range(100_000)
    )
    assert dets.feed_wifi(signals) == 100_000
    records = (
        fw(
            routers[i % 6],
            T0 + i * 0.01,
            zone=("wan", "guest", "iot")[i % 3],
            src=f"10.{i % 200}.{(i >> 8) % 250}.{i % 250}",
            dpt=i % 65535,
            dir="forward",
            dest_zone="lan",
        )
        if i % 2
        else dns(
            routers[i % 6],
            T0 + i * 0.01,
            f"10.0.{(i >> 8) % 250}.{i % 250}",
            f"h{i}.example.com",
            "NXDOMAIN" if i % 3 else "NOERROR",
        )
        for i in range(100_000)
    )
    dets.feed_records(records)
    results = dets.evaluate(T0 + 1000, statuses(*routers, now=T0 + 1000))
    elapsed = time.perf_counter() - start
    assert elapsed < 30, elapsed
    for det in dets.detectors:
        assert len(det._slots) <= det.max_keys  # type: ignore[attr-defined]
    assert dets.state_size() < 13 * 512 * 600
    events = results_events(results)
    groups = correlate(events)
    assert sum(g.count for g in groups) == len(events)


# --- case 21: privacy -------------------------------------------------------


def test_case21_rules_privacy(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    dets = default_detectors()
    dets.feed_wifi([sig("wifi.psk_mismatch", T0 + i) for i in range(6)])
    dets.feed_records(
        [
            dns(R1, T0 + i, "192.168.1.30", f"x{i}.secret-site.example", "NXDOMAIN")
            for i in range(40)
        ]
    )
    dets.note_uptime(R1, 100)
    dets.note_uptime(R1, 1)
    results = dets.evaluate(T0 + 50, statuses(R1, now=T0 + 50))
    groups = correlate(
        results_events(results),
        incidents=[IncidentRef(incident_id="i", start=T0, clients=(MAC_A,))],
    )
    text = " ".join(
        repr(x) for x in (*results, *groups, *dets.detectors, sig("wifi.x", T0))
    )
    text += json.dumps([e.redacted() for g in groups for e in g.events])
    for ident in (MAC_A, "192.168.1.30", "secret-site"):
        assert ident not in text
        for record in caplog.records:
            assert ident not in record.getMessage()


def test_describe_and_unique_ids() -> None:
    dets = default_detectors()
    desc = dets.describe()
    assert len(desc) == len(dets.detectors) == 14
    assert all(d.sources for d in dets.detectors)
    with pytest.raises(ValueError):
        DetectorSet([WifiAuthRepeatDetector(), WifiAuthRepeatDetector()])
    assert isinstance(WifiMultiApAuthDetector().describe(), str)
    assert BaselineBook() is not None
