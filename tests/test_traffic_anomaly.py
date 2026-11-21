"""Traffic anomaly candidates (test areas 18 detection, 19 normal peaks, 20 baselines).

traffic_anomaly.py over the history interface (memory ring): robust
baselines per weekday class and hour, learning below the minimum data base,
candidates with minimum duration, hysteresis, debounce and budgets, regular
patterns learned in, suppression only of traffic candidates, events through
the core ``emit`` (no incident engine). No router, no network.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest

from custom_components.openwrt_router.traffic_anomaly import (
    TRAFFIC_KINDS,
    AnomalyDetector,
    CandidateBook,
    CandidatePublisher,
    SlotClock,
    SuppressionRule,
    build_baseline,
    candidate_dict,
    family_availability,
    robust_stats,
)
from custom_components.openwrt_router.traffic_const import (
    BUDGET_PER_HOUR,
    EVENT_ANOMALY_ENDED,
    EVENT_ANOMALY_STARTED,
    MAX_CANDIDATES,
    SUPPRESSED_BUDGET_HOUR,
    SUPPRESSED_BUDGET_POINT,
    SUPPRESSED_BUDGET_POINT_KIND,
    SUPPRESSED_RULE,
    SUPPRESSED_STORE_FULL,
)
from custom_components.openwrt_router.traffic_model import (
    AnomalyCandidate,
    Bucket,
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
)
from custom_components.openwrt_router.traffic_series import MemoryBucketRing

RID = "rtr_" + "1" * 32
MON = datetime(2027, 1, 4, tzinfo=UTC).timestamp()  # a Monday, 00:00 UTC
DAY = 86400
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")
CLIENT = MeasurementPoint(None, Scope.CLIENT, client_ref="cli_" + "c" * 16)
MBIT = 1_000_000.0

Profile = Callable[[float], tuple[float, float, float | None]]


def ring() -> MemoryBucketRing:
    return MemoryBucketRing(max_buckets_infra=9000, max_buckets_client=9000)


def feed(
    source: MemoryBucketRing,
    point: MeasurementPoint,
    start: float,
    end: float,
    profile: Profile,
) -> float:
    """One 300 s rate per bucket; profile(t) -> (rx bit/s, tx bit/s, rx peak)."""
    t = start + 300
    while t <= end:
        rx_bps, tx_bps, peak = profile(t)
        source.add_rate(
            Rate(
                point,
                Quality.OK,
                interval_s=300.0,
                rx_bps=peak if peak is not None else rx_bps,
                tx_bps=tx_bps,
                rx_delta=int(rx_bps * 300 / 8),
                tx_delta=int(tx_bps * 300 / 8),
                coverage=Coverage.FULL,
                wall_s=t,
                mono_s=t,
            )
        )
        t += 300
    return end


def flat(rx: float = MBIT, tx: float = MBIT) -> Profile:
    return lambda _t: (rx, tx, None)


def kinds(detector: AnomalyDetector, state: str = "open") -> set[str]:
    return {c.kind for c in detector.book.candidates(state=state)}


def week_then(source: MemoryBucketRing, point: MeasurementPoint, until: float) -> None:
    feed(source, point, MON, until, flat())


# --- area 20: baselines ---------------------------------------------------------------


def test_robust_stats_median_and_mad() -> None:
    stats = robust_stats([1, 2, 3, 4, 100], days=3)
    assert stats.median == 3
    assert stats.mad == pytest.approx(1.4826)
    assert robust_stats([], days=0) is None
    assert not robust_stats([1.0] * 5, days=5).ready  # < 6 values
    assert not robust_stats([1.0] * 10, days=2).ready  # < 3 days
    assert robust_stats([1.0] * 6, days=3).ready


def test_spread_has_floors() -> None:
    stats = robust_stats([10 * MBIT] * 10, days=4)
    assert stats.mad == 0
    assert stats.spread == pytest.approx(MBIT)  # 10 % of the median
    low = robust_stats([1000.0] * 10, days=4)
    assert low.spread == 100_000.0  # absolute floor


def test_gappy_buckets_never_count_in_baselines() -> None:
    clock = SlotClock()
    gappy = [
        Bucket(int(MON) + d * DAY, 300, rx_bytes=1000, tx_bytes=1000, covered_s=100)
        for d in range(10)
    ]
    assert build_baseline(gappy, clock, 0).avg == {}
    full = [
        Bucket(int(MON) + d * DAY, 300, rx_bytes=37_500, tx_bytes=1, covered_s=300)
        for d in range(5)
    ]
    base = build_baseline(full, clock, 0)
    stats = base.avg[("rx", ("weekday", 0))]
    assert stats.median == 1000.0 and stats.days == 5 and stats.values == 5


def test_slots_split_weekday_and_weekend() -> None:
    clock = SlotClock()
    assert clock.slot(MON + 3 * 3600)[0] == ("weekday", 3)
    assert clock.slot(MON + 5 * DAY + 3600)[0] == ("weekend", 1)


def test_learning_without_enough_days_gives_no_candidate() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + DAY + 10 * 3600, flat())  # Mon + Tue
    feed(source, WAN, now, now + 600, flat(rx=80 * MBIT))
    detector = AnomalyDetector(source)
    result = detector.evaluate(now + 600)
    assert result.learning == 1 and result.events == ()
    assert detector.book.candidates() == []


# --- area 18: detection ----------------------------------------------------------------


def test_download_spike_needs_two_buckets() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 10 * 3600, flat())
    detector = AnomalyDetector(source)
    now = feed(source, WAN, now, now + 300, flat(rx=50 * MBIT))
    assert detector.evaluate(now).events == ()  # one bucket only
    now = feed(source, WAN, now, now + 300, flat(rx=50 * MBIT))
    result = detector.evaluate(now)
    assert [e.event_type for e in result.events] == [EVENT_ANOMALY_STARTED]
    (cand,) = detector.book.candidates(state="open")
    assert cand.kind == "download_spike"  # WAN: download = RX
    assert cand.observed == pytest.approx(50 * MBIT, rel=1e-3)
    assert cand.baseline_median == pytest.approx(MBIT, rel=1e-3)
    assert cand.threshold == pytest.approx(1.6 * MBIT, rel=1e-3)
    assert cand.window_s == 600 and 0 < cand.confidence <= 0.9
    assert cand.coverage is Coverage.FULL


def test_night_activity_when_the_night_is_quiet() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 3 * 3600, flat())
    now = feed(source, WAN, now, now + 600, flat(tx=40 * MBIT))
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert kinds(detector) == {"upload_night_activity"}


def test_sudden_drop() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 12 * 3600, flat(rx=10 * MBIT))
    now = feed(source, WAN, now, now + 900, flat(rx=0.5 * MBIT))
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert "download_drop" in kinds(detector)


def test_missing_data_is_no_drop_and_no_all_clear() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 12 * 3600, flat(rx=10 * MBIT))
    now = feed(source, WAN, now, now + 600, flat(rx=80 * MBIT))
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert kinds(detector) == {"download_spike"}
    # router silent for an hour: no drop, and the open candidate stays open
    result = detector.evaluate(now + 3600)
    assert result.events == ()
    assert kinds(detector) == {"download_spike"}
    assert detector.counters["no_current_data"] == 1


def test_sustained_high_load() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 14 * 3600, flat())
    now = feed(source, WAN, now, now + 1800, flat(rx=1.5 * MBIT))
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert kinds(detector) == {"download_sustained_high"}


def test_repeated_short_bursts() -> None:
    source = ring()
    now = feed(source, WAN, MON, MON + 7 * DAY + 15 * 3600, flat())
    bursts = {now + 300 * i for i in (2, 4, 7, 10)}

    def profile(t: float) -> tuple[float, float, float | None]:
        return MBIT, MBIT, 20 * MBIT if t in bursts else None

    now = feed(source, WAN, now, now + 3600, profile)
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert kinds(detector) == {"download_bursts"}


def test_unusual_daily_volume_of_one_client() -> None:
    source = ring()
    feed(source, CLIENT, MON, MON + 7 * DAY, flat(rx=0.2 * MBIT, tx=2 * MBIT))
    day8 = MON + 7 * DAY
    feed(source, CLIENT, day8, day8 + 22 * 3600, flat(rx=0.2 * MBIT, tx=6 * MBIT))
    now = feed(
        source, CLIENT, day8 + 22 * 3600, day8 + DAY, flat(rx=0.2 * MBIT, tx=2 * MBIT)
    )
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    (cand,) = detector.book.candidates(state="open")
    assert cand.kind == "download_volume"  # client: download = what the AP sent
    assert cand.client_ref == CLIENT.client_ref and cand.router_id is None
    assert cand.observed > cand.threshold >= 2 * cand.baseline_median


def test_ports_are_left_to_network_intelligence() -> None:
    source = ring()
    port = MeasurementPoint(RID, Scope.PORT, device="lan1")
    now = feed(source, port, MON, MON + 7 * DAY + 10 * 3600, flat())
    now = feed(source, port, now, now + 900, flat(rx=900 * MBIT))
    detector = AnomalyDetector(source)
    result = detector.evaluate(now)
    assert result.evaluated == 0 and detector.book.candidates() == []
    families = result.families
    assert families["port_load"].state == "covered_by_network_intelligence"
    assert families["port_errors"].reason.endswith("lan_port_errors")


def test_families_that_need_other_sources() -> None:
    none = family_availability(
        has_points=False, conntrack_sources=None, flow_ready=False
    )
    assert none["spikes"].state == "unavailable"
    assert none["connection_rate"].reason == "conntrack_source_not_count_file"
    assert none["communication_pattern"].reason == "needs_flow_source"
    assert none["inter_vlan"].state == "unavailable"
    assert none["incident_engine"].state == "not_connected"
    with_ct = family_availability(
        has_points=True, conntrack_sources={RID: "count_file"}, flow_ready=True
    )
    assert with_ct["connection_rate"].state == "covered_by_network_intelligence"
    assert with_ct["connection_rate"].reason.endswith("system_conntrack_jump")
    assert with_ct["inter_vlan"].state == "learning"
    scan = family_availability(
        has_points=True, conntrack_sources={RID: "table_scan"}, flow_ready=False
    )
    assert scan["connection_rate"].state == "unavailable"


# --- area 19: normal peaks ---------------------------------------------------------------


def test_nightly_backup_is_learned_and_stays_quiet() -> None:
    source = ring()

    def backup(t: float) -> tuple[float, float, float | None]:
        hour = int((t - 300 - MON) % DAY // 3600)
        return (MBIT, 50 * MBIT if hour == 2 else MBIT, None)

    now = feed(source, WAN, MON, MON + 7 * DAY + 2 * 3600 + 1800, backup)
    detector = AnomalyDetector(source)
    result = detector.evaluate(now)
    assert result.learning == 0
    assert detector.book.candidates() == []


def test_camera_stream_is_no_anomaly() -> None:
    source = ring()
    now = feed(source, CLIENT, MON, MON + 8 * DAY, flat(rx=8 * MBIT, tx=0.1 * MBIT))
    detector = AnomalyDetector(source)
    for step in range(6):
        now = feed(source, CLIENT, now, now + 300, flat(rx=8 * MBIT, tx=0.1 * MBIT))
        detector.evaluate(now)
    assert detector.book.candidates() == []


def test_daytime_peak_seen_every_day_is_normal() -> None:
    source = ring()

    def profile(t: float) -> tuple[float, float, float | None]:
        hour = int((t - 300 - MON) % DAY // 3600)
        return (30 * MBIT if 19 <= hour < 21 else MBIT, MBIT, None)

    now = feed(source, WAN, MON, MON + 7 * DAY + 20 * 3600, profile)
    detector = AnomalyDetector(source)
    detector.evaluate(now)
    assert detector.book.candidates() == []


# --- brakes: hysteresis, debounce, budgets, rules, quotas ------------------------------


def test_hysteresis_and_debounce() -> None:
    source = ring()
    publisher_calls: list[dict[str, Any]] = []
    detector = AnomalyDetector(
        source,
        publisher=CandidatePublisher(lambda t, **kw: publisher_calls.append({"t": t})),
    )
    now = feed(source, WAN, MON, MON + 7 * DAY + 10 * 3600, flat())
    now = feed(source, WAN, now, now + 600, flat(rx=50 * MBIT))
    detector.evaluate(now)
    (first,) = detector.book.candidates(state="open")
    now = feed(source, WAN, now, now + 300, flat(rx=1.4 * MBIT))  # above clear
    assert detector.evaluate(now).events == ()
    assert kinds(detector) == {"download_spike"}
    now = feed(source, WAN, now, now + 300, flat())  # back to normal
    result = detector.evaluate(now)
    assert [e.event_type for e in result.events] == [EVENT_ANOMALY_ENDED]
    assert kinds(detector, "ended") == {"download_spike"}
    now = feed(source, WAN, now, now + 600, flat(rx=50 * MBIT))  # within 30 min
    assert detector.evaluate(now).events == ()
    (again,) = detector.book.candidates(state="open")
    assert again.candidate_id == first.candidate_id
    assert detector.book.counters["reopened_debounce"] == 1
    assert [c["t"] for c in publisher_calls] == [
        EVENT_ANOMALY_STARTED,
        EVENT_ANOMALY_ENDED,
    ]


def cand(n: int, kind: str = "download_spike", now: float = MON) -> AnomalyCandidate:
    return AnomalyCandidate(
        candidate_id=f"tac_{n:016x}",
        point_id=f"tpt_{n:016x}",
        router_id=RID,
        client_ref=None,
        kind=kind,
        observed=1.0,
        baseline_median=0.5,
        baseline_mad=0.1,
        threshold=0.8,
        window_s=600,
        confidence=0.5,
        coverage=Coverage.FULL,
        started=now,
        last_seen=now,
    )


def test_budget_per_hour_against_floods() -> None:
    book = CandidateBook()
    events = [book.raise_candidate(cand(n), now=MON, hour=10) for n in range(40)]
    assert sum(e is not None for e in events) == BUDGET_PER_HOUR
    assert book.counters[f"suppressed_{SUPPRESSED_BUDGET_HOUR}"] == 10
    reasons = {c.suppressed_reason for c in book.candidates(state="suppressed")}
    assert reasons == {SUPPRESSED_BUDGET_HOUR}
    # an hour later the budget is free again
    assert book.raise_candidate(cand(99), now=MON + 3600, hour=11) is not None


def test_budget_per_point_and_per_point_kind() -> None:
    book = CandidateBook()
    assert book.raise_candidate(cand(1, "download_spike"), now=MON, hour=1)
    assert book.raise_candidate(cand(1, "upload_spike"), now=MON, hour=1)
    assert book.raise_candidate(cand(1, "rx_drop"), now=MON, hour=1) is None
    assert book.counters[f"suppressed_{SUPPRESSED_BUDGET_POINT}"] == 1
    book.end((cand(1).point_id, "download_spike"), MON + 60)
    later = MON + 2 * 3600  # past the debounce, inside 6 h
    assert (
        book.raise_candidate(cand(1, "download_spike", later), now=later, hour=3)
        is None
    )
    assert book.counters[f"suppressed_{SUPPRESSED_BUDGET_POINT_KIND}"] == 1


def test_suppression_rules_act_only_on_traffic_candidates() -> None:
    with pytest.raises(ValueError):
        SuppressionRule("r1", kind="wifi_auth_failures")  # an NI rule: refused
    with pytest.raises(ValueError):
        SuppressionRule("r2")  # matches everything: refused
    book = CandidateBook()
    book.add_rule(SuppressionRule("r3", kind="download_spike", until=MON + 100))
    assert book.raise_candidate(cand(1), now=MON, hour=0) is None
    assert book.candidates(state="suppressed")[0].suppressed_reason == SUPPRESSED_RULE
    assert book.raise_candidate(cand(2), now=MON + 200, hour=0) is not None  # expired
    rule = SuppressionRule("r4", point_id=cand(3).point_id)
    assert not rule.matches(cand(3).point_id, "lan_port_load", MON, 0)
    assert "lan_port_load" not in TRAFFIC_KINDS


def test_candidate_memory_is_bounded_with_separate_quotas() -> None:
    book = CandidateBook()
    for n in range(130):
        book.raise_candidate(cand(n), now=MON + n * 200, hour=0)
    assert len(book) <= MAX_CANDIDATES
    assert len(book.open) == 80  # open ones are never evicted
    assert len(book.suppressed) == 20
    assert book.counters[f"suppressed_{SUPPRESSED_STORE_FULL}"] == 50
    assert book.counters["dropped_suppressed"] == 30
    for key in list(book.open)[:10]:
        book.end(key, MON + 30_000)
    book.raise_candidate(cand(500), now=MON + 40_000, hour=0)
    assert len(book.open) + len(book.ended) <= 80
    assert book.counters["dropped_ended"] == 1


# --- publishing ----------------------------------------------------------------------------


def test_events_go_through_core_emit_only() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    source = ring()
    detector = AnomalyDetector(
        source, publisher=CandidatePublisher(lambda t, **kw: calls.append((t, kw)))
    )
    now = feed(source, CLIENT, MON, MON + 7 * DAY + 10 * 3600, flat())
    now = feed(source, CLIENT, now, now + 600, flat(tx=60 * MBIT))
    detector.evaluate(now)
    ((event_type, kw),) = calls
    assert event_type == EVENT_ANOMALY_STARTED
    assert kw["source"] == "traffic_analytics"
    assert kw["client_ref"] == CLIENT.client_ref
    assert kw["classification"] == "download_spike"
    assert kw["data"]["incident_engine"] == "not_connected"
    text = json.dumps(
        [kw["data"]] + [candidate_dict(c) for c in detector.book.candidates()]
    ).lower()
    assert "attack" not in text and "angriff" not in text
    assert detector.summary()["published"] == 1


def test_without_core_nothing_is_published_and_it_says_so() -> None:
    source = ring()
    detector = AnomalyDetector(source)
    now = feed(source, WAN, MON, MON + 7 * DAY + 10 * 3600, flat())
    now = feed(source, WAN, now, now + 600, flat(rx=60 * MBIT))
    detector.evaluate(now)
    summary = detector.summary()
    assert summary["not_published"] == 1
    assert summary["not_published_reason"] == "core_events_not_bound"
    assert summary["incident_engine"] == "not_connected"
    assert "cli_" not in json.dumps(summary) and "tpt_" not in json.dumps(summary)


def test_failing_emit_never_breaks_the_detector() -> None:
    def boom(*_a: Any, **_kw: Any) -> None:
        raise ValueError("refused")

    publisher = CandidatePublisher(boom)
    book = CandidateBook()
    event = book.raise_candidate(cand(1), now=MON, hour=0)
    assert publisher.publish(event) is False
    assert publisher.counters["publish_failed"] == 1


def test_engine_has_the_detector_and_throttles_it() -> None:
    from core_testkit import make_hass

    from custom_components.openwrt_router.traffic_engine import TrafficEngine

    engine = TrafficEngine(make_hass())
    times = iter([MON, MON + 10, MON + 400])
    engine.wall = lambda: next(times)
    engine._maybe_evaluate_anomalies()
    engine._maybe_evaluate_anomalies()  # throttled
    engine._maybe_evaluate_anomalies()
    assert engine.anomalies.counters["evaluations"] == 2
    summary = engine.summary()["anomalies"]
    assert summary["incident_engine"] == "not_connected"
    assert summary["families"]["spikes"]["state"] == "unavailable"
