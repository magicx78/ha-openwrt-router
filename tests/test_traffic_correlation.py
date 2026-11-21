"""Correlation (test areas 30 quality/congestion, 31 security intelligence).

traffic_correlate.py: bottleneck narrowing needs a second independent
indicator, everything is "possible", recommendations need a data base;
optional modules (Network Diagnostics, WiFi RF) through adapters - both
"missing" and "present" via test doubles in the shape of their branches;
indicators with stable evidence refs, never called an attack; the read API
for other modules (acceptance criterion 11). No router, no network; ids are
synthetic test values.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from core_testkit import FakeDisks, make_hass

from custom_components.openwrt_router.const import (
    DATA_TRAFFIC_ANALYTICS,
    EVENT_INCIDENT,
)
from custom_components.openwrt_router.traffic_capacity import LinkFacts
from custom_components.openwrt_router.traffic_collect import DeviceCounters
from custom_components.openwrt_router.traffic_const import (
    ASSESS_BOTTLENECK,
    ASSESS_HIGH_UTIL,
    ASSESS_LINK_QUALITY,
    ASSESS_UPLINK_BOTTLENECK,
    ASSESS_WIFI_CONGESTION,
    ASSESS_WIFI_SINGLE,
    CORR_MAX_CONFIDENCE,
    DIAG_DATA_KEY,
    EVENT_INDICATOR,
    EVENT_PREFIX,
    IND_CONNECTION_RATE,
    IND_INTER_VLAN,
    IND_OUTBOUND,
    IND_UNUSUAL_VOLUME,
    INDICATOR_BUDGET_PER_HOUR,
    INDICATOR_CLASSIFICATION,
    MAX_CORR_POINTS,
    MAX_EVIDENCE,
    READ_API_VERSION,
    REASON_DISABLED,
    REASON_INSUFFICIENT_DATA,
    REASON_INTERFACE_MISMATCH,
    REASON_LOOKUP_FAILED,
    REASON_MODULE_DISABLED,
    REASON_MODULE_NOT_LOADED,
    REASON_NO_LINK_SPEED,
    REASON_NO_ROUTER_SERIES,
    REASON_NOT_A_BOTTLENECK_ALONE,
    REASON_NOT_LISTENING,
    REASON_READ_FAILED,
    REASON_SINGLE_INDICATOR,
    REASON_TOO_FEW_SAMPLES,
    REASON_UNKNOWN_POINT,
    REASON_UNKNOWN_WINDOW,
    SOURCE_MODULE_MISSING,
    SOURCE_NO_DATA,
    SOURCE_NOT_CONNECTED,
    SOURCE_NOT_READY,
    SOURCE_READY,
    SRC_DIAG,
    SRC_NI,
    SRC_WIFI_RF,
    VERDICT_FINDINGS,
    VERDICT_INSUFFICIENT,
    VERDICT_NOTHING_IN_COVERED,
    WIFI_RF_DATA_KEY,
)
from custom_components.openwrt_router.traffic_correlate import (
    DiagnosticsAdapter,
    EvidenceBook,
    SecurityIndicators,
    TrafficCorrelator,
    async_get_traffic_read_api,
    confidence_of,
    evidence_ref_of,
    indicator_of,
    valid_evidence_ref,
)
from custom_components.openwrt_router.traffic_engine import TrafficEngine
from custom_components.openwrt_router.traffic_model import (
    AnomalyCandidate,
    Bucket,
    CandidateState,
    Coverage,
    MeasurementPoint,
    Quality,
    Rate,
    Scope,
    quality_bit,
)
from custom_components.openwrt_router.traffic_series import (
    MemoryBucketRing,
    SeriesWindow,
)

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
REF = "cli_" + "a" * 16
KEY = bytes(range(32))
NOW = 1_800_000_000.0 - 1_800_000_000 % 3600  # aligned to the hour
WAN = MeasurementPoint(RID, Scope.WAN, device="wan")
PORT = MeasurementPoint(RID, Scope.PORT, device="lan1")
CLIENT = MeasurementPoint(None, Scope.CLIENT, client_ref=REF)
GIG = LinkFacts(1000, "full")
MBIT = 1_000_000.0


# --- helpers ---------------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disks():
    """Engines here activate: their history store runs on FakeDisks."""
    with FakeDisks().patch() as fake:
        yield fake


def bucket(i: int, rx_bps: float, *, covered: float = 300.0, mask: int = 0) -> Bucket:
    """Bucket ``i`` of the hour before NOW (0 = oldest)."""
    return Bucket(
        start=int(NOW - 3600 + i * 300),
        resolution_s=300,
        rx_bytes=int(rx_bps * covered / 8),
        tx_bytes=int(rx_bps * covered / 80),
        rx_peak_bps=rx_bps,
        covered_s=covered,
        samples=5,
        quality_mask=mask,
    )


class FakeSource:
    """A ``BucketSource`` over fixed buckets per point."""

    resolution_s = 300

    def __init__(self, series: Mapping[MeasurementPoint, list[Bucket]]) -> None:
        self.series = dict(series)
        self.version = 1

    def points(self) -> list[MeasurementPoint]:
        return list(self.series)

    def window(
        self, point_id: str, window_s: int, *, end: float
    ) -> SeriesWindow | None:
        for point, buckets in self.series.items():
            if point.point_id == point_id:
                inside = tuple(b for b in buckets if end - window_s <= b.start < end)
                return SeriesWindow(
                    point=point,
                    window_s=window_s,
                    end=end,
                    resolution_s=300,
                    buckets=inside,
                    depth_s=float(window_s),
                    area_coverage=Coverage.FULL,
                )
        return None

    def dropped(self) -> dict[str, int]:
        return {}


def busy(rx_bps: float = 900 * MBIT, n: int = 12) -> list[Bucket]:
    return [bucket(i, rx_bps) for i in range(n)]


def drop_rates(point: MeasurementPoint, drops: int, *, n: int = 12) -> list[Rate]:
    """``n`` rates over the hour with ``drops`` drops each."""
    return [
        Rate(
            point,
            Quality.OK,
            interval_s=300,
            rx_dropped_delta=drops,
            tx_dropped_delta=0,
            rx_errors_delta=0,
            tx_errors_delta=0,
            rx_packets_delta=10_000,
            tx_packets_delta=10_000,
            wall_s=NOW - 3600 + 300 * (i + 1) - 1,
        )
        for i in range(n)
    ]


def summary(**kw: Any) -> dict[str, Any]:
    """A ``diag_stats.LatencySummary`` dict (main 1.48.0)."""
    out = {
        "answered": 60,
        "lost": 0,
        "gaps": 0,
        "expected": 60,
        "coverage": 1.0,
        "current_ms": 10.0,
        "mean_ms": 10.0,
        "min_ms": 8.0,
        "max_ms": 14.0,
        "jitter_ms": 1.0,
        "loss_pct": 0.0,
        "outliers": 0,
    }
    out.update(kw)
    return out


class FakeDiagnostics:
    """Test double of ``diag_runtime.NetDiagnostics`` (``history_view`` only)."""

    def __init__(self, view: Any) -> None:
        self.view = view
        self.calls = 0

    def history_view(self) -> Any:
        self.calls += 1
        if isinstance(self.view, Exception):
            raise self.view
        return self.view


def diag_view(hour: dict[str, Any], week: dict[str, Any] | None = None) -> dict:
    return {
        "state": "ready",
        "reasons": [],
        "windows": ["1h", "24h", "7d", "30d"],
        "series": [
            {
                "point": RID,
                "target_id": "tgt_0001",
                "kind": "icmp",
                "family": "ipv4",
                "windows": {"1h": hour, "24h": None, "7d": week, "30d": None},
            },
            {  # another router and a non-latency kind: ignored
                "point": RID2,
                "target_id": "tgt_0002",
                "kind": "icmp",
                "family": "ipv4",
                "windows": {"1h": summary(mean_ms=900.0)},
            },
            {
                "point": RID,
                "target_id": "tgt_0003",
                "kind": "fact",
                "family": None,
                "windows": {"1h": summary(mean_ms=999.0)},
            },
        ],
        "gaps": 0,
    }


class FakeRf:
    """Test double of a WiFi RF center (the W6 read API; see test_traffic_rf_adapter for main)."""

    def __init__(
        self,
        radios: dict[str, dict[str, Any]],
        retries: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self.radios = radios
        self.retries = retries or {}

    def radio_utilization(self, router_id: str, window_s: int) -> dict:
        return self.radios if router_id == RID else {}

    def client_retry_rates(self, router_id: str, window_s: int) -> dict:
        return self.retries if router_id == RID else {}


def util(mean: float, valid: int = 12, overload: bool = False) -> dict[str, Any]:
    """``rf_utilization.UtilizationSummary.as_dict()`` (main 1.48.0)."""
    return {
        "current": mean,
        "mean": mean,
        "peak": mean,
        "valid_count": valid,
        "invalid_count": 0,
        "coverage": 1.0,
        "phases": [],
        "sustained_overload": overload,
    }


def metric(value: float | None, state: str = "measured") -> dict[str, Any]:
    """``rf_models.Metric.as_dict()`` (main 1.48.0)."""
    return {"value": value, "state": state, "source": "iw", "measured_at": NOW}


def only(report: Any, point: MeasurementPoint | None = None) -> Any:
    found = [
        f for f in report.findings if point is None or f.point_id == point.point_id
    ]
    assert len(found) == 1, report.to_dict()
    return found[0]


def no_confirmed(payload: Any) -> None:
    text = json.dumps(payload)
    assert "confirmed" not in text
    assert "healthy" not in text


# --- area 30: bottleneck narrowing --------------------------------------------------------------


def test_high_utilization_alone_is_never_a_bottleneck() -> None:
    corr = TrafficCorrelator()
    report = corr.evaluate(
        FakeSource({PORT: busy()}), now=NOW, links={PORT.point_id: GIG}
    )
    finding = only(report, PORT)
    assert finding.assessment == ASSESS_HIGH_UTIL
    assert finding.wording == "possible"
    assert finding.recommendations == ()
    assert finding.recommendation_withheld == REASON_NOT_A_BOTTLENECK_ALONE
    assert finding.independent_families == ()
    obs = finding.observations[0]
    assert obs.indicator == "utilization_high" and obs.elevated
    assert obs.value == pytest.approx(90.0) and obs.threshold == 80
    assert (obs.start, obs.end, obs.window_s) == (NOW - 3600, NOW, 3600)
    assert report.verdict == VERDICT_FINDINGS
    no_confirmed(report.to_dict())


def test_utilization_plus_drops_is_a_possible_bottleneck_with_advice() -> None:
    corr = TrafficCorrelator()
    corr.observe_rates(drop_rates(PORT, 50))
    report = corr.evaluate(
        FakeSource({PORT: busy()}),
        now=NOW,
        links={PORT.point_id: GIG},
        uplink_ports={RID: frozenset({"lan4"})},
    )
    finding = only(report, PORT)
    assert finding.assessment == ASSESS_BOTTLENECK
    assert finding.independent_families == ("interface_counters",)
    assert "check_link_capacity" in finding.recommendations
    assert finding.recommendation_withheld is None
    drops = next(o for o in finding.observations if o.indicator == "interface_drops")
    assert drops.value == 600 and drops.elevated and drops.detail["packets"] == 240_000
    assert 0 < finding.confidence <= CORR_MAX_CONFIDENCE
    assert finding.confidence == confidence_of(1, 1.0) == 0.5
    assert finding.coverage["traffic_analytics"]["usable_buckets"] == 12
    no_confirmed(finding.to_dict())


def test_few_drops_are_measured_but_not_elevated() -> None:
    corr = TrafficCorrelator()
    corr.observe_rates(drop_rates(PORT, 0))
    finding = only(
        corr.evaluate(FakeSource({PORT: busy()}), now=NOW, links={PORT.point_id: GIG})
    )
    drops = next(o for o in finding.observations if o.indicator == "interface_drops")
    assert drops.value == 0 and not drops.elevated
    assert finding.assessment == ASSESS_HIGH_UTIL


def test_recommendation_needs_minimum_data() -> None:
    corr = TrafficCorrelator()
    corr.observe_rates(drop_rates(PORT, 50))
    # 7 usable buckets: enough to observe (6), too few to advise (9).
    buckets = busy(n=7)
    finding = only(
        corr.evaluate(FakeSource({PORT: buckets}), now=NOW, links={PORT.point_id: GIG})
    )
    assert finding.assessment == ASSESS_BOTTLENECK
    assert finding.recommendations == ()
    assert finding.recommendation_withheld == REASON_INSUFFICIENT_DATA
    assert finding.confidence < confidence_of(1, 1.0)


def test_unknown_link_speed_gives_no_utilization() -> None:
    corr = TrafficCorrelator()
    report = corr.evaluate(FakeSource({PORT: busy()}), now=NOW, links={})
    assert report.findings == ()
    assert report.verdict == VERDICT_NOTHING_IN_COVERED
    corr.observe_rates(drop_rates(PORT, 50))
    finding = only(corr.evaluate(FakeSource({PORT: busy()}), now=NOW, links={}))
    assert finding.assessment == ASSESS_LINK_QUALITY
    assert finding.unmeasured["utilization"] == REASON_NO_LINK_SPEED


def test_too_few_buckets_is_insufficient_not_ok() -> None:
    corr = TrafficCorrelator()
    report = corr.evaluate(
        FakeSource({PORT: busy(n=3)}), now=NOW, links={PORT.point_id: GIG}
    )
    assert report.findings == ()
    assert report.verdict == VERDICT_INSUFFICIENT
    assert report.points_insufficient == 1
    empty = corr.evaluate(FakeSource({}), now=NOW)
    assert empty.verdict == VERDICT_INSUFFICIENT
    assert empty.sources[0].state == SOURCE_NO_DATA


def test_gappy_buckets_do_not_count() -> None:
    corr = TrafficCorrelator()
    buckets = [bucket(i, 900 * MBIT, covered=100.0) for i in range(12)]
    report = corr.evaluate(
        FakeSource({PORT: buckets}), now=NOW, links={PORT.point_id: GIG}
    )
    assert report.findings == ()
    assert report.verdict == VERDICT_INSUFFICIENT


def test_sources_are_reported_and_never_ok_without_data() -> None:
    corr = TrafficCorrelator()
    report = corr.evaluate(
        FakeSource({PORT: busy(100 * MBIT)}), now=NOW, links={PORT.point_id: GIG}
    )
    assert report.verdict == VERDICT_NOTHING_IN_COVERED
    states = {s.module: (s.state, s.reason) for s in report.sources}
    assert states[SRC_DIAG] == (SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED)
    assert states[SRC_WIFI_RF] == (SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED)
    assert states[SRC_NI] == (SOURCE_NOT_CONNECTED, REASON_NOT_LISTENING)
    assert "ok" not in {s.state for s in report.sources}


def test_wan_with_latency_from_diagnostics_is_possible_uplink_bottleneck() -> None:
    diag = DiagnosticsAdapter(
        lambda: FakeDiagnostics(
            diag_view(summary(mean_ms=80.0, loss_pct=3.0), summary(mean_ms=15.0))
        )
    )
    corr = TrafficCorrelator()
    report = corr.evaluate(
        FakeSource({WAN: busy()}),
        now=NOW,
        links={WAN.point_id: LinkFacts(1000, "full")},
        diagnostics=diag,
    )
    finding = only(report, WAN)
    assert finding.assessment == ASSESS_UPLINK_BOTTLENECK
    assert finding.independent_families == ("path_quality",)
    names = {o.indicator: o for o in finding.observations}
    assert names["latency_elevated"].value == 80.0
    assert names["latency_elevated"].detail["reference_ms_7d"] == 15.0
    assert names["packet_loss"].value == 3.0 and names["packet_loss"].elevated
    assert names["latency_elevated"].source == SRC_DIAG
    assert "check_sqm_configuration" in finding.recommendations
    assert finding.coverage[SRC_DIAG]["state"] == SOURCE_READY
    assert {s.module: s.state for s in report.sources}[SRC_DIAG] == SOURCE_READY


def test_wan_latency_without_reference_is_not_elevated() -> None:
    diag = DiagnosticsAdapter(lambda: FakeDiagnostics(diag_view(summary(mean_ms=80.0))))
    finding = only(
        TrafficCorrelator().evaluate(
            FakeSource({WAN: busy()}),
            now=NOW,
            links={WAN.point_id: GIG},
            diagnostics=diag,
        )
    )
    assert finding.assessment == ASSESS_HIGH_UTIL
    assert finding.unmeasured["path_quality"] == "no_reference_window"


def test_wan_without_diagnostics_names_the_missing_module() -> None:
    diag = DiagnosticsAdapter(lambda: None)
    finding = only(
        TrafficCorrelator().evaluate(
            FakeSource({WAN: busy()}),
            now=NOW,
            links={WAN.point_id: GIG},
            diagnostics=diag,
        )
    )
    assert finding.assessment == ASSESS_HIGH_UTIL
    assert finding.unmeasured["path_quality"] == (
        f"{SOURCE_MODULE_MISSING}:{REASON_MODULE_NOT_LOADED}"
    )
    assert finding.coverage[SRC_DIAG]["state"] == SOURCE_MODULE_MISSING


@pytest.mark.parametrize(
    ("module", "state", "reason"),
    [
        (None, SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED),
        (object(), SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH),
        (FakeDiagnostics(RuntimeError("x")), SOURCE_NOT_READY, REASON_READ_FAILED),
        (
            FakeDiagnostics(["not", "a", "dict"]),
            SOURCE_NOT_READY,
            REASON_INTERFACE_MISMATCH,
        ),
        (FakeDiagnostics({"state": "off"}), SOURCE_NOT_READY, REASON_MODULE_DISABLED),
        (
            FakeDiagnostics({"state": "not_ready", "reasons": ["module_key_missing"]}),
            SOURCE_NOT_READY,
            "module_key_missing",
        ),
        (FakeDiagnostics({"state": "weird"}), SOURCE_NOT_READY, "unknown_module_state"),
        (
            FakeDiagnostics({"state": "ready", "series": []}),
            SOURCE_NO_DATA,
            REASON_NO_ROUTER_SERIES,
        ),
        (
            FakeDiagnostics(diag_view(summary(answered=2, lost=0))),
            SOURCE_NO_DATA,
            REASON_TOO_FEW_SAMPLES,
        ),
        (
            FakeDiagnostics(diag_view(summary(coverage=0.2))),
            SOURCE_NO_DATA,
            REASON_TOO_FEW_SAMPLES,
        ),
    ],
)
def test_diagnostics_adapter_states(module: Any, state: str, reason: str) -> None:
    status, facts = DiagnosticsAdapter(lambda: module).latency(RID)
    assert (status.state, status.reason) == (state, reason)
    assert facts is None


def test_diagnostics_lookup_failure_is_not_ready() -> None:
    def boom() -> Any:
        raise KeyError("gone")

    status, facts = DiagnosticsAdapter(boom).latency(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, REASON_LOOKUP_FAILED)
    assert facts is None


def test_diagnostics_adapter_reads_worst_series_of_the_router() -> None:
    view = diag_view(summary(mean_ms=12.0), summary(mean_ms=10.0))
    view["series"].append(
        {
            "point": RID,
            "target_id": "tgt_0004",
            "kind": "tcp",
            "family": "ipv4",
            "windows": {"1h": summary(mean_ms=30.0, loss_pct=1.0), "7d": None},
        }
    )
    status, facts = DiagnosticsAdapter(lambda: FakeDiagnostics(view)).latency(RID)
    assert status.state == SOURCE_READY
    assert facts is not None
    assert facts.mean_ms == 30.0 and facts.reference_ms is None
    assert facts.latency_elevated is None and facts.loss_pct == 1.0
    assert facts.series == 2 and not facts.loss_elevated


def test_wifi_rf_missing_or_mismatched() -> None:
    corr = TrafficCorrelator()
    from custom_components.openwrt_router.traffic_correlate import WifiRfAdapter

    for module, state, reason in (
        (None, SOURCE_MODULE_MISSING, REASON_MODULE_NOT_LOADED),
        (object(), SOURCE_NOT_READY, REASON_INTERFACE_MISMATCH),
        (
            SimpleNamespace(
                radio_utilization=lambda *_: {},
                client_retry_rates=lambda *_: {},
                enabled=False,
            ),
            SOURCE_NOT_READY,
            REASON_MODULE_DISABLED,
        ),
        (FakeRf({}), SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES),
        (FakeRf({"phy0": util(95.0, valid=2)}), SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES),
    ):
        report = corr.evaluate(
            FakeSource({PORT: busy(10 * MBIT)}),
            now=NOW,
            links={PORT.point_id: GIG},
            wifi_rf=WifiRfAdapter(lambda m=module: m),
        )
        rf = {s.module: s for s in report.sources}[SRC_WIFI_RF]
        assert (rf.state, rf.reason) == (state, reason)
        assert report.findings == ()


def test_wifi_rf_airtime_and_retries_give_possible_congestion() -> None:
    from custom_components.openwrt_router.traffic_correlate import WifiRfAdapter

    center = FakeRf(
        {"phy0": util(85.0), "phy1": util(20.0)},
        {
            REF: metric(0.4),
            "cli_" + "b" * 16: metric(0.1),
            "cli_" + "c" * 16: metric(None, "no_data"),
            "aa:bb": metric(0.9),  # not a pseudonym: ignored
        },
    )
    report = TrafficCorrelator().evaluate(
        FakeSource({PORT: busy(10 * MBIT)}),
        now=NOW,
        links={PORT.point_id: GIG},
        wifi_rf=WifiRfAdapter(lambda: center),
    )
    finding = only(report)
    assert finding.scope == "radio" and finding.point_id is None
    assert finding.assessment == ASSESS_WIFI_CONGESTION
    obs = {o.indicator: o for o in finding.observations}
    assert obs["airtime_high"].value == 85.0
    assert obs["airtime_high"].detail["radio_id"] == "phy0"
    assert obs["retransmissions_high"].detail["clients_measured"] == 2
    assert finding.recommendations == ("check_channel_plan_and_airtime",)
    no_confirmed(report.to_dict())


def test_wifi_rf_single_indicator_gives_no_advice() -> None:
    from custom_components.openwrt_router.traffic_correlate import WifiRfAdapter

    center = FakeRf({"phy0": util(85.0)})
    finding = only(
        TrafficCorrelator().evaluate(
            FakeSource({PORT: busy(10 * MBIT)}),
            now=NOW,
            wifi_rf=WifiRfAdapter(lambda: center),
        )
    )
    assert finding.assessment == ASSESS_WIFI_SINGLE
    assert finding.recommendations == ()
    assert finding.recommendation_withheld == REASON_SINGLE_INDICATOR


def test_wifi_rf_read_failure_is_not_ready() -> None:
    from custom_components.openwrt_router.traffic_correlate import WifiRfAdapter

    def broken(*_: Any) -> Any:
        raise OSError("x")

    center = SimpleNamespace(radio_utilization=broken, client_retry_rates=broken)
    status, facts = WifiRfAdapter(lambda: center).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, REASON_READ_FAILED)
    assert facts is None


def test_link_down_and_router_restart_are_connectivity_indicators() -> None:
    corr = TrafficCorrelator()
    corr.observe_links(
        RID,
        [DeviceCounters("lan1", (0,) * 8, up=True, carrier=False)],
        NOW - 600,
    )
    corr.observe_links(RID, [DeviceCounters("lan1", (0,) * 8, up=True)], NOW - 300)
    buckets = busy()
    buckets[5] = bucket(5, 900 * MBIT, mask=quality_bit(Quality.ROUTER_RESTART))
    finding = only(
        corr.evaluate(FakeSource({PORT: buckets}), now=NOW, links={PORT.point_id: GIG})
    )
    obs = {o.indicator: o for o in finding.observations}
    assert obs["link_down_observed"].value == 1 and obs["link_down_observed"].elevated
    assert obs["router_restart"].value == 1
    assert finding.assessment == ASSESS_BOTTLENECK
    assert finding.independent_families == ("connectivity",)


def test_ni_incidents_are_linked_not_copied() -> None:
    corr = TrafficCorrelator()
    corr.ni_listening = True
    data = {
        "state": "opened",
        "incident_id": "inc_000001",
        "type": "uplink_down",
        "severity": "major",
        "confidence": 0.9,
        "cause": "uplink",
        "scope": "router",
        "routers": ["Test Router A"],  # titles: never kept
        "entry_ids": ["entry-1", "entry-unknown"],
        "device_id": "dev-1",
    }
    lookup = {"entry-1": RID}.get
    assert corr.observe_incident(data, lookup, NOW - 120)
    assert not corr.observe_incident({"type": "Bad Type!"}, lookup, NOW)
    assert not corr.observe_incident(
        {**data, "entry_ids": ["entry-unknown"]}, lookup, NOW
    )
    assert corr.counters["ni_events_invalid"] == 1
    assert corr.counters["ni_events_unmapped"] == 1
    finding = only(
        corr.evaluate(FakeSource({PORT: busy()}), now=NOW, links={PORT.point_id: GIG})
    )
    assert finding.incident_refs == ("inc_000001",)
    obs = next(
        o for o in finding.observations if o.indicator == "connectivity_incident"
    )
    assert obs.source == SRC_NI and obs.detail == {"types": ["uplink_down"]}
    text = json.dumps(finding.to_dict()) + json.dumps(corr.summary())
    assert "Test Router A" not in text and "dev-1" not in text
    assert finding.coverage[SRC_NI]["state"] == SOURCE_READY


def test_correlator_memory_is_bounded_and_forgets() -> None:
    corr = TrafficCorrelator()
    rates = []
    for n in range(MAX_CORR_POINTS + 5):
        point = MeasurementPoint(RID, Scope.PORT, device=f"p{n}")
        rates.append(
            Rate(point, Quality.OK, interval_s=60, rx_dropped_delta=1, wall_s=NOW)
        )
    corr.observe_rates(rates)
    assert corr.summary()["quality_points"] == MAX_CORR_POINTS
    assert corr.counters["dropped_quality_points"] == 5
    corr.observe_rates(drop_rates(MeasurementPoint(RID2, Scope.WAN, device="wan"), 1))
    corr.drop_router(RID)
    assert corr.summary()["quality_points"] == 0
    corr.clear()
    assert corr.summary()["link_devices"] == 0 and not corr.ni_listening


def test_correlation_with_the_memory_ring() -> None:
    ring = MemoryBucketRing()
    for i in range(12):
        ring.add_rate(
            Rate(
                WAN,
                Quality.OK,
                interval_s=300,
                rx_bps=950 * MBIT,
                tx_bps=10 * MBIT,
                rx_delta=int(950 * MBIT * 300 / 8),
                tx_delta=int(10 * MBIT * 300 / 8),
                wall_s=NOW - 3600 + 300 * (i + 1),
            )
        )
    report = TrafficCorrelator().evaluate(ring, now=NOW + 1, links={WAN.point_id: GIG})
    finding = only(report, WAN)
    assert finding.assessment == ASSESS_HIGH_UTIL
    assert finding.observations[0].value == pytest.approx(95.0, rel=0.02)


# --- area 31: security indicators and evidence ----------------------------------------------------


def candidate(
    n: int = 1,
    *,
    kind: str = "client_volume",
    point: MeasurementPoint = CLIENT,
    state: CandidateState = CandidateState.OPEN,
) -> AnomalyCandidate:
    return AnomalyCandidate(
        candidate_id=f"tac_{n:016x}",
        point_id=point.point_id,
        router_id=point.router_id,
        client_ref=point.client_ref,
        kind=kind,
        observed=5e9,
        baseline_median=1e9,
        baseline_mad=1e8,
        threshold=2e9,
        window_s=86400,
        confidence=0.6,
        coverage=Coverage.FULL,
        started=NOW - 600,
        last_seen=NOW,
        state=state,
    )


def client_source() -> FakeSource:
    return FakeSource({CLIENT: busy(5 * MBIT)})


def test_open_volume_candidate_becomes_indicator_with_evidence() -> None:
    emit = MagicMock()
    ind = SecurityIndicators(emit)
    refs = ind.evaluate([candidate()], client_source(), now=NOW, key=KEY)
    assert len(refs) == 1 and valid_evidence_ref(refs[0])
    assert refs[0] == evidence_ref_of(KEY, candidate().candidate_id)  # stable
    (event,), kwargs = emit.call_args
    assert event == EVENT_INDICATOR and event.startswith(EVENT_PREFIX)
    assert kwargs["classification"] == INDICATOR_CLASSIFICATION
    assert kwargs["security_relevant"] is False
    assert kwargs["client_ref"] == REF
    assert kwargs["data"]["evidence_ref"] == refs[0]
    assert kwargs["data"]["indicator"] == IND_UNUSUAL_VOLUME
    assert kwargs["data"]["security_center"] == SOURCE_NOT_CONNECTED
    assert kwargs["dedup_key"] == f"{CLIENT.point_id}:{IND_UNUSUAL_VOLUME}"
    evidence = ind.evidence.resolve(refs[0])
    assert evidence is not None
    assert evidence["point"]["client_ref"] == REF
    assert len(evidence["rows"]) == 12 and evidence["resolution_s"] == 300
    assert evidence["excerpt_end"] == NOW
    # The same candidate again: no second event.
    assert ind.evaluate([candidate()], client_source(), now=NOW + 300, key=KEY) == []
    assert emit.call_count == 1


def test_traffic_anomaly_is_never_called_an_attack() -> None:
    emit = MagicMock()
    ind = SecurityIndicators(emit)
    ind.evaluate([candidate()], client_source(), now=NOW, key=KEY)
    text = json.dumps(emit.call_args.kwargs["data"]) + json.dumps(
        ind.evidence.resolve(ind.evidence.refs()[0])
    )
    text += json.dumps(ind.summary())
    assert text.count("attack") == text.count("not_an_attack") > 0


def test_without_module_key_indicators_are_not_ready() -> None:
    emit = MagicMock()
    ind = SecurityIndicators(emit)
    assert ind.evaluate([candidate()], client_source(), now=NOW, key=None) == []
    emit.assert_not_called()
    assert ind.summary()["indicators"][IND_UNUSUAL_VOLUME]["state"] == "not_ready"
    assert len(ind.evidence) == 0


def test_flow_indicators_unavailable_without_flow_source() -> None:
    ind = SecurityIndicators()
    ind.evaluate([], client_source(), now=NOW, key=KEY, has_points=True)
    states = ind.summary()["indicators"]
    assert states[IND_OUTBOUND] == {
        "state": "unavailable",
        "reason": "needs_flow_source",
    }
    assert states[IND_INTER_VLAN]["state"] == "unavailable"
    assert states[IND_CONNECTION_RATE]["state"] == "unavailable"
    assert states[IND_UNUSUAL_VOLUME]["state"] == "active"
    ind.evaluate(
        [],
        client_source(),
        now=NOW,
        key=KEY,
        flow_ready=True,
        conntrack_sources={RID: "count_file"},
        has_points=True,
    )
    states = ind.summary()["indicators"]
    assert states[IND_OUTBOUND]["state"] == "learning"
    assert states[IND_CONNECTION_RATE]["state"] == "covered_by_network_intelligence"
    assert ind.summary()["security_center"]["state"] == SOURCE_NOT_CONNECTED


def test_only_open_volume_candidates_are_indicators() -> None:
    assert indicator_of(candidate(kind="wan_spike", point=WAN)) == IND_UNUSUAL_VOLUME
    assert indicator_of(candidate(kind="client_night_activity")) == IND_UNUSUAL_VOLUME
    assert indicator_of(candidate(state=CandidateState.ENDED)) is None
    assert indicator_of(candidate(kind="connection_rate")) is None


def test_indicator_budget_and_point_kind_limit_are_counted() -> None:
    emit = MagicMock()
    ind = SecurityIndicators(emit)
    points = [
        MeasurementPoint(None, Scope.CLIENT, client_ref=f"cli_{n:016x}")
        for n in range(INDICATOR_BUDGET_PER_HOUR + 3)
    ]
    cands = [candidate(n, point=p) for n, p in enumerate(points)]
    ind.evaluate(cands, client_source(), now=NOW, key=KEY)
    assert emit.call_count == INDICATOR_BUDGET_PER_HOUR
    assert ind.counters["dropped_events_budget"] == 3
    # Same point and indicator within 6 h: no second event.
    ind.evaluate(
        [candidate(500, point=points[0])], client_source(), now=NOW + 3700, key=KEY
    )
    assert ind.counters["dropped_events_point_kind"] == 1
    assert emit.call_count == INDICATOR_BUDGET_PER_HOUR


def test_emit_failure_or_unbound_never_raises() -> None:
    ind = SecurityIndicators(MagicMock(side_effect=RuntimeError("core gone")))
    ind.evaluate([candidate()], client_source(), now=NOW, key=KEY)
    assert ind.counters["publish_failed"] == 1
    unbound = SecurityIndicators()
    unbound.evaluate([candidate()], client_source(), now=NOW, key=KEY)
    assert unbound.summary()["not_published"] == 1
    assert len(unbound.evidence) == 1  # evidence still resolvable


def test_evidence_book_is_bounded_and_counts_discards() -> None:
    book = EvidenceBook()
    entry = {"router_id": None, "client_ref": REF, "point": {}, "rows": []}
    refs = [evidence_ref_of(KEY, f"tac_{n:016x}") for n in range(MAX_EVIDENCE + 7)]
    for ref in refs:
        book.add(ref, entry)
    assert len(book) == MAX_EVIDENCE
    assert book.counters["evidence_dropped"] == 7
    assert book.resolve(refs[0]) is None and book.counters["resolve_unknown"] == 1
    assert book.resolve(refs[-1]) is not None
    assert book.resolve("evr_nothex") is None and book.counters["resolve_invalid"] == 1
    with pytest.raises(ValueError):
        book.add("bad", entry)
    assert book.drop_client(REF) == MAX_EVIDENCE
    assert len(book) == 0


def test_evidence_export_restore_round_trip_and_validation() -> None:
    ind = SecurityIndicators(MagicMock())
    ind.evaluate([candidate()], client_source(), now=NOW, key=KEY)
    exported = ind.evidence.export()
    json.dumps(exported)  # JSON-safe
    fresh = EvidenceBook()
    bad = [
        {"evidence_ref": "nope"},
        {**exported[0], "evidence_ref": evidence_ref_of(KEY, "x"), "rows": "x"},
        {**exported[0], "evidence_ref": evidence_ref_of(KEY, "y"), "router_id": "a"},
        "not a dict",
    ]
    assert fresh.restore([*exported, *bad]) == 1
    assert fresh.counters["evidence_invalid_on_load"] == 4
    ref = exported[0]["evidence_ref"]
    assert fresh.resolve(ref) == ind.evidence.resolve(ref)


# --- read API (acceptance criterion 11) and engine wiring ------------------------------------------


def feed(engine: TrafficEngine, point: MeasurementPoint) -> None:
    for i in range(12):
        engine.series.add_rate(
            Rate(
                point,
                Quality.OK,
                interval_s=300,
                rx_bps=8000.0,
                tx_bps=800.0,
                rx_delta=300_000,
                tx_delta=30_000,
                wall_s=NOW - 3600 + 300 * (i + 1),
            )
        )


async def test_read_api_off_says_so() -> None:
    hass = make_hass()
    engine = TrafficEngine(hass)
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    api = async_get_traffic_read_api(hass)
    assert api is engine.read_api and api.version == READ_API_VERSION
    assert api.status() == {"v": 1, "state": "off", "reason": REASON_DISABLED}
    assert api.points() == [] and api.latest(RID) == []
    assert api.window(WAN.point_id)["reason"] == REASON_DISABLED
    assert api.congestion()["state"] == "unavailable"
    assert api.evidence(evidence_ref_of(KEY, "x")) is None
    hass.bus.async_listen.assert_not_called()
    assert async_get_traffic_read_api(make_hass()) is None


async def test_read_api_window_and_incident_listener() -> None:
    hass = make_hass()
    engine = TrafficEngine(hass)
    engine.wall = lambda: NOW
    hass.data[DATA_TRAFFIC_ANALYTICS] = engine
    await engine.async_activate()
    hass.bus.async_listen.assert_called_once()
    assert hass.bus.async_listen.call_args.args[0] == EVENT_INCIDENT
    assert engine.correlator.ni_listening
    feed(engine, WAN)
    api = engine.read_api
    assert api.status()["state"] == "not_ready"  # no core in this test
    out = api.window(WAN.point_id, "1h")
    assert out["state"] == "available" and out["v"] == 1
    assert out["rx_bytes"] == 12 * 300_000 and out["download"] == "rx"
    assert out["avg_rx_bps"] == pytest.approx(8000.0)
    assert out["time_coverage"] == 1.0
    assert set(out) >= {"router_id", "point_id", "coverage", "reasons", "resolution_s"}
    assert api.window(WAN.point_id, "2h")["reason"] == REASON_UNKNOWN_WINDOW
    assert api.window(PORT.point_id)["reason"] == REASON_UNKNOWN_POINT
    assert api.window("garbage")["reason"] == REASON_UNKNOWN_POINT
    router = api.router_window(RID, "24h")
    assert router["points"] == 1 and router["wan"][0]["rx_bytes"] == 12 * 300_000
    assert [p["point_id"] for p in api.points(RID)] == [WAN.point_id]
    report = api.congestion(RID)
    assert report["v"] == 1 and report["verdict"] in (
        VERDICT_NOTHING_IN_COVERED,
        VERDICT_INSUFFICIENT,
    )
    # An NI event reaches the correlator through the engine's callback.
    engine.router_id_of = {"entry-1": RID}.get
    callback = hass.bus.async_listen.call_args.args[1]
    callback(
        SimpleNamespace(
            data={
                "state": "opened",
                "incident_id": "inc_1",
                "type": "wan_down",
                "entry_ids": ["entry-1"],
            }
        )
    )
    assert engine.correlator.summary()["ni_notes"] == 1
    text = json.dumps(engine.summary())
    assert "correlation" in text and "indicators" in text
    unsub = hass.bus.async_listen.return_value
    await engine.async_deactivate()
    unsub.assert_called_once()
    assert not engine.correlator.ni_listening
    assert engine.correlator.summary()["ni_notes"] == 0
    assert api.status()["state"] == "off"


async def test_engine_looks_up_optional_modules_at_run_time() -> None:
    hass = make_hass()
    engine = TrafficEngine(hass)
    engine.wall = lambda: NOW
    await engine.async_activate()
    states = {s.module: s.state for s in engine.congestion().sources}
    assert states[SRC_DIAG] == SOURCE_MODULE_MISSING
    assert states[SRC_WIFI_RF] == SOURCE_MODULE_MISSING
    hass.data[DIAG_DATA_KEY] = FakeDiagnostics({"state": "off"})
    hass.data[WIFI_RF_DATA_KEY] = FakeRf({})
    feed(engine, WAN)
    states = {s.module: (s.state, s.reason) for s in engine.congestion().sources}
    assert states[SRC_DIAG] == (SOURCE_NOT_READY, REASON_MODULE_DISABLED)
    assert states[SRC_WIFI_RF] == (SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES)
    await engine.async_shutdown()
