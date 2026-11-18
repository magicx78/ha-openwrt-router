"""Tests for roaming quality and sticky suspicion (rf_roaming.py, pure)."""

from __future__ import annotations

import itertools

import pytest

from custom_components.openwrt_router.rf_conflicts import RadioRef
from custom_components.openwrt_router.rf_models import (
    CapabilityState,
    metric_measured,
    metric_missing,
)
from custom_components.openwrt_router.rf_roaming import (
    WEIGHTS,
    AlternativeAp,
    ClientRoamWindow,
    FlapKind,
    RoamEvent,
    RoamQuality,
    RoamStatus,
    RoamThresholds,
    StickyInput,
    StickyStatus,
    StickyThresholds,
    assess_sticky,
    classify_roam,
    detect_flapping,
    roaming_quality,
)

TH = RoamThresholds()
STH = StickyThresholds()
A = RadioRef("ap1", "radio1")
B = RadioRef("ap2", "radio1")
A24 = RadioRef("ap1", "radio0")
SRC = "usteer"


def _ev(ts, frm=A, to=B, before=-75.0, after=-60.0, gap=0.3, **kw):
    base = {
        "client_key": "c1",
        "ts": ts,
        "from_radio": frm,
        "to_radio": to,
        "from_band": "5g",
        "to_band": "5g",
        "rssi_before": before,
        "rssi_after": after,
        "gap_s": gap,
        "auth_failures": 0,
        "reauth": False,
    }
    base.update(kw)
    return RoamEvent(**base)


def _ping_pong(n, step_s, start=0.0):
    out = []
    for i in range(n):
        frm, to = (A, B) if i % 2 == 0 else (B, A)
        out.append(_ev(start + i * step_s, frm, to))
    return out


def _window(events, online_s=8 * 3600.0, mobility="mobile"):
    return ClientRoamWindow(
        client_key="c1",
        window_s=24 * 3600.0,
        online_s=online_s,
        events=tuple(events),
        mobility=mobility,
    )


# =====================================================================
# Single roam
# =====================================================================


class TestClassifyRoam:
    def test_improved(self):
        r = classify_roam(_ev(0, before=-78, after=-60), TH)
        assert r.quality is RoamQuality.IMPROVED
        assert r.delta_db == pytest.approx(18.0)
        assert r.long_gap is False
        assert r.band_change is False
        assert r.same_router_band_switch is False

    def test_degraded_and_neutral(self):
        assert classify_roam(_ev(0, before=-60, after=-72), TH).quality is (
            RoamQuality.DEGRADED
        )
        assert classify_roam(_ev(0, before=-60, after=-62), TH).quality is (
            RoamQuality.NEUTRAL
        )

    def test_case_25_missing_rssi_is_unknown(self):
        r = classify_roam(_ev(0, before=None), TH)
        assert r.quality is RoamQuality.UNKNOWN
        assert r.delta_db is None
        r = classify_roam(_ev(0, after=None, gap=None, from_band=None), TH)
        assert r.quality is RoamQuality.UNKNOWN
        assert r.long_gap is None
        assert r.band_change is None

    def test_flags(self):
        r = classify_roam(_ev(0, A, A24, gap=8.0, to_band="2.4g"), TH)
        assert r.long_gap is True
        assert r.band_change is True
        assert r.same_router_band_switch is True
        assert "same_router_band_switch:ap1" in r.evidence


# =====================================================================
# Flapping
# =====================================================================


class TestFlapping:
    def test_case_11_normal_roaming_is_not_flapping(self):
        events = [
            _ev(0, A, B),
            _ev(3600, B, A),
            _ev(7200, A, B),
        ]
        assert detect_flapping(events, TH) == []

    def test_case_11_slow_back_and_forth_is_not_flapping(self):
        assert detect_flapping(_ping_pong(8, 900.0), TH) == []

    def test_case_12_roaming_flapping(self):
        flaps = detect_flapping(_ping_pong(5, 60.0), TH)
        (f,) = flaps
        assert f.kind is FlapKind.PING_PONG
        assert f.pair == (A, B)
        assert f.switches == 5
        assert (f.start, f.end) == (0.0, 240.0)
        assert "switches:5/600s" in f.evidence

    def test_case_12_flapping_even_if_each_roam_improves(self):
        events = [
            _ev(i * 30.0, *((A, B) if i % 2 == 0 else (B, A)), before=-80, after=-60)
            for i in range(4)
        ]
        assert [f.kind for f in detect_flapping(events, TH)] == [FlapKind.PING_PONG]

    def test_case_12_band_flapping_same_router(self):
        events = [
            _ev(0, A, A24, from_band="5g", to_band="2.4g"),
            _ev(120, A24, A, from_band="2.4g", to_band="5g"),
        ]
        (f,) = detect_flapping(events, TH)
        assert f.kind is FlapKind.BAND_FLAPPING
        assert f.pair == (A24, A)
        assert "router:ap1" in f.evidence

    def test_three_radios_round_trip_is_not_ping_pong(self):
        c = RadioRef("ap3", "radio1")
        events = [_ev(0, A, B), _ev(60, B, c), _ev(120, c, A), _ev(180, A, B)]
        assert detect_flapping(events, TH) == []

    def test_clients_are_separated(self):
        events = [
            _ev(i * 60.0, *((A, B) if i % 2 == 0 else (B, A)), client_key=f"c{i % 2}")
            for i in range(6)
        ]
        assert detect_flapping(events, TH) == []

    def test_thresholds_are_parameters(self):
        th = RoamThresholds(flap_min_switches=6)
        assert detect_flapping(_ping_pong(5, 60.0), th) == []


# =====================================================================
# Roaming quality
# =====================================================================


class TestRoamingQuality:
    def test_weights_sum_to_one(self):
        assert sum(WEIGHTS.values()) == pytest.approx(1.0)

    def test_case_11_normal_roaming_scores_high(self):
        events = [_ev(0, A, B), _ev(3600, B, A), _ev(7200, A, B)]
        r = roaming_quality(_window(events), TH)
        assert r.status is RoamStatus.SCORED
        assert r.score == pytest.approx(100.0)
        assert r.coverage == pytest.approx(1.0)

    def test_case_12_flapping_lowers_score(self):
        r = roaming_quality(_window(_ping_pong(6, 60.0), online_s=3600.0), TH)
        assert r.status is RoamStatus.SCORED
        assert r.score < 70
        parts = {p.name: p for p in r.parts}
        assert parts["continuity"].score == pytest.approx(0.0)
        assert parts["frequency"].score < 100

    def test_stationary_without_roams_is_not_applicable(self):
        r = roaming_quality(_window([], mobility="stationary"), TH)
        assert r.status is RoamStatus.NOT_APPLICABLE
        assert r.score is None
        assert "no_roams:stationary" in r.evidence

    def test_no_roams_is_never_a_score(self):
        for mobility in ("mobile", None):
            r = roaming_quality(_window([], mobility=mobility), TH)
            assert r.status is RoamStatus.NOT_APPLICABLE
            assert r.score is None

    def test_case_25_too_few_events(self):
        r = roaming_quality(_window([_ev(0)]), TH)
        assert r.status is RoamStatus.INSUFFICIENT
        assert r.score is None

    def test_case_25_missing_parts_lower_coverage_not_score(self):
        events = [_ev(i * 3600.0, before=None, gap=None) for i in range(3)]
        r = roaming_quality(_window(events), TH)
        assert r.coverage == pytest.approx(0.5)
        assert r.status is RoamStatus.INSUFFICIENT
        assert r.score is None
        parts = {p.name: p for p in r.parts}
        assert parts["signal"].score is None
        assert parts["gap"].score is None

    def test_missing_part_is_renormalized_not_counted_full(self):
        events = [
            _ev(0, before=None, gap=5.0 + 1),
            _ev(3600, B, A, before=None, gap=0.2),
            _ev(7200, before=None, gap=0.2),
        ]
        r = roaming_quality(_window(events), TH)
        assert r.coverage == pytest.approx(0.75)
        # gap part 66.7 (1 of 3 long), others 100; signal missing
        expected = (0.25 * (200 / 3) + 0.20 * 100 + 0.15 * 100 + 0.15 * 100) / 0.75
        assert r.score == pytest.approx(expected, abs=0.1)

    def test_auth_failures_and_degraded_roams(self):
        events = [
            _ev(0, auth_failures=2),
            _ev(3600, B, A, before=-60, after=-75),
            _ev(7200),
        ]
        parts = {p.name: p for p in roaming_quality(_window(events), TH).parts}
        assert parts["auth"].score == pytest.approx(100 * 2 / 3)
        assert parts["signal"].score == pytest.approx(100 * 2 / 3)


# =====================================================================
# Sticky
# =====================================================================


def _rssi(value, state=CapabilityState.MEASURED):
    if state is CapabilityState.MEASURED:
        return metric_measured(value, SRC, measured_at=1.0)
    return metric_missing(state, SRC)


def _sticky(alternatives=(), *, rssi=-80.0, dwell=1800.0, weak=0.8, mobility=None):
    return StickyInput(
        client_key="c1",
        current_radio=A,
        current_rssi=_rssi(rssi),
        dwell_s=dwell,
        weak_share=weak,
        alternatives=tuple(alternatives),
        mobility=mobility,
    )


def _alt(radio, rssi, basis, age=60.0):
    return AlternativeAp(radio=radio, rssi=_rssi(rssi), basis=basis, age_s=age)


class TestSticky:
    def test_status_has_no_confirmed(self):
        assert "confirmed" not in {s.value for s in StickyStatus}

    def test_case_13_sticky_suspected_from_history(self):
        s = assess_sticky(_sticky([_alt(B, -65.0, "historic_same_client")]), STH)
        assert s.status is StickyStatus.SUSPECTED
        assert s.better_radio is None
        assert "historic_better:ap2/radio1:15dB" in s.evidence
        assert s.radio == A

    def test_case_13_sticky_supported_by_measurement(self):
        s = assess_sticky(_sticky([_alt(B, -62.0, "measured_same_client")]), STH)
        assert s.status is StickyStatus.SUPPORTED_BY_MEASUREMENT
        assert s.better_radio == B
        assert s.delta_db == pytest.approx(18.0)
        assert "measured_better:ap2/radio1:18dB:age60s" in s.evidence

    def test_case_13_no_measurement_mobile_is_suspected(self):
        s = assess_sticky(_sticky(mobility="mobile"), STH)
        assert s.status is StickyStatus.SUSPECTED
        assert "no_comparable_measurement" in s.evidence
        assert s.better_radio is None

    def test_no_measurement_stationary_is_none(self):
        s = assess_sticky(_sticky(mobility="stationary"), STH)
        assert s.status is StickyStatus.NONE

    def test_stale_measurement_does_not_support(self):
        s = assess_sticky(
            _sticky(
                [_alt(B, -55.0, "measured_same_client", age=900.0)], mobility="mobile"
            ),
            STH,
        )
        assert s.status is StickyStatus.SUSPECTED
        assert s.better_radio is None
        assert "no_comparable_measurement" in s.evidence

    def test_fresh_measurement_without_better_ap_is_none(self):
        s = assess_sticky(
            _sticky([_alt(B, -78.0, "measured_same_client")], mobility="mobile"),
            STH,
        )
        assert s.status is StickyStatus.NONE
        assert "no_better_alternative_measured" in s.evidence

    @pytest.mark.parametrize(
        ("basis", "mobility", "age"),
        list(
            itertools.product(
                ["historic_same_client", "none"],
                ["mobile", "stationary", None],
                [0.0, 10.0, 10_000.0],
            )
        ),
    )
    def test_rule_never_supported_without_comparable_measurement(
        self, basis, mobility, age
    ):
        s = assess_sticky(
            _sticky([_alt(B, -40.0, basis, age=age)], rssi=-90.0, mobility=mobility),
            STH,
        )
        assert s.status is not StickyStatus.SUPPORTED_BY_MEASUREMENT
        assert s.better_radio is None

    def test_better_radio_only_with_measured_basis(self):
        for alts in (
            [_alt(B, -50.0, "historic_same_client")],
            [_alt(B, -50.0, "none")],
            [],
        ):
            assert (
                assess_sticky(_sticky(alts, mobility="mobile"), STH).better_radio
                is None
            )

    def test_short_dwell_or_low_weak_share_is_none(self):
        alt = [_alt(B, -60.0, "measured_same_client")]
        assert assess_sticky(_sticky(alt, dwell=60.0), STH).status is StickyStatus.NONE
        assert assess_sticky(_sticky(alt, weak=0.1), STH).status is StickyStatus.NONE
        assert assess_sticky(_sticky(alt, rssi=-60.0), STH).status is StickyStatus.NONE

    def test_case_25_unknown_inputs(self):
        alt = [_alt(B, -60.0, "measured_same_client")]
        missing = StickyInput(
            client_key="c1",
            current_radio=A,
            current_rssi=_rssi(None, CapabilityState.NO_DATA),
            dwell_s=1800.0,
            weak_share=0.8,
            alternatives=tuple(alt),
        )
        s = assess_sticky(missing, STH)
        assert s.status is StickyStatus.UNKNOWN
        assert s.better_radio is None
        s = assess_sticky(_sticky(alt, weak=None), STH)
        assert s.status is StickyStatus.UNKNOWN
        assert "weak_share_unknown" in s.evidence

    def test_alternative_equal_to_current_is_ignored(self):
        s = assess_sticky(_sticky([_alt(A, -50.0, "measured_same_client")]), STH)
        assert s.status is not StickyStatus.SUPPORTED_BY_MEASUREMENT

    def test_confidence_order(self):
        supported = assess_sticky(
            _sticky([_alt(B, -60.0, "measured_same_client")]), STH
        )
        historic = assess_sticky(_sticky([_alt(B, -60.0, "historic_same_client")]), STH)
        nothing = assess_sticky(_sticky(mobility="mobile"), STH)
        assert supported.confidence > historic.confidence > nothing.confidence > 0

    def test_as_dict(self):
        s = assess_sticky(_sticky([_alt(B, -62.0, "measured_same_client")]), STH)
        d = s.as_dict()
        assert d["status"] == "supported_by_measurement"
        assert d["better_radio"] == {"router_key": "ap2", "radio_key": "radio1"}
