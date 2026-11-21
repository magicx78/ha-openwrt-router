"""Tests for the RF health score and monitoring coverage (rf_health.py)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.rf_conflicts import (
    Conflict,
    ConflictKind,
    ConflictStatus,
    RadioRef,
    Severity,
)
from custom_components.openwrt_router.rf_health import (
    BASIS_MEASURED,
    BASIS_PLAN,
    WEIGHTS,
    ComponentScore,
    HealthItem,
    HealthThresholds,
    ap_health,
    component_from_metric,
    item_from,
    monitoring_coverage,
    network_health,
    overlap_component,
    radio_health,
    score_retry_rate,
    score_utilization,
)
from custom_components.openwrt_router.rf_models import (
    METRIC_NOISE,
    SOURCE_HOSTAPD_STATUS,
    CapabilityState,
    RadioCapabilities,
    metric_measured,
    metric_missing,
)

C = CapabilityState
TH = HealthThresholds()


def _c(name, score, state=C.MEASURED):
    if state is not C.MEASURED:
        score = None
    return ComponentScore(name, score, state, (f"test:{name}",))


def _all(score):
    return [_c(name, score) for name in WEIGHTS]


class TestWeights:
    def test_weights_sum_to_one(self):
        assert sum(WEIGHTS.values()) == pytest.approx(1.0)

    def test_weights_are_documented_in_module_docstring(self):
        from custom_components.openwrt_router import rf_health

        for name, weight in WEIGHTS.items():
            assert name in rf_health.__doc__
            assert f"{weight:.2f}" in rf_health.__doc__


class TestComponentScore:
    def test_measured_needs_score(self):
        with pytest.raises(ValueError):
            ComponentScore("signal", None, C.MEASURED, ())

    def test_unmeasured_must_not_carry_score(self):
        for state in (C.NO_DATA, C.UNSUPPORTED, C.UNREACHABLE, C.STALE):
            with pytest.raises(ValueError):
                ComponentScore("signal", 50.0, state, ())

    def test_score_range_and_name(self):
        with pytest.raises(ValueError):
            ComponentScore("signal", 120.0, C.MEASURED, ())
        with pytest.raises(ValueError):
            ComponentScore("unknown_part", 50.0, C.MEASURED, ())


class TestRadioHealth:
    def test_case_21_rf_health_score_all_measured(self):
        h = radio_health(_all(100.0), TH)
        assert h.score == 100
        assert h.coverage == pytest.approx(1.0)
        assert h.grade == "excellent"
        assert h.capped is False

    def test_case_21_weighted_mean(self):
        comps = _all(100.0)
        comps[0] = _c("utilization", 0.0)  # weight 0.20
        assert radio_health(comps, TH).score == 80

    def test_rule_unmeasured_do_not_count_as_100_and_lower_coverage(self):
        measured = {"utilization", "retries", "signal", "overlap", "stability"}
        comps = [
            _c(name, 50.0) if name in measured else _c(name, None, C.UNSUPPORTED)
            for name in WEIGHTS
        ]
        h = radio_health(comps, TH)
        assert h.score == 50  # not 65 as with missing = 100
        assert h.coverage == pytest.approx(0.70)

    @pytest.mark.parametrize(
        "state", [C.UNSUPPORTED, C.UNREACHABLE, C.NO_DATA, C.STALE]
    )
    def test_rule_every_unmeasured_state_is_left_out(self, state):
        comps = _all(60.0)
        comps[0] = _c("utilization", None, state)
        h = radio_health(comps, TH)
        assert h.score == 60
        assert h.coverage == pytest.approx(0.80)

    def test_case_25_missing_components_are_no_data(self):
        h = radio_health([_c("utilization", 90.0), _c("signal", 90.0)], TH)
        by = {c.name: c for c in h.components}
        assert by["airtime"].state is C.NO_DATA
        assert by["airtime"].score is None
        assert len(h.components) == len(WEIGHTS)

    def test_case_25_below_min_coverage_no_score(self):
        h = radio_health([_c("overlap", 100.0)], TH)
        assert h.score is None
        assert h.grade == "unknown"
        assert h.coverage == pytest.approx(0.10)
        assert "coverage_below_minimum" in h.evidence

    def test_case_21_little_measured_is_never_excellent(self):
        comps = [_c(n, 100.0) for n in ("utilization", "retries", "signal", "overlap")]
        h = radio_health(comps, TH)  # coverage 0.60
        assert h.score == TH.score_cap
        assert h.capped is True
        assert h.grade != "excellent"

    def test_cap_only_below_cap_coverage(self):
        comps = _all(100.0)
        comps[1] = _c("airtime", None, C.UNSUPPORTED)  # coverage 0.90
        h = radio_health(comps, TH)
        assert h.score == 100
        assert h.capped is False

    def test_duplicate_component_rejected(self):
        with pytest.raises(ValueError):
            radio_health([_c("signal", 1.0), _c("signal", 2.0)], TH)

    def test_as_dict(self):
        d = radio_health(_all(70.0), TH).as_dict()
        assert d["score"] == 70
        assert d["grade"] == "fair"
        assert [c["name"] for c in d["components"]] == list(WEIGHTS)


class TestScorers:
    def test_utilization(self):
        assert score_utilization(10.0) == 100.0
        assert score_utilization(100.0) == 0.0
        assert 0 < score_utilization(60.0) < 100

    def test_retry(self):
        assert score_retry_rate(0.01) == 100.0
        assert score_retry_rate(0.6) == 0.0

    def test_case_25_component_from_missing_metric(self):
        gone = metric_missing(C.UNREACHABLE, SOURCE_HOSTAPD_STATUS)
        c = component_from_metric("utilization", gone, score_utilization)
        assert c.state is C.UNREACHABLE
        assert c.score is None
        c = component_from_metric("utilization", None, score_utilization)
        assert c.state is C.NO_DATA

    def test_component_from_measured_metric(self):
        m = metric_measured(20.0, SOURCE_HOSTAPD_STATUS, measured_at=1.0)
        c = component_from_metric("utilization", m, score_utilization)
        assert c.state is C.MEASURED
        assert c.score == 100.0
        assert "utilization:20:hostapd.get_status" in c.evidence

    def test_overlap_component(self):
        ref = RadioRef("ap1", "radio0")
        other = RadioRef("ap2", "radio0")

        def conflict(status):
            return Conflict(
                ConflictKind.CO_CHANNEL, "2.4g", (ref, other), status, Severity.INFO, ()
            )

        # Review L1: an empty list is plan basis, not a measured 100.
        empty = overlap_component(ref, [])
        assert empty.state is C.NO_DATA
        assert empty.basis == BASIS_PLAN
        assert empty.score == 100.0
        acceptable = overlap_component(ref, [conflict(ConflictStatus.ACCEPTABLE)])
        assert acceptable.score == 100.0
        assert acceptable.state is C.MEASURED
        potential = overlap_component(ref, [conflict(ConflictStatus.POTENTIAL)])
        assert potential.basis == BASIS_PLAN
        measured = overlap_component(
            ref, [conflict(ConflictStatus.POTENTIAL), conflict(ConflictStatus.MEASURED)]
        )
        assert measured.state is C.MEASURED
        assert measured.score < potential.score < 100.0


class TestReviewH2PlanBasis:
    REF = RadioRef("ap1", "radio0")
    OTHER = RadioRef("ap2", "radio0")

    def _three_measured(self):
        # utilization 0.20 + signal 0.15 + client_quality 0.10 = 0.45 < 0.5
        return [
            _c("utilization", 100.0),
            _c("signal", 100.0),
            _c("client_quality", 100.0),
        ]

    def _conflict(self, status):
        return Conflict(
            ConflictKind.CO_CHANNEL,
            "2.4g",
            (self.REF, self.OTHER),
            status,
            Severity.INFO,
            (),
        )

    def test_review_h2_plan_overlap_does_not_lift_coverage(self):
        ov = overlap_component(self.REF, [])
        h = radio_health([*self._three_measured(), ov], TH)
        assert h.coverage == pytest.approx(0.45)
        assert h.score is None
        assert "plan_basis:overlap" in h.evidence

    def test_review_h2_potential_only_is_plan_basis(self):
        ov = overlap_component(self.REF, [self._conflict(ConflictStatus.POTENTIAL)])
        assert ov.state is C.NO_DATA
        assert ov.basis == BASIS_PLAN
        h = radio_health([*self._three_measured(), ov], TH)
        assert h.coverage == pytest.approx(0.45)

    def test_review_h2_plan_penalty_still_lowers_the_score(self):
        base = [*_all(100.0)]
        base = [c for c in base if c.name != "overlap"]
        ov = overlap_component(
            self.REF,
            [self._conflict(ConflictStatus.POTENTIAL)] * 3,
        )
        without = radio_health(base, TH)
        with_plan = radio_health([*base, ov], TH)
        assert with_plan.coverage == without.coverage == pytest.approx(0.9)
        assert with_plan.score < without.score

    def test_review_h2_plan_never_raises_the_score(self):
        base = [_c(name, 60.0) for name in WEIGHTS if name != "overlap"]
        ov = overlap_component(self.REF, [])
        assert radio_health([*base, ov], TH).score == radio_health(base, TH).score

    def test_review_h2_measured_conflict_makes_overlap_measured(self):
        ov = overlap_component(self.REF, [self._conflict(ConflictStatus.MEASURED)])
        assert ov.state is C.MEASURED
        assert ov.basis == BASIS_MEASURED
        h = radio_health([*self._three_measured(), ov], TH)
        assert h.coverage == pytest.approx(0.55)

    def test_review_h2_plan_component_dict_names_basis(self):
        assert overlap_component(self.REF, []).as_dict()["basis"] == BASIS_PLAN

    def test_review_h2_documented(self):
        from custom_components.openwrt_router import rf_health

        assert "plan" in rf_health.__doc__


class TestAggregation:
    def test_unscored_radio_lowers_coverage_not_score(self):
        ap = ap_health(
            [
                HealthItem("r0", 70, 1.0, 10),
                HealthItem("r1", None, 0.2, 10),
            ],
            TH,
        )
        assert ap.score == 70
        assert ap.coverage == pytest.approx(0.5)
        assert "unscored:r1" in ap.evidence

    def test_weighted_by_clients_min_weight_one(self):
        ap = ap_health([HealthItem("r0", 90, 1.0, 9), HealthItem("r1", 50, 1.0, 0)], TH)
        assert ap.score == 86  # (90*9 + 50*1) / 10
        assert ap.worst_member_id == "r1"
        assert ap.worst_score == 50

    def test_unknown_clients_weight_one(self):
        ap = ap_health(
            [HealthItem("r0", 90, 1.0, None), HealthItem("r1", 50, 1.0, None)], TH
        )
        assert ap.score == 70

    def test_low_coverage_caps_aggregate(self):
        ap = ap_health(
            [HealthItem("r0", 100, 1.0, 1), HealthItem("r1", None, 0.0, 1)], TH
        )
        assert ap.score == TH.score_cap
        assert ap.capped is True

    def test_case_25_nothing_scored(self):
        ap = ap_health([HealthItem("r0", None, 0.3, 5)], TH)
        assert ap.score is None
        assert ap.grade == "unknown"
        assert ap.worst_member_id is None

    def test_network_from_aps(self):
        r = radio_health(_all(80.0), TH)
        ap1 = ap_health([item_from("r0", r, 4)], TH)
        ap2 = ap_health([HealthItem("r0", 40, 1.0, 4)], TH)
        net = network_health([item_from("ap1", ap1, 4), item_from("ap2", ap2, 4)], TH)
        assert net.score == 60
        assert net.worst_member_id == "ap2"


class TestMonitoringCoverage:
    def test_mean_of_radio_coverages(self):
        full = RadioCapabilities("ap1", "radio0", {METRIC_NOISE: C.MEASURED})
        none = RadioCapabilities("ap1", "radio1", {})
        expected = (full.coverage() + none.coverage()) / 2
        assert monitoring_coverage([full, none]) == pytest.approx(expected)

    def test_case_25_no_radios(self):
        assert monitoring_coverage([]) == 0.0
