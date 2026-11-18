"""Tests for the RF capability model (rf_models.py, pure, no HA)."""

from __future__ import annotations

import math

import pytest

from custom_components.openwrt_router.rf_models import (
    ALL_METRICS,
    METRIC_BUSY_TIME,
    METRIC_CHANNEL,
    METRIC_NOISE,
    METRIC_RETRIES,
    METRIC_SCAN,
    METRIC_UTILIZATION,
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_INFO,
    SOURCE_IWINFO_SURVEY,
    CapabilityState,
    Metric,
    RadioCapabilities,
    classify,
    metric_measured,
    metric_missing,
    with_staleness,
)

M = CapabilityState


# =====================================================================
# Metric invariant
# =====================================================================


class TestMetric:
    def test_measured_carries_value_and_source(self):
        metric = metric_measured(-92, SOURCE_IWINFO_INFO, measured_at=100.0)
        assert metric.value == -92
        assert metric.state is M.MEASURED
        assert metric.source == SOURCE_IWINFO_INFO
        assert metric.measured_at == 100.0
        assert metric.is_measured

    @pytest.mark.parametrize("value", [None, math.nan, True])
    def test_measured_rejects_missing_or_invented_values(self, value):
        with pytest.raises(ValueError):
            metric_measured(value, SOURCE_IWINFO_INFO, measured_at=1.0)

    @pytest.mark.parametrize("state", [M.NO_DATA, M.UNSUPPORTED, M.UNREACHABLE])
    def test_missing_has_no_value(self, state):
        metric = metric_missing(state, SOURCE_HOSTAPD_STATUS)
        assert metric.value is None
        assert metric.state is state
        assert not metric.is_measured

    @pytest.mark.parametrize("state", [M.MEASURED, M.STALE])
    def test_missing_rejects_states_that_need_a_value(self, state):
        with pytest.raises(ValueError):
            metric_missing(state, SOURCE_HOSTAPD_STATUS)

    def test_invariant_value_only_for_measured_and_stale(self):
        with pytest.raises(ValueError):
            Metric(value=5, state=M.NO_DATA, source="x", measured_at=None)
        with pytest.raises(ValueError):
            Metric(value=None, state=M.MEASURED, source="x", measured_at=1.0)
        with pytest.raises(ValueError):
            Metric(value=None, state=M.STALE, source="x", measured_at=1.0)

    def test_as_dict(self):
        metric = metric_measured(42.5, SOURCE_IWINFO_SURVEY, measured_at=10.0)
        assert metric.as_dict() == {
            "value": 42.5,
            "state": "measured",
            "source": "iwinfo.survey",
            "measured_at": 10.0,
        }


class TestWithStaleness:
    def test_fresh_metric_stays_measured(self):
        metric = metric_measured(1, "s", measured_at=100.0)
        assert with_staleness(metric, now=150.0, max_age_s=60).state is M.MEASURED

    def test_old_metric_becomes_stale_and_keeps_value(self):
        metric = metric_measured(1, "s", measured_at=100.0)
        stale = with_staleness(metric, now=161.0, max_age_s=60)
        assert stale.state is M.STALE
        assert stale.value == 1
        assert metric.state is M.MEASURED  # original untouched

    def test_unknown_age_is_stale(self):
        metric = metric_measured(1, "s", measured_at=None)
        assert with_staleness(metric, now=10.0, max_age_s=60).state is M.STALE

    def test_missing_metric_is_unchanged(self):
        metric = metric_missing(M.UNSUPPORTED, "s")
        assert with_staleness(metric, now=10.0, max_age_s=60) is metric


# =====================================================================
# classify: the five states
# =====================================================================


class TestClassify:
    def test_measured(self):
        assert (
            classify(
                present=True,
                value=-90,
                source_ok=True,
                supported=True,
                age_s=5,
                max_age_s=60,
            )
            is M.MEASURED
        )

    def test_no_data_when_supported_but_absent(self):
        assert (
            classify(
                present=False,
                value=None,
                source_ok=True,
                supported=True,
                age_s=None,
                max_age_s=60,
            )
            is M.NO_DATA
        )

    def test_present_key_with_none_value_is_no_data(self):
        assert (
            classify(
                present=True,
                value=None,
                source_ok=True,
                supported=True,
                age_s=1,
                max_age_s=60,
            )
            is M.NO_DATA
        )

    def test_unsupported_when_known_unsupported(self):
        assert (
            classify(
                present=False,
                value=None,
                source_ok=True,
                supported=False,
                age_s=None,
                max_age_s=60,
            )
            is M.UNSUPPORTED
        )

    def test_unreachable_source(self):
        assert (
            classify(
                present=False,
                value=None,
                source_ok=False,
                supported=True,
                age_s=None,
                max_age_s=60,
            )
            is M.UNREACHABLE
        )

    def test_unknown_support_and_unreachable_is_never_unsupported(self):
        state = classify(
            present=False,
            value=None,
            source_ok=False,
            supported=None,
            age_s=None,
            max_age_s=60,
        )
        assert state is M.UNREACHABLE

    def test_unknown_support_reachable_but_absent_is_no_data(self):
        state = classify(
            present=False,
            value=None,
            source_ok=True,
            supported=None,
            age_s=None,
            max_age_s=60,
        )
        assert state is M.NO_DATA

    def test_stale(self):
        assert (
            classify(
                present=True,
                value=-90,
                source_ok=True,
                supported=True,
                age_s=61,
                max_age_s=60,
            )
            is M.STALE
        )

    def test_unknown_age_with_limit_is_stale(self):
        assert (
            classify(
                present=True,
                value=-90,
                source_ok=True,
                supported=None,
                age_s=None,
                max_age_s=60,
            )
            is M.STALE
        )

    def test_no_age_limit_means_measured(self):
        assert (
            classify(
                present=True,
                value=-90,
                source_ok=True,
                supported=None,
                age_s=None,
                max_age_s=None,
            )
            is M.MEASURED
        )

    def test_nan_counts_as_absent(self):
        assert (
            classify(
                present=True,
                value=math.nan,
                source_ok=True,
                supported=True,
                age_s=1,
                max_age_s=60,
            )
            is M.NO_DATA
        )


# =====================================================================
# RadioCapabilities
# =====================================================================


class TestRadioCapabilities:
    def test_case_02_unsupported_radio_metrics_do_not_count_as_covered(self):
        """Case 2: a radio without survey/retries support has partial coverage."""
        states = dict.fromkeys(ALL_METRICS, M.MEASURED)
        states[METRIC_BUSY_TIME] = M.UNSUPPORTED
        states[METRIC_RETRIES] = M.UNSUPPORTED
        caps = RadioCapabilities("rtr", "radio0", states)
        assert caps.state(METRIC_BUSY_TIME) is M.UNSUPPORTED
        assert caps.coverage() == pytest.approx(
            (len(ALL_METRICS) - 2) / len(ALL_METRICS)
        )
        assert caps.as_dict()["states"][METRIC_RETRIES] == "unsupported"

    @pytest.mark.parametrize(
        "state", [M.UNSUPPORTED, M.UNREACHABLE, M.NO_DATA, M.STALE]
    )
    def test_only_measured_counts(self, state):
        caps = RadioCapabilities(
            "rtr", "r", {METRIC_CHANNEL: M.MEASURED, METRIC_NOISE: state}
        )
        # 2 of all metrics assessed, 1 measured
        assert caps.coverage() == pytest.approx(1 / len(ALL_METRICS))

    def test_not_assessed_metric_is_none_and_uncovered(self):
        caps = RadioCapabilities("rtr", "r", {})
        assert caps.state(METRIC_SCAN) is None
        assert caps.coverage() == 0.0
        assert caps.as_dict()["states"][METRIC_SCAN] is None

    def test_excluded_metrics_leave_the_denominator(self):
        states = {METRIC_CHANNEL: M.MEASURED, METRIC_UTILIZATION: M.MEASURED}
        excluded = frozenset(set(ALL_METRICS) - set(states))
        caps = RadioCapabilities("rtr", "r", states, excluded=excluded)
        assert caps.coverage() == 1.0

    def test_everything_excluded_gives_none(self):
        caps = RadioCapabilities("rtr", "r", {}, excluded=frozenset(ALL_METRICS))
        assert caps.coverage() is None

    def test_unknown_metric_name_is_rejected(self):
        with pytest.raises(ValueError):
            RadioCapabilities("rtr", "r", {"bogus": M.MEASURED})
        with pytest.raises(ValueError):
            RadioCapabilities("rtr", "r", {}, excluded=frozenset({"bogus"}))

    def test_states_are_read_only_copy(self):
        source = {METRIC_CHANNEL: M.MEASURED}
        caps = RadioCapabilities("rtr", "r", source)
        source[METRIC_CHANNEL] = M.UNSUPPORTED
        assert caps.state(METRIC_CHANNEL) is M.MEASURED
        with pytest.raises(TypeError):
            caps.states[METRIC_CHANNEL] = M.NO_DATA  # type: ignore[index]

    def test_as_dict_lists_every_metric(self):
        caps = RadioCapabilities("rtr", "r", {METRIC_CHANNEL: M.MEASURED})
        data = caps.as_dict()
        assert data["router_key"] == "rtr"
        assert data["radio_key"] == "r"
        assert list(data["states"]) == list(ALL_METRICS)
        assert data["excluded"] == []
        assert data["coverage"] == pytest.approx(1 / len(ALL_METRICS))

    def test_metric_names_are_the_agreed_set(self):
        assert ALL_METRICS == (
            "channel",
            "width",
            "txpower",
            "txpower_max",
            "noise",
            "busy_time",
            "active_time",
            "rx_time",
            "tx_time",
            "utilization",
            "client_airtime",
            "clients",
            "rssi",
            "rate",
            "retries",
            "failed",
            "connected_time",
            "freqlist",
            "country",
            "scan",
        )
