"""Tests for per-client signal and retry assessment (rf_clients.py, pure)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from custom_components.openwrt_router.rf_clients import (
    ClientRfWindow,
    ClientThresholds,
    FindingKind,
    assess_client,
    counter_delta,
    driver_family,
    failure_rate,
    retry_comparable,
    retry_rate,
    snr,
    summarize_radio_clients,
)
from custom_components.openwrt_router.rf_conflicts import RadioRef, Severity
from custom_components.openwrt_router.rf_models import (
    SOURCE_IWINFO_INFO,
    CapabilityState,
    metric_measured,
    metric_missing,
)

C = CapabilityState
F = FindingKind
TH = ClientThresholds()
RADIO = RadioRef("ap1", "radio1")


def _win(**kw):
    base = {
        "client_key": "c1",
        "radio": RADIO,
        "band": "5g",
        "driver": "mt7915e",
        "window_s": 3600.0,
        "rssi_mean": -60.0,
        "rssi_min": -66.0,
        "rssi_stddev": 2.0,
        "weak_share": 0.0,
        "noise": None,
        "rate_tx_mean": 200_000.0,
        "rate_tx_trend": 0.0,
        "tx_packets": 10_000,
        "tx_retries": 500,
        "tx_failed": 600,
        "disconnects": 0,
        "disconnects_weak": 0,
        "mobility": "mobile",
        "demand": "high",
        "samples": 60,
    }
    base.update(kw)
    return ClientRfWindow(**base)


def _kinds(assessment):
    return {f.kind for f in assessment.findings}


def _finding(assessment, kind):
    (f,) = [f for f in assessment.findings if f.kind is kind]
    return f


# =====================================================================
# Counters and rates
# =====================================================================


class TestCounters:
    def test_delta(self):
        assert counter_delta(100, 150) == 50
        assert counter_delta(100, 100) == 0

    def test_smaller_counter_is_unknown(self):
        assert counter_delta(150, 100) is None  # reconnect or reset

    def test_missing_counter_is_unknown(self):
        assert counter_delta(None, 100) is None
        assert counter_delta(100, None) is None

    def test_case_10_retry_rate(self):
        m = retry_rate(300, 1000, min_packets=100)
        assert m.state is C.MEASURED
        assert m.value == pytest.approx(0.3)

    def test_case_25_retry_rate_missing_counters(self):
        for retries, packets in ((None, 1000), (10, None), (None, None)):
            m = retry_rate(retries, packets, min_packets=100)
            assert m.state is C.NO_DATA
            assert m.value is None

    def test_case_25_too_few_packets_is_unknown_not_zero(self):
        m = retry_rate(0, 50, min_packets=100)
        assert m.state is C.NO_DATA
        assert m.value is None

    def test_negative_counters_are_unknown(self):
        assert retry_rate(-1, 1000, min_packets=1).state is C.NO_DATA

    def test_failure_rate(self):
        m = failure_rate(20, 1000, min_packets=100)
        assert m.value == pytest.approx(0.02)
        assert failure_rate(None, 1000, min_packets=100).state is C.NO_DATA


class TestSnr:
    def _noise(self, value):
        return metric_measured(value, SOURCE_IWINFO_INFO, measured_at=1.0)

    def test_snr(self):
        m = snr(-60.0, self._noise(-95))
        assert m.state is C.MEASURED
        assert m.value == pytest.approx(35.0)

    def test_case_25_noise_zero_is_unknown(self):
        # iwinfo reports noise 0 when the driver gave none
        assert snr(-60.0, self._noise(0)).state is C.NO_DATA

    def test_case_25_noise_missing_or_stale(self):
        assert snr(-60.0, None).state is C.NO_DATA
        gone = metric_missing(C.UNSUPPORTED, SOURCE_IWINFO_INFO)
        assert snr(-60.0, gone).state is C.UNSUPPORTED
        stale = replace(self._noise(-95), state=C.STALE)
        assert snr(-60.0, stale).state is C.NO_DATA
        assert snr(None, self._noise(-95)).state is C.NO_DATA


class TestDriverFamily:
    @pytest.mark.parametrize(
        ("driver", "family"),
        [
            ("mt7915e", "mt76"),
            ("mt76", "mt76"),
            ("ath10k-ct", "ath10k"),
            ("ath10k_pci", "ath10k"),
            ("ath9k", "ath9k"),
            (None, None),
            ("", None),
            # iwinfo's catch-all hardware name (fixtures/rf/iwinfo_info_ath9k.json)
            # names no driver family
            ("Generic MAC80211", None),
            ("brcmfmac", None),
        ],
    )
    def test_family(self, driver, family):
        assert driver_family(driver) == family

    def test_rule_no_retry_comparison_across_drivers(self):
        assert retry_comparable("mt7915e", "mt76") is True
        assert retry_comparable("mt7915e", "ath10k-ct") is False
        assert retry_comparable(None, "mt76") is False
        assert retry_comparable(None, None) is False
        # two unknown drivers are never comparable, even with the same name
        assert retry_comparable("Generic MAC80211", "Generic MAC80211") is False


# =====================================================================
# Assessment
# =====================================================================


class TestWeakSignal:
    def test_case_09_weak_client_signal_with_retries_is_warning(self):
        a = assess_client(_win(rssi_mean=-80.0, weak_share=0.8, tx_retries=4000), TH)
        f = _finding(a, F.WEAK_SIGNAL_PERSISTENT)
        assert f.severity is Severity.WARNING
        assert "weak_share:0.80:client_history" in f.evidence
        assert any(e.startswith("retry_rate:") for e in f.evidence)

    def test_case_09_weak_client_signal_mobile_high_demand_is_warning(self):
        a = assess_client(_win(rssi_mean=-75.0, weak_share=0.7), TH)
        f = _finding(a, F.WEAK_SIGNAL_PERSISTENT)
        assert f.severity is Severity.WARNING
        assert "context:mobile+high" in f.evidence

    def test_case_09_iot_at_minus_75_without_problems_no_finding(self):
        a = assess_client(
            _win(
                rssi_mean=-75.0,
                weak_share=0.7,
                mobility="stationary",
                demand="low",
            ),
            TH,
        )
        assert F.WEAK_SIGNAL_PERSISTENT not in _kinds(a)
        assert all(f.severity is Severity.INFO for f in a.findings)

    def test_case_09_iot_far_below_threshold_is_info_only(self):
        a = assess_client(
            _win(
                rssi_mean=-84.0,
                weak_share=1.0,
                mobility="stationary",
                demand="low",
            ),
            TH,
        )
        assert _finding(a, F.WEAK_SIGNAL_PERSISTENT).severity is Severity.INFO

    def test_case_09_unknown_context_middle_threshold_lower_confidence(self):
        known = assess_client(
            _win(rssi_mean=-77.0, weak_share=0.8, mobility="stationary", demand="low"),
            TH,
        )
        unknown = assess_client(
            _win(rssi_mean=-77.0, weak_share=0.8, mobility=None, demand=None), TH
        )
        assert F.WEAK_SIGNAL_PERSISTENT not in _kinds(known)  # -77 > -80
        f = _finding(unknown, F.WEAK_SIGNAL_PERSISTENT)  # -77 <= -75
        assert f.severity is Severity.INFO
        assert "context_unknown" in f.evidence
        sensitive = assess_client(_win(rssi_mean=-77.0, weak_share=0.8), TH)
        assert f.confidence < _finding(sensitive, F.WEAK_SIGNAL_PERSISTENT).confidence

    @pytest.mark.parametrize("mobility", ["mobile", "stationary", None])
    @pytest.mark.parametrize("demand", ["high", "low", None])
    def test_rule_rssi_alone_never_warning(self, mobility, demand):
        # Very weak mean, but no share over time, no retries, no rate, no
        # disconnect data: only the RSSI itself.
        a = assess_client(
            _win(
                rssi_mean=-88.0,
                rssi_min=-92.0,
                rssi_stddev=12.0,
                weak_share=None,
                rate_tx_mean=None,
                rate_tx_trend=None,
                tx_packets=None,
                tx_retries=None,
                tx_failed=None,
                disconnects=None,
                disconnects_weak=None,
                mobility=mobility,
                demand=demand,
            ),
            TH,
        )
        assert all(f.severity is Severity.INFO for f in a.findings)

    def test_rule_weak_share_alone_without_context_is_not_warning(self):
        a = assess_client(
            _win(rssi_mean=-82.0, weak_share=0.9, mobility="mobile", demand=None),
            TH,
        )
        assert _finding(a, F.WEAK_SIGNAL_PERSISTENT).severity is Severity.INFO

    def test_case_25_weak_share_unknown_no_persistent_finding(self):
        a = assess_client(_win(rssi_mean=-82.0, weak_share=None), TH)
        assert F.WEAK_SIGNAL_PERSISTENT not in _kinds(a)
        assert "weak_share" in a.missing


class TestOtherFindings:
    def test_rssi_unstable(self):
        a = assess_client(_win(rssi_stddev=9.0), TH)
        assert _finding(a, F.RSSI_UNSTABLE).severity is Severity.INFO

    def test_rate_declining(self):
        a = assess_client(_win(rate_tx_trend=-45.0), TH)
        f = _finding(a, F.RATE_DECLINING)
        assert "rate_tx_trend:-45.0%:client_history" in f.evidence

    def test_case_25_no_previous_window_no_rate_finding(self):
        a = assess_client(_win(rate_tx_trend=None), TH)
        assert F.RATE_DECLINING not in _kinds(a)
        assert "rate_tx_trend" in a.missing

    def test_case_10_retry_rate_high(self):
        a = assess_client(_win(tx_retries=4000), TH)
        f = _finding(a, F.RETRY_RATE_HIGH)
        assert f.severity is Severity.WARNING
        assert "retry_rate:0.400:iwinfo.assoclist" in f.evidence
        assert "driver_family:mt76" in f.evidence

    def test_case_10_retry_unknown_driver_lower_confidence(self):
        known = assess_client(_win(tx_retries=4000), TH)
        unknown = assess_client(_win(tx_retries=4000, driver=None), TH)
        fu = _finding(unknown, F.RETRY_RATE_HIGH)
        assert "driver_unknown" in fu.evidence
        assert fu.confidence < _finding(known, F.RETRY_RATE_HIGH).confidence

    def test_case_10_mt76_failed_counts_retries_and_is_not_extra_evidence(self):
        # mt76 counts retries in tx_failed: a high "failure" there is not an
        # independent finding.
        a = assess_client(_win(tx_retries=100, tx_failed=900), TH)
        assert F.RETRY_RATE_HIGH not in _kinds(a)
        assert F.POOR_LINK_DESPITE_SIGNAL not in _kinds(a)
        b = assess_client(_win(driver="ath10k-ct", tx_retries=100, tx_failed=900), TH)
        assert F.POOR_LINK_DESPITE_SIGNAL in _kinds(b)

    def test_case_25_retry_counters_missing(self):
        a = assess_client(_win(tx_retries=None, tx_failed=None), TH)
        assert F.RETRY_RATE_HIGH not in _kinds(a)
        assert a.retry_rate.state is C.NO_DATA
        assert "tx_retries" in a.missing

    def test_disconnects_at_weak_signal(self):
        a = assess_client(
            _win(rssi_mean=-79.0, weak_share=0.4, disconnects=3, disconnects_weak=3),
            TH,
        )
        f = _finding(a, F.DISCONNECTS_AT_WEAK_SIGNAL)
        assert f.severity is Severity.WARNING
        assert "disconnects_weak:3/3:client_history" in f.evidence

    def test_poor_link_despite_signal(self):
        a = assess_client(_win(rssi_mean=-55.0, tx_retries=4000), TH)
        f = _finding(a, F.POOR_LINK_DESPITE_SIGNAL)
        assert f.severity is Severity.WARNING
        assert "rssi_mean:-55.0dBm:client_history" in f.evidence

    def test_low_rate_despite_signal_is_info_and_ignored_for_low_demand(self):
        a = assess_client(_win(rssi_mean=-55.0, rate_tx_mean=6000.0), TH)
        assert _finding(a, F.POOR_LINK_DESPITE_SIGNAL).severity is Severity.INFO
        b = assess_client(_win(rssi_mean=-55.0, rate_tx_mean=6000.0, demand="low"), TH)
        assert F.POOR_LINK_DESPITE_SIGNAL not in _kinds(b)

    def test_healthy_client_has_no_findings(self):
        assert assess_client(_win(), TH).findings == ()

    def test_confidence_drops_with_few_samples(self):
        many = assess_client(_win(tx_retries=4000), TH)
        few = assess_client(_win(tx_retries=4000, samples=5), TH)
        assert (
            _finding(few, F.RETRY_RATE_HIGH).confidence
            < _finding(many, F.RETRY_RATE_HIGH).confidence
        )
        for f in few.findings:
            assert 0.0 <= f.confidence <= 1.0

    def test_case_25_no_samples_no_findings(self):
        a = assess_client(_win(samples=0, tx_retries=4000, rssi_mean=-85.0), TH)
        assert a.findings == ()
        assert "samples" in a.missing

    def test_snr_in_assessment(self):
        noise = metric_measured(-92, SOURCE_IWINFO_INFO, measured_at=1.0)
        a = assess_client(_win(noise=noise), TH)
        assert a.snr.value == pytest.approx(32.0)

    def test_as_dict(self):
        a = assess_client(_win(tx_retries=4000), TH)
        d = a.as_dict()
        assert d["radio"] == {"router_key": "ap1", "radio_key": "radio1"}
        assert d["findings"][0]["kind"] == "retry_rate_high"
        assert d["retry_rate"]["state"] == "measured"


# =====================================================================
# Radio summary
# =====================================================================


class TestSummary:
    def test_weighted_retry_rate_and_counts(self):
        a = assess_client(_win(client_key="a", tx_packets=1000, tx_retries=100), TH)
        b = assess_client(_win(client_key="b", tx_packets=9000, tx_retries=4500), TH)
        s = summarize_radio_clients([a, b])
        assert s.radio == RADIO
        assert s.client_count == 2
        assert s.retry_rate.value == pytest.approx(4600 / 10000)
        assert s.retry_coverage == 1.0
        assert s.problem_clients == 1

    def test_case_25_unknown_clients_do_not_count_as_zero(self):
        a = assess_client(_win(client_key="a", tx_packets=1000, tx_retries=500), TH)
        b = assess_client(
            _win(client_key="b", tx_packets=None, tx_retries=None, rssi_mean=None),
            TH,
        )
        s = summarize_radio_clients([a, b])
        assert s.retry_rate.value == pytest.approx(0.5)
        assert s.retry_coverage == 0.5
        assert s.signal_coverage == 0.5
        assert s.signal_quality_mean == pytest.approx(a.signal_quality)

    def test_case_25_no_measured_client(self):
        b = assess_client(_win(tx_packets=None, rssi_mean=None, weak_share=None), TH)
        s = summarize_radio_clients([b])
        assert s.retry_rate.state is C.NO_DATA
        assert s.signal_quality_mean is None
        assert s.retry_coverage == 0.0

    def test_rule_mixed_driver_families_give_no_retry_rate(self):
        a = assess_client(_win(client_key="a"), TH)
        b = assess_client(_win(client_key="b", driver="ath10k-ct"), TH)
        s = summarize_radio_clients([a, b])
        assert s.retry_rate.state is C.NO_DATA
        assert "mixed_driver_families" in s.evidence

    def test_weak_persistent_clients(self):
        weak = _win(client_key="w", rssi_mean=-82.0, weak_share=0.9)
        s = summarize_radio_clients(
            [assess_client(weak, TH), assess_client(_win(), TH)]
        )
        assert s.weak_persistent_clients == 1

    def test_mixed_radios_rejected(self):
        a = assess_client(_win(), TH)
        b = assess_client(_win(radio=RadioRef("ap2", "radio1")), TH)
        with pytest.raises(ValueError):
            summarize_radio_clients([a, b])

    def test_empty(self):
        s = summarize_radio_clients([])
        assert s.client_count == 0
        assert s.radio is None
        assert s.signal_coverage is None


class TestReviewM4Mt76RetriesReliable:
    """mt76 with WED reports no retries: a 0 there is unknown, not good."""

    def test_review_m4_mt76_zero_retries_wed_unknown_is_no_data(self):
        a = assess_client(_win(tx_retries=0, tx_packets=5000, tx_failed=0))
        assert a.retry_rate.state is C.NO_DATA
        assert "retries_reliable" in a.missing

    def test_review_m4_mt76_zero_retries_wed_on_is_no_data(self):
        w = _win(tx_retries=0, tx_packets=5000, retries_reliable=False)
        assert assess_client(w).retry_rate.state is C.NO_DATA

    def test_review_m4_reliable_zero_stays_measured_zero(self):
        w = _win(tx_retries=0, tx_packets=5000, retries_reliable=True)
        a = assess_client(w)
        assert a.retry_rate.state is C.MEASURED
        assert a.retry_rate.value == 0.0
        assert "retries_reliable" not in a.missing

    def test_review_m4_nonzero_retries_are_measured(self):
        a = assess_client(_win(tx_retries=500, tx_packets=10_000))
        assert a.retry_rate.state is C.MEASURED

    def test_review_m4_other_family_zero_is_measured(self):
        w = _win(driver="ath10k-ct", tx_retries=0, tx_packets=5000)
        assert assess_client(w).retry_rate.state is C.MEASURED

    def test_review_m4_documented(self):
        import custom_components.openwrt_router.rf_clients as mod

        assert "retries_reliable" in (mod.ClientRfWindow.__doc__ or "")
