"""Tests for load assessment and client distribution (rf_load.py, pure)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from custom_components.openwrt_router.rf_conflicts import RadioRef
from custom_components.openwrt_router.rf_load import (
    ApLoadInput,
    LoadStatus,
    LoadThresholds,
    RadioLoad,
    assess_load,
    distribution,
)
from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_ASSOCLIST,
    CapabilityState,
    metric_measured,
    metric_missing,
)

C = CapabilityState
L = LoadStatus
TH = LoadThresholds()


def _m(value, source=SOURCE_HOSTAPD_STATUS):
    return metric_measured(value, source, measured_at=1.0)


def _radio(router="ap1", radio="radio1", band="5g", **kw):
    base = {
        "ref": RadioRef(router, radio),
        "band": band,
        "client_count": 5,
        "utilization": None,
        "airtime_share_top_client": None,
        "rssi_mean": None,
        "retry_rate": None,
        "driver": "mt7915e",
        "tx_bytes_rate": None,
        "rx_bytes_rate": None,
        "problem_clients": None,
    }
    base.update(kw)
    return RadioLoad(**base)


def _ap(*radios, router="ap1"):
    return ApLoadInput(router_key=router, radios=tuple(radios))


def _status(radio):
    (ap,) = assess_load([_ap(radio)], TH).aps
    (r,) = ap.radios
    return r


class TestAssessLoad:
    def test_case_14_ap_overload_util_and_many_clients(self):
        r = _status(_radio(utilization=_m(85.0), client_count=40))
        assert r.status is L.OVERLOADED
        assert "utilization:ap1/radio1:85.0%:hostapd.get_status" in r.evidence
        assert "many_clients:ap1/radio1:40" in r.evidence

    def test_case_14_ap_overload_util_and_retries(self):
        retry = _m(0.4, SOURCE_IWINFO_ASSOCLIST)
        r = _status(_radio(utilization=_m(85.0), retry_rate=retry))
        assert r.status is L.OVERLOADED

    def test_case_14_retry_path_with_second_evidence(self):
        retry = _m(0.4, SOURCE_IWINFO_ASSOCLIST)
        r = _status(_radio(retry_rate=retry, problem_clients=5))
        assert r.status is L.OVERLOADED
        assert any(e.startswith("utilization_unknown") for e in r.evidence)
        assert (
            r.confidence
            < _status(_radio(utilization=_m(85.0), client_count=40)).confidence
        )

    def test_high_util_alone_is_elevated(self):
        assert _status(_radio(utilization=_m(85.0))).status is L.ELEVATED

    def test_middle_util_is_elevated(self):
        assert _status(_radio(utilization=_m(60.0))).status is L.ELEVATED

    def test_low_util_is_ok(self):
        r = _status(_radio(utilization=_m(20.0)))
        assert r.status is L.OK

    def test_retries_at_low_load_are_not_overload(self):
        retry = _m(0.4, SOURCE_IWINFO_ASSOCLIST)
        r = _status(_radio(utilization=_m(20.0), retry_rate=retry, client_count=40))
        assert r.status is L.OK
        assert "retry_rate_high_without_load:ap1/radio1" in r.evidence

    @pytest.mark.parametrize("count", [0, 30, 60, 500])
    @pytest.mark.parametrize("util", [None, 20.0, 60.0])
    def test_rule_client_count_alone_never_overloaded(self, count, util):
        utilization = None if util is None else _m(util)
        r = _status(_radio(client_count=count, utilization=utilization))
        assert r.status is not L.OVERLOADED

    def test_many_clients_at_low_util_is_ok_with_hint(self):
        r = _status(_radio(client_count=60, utilization=_m(20.0)))
        assert r.status is L.OK
        assert "many_clients:ap1/radio1:60" in r.evidence

    def test_case_25_no_utilization_no_hints_is_unknown(self):
        r = _status(_radio())
        assert r.status is L.UNKNOWN
        assert "utilization_unknown:ap1/radio1:none" in r.evidence

    def test_case_25_no_utilization_with_hints_is_elevated_never_ok(self):
        r = _status(_radio(client_count=60))
        assert r.status is L.ELEVATED
        assert "utilization_unknown:ap1/radio1:none" in r.evidence

    def test_case_25_stale_or_missing_utilization_is_unknown(self):
        stale = replace(_m(90.0), state=C.STALE)
        r = _status(_radio(utilization=stale))
        assert r.status is L.UNKNOWN
        assert "utilization_unknown:ap1/radio1:stale" in r.evidence
        gone = metric_missing(C.UNREACHABLE, SOURCE_HOSTAPD_STATUS)
        assert _status(_radio(utilization=gone)).status is L.UNKNOWN

    def test_case_25_client_count_unknown(self):
        r = _status(_radio(client_count=None, utilization=_m(20.0)))
        assert "client_count_unknown:ap1/radio1" in r.evidence

    def test_top_client_airtime_is_second_evidence(self):
        r = _status(_radio(utilization=_m(80.0), airtime_share_top_client=_m(65.0)))
        assert r.status is L.OVERLOADED
        assert "top_client_airtime:ap1/radio1:65.0%" in r.evidence

    def test_ap_status_is_worst_known_and_unknown_is_not_ok(self):
        ok = _radio(radio="radio0", band="2.4g", utilization=_m(10.0))
        over = _radio(utilization=_m(90.0), client_count=40)
        unknown = _radio()
        report = assess_load(
            [
                _ap(ok, over, router="a"),
                _ap(ok, unknown, router="b"),
                _ap(ok, router="c"),
            ],
            TH,
        )
        by = {ap.router_key: ap for ap in report.aps}
        assert by["a"].status is L.OVERLOADED
        assert by["b"].status is L.UNKNOWN
        assert by["c"].status is L.OK

    def test_as_dict(self):
        d = assess_load([_ap(_radio(utilization=_m(20.0)))], TH).as_dict()
        assert d["aps"][0]["status"] == "ok"
        assert d["aps"][0]["radios"][0]["ref"] == {
            "router_key": "ap1",
            "radio_key": "radio1",
        }


class TestDistribution:
    def _aps(self, *counts):
        return [
            _ap(_radio(router=f"ap{i}", client_count=n), router=f"ap{i}")
            for i, n in enumerate(counts, start=1)
        ]

    def test_case_15_uneven_client_distribution(self):
        d = distribution(self._aps(20, 2, 2), TH)
        (f,) = d.findings
        assert f.kind == "uneven_client_distribution"
        assert d.largest_ap == "ap1"
        assert d.largest_share == pytest.approx(20 / 24)
        assert d.max_over_median == pytest.approx(10.0)
        assert "largest:ap1:20/24" in f.evidence

    def test_case_15_even_distribution_no_finding(self):
        assert distribution(self._aps(8, 8, 7), TH).findings == ()

    def test_case_15_two_aps(self):
        assert distribution(self._aps(17, 3), TH).findings != ()
        assert distribution(self._aps(12, 8), TH).findings == ()

    def test_below_minimum_total_no_finding(self):
        d = distribution(self._aps(6, 1, 1), TH)
        assert d.findings == ()
        assert "total_below_minimum:8<10" in d.evidence

    def test_case_25_incomplete_counts_no_verdict(self):
        aps = self._aps(20, 2)
        aps.append(_ap(_radio(router="ap3", client_count=None), router="ap3"))
        d = distribution(aps, TH)
        assert d.findings == ()
        assert d.per_ap["ap3"] is None
        assert d.coverage == pytest.approx(2 / 3)
        assert "client_counts_incomplete" in d.evidence

    def test_band_shares_without_capability_no_verdict(self):
        aps = [
            _ap(
                _radio(radio="radio0", band="2.4g", client_count=15),
                _radio(radio="radio1", band="5g", client_count=5),
            )
        ]
        d = distribution(aps, TH)
        assert d.per_band == {"2.4g": 15, "5g": 5}
        assert all(f.kind != "band_imbalance" for f in d.findings)
        assert "band_capability_unknown" in d.evidence

    def test_band_imbalance_only_with_capability_data(self):
        aps = [
            _ap(
                _radio(radio="radio0", band="2.4g", client_count=15),
                _radio(radio="radio1", band="5g", client_count=5),
            )
        ]
        d = distribution(aps, TH, capable_5g_on_24=10)
        (f,) = [f for f in d.findings if f.kind == "band_imbalance"]
        assert f.severity.value == "info"
        assert "capable_5g_on_24:10/15" in f.evidence
