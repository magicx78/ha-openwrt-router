"""Tests for channel, width, TX power and load hints (rf_recommend.py, pure)."""

from __future__ import annotations

import inspect

import pytest

from custom_components.openwrt_router import rf_recommend
from custom_components.openwrt_router.rf_clients import RadioClientSummary
from custom_components.openwrt_router.rf_conflicts import (
    Conflict,
    ConflictKind,
    ConflictStatus,
    RadioRef,
    RadioView,
    Severity,
)
from custom_components.openwrt_router.rf_load import (
    ApLoadInput,
    LoadThresholds,
    RadioLoad,
    assess_load,
    distribution,
)
from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_ASSOCLIST,
    SOURCE_IWINFO_INFO,
    CapabilityState,
    metric_measured,
    metric_missing,
)
from custom_components.openwrt_router.rf_recommend import (
    Recommendation,
    RecommendThresholds,
    SelfHealingAction,
    recommend_channel,
    recommend_load,
    recommend_tx_power,
    recommend_width,
)
from custom_components.openwrt_router.rf_roaming import StickyAssessment, StickyStatus
from custom_components.openwrt_router.rf_spectrum import (
    RadioRegulatory,
    channels_from_freqlist,
)
from custom_components.openwrt_router.rf_utilization import UtilizationSummary

TH = RecommendThresholds()
CH_5G = [*range(36, 65, 4), *range(100, 141, 4)]


def _reg(band, channels, restricted=(), flags=()):
    def mhz(ch):
        return 2407 + 5 * ch if band == "2.4g" else 5000 + 5 * ch

    raw = [
        {
            "channel": ch,
            "mhz": mhz(ch),
            "restricted": ch in restricted,
            "flags": None if flags is None else list(flags),
        }
        for ch in channels
    ]
    return RadioRegulatory(
        channels=tuple(channels_from_freqlist(raw)), txpower_dbm_list=None, country=None
    )


REG_24 = _reg("2.4g", range(1, 14))
REG_5 = _reg("5g", CH_5G)


def _view(router, radio, channel, width=20, band="2.4g", **kw):
    return RadioView(
        router_key=router,
        radio_key=radio,
        band=band,
        channel=channel,
        width_mhz=width,
        **kw,
    )


def _summary(mean, sustained=True, coverage=1.0):
    return UtilizationSummary(
        current=mean,
        mean=mean,
        peak=mean,
        valid_count=12,
        invalid_count=0,
        coverage=coverage,
        phases=(),
        sustained_overload=sustained,
    )


AP1 = _view("ap1", "radio0", 6, regulatory=REG_24)
OTHERS = [_view("ap2", "radio0", 6), _view("ap3", "radio0", 1)]


# =====================================================================
# Channel
# =====================================================================


class TestChannelExample:
    def test_example_lower_observed_utilization_only_with_comparison_data(self):
        per_channel = {11: _summary(20.0, sustained=False), 1: _summary(75.0)}
        r = recommend_channel(AP1, _summary(78.0), OTHERS, per_channel, TH)
        assert r.action == "change_channel"
        assert r.action_params["channel"] == 11
        assert r.basis == "lower_observed_utilization"
        assert r.expected_effect == "lower_channel_utilization"
        assert "utilization:ch6:78.0%" in r.evidence
        assert "utilization:ch11:20.0%" in r.evidence
        assert "clients_reconnect_on_change" in r.risk
        assert r.confidence <= TH.comparison_confidence

    def test_example_without_comparison_data_is_planning_only(self):
        r = recommend_channel(AP1, _summary(78.0), OTHERS, None, TH)
        assert r.action == "change_channel"
        assert r.action_params["channel"] == 11
        assert r.basis == "fewer_managed_radios_on_channel"
        assert r.expected_effect == "unknown_no_comparison_data"
        assert r.confidence <= 0.4
        assert "per_channel_utilization" in r.requires
        assert not any(e.startswith("utilization:ch11") for e in r.evidence)

    def test_rule_no_comparison_argument_without_data_for_that_channel(self):
        # Data only for channel 1 (busy) and an empty summary for 11.
        empty = UtilizationSummary(None, None, None, 0, 5, 0.0, (), None)
        per_channel = {1: _summary(75.0), 11: empty}
        r = recommend_channel(AP1, _summary(78.0), OTHERS, per_channel, TH)
        assert r.action_params["channel"] == 11
        assert r.basis == "fewer_managed_radios_on_channel"
        assert r.confidence <= TH.planning_confidence_cap

    def test_candidate_busier_by_data_is_not_recommended(self):
        per_channel = {11: _summary(70.0), 1: _summary(75.0)}
        r = recommend_channel(AP1, _summary(78.0), OTHERS, per_channel, TH)
        assert r.action == "review_channel_plan"
        assert "no_better_candidate" in r.evidence


class TestChannelRules:
    def test_rule_no_channel_list_no_channel_change(self):
        radio = _view("ap1", "radio0", 6)
        r = recommend_channel(radio, _summary(78.0), OTHERS, None, TH)
        assert r.action == "collect_channel_list"
        assert r.priority == "low"
        assert "freqlist" in r.requires
        assert "channel" not in r.action_params

    def test_rule_no_channel_list_nothing_to_fix_is_none(self):
        radio = _view("ap1", "radio0", 11)
        assert recommend_channel(radio, _summary(10.0, False), [], None, TH) is None

    @pytest.mark.parametrize(
        "listed",
        [range(1, 7), range(1, 12), [1, 6, 11], [6, 11], range(4, 14)],
    )
    def test_rule_never_outside_reported_list(self, listed):
        radio = _view("ap1", "radio0", 6, regulatory=_reg("2.4g", listed))
        others = [_view("ap2", "radio0", 6)]
        r = recommend_channel(radio, _summary(78.0), others, None, TH)
        if r is not None and r.action == "change_channel":
            assert r.action_params["channel"] in set(listed)

    def test_restricted_channel_is_never_recommended(self):
        radio = _view("ap1", "radio0", 6, regulatory=_reg("2.4g", range(1, 14), [11]))
        r = recommend_channel(radio, _summary(78.0), OTHERS, None, TH)
        assert r.action != "change_channel" or r.action_params["channel"] != 11

    def test_without_sustained_load_only_review(self):
        for summary in (None, _summary(78.0, sustained=False), _summary(30.0, False)):
            r = recommend_channel(AP1, summary, OTHERS, None, TH)
            assert r.action == "review_channel_plan"
            assert r.confidence <= TH.review_confidence
            assert "potential_overlap:ap2/radio0:co_channel" in r.evidence

    def test_case_25_unknown_sustained_is_not_overload(self):
        unknown = _summary(78.0, sustained=None)
        r = recommend_channel(AP1, unknown, OTHERS, None, TH)
        assert r.action == "review_channel_plan"

    def test_without_load_or_overlap_nothing(self):
        radio = _view("ap1", "radio0", 11, regulatory=REG_24)
        assert recommend_channel(radio, None, OTHERS, None, TH) is None

    def test_dfs_candidate_carries_risks(self):
        radio = _view("ap1", "radio1", 36, 80, band="5g", regulatory=REG_5)
        others = [_view("ap2", "radio1", 36, 80, band="5g")]
        r = recommend_channel(radio, _summary(85.0), others, None, TH)
        assert r.action == "change_channel"
        assert r.action_params["channel"] == 52
        assert "dfs_radar_may_force_change" in r.risk
        assert "dfs_cac_outage" in r.risk
        assert "clients_reconnect_on_change" in r.risk

    def test_rule_backhaul_radio_gets_no_channel_change(self):
        radio = _view(
            "rep", "radio1", 36, 80, band="5g", regulatory=REG_5, backhaul=True
        )
        others = [_view("ap2", "radio1", 36, 80, band="5g")]
        per_channel = {ch: _summary(5.0, False) for ch in CH_5G}
        r = recommend_channel(radio, _summary(90.0), others, per_channel, TH)
        assert r.action == "review_backhaul_channel"
        assert "channel" not in r.action_params
        assert "uplink_loss_on_change" in r.risk
        assert r.confidence <= TH.review_confidence

    def test_as_dict(self):
        r = recommend_channel(AP1, _summary(78.0), OTHERS, None, TH)
        d = r.as_dict()
        assert d["target"] == {"router_key": "ap1", "radio_key": "radio0"}
        assert d["action"] == "change_channel"
        assert d["action_params"]["channel"] == 11
        assert isinstance(d["risk"], list)


# =====================================================================
# Width
# =====================================================================


class TestWidth:
    def test_24_40mhz_to_20(self):
        radio = _view("ap1", "radio0", 1, 40, regulatory=REG_24, htmode="HT40+")
        r = recommend_width(radio, None, OTHERS, TH)
        assert r.action == "change_width"
        assert r.action_params == {"width_mhz": 20, "channel": 1}
        assert any(e.startswith("overlaps:ap3/radio0") for e in r.evidence)
        assert "clients_reconnect_on_change" in r.risk

    def test_24_40mhz_without_list_collects_list(self):
        radio = _view("ap1", "radio0", 1, 40, htmode="HT40+")
        r = recommend_width(radio, None, OTHERS, TH)
        assert r.action == "collect_channel_list"
        assert "width_mhz" not in r.action_params

    def test_24_20mhz_nothing(self):
        assert recommend_width(AP1, None, OTHERS, TH) is None

    def test_5g_narrower_only_with_overlap_and_high_load(self):
        radio = _view("ap1", "radio1", 36, 80, band="5g", regulatory=REG_5)
        others = [_view("ap2", "radio1", 44, 20, band="5g")]
        r = recommend_width(radio, _summary(85.0), others, TH)
        assert r.action == "change_width"
        assert r.action_params["width_mhz"] == 40
        assert recommend_width(radio, _summary(20.0, False), others, TH) is None
        assert recommend_width(radio, _summary(85.0), [], TH) is None

    def test_width_not_confirmed_by_allowed_is_never_recommended(self):
        unknown_flags = _reg("5g", CH_5G, flags=None)
        radio = _view("ap1", "radio1", 36, 80, band="5g", regulatory=unknown_flags)
        others = [_view("ap2", "radio1", 44, 20, band="5g")]
        assert recommend_width(radio, _summary(85.0), others, TH) is None

    def test_backhaul_width_is_hint_only(self):
        radio = _view(
            "rep", "radio0", 1, 40, regulatory=REG_24, htmode="HT40+", backhaul=True
        )
        r = recommend_width(radio, None, OTHERS, TH)
        assert r.action == "review_backhaul_width"
        assert "uplink_loss_on_change" in r.risk


# =====================================================================
# TX power
# =====================================================================

RADIO = _view("ap1", "radio1", 36, 80, band="5g")


def _dbm(value):
    return metric_measured(value, SOURCE_IWINFO_INFO, measured_at=1.0)


def _sticky(n, status=StickyStatus.SUSPECTED, radio=RADIO.ref):
    return [
        StickyAssessment(f"c{i}", radio, status, None, None, ("x",), 0.5)
        for i in range(n)
    ]


def _overlap(status=ConflictStatus.MEASURED, evidence=("utilization:x",)):
    return Conflict(
        ConflictKind.CO_CHANNEL,
        "5g",
        (RADIO.ref, RadioRef("ap2", "radio1")),
        status,
        Severity.WARNING if status is ConflictStatus.MEASURED else Severity.INFO,
        evidence,
    )


def _clients(weak):
    return RadioClientSummary(
        radio=RADIO.ref,
        client_count=10,
        problem_clients=weak,
        flagged_clients=weak,
        weak_persistent_clients=weak,
        signal_quality_mean=40.0,
        signal_coverage=1.0,
        retry_rate=metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST),
        retry_coverage=0.0,
        driver_family="mt76",
        evidence=(),
    )


class TestTxPower:
    def test_case_20_tx_power_too_high(self):
        r = recommend_tx_power(
            RADIO, _dbm(20), (5, 23), _clients(0), _sticky(2), [_overlap()], (), TH
        )
        assert r.kind == "tx_power"
        assert r.action_params == {"direction": "lower", "dbm": 17}
        assert r.confidence <= TH.tx_confidence_cap
        assert "sticky_clients:2" in r.evidence
        assert "coverage_gaps_possible" in r.risk

    def test_case_20_env_measurement_raises_cap(self):
        conflict = _overlap(evidence=("neighbor_signal:a<-b:-60dBm:iwinfo.scan",))
        r = recommend_tx_power(
            RADIO, _dbm(20), (5, 23), None, _sticky(3), [conflict], (), TH
        )
        assert TH.tx_confidence_cap < r.confidence <= TH.tx_confidence_env_cap

    def test_case_20_value_stays_within_limits(self):
        r = recommend_tx_power(
            RADIO, _dbm(6), (5, 23), None, _sticky(2), [_overlap()], (), TH
        )
        assert r.action_params["dbm"] == 5

    def test_case_20_without_limits_direction_only(self):
        r = recommend_tx_power(RADIO, _dbm(20), None, None, _sticky(2), [_overlap()])
        assert r.action_params == {"direction": "lower"}
        assert "txpowerlist" in r.requires

    def test_case_25_current_power_unknown_direction_only(self):
        gone = metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_INFO)
        r = recommend_tx_power(RADIO, gone, (5, 23), None, _sticky(2), [_overlap()])
        assert "dbm" not in r.action_params
        assert "txpower" in r.requires

    def test_case_20_too_low_warns_about_uplink(self):
        r = recommend_tx_power(RADIO, _dbm(14), (5, 23), _clients(4), [], [], (), TH)
        assert r.action_params == {"direction": "raise", "dbm": 17}
        assert "ap_power_does_not_fix_client_uplink" in r.risk
        assert "weak_persistent_clients:4" in r.evidence

    def test_case_20_too_low_at_max_is_placement_review(self):
        r = recommend_tx_power(RADIO, _dbm(23), (5, 23), _clients(4), [], [], (), TH)
        assert r.action == "review_ap_placement"
        assert "ap_power_does_not_fix_client_uplink" in r.risk

    def test_too_low_not_when_alternatives_exist(self):
        r = recommend_tx_power(
            RADIO, _dbm(14), (5, 23), _clients(4), _sticky(1), [], (), TH
        )
        assert r is None

    def test_no_hint_without_both_conditions(self):
        assert (
            recommend_tx_power(RADIO, _dbm(20), (5, 23), None, _sticky(1), [_overlap()])
            is None
        )
        potential = _overlap(ConflictStatus.POTENTIAL)
        assert (
            recommend_tx_power(RADIO, _dbm(20), (5, 23), None, _sticky(3), [potential])
            is None
        )
        other_radio = _sticky(3, radio=RadioRef("ap9", "radio1"))
        assert (
            recommend_tx_power(
                RADIO, _dbm(20), (5, 23), None, other_radio, [_overlap()]
            )
            is None
        )

    def test_contradicting_evidence_gives_nothing(self):
        r = recommend_tx_power(
            RADIO, _dbm(20), (5, 23), _clients(5), _sticky(3), [_overlap()], (), TH
        )
        assert r is None


# =====================================================================
# Load
# =====================================================================


def _load_radio(router, count, util=None, **kw):
    utilization = (
        None
        if util is None
        else metric_measured(util, SOURCE_HOSTAPD_STATUS, measured_at=1.0)
    )
    base = {
        "ref": RadioRef(router, "radio1"),
        "band": "5g",
        "client_count": count,
        "utilization": utilization,
        "airtime_share_top_client": None,
        "rssi_mean": None,
        "retry_rate": None,
        "driver": None,
        "tx_bytes_rate": None,
        "rx_bytes_rate": None,
        "problem_clients": None,
    }
    base.update(kw)
    return ApLoadInput(router, (RadioLoad(**base),))


_FORBIDDEN = ("steer", "move_client", "disconnect", "kick", "deauth")


class TestLoad:
    def test_load_hints_are_review_tasks(self):
        aps = [
            _load_radio("ap1", 40, 90.0),
            _load_radio("ap2", 30),
            _load_radio("ap3", 2, 10.0),
        ]
        th = LoadThresholds()
        recs = recommend_load(assess_load(aps, th), distribution(aps, th))
        actions = {(r.target, r.action) for r in recs}
        assert ("ap1", "review_ap_load") in actions
        assert ("ap2", "collect_utilization") in actions
        assert ("ap1", "review_client_distribution") in actions
        for r in recs:
            assert not any(word in r.action for word in _FORBIDDEN)
            assert r.evidence

    def test_nothing_to_say(self):
        aps = [_load_radio("ap1", 5, 10.0), _load_radio("ap2", 5, 12.0)]
        th = LoadThresholds()
        assert recommend_load(assess_load(aps, th), distribution(aps, th)) == []


# =====================================================================
# Self-healing type only
# =====================================================================


class TestSelfHealing:
    def test_type_exists_without_any_executor(self):
        action = SelfHealingAction(
            kind="change_channel",
            target=RadioRef("ap1", "radio0"),
            params={"channel": 11},
            preconditions=("no_print_running",),
            rollback={"channel": 6},
        )
        assert action.kind == "change_channel"
        assert "nicht implementiert" in (SelfHealingAction.__doc__ or "")
        for name in ("apply", "execute", "run", "__call__"):
            assert not hasattr(action, name)

    def test_module_has_no_apply_or_execute(self):
        names = {
            name
            for name, obj in inspect.getmembers(rf_recommend)
            if inspect.isfunction(obj) or inspect.isclass(obj)
        }
        assert not {n for n in names if n.startswith(("apply", "execute"))}

    def test_recommendation_is_frozen(self):
        r = recommend_channel(AP1, _summary(78.0), OTHERS, None, TH)
        assert isinstance(r, Recommendation)
        with pytest.raises(AttributeError):
            r.confidence = 1.0  # type: ignore[misc]
