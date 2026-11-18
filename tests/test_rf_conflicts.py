"""Tests for RF conflict detection (rf_conflicts.py, pure, no HA)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.channel_plan import (
    FINDING_OVERLAP,
    FINDING_SAME_CHANNEL,
    Radio,
    analyze,
)
from custom_components.openwrt_router.rf_conflicts import (
    ConflictKind,
    ConflictStatus,
    ConflictThresholds,
    RadioRef,
    RadioView,
    Severity,
    detect_conflicts,
    from_channel_plan_radio,
)
from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_SCAN,
    CapabilityState,
    metric_measured,
    metric_missing,
)
from custom_components.openwrt_router.rf_spectrum import (
    RadioRegulatory,
    channels_from_freqlist,
)

K = ConflictKind
S = ConflictStatus
TH = ConflictThresholds()


def _util(pct, at=100.0):
    return metric_measured(pct, SOURCE_HOSTAPD_STATUS, measured_at=at)


def _view(router, radio, channel, width=20, band="2.4g", **kw):
    return RadioView(
        router_key=router,
        radio_key=radio,
        band=band,
        channel=channel,
        width_mhz=width,
        **kw,
    )


def _of(conflicts, kind):
    return [c for c in conflicts if c.kind is kind]


def _four_aps(util_a=None, util_b=None):
    return [
        _view("ap1", "radio0", 6, utilization=util_a),
        _view("ap2", "radio0", 6, utilization=util_b),
        _view("ap3", "radio0", 1),
        _view("ap4", "radio0", 11),
    ]


def _reg_24(channels=range(1, 14)):
    raw = [
        {"channel": ch, "mhz": 2407 + 5 * ch, "restricted": False, "flags": []}
        for ch in channels
    ]
    return RadioRegulatory(
        channels=tuple(channels_from_freqlist(raw)),
        txpower_dbm_list=None,
        country=None,
    )


# =====================================================================
# Co-channel and overlap
# =====================================================================


class TestCoChannel:
    def test_four_aps_one_pair_potential_without_measurement(self):
        conflicts = detect_conflicts(_four_aps(), TH)
        assert len(conflicts) == 1
        (c,) = conflicts
        assert c.kind is K.CO_CHANNEL
        assert c.members == (RadioRef("ap1", "radio0"), RadioRef("ap2", "radio0"))
        assert c.status is S.POTENTIAL
        assert c.severity is Severity.INFO
        assert "channel_plan:co_channel:2.4g" in c.evidence
        assert "utilization_unknown:ap1/radio0:none" in c.evidence

    def test_case_08_critical_overlap_measured(self):
        conflicts = detect_conflicts(_four_aps(util_a=_util(78.0)), TH)
        (c,) = conflicts
        assert c.status is S.MEASURED
        assert c.severity is Severity.WARNING
        assert "utilization:ap1/radio0:78.0%:hostapd.get_status" in c.evidence

    def test_case_07_normal_overlap_acceptable(self):
        conflicts = detect_conflicts(_four_aps(_util(12.0), _util(20.0)), TH)
        (c,) = conflicts
        assert c.status is S.ACCEPTABLE
        assert c.severity is Severity.INFO

    def test_case_07_one_unknown_stays_potential(self):
        conflicts = detect_conflicts(_four_aps(_util(12.0), None), TH)
        assert conflicts[0].status is S.POTENTIAL

    def test_case_07_stale_or_missing_metric_counts_as_unknown(self):
        stale = metric_measured(5.0, SOURCE_HOSTAPD_STATUS, measured_at=1.0)
        stale = type(stale)(5.0, CapabilityState.STALE, stale.source, 1.0)
        missing = metric_missing(CapabilityState.UNREACHABLE, SOURCE_HOSTAPD_STATUS)
        conflicts = detect_conflicts(_four_aps(_util(5.0), stale), TH)
        assert conflicts[0].status is S.POTENTIAL
        assert "utilization_unknown:ap2/radio0:stale" in conflicts[0].evidence
        conflicts = detect_conflicts(_four_aps(_util(5.0), missing), TH)
        assert conflicts[0].status is S.POTENTIAL

    def test_middle_utilization_stays_potential(self):
        conflicts = detect_conflicts(_four_aps(_util(10.0), _util(55.0)), TH)
        assert conflicts[0].status is S.POTENTIAL

    def test_same_channel_alone_is_never_warning(self):
        conflicts = detect_conflicts(_four_aps(), TH)
        assert all(c.severity is Severity.INFO for c in conflicts)

    def test_thresholds_are_parameters(self):
        th = ConflictThresholds(high_utilization_pct=90.0)
        conflicts = detect_conflicts(_four_aps(util_a=_util(78.0)), th)
        assert conflicts[0].status is S.POTENTIAL

    def test_adjacent_overlap(self):
        radios = [_view("ap1", "r0", 1), _view("ap2", "r0", 3)]
        conflicts = _of(detect_conflicts(radios, TH), K.ADJACENT_OVERLAP)
        (c,) = conflicts
        assert c.status is S.POTENTIAL
        assert "overlap_mhz:10" in c.evidence
        assert "overlap_ratio:0.50" in c.evidence

    def test_case_08_adjacent_overlap_with_high_load(self):
        radios = [
            _view("ap1", "r0", 36, 80, band="5g", utilization=_util(85.0)),
            _view("ap2", "r0", 44, 20, band="5g", utilization=_util(10.0)),
        ]
        (c,) = detect_conflicts(radios, TH)
        assert c.kind is K.ADJACENT_OVERLAP
        assert c.status is S.MEASURED
        assert c.severity is Severity.WARNING

    def test_different_bands_never_overlap(self):
        radios = [_view("ap1", "r0", 1), _view("ap2", "r1", 1, band="6g")]
        assert detect_conflicts(radios, TH) == []

    def test_same_radio_listed_twice_is_not_a_pair(self):
        radios = [_view("ap1", "r0", 6), _view("ap1", "r0", 6)]
        assert detect_conflicts(radios, TH) == []

    def test_same_radio_key_on_two_routers_is_two_radios(self):
        radios = [_view("ap1", "radio0", 6), _view("ap2", "radio0", 6)]
        assert len(detect_conflicts(radios, TH)) == 1


class TestNeighborSignal:
    def test_case_08_mutual_reception_above_threshold_is_measured(self):
        heard = {
            RadioRef("ap2", "r0b"): metric_measured(
                -60, SOURCE_IWINFO_SCAN, measured_at=1.0
            )
        }
        radios = [
            _view("ap1", "r0a", 6, neighbors=heard),
            _view("ap2", "r0b", 6),
        ]
        (c,) = detect_conflicts(radios, TH)
        assert c.status is S.MEASURED
        assert c.severity is Severity.WARNING
        assert "neighbor_signal:ap1/r0a<-ap2/r0b:-60dBm:iwinfo.scan" in c.evidence

    def test_weak_reception_is_evidence_only(self):
        weak = {
            RadioRef("ap2", "r0b"): metric_measured(
                -90, SOURCE_IWINFO_SCAN, measured_at=1.0
            )
        }
        radios = [_view("ap1", "r0a", 6, neighbors=weak), _view("ap2", "r0b", 6)]
        (c,) = detect_conflicts(radios, TH)
        assert c.status is S.POTENTIAL
        assert "neighbor_signal:ap1/r0a<-ap2/r0b:-90dBm:iwinfo.scan" in c.evidence

    def test_missing_neighbor_metric_is_ignored(self):
        gone = {
            RadioRef("ap2", "r0b"): metric_missing(
                CapabilityState.UNSUPPORTED, SOURCE_IWINFO_SCAN
            )
        }
        radios = [_view("ap1", "r0a", 6, neighbors=gone), _view("ap2", "r0b", 6)]
        assert detect_conflicts(radios, TH)[0].status is S.POTENTIAL

    def test_same_radio_key_on_two_routers_is_looked_up_per_router(self):
        # radio0 exists on every router: hearing ap2/radio0 says nothing
        # about ap3/radio0.
        heard = {
            RadioRef("ap2", "radio0"): metric_measured(
                -60, SOURCE_IWINFO_SCAN, measured_at=1.0
            )
        }
        radios = [
            _view("ap1", "radio0", 6, neighbors=heard),
            _view("ap2", "radio0", 6),
            _view("ap3", "radio0", 6),
        ]
        by_members = {c.members: c for c in detect_conflicts(radios, TH)}
        a1, a2, a3 = (RadioRef(f"ap{i}", "radio0") for i in (1, 2, 3))
        assert by_members[(a1, a2)].status is S.MEASURED
        assert by_members[(a1, a3)].status is S.POTENTIAL
        assert not any(
            e.startswith("neighbor_signal") for e in by_members[(a1, a3)].evidence
        )
        assert by_members[(a2, a3)].status is S.POTENTIAL


class TestBackhaulAndSameRouter:
    def test_backhaul_pair_is_reported_as_expected(self):
        radios = [_view("root", "r0", 6), _view("rep", "r0", 6, backhaul=True)]
        (c,) = detect_conflicts(radios, TH)
        assert c.kind is K.CO_CHANNEL
        assert c.status is S.ACCEPTABLE
        assert c.severity is Severity.INFO
        assert "backhaul_shared_channel:rep/r0" in c.evidence

    def test_backhaul_does_not_hide_a_measured_load(self):
        radios = [
            _view("root", "r0", 6, utilization=_util(90.0)),
            _view("rep", "r0", 6, backhaul=True),
        ]
        (c,) = detect_conflicts(radios, TH)
        assert c.status is S.MEASURED
        assert "backhaul_shared_channel:rep/r0" in c.evidence

    def test_same_router_two_radios_is_at_least_potential(self):
        radios = [
            _view("fr3", "radio1", 36, 80, band="5g", utilization=_util(5.0)),
            _view("fr3", "radio2", 44, 20, band="5g", utilization=_util(5.0)),
        ]
        (c,) = detect_conflicts(radios, TH)
        assert c.kind is K.ADJACENT_OVERLAP
        assert c.status is S.POTENTIAL
        assert "same_router:fr3" in c.evidence

    def test_same_router_backhaul_is_not_acceptable(self):
        radios = [
            _view("fr3", "radio1", 36, 80, band="5g"),
            _view("fr3", "radio2", 36, 80, band="5g", backhaul=True),
        ]
        (c,) = detect_conflicts(radios, TH)
        assert c.status is S.POTENTIAL


# =====================================================================
# Single-radio findings
# =====================================================================


class TestSingleRadio:
    def test_non_standard_24(self):
        radios = [_view("ap1", "r0", 3)]
        (c,) = detect_conflicts(radios, TH)
        assert c.kind is K.NON_STANDARD_24
        assert c.status is S.POTENTIAL
        assert c.severity is Severity.INFO
        assert c.evidence == ("channel:3",)

    def test_wide_channel_24(self):
        radios = [_view("ap1", "r0", 1, 40)]
        (c,) = detect_conflicts(radios, TH)
        assert c.kind is K.WIDE_CHANNEL_24
        assert "width_mhz:40" in c.evidence

    def test_backhaul_radio_findings_carry_the_flag(self):
        radios = [_view("rep", "r0", 3, backhaul=True)]
        (c,) = detect_conflicts(radios, TH)
        assert "backhaul_shared_channel:rep/r0" in c.evidence

    def test_5g_has_no_24_findings(self):
        assert detect_conflicts([_view("ap1", "r0", 36, 80, band="5g")], TH) == []


# =====================================================================
# Uneven distribution
# =====================================================================


class TestUnevenDistribution:
    def _crowded(self, reg):
        return [
            _view("ap1", "r0", 6, regulatory=reg),
            _view("ap2", "r0", 6, regulatory=reg),
            _view("ap3", "r0", 6, regulatory=reg),
            _view("ap4", "r0", 1, regulatory=reg),
        ]

    def test_three_of_four_on_one_channel_with_free_alternative(self):
        conflicts = detect_conflicts(self._crowded(_reg_24()), TH)
        (u,) = _of(conflicts, K.UNEVEN_DISTRIBUTION)
        assert len(u.members) == 3
        assert u.status is S.POTENTIAL
        assert u.severity is Severity.INFO
        assert "crowded:2.4g:ch6:3/4" in u.evidence
        assert "alternatives:1,11" in u.evidence
        # the co-channel pairs are still all there
        assert len(_of(conflicts, K.CO_CHANNEL)) == 3

    def test_without_channel_list_no_uneven_finding(self):
        conflicts = detect_conflicts(self._crowded(None), TH)
        assert _of(conflicts, K.UNEVEN_DISTRIBUTION) == []
        assert len(_of(conflicts, K.CO_CHANNEL)) == 3

    def test_no_allowed_alternative_no_finding(self):
        conflicts = detect_conflicts(self._crowded(_reg_24([6])), TH)
        assert _of(conflicts, K.UNEVEN_DISTRIBUTION) == []

    def test_one_radio_with_list_is_enough(self):
        radios = self._crowded(None)
        radios[0] = _view("ap1", "r0", 6, regulatory=_reg_24())
        conflicts = detect_conflicts(radios, TH)
        (u,) = _of(conflicts, K.UNEVEN_DISTRIBUTION)
        assert "channel_list_from:ap1/r0" in u.evidence

    def test_even_spread_no_finding(self):
        reg = _reg_24()
        radios = [
            _view("ap1", "r0", 1, regulatory=reg),
            _view("ap2", "r0", 6, regulatory=reg),
            _view("ap3", "r0", 11, regulatory=reg),
            _view("ap4", "r0", 6, regulatory=reg),
        ]
        assert _of(detect_conflicts(radios, TH), K.UNEVEN_DISTRIBUTION) == []


# =====================================================================
# Same pairs as channel_plan.analyze
# =====================================================================


def _cp(entry, phy, band, channel, width, center, backhaul=False):
    return Radio(entry, f"Router {entry}", phy, band, channel, width, center, backhaul)


CONSTELLATIONS = {
    "24_same_and_clean": [
        _cp("e1", "phy0", "2.4g", 1, 20, 1),
        _cp("e2", "phy0", "2.4g", 1, 20, 1),
        _cp("e3", "phy0", "2.4g", 6, 20, 6),
        _cp("e4", "phy0", "2.4g", 11, 20, 11),
    ],
    "24_forty_and_offgrid": [
        _cp("e1", "phy0", "2.4g", 1, 40, 3),
        _cp("e2", "phy0", "2.4g", 6, 20, 6),
        _cp("e3", "phy0", "2.4g", 11, 20, 11),
        _cp("e4", "phy0", "2.4g", 9, 20, 9),
    ],
    "5g_wide_blocks": [
        _cp("e1", "phy1", "5g", 36, 80, 42),
        _cp("e2", "phy1", "5g", 44, 40, 46),
        _cp("e3", "phy1", "5g", 52, 20, 52),
        _cp("e4", "phy1", "5g", 100, 160, 114),
        _cp("e5", "phy1", "5g", 116, 20, 116),
    ],
    "mixed_with_backhaul_and_same_router": [
        _cp("e1", "phy0", "2.4g", 6, 20, 6),
        _cp("e2", "phy0", "2.4g", 6, 20, 6, backhaul=True),
        _cp("e3", "phy0", "2.4g", 6, 20, 6),
        _cp("e3", "phy1", "5g", 36, 80, 42),
        _cp("e3", "phy2", "5g", 48, 20, 48),
        _cp("e1", "phy1", "5g", 36, 20, 36),
    ],
}

_KIND_MAP = {FINDING_SAME_CHANNEL: K.CO_CHANNEL, FINDING_OVERLAP: K.ADJACENT_OVERLAP}


def _cp_pairs(radios):
    by_attr = {(r.router, r.phy): (r.entry_id, r.phy) for r in radios}
    pairs = set()
    for f in analyze(radios):
        if f["type"] in _KIND_MAP:
            members = frozenset(by_attr[(a["router"], a["radio"])] for a in f["radios"])
            pairs.add((_KIND_MAP[f["type"]], members))
    return pairs


def _rf_pairs(radios):
    views = [from_channel_plan_radio(r) for r in radios]
    pairs = set()
    for c in detect_conflicts(views, TH):
        if c.kind in (K.CO_CHANNEL, K.ADJACENT_OVERLAP):
            if any("backhaul_shared_channel" in e for e in c.evidence):
                continue  # channel_plan skips backhaul pairs by design
            members = frozenset((m.router_key, m.radio_key) for m in c.members)
            pairs.add((c.kind, members))
    return pairs


class TestMatchesChannelPlan:
    @pytest.mark.parametrize("name", sorted(CONSTELLATIONS))
    def test_same_pairs_as_channel_plan_analyze(self, name):
        radios = CONSTELLATIONS[name]
        expected = _cp_pairs(radios)
        assert expected  # every constellation has at least one pair
        assert _rf_pairs(radios) == expected

    def test_backhaul_pairs_are_extra_not_missing(self):
        radios = CONSTELLATIONS["mixed_with_backhaul_and_same_router"]
        views = [from_channel_plan_radio(r) for r in radios]
        backhaul = [
            c
            for c in detect_conflicts(views, TH)
            if any("backhaul_shared_channel" in e for e in c.evidence)
        ]
        assert {c.status for c in backhaul} == {S.ACCEPTABLE}
        assert len(backhaul) == 2  # e2 with e1 and with e3

    def test_identical_block_other_primary_is_co_channel_here(self):
        # Deliberate difference: channel_plan calls this "overlap", the RF
        # module "co_channel" (identical block). The pair is the same.
        radios = [
            _cp("e1", "phy1", "5g", 36, 80, 42),
            _cp("e2", "phy1", "5g", 40, 80, 42),
        ]
        assert {k for k, _ in _cp_pairs(radios)} == {K.ADJACENT_OVERLAP}
        assert {k for k, _ in _rf_pairs(radios)} == {K.CO_CHANNEL}
        assert {m for _, m in _cp_pairs(radios)} == {m for _, m in _rf_pairs(radios)}

    def test_adapter_keeps_fields(self):
        view = from_channel_plan_radio(_cp("e1", "phy0", "2.4g", 1, 40, 3, True))
        assert (view.router_key, view.radio_key) == ("e1", "phy0")
        assert (view.band, view.channel, view.width_mhz) == ("2.4g", 1, 40)
        assert view.center_channel == 3
        assert view.backhaul is True
        assert view.utilization is None


def test_as_dict():
    (c,) = detect_conflicts(_four_aps(util_a=_util(78.0)), TH)
    data = c.as_dict()
    assert data["kind"] == "co_channel"
    assert data["status"] == "measured"
    assert data["severity"] == "warning"
    assert data["members"] == [
        {"router_key": "ap1", "radio_key": "radio0"},
        {"router_key": "ap2", "radio_key": "radio0"},
    ]
    assert c.radio_keys == ("radio0", "radio0")
