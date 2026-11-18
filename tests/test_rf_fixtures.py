"""Parser and logic checks against synthetic fixtures (live structure 2026-11-18).

The fixtures under ``tests/fixtures/rf`` copy the field structure seen on
live routers (mt76, ath10k-ct, ath9k) with invented values.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest

from custom_components.openwrt_router.rf_clients import (
    ClientRfWindow,
    assess_client,
    assoc_counters_from_assoclist,
    counter_delta,
    mt76_retries_reliable,
)
from custom_components.openwrt_router.rf_conflicts import RadioRef
from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    CapabilityState,
)
from custom_components.openwrt_router.rf_spectrum import (
    BAND_5,
    RadioRegulatory,
    allowed,
    block_for,
    candidate_blocks,
    channels_from_freqlist,
)
from custom_components.openwrt_router.rf_utilization import (
    UnknownReason,
    bss_load_from_get_status,
    survey_noise_dbm,
    survey_samples_from_iwinfo,
    utilization_from_bss_load,
    utilization_from_delta,
)

FIXTURES = Path(__file__).parent / "fixtures" / "rf"
COMMENT = "synthetisch, Struktur nach Live-Prüfung 2026-11-18"


def _load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _reg(raw) -> RadioRegulatory:
    return RadioRegulatory(
        channels=tuple(channels_from_freqlist(raw)), txpower_dbm_list=None, country=None
    )


def test_every_fixture_is_marked_synthetic():
    names = sorted(p.name for p in FIXTURES.glob("*.json"))
    assert names
    for name in names:
        assert next(iter(_load(name))) == "_comment", name
        assert _load(name)["_comment"] == COMMENT


def test_no_txpowerlist_fixture_without_live_structure():
    assert not list(FIXTURES.glob("*txpowerlist*"))


# =====================================================================
# iwinfo info
# =====================================================================


class TestIwinfoInfo:
    def test_mt76_info_gives_a_block(self):
        info = _load("iwinfo_info_mt76.json")
        block = block_for(
            BAND_5, info["channel"], 80, center_channel=info["center_chan1"]
        )
        assert block is not None
        assert block.channels == (36, 40, 44, 48)

    def test_ath9k_info_lacks_offsets_and_hardware_id(self):
        info = _load("iwinfo_info_ath9k.json")
        assert "frequency_offset" not in info
        assert "txpower_offset" not in info
        assert info["hardware"]["id"] == [0, 0, 0, 0]


# =====================================================================
# iwinfo survey
# =====================================================================


class TestSurvey:
    @pytest.mark.parametrize(
        ("raw", "dbm"),
        [(164, -92), (255, -1), (128, -128), (127, None), (1, None), (0, None)]
        + [(-92, -92)],
    )
    def test_noise_is_unsigned_and_zero_is_unknown(self, raw, dbm):
        assert survey_noise_dbm(raw) == dbm

    @pytest.mark.parametrize("raw", [None, True, 256, -129, 1.5, "164"])
    def test_noise_out_of_range_is_unknown(self, raw):
        assert survey_noise_dbm(raw) is None

    def test_all_zero_entries_are_not_samples(self):
        raw = _load("iwinfo_survey_mt76_a.json")
        samples = survey_samples_from_iwinfo(raw, "radio1", 1000.0, 5000.0)
        assert [s.mhz for s in samples] == [5180]
        assert samples[0].noise == -92
        assert samples[0].active_ms == 200_000_000

    def test_operating_frequency_filter(self):
        raw = _load("iwinfo_survey_ath9k.json")
        every = survey_samples_from_iwinfo(raw, "radio0", 1000.0, 5000.0)
        assert [s.mhz for s in every] == [2412, 2437, 2462]
        only = survey_samples_from_iwinfo(raw, "radio0", 1000.0, 5000.0, mhz=2437)
        assert [s.mhz for s in only] == [2437]

    def test_mt76_pair_gives_busy_share(self):
        a = survey_samples_from_iwinfo(
            _load("iwinfo_survey_mt76_a.json"), "radio1", 1000.0, 5000.0, mhz=5180
        )
        b = survey_samples_from_iwinfo(
            _load("iwinfo_survey_mt76_b.json"), "radio1", 1060.0, 5060.0, mhz=5180
        )
        result = utilization_from_delta(a[0], b[0])
        assert result.busy_pct == pytest.approx(40.0)
        assert result.rx_pct == pytest.approx(25.0)
        assert result.tx_pct == pytest.approx(10.0)

    def test_ath9k_off_channel_leftover_is_not_a_measurement(self):
        raw = _load("iwinfo_survey_ath9k.json")
        a = survey_samples_from_iwinfo(raw, "radio0", 1000.0, 5000.0, mhz=2412)
        b = survey_samples_from_iwinfo(raw, "radio0", 1060.0, 5060.0, mhz=2412)
        result = utilization_from_delta(a[0], b[0])
        assert result.reason is UnknownReason.ACTIVE_TOO_SMALL

    def test_garbage_is_empty(self):
        assert survey_samples_from_iwinfo(None, "r", 1.0, None) == ()
        assert survey_samples_from_iwinfo({"results": [1, {}]}, "r", 1.0, None) == ()


# =====================================================================
# hostapd get_status
# =====================================================================


class TestGetStatus:
    def test_counters_are_read(self):
        load = bss_load_from_get_status(_load("hostapd_get_status_mt76_a.json"))
        assert load is not None
        assert (load.freq, load.channel) == (5180, 36)
        assert (load.time_ms, load.busy_ms) == (200_000_000, 60_000_000)
        assert load.load_byte == 255
        assert load.cac_active is False

    def test_utilization_comes_from_counter_delta_not_byte(self):
        a = bss_load_from_get_status(_load("hostapd_get_status_mt76_a.json"))
        b = bss_load_from_get_status(_load("hostapd_get_status_mt76_b.json"))
        result = utilization_from_delta(
            a.as_sample("radio1", 1000.0, 5000.0), b.as_sample("radio1", 1060.0, 5060.0)
        )
        assert result.busy_pct == pytest.approx(38.0)
        assert result.source == SOURCE_HOSTAPD_STATUS
        assert result.rx_pct is None  # get_status has no rx/tx split
        # The byte of the same snapshot claims 0 %.
        assert utilization_from_bss_load(b.load_byte).value == 0.0

    def test_survey_and_get_status_are_never_mixed(self):
        load = bss_load_from_get_status(_load("hostapd_get_status_mt76_b.json"))
        (survey,) = survey_samples_from_iwinfo(
            _load("iwinfo_survey_mt76_a.json"), "radio1", 1000.0, 5000.0, mhz=5180
        )
        result = utilization_from_delta(
            survey, load.as_sample("radio1", 1060.0, 5060.0)
        )
        assert result.reason is UnknownReason.SOURCE_MISMATCH
        assert result.busy_pct is None

    def test_unknown_pair_keeps_the_source(self):
        b = bss_load_from_get_status(_load("hostapd_get_status_mt76_b.json"))
        result = utilization_from_delta(None, b.as_sample("radio1", 1060.0, None))
        assert result.reason is UnknownReason.NO_PREVIOUS
        assert result.source == SOURCE_HOSTAPD_STATUS

    def test_ath10k_bss_color_minus_one_is_kept_raw(self):
        load = bss_load_from_get_status(_load("hostapd_get_status_ath10k_ct.json"))
        assert load is not None
        assert load.channel == 149

    def test_missing_airtime_is_none(self):
        raw = _load("hostapd_get_status_mt76_a.json")
        broken = {k: v for k, v in raw.items() if k != "airtime"}
        assert bss_load_from_get_status(broken) is None
        assert bss_load_from_get_status(None) is None
        bad = {**raw, "airtime": {"time": True, "time_busy": 1, "utilization": 0}}
        assert bss_load_from_get_status(bad) is None


# =====================================================================
# iwinfo assoclist
# =====================================================================


class TestAssoclist:
    def test_counters_per_mac(self):
        counters = assoc_counters_from_assoclist(_load("iwinfo_assoclist_mt76.json"))
        c = counters["02:00:00:00:02:01"]
        assert (c.tx_packets, c.tx_retries, c.tx_failed) == (150_000, 4100, 5400)
        assert c.connected_time_s == 7200
        assert c.inactive_ms == 340
        assert c.signal_dbm == -61
        assert c.noise_dbm == -92
        assert c.tx_rate_kbps == 780_000

    def test_mac_is_lower_case_key(self):
        raw = _load("iwinfo_assoclist_ath9k.json")
        raw["results"][0]["mac"] = raw["results"][0]["mac"].upper()
        assert "02:00:00:00:04:01" in assoc_counters_from_assoclist(raw)

    def test_missing_fields_stay_none(self):
        raw = {"results": [{"mac": "02:00:00:00:09:01", "tx": {"packets": 5}}]}
        c = assoc_counters_from_assoclist(raw)["02:00:00:00:09:01"]
        assert c.tx_packets == 5
        assert c.tx_retries is None
        assert c.connected_time_s is None
        assert assoc_counters_from_assoclist(None) == {}

    def test_noise_zero_is_unknown(self):
        raw = _load("iwinfo_assoclist_mt76.json")
        raw["results"][0]["noise"] = 0
        c = assoc_counters_from_assoclist(raw)["02:00:00:00:02:01"]
        assert c.noise_dbm is None

    def test_ath9k_retry_share_is_classic(self):
        c = assoc_counters_from_assoclist(_load("iwinfo_assoclist_ath9k.json"))[
            "02:00:00:00:04:01"
        ]
        assert c.tx_retries / c.tx_packets == pytest.approx(0.145)
        assert c.tx_failed < c.tx_retries

    def test_mt76_zero_retries_need_wed_off(self):
        counters = assoc_counters_from_assoclist(_load("iwinfo_assoclist_mt76.json"))
        idle = counters["02:00:00:00:02:02"]
        assert idle.tx_retries == 0
        assert mt76_retries_reliable("N") is True
        assert mt76_retries_reliable("Y") is False
        assert mt76_retries_reliable(None) is None
        assert mt76_retries_reliable("maybe") is None

    def test_counter_delta_between_polls(self):
        first = assoc_counters_from_assoclist(_load("iwinfo_assoclist_mt76.json"))
        raw = _load("iwinfo_assoclist_mt76.json")
        raw["results"][0]["tx"]["packets"] += 1000
        second = assoc_counters_from_assoclist(raw)
        mac = "02:00:00:00:02:01"
        delta = counter_delta(first[mac].tx_packets, second[mac].tx_packets)
        assert delta == 1000


def test_reliable_window_from_fixture_counters():
    """End to end: WED off ("N") keeps an mt76 zero retry count measured."""
    c = assoc_counters_from_assoclist(_load("iwinfo_assoclist_mt76.json"))[
        "02:00:00:00:02:02"
    ]
    window = ClientRfWindow(
        client_key="c1",
        radio=RadioRef("ap1", "radio1"),
        band="5g",
        driver="mt7915e",
        window_s=3600.0,
        rssi_mean=float(c.signal_dbm),
        rssi_min=None,
        rssi_stddev=None,
        weak_share=0.0,
        noise=None,
        rate_tx_mean=None,
        rate_tx_trend=None,
        tx_packets=c.tx_packets,
        tx_retries=c.tx_retries,
        tx_failed=c.tx_failed,
        disconnects=0,
        disconnects_weak=0,
        mobility=None,
        demand=None,
        samples=60,
    )
    assert assess_client(window).retry_rate.state is CapabilityState.NO_DATA
    reliable = replace(window, retries_reliable=mt76_retries_reliable("N"))
    assert assess_client(reliable).retry_rate.value == 0.0


# =====================================================================
# hostapd get_clients
# =====================================================================


class TestGetClients:
    def test_get_clients_has_no_connected_time(self):
        for name in (
            "hostapd_get_clients_mt76.json",
            "hostapd_get_clients_ath10k_ct.json",
        ):
            clients = _load(name)["clients"]
            assert all("connected_time" not in c for c in clients.values())

    def test_ath10k_airtime_rx_is_zero(self):
        (client,) = _load("hostapd_get_clients_ath10k_ct.json")["clients"].values()
        assert client["airtime"]["rx"] == 0


# =====================================================================
# iwinfo freqlist
# =====================================================================


class TestFreqlist:
    def test_numeric_band_and_lower_case_flags(self):
        channels = channels_from_freqlist(_load("iwinfo_freqlist_5g_mt76.json"))
        assert {c.band for c in channels} == {BAND_5}
        ch140 = next(c for c in channels if c.channel == 140)
        assert ch140.flags == frozenset({"NO_80MHZ", "NO_160MHZ"})
        assert ch140.restricted is False

    def test_lower_case_width_flag_bans_the_block(self):
        reg = _reg(_load("iwinfo_freqlist_5g_mt76.json"))
        verdict = allowed(block_for(BAND_5, 132, 80), reg)
        assert verdict.ok is False
        assert "flag:NO_80MHZ:132" in verdict.reasons
        assert allowed(block_for(BAND_5, 36, 80), reg).ok is True

    def test_numeric_band_without_mhz(self):
        raw = {"results": [{"band": 5, "channel": 36}, {"band": 2, "channel": 6}]}
        channels = channels_from_freqlist(raw)
        assert [(c.band, c.mhz) for c in channels] == [("5g", 5180), ("2.4g", 2437)]

    def test_unseen_numeric_band_is_not_guessed(self):
        raw = {"results": [{"band": 6, "channel": 37}, {"band": True, "channel": 6}]}
        assert channels_from_freqlist(raw) == []

    def test_all_restricted_list_gives_no_candidates(self):
        reg = _reg(_load("iwinfo_freqlist_5g_ath10k_ct_restricted.json"))
        assert all(c.restricted for c in reg.channels)
        result = candidate_blocks(BAND_5, 20, reg)
        assert result.blocks == ()
