"""Tests for spectrum and regulatory helpers (rf_spectrum.py, pure, no HA)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.rf_spectrum import (
    DFS_BASIS_FREQUENCY_RANGE,
    DFS_BASIS_OUTSIDE_5G,
    DFS_BASIS_UNKNOWN,
    REASON_NO_CHANNEL_LIST,
    Channel,
    OverlapKind,
    RadioRegulatory,
    allowed,
    block_dfs,
    block_for,
    candidate_blocks,
    channels_from_freqlist,
    classify_overlap,
    dfs_info,
    is_dfs,
    overlap_mhz,
    overlap_ratio,
    tx_power_limits,
    txpowers_from_txpowerlist,
)


def _entry(channel, mhz, flags=(), restricted=False, active=False, band=None):
    entry = {
        "channel": channel,
        "mhz": mhz,
        "restricted": restricted,
        "flags": list(flags),
        "active": active,
    }
    if band is not None:
        entry["band"] = band
    return entry


def _synthetic_freqlist():
    """SYNTHETIC iwinfo freqlist, built by hand in the rpcd shape.

    Not captured from a device. Modelled on an ETSI-like regdomain: 2.4 GHz
    channels 1-13 (HT40- impossible on 1-4, HT40+ impossible on 10-13),
    5 GHz 36-64 and 100-140 without 144 (so 140 cannot do 40+/80 MHz).
    Like iwinfo, there is no DFS flag.
    """
    entries = []
    for ch in range(1, 14):
        flags = []
        if ch <= 4:
            flags.append("NO_HT40-")
        if ch >= 10:
            flags.append("NO_HT40+")
        entries.append(_entry(ch, 2407 + 5 * ch, flags, active=ch == 6))
    for ch in [*range(36, 65, 4), *range(100, 141, 4)]:
        flags = ["NO_HT40+", "NO_80MHZ", "NO_160MHZ"] if ch == 140 else []
        entries.append(_entry(ch, 5000 + 5 * ch, flags, active=ch == 36))
    return {"results": entries}


REG = RadioRegulatory(
    channels=tuple(channels_from_freqlist(_synthetic_freqlist())),
    txpower_dbm_list=tuple(range(21)),
    country="DE",
)
NO_LIST = RadioRegulatory(channels=None, txpower_dbm_list=None, country=None)


def _reg(*entries):
    return RadioRegulatory(
        channels=tuple(channels_from_freqlist(list(entries))),
        txpower_dbm_list=None,
        country=None,
    )


# =====================================================================
# Parser
# =====================================================================


class TestChannelsFromFreqlist:
    def test_parses_rpcd_shape(self):
        channels = channels_from_freqlist(_synthetic_freqlist())
        assert len(channels) == 13 + 8 + 11
        first = channels[0]
        assert first == Channel(
            band="2.4g",
            channel=1,
            mhz=2412,
            restricted=False,
            flags=frozenset({"NO_HT40-"}),
            active=False,
        )
        assert [c.channel for c in channels if c.active] == [6, 36]

    def test_accepts_plain_list_and_normalises_flags(self):
        (ch,) = channels_from_freqlist([_entry(36, 5180, ["no_ir"])])
        assert ch.band == "5g"
        assert ch.flags == frozenset({"NO_IR"})

    def test_missing_fields_stay_unknown(self):
        (ch,) = channels_from_freqlist([{"channel": 36, "mhz": 5180}])
        assert ch.restricted is None
        assert ch.flags is None
        assert ch.active is None

    def test_band_from_field_when_mhz_missing(self):
        (ch,) = channels_from_freqlist([{"channel": 36, "band": "5 GHz"}])
        assert ch.band == "5g"
        assert ch.mhz == 5180

    @pytest.mark.parametrize(
        "raw",
        [None, "x", 42, {"results": None}, [None, "x", {"mhz": 5180}, {"channel": 0}]],
    )
    def test_garbage_gives_empty_list(self, raw):
        assert channels_from_freqlist(raw) == []

    def test_entry_without_mhz_and_band_is_skipped(self):
        assert channels_from_freqlist([{"channel": 36}]) == []


class TestRegulatory:
    def test_empty_channel_list_counts_as_unknown(self):
        reg = RadioRegulatory(channels=(), txpower_dbm_list=None, country=None)
        assert reg.channels is None
        assert allowed(block_for("5g", 36, 20), reg).ok is None

    def test_tx_power_limits(self):
        assert tx_power_limits(REG) == (0, 20)
        assert tx_power_limits(NO_LIST) is None

    def test_txpowerlist_parser(self):
        raw = {
            "results": [
                {"dbm": 0, "mw": 1, "active": False},
                {"dbm": 20, "mw": 100, "active": True},
                {"mw": 5},
                "x",
            ]
        }
        assert txpowers_from_txpowerlist(raw) == (0, 20)
        assert txpowers_from_txpowerlist(None) is None
        assert txpowers_from_txpowerlist({"results": []}) is None


# =====================================================================
# Blocks
# =====================================================================


class TestBlockFor:
    def test_5g_80(self):
        block = block_for("5g", 36, 80)
        assert block.center_channel == 42
        assert (block.low_mhz, block.high_mhz) == (5170.0, 5250.0)
        assert block.channels == (36, 40, 44, 48)
        assert block.primary == 36

    def test_5g_160(self):
        assert block_for("5g", 100, 160).channels == tuple(range(100, 129, 4))

    def test_24_40_default_side(self):
        low = block_for("2.4g", 1, 40)
        assert low.channels == (1, 5)
        assert (low.low_mhz, low.high_mhz) == (2402.0, 2442.0)
        assert block_for("2.4g", 11, 40).channels == (7, 11)

    def test_24_40_explicit_side(self):
        assert block_for("2.4g", 6, 40, htmode="HT40+").channels == (6, 10)
        assert block_for("2.4g", 6, 40, htmode="HT40-").channels == (2, 6)

    def test_24_20_uses_real_20_mhz(self):
        block = block_for("2.4g", 6, 20)
        assert (block.low_mhz, block.high_mhz) == (2427.0, 2447.0)

    def test_6g_320(self):
        block = block_for("6g", 1, 320)
        assert block.channels == tuple(range(1, 62, 4))

    def test_center_override(self):
        assert block_for("5g", 36, 80, center_channel=42).center_channel == 42
        assert block_for("5g", 36, 80, center_channel=58) is None

    @pytest.mark.parametrize(
        ("band", "channel", "width", "htmode"),
        [
            ("2.4g", 1, 80, None),
            ("2.4g", 1, 40, "HT40-"),
            ("2.4g", 13, 40, "HT40+"),
            ("5g", 181, 80, None),
            ("5g", 36, 30, None),
            ("5g", 36, 320, None),
            ("6g", 2, 20, None),
            ("60g", 1, 20, None),
            ("5g", 0, 20, None),
        ],
    )
    def test_invalid_blocks(self, band, channel, width, htmode):
        assert block_for(band, channel, width, htmode=htmode) is None


# =====================================================================
# DFS (case 18)
# =====================================================================


class TestDfs:
    @pytest.mark.parametrize(
        ("mhz", "dfs"),
        [
            (5180, False),
            (5240, False),
            (5260, True),
            (5320, True),
            (5500, True),
            (5720, True),
            (5745, False),
        ],
    )
    def test_case_18_dfs_channels_from_frequency_range(self, mhz, dfs):
        info = dfs_info(mhz)
        assert info.dfs is dfs
        assert info.basis == DFS_BASIS_FREQUENCY_RANGE
        assert is_dfs(mhz) is dfs

    def test_case_18_outside_5ghz_is_false(self):
        assert dfs_info(2437).dfs is False
        assert dfs_info(2437).basis == DFS_BASIS_OUTSIDE_5G
        assert dfs_info(5975).dfs is False

    def test_case_18_unknown_frequency(self):
        assert dfs_info(None).dfs is None
        assert dfs_info(None).basis == DFS_BASIS_UNKNOWN
        assert is_dfs("x") is None

    def test_case_18_block_with_one_dfs_subchannel_is_dfs(self):
        assert block_dfs(block_for("5g", 36, 160)).dfs is True  # 36-64
        assert block_dfs(block_for("5g", 36, 80)).dfs is False
        assert block_dfs(block_for("5g", 100, 20)).dfs is True
        info = block_dfs(block_for("2.4g", 6, 20))
        assert (info.dfs, info.basis) == (False, DFS_BASIS_OUTSIDE_5G)

    def test_review_l2_block_basis_says_not_reported_by_radio(self):
        # The verdict a caller gets, not just the constant.
        for channel in (52, 100):
            basis = block_dfs(block_for("5g", channel, 20)).basis
            assert basis == DFS_BASIS_FREQUENCY_RANGE
            assert "not_reported" in basis


# =====================================================================
# Regulatory limits (case 19)
# =====================================================================


class TestAllowed:
    def test_case_19_listed_block_is_allowed(self):
        result = allowed(block_for("5g", 36, 80), REG)
        assert result.ok is True
        assert result.reasons == ()

    def test_case_19_unlisted_subchannel_blocks(self):
        result = allowed(block_for("5g", 132, 80), REG)  # needs 144
        assert result.ok is False
        assert "not_listed:144" in result.reasons

    def test_case_19_width_flag_blocks(self):
        result = allowed(block_for("5g", 140, 20), REG)
        assert result.ok is True
        result = allowed(block_for("5g", 136, 40), REG)  # fixed pair 132+136
        assert result.ok is True
        result = allowed(block_for("5g", 140, 40), REG)  # fixed pair 140+144
        assert result.ok is False
        assert set(result.reasons) == {"flag:NO_HT40+:140", "not_listed:144"}

    def test_case_19_no_80mhz_flag(self):
        reg = _reg(
            *(
                _entry(ch, 5000 + 5 * ch, ["NO_80MHZ"] if ch == 104 else [])
                for ch in (100, 104, 108, 112)
            )
        )
        result = allowed(block_for("5g", 100, 80), reg)
        assert result.ok is False
        assert result.reasons == ("flag:NO_80MHZ:104",)

    def test_case_19_ht40_side_flags_on_24(self):
        reg = _reg(_entry(6, 2437, ["NO_HT40+"]), _entry(10, 2457))
        result = allowed(block_for("2.4g", 6, 40, htmode="HT40+"), reg)
        assert result.ok is False
        assert result.reasons == ("flag:NO_HT40+:6",)
        reg = _reg(_entry(2, 2417), _entry(6, 2437, ["NO_HT40+"]))
        assert allowed(block_for("2.4g", 6, 40, htmode="HT40-"), reg).ok is True

    def test_case_19_no_ir_and_restricted(self):
        reg = _reg(_entry(36, 5180, ["NO_IR"]), _entry(40, 5200, restricted=True))
        result = allowed(block_for("5g", 36, 40), reg)
        assert result.ok is False
        assert set(result.reasons) == {"flag:NO_IR:36", "restricted:40"}

    def test_case_19_no_20mhz_flag(self):
        reg = _reg(_entry(36, 5180, ["NO_20MHZ"]))
        assert allowed(block_for("5g", 36, 20), reg).ok is False

    def test_case_19_unknown_flags_or_restricted_give_none(self):
        reg = _reg({"channel": 36, "mhz": 5180})
        result = allowed(block_for("5g", 36, 20), reg)
        assert result.ok is None
        assert set(result.reasons) == {"restricted_unknown:36", "flags_unknown:36"}

    def test_case_19_definite_ban_beats_unknown(self):
        reg = _reg({"channel": 36, "mhz": 5180}, _entry(40, 5200, ["NO_IR"]))
        assert allowed(block_for("5g", 36, 40), reg).ok is False

    def test_case_19_320_width_flag_not_reported(self):
        reg = _reg(*(_entry(ch, 5950 + 5 * ch) for ch in range(1, 62, 4)))
        result = allowed(block_for("6g", 1, 320), reg)
        assert result.ok is None
        assert result.reasons == ("width_not_checked:320",)

    def test_case_25_no_channel_list_is_unknown(self):
        result = allowed(block_for("5g", 36, 80), NO_LIST)
        assert result.ok is None
        assert result.reasons == (REASON_NO_CHANNEL_LIST,)
        assert allowed(block_for("5g", 36, 80), None).ok is None

    def test_case_19_candidates_only_allowed_blocks(self):
        result = candidate_blocks("5g", 80, REG)
        assert [b.center_channel for b in result.blocks] == [42, 58, 106, 122]
        assert result.reason is None

    def test_case_19_candidates_24_20(self):
        result = candidate_blocks("2.4g", 20, REG)
        assert [b.primary for b in result.blocks] == list(range(1, 14))

    def test_case_19_candidates_24_40_both_sides(self):
        blocks = candidate_blocks("2.4g", 40, REG).blocks
        spans = {b.channels for b in blocks}
        assert (1, 5) in spans
        assert (9, 13) in spans
        # HT40- on 1-4 impossible, HT40+ on 10-13 impossible
        assert all(1 <= ch <= 13 for span in spans for ch in span)

    def test_case_25_no_list_gives_no_candidates_and_reason(self):
        result = candidate_blocks("5g", 80, NO_LIST)
        assert result.blocks == ()
        assert result.reason == REASON_NO_CHANNEL_LIST

    def test_candidates_for_band_not_in_list(self):
        result = candidate_blocks("6g", 20, REG)
        assert result.blocks == ()
        assert result.reason == "no_channel_of_band"


# =====================================================================
# Overlap
# =====================================================================


class TestOverlap:
    def test_24_non_overlapping(self):
        a, b = block_for("2.4g", 1, 20), block_for("2.4g", 6, 20)
        assert overlap_mhz(a, b) == 0
        assert classify_overlap(a, b) is OverlapKind.NONE

    def test_24_touching_edges_do_not_overlap(self):
        a, b = block_for("2.4g", 1, 20), block_for("2.4g", 5, 20)
        assert overlap_mhz(a, b) == 0

    def test_24_partial(self):
        a, b = block_for("2.4g", 1, 20), block_for("2.4g", 3, 20)
        assert overlap_mhz(a, b) == 10
        assert overlap_ratio(a, b) == pytest.approx(0.5)
        assert classify_overlap(a, b) is OverlapKind.ADJACENT_OVERLAP

    def test_24_40_mhz_uses_reported_width(self):
        a = block_for("2.4g", 6, 40, htmode="HT40+")  # 2427-2467
        b = block_for("2.4g", 11, 20)  # 2452-2472
        assert overlap_mhz(a, b) == 15
        assert overlap_ratio(a, b) == pytest.approx(0.75)  # of the narrower
        assert classify_overlap(a, b) is OverlapKind.ADJACENT_OVERLAP

    def test_same_primary_is_co_channel(self):
        a, b = block_for("2.4g", 6, 20), block_for("2.4g", 6, 20)
        assert classify_overlap(a, b) is OverlapKind.CO_CHANNEL
        assert overlap_ratio(a, b) == 1.0
        a, b = block_for("5g", 36, 80), block_for("5g", 36, 20)
        assert classify_overlap(a, b) is OverlapKind.CO_CHANNEL

    def test_identical_block_is_co_channel(self):
        a, b = block_for("5g", 36, 80), block_for("5g", 40, 80)
        assert classify_overlap(a, b) is OverlapKind.CO_CHANNEL

    def test_5g_wide_contains_narrow(self):
        a, b = block_for("5g", 36, 80), block_for("5g", 44, 20)
        assert overlap_ratio(a, b) == 1.0
        assert classify_overlap(a, b) is OverlapKind.ADJACENT_OVERLAP

    def test_5g_neighbouring_80_blocks(self):
        a, b = block_for("5g", 36, 80), block_for("5g", 52, 80)
        assert classify_overlap(a, b) is OverlapKind.NONE

    def test_different_bands_never_overlap(self):
        a, b = block_for("2.4g", 1, 20), block_for("6g", 1, 20)
        assert overlap_mhz(a, b) == 0
        assert classify_overlap(a, b) is OverlapKind.NONE
