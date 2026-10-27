"""Tests for the Wi-Fi channel plan analysis (F2): channel_plan.py, fleet, sensor."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.channel_plan import (
    FINDING_DFS,
    FINDING_NON_STANDARD_24,
    FINDING_OVERLAP,
    FINDING_SAME_CHANNEL,
    Radio,
    analyze,
    format_finding,
    htmode_width,
    radios_from_ap_interfaces,
)
from custom_components.openwrt_router.fleet import (
    CHANNEL_CONFLICT_POLLS,
    ChannelPlanMonitor,
    async_get_channel_plan_monitor,
    collect_radios,
)


def _iface(ifname, channel, htmode="HE20", freq=None, phy=None, center=None, band=None):
    if freq is None:
        if channel <= 14:
            freq = 2484 if channel == 14 else 2407 + 5 * channel
        else:
            freq = 5000 + 5 * channel
    iface = {
        "ifname": ifname,
        "channel": channel,
        "htmode": htmode,
        "frequency": freq,
        "phy": phy if phy is not None else ifname.split("-")[0],
        "center_chan1": center,
    }
    if band is not None:
        iface["band"] = band
    return iface


def _radios(entry_id, ifaces):
    return radios_from_ap_interfaces(entry_id, f"Router {entry_id}", ifaces)


def _types(findings):
    return sorted(f["type"] for f in findings)


# =====================================================================
# Parsing / normalisation
# =====================================================================


class TestHtmodeWidth:
    @pytest.mark.parametrize(
        ("htmode", "width"),
        [
            ("HT20", 20),
            ("HT40+", 40),
            ("HT40-", 40),
            ("VHT80", 80),
            ("HE160", 160),
            ("EHT320", 320),
            ("NOHT", 20),
            (None, 20),
            ("", 20),
            ("HE70", 20),
            (42, 20),
        ],
    )
    def test_width(self, htmode, width):
        assert htmode_width(htmode) == width


class TestRadiosFromApInterfaces:
    def test_two_ssids_on_one_radio_are_one_radio(self):
        radios = _radios(
            "gw",
            [_iface("phy1-ap0", 36), _iface("phy1-ap1", 36), _iface("phy0-ap0", 1)],
        )
        assert sorted(r.phy for r in radios) == ["phy0", "phy1"]

    def test_phy_derived_from_ifname_when_missing(self):
        iface = _iface("phy1-ap0", 36)
        iface["phy"] = None
        (radio,) = _radios("gw", [iface])
        assert radio.phy == "phy1"

    @pytest.mark.parametrize(
        "bad",
        [
            {"ifname": "phy0-ap0", "channel": None, "frequency": 2412},
            {"ifname": "phy0-ap0", "channel": "x", "frequency": 2412},
            {"ifname": "phy0-ap0", "channel": 0, "frequency": 2412},
            {"ifname": "phy0-ap0", "channel": 6},  # no band at all
            {"ifname": "phy0-ap0", "channel": 6, "band": "unknown"},
            "not-a-dict",
        ],
    )
    def test_unusable_interfaces_are_skipped(self, bad):
        assert _radios("gw", [bad]) == []

    def test_none_and_empty(self):
        assert _radios("gw", None) == []
        assert _radios("gw", []) == []

    def test_band_from_band_key_without_frequency(self):
        (radio,) = _radios(
            "gw", [{"ifname": "default_radio1", "channel": 36, "band": "5g", "phy": "radio1"}]
        )
        assert (radio.band, radio.channel, radio.width) == ("5g", 36, 20)

    def test_6ghz_detected_from_frequency(self):
        (radio,) = _radios("gw", [_iface("phy2-ap0", 5, freq=5975)])
        assert radio.band == "6g"

    def test_center_from_iwinfo_is_used(self):
        (radio,) = _radios("gw", [_iface("phy1-ap0", 36, "HE80", center=42)])
        assert radio.center == 42
        assert radio.subchannels() == [36, 40, 44, 48]

    @pytest.mark.parametrize(
        ("channel", "htmode", "center", "subs"),
        [
            (44, "HE40", 46, [44, 48]),
            (48, "HE40", 46, [44, 48]),
            (36, "HE160", 50, [36, 40, 44, 48, 52, 56, 60, 64]),
            (64, "VHT160", 50, [36, 40, 44, 48, 52, 56, 60, 64]),
            (100, "VHT80", 106, [100, 104, 108, 112]),
            (149, "HE80", 155, [149, 153, 157, 161]),
        ],
    )
    def test_center_derived_for_5ghz_blocks(self, channel, htmode, center, subs):
        (radio,) = _radios("gw", [_iface("phy1-ap0", channel, htmode)])
        assert radio.center == center
        assert radio.subchannels() == subs

    def test_center_derived_for_6ghz(self):
        (radio,) = _radios("gw", [_iface("phy2-ap0", 37, "HE80", freq=6135)])
        # 80 MHz blocks in 6 GHz: 33–45 → center 39
        assert radio.center == 39

    def test_24ghz_ht40_minus_and_plus(self):
        (minus,) = _radios("gw", [_iface("phy0-ap0", 11, "HT40-")])
        (plus,) = _radios("ap", [_iface("phy0-ap0", 1, "HT40+")])
        assert minus.center == 9
        assert plus.center == 3

    def test_24ghz_width_capped_at_40(self):
        (radio,) = _radios("gw", [_iface("phy0-ap0", 6, "HE80")])
        assert radio.width == 40


# =====================================================================
# analyze
# =====================================================================


class TestAnalyze:
    def test_live_like_plan_has_no_findings(self):
        """1/6/11 and 36@40 MHz, 44, 48 on three routers (state 2026-10-27)."""
        radios = (
            _radios("gw", [_iface("phy0-ap0", 1), _iface("phy1-ap0", 36, "HE40", center=38)])
            + _radios("ap2", [_iface("phy0-ap0", 6), _iface("phy1-ap0", 44)])
            + _radios("ap4", [_iface("phy0-ap0", 11), _iface("phy1-ap0", 48)])
        )
        assert analyze(radios) == []

    def test_same_channel_between_routers(self):
        radios = _radios("gw", [_iface("phy1-ap0", 36)]) + _radios(
            "ap2", [_iface("phy1-ap0", 36, "HE80")]
        )
        (finding,) = analyze(radios)
        assert finding["type"] == FINDING_SAME_CHANNEL
        assert finding["band"] == "5g"
        assert finding["entry_ids"] == ["ap2", "gw"]
        assert [r["router"] for r in finding["radios"]] == ["Router ap2", "Router gw"]

    def test_two_ssids_on_one_radio_give_no_finding(self):
        radios = _radios(
            "gw", [_iface("phy1-ap0", 36), _iface("phy1-ap1", 36), _iface("phy1-ap2", 36)]
        )
        assert analyze(radios) == []

    def test_two_radios_of_one_router_same_channel(self):
        radios = _radios("gw", [_iface("phy1-ap0", 36), _iface("phy2-ap0", 36)])
        assert _types(analyze(radios)) == [FINDING_SAME_CHANNEL]

    def test_overlap_40mhz_block_44_48(self):
        radios = _radios("gw", [_iface("phy1-ap0", 44, "HE40")]) + _radios(
            "ap2", [_iface("phy1-ap0", 48, "HE40")]
        )
        assert _types(analyze(radios)) == [FINDING_OVERLAP]

    def test_overlap_40mhz_with_20mhz_neighbour_in_block(self):
        radios = _radios("gw", [_iface("phy1-ap0", 44, "HT40")]) + _radios(
            "ap2", [_iface("phy1-ap0", 48)]
        )
        assert _types(analyze(radios)) == [FINDING_OVERLAP]

    def test_adjacent_blocks_do_not_overlap(self):
        radios = _radios("gw", [_iface("phy1-ap0", 36, "HE40")]) + _radios(
            "ap2", [_iface("phy1-ap0", 44, "HE40")]
        )
        assert analyze(radios) == []

    def test_160mhz_on_36_covers_36_to_64(self):
        radios = _radios("gw", [_iface("phy1-ap0", 36, "HE160")]) + _radios(
            "ap2", [_iface("phy1-ap0", 64)]
        )
        types = _types(analyze(radios))
        # overlap between the routers, DFS for both radios (52–64 are DFS)
        assert types == [FINDING_DFS, FINDING_DFS, FINDING_OVERLAP]

    def test_160mhz_does_not_reach_100(self):
        radios = _radios("gw", [_iface("phy1-ap0", 36, "HE160")]) + _radios(
            "ap2", [_iface("phy1-ap0", 100)]
        )
        assert FINDING_OVERLAP not in _types(analyze(radios))

    def test_dfs_only_with_subchannel_in_range(self):
        radios = (
            _radios("a", [_iface("phy1-ap0", 48)])
            + _radios("b", [_iface("phy1-ap0", 52)])
            + _radios("c", [_iface("phy1-ap0", 144)])
            + _radios("d", [_iface("phy1-ap0", 149)])
            + _radios("e", [_iface("phy1-ap0", 36, "HE80")])
        )
        dfs = [f["entry_ids"][0] for f in analyze(radios) if f["type"] == FINDING_DFS]
        assert sorted(dfs) == ["b", "c"]

    def test_non_standard_24(self):
        radios = _radios("gw", [_iface("phy0-ap0", 3)])
        (finding,) = analyze(radios)
        assert finding["type"] == FINDING_NON_STANDARD_24
        assert finding["band"] == "2.4g"

    def test_24ghz_overlap_with_neighbour(self):
        radios = _radios("gw", [_iface("phy0-ap0", 1)]) + _radios(
            "ap2", [_iface("phy0-ap0", 4)]
        )
        assert _types(analyze(radios)) == [FINDING_NON_STANDARD_24, FINDING_OVERLAP]

    def test_24ghz_1_6_11_and_1_5_touching_do_not_overlap(self):
        radios = (
            _radios("gw", [_iface("phy0-ap0", 1)])
            + _radios("ap2", [_iface("phy0-ap0", 6)])
            + _radios("ap4", [_iface("phy0-ap0", 11)])
        )
        assert analyze(radios) == []

    def test_24ghz_40mhz_on_1_overlaps_6(self):
        radios = _radios("gw", [_iface("phy0-ap0", 1, "HT40+")]) + _radios(
            "ap2", [_iface("phy0-ap0", 6)]
        )
        assert _types(analyze(radios)) == [FINDING_OVERLAP]

    def test_bands_are_never_compared(self):
        radios = _radios("gw", [_iface("phy0-ap0", 1)]) + _radios(
            "ap2", [_iface("phy2-ap0", 1, freq=5955)]
        )
        assert analyze(radios) == []

    def test_findings_are_sorted_by_type(self):
        radios = _radios("gw", [_iface("phy0-ap0", 3), _iface("phy1-ap0", 52)]) + _radios(
            "ap2", [_iface("phy1-ap0", 52)]
        )
        assert [f["type"] for f in analyze(radios)] == [
            FINDING_SAME_CHANNEL,
            FINDING_NON_STANDARD_24,
            FINDING_DFS,
            FINDING_DFS,
        ]

    def test_format_finding(self):
        radios = _radios("gw", [_iface("phy1-ap0", 44, "HE40")]) + _radios(
            "ap2", [_iface("phy1-ap0", 48, "HE40")]
        )
        (finding,) = analyze(radios)
        assert format_finding(finding) == (
            "overlap (5 GHz): Router ap2 phy1 ch 48/40 MHz + Router gw phy1 ch 44/40 MHz"
        )


# =====================================================================
# Fleet: collect_radios + ChannelPlanMonitor
# =====================================================================


def _entry(entry_id, ifaces, success=True):
    entry = MagicMock()
    entry.entry_id = entry_id
    entry.title = f"Router {entry_id}"
    entry.runtime_data.coordinator.last_update_success = success
    entry.runtime_data.coordinator.data.ap_interfaces = ifaces
    return entry


class _Fleet:
    def __init__(self):
        self.hass = MagicMock()
        self.hass.data = {}
        self.entries: list = []
        self.hass.config_entries.async_loaded_entries = MagicMock(
            side_effect=lambda domain: list(self.entries)
        )
        self._p = patch("custom_components.openwrt_router.issues.ir")
        self.ir = self._p.start()
        self.monitor = ChannelPlanMonitor(self.hass)

    def set(self, **routers):
        self.entries = [_entry(eid, ifaces) for eid, ifaces in routers.items()]

    @property
    def created(self):
        return self.ir.async_create_issue.call_args_list

    @property
    def deleted(self):
        return [c.args[2] for c in self.ir.async_delete_issue.call_args_list]

    def stop(self):
        self._p.stop()


@pytest.fixture
def fleet():
    f = _Fleet()
    yield f
    f.stop()


CONFLICT = {"gw": [_iface("phy1-ap0", 36)], "ap2": [_iface("phy1-ap0", 36)]}


class TestCollectRadios:
    def test_skips_failed_and_incomplete_entries(self, fleet):
        ok = _entry("gw", [_iface("phy1-ap0", 36)])
        down = _entry("ap2", [_iface("phy1-ap0", 36)], success=False)
        no_runtime = MagicMock(entry_id="x", title="x", runtime_data=None)
        no_data = _entry("ap4", [])
        no_data.runtime_data.coordinator.data = None
        fleet.entries = [ok, down, no_runtime, no_data]
        radios = collect_radios(fleet.hass)
        assert [(r.entry_id, r.phy) for r in radios] == [("gw", "phy1")]

    def test_monitor_is_a_singleton(self, fleet):
        assert async_get_channel_plan_monitor(fleet.hass) is async_get_channel_plan_monitor(
            fleet.hass
        )


class TestChannelPlanMonitor:
    def test_raised_after_two_polls_of_an_involved_router(self, fleet):
        fleet.set(**CONFLICT)
        fleet.monitor.evaluate("gw")
        assert not fleet.created
        fleet.monitor.evaluate("ap2")  # other router: its first sighting
        assert not fleet.created
        fleet.monitor.evaluate("gw")
        assert CHANNEL_CONFLICT_POLLS == 2
        (call,) = fleet.created
        assert call.args[1:3] == ("openwrt_router", "channel_plan_conflict")
        assert call.kwargs["translation_key"] == "channel_plan_conflict"
        placeholders = call.kwargs["translation_placeholders"]
        assert placeholders["count"] == "1"
        assert placeholders["findings"].startswith("- same_channel (5 GHz): ")

    def test_uninvolved_router_does_not_count(self, fleet):
        fleet.set(**CONFLICT, ap4=[_iface("phy1-ap0", 149)])
        for _ in range(3):
            fleet.monitor.evaluate("ap4")
        assert not fleet.created

    def test_interruption_resets_streak(self, fleet):
        fleet.set(**CONFLICT)
        fleet.monitor.evaluate("gw")
        fleet.set(gw=[_iface("phy1-ap0", 36)], ap2=[_iface("phy1-ap0", 44)])
        fleet.monitor.evaluate("ap2")  # no conflict anywhere → all streaks reset
        fleet.set(**CONFLICT)
        fleet.monitor.evaluate("ap2")
        assert not fleet.created
        fleet.monitor.evaluate("ap2")
        assert len(fleet.created) == 1

    def test_dfs_only_never_raises(self, fleet):
        fleet.set(gw=[_iface("phy1-ap0", 36, "HE160")], ap2=[_iface("phy1-ap0", 100)])
        for _ in range(4):
            fleet.monitor.evaluate("gw")
            fleet.monitor.evaluate("ap2")
        assert not fleet.created

    def test_non_standard_24_counts_as_conflict(self, fleet):
        fleet.set(gw=[_iface("phy0-ap0", 3)])
        fleet.monitor.evaluate("gw")
        fleet.monitor.evaluate("gw")
        assert len(fleet.created) == 1

    def test_cleared_once_conflicts_are_gone(self, fleet):
        fleet.set(**CONFLICT)
        for _ in range(2):
            fleet.monitor.evaluate("gw")
        fleet.set(gw=[_iface("phy1-ap0", 36)], ap2=[_iface("phy1-ap0", 44)])
        fleet.monitor.evaluate("ap2")
        assert fleet.deleted == ["channel_plan_conflict"]
        fleet.monitor.evaluate("ap2")
        assert fleet.deleted == ["channel_plan_conflict"]  # only once

    def test_issue_updated_only_when_findings_change(self, fleet):
        fleet.set(**CONFLICT)
        for _ in range(4):
            fleet.monitor.evaluate("gw")
        assert len(fleet.created) == 1
        fleet.set(**CONFLICT, ap4=[_iface("phy1-ap0", 36)])
        fleet.monitor.evaluate("ap4")
        assert len(fleet.created) == 2
        assert fleet.created[-1].kwargs["translation_placeholders"]["count"] == "3"

    def test_unregister_clears_when_last_conflict_partner_leaves(self, fleet):
        fleet.set(**CONFLICT)
        for _ in range(2):
            fleet.monitor.evaluate("gw")
        # ap2 is being unloaded: HA no longer lists it as loaded
        fleet.set(gw=CONFLICT["gw"])
        fleet.monitor.unregister("ap2")
        assert fleet.deleted == ["channel_plan_conflict"]

    def test_unregister_without_issue_is_quiet(self, fleet):
        fleet.set(**CONFLICT)
        fleet.monitor.evaluate("gw")
        fleet.monitor.unregister("gw")
        assert not fleet.created
        assert fleet.deleted == []


# =====================================================================
# Sensor
# =====================================================================


class TestChannelPlanSensor:
    def _sensor(self, fleet, entry_id="gw"):
        from custom_components.openwrt_router.sensor import OpenWrtChannelPlanSensor

        entry = next(e for e in fleet.entries if e.entry_id == entry_id)
        coordinator = entry.runtime_data.coordinator
        coordinator.router_info = {}
        sensor = OpenWrtChannelPlanSensor(coordinator, entry)
        sensor.hass = fleet.hass
        return sensor

    def test_unique_id_and_category(self, fleet):
        from homeassistant.const import EntityCategory

        fleet.set(**CONFLICT)
        sensor = self._sensor(fleet)
        assert sensor.unique_id == "gw_channel_plan"
        assert sensor.entity_category == EntityCategory.DIAGNOSTIC
        for legacy in ("_rate", "_ap_", "_port_", "_radio_", "_iface_"):
            assert legacy not in sensor.unique_id

    def test_counts_own_findings_across_routers(self, fleet):
        fleet.set(
            gw=[_iface("phy1-ap0", 36, "HE160"), _iface("phy0-ap0", 1)],
            ap2=[_iface("phy1-ap0", 44)],
            ap4=[_iface("phy0-ap0", 3)],
        )
        sensor = self._sensor(fleet, "gw")
        # gw: dfs (36@160), 5 GHz overlap with ap2, 2.4 GHz overlap 1↔3 with
        # ap4; ap4's non_standard_24 is not gw's
        assert sensor.native_value == 3
        attrs = sensor.extra_state_attributes
        assert sorted(f["type"] for f in attrs["findings"]) == [
            FINDING_DFS,
            FINDING_OVERLAP,
            FINDING_OVERLAP,
        ]
        assert all("entry_ids" not in f for f in attrs["findings"])
        assert {r["radio"] for r in attrs["radios"]} == {"phy0", "phy1"}
        assert self._sensor(fleet, "ap4").native_value == 2

    def test_without_hass_returns_zero(self, fleet):
        fleet.set(**CONFLICT)
        sensor = self._sensor(fleet)
        sensor.hass = None
        assert sensor.native_value == 0
        assert sensor.extra_state_attributes == {"findings": [], "radios": []}


# =====================================================================
# API: iwinfo fields kept for the channel plan
# =====================================================================


class TestApInterfaceFields:
    @pytest.mark.asyncio
    async def test_phy_and_center_are_kept(self):
        from custom_components.openwrt_router.api import OpenWrtAPI

        api = OpenWrtAPI(
            host="router.test",
            port=80,
            username="root",
            password="test",
            session=MagicMock(),
            protocol="http",
        )
        api._hostapd_ifaces = ["phy1-ap0"]
        api._call = AsyncMock(
            return_value={
                "ssid": "Test",
                "mode": "Master",
                "channel": 36,
                "center_chan1": 42,
                "htmode": "HE80",
                "frequency": 5180,
                "phy": "phy1",
            }
        )
        (iface,) = await api.get_ap_interface_details()
        assert iface["phy"] == "phy1"
        assert iface["center_chan1"] == 42
        (radio,) = radios_from_ap_interfaces("gw", "Router", [iface])
        assert radio == Radio(
            entry_id="gw", router="Router", phy="phy1", band="5g", channel=36, width=80, center=42
        )
