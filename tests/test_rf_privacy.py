"""RF output masking on top of core_masking (rf_privacy.py)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.core_masking import (
    MASK,
    is_secret_key,
    mask_for_output,
)
from custom_components.openwrt_router.core_models import default_router_id
from custom_components.openwrt_router.rf_clients import (
    ClientRfWindow,
    assess_client,
    summarize_radio_clients,
)
from custom_components.openwrt_router.rf_conflicts import (
    RadioRef,
    RadioView,
    detect_conflicts,
)
from custom_components.openwrt_router.rf_models import (
    METRIC_NOISE,
    SOURCE_HOSTAPD_STATUS,
    CapabilityState,
    RadioCapabilities,
    metric_measured,
)
from custom_components.openwrt_router.rf_privacy import (
    IDENTIFIER_KEYS,
    REFERENCE_KEYS,
    mask_rf_output,
)
from custom_components.openwrt_router.rf_recommend import Recommendation
from custom_components.openwrt_router.rf_roaming import (
    ClientRoamWindow,
    RoamEvent,
    detect_flapping,
    roaming_quality,
)
from custom_components.openwrt_router.rf_scan_policy import sanitize_neighbors

R1 = default_router_id("e1")
R2 = default_router_id("e2")
MAC = "aa:bb:cc:dd:ee:01"
MAC_FORMS = (MAC, MAC.upper(), "aa-bb-cc-dd-ee-01", "aabb.ccdd.ee01", "aabbccddee01")
OWN_BSSID = "02:11:22:33:44:55"
SALT = b"test-salt-0123456789abcdef"


def _text(data):
    return repr(data)


def _no_mac(data):
    text = _text(data).lower()
    for form in MAC_FORMS:
        assert form.lower() not in text


class TestCoreGap:
    """What core_masking does NOT do (reported as a Core gap)."""

    def test_core_does_not_mask_ssid_bssid_or_mac(self):
        data = {"ssid": "Home", "bssid": MAC, "mac": MAC, "note": f"client {MAC}"}
        assert mask_for_output(data) == data

    def test_core_over_masks_rf_reference_keys(self):
        # "key" is a secret word for the core: router_key/radio_key would be
        # wiped, so RF cannot hand its as_dict forms to mask_for_output.
        for name in ("router_key", "radio_key", "key", "client_key"):
            assert is_secret_key(name)
        assert mask_for_output({"router_key": R1})["router_key"] == MASK


class TestMaskRfOutput:
    def test_identifier_keys_become_the_core_placeholder(self):
        data = {k: "x" for k in ("ssid", "ssids", "bssid", "mac", "hostname", "ip")}
        data["client_key"] = MAC
        out = mask_rf_output(data)
        assert set(out.values()) == {MASK}
        assert {"ssid", "bssid", "mac", "client_key"} <= IDENTIFIER_KEYS

    @pytest.mark.parametrize("form", MAC_FORMS)
    def test_macs_in_free_text_are_masked(self, form):
        out = mask_rf_output({"evidence": [f"roam:{form}->x", f"x {form} y"]})
        _no_mac(out)
        assert out["evidence"] == [f"roam:{MASK}->x", f"x {MASK} y"]

    def test_reference_keys_and_rf_codes_stay_readable(self):
        data = {
            "router_key": R1,
            "radio_key": "radio0",
            "evidence": [f"utilization:{R1}/radio0:78.0%:hostapd.get_status"],
            "kind": "co_channel",
            "coverage": 0.5,
            "count": 3,
            "flag": None,
        }
        assert mask_rf_output(data) == data
        assert {"router_key", "radio_key", "key"} <= REFERENCE_KEYS

    def test_a_mac_under_a_reference_key_is_masked(self):
        assert mask_rf_output({"key": OWN_BSSID}) == {"key": MASK}

    def test_secret_keys_use_the_core_rule(self):
        out = mask_rf_output({"password": "hunter2", "nested": {"token": "abc"}})
        assert out == {"password": MASK, "nested": {"token": MASK}}

    def test_core_text_redaction_runs_on_strings(self):
        out = mask_rf_output({"note": "url http://root:hunter2@10.0.0.1/"})
        assert "hunter2" not in _text(out)

    def test_accepts_objects_with_as_dict_and_sequences(self):
        ref = RadioRef(R1, "radio0")
        assert mask_rf_output(ref) == {"router_key": R1, "radio_key": "radio0"}
        assert mask_rf_output([ref]) == [{"router_key": R1, "radio_key": "radio0"}]
        assert mask_rf_output((1, "a")) == [1, "a"]

    def test_input_is_not_changed(self):
        data = {"client_key": MAC, "inner": {"mac": MAC}}
        mask_rf_output(data)
        assert data == {"client_key": MAC, "inner": {"mac": MAC}}

    def test_idempotent(self):
        data = {"client_key": MAC, "evidence": [f"a:{MAC}"], "router_key": R1}
        once = mask_rf_output(data)
        assert mask_rf_output(once) == once

    def test_unknown_objects_are_refused(self):
        with pytest.raises(TypeError):
            mask_rf_output(object())


# ---------------------------------------------------------------------------
# Every RF output form that can carry an identifier
# ---------------------------------------------------------------------------


def _window(**kw):
    base = {
        "client_key": MAC,
        "radio": RadioRef(R1, "radio0"),
        "band": "5g",
        "driver": "mt7915e",
        "window_s": 3600.0,
        "rssi_mean": -82.0,
        "rssi_min": -88.0,
        "rssi_stddev": 2.0,
        "weak_share": 0.9,
        "noise": metric_measured(-95, "iwinfo.info", measured_at=1.0),
        "rate_tx_mean": 20.0,
        "rate_tx_trend": -40.0,
        "tx_packets": 1000,
        "tx_retries": 400,
        "tx_failed": 50,
        "disconnects": 4,
        "disconnects_weak": 3,
        "mobility": "stationary",
        "demand": "high",
        "samples": 60,
        "retries_reliable": True,
    }
    base.update(kw)
    return ClientRfWindow(**base)


def _roams():
    a, b = RadioRef(R1, "radio0"), RadioRef(R2, "radio0")
    events = tuple(
        RoamEvent(
            client_key=MAC,
            ts=100.0 * i,
            from_radio=a if i % 2 == 0 else b,
            to_radio=b if i % 2 == 0 else a,
            from_band="5g",
            to_band="5g",
            rssi_before=-75.0,
            rssi_after=-70.0,
            gap_s=0.5,
            auth_failures=1,
            reauth=False,
        )
        for i in range(6)
    )
    return ClientRoamWindow(
        client_key=MAC, window_s=3600.0, online_s=3600.0, events=events, mobility=None
    )


def _outputs():
    view = RadioView(
        router_key=R1,
        radio_key="radio0",
        band="2.4g",
        channel=6,
        width_mhz=20,
        utilization=metric_measured(78.0, SOURCE_HOSTAPD_STATUS, measured_at=1.0),
    )
    other = RadioView(
        router_key=R2, radio_key="radio0", band="2.4g", channel=6, width_mhz=20
    )
    assessment = assess_client(_window())
    roams = _roams()
    neighbors = sanitize_neighbors(
        [
            {"ssid": "Mine", "bssid": OWN_BSSID, "channel": 6, "signal": -40},
            {"ssid": "Nachbar", "bssid": MAC, "channel": 6, "signal": -70},
        ],
        [OWN_BSSID],
        salt=SALT,
    )
    rec = Recommendation(
        kind="channel",
        target=RadioRef(R1, "radio0"),
        problem="p",
        evidence=(f"client:{MAC}",),
        action="a",
        action_params={"channel": 1},
        expected_effect="e",
        confidence=0.5,
        risk=(),
    )
    return {
        "conflicts": detect_conflicts([view, other]),
        "capabilities": RadioCapabilities(
            R1, "radio0", {METRIC_NOISE: CapabilityState.MEASURED}
        ),
        "assessment": assessment,
        "summary": summarize_radio_clients([assessment]),
        "flaps": detect_flapping(roams.events),
        "roaming": roaming_quality(roams),
        "neighbors": neighbors,
        "recommendation": rec,
    }


class TestEveryOutputForm:
    def test_no_mac_survives_and_router_ids_stay(self):
        outputs = _outputs()
        assert outputs["flaps"]  # the window really flaps
        masked = mask_rf_output(outputs)
        _no_mac(masked)
        assert R1 in _text(masked)

    def test_client_identity_is_masked_not_dropped(self):
        masked = mask_rf_output(_outputs())
        assert masked["assessment"]["client_key"] == MASK
        assert masked["roaming"]["client_key"] == MASK
        assert all(f["client_key"] == MASK for f in masked["flaps"])

    def test_own_bssid_masked_foreign_hash_kept(self):
        masked = mask_rf_output(_outputs())["neighbors"]
        own = [n for n in masked if n["own"]]
        foreign = [n for n in masked if not n["own"]]
        assert own[0]["key"] == MASK
        assert len(foreign[0]["key"]) == 16 and foreign[0]["key"] != MASK
        assert "Nachbar" not in _text(masked) and "Mine" not in _text(masked)

    def test_radio_references_stay_readable(self):
        masked = mask_rf_output(_outputs())
        assert masked["recommendation"]["target"] == {
            "router_key": R1,
            "radio_key": "radio0",
        }
        assert masked["capabilities"]["router_key"] == R1
        members = masked["conflicts"][0]["members"]
        assert {m["router_key"] for m in members} == {R1, R2}
