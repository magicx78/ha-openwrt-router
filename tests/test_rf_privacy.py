"""RF output masking on top of core_masking (rf_privacy.py).

Identifiers become Core pseudonyms (``pseudonymise_identifier``) under the
``wifi_rf`` module key; without a key they become the Core ``MASK``.
"""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.core_masking import (
    IDENTIFIER_INVALID,
    IDENTIFIER_PSEUDONYM_PREFIXES,
    MASK,
    is_secret_key,
    mask_for_output,
    pseudonymise_fields,
    pseudonymise_identifier,
)
from custom_components.openwrt_router.core_models import (
    default_router_id,
    derive_module_key,
)
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
    RF_IDENTIFIER_FIELDS,
    RF_PSEUDONYM_PURPOSE,
    client_ref,
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
KEY = derive_module_key(b"\x07" * 32, "wifi_rf", RF_PSEUDONYM_PURPOSE)
MAC_PSEUDO = pseudonymise_identifier("mac", MAC, KEY)


def _text(data):
    return repr(data)


def _no_mac(data):
    text = _text(data).lower()
    for form in MAC_FORMS:
        assert form.lower() not in text


class TestCoreGapClosed:
    """The former Core gaps (``TestCoreGap``), inverted: the Core closes them."""

    def test_core_pseudonymises_ssid_bssid_and_mac(self):
        data = {"ssid": "Home", "bssid": MAC, "mac": MAC}
        out = pseudonymise_fields(data, KEY, RF_IDENTIFIER_FIELDS)
        assert out == {
            "ssid": pseudonymise_identifier("ssid", "Home", KEY),
            "bssid": pseudonymise_identifier("bssid", MAC, KEY),
            "mac": MAC_PSEUDO,
        }
        assert mask_rf_output(data, key=KEY) == out
        # the masking alone still shows them: pseudonyms are a separate step
        assert mask_for_output(data) == data

    def test_rf_reference_names_are_no_core_secret_any_more(self):
        for name in ("router_id", "radio_id", "member_id", "worst_member_id"):
            assert not is_secret_key(name), name
        assert mask_for_output({"router_id": R1}) == {"router_id": R1}
        # the old *_key names would be masked: that is why they were renamed
        for name in ("router_key", "radio_key", "key", "client_key"):
            assert is_secret_key(name), name


class TestMaskRfOutput:
    FIELDS = ("ssid", "ssids", "bssid", "mac", "hostname", "ip", "client_mac")

    def test_without_a_key_identifiers_become_the_core_placeholder(self):
        data = {k: "x" for k in self.FIELDS}
        data["client_mac"] = MAC
        out = mask_rf_output(data, key=None)
        assert set(out.values()) == {MASK}
        assert set(self.FIELDS) <= set(RF_IDENTIFIER_FIELDS)

    def test_with_a_key_no_identifier_keeps_its_value(self):
        data = {k: "x" for k in self.FIELDS}
        data["client_mac"] = MAC
        out = mask_rf_output(data, key=KEY)
        for name, value in out.items():
            prefix = IDENTIFIER_PSEUDONYM_PREFIXES[RF_IDENTIFIER_FIELDS[name]]
            assert value == IDENTIFIER_INVALID or value.startswith(prefix), name
            assert value != data[name]
        assert out["client_mac"] == client_ref(MAC, KEY)
        assert out["ssid"] == pseudonymise_identifier("ssid", "x", KEY)
        assert out["mac"] == IDENTIFIER_INVALID  # "x" is no MAC

    @pytest.mark.parametrize("form", MAC_FORMS)
    def test_macs_in_free_text_become_the_core_pseudonym(self, form):
        out = mask_rf_output({"evidence": [f"roam:{form}->x", f"x {form} y"]}, key=KEY)
        _no_mac(out)
        assert out["evidence"] == [f"roam:{MAC_PSEUDO}->x", f"x {MAC_PSEUDO} y"]

    @pytest.mark.parametrize("form", MAC_FORMS)
    def test_macs_in_free_text_without_a_key_are_masked(self, form):
        out = mask_rf_output({"evidence": [f"roam:{form}->x", f"x {form} y"]}, key=None)
        _no_mac(out)
        assert out["evidence"] == [f"roam:{MASK}->x", f"x {MASK} y"]

    def test_reference_keys_and_rf_codes_stay_readable(self):
        data = {
            "router_id": R1,
            "radio_id": "radio0",
            "evidence": [f"utilization:{R1}/radio0:78.0%:hostapd.get_status"],
            "kind": "co_channel",
            "coverage": 0.5,
            "count": 3,
            "flag": None,
        }
        assert mask_rf_output(data, key=KEY) == data
        assert not [k for k in data if is_secret_key(k)]

    def test_a_mac_under_any_other_name_is_pseudonymised(self):
        assert mask_rf_output({"note": OWN_BSSID}, key=KEY) == {
            "note": pseudonymise_identifier("mac", OWN_BSSID, KEY)
        }
        # a ``*_key`` name is a Core secret: its value never shows
        assert mask_rf_output({"key": OWN_BSSID}, key=KEY) == {"key": MASK}

    def test_secret_keys_use_the_core_rule(self):
        out = mask_rf_output(
            {"password": "hunter2", "nested": {"token": "abc"}}, key=KEY
        )
        assert out == {"password": MASK, "nested": {"token": MASK}}

    def test_core_text_redaction_runs_on_strings(self):
        out = mask_rf_output({"note": "url http://root:hunter2@10.0.0.1/"}, key=KEY)
        assert "hunter2" not in _text(out)

    def test_identifying_names_without_a_core_kind_are_masked(self):
        out = mask_rf_output({"username": "root", "web_url": "http://x/"}, key=KEY)
        assert out == {"username": MASK, "web_url": MASK}

    def test_accepts_objects_with_as_dict_and_sequences(self):
        ref = RadioRef(R1, "radio0")
        assert mask_rf_output(ref, key=KEY) == {"router_id": R1, "radio_id": "radio0"}
        assert mask_rf_output([ref], key=KEY) == [
            {"router_id": R1, "radio_id": "radio0"}
        ]
        assert mask_rf_output((1, "a"), key=KEY) == [1, "a"]

    def test_input_is_not_changed(self):
        data = {"client_mac": MAC, "inner": {"mac": MAC}}
        mask_rf_output(data, key=KEY)
        assert data == {"client_mac": MAC, "inner": {"mac": MAC}}

    @pytest.mark.parametrize("key", [KEY, None])
    def test_idempotent(self, key):
        data = {"client_mac": MAC, "evidence": [f"a:{MAC}"], "router_id": R1}
        once = mask_rf_output(data, key=key)
        assert mask_rf_output(once, key=key) == once

    def test_a_pseudonym_of_another_kind_is_not_taken_as_is(self):
        # a client pseudonym under ``mac`` is no MAC: refused, not passed on
        out = mask_rf_output({"mac": client_ref(MAC, KEY)}, key=KEY)
        assert out == {"mac": IDENTIFIER_INVALID}

    def test_unknown_objects_are_refused(self):
        with pytest.raises(TypeError):
            mask_rf_output(object(), key=KEY)


# ---------------------------------------------------------------------------
# Every RF output form that can carry an identifier
# ---------------------------------------------------------------------------


def _window(**kw):
    base = {
        "client_mac": MAC,
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
            client_mac=MAC,
            ts=100.0 * i,
            from_radio=a if i % 2 == 0 else b,
            to_radio=b if i % 2 == 0 else a,
            from_band="5g",
            to_band="5g",
            rssi_before=-75.0,
            rssi_after=-70.0,
            gap_s=0.5,
            handshake_failures=1,
            reauth=False,
        )
        for i in range(6)
    )
    return ClientRoamWindow(
        client_mac=MAC, window_s=3600.0, online_s=3600.0, events=events, mobility=None
    )


def _outputs():
    view = RadioView(
        router_id=R1,
        radio_id="radio0",
        band="2.4g",
        channel=6,
        width_mhz=20,
        utilization=metric_measured(78.0, SOURCE_HOSTAPD_STATUS, measured_at=1.0),
    )
    other = RadioView(
        router_id=R2, radio_id="radio0", band="2.4g", channel=6, width_mhz=20
    )
    assessment = assess_client(_window())
    roams = _roams()
    neighbors = sanitize_neighbors(
        [
            {"ssid": "Mine", "bssid": OWN_BSSID, "channel": 6, "signal": -40},
            {"ssid": "Nachbar", "bssid": MAC, "channel": 6, "signal": -70},
        ],
        [OWN_BSSID],
        key=KEY,
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
        for key in (KEY, None):
            masked = mask_rf_output(outputs, key=key)
            _no_mac(masked)
            assert R1 in _text(masked)

    def test_client_identity_is_pseudonymised_not_dropped(self):
        masked = mask_rf_output(_outputs(), key=KEY)
        ref = client_ref(MAC, KEY)
        assert masked["assessment"]["client_mac"] == ref
        assert masked["roaming"]["client_mac"] == ref
        assert all(f["client_mac"] == ref for f in masked["flaps"])

    def test_client_identity_without_a_key_is_masked(self):
        masked = mask_rf_output(_outputs(), key=None)
        assert masked["assessment"]["client_mac"] == MASK
        assert masked["roaming"]["client_mac"] == MASK
        assert all(f["client_mac"] == MASK for f in masked["flaps"])

    def test_own_bssid_pseudonymised_foreign_pseudonym_kept(self):
        masked = mask_rf_output(_outputs(), key=KEY)["neighbors"]
        own = [n for n in masked if n["own"]]
        foreign = [n for n in masked if not n["own"]]
        assert own[0]["bssid"] == pseudonymise_identifier("bssid", OWN_BSSID, KEY)
        assert foreign[0]["bssid"] == pseudonymise_identifier("bssid", MAC, KEY)
        assert len(foreign[0]["bssid"]) == 20
        assert "Nachbar" not in _text(masked) and "Mine" not in _text(masked)

    def test_own_bssid_without_a_key_is_masked(self):
        masked = mask_rf_output(_outputs(), key=None)["neighbors"]
        assert [n["bssid"] for n in masked if n["own"]] == [MASK]

    def test_radio_references_stay_readable(self):
        masked = mask_rf_output(_outputs(), key=KEY)
        assert masked["recommendation"]["target"] == {
            "router_id": R1,
            "radio_id": "radio0",
        }
        assert masked["capabilities"]["router_id"] == R1
        members = masked["conflicts"][0]["members"]
        assert {m["router_id"] for m in members} == {R1, R2}
