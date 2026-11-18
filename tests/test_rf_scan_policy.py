"""Tests for the scan decision and neighbor redaction (rf_scan_policy.py)."""

from __future__ import annotations

import inspect

import pytest

from custom_components.openwrt_router.rf_models import CapabilityState
from custom_components.openwrt_router.rf_scan_policy import (
    NeighborBss,
    ScanPolicy,
    ScanReason,
    ScanRequest,
    ScanState,
    decide_scan,
    is_uplink_radio,
    sanitize_neighbors,
)

C = CapabilityState
R = ScanReason
POLICY = ScanPolicy()
EMPTY = ScanState(last_scan_at={}, last_router_scan_at=None)
NOW = 100_000.0


def _req(manual=True, is_admin=True, radio="radio0", at=NOW):
    return ScanRequest(
        radio_key=radio, requested_at=at, manual=manual, is_admin=is_admin
    )


def _decide(request=None, **kw):
    args = {
        "capability": C.MEASURED,
        "uplink": False,
        "cac_active": False,
        "state": EMPTY,
        "policy": POLICY,
    }
    args.update(kw)
    return decide_scan(request or _req(), **args)


# =====================================================================
# Uplink detection
# =====================================================================


class TestIsUplinkRadio:
    @pytest.mark.parametrize(
        "modes",
        [
            ["Master", "Client"],
            ["ap", "sta"],
            ["Mesh Point"],
            ["mesh"],
            ["Ad-Hoc"],
            ["adhoc"],
            ["WDS"],
            ["wds_sta"],
            ["wds-sta"],
            ["Station"],
            ["  CLIENT "],
        ],
    )
    def test_uplink_modes(self, modes):
        assert is_uplink_radio(modes, wds=False, backhaul_flag=False) is True

    @pytest.mark.parametrize("modes", [["Master"], ["ap", "AP"], ["Master", "Monitor"]])
    def test_ap_only(self, modes):
        assert is_uplink_radio(modes, wds=False, backhaul_flag=False) is False

    def test_unknown_modes_give_none(self):
        assert is_uplink_radio([], wds=False, backhaul_flag=False) is None
        assert is_uplink_radio(["", None], wds=False, backhaul_flag=False) is None
        assert (
            is_uplink_radio(["Master", "Unknown"], wds=False, backhaul_flag=False)
            is None
        )

    def test_flags_are_radio_wide(self):
        assert is_uplink_radio(["Master"], wds=True, backhaul_flag=False) is True
        assert is_uplink_radio([], wds=False, backhaul_flag=True) is True

    def test_accepts_any_iterable(self):
        assert (
            is_uplink_radio(iter(["Master"]), wds=False, backhaul_flag=False) is False
        )


# =====================================================================
# Scan decision
# =====================================================================


class TestDecideScan:
    def test_allowed(self):
        decision = _decide()
        assert decision.allowed is True
        assert decision.reason is R.ALLOWED
        assert decision.retry_after_s is None

    @pytest.mark.parametrize("state", [C.MEASURED, C.NO_DATA, C.STALE])
    def test_supported_states_allow(self, state):
        assert _decide(capability=state).allowed is True

    def test_case_16_scan_unsupported(self):
        decision = _decide(capability=C.UNSUPPORTED)
        assert (decision.allowed, decision.reason) == (False, R.SCAN_UNSUPPORTED)
        assert decision.retry_after_s is None

    def test_case_16_scan_unavailable(self):
        decision = _decide(capability=C.UNREACHABLE)
        assert (decision.allowed, decision.reason) == (False, R.SCAN_UNAVAILABLE)

    def test_not_admin(self):
        assert _decide(_req(is_admin=False)).reason is R.NOT_ADMIN

    def test_auto_disabled_by_default(self):
        assert _decide(_req(manual=False)).reason is R.AUTO_DISABLED

    def test_auto_allowed_when_enabled(self):
        policy = ScanPolicy(enabled_auto=True)
        assert _decide(_req(manual=False), policy=policy).allowed is True

    def test_uplink_radio_is_refused(self):
        assert _decide(uplink=True).reason is R.UPLINK_RADIO

    def test_uplink_lock_cannot_be_overridden(self):
        params = set(inspect.signature(decide_scan).parameters)
        assert not any("force" in p or "override" in p for p in params)
        assert not any(
            "force" in f or "override" in f for f in ScanPolicy.__dataclass_fields__
        )
        policy = ScanPolicy(enabled_auto=True, min_interval_manual_s=0)
        assert _decide(_req(manual=True), uplink=True, policy=policy).allowed is False

    def test_uplink_unknown_is_refused(self):
        assert _decide(uplink=None).reason is R.UPLINK_UNKNOWN

    def test_cac_active(self):
        assert _decide(cac_active=True).reason is R.CAC_ACTIVE

    def test_cac_unknown(self):
        assert _decide(cac_active=None).reason is R.CAC_UNKNOWN

    def test_case_17_rate_limit_per_radio(self):
        state = ScanState(last_scan_at={"radio0": NOW - 1800}, last_router_scan_at=None)
        decision = _decide(state=state)
        assert (decision.allowed, decision.reason) == (False, R.RATE_LIMIT_RADIO)
        assert decision.retry_after_s == pytest.approx(
            POLICY.min_interval_manual_s - 1800
        )

    def test_case_17_rate_limit_ends(self):
        last = NOW - POLICY.min_interval_manual_s
        state = ScanState(last_scan_at={"radio0": last}, last_router_scan_at=last)
        assert _decide(state=state).allowed is True

    def test_case_17_other_radio_is_not_limited_by_radio_limit(self):
        state = ScanState(last_scan_at={"radio1": NOW - 10}, last_router_scan_at=None)
        assert _decide(state=state).allowed is True

    def test_case_17_auto_scans_use_the_long_interval(self):
        policy = ScanPolicy(enabled_auto=True)
        state = ScanState(last_scan_at={"radio0": NOW - 7200}, last_router_scan_at=None)
        decision = _decide(_req(manual=False), state=state, policy=policy)
        assert decision.reason is R.RATE_LIMIT_RADIO
        assert decision.retry_after_s == pytest.approx(
            policy.min_interval_auto_s - 7200
        )
        assert policy.min_interval_auto_s == 24 * 3600

    def test_case_17_rate_limit_per_router(self):
        state = ScanState(last_scan_at={}, last_router_scan_at=NOW - 60)
        decision = _decide(state=state)
        assert decision.reason is R.RATE_LIMIT_ROUTER
        assert decision.retry_after_s == pytest.approx(POLICY.min_gap_per_router_s - 60)

    def test_case_17_clock_going_back_is_limited(self):
        state = ScanState(last_scan_at={"radio0": NOW + 50}, last_router_scan_at=None)
        decision = _decide(state=state)
        assert decision.reason is R.RATE_LIMIT_RADIO
        assert decision.retry_after_s == pytest.approx(POLICY.min_interval_manual_s)

    @pytest.mark.parametrize(
        ("kwargs", "expected"),
        [
            (
                {"capability": C.UNSUPPORTED, "is_admin": False, "uplink": True},
                R.SCAN_UNSUPPORTED,
            ),
            ({"is_admin": False, "manual": False, "uplink": True}, R.NOT_ADMIN),
            ({"manual": False, "uplink": True}, R.AUTO_DISABLED),
            ({"uplink": True, "cac_active": True}, R.UPLINK_RADIO),
            ({"uplink": None, "cac_active": True}, R.UPLINK_UNKNOWN),
            ({"cac_active": True, "radio_limited": True}, R.CAC_ACTIVE),
            ({"radio_limited": True, "router_limited": True}, R.RATE_LIMIT_RADIO),
        ],
    )
    def test_fixed_order_of_reasons(self, kwargs, expected):
        request = _req(
            manual=kwargs.pop("manual", True), is_admin=kwargs.pop("is_admin", True)
        )
        state = ScanState(
            last_scan_at={"radio0": NOW - 1}
            if kwargs.pop("radio_limited", False)
            else {},
            last_router_scan_at=NOW - 1
            if kwargs.pop("router_limited", False)
            else None,
        )
        assert _decide(request, state=state, **kwargs).reason is expected

    def test_as_dict(self):
        assert _decide(uplink=True).as_dict() == {
            "allowed": False,
            "reason": "uplink_radio",
            "retry_after_s": None,
        }


# =====================================================================
# Neighbor redaction
# =====================================================================

FOREIGN_SSID = "Nachbar-WLAN-Mueller"
FOREIGN_BSSID = "AA:BB:CC:DD:EE:01"
OWN_BSSID = "02:11:22:33:44:55"
SALT = "test-salt"


def _scan_entry(ssid, bssid, channel, signal, mhz=None, **extra):
    entry = {
        "ssid": ssid,
        "bssid": bssid,
        "mode": "Master",
        "channel": channel,
        "mhz": mhz or (2407 + 5 * channel if channel <= 14 else 5000 + 5 * channel),
        "signal": signal,
        "quality": 40,
        "quality_max": 70,
        "encryption": {"enabled": True, "wpa": [2], "authentication": ["psk"]},
    }
    entry.update(extra)
    return entry


def _scan():
    """SYNTHETIC iwinfo scan result in the rpcd shape, not from a device."""
    return {
        "results": [
            _scan_entry("MyHome", OWN_BSSID.lower(), 6, -40),
            _scan_entry(
                FOREIGN_SSID,
                FOREIGN_BSSID,
                6,
                -71,
                ht_operation={
                    "secondary_channel_offset": "above",
                    "channel_width": 2040,
                },
            ),
            _scan_entry(
                "Other",
                "aa:bb:cc:dd:ee:02",
                36,
                -80,
                vht_operation={"channel_width": 80, "center_freq_1": 42},
                encryption={"enabled": False},
            ),
        ]
    }


class TestSanitizeNeighbors:
    def test_separates_own_from_foreign(self):
        result = sanitize_neighbors(_scan(), [OWN_BSSID], salt=SALT)
        own = [n for n in result if n.own]
        foreign = [n for n in result if not n.own]
        assert len(own) == 1
        assert own[0].key == OWN_BSSID.lower()
        assert len(foreign) == 2

    def test_foreign_ssid_and_bssid_never_in_output(self):
        result = sanitize_neighbors(_scan(), [OWN_BSSID], salt=SALT)
        text = repr(result) + repr([n.as_dict() for n in result])
        for secret in (
            FOREIGN_SSID,
            "Other",
            FOREIGN_BSSID,
            FOREIGN_BSSID.lower(),
            FOREIGN_BSSID.replace(":", "").lower(),
            "aa:bb:cc:dd:ee:02",
        ):
            assert secret not in text
        assert "MyHome" not in text  # SSIDs are never kept

    def test_foreign_fields(self):
        result = sanitize_neighbors(_scan(), [], salt=SALT)
        strongest = result[0]
        assert strongest.own is False
        assert len(strongest.key) == 16
        assert (strongest.band, strongest.channel, strongest.signal_dbm) == (
            "2.4g",
            6,
            -40,
        )
        second = result[1]
        assert second.width_mhz == 40
        assert second.encryption == "wpa2-psk"
        third = result[2]
        assert (third.band, third.width_mhz, third.encryption) == ("5g", 80, "open")

    def test_key_is_stable_per_salt(self):
        a = sanitize_neighbors(_scan(), [], salt=SALT)
        b = sanitize_neighbors(_scan(), [], salt=SALT)
        c = sanitize_neighbors(_scan(), [], salt="other")
        assert [n.key for n in a] == [n.key for n in b]
        assert a[0].key != c[0].key

    def test_empty_salt_is_refused(self):
        with pytest.raises(ValueError):
            sanitize_neighbors(_scan(), [], salt="")

    def test_limit_keeps_strongest_foreign_and_all_own(self):
        raw = [
            _scan_entry("x", f"aa:bb:cc:dd:ee:{i:02x}", 1, -50 - i) for i in range(10)
        ]
        raw.append(_scan_entry("mine", OWN_BSSID, 1, -95))
        result = sanitize_neighbors(
            raw, [OWN_BSSID.replace(":", "-")], salt=SALT, max_neighbors=3
        )
        foreign = [n for n in result if not n.own]
        assert [n.signal_dbm for n in foreign] == [-50, -51, -52]
        assert [n.own for n in result].count(True) == 1

    def test_width_variants(self):
        def width(**ops):
            raw = [_scan_entry("x", "aa:bb:cc:dd:ee:09", 36, -60, **ops)]
            return sanitize_neighbors(raw, [], salt=SALT)[0].width_mhz

        assert width() is None
        assert (
            width(
                ht_operation={
                    "secondary_channel_offset": "no secondary",
                    "channel_width": 20,
                }
            )
            == 20
        )
        assert width(vht_operation={"channel_width": 8080}) == 160
        assert width(vht_operation={"channel_width": 160}) == 160

    def test_invalid_values_are_unknown(self):
        raw = [_scan_entry("x", "aa:bb:cc:dd:ee:09", 6, 0, encryption=None)]
        (n,) = sanitize_neighbors(raw, [], salt=SALT)
        assert n.signal_dbm is None
        assert n.encryption is None

    @pytest.mark.parametrize(
        "raw", [None, "x", {"results": "x"}, [None, {"ssid": "no bssid"}]]
    )
    def test_garbage(self, raw):
        assert sanitize_neighbors(raw, [], salt=SALT) == []

    def test_neighbor_bss_has_no_ssid_field(self):
        assert "ssid" not in NeighborBss.__dataclass_fields__
        assert "bssid" not in NeighborBss.__dataclass_fields__
