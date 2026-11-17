"""Tests for wifi_reasons (codes from hostapd ieee802_11_defs.h)."""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.wifi_reasons import (
    UNKNOWN,
    classify_text,
    from_log_reason,
    lookup_code,
    rcpi_to_dbm,
)


@pytest.mark.parametrize(
    ("code", "key"),
    [
        (1, "unspecified"),
        (2, "prev_auth_not_valid"),
        (3, "deauth_leaving"),
        (4, "disassoc_due_to_inactivity"),
        (8, "disassoc_sta_has_left"),
        (15, "4way_handshake_timeout"),
        (23, "ieee_802_1x_auth_failed"),
        (34, "disassoc_low_ack"),
        (49, "invalid_pmkid"),
        (66, "mesh_channel_switch_unspecified"),
    ],
)
def test_code_keys(code: int, key: str) -> None:
    info = lookup_code(code)
    assert info.key == key
    assert info.code == code


def test_code_flags() -> None:
    assert lookup_code(34).weak_signal_hint
    assert lookup_code(34).category == "radio"
    assert lookup_code(15).auth_problem
    assert lookup_code(14).auth_problem
    assert lookup_code(4).category == "inactivity"
    assert lookup_code(3).ap_initiated is False
    assert lookup_code(5).ap_initiated is True


def test_unknown_code() -> None:
    assert lookup_code(9999) is UNKNOWN
    assert lookup_code(40) is UNKNOWN  # gap in the hostapd table
    assert lookup_code("x") is UNKNOWN  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "text",
    ["deauthenticated due to inactivity", "disassociated due to inactivity"],
)
def test_inactivity(text: str) -> None:
    assert classify_text(text).category == "inactivity"


def test_local_request() -> None:
    info = classify_text("deauthenticated due to local deauth request")
    assert info.category == "ap"
    assert info.key == "local_request"


def test_missing_acks() -> None:
    info = classify_text("disconnected due to excessive missing ACKs")
    assert info.category == "radio"
    assert info.weak_signal_hint


@pytest.mark.parametrize("text", ["disassociated", "deauthenticated", "", "foo"])
def test_plain_unknown(text: str) -> None:
    assert classify_text(text) is UNKNOWN


def test_none_unknown() -> None:
    assert classify_text(None) is UNKNOWN  # type: ignore[arg-type]
    assert from_log_reason(None) is UNKNOWN
    assert from_log_reason("") is UNKNOWN


@pytest.mark.parametrize(
    "text",
    [
        "group key handshake failed (RSN) after 4 tries",
        "pairwise key handshake failed (RSN) after 4 tries",
        "4-Way Handshake failed",
        "AP-STA-POSSIBLE-PSK-MISMATCH aa:bb:cc:dd:ee:ff",
        "received EAPOL-Key frame with invalid MIC",
        "EAPOL-Key timeout",
    ],
)
def test_security_text(text: str) -> None:
    info = classify_text(text)
    assert info.category == "security"
    assert info.auth_problem


@pytest.mark.parametrize(
    ("text", "key"),
    [("reason=4", "disassoc_due_to_inactivity"), ("reason 34", "disassoc_low_ack")],
)
def test_reason_fragment(text: str, key: str) -> None:
    assert classify_text(f"foo {text} bar").key == key


def test_reason_fragment_unknown_number() -> None:
    assert classify_text("reason=9999") is UNKNOWN


@pytest.mark.parametrize(
    ("key", "category"),
    [
        ("inactivity", "inactivity"),
        ("local_request", "ap"),
        ("prune", "unknown"),
        ("other", "unknown"),
        ("timeout", "security"),
        ("invalid_mic", "security"),
        ("failed", "security"),
        ("psk", "security"),
        ("max_sta", "ap"),
        ("blocked", "ap"),
        ("bogus", "unknown"),
    ],
)
def test_log_keys(key: str, category: str) -> None:
    assert from_log_reason(key).category == category


@pytest.mark.parametrize(
    ("rcpi", "dbm"),
    [(0, -110.0), (220, 0.0), (74, -73.0), (221, None), (255, None), (-1, None)],
)
def test_rcpi(rcpi: int, dbm: float | None) -> None:
    assert rcpi_to_dbm(rcpi) == dbm
