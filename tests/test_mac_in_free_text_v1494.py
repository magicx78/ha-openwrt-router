"""1.49.4: MAC addresses in free text are masked by the Core, the
configuration manager's text redaction and every network-diagnostics output.

One pattern (``core_masking.MAC_IN_TEXT_RE``, the Security Center's pattern
of 1.49.3) serves all of them. Structured output of the Core and the
configuration manager (``mask_for_output`` / ``config_mask_for_output``
without ``macs=True``) keeps MACs on purpose: config diffs name sections by
MAC (``@host{"mac":"…"}``) and an admin compares and restores them.
"""

from __future__ import annotations

import time

import pytest

from custom_components.openwrt_router import diag_core, security_model
from custom_components.openwrt_router.config_const import (
    config_mask_for_output,
    config_redact_text,
)
from custom_components.openwrt_router.core_masking import (
    MAC_IN_TEXT_RE,
    MASK,
    mask_for_output,
    redact_text,
    scrub_text,
)

MAC_FORMS = (
    "AA:BB:CC:DD:EE:FF",
    "aa:bb:cc:dd:ee:ff",
    "00:11:22:33:44:55",
    "AA-BB-CC-DD-EE-FF",
    "aabb.ccdd.eeff",
    "0011.2233.44aa",
    "aabbccddeeff",
    "00112233445a",  # bare, one letter
    "AA BB CC DD EE FF",
)
NOT_MACS = (
    "123456789012",  # 12-digit decimal
    "bytes=123456789012",
    "202611211530",  # timestamp
    "2026.1121.1530",  # dotted timestamp
    "2026-11-21T15:30:00Z",
    "+49 151 23456789",  # phone number
    "0049 5202 123456",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256
    "rtr_0123456789abcdef0123456789abcdef",  # core id
    "mac_0123456789abcdef",  # pseudonym
    "usr_0123456789ab",  # user pseudonym (12 hex after a core prefix)
    "6df0e3d02a",  # 10-hex revision
    "fe80::aabb:ccff:fedd:eeff",
)


def _redactors():
    return {
        "redact_text": redact_text,
        "scrub_text": scrub_text,
        "config_redact_text": config_redact_text,
        "mask_for_output(macs)": lambda t: mask_for_output({"m": t}, macs=True)["m"],
        "diag_log_safe": lambda t: diag_core.log_safe({"text": t})["text"],
        "diag_masked": lambda t: diag_core._masked({"text": t})["text"],
    }


@pytest.mark.parametrize("name", list(_redactors()))
@pytest.mark.parametrize("mac", MAC_FORMS)
def test_mac_masked_in_free_text(name: str, mac: str) -> None:
    out = _redactors()[name](f"client {mac} left (reason 3)")
    assert mac not in out
    assert out == f"client {MASK} left (reason 3)"


@pytest.mark.parametrize("name", list(_redactors()))
@pytest.mark.parametrize("text", NOT_MACS)
def test_no_mac_stays(name: str, text: str) -> None:
    assert _redactors()[name](f"value {text} end") == f"value {text} end"


def test_router_error_line_masked() -> None:
    line = "hostapd: wlan0: STA 3c:22:fb:12:34:56 IEEE 802.11: disassociated"
    assert "3c:22:fb" not in redact_text(line)
    assert "3c:22:fb" not in diag_core.log_safe({"reason": line})["reason"]


def test_structured_output_keeps_macs_by_default() -> None:
    """Config diffs and admin views show MACs on purpose."""
    data = {
        "section": '@host{"mac":"AA:BB:CC:DD:EE:FF"}',
        "change": {"option": "mac", "config": "dhcp", "new": "00:11:22:33:44:55"},
    }
    assert mask_for_output(data) == data
    assert config_mask_for_output(data) == data
    masked = config_mask_for_output(data, macs=True)
    assert "AA:BB:CC:DD:EE:FF" not in str(masked)


def test_secrets_still_masked_with_macs() -> None:
    out = redact_text("psk=hunter2hunter2 mac aa:bb:cc:dd:ee:ff")
    assert "hunter2" not in out and "aa:bb" not in out


def test_security_center_uses_the_shared_pattern() -> None:
    assert security_model._MAC_RE is MAC_IN_TEXT_RE
    assert security_model.mask_identities("x aa:bb:cc:dd:ee:ff") == "x <mac>"


def test_hex_dump_not_masked() -> None:
    dump = "00 11 22 33 44 55 66 77 aa bb"
    assert redact_text(dump) == dump


@pytest.mark.parametrize(
    "func",
    [redact_text, config_redact_text, lambda t: diag_core.log_safe({"t": t})],
)
def test_one_megabyte_is_fast(func) -> None:
    big = ("ab:cd 0123456789ab " * 60000)[:1_000_000]
    start = time.perf_counter()
    func(big)
    assert time.perf_counter() - start < 2.0
    worst = "a" * 1_000_000
    start = time.perf_counter()
    func(worst)
    assert time.perf_counter() - start < 2.0
