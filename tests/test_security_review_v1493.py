"""Security Center review findings of 1.49.3 (F3, F4, S1). Mocks only."""

from __future__ import annotations

import time

import pytest

from custom_components.openwrt_router.security_model import (
    MASK_MAC,
    mask_identities,
)

# --- F3: twelve decimal digits are no MAC -----------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        "bytes=123456789012",
        "call +491701234567 now",
        "at 202611211530",
        "build 2026.1121.1530",
    ],
)
def test_f3_numbers_are_not_masked_as_macs(text: str) -> None:
    assert MASK_MAC not in mask_identities({"note": text})["note"]


@pytest.mark.parametrize(
    "text",
    [
        "from aabbccddeeff",
        "from 0011223344aa",
        "from 0011.2233.44aa",
        "from AABB.CCDD.EEFF",
        "from 00:11:22:33:44:55",
        "from 00-11-22-33-44-55",
        "from AA BB CC DD EE FF end",
        "from 00 11 22 33 44 5a end",
    ],
)
def test_f3_mac_forms_are_masked(text: str) -> None:
    masked = mask_identities({"note": text})["note"]
    assert MASK_MAC in masked, masked


@pytest.mark.parametrize(
    "text",
    [
        "dump de ad be ef 00 11 22 33 44",  # longer hex dump: not a MAC
        "12 34 56 78 90 12",  # digits only, space separated
    ],
)
def test_f3_space_form_without_false_hits(text: str) -> None:
    assert MASK_MAC not in mask_identities({"note": text})["note"]


def test_f3_no_catastrophic_backtracking() -> None:
    from custom_components.openwrt_router.security_model import _mask_text

    for chunk in ("a" * 1_000_000, "0a " * 333_333, "1" * 1_000_000, "a:" * 500_000):
        start = time.perf_counter()
        _mask_text(chunk)
        assert time.perf_counter() - start < 2.0
