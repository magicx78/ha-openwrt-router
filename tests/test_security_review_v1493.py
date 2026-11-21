"""Security Center review findings of 1.49.3 (F3, F4, S1). Mocks only."""

from __future__ import annotations

import time
from typing import Any

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


# --- F4: Traffic notes never push security entries out of the timeline --------------


def _bare_center() -> Any:
    from core_testkit import make_hass

    from custom_components.openwrt_router.security_center import SecurityCenter

    return SecurityCenter(make_hass())


def _note(center: Any, ts: float, kind: str) -> None:
    from custom_components.openwrt_router.security_model import Severity

    center._timeline(
        ts,
        kind,
        category="system",
        severity=Severity.INFO,
        router_id=None,
        text="t",
    )


def test_f4_traffic_notes_have_their_own_cap_in_the_timeline() -> None:
    from custom_components.openwrt_router.const import (
        SEC_TIMELINE_MAX,
        SEC_TIMELINE_TRAFFIC_MAX,
    )

    center = _bare_center()
    for i in range(300):
        _note(center, float(i), "incident_opened")
    # 20 per hour over 14 days: 6720 notes, far over the timeline limit
    for i in range(6720):
        _note(center, 1000.0 + i, "traffic_indicator")
    kinds = [t["kind"] for t in center.timeline]
    assert kinds.count("incident_opened") == 300
    assert kinds.count("traffic_indicator") == SEC_TIMELINE_TRAFFIC_MAX
    assert len(center.timeline) <= SEC_TIMELINE_MAX
    # the newest traffic notes stay, the oldest went first
    traffic = [t["ts"] for t in center.timeline if t["kind"] == "traffic_indicator"]
    assert traffic[-1] == 1000.0 + 6719
    assert traffic == sorted(traffic)


def test_f4_security_entries_overflow_drops_traffic_first() -> None:
    from custom_components.openwrt_router.const import SEC_TIMELINE_MAX

    center = _bare_center()
    for i in range(SEC_TIMELINE_MAX - 100):
        _note(center, float(i), "incident_opened")
    for i in range(100):
        _note(center, 5000.0 + i, "traffic_indicator")
    for i in range(50):
        _note(center, 9000.0 + i, "incident_opened")
    kinds = [t["kind"] for t in center.timeline]
    assert len(kinds) == SEC_TIMELINE_MAX
    # no security entry went; the 50 oldest traffic notes made the room
    assert kinds.count("incident_opened") == SEC_TIMELINE_MAX - 50
    assert center.timeline[0]["ts"] == 0.0
