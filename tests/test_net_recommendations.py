"""Tests for the recommendation per cause (RT7).

The panel API sends ``recommendation_key`` (``rec_<cause>``) for every cause
the engine can name; the German texts live in the frontend (``intel.ts``),
the English ones in ``docs/realtime-rca.md``. A recommendation is text only:
it never triggers an action.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from custom_components.openwrt_router.net_events import CauseStatus, Incident, Scope
from custom_components.openwrt_router.net_query import incident_dict
from custom_components.openwrt_router.net_rules import (
    RECOMMENDED_CAUSES,
    ROOT_CAUSES,
    recommendation_key,
)

ROOT = Path(__file__).resolve().parents[1]
INTEL_TS = (
    ROOT
    / "custom_components"
    / "openwrt_router"
    / "frontend"
    / "topology"
    / "src"
    / "utils"
    / "intel.ts"
)
DOC = ROOT / "docs" / "realtime-rca.md"


def test_every_root_cause_has_a_recommendation() -> None:
    assert set(ROOT_CAUSES.values()) <= RECOMMENDED_CAUSES
    assert {"client_side", "weak_signal", "dns_resolution"} <= RECOMMENDED_CAUSES


@pytest.mark.parametrize(
    ("cause", "key"),
    [
        ("weak_signal", "rec_weak_signal"),
        ("port_flap", "rec_port_flap"),
        ("client_side", "rec_client_side"),
        ("something_new", None),
        (None, None),
    ],
)
def test_recommendation_key(cause: str | None, key: str | None) -> None:
    assert recommendation_key(cause) == key


def test_panel_incident_carries_the_key() -> None:
    inc = Incident(
        id="inc1",
        type="wifi_reconnect_storm",
        scope=Scope.CLIENT,
        scope_key="02:00:5E:10:00:01",
        cause="client_side",
        cause_status=CauseStatus.HYPOTHESIS,
    )
    assert incident_dict(inc, str, 0.0)["recommendation_key"] == "rec_client_side"
    bare = Incident(id="i2", type="wan_down", scope=Scope.ROUTER, scope_key="gw")
    assert incident_dict(bare, str, 0.0)["recommendation_key"] is None


def test_frontend_has_a_german_text_for_every_key() -> None:
    source = INTEL_TS.read_text(encoding="utf-8")
    block = re.search(r"CAUSE_RECOMMENDATION[^{]*\{(.*?)\n\};", source, re.DOTALL)
    assert block is not None
    keys = set(re.findall(r"^\s*(rec_[a-z_]+):", block.group(1), re.MULTILINE))
    assert keys == {f"rec_{c}" for c in RECOMMENDED_CAUSES}


def test_docs_list_every_key_in_english() -> None:
    text = DOC.read_text(encoding="utf-8")
    missing = [c for c in sorted(RECOMMENDED_CAUSES) if f"`rec_{c}`" not in text]
    assert missing == []
