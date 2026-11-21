"""1.49.4: every discard counter of the traffic overview has a German text.

The panel's "Verworfen" line shows ``reasonText(code)`` for each key of
``overview()["drops"]``; a key without an entry in ``REASON_TEXT``
(trafficLogic.ts) appears as "Code <key>". This test takes the keys from a
running engine, so a counter added later without a text fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

from core_testkit import FakeDisks, drain
from test_traffic_engine import enabled, make_hass, start
from test_traffic_panel_v1493 import _data
from test_traffic_review_fixes import disks  # noqa: F401  (fixture)

from custom_components.openwrt_router import traffic_output as out

_LOGIC = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/traffic"
    / "trafficLogic.ts"
)


def _reason_text_keys() -> set[str]:
    source = _LOGIC.read_text(encoding="utf-8")
    start = source.index("export const REASON_TEXT: Record<string, string> = {")
    body = source[start : source.index("\n};", start)]
    return set(re.findall(r"^\s+([A-Za-z0-9_]+):", body, flags=re.MULTILINE))


async def test_every_drop_counter_has_a_german_text(
    disks: FakeDisks,  # noqa: F811
) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    coord.poll(data=_data(100.0))
    await drain(hass)
    keys = set(out.overview(engine)["drops"])
    assert {"dropped_snapshots", "stations_dropped", "dropped_feeds"} <= keys
    assert "late_rates" in keys  # the series counters are part of it
    missing = sorted(keys - _reason_text_keys())
    assert missing == [], f"drop counters without a German text: {missing}"
