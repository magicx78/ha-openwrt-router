"""1.49.3: the overview tells the panel what the traffic review fixes count.

``devices_omitted`` per router (netdevs over the cap, T3) and the flow
sources pushed out over ``MAX_FLOW_FEEDS`` (``dropped_feeds``, T2) reach the
read API next to the existing router facts and discard counters.
"""

from __future__ import annotations

from typing import Any

from core_testkit import FakeDisks, drain
from test_traffic_engine import RID, counters, enabled, make_hass, poll_data, start
from test_traffic_review_fixes import disks  # noqa: F401  (fixture)

from custom_components.openwrt_router import traffic_output as out
from custom_components.openwrt_router.traffic_const import MAX_DEVICES_PER_ROUTER


def _data(mono: float) -> Any:
    d = poll_data(mono, (1_000 + int(mono), 500 + int(mono)))
    d.device_counters = {
        **{f"eth{i:02d}": counters(i, i) for i in range(70)},
        "wan": counters(1, 1),
    }
    d.device_counters_omitted = 9
    return d


async def test_overview_shows_omitted_netdevs_per_router(disks: FakeDisks) -> None:  # noqa: F811
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    coord.poll(data=_data(100.0))
    await drain(hass)
    row = next(r for r in out.overview(engine)["routers"] if r["router_id"] == RID)
    assert row["devices"] == MAX_DEVICES_PER_ROUTER
    assert row["devices_omitted"] == 9 + 71 - MAX_DEVICES_PER_ROUTER


async def test_overview_drops_count_the_pushed_out_flow_feeds(
    disks: FakeDisks,  # noqa: F811
) -> None:
    hass = make_hass()
    enabled(disks)
    engine, coord = await start(hass)
    coord.poll(data=_data(100.0))
    await drain(hass)
    assert out.overview(engine)["drops"]["dropped_feeds"] == 0
    engine.flows.counters["dropped_feeds"] += 3
    assert out.overview(engine)["drops"]["dropped_feeds"] == 3
