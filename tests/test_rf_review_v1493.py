"""WiFi RF review findings of 1.49.3 (R1-R5).

Mocks only, no router is contacted.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import Any

from custom_components.openwrt_router.const import (
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_LISTS,
)
from custom_components.openwrt_router.rf_collector import (
    RadioPlanInput,
    RfCollector,
    Target,
    options_from_entry,
)
from custom_components.openwrt_router.rf_models import CapabilityState


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


RADIO = RadioPlanInput("radio1", ("phy1-ap0",), (36, "DE"))


def _yes(_name: str) -> tuple[bool, str | None]:
    return True, None


# --- R1: a read cut by the round time limit is a transient failure ------------------


async def test_r1_hanging_setup_list_backs_off_and_does_not_block_the_rest():
    """A hanging freqlist was sent on every poll and get_status never ran."""
    clock = Clock()
    collector = RfCollector(clock=clock, round_timeout_s=0.02)
    opts = options_from_entry(
        {
            OPTION_WIFI_RF_ENABLED: True,
            OPTION_WIFI_RF_EVERY_N_POLLS: 1,
            OPTION_WIFI_RF_GET_STATUS: True,
            OPTION_WIFI_RF_LISTS: True,
        }
    )
    calls: list[str] = []

    async def read(kind: str, device: str) -> dict[str, Any]:
        calls.append(kind)
        if kind == "freqlist":
            await asyncio.sleep(10)
        return {"results": []}

    for _ in range(12):  # 12 polls of 60 s
        targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
        await collector.async_run(
            targets, read, list_bases={"radio1": RADIO.list_basis}
        )
        clock.t += 60
    assert calls.count("freqlist") <= 3  # backoff 300 s, 600 s, ...
    assert "get_status" in calls
    assert "txpowerlist" in calls
    state = collector.targets[("freqlist", "phy1-ap0")]
    assert state.failures >= 1
    assert state.retry_at is not None
    assert state.state is CapabilityState.UNREACHABLE
    assert state.reason == "round_timeout"


async def test_r1_periodic_read_cut_by_the_time_limit_backs_off():
    clock = Clock()
    collector = RfCollector(clock=clock, round_timeout_s=0.02)
    times: list[float] = []

    async def read(kind: str, device: str) -> dict[str, Any]:
        times.append(clock.t)
        await asyncio.sleep(10)
        return {}

    opts = options_from_entry(
        {
            OPTION_WIFI_RF_ENABLED: True,
            OPTION_WIFI_RF_EVERY_N_POLLS: 1,
            OPTION_WIFI_RF_GET_STATUS: True,
        }
    )
    for _ in range(40):
        targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
        await collector.async_run(targets, read)
        clock.t += 60
    gaps = [b - a for a, b in itertools.pairwise(times)]
    assert gaps[:3] == [300.0, 600.0, 1200.0]


async def test_r1_round_order_rotates_so_an_early_target_cannot_starve_the_rest():
    collector = RfCollector(clock=Clock())
    firsts: list[str] = []
    targets = [
        Target("assoclist", "phy1-ap0", "radio1"),
        Target("get_status", "phy1-ap0", "radio1"),
        Target("survey", "phy1-ap0", "radio1"),
    ]

    seen: list[str] = []

    async def rec(kind: str, device: str) -> dict[str, Any]:
        seen.append(kind)
        return {}

    for _ in range(3):
        seen.clear()
        await collector.async_run(targets, rec)
        firsts.append(seen[0])
        assert sorted(seen) == ["assoclist", "get_status", "survey"]
    assert len(set(firsts)) == 3
