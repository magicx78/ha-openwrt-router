"""Network Time Machine, Phase A: the ``time_machine`` diagnostics block.

Behind the block the real sources of ``test_tm_views.full_env``: enterprise
core, configuration manager and Security Center of the VLAN drift scenario
plus Network Intelligence with WAN flaps and a client with a wrong key. The
diagnostics module's clock is pinned to the test world's clock (the block
reads the last 24 h). No router, no HA instance, no network.
"""

from __future__ import annotations

import json
import logging
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from test_tm_views import (
    SECRETS,
    close,
    core_disks,  # noqa: F401 - shared fixture
    full_env,
    listeners,
)

from custom_components.openwrt_router import diagnostics, tm_query, tm_sources
from custom_components.openwrt_router.config_api import ConfigurationApi
from custom_components.openwrt_router.const import DATA_TIME_MACHINE_STATS


def pinned(world: Any, after: float = 3600.0) -> Any:
    """The diagnostics module's ``time`` at the world's clock (plus ``after``)."""
    now = world.start + after
    return patch.object(
        diagnostics,
        "time",
        SimpleNamespace(time=lambda: now, monotonic=time.monotonic),
    )


async def download(world: Any, entry: Any = None) -> dict[str, Any]:
    """The whole download with a stub base: the blocks of this test only."""
    entry = entry if entry is not None else world.env.entries[0]
    with (
        pinned(world),
        patch.object(
            diagnostics,
            "_async_get_config_entry_diagnostics_traffic",
            AsyncMock(return_value={"base": 1}),
        ),
    ):
        return await diagnostics.async_get_config_entry_diagnostics(
            world.env.hass, entry
        )


async def test_off_shows_only_the_switch_and_reads_nothing(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    world = await full_env(core_disks, tmp_path, on=False)

    async def no_read(*_a: Any) -> Any:
        raise AssertionError("a source was read while off")

    with (
        patch.dict(tm_sources.READERS, dict.fromkeys(tm_sources.SOURCE_IDS, no_read)),
        patch.object(tm_sources, "build_router_map", side_effect=AssertionError),
    ):
        result = await download(world)
    assert result["base"] == 1
    assert result["time_machine"] == {"enabled": False}
    assert DATA_TIME_MACHINE_STATS not in world.env.hass.data
    await close(world)


async def test_on_shows_states_counts_and_limits_and_nothing_personal(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    world = await full_env(core_disks, tmp_path)
    hass = world.env.hass
    before = (listeners(world), set(core_disks.disks), set(hass.data))
    with patch.object(
        ConfigurationApi, "async_get_module_key", AsyncMock(side_effect=AssertionError)
    ) as key:
        block = (await download(world))["time_machine"]
    key.assert_not_called()
    assert set(block) == {
        "enabled",
        "entry_enabled",
        "api_version",
        "window_s",
        "limits",
        "sources",
        "counters",
    }
    assert block["enabled"] is True and block["entry_enabled"] is True
    assert block["api_version"] == 1 and block["window_s"] == 86_400.0
    assert block["limits"] == {
        "default_window_s": 86_400.0,
        "max_window_s": 14 * 86_400.0,
        "default_limit": 200,
        "max_limit": 500,
        "source_mark_cap": 500,
        "source_budget_s": 2.0,
    }
    sources = block["sources"]
    assert list(sources) == list(tm_sources.SOURCE_IDS)
    for item in sources.values():
        assert set(item) == {
            "state",
            "reason",
            "count",
            "truncated",
            "omitted_client_marks",
        }
        assert item["state"] == "ok" and item["reason"] is None
        assert item["count"] >= 1 and item["truncated"] is False
    # the client with the wrong key is counted, never shown
    assert sources["ni_events"]["omitted_client_marks"] >= 1
    # no request yet: counters exist, the download made none and stored none
    assert block["counters"] == {
        "requests": 0,
        "unreadable": {},
        "last_duration_ms": None,
        "last_marks": None,
    }
    assert set(hass.data) == before[2]
    text = json.dumps(block)
    for needle in (*SECRETS, "rtr_", "tmm_", "cli_", "bkp_", "Router e1"):
        assert needle not in text, needle
    # no listener, no store, no router call
    assert listeners(world) == before[0]
    assert set(core_disks.disks) == before[1]
    assert world.env.router_calls() == []
    await close(world)


async def test_counters_follow_the_timeline_requests(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    world = await full_env(core_disks, tmp_path)
    hass = world.env.hass
    stats = hass.data[DATA_TIME_MACHINE_STATS] = tm_query.Stats()
    query = tm_query.parse_query(
        {
            "from": str(int(world.start - 3600)),
            "until": str(int(world.start + 3600)),
        },
        now=world.start + 3600,
    )
    body = await tm_query.async_timeline(
        hass, query, admin=True, now=world.start + 3600, stats=stats
    )
    counters = (await download(world))["time_machine"]["counters"]
    assert counters["requests"] == 1
    assert counters["unreadable"] == {}
    assert counters["last_marks"] == len(body["marks"])
    assert isinstance(counters["last_duration_ms"], float)
    await close(world)


async def test_another_entry_shows_its_own_option_and_the_fleet_state(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    world = await full_env(core_disks, tmp_path)
    other = SimpleNamespace(entry_id="e2", options={})
    block = (await download(world, other))["time_machine"]
    assert block["enabled"] is True and block["entry_enabled"] is False
    await close(world)


async def test_a_failing_source_shows_unreadable_with_a_fixed_reason(
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    world = await full_env(core_disks, tmp_path)

    async def broken(*_a: Any) -> Any:
        raise RuntimeError("192.0.2.7 r1 phy1-ap0")

    with patch.dict(tm_sources.READERS, {"security_timeline": broken}):
        block = (await download(world))["time_machine"]
    assert block["sources"]["security_timeline"] == {
        "state": "unreadable",
        "reason": "error",
        "count": 0,
        "truncated": False,
        "omitted_client_marks": 0,
    }
    assert block["sources"]["core_audit"]["state"] == "ok"
    assert "192.0.2.7" not in json.dumps(block)
    await close(world)


async def test_a_failure_never_fails_the_download_and_logs_the_type_only(
    core_disks,  # noqa: F811
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    world = await full_env(core_disks, tmp_path)
    caplog.set_level(logging.DEBUG, logger=diagnostics.__name__)
    with patch.object(
        tm_sources,
        "build_router_map",
        side_effect=RuntimeError("192.0.2.7 r1 02:00:5E:40:00:01"),
    ):
        result = await download(world)
    assert result["base"] == 1
    assert result["time_machine"] == {"loaded": False, "error": True}
    assert "RuntimeError" in caplog.text
    for needle in ("192.0.2.7", "r1 ", "02:00:5E"):
        assert needle not in caplog.text, needle
    await close(world)


def test_the_block_is_the_last_wrapper_of_the_download() -> None:
    wrapped = diagnostics.async_get_config_entry_diagnostics
    assert (
        wrapped.__wrapped__ is diagnostics._async_get_config_entry_diagnostics_traffic
    )
    assert wrapped.__name__ == "async_get_config_entry_diagnostics"
