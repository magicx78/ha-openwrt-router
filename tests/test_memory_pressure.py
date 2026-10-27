"""Tests for the RAM pressure calculation and the ram_high Repairs issue (F9)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.helpers import issue_registry as ir

from custom_components.openwrt_router.const import (
    RAM_PRESSURE_HOLD_SECONDS,
)
from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
    calc_memory_pressure,
)

MB = 1024 * 1024
T0 = datetime(2026, 10, 27, 8, 0, tzinfo=UTC)


def _mem(total_mb: float, available_mb: float) -> dict:
    return {"total": int(total_mb * MB), "free": 0, "available": int(available_mb * MB)}


# =====================================================================
# calc_memory_pressure
# =====================================================================


class TestCalcMemoryPressure:
    def test_uses_available(self):
        p = calc_memory_pressure(
            {"total": 256 * MB, "free": 10 * MB, "available": 64 * MB}
        )
        assert p["pressure_pct"] == 75.0
        assert p["available_mb"] == 64.0
        assert p["available_bytes"] == 64 * MB
        assert p["estimated"] is False

    def test_live_shape_from_openwrt_25(self):
        """Field set of ubus system info on 25.12 (buffered is 0 there)."""
        p = calc_memory_pressure(
            {
                "total": 240 * MB,
                "free": 100 * MB,
                "shared": 2 * MB,
                "buffered": 0,
                "available": 130 * MB,
                "cached": 40 * MB,
            }
        )
        assert p["pressure_pct"] == pytest.approx(45.8, abs=0.05)
        assert p["estimated"] is False

    def test_fallback_without_available(self):
        """free + buffered + (cached - shared) when MemAvailable is missing."""
        p = calc_memory_pressure(
            {
                "total": 100 * MB,
                "free": 10 * MB,
                "buffered": 5 * MB,
                "cached": 20 * MB,
                "shared": 15 * MB,
            }
        )
        # available = 10 + 5 + (20 - 15) = 20 MB → 80 %
        assert p["pressure_pct"] == 80.0
        assert p["available_mb"] == 20.0
        assert p["estimated"] is True

    def test_fallback_ssh_keys(self):
        """The SSH metrics script reports 'buffers' instead of 'buffered'."""
        p = calc_memory_pressure(
            {"total": 100 * MB, "free": 10 * MB, "buffers": 10 * MB, "cached": 0}
        )
        assert p["pressure_pct"] == 80.0
        assert p["estimated"] is True

    def test_shmem_larger_than_cache_does_not_go_negative(self):
        p = calc_memory_pressure(
            {"total": 100 * MB, "free": 10 * MB, "cached": 5 * MB, "shared": 50 * MB}
        )
        assert p["available_mb"] == 10.0

    @pytest.mark.parametrize(
        "memory",
        [{}, {"total": 0}, {"total": None}, {"total": "abc"}, {"free": 1}],
    )
    def test_unusable_stats_return_empty(self, memory):
        assert calc_memory_pressure(memory) == {}

    def test_string_numbers_and_garbage_are_tolerated(self):
        p = calc_memory_pressure(
            {"total": str(100 * MB), "available": "x", "free": 1}
        )
        # "x" is present → not estimated, but unusable → treated as 0 available
        assert p["pressure_pct"] == 100.0

    def test_available_larger_than_total_is_clamped(self):
        p = calc_memory_pressure({"total": 100 * MB, "available": 200 * MB})
        assert p["pressure_pct"] == 0.0
        assert p["available_mb"] == 100.0


# =====================================================================
# Coordinator: hold time, hysteresis, issue lifecycle
# =====================================================================


def _make_coordinator(entry=True):
    hass = MagicMock()
    api = AsyncMock()
    with patch("homeassistant.helpers.frame.report_usage"):
        coord = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    if entry:
        coord._entry = MagicMock(entry_id="e1", title="Router A")
    return coord


def _data(memory: dict) -> OpenWrtCoordinatorData:
    data = OpenWrtCoordinatorData()
    data.memory = memory
    data.memory_pressure = calc_memory_pressure(memory)
    return data


class _Feed:
    """Feeds readings one minute apart and captures issue registry calls."""

    def __init__(self, coord):
        self.coord = coord
        self.now = T0
        self._p = patch("custom_components.openwrt_router.issues.ir")
        self.ir = self._p.start()
        self.ir.IssueSeverity = ir.IssueSeverity

    def poll(self, memory: dict, minutes: float = 1.0) -> None:
        self.coord._check_memory_pressure(_data(memory), self.now)
        self.now += timedelta(minutes=minutes)

    @property
    def created(self):
        return self.ir.async_create_issue.call_args_list

    @property
    def deleted(self):
        return [c.args[2] for c in self.ir.async_delete_issue.call_args_list]

    def stop(self):
        self._p.stop()


@pytest.fixture
def feed():
    f = _Feed(_make_coordinator())
    yield f
    f.stop()


HOLD_POLLS = RAM_PRESSURE_HOLD_SECONDS // 60  # readings 1 min apart


class TestRamIssueHoldTime:
    def test_raised_after_15_minutes_above_85(self, feed):
        for _ in range(HOLD_POLLS):  # t = 0 … 14 min
            feed.poll(_mem(256, 25))  # ~90 %
        assert not feed.created
        feed.poll(_mem(256, 25))  # t = 15 min
        assert len(feed.created) == 1
        call = feed.created[0]
        assert call.args[1:3] == ("openwrt_router", "ram_high_e1")
        assert call.kwargs["translation_key"] == "ram_high"
        assert call.kwargs["severity"] == ir.IssueSeverity.WARNING
        assert call.kwargs["is_persistent"] is False
        placeholders = call.kwargs["translation_placeholders"]
        assert placeholders["router"] == "Router A"
        assert placeholders["pressure"] == "90"
        assert placeholders["available_mb"] == "25"
        assert placeholders["since"]

    def test_not_raised_again_while_active(self, feed):
        for _ in range(HOLD_POLLS + 5):
            feed.poll(_mem(256, 25))
        assert len(feed.created) == 1

    def test_normal_reading_resets_hold_time(self, feed):
        for _ in range(10):
            feed.poll(_mem(256, 25))
        feed.poll(_mem(256, 50))  # ~80.5 % → not high
        for _ in range(HOLD_POLLS):
            feed.poll(_mem(256, 25))
        assert not feed.created
        feed.poll(_mem(256, 25))
        assert len(feed.created) == 1

    def test_exactly_85_percent_is_not_high(self, feed):
        for _ in range(HOLD_POLLS + 2):
            feed.poll(_mem(100, 15.0001))  # 85.0 % … but available < 16 MB
        assert len(feed.created) == 1  # triggered by the absolute floor
        f2 = _Feed(_make_coordinator())
        try:
            for _ in range(HOLD_POLLS + 2):
                f2.poll(_mem(200, 30))  # exactly 85.0 %, 30 MB available
            assert not f2.created
        finally:
            f2.stop()

    def test_low_available_triggers_below_85_percent(self, feed):
        """Small router: 64 MB total, 12 MB available = 81 % but < 16 MB."""
        for _ in range(HOLD_POLLS + 1):
            feed.poll(_mem(64, 12))
        assert len(feed.created) == 1

    def test_polls_without_memory_stats_keep_state(self, feed):
        for _ in range(10):
            feed.poll(_mem(256, 25))
        feed.poll({})  # failed/empty system info
        for _ in range(5):
            feed.poll(_mem(256, 25))
        assert len(feed.created) == 1

    def test_estimated_formula_also_triggers(self, feed):
        memory = {"total": 128 * MB, "free": 5 * MB, "buffered": 0, "cached": 6 * MB}
        for _ in range(HOLD_POLLS + 1):
            feed.poll(memory)
        assert len(feed.created) == 1


class TestRamIssueHysteresis:
    def _raise(self, feed):
        for _ in range(HOLD_POLLS + 1):
            feed.poll(_mem(256, 25))
        assert len(feed.created) == 1

    def test_stays_between_80_and_85(self, feed):
        self._raise(feed)
        feed.poll(_mem(256, 45))  # ~82 %
        assert feed.deleted == []

    def test_cleared_below_80(self, feed):
        self._raise(feed)
        feed.poll(_mem(256, 60))  # ~76.6 %
        assert feed.deleted == ["ram_high_e1"]
        assert feed.coord._ram_issue_active is False
        assert feed.coord._mem_high_since is None

    def test_not_cleared_while_available_below_floor(self, feed):
        for _ in range(HOLD_POLLS + 1):
            feed.poll(_mem(64, 12))
        feed.poll(_mem(64, 14))  # 78 % but still < 16 MB
        assert feed.deleted == []
        feed.poll(_mem(64, 20))  # 68.75 %, 20 MB
        assert feed.deleted == ["ram_high_e1"]

    def test_new_hold_time_after_clear(self, feed):
        self._raise(feed)
        feed.poll(_mem(256, 60))
        for _ in range(HOLD_POLLS):
            feed.poll(_mem(256, 25))
        assert len(feed.created) == 1
        feed.poll(_mem(256, 25))
        assert len(feed.created) == 2


class TestRamIssueWithoutEntry:
    def test_no_issue_without_config_entry(self):
        f = _Feed(_make_coordinator(entry=False))
        try:
            for _ in range(HOLD_POLLS + 1):
                f.poll(_mem(256, 25))
            assert not f.created
            assert f.coord._ram_issue_active is True
        finally:
            f.stop()


# =====================================================================
# Poll integration
# =====================================================================


class TestPollIntegration:
    @pytest.mark.asyncio
    async def test_poll_fills_memory_pressure(self):
        coord = _make_coordinator()
        api = coord.api
        api.detect_features = AsyncMock(return_value={})
        api.get_router_info = AsyncMock(return_value={})
        api.get_wan_status = AsyncMock(return_value={"connected": True})
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(
            return_value={"uptime": 1, "cpu_load": 1.0, "memory": _mem(256, 64)}
        )
        api.get_services = AsyncMock(return_value=[])
        api.uses_ssh_fallback = False
        api.reset_ssh_fallback_flag = MagicMock()
        with patch.object(coord, "_check_memory_pressure") as check:
            data = await coord._async_update_data()
        assert data.memory_pressure["pressure_pct"] == 75.0
        assert data.as_dict()["memory_pressure"] == data.memory_pressure
        check.assert_called_once()
        assert check.call_args.args[0] is data

    @pytest.mark.asyncio
    async def test_failed_poll_does_not_evaluate(self):
        from homeassistant.helpers.update_coordinator import UpdateFailed

        from custom_components.openwrt_router.api import OpenWrtConnectionError

        coord = _make_coordinator()
        coord.api.reset_ssh_fallback_flag = MagicMock()
        coord.api.detect_features = AsyncMock(return_value={})
        coord.api.get_router_info = AsyncMock(return_value={})
        coord.api.get_wan_status = AsyncMock(side_effect=OpenWrtConnectionError("x"))
        with patch.object(coord, "_check_memory_pressure") as check:
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
        check.assert_not_called()
