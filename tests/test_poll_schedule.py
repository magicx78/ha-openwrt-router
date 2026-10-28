"""Tests for poll scheduling and the poll catch-all (package A7).

- N10: every entry gets its own stagger offset, and only the first
  *scheduled* poll is delayed — never an explicitly requested refresh.
- N11: the poll interval is derived from the current state on every poll
  (SSH fallback 300 s, CPU throttling 120 s, else 60 s) instead of latching.
- NEU-B5: unexpected exceptions are recorded as failures and surface as
  UpdateFailed, logged once with traceback.
"""
from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import (
    DataUpdateCoordinator,
    UpdateFailed,
)

from custom_components.openwrt_router import _stagger_offset
from custom_components.openwrt_router.api import OpenWrtAuthError
from custom_components.openwrt_router.coordinator import OpenWrtCoordinator
from custom_components.openwrt_router.const import (
    NOTIFICATION_FAILURE_THRESHOLD,
    SCAN_INTERVAL_SECONDS,
    SSH_FALLBACK_INTERVAL_SECONDS,
)

from test_coordinator import _make_coordinator


# ---------------------------------------------------------------------------
# N10 — stagger offset
# ---------------------------------------------------------------------------


class TestStaggerOffset:
    def test_entries_get_distinct_offsets(self):
        ids = ["c", "a", "b"]
        offsets = {eid: _stagger_offset(ids, eid, 60) for eid in ids}
        assert sorted(offsets.values()) == [0, 20, 40]

    def test_offset_does_not_depend_on_list_order(self):
        assert _stagger_offset(["b", "a"], "b", 60) == _stagger_offset(
            ["a", "b"], "b", 60
        )

    def test_single_entry_has_no_offset(self):
        assert _stagger_offset(["a"], "a", 60) == 0

    def test_entry_missing_from_list_is_counted(self):
        # The entry being set up is always part of the spread.
        assert _stagger_offset(["a"], "b", 60) == 30


def _staggered(offset: int):
    _, api = _make_coordinator()
    with patch("homeassistant.helpers.frame.report_usage"):
        return OpenWrtCoordinator(
            hass=MagicMock(), api=api, entry_title="test", poll_offset_seconds=offset
        )


class TestStaggerOnlyDelaysScheduledPoll:
    @pytest.mark.asyncio
    async def test_requested_refreshes_never_sleep(self):
        coord = _staggered(45)
        with patch(
            "custom_components.openwrt_router.coordinator.asyncio.sleep",
            new=AsyncMock(),
        ) as sleep:
            for _ in range(3):
                await coord._async_update_data()
        assert all(c.args != (45,) for c in sleep.await_args_list)

    @pytest.mark.asyncio
    async def test_first_scheduled_poll_is_delayed_once(self):
        coord = _staggered(45)
        with (
            patch(
                "custom_components.openwrt_router.coordinator.asyncio.sleep",
                new=AsyncMock(),
            ) as sleep,
            patch.object(
                DataUpdateCoordinator, "_handle_refresh_interval", new=AsyncMock()
            ) as base,
        ):
            await coord._handle_refresh_interval()
            await coord._handle_refresh_interval()
        sleep.assert_awaited_once_with(45)
        assert base.await_count == 2

    @pytest.mark.asyncio
    async def test_delayed_poll_skipped_when_refresh_rescheduled_meanwhile(self):
        coord = _staggered(45)

        async def _refresh_during_sleep(_seconds):
            # An explicit refresh ran while waiting and scheduled the next poll.
            coord._unsub_refresh = MagicMock()

        with (
            patch(
                "custom_components.openwrt_router.coordinator.asyncio.sleep",
                new=AsyncMock(side_effect=_refresh_during_sleep),
            ),
            patch.object(
                DataUpdateCoordinator, "_handle_refresh_interval", new=AsyncMock()
            ) as base,
        ):
            await coord._handle_refresh_interval()
        base.assert_not_awaited()


# ---------------------------------------------------------------------------
# N11 — interval derived from current state
# ---------------------------------------------------------------------------


def _coord_with(cpu: float, ssh: bool):
    coord, api = _make_coordinator()
    api.reset_ssh_fallback_flag = MagicMock()
    api.uses_ssh_fallback = ssh
    api.get_router_status = AsyncMock(return_value={
        "uptime": 1, "cpu_load": cpu, "cpu_load_5min": 0.0,
        "cpu_load_15min": 0.0, "memory": {},
    })
    return coord, api


class TestIntervalFromState:
    @pytest.mark.asyncio
    async def test_ssh_fallback_then_repaired_acl_restores_default(self):
        coord, api = _coord_with(cpu=10.0, ssh=True)
        with patch(
            "homeassistant.components.persistent_notification.async_create"
        ):
            await coord._async_update_data()
        assert coord.update_interval == timedelta(
            seconds=SSH_FALLBACK_INTERVAL_SECONDS
        )
        api.uses_ssh_fallback = False
        await coord._async_update_data()
        assert coord.update_interval == timedelta(seconds=SCAN_INTERVAL_SECONDS)

    @pytest.mark.asyncio
    async def test_ssh_fallback_wins_over_cpu_restore(self):
        # Before: throttle restore (cpu < 80) overwrote the 300 s fallback.
        coord, api = _coord_with(cpu=130.0, ssh=True)
        with patch(
            "homeassistant.components.persistent_notification.async_create"
        ):
            await coord._async_update_data()
            api.get_router_status.return_value["cpu_load"] = 10.0
            await coord._async_update_data()
        assert coord.update_interval == timedelta(
            seconds=SSH_FALLBACK_INTERVAL_SECONDS
        )

    @pytest.mark.asyncio
    async def test_ssh_fallback_wins_over_throttle(self):
        coord, api = _coord_with(cpu=10.0, ssh=True)
        with patch(
            "homeassistant.components.persistent_notification.async_create"
        ):
            await coord._async_update_data()
            api.get_router_status.return_value["cpu_load"] = 130.0
            await coord._async_update_data()
        assert coord._throttled is True
        assert coord.update_interval == timedelta(
            seconds=SSH_FALLBACK_INTERVAL_SECONDS
        )

    @pytest.mark.asyncio
    async def test_throttled_without_fallback(self):
        coord, _ = _coord_with(cpu=130.0, ssh=False)
        await coord._async_update_data()
        assert coord.update_interval == timedelta(seconds=SCAN_INTERVAL_SECONDS * 2)


# ---------------------------------------------------------------------------
# NEU-B5 — catch-all
# ---------------------------------------------------------------------------


class TestCatchAll:
    @pytest.mark.parametrize("exc", [OSError("io"), IndexError("idx"), LookupError()])
    @pytest.mark.asyncio
    async def test_unexpected_error_is_recorded(self, exc):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=exc)
        with pytest.raises(UpdateFailed):
            await coord._async_update_data()
        assert coord._failure_count == 1

    @pytest.mark.asyncio
    async def test_unexpected_errors_reach_the_outage_tracker(self):
        coord, api = _make_coordinator()
        tracker = MagicMock()
        coord.attach_outage_tracker(tracker)
        coord._entry = SimpleNamespace(entry_id="e1")
        api.get_wan_status = AsyncMock(side_effect=OSError("io"))
        for _ in range(NOTIFICATION_FAILURE_THRESHOLD):
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
        tracker.report_down.assert_called()

    @pytest.mark.asyncio
    async def test_traceback_logged_once_per_streak(self, caplog):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OSError("io"))
        with caplog.at_level("DEBUG"):
            for _ in range(3):
                with pytest.raises(UpdateFailed):
                    await coord._async_update_data()
        warnings = [r for r in caplog.records if r.levelname in ("WARNING", "ERROR")
                    and "Unexpected error" in r.getMessage()]
        assert len(warnings) == 1
        assert warnings[0].exc_info is not None

    @pytest.mark.asyncio
    async def test_auth_failed_still_propagates(self):
        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthError("bad"))
        for _ in range(2):
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
        with pytest.raises(ConfigEntryAuthFailed):
            await coord._async_update_data()

    @pytest.mark.asyncio
    async def test_cancelled_error_is_not_caught(self):
        import asyncio

        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=asyncio.CancelledError())
        with pytest.raises(asyncio.CancelledError):
            await coord._async_update_data()
        assert coord._failure_count == 0
