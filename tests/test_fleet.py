"""Tests for the fleet-wide outage tracker (fleet.py)."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

from custom_components.openwrt_router.const import (
    ERROR_TYPE_AUTH,
    ERROR_TYPE_CONNECTION,
    ERROR_TYPE_TIMEOUT,
    EVENT_OUTAGE,
)
from custom_components.openwrt_router.fleet import (
    OUTAGE_SETTLE_SECONDS,
    FleetOutageTracker,
    async_get_outage_tracker,
)

T0 = datetime(2026, 10, 20, 8, 5, tzinfo=UTC)


class _Harness:
    """Tracker with captured timers, issues and events."""

    def __init__(self, routers=("gw", "ap1", "ap4"), interval=60):
        self.hass = MagicMock()
        self.hass.data = {}
        self.timers: list = []
        self.cancelled: list = []
        self._p_later = patch(
            "custom_components.openwrt_router.fleet.async_call_later",
            side_effect=self._call_later,
        )
        self._p_ir = patch("custom_components.openwrt_router.issues.ir")
        self._p_later.start()
        self.ir = self._p_ir.start()
        self.tracker = FleetOutageTracker(self.hass)
        for r in routers:
            self.tracker.register(r, f"Router {r}", lambda: timedelta(seconds=interval))

    def _call_later(self, hass, delay, action):
        cancel = MagicMock()
        self.timers.append((delay, action, cancel))
        return cancel

    def fire_timer(self):
        delay, action, cancel = self.timers.pop(0)
        action(T0 + timedelta(seconds=delay))

    def stop(self):
        self._p_later.stop()
        self._p_ir.stop()

    @property
    def created(self):
        return [c.args[2] for c in self.ir.async_create_issue.call_args_list]

    @property
    def deleted(self):
        return [c.args[2] for c in self.ir.async_delete_issue.call_args_list]

    @property
    def events(self):
        return [
            c.args[1]
            for c in self.hass.bus.async_fire.call_args_list
            if c.args[0] == EVENT_OUTAGE
        ]


@pytest.fixture
def h():
    harness = _Harness()
    yield harness
    harness.stop()


class TestBundling:
    def test_all_routers_down_staggered_gives_one_lan_issue(self, h):
        """The 2026-10-20 case: three routers drop within one poll cycle."""
        h.tracker.report_down("gw", ERROR_TYPE_CONNECTION, T0)
        h.tracker.report_down("ap1", ERROR_TYPE_TIMEOUT, T0 + timedelta(seconds=20))
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0 + timedelta(seconds=40))
        assert len(h.timers) == 1  # one settle window, not one per router
        assert h.timers[0][0] == 60 + OUTAGE_SETTLE_SECONDS

        h.fire_timer()

        assert h.created == ["lan_unreachable"]
        kwargs = h.ir.async_create_issue.call_args.kwargs
        assert kwargs["translation_key"] == "lan_unreachable"
        assert kwargs["translation_placeholders"]["count"] == "3"
        assert kwargs["is_persistent"] is False
        assert len(h.events) == 1
        ev = h.events[0]
        assert (ev["scope"], ev["state"]) == ("fleet", "down")
        assert ev["since"] == T0.isoformat()
        assert ev["error_type"] == "mixed"

    def test_single_router_down_gives_router_issue(self, h):
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()

        assert h.created == ["router_unreachable_ap4"]
        assert h.ir.async_create_issue.call_args.kwargs[
            "translation_placeholders"
        ]["router"] == "Router ap4"
        assert [(e["scope"], e["state"]) for e in h.events] == [("router", "down")]

    def test_auth_error_is_never_bundled(self, h):
        h.tracker.report_down("gw", ERROR_TYPE_CONNECTION, T0)
        h.tracker.report_down("ap1", ERROR_TYPE_AUTH, T0)
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()

        assert "lan_unreachable" not in h.created
        assert sorted(h.created) == [
            "router_unreachable_ap1",
            "router_unreachable_ap4",
            "router_unreachable_gw",
        ]

    def test_single_configured_router_is_never_a_lan_outage(self):
        h = _Harness(routers=("gw",))
        try:
            h.tracker.report_down("gw", ERROR_TYPE_CONNECTION, T0)
            h.fire_timer()
            assert h.created == ["router_unreachable_gw"]
        finally:
            h.stop()

    def test_single_issues_fold_into_lan_issue_when_last_router_drops(self, h):
        """A slow (SSH-fallback) router crossing the threshold late tips it to 'all'."""
        h.tracker.report_down("gw", ERROR_TYPE_CONNECTION, T0)
        h.tracker.report_down("ap1", ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()
        assert sorted(h.created) == ["router_unreachable_ap1", "router_unreachable_gw"]

        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0 + timedelta(minutes=10))
        h.fire_timer()

        assert sorted(h.deleted) == ["router_unreachable_ap1", "router_unreachable_gw"]
        assert h.created[-1] == "lan_unreachable"
        assert h.events[-1]["scope"] == "fleet"


class TestRecovery:
    def test_router_recovers_before_settle_window_is_silent(self, h):
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)
        h.tracker.report_up("ap4")

        h.timers[0][2].assert_called_once()  # pending evaluation cancelled
        assert h.created == []
        assert h.events == []

    def test_router_recovery_clears_issue_and_fires_up(self, h):
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()
        h.tracker.report_up("ap4")

        assert h.deleted == ["router_unreachable_ap4"]
        up = h.events[-1]
        assert (up["scope"], up["state"]) == ("router", "up")
        assert up["duration_s"] > 0

    def test_lan_recovery_staggered_does_not_spawn_single_issues(self, h):
        for r in ("gw", "ap1", "ap4"):
            h.tracker.report_down(r, ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()

        h.tracker.report_up("gw")  # first router back ends the LAN outage
        assert h.deleted == ["lan_unreachable"]
        assert (h.events[-1]["scope"], h.events[-1]["state"]) == ("fleet", "up")
        assert len(h.timers) == 1  # fresh settle window for the rest

        h.tracker.report_up("ap1")
        h.tracker.report_up("ap4")
        h.timers[0][2].assert_called_once()
        assert h.created == ["lan_unreachable"]  # nothing new

    def test_router_still_down_after_lan_recovery_gets_own_issue(self, h):
        for r in ("gw", "ap1", "ap4"):
            h.tracker.report_down(r, ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()
        h.tracker.report_up("gw")
        h.tracker.report_up("ap1")
        h.fire_timer()

        assert h.created == ["lan_unreachable", "router_unreachable_ap4"]


class TestLifecycle:
    def test_unregister_drops_issue(self, h):
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)
        h.fire_timer()
        h.tracker.unregister("ap4")

        assert h.deleted == ["router_unreachable_ap4"]
        h.tracker.report_down("ap4", ERROR_TYPE_CONNECTION, T0)  # ignored now
        assert h.timers == []

    def test_unknown_entry_is_ignored(self, h):
        h.tracker.report_down("nope", ERROR_TYPE_CONNECTION, T0)
        h.tracker.report_up("nope")
        assert h.timers == []

    def test_get_tracker_is_singleton_per_hass(self):
        hass = MagicMock()
        hass.data = {}
        assert async_get_outage_tracker(hass) is async_get_outage_tracker(hass)
