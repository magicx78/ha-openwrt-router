"""Fleet-wide state across all OpenWrt router config entries.

Currently: outage tracking. Each coordinator reports its router as down (after
NOTIFICATION_FAILURE_THRESHOLD failed polls) or up. The tracker waits a short
settle window and then classifies the outage:

- every loaded router (at least two) is down for a connection/timeout-type
  reason → ONE ``lan_unreachable`` Repairs issue. Several routers failing at
  the same moment almost always points at the HA host or the LAN, not at
  each router individually;
- otherwise → one ``router_unreachable_<entry_id>`` issue per down router.

Both start and end are also fired as ``openwrt_router_outage_event``.
Auth errors are never bundled — they are a per-router credential problem.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from homeassistant.core import CALLBACK_TYPE, HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.event import async_call_later
from homeassistant.util import dt as dt_util

from .const import DOMAIN, ERROR_TYPE_AUTH, EVENT_OUTAGE
from .issues import (
    ISSUE_LAN_UNREACHABLE,
    ISSUE_ROUTER_UNREACHABLE,
    async_clear_issue,
    async_raise_issue,
    router_unreachable_issue_id,
)

_LOGGER = logging.getLogger(__name__)

_DATA_KEY = f"{DOMAIN}_fleet_outage_tracker"

# Added to the slowest poll interval before an outage is classified, so that
# staggered coordinators (poll offsets 0/20/40 s) all get a chance to report.
OUTAGE_SETTLE_SECONDS = 30

SCOPE_FLEET = "fleet"
SCOPE_ROUTER = "router"


@dataclass
class _Router:
    title: str
    interval: Callable[[], timedelta | None]


@dataclass
class _Outage:
    since: datetime
    error_type: str | None
    reported: bool = False  # per-router issue + "down" event already emitted


@callback
def async_get_outage_tracker(hass: HomeAssistant) -> FleetOutageTracker:
    """Return the per-HA-instance tracker, creating it on first use."""
    tracker = hass.data.get(_DATA_KEY)
    if tracker is None:
        tracker = hass.data[_DATA_KEY] = FleetOutageTracker(hass)
    return tracker


class FleetOutageTracker:
    """Bundle simultaneous router outages into a single Repairs issue."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._routers: dict[str, _Router] = {}
        self._down: dict[str, _Outage] = {}
        self._fleet_since: datetime | None = None
        self._cancel_eval: CALLBACK_TYPE | None = None

    # ------------------------------------------------------------------
    # Coordinator / setup interface
    # ------------------------------------------------------------------

    @callback
    def register(
        self,
        entry_id: str,
        title: str,
        interval: Callable[[], timedelta | None],
    ) -> None:
        """Add a router; ``interval`` returns its current poll interval."""
        self._routers[entry_id] = _Router(title=title, interval=interval)

    @callback
    def unregister(self, entry_id: str) -> None:
        """Remove a router (entry unloaded) and drop its issues silently."""
        self._routers.pop(entry_id, None)
        outage = self._down.pop(entry_id, None)
        if outage is not None and outage.reported:
            async_clear_issue(self.hass, router_unreachable_issue_id(entry_id))
        if self._fleet_since is not None and not self._all_down():
            self._fleet_since = None
            async_clear_issue(self.hass, ISSUE_LAN_UNREACHABLE)
            if self._down:
                self._schedule_evaluation()
        if not self._down:
            self._cancel_pending()

    @callback
    def report_down(
        self, entry_id: str, error_type: str | None, since: datetime
    ) -> None:
        """Router crossed the failure threshold (called on every failed poll)."""
        if entry_id not in self._routers:
            return
        outage = self._down.get(entry_id)
        if outage is None:
            self._down[entry_id] = _Outage(since=since, error_type=error_type)
            self._schedule_evaluation()
            return
        outage.error_type = error_type

    @callback
    def report_up(self, entry_id: str) -> None:
        """Router answered a poll again."""
        outage = self._down.pop(entry_id, None)
        if outage is None:
            return
        now = dt_util.utcnow()
        if self._fleet_since is not None:
            self._end_fleet_outage(now)
            # Routers still down get a fresh settle window: staggered
            # recoveries after a LAN outage must not spawn N single issues.
            if self._down:
                self._schedule_evaluation()
        elif outage.reported:
            async_clear_issue(self.hass, router_unreachable_issue_id(entry_id))
            self._fire(
                SCOPE_ROUTER,
                "up",
                [entry_id],
                outage.since,
                now,
                outage.error_type,
            )
            _LOGGER.info("%s is reachable again", self._title(entry_id))
        if not self._down:
            self._cancel_pending()

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    def _all_down(self) -> bool:
        return (
            len(self._routers) >= 2
            and set(self._routers) <= set(self._down)
            and all(o.error_type != ERROR_TYPE_AUTH for o in self._down.values())
        )

    @callback
    def _schedule_evaluation(self) -> None:
        if self._cancel_eval is not None:
            return
        intervals = [
            iv.total_seconds()
            for r in self._routers.values()
            if (iv := r.interval()) is not None
        ]
        delay = max(intervals, default=0) + OUTAGE_SETTLE_SECONDS
        self._cancel_eval = async_call_later(self.hass, delay, self._evaluate)

    @callback
    def _cancel_pending(self) -> None:
        if self._cancel_eval is not None:
            self._cancel_eval()
            self._cancel_eval = None

    @callback
    def _evaluate(self, _now: datetime | None = None) -> None:
        self._cancel_eval = None
        if self._all_down():
            if self._fleet_since is None:
                self._start_fleet_outage()
            return
        for entry_id, outage in self._down.items():
            if outage.reported:
                continue
            outage.reported = True
            title = self._title(entry_id)
            async_raise_issue(
                self.hass,
                router_unreachable_issue_id(entry_id),
                ISSUE_ROUTER_UNREACHABLE,
                ir.IssueSeverity.WARNING,
                {
                    "router": title,
                    "since": _fmt(outage.since),
                    "error_type": outage.error_type or "unknown",
                },
            )
            self._fire(
                SCOPE_ROUTER, "down", [entry_id], outage.since, None, outage.error_type
            )
            _LOGGER.warning(
                "%s unreachable since %s (%s)",
                title,
                _fmt(outage.since),
                outage.error_type,
            )

    @callback
    def _start_fleet_outage(self) -> None:
        self._fleet_since = min(o.since for o in self._down.values())
        # Fold already raised single issues into the fleet issue.
        for entry_id, outage in self._down.items():
            if outage.reported:
                async_clear_issue(self.hass, router_unreachable_issue_id(entry_id))
                outage.reported = False
        entry_ids = sorted(self._down)
        titles = ", ".join(self._title(e) for e in entry_ids)
        async_raise_issue(
            self.hass,
            ISSUE_LAN_UNREACHABLE,
            ISSUE_LAN_UNREACHABLE,
            ir.IssueSeverity.ERROR,
            {
                "count": str(len(entry_ids)),
                "routers": titles,
                "since": _fmt(self._fleet_since),
            },
        )
        self._fire(
            SCOPE_FLEET,
            "down",
            entry_ids,
            self._fleet_since,
            None,
            self._fleet_error_type(),
        )
        _LOGGER.warning(
            "All %d OpenWrt routers unreachable since %s (%s) — likely a problem "
            "between Home Assistant and the LAN, not in the routers",
            len(entry_ids),
            _fmt(self._fleet_since),
            titles,
        )

    @callback
    def _end_fleet_outage(self, now: datetime) -> None:
        since = self._fleet_since
        if since is None:
            return
        self._fleet_since = None
        async_clear_issue(self.hass, ISSUE_LAN_UNREACHABLE)
        self._fire(SCOPE_FLEET, "up", sorted(self._routers), since, now, None)
        _LOGGER.info(
            "OpenWrt routers reachable again (LAN outage since %s)", _fmt(since)
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fleet_error_type(self) -> str | None:
        types = {o.error_type for o in self._down.values()}
        return types.pop() if len(types) == 1 else "mixed"

    def _title(self, entry_id: str) -> str:
        router = self._routers.get(entry_id)
        return router.title if router else entry_id

    @callback
    def _fire(
        self,
        scope: str,
        state: str,
        entry_ids: list[str],
        since: datetime,
        until: datetime | None,
        error_type: str | None,
    ) -> None:
        payload: dict[str, Any] = {
            "scope": scope,
            "state": state,
            "entry_ids": entry_ids,
            "routers": [self._title(e) for e in entry_ids],
            "since": since.isoformat(),
            "duration_s": int((until - since).total_seconds()) if until else None,
            "error_type": error_type,
        }
        self.hass.bus.async_fire(EVENT_OUTAGE, payload)


def _fmt(ts: datetime) -> str:
    return dt_util.as_local(ts).strftime("%Y-%m-%d %H:%M")
