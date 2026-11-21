"""Schedule of the extra RF reads of one router (WiFi RF Intelligence 1.48.0).

The reads themselves live in ``api.py`` (``async_rf_read``); this module
only decides which of them run and keeps their state. No other network
access, no Home Assistant objects.

Rules (plan 2026-11-17 §8, task decisions):

* Every kind is off unless its option is on; with ``wifi_rf_enabled`` off
  :meth:`RfCollector.plan` returns nothing at all.
* Periodic kinds (get_status, assoclist, survey) run every N polls and never
  more often than :data:`.rf_guard.POLL_READ_MIN_INTERVAL_S` per target
  (router + interface + kind), minus a small jitter tolerance.
* Setup kinds (freqlist, txpowerlist) run once per radio and again only
  after its channel or country changed; never as part of the cadence.
* One round per router at a time (the caller holds :attr:`busy`), the kinds
  of a round run one after the other, so at most one fetch per kind and
  router is in flight; the round has an overall time limit.
* Errors: method not found / permission denied / invalid argument make the
  target ``unsupported`` and it is asked again only after
  ``WIFI_RF_PROBE_BACKOFF_MAX_S``; transient errors back off exponentially
  from the floor. No retry storm, nothing raised to the poll.
* Survey and txpowerlist need the Core capability (``rf.survey`` /
  ``rf.txpowerlist``, facts of the deployed ACL) to be available; otherwise
  they are not asked and stay "not ready" with the Core's reason.
* While the coordinator is throttled (CPU) or on the SSH fallback the
  periodic reads pause (plan §8.4 proposal).
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .api import (
    RF_KIND_ASSOCLIST,
    RF_KIND_FREQLIST,
    RF_KIND_GET_STATUS,
    RF_KIND_SURVEY,
    RF_KIND_TXPOWERLIST,
    RfReadError,
)
from .const import (
    DEFAULT_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_ASSOCLIST,
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_LISTS,
    OPTION_WIFI_RF_SURVEY,
    WIFI_RF_EVERY_N_POLLS_MAX,
    WIFI_RF_EVERY_N_POLLS_MIN,
    WIFI_RF_FLOOR_TOLERANCE_S,
    WIFI_RF_PROBE_BACKOFF_MAX_S,
    WIFI_RF_ROUND_TIMEOUT_S,
)
from .rf_guard import POLL_READ_MIN_INTERVAL_S
from .rf_models import CapabilityState

_LOGGER = logging.getLogger(__name__)

PERIODIC_KINDS = (RF_KIND_GET_STATUS, RF_KIND_ASSOCLIST, RF_KIND_SURVEY)
SETUP_KINDS = (RF_KIND_FREQLIST, RF_KIND_TXPOWERLIST)
KIND_OPTIONS: Mapping[str, str] = {
    RF_KIND_GET_STATUS: OPTION_WIFI_RF_GET_STATUS,
    RF_KIND_ASSOCLIST: OPTION_WIFI_RF_ASSOCLIST,
    RF_KIND_FREQLIST: OPTION_WIFI_RF_LISTS,
    RF_KIND_TXPOWERLIST: OPTION_WIFI_RF_LISTS,
    RF_KIND_SURVEY: OPTION_WIFI_RF_SURVEY,
}
# Core-owned capability that must be available before a kind is asked.
KIND_CAPABILITY: Mapping[str, str] = {
    RF_KIND_SURVEY: "rf.survey",
    RF_KIND_TXPOWERLIST: "rf.txpowerlist",
}
REASON_OPTION_OFF = "option_off"
REASON_CAPABILITY = "capability_unavailable"
REASON_ROUND_TIMEOUT = "round_timeout"
REASON_PAUSED = "paused"


@dataclass(frozen=True)
class RfOptions:
    """The RF options of one entry, validated (odd values fall back)."""

    enabled: bool = False
    kinds: frozenset[str] = frozenset()
    every_n_polls: int = DEFAULT_WIFI_RF_EVERY_N_POLLS


def options_from_entry(options: Mapping[str, Any] | None) -> RfOptions:
    """Read the RF options; only a real True switches on."""
    opts = options if isinstance(options, Mapping) else {}
    every = opts.get(OPTION_WIFI_RF_EVERY_N_POLLS, DEFAULT_WIFI_RF_EVERY_N_POLLS)
    if (
        isinstance(every, bool)
        or not isinstance(every, int)
        or not WIFI_RF_EVERY_N_POLLS_MIN <= every <= WIFI_RF_EVERY_N_POLLS_MAX
    ):
        every = DEFAULT_WIFI_RF_EVERY_N_POLLS
    enabled = opts.get(OPTION_WIFI_RF_ENABLED) is True
    kinds = frozenset(
        kind for kind, option in KIND_OPTIONS.items() if opts.get(option) is True
    )
    return RfOptions(enabled, kinds if enabled else frozenset(), every)


@dataclass(frozen=True)
class Target:
    """One read: kind, kernel interface and the radio it belongs to."""

    kind: str
    device: str
    radio_id: str


@dataclass
class TargetState:
    """What the collector knows about one target (memory only)."""

    last_at: float | None = None  # monotonic time of the last attempt
    ok_at: float | None = None  # monotonic time of the last success
    state: CapabilityState | None = None
    reason: str | None = None
    failures: int = 0
    retry_at: float | None = None
    list_key: Any = None  # channel/country a setup list was read for

    def as_dict(self) -> dict[str, Any]:
        """Plain view (no device names: the caller keys it)."""
        return {
            "state": self.state.value if self.state else None,
            "reason": self.reason,
            "failures": self.failures,
        }


@dataclass(frozen=True)
class RadioPlanInput:
    """What the plan needs of one radio (from the poll data)."""

    radio_id: str
    devices: tuple[str, ...]  # AP interfaces of the radio, first = primary
    list_key: Any  # (channel, country): a change re-reads the setup lists


@dataclass
class RoundResult:
    """Answers of one round: (kind, device) -> raw answer, plus errors."""

    answers: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    errors: dict[tuple[str, str], str] = field(default_factory=dict)
    timed_out: bool = False
    taken_at: float | None = None  # wall clock when the round started


class RfCollector:
    """Decides and runs the extra RF reads of one router."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        floor_s: float = POLL_READ_MIN_INTERVAL_S,
        tolerance_s: float = WIFI_RF_FLOOR_TOLERANCE_S,
        round_timeout_s: float = WIFI_RF_ROUND_TIMEOUT_S,
        backoff_max_s: float = WIFI_RF_PROBE_BACKOFF_MAX_S,
    ) -> None:
        """A collector with no history (a new HA run probes again)."""
        self._clock = clock
        self.floor_s = floor_s
        self.tolerance_s = tolerance_s
        self.round_timeout_s = round_timeout_s
        self.backoff_max_s = backoff_max_s
        self.targets: dict[tuple[str, str], TargetState] = {}
        self.polls_since: dict[str, int] = {}
        self.busy = False
        self.counters: dict[str, int] = {
            "rounds": 0,
            "reads": 0,
            "read_errors": 0,
            "rounds_timed_out": 0,
            "rounds_skipped_busy": 0,
            "polls_paused": 0,
            "entries_truncated": 0,
        }

    # -- plan ------------------------------------------------------------------

    def plan(
        self,
        options: RfOptions,
        radios: Sequence[RadioPlanInput],
        *,
        paused: bool,
        capability: Callable[[str], tuple[bool, str | None]],
    ) -> list[Target]:
        """Targets due in this poll (counts the poll; no I/O).

        ``capability(name)`` answers (available, reason) for a Core-owned
        capability. Returns [] when RF is off or nothing is due.
        """
        if not options.enabled or not options.kinds:
            return []
        if paused:
            self.counters["polls_paused"] += 1
            return []
        now = self._clock()
        due_kinds = self._advance(options)
        targets: list[Target] = []
        for radio in radios:
            if not radio.devices:
                continue
            for kind in sorted(options.kinds):
                if kind in KIND_CAPABILITY and not self._capable(
                    kind, radio, capability
                ):
                    continue
                for device in self._devices(kind, radio):
                    if self._wanted(kind, device, radio, due_kinds, now):
                        targets.append(Target(kind, device, radio.radio_id))
        return targets

    def _advance(self, options: RfOptions) -> set[str]:
        due: set[str] = set()
        for kind in PERIODIC_KINDS:
            if kind not in options.kinds:
                self.polls_since.pop(kind, None)
                continue
            count = self.polls_since.get(kind)
            # The first poll with the kind on reads at once (a start probe).
            count = options.every_n_polls if count is None else count + 1
            if count >= options.every_n_polls:
                due.add(kind)
                count = 0
            self.polls_since[kind] = count
        return due

    def _capable(
        self,
        kind: str,
        radio: RadioPlanInput,
        capability: Callable[[str], tuple[bool, str | None]],
    ) -> bool:
        available, reason = capability(KIND_CAPABILITY[kind])
        if available:
            return True
        for device in self._devices(kind, radio):
            state = self.targets.setdefault((kind, device), TargetState())
            state.state = CapabilityState.UNSUPPORTED
            state.reason = f"{REASON_CAPABILITY}:{reason or 'unknown'}"
        return False

    @staticmethod
    def _devices(kind: str, radio: RadioPlanInput) -> tuple[str, ...]:
        # assoclist per AP interface; everything else once per radio.
        if kind == RF_KIND_ASSOCLIST:
            return radio.devices
        return radio.devices[:1]

    def _wanted(
        self,
        kind: str,
        device: str,
        radio: RadioPlanInput,
        due_kinds: set[str],
        now: float,
    ) -> bool:
        state = self.targets.get((kind, device))
        if state is not None and state.retry_at is not None and now < state.retry_at:
            return False
        if kind in SETUP_KINDS:
            return (
                state is None
                or state.ok_at is None
                or (state.list_key != radio.list_key)
            )
        if kind not in due_kinds:
            return False
        if state is None or state.last_at is None:
            return True
        return now - state.last_at >= self.floor_s - self.tolerance_s

    # -- round -----------------------------------------------------------------

    async def async_run(
        self,
        targets: Sequence[Target],
        read: Callable[[str, str], Awaitable[dict[str, Any]]],
        *,
        list_keys: Mapping[str, Any] | None = None,
        wall_clock: Callable[[], float] = time.time,
    ) -> RoundResult:
        """Run the targets one by one within the round time limit.

        ``read(kind, device)`` is ``api.async_rf_read`` bound to the router's
        API. Never raises for a router error; the caller must hold
        :attr:`busy` (one round per router).
        """
        result = RoundResult(taken_at=wall_clock())
        if not targets:
            return result
        self.counters["rounds"] += 1
        keys = list_keys or {}
        try:
            async with asyncio.timeout(self.round_timeout_s):
                for target in targets:
                    await self._one(target, read, result, keys.get(target.radio_id))
        except TimeoutError:
            result.timed_out = True
            self.counters["rounds_timed_out"] += 1
            for target in targets:
                key = (target.kind, target.device)
                if key not in result.answers and key not in result.errors:
                    result.errors[key] = REASON_ROUND_TIMEOUT
        return result

    async def _one(
        self,
        target: Target,
        read: Callable[[str, str], Awaitable[dict[str, Any]]],
        result: RoundResult,
        list_key: Any,
    ) -> None:
        key = (target.kind, target.device)
        state = self.targets.setdefault(key, TargetState())
        now = self._clock()
        state.last_at = now
        self.counters["reads"] += 1
        try:
            answer = await read(target.kind, target.device)
        except RfReadError as err:
            self.counters["read_errors"] += 1
            self._failed(state, err, now)
            result.errors[key] = err.reason
            return
        if isinstance(answer.get("_truncated"), int):
            self.counters["entries_truncated"] += answer["_truncated"]
        state.ok_at = now
        state.state = CapabilityState.MEASURED
        state.reason = None
        state.failures = 0
        state.retry_at = None
        state.list_key = list_key
        result.answers[key] = answer

    def _failed(self, state: TargetState, err: RfReadError, now: float) -> None:
        state.failures += 1
        state.reason = err.reason
        if err.unsupported:
            state.state = CapabilityState.UNSUPPORTED
            state.retry_at = now + self.backoff_max_s
            return
        state.state = CapabilityState.UNREACHABLE
        delay = min(self.backoff_max_s, self.floor_s * 2 ** (state.failures - 1))
        state.retry_at = now + delay

    # -- views -----------------------------------------------------------------

    def kind_state(
        self, kind: str, device: str
    ) -> tuple[CapabilityState | None, str | None]:
        """State and reason of one target; (None, None) when never planned."""
        state = self.targets.get((kind, device))
        if state is None:
            return None, None
        return state.state, state.reason

    def forget_device(self, device: str) -> None:
        """Drop the state of an interface that is gone."""
        for key in [k for k in self.targets if k[1] == device]:
            del self.targets[key]

    def summary(self) -> dict[str, Any]:
        """Counters and per-kind state counts (no device names)."""
        by_kind: dict[str, dict[str, int]] = {}
        for (kind, _device), state in self.targets.items():
            name = state.state.value if state.state else "not_assessed"
            bucket = by_kind.setdefault(kind, {})
            bucket[name] = bucket.get(name, 0) + 1
        return {"counters": dict(self.counters), "targets": by_kind}
