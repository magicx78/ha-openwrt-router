"""Two HA stores of Traffic Analytics: fine and coarse (Phase I, plan §5).

Pattern of the other enterprise modules: ``core_store.create_store``
(versioned, migrate function, private file, atomic writes) and
``core_store.async_load_store`` (an unreadable or foreign file is kept as
``.bak`` / HA's ``.corrupt.`` copy and the module starts empty, the setup
never fails), a delayed save, an explicit flush when the module is switched
off or the last entry goes, and HA's own final write at shutdown.

* ``openwrt_router.traffic_coarse``: the fleet settings and the
  hourly/daily history. Read once at the first activation (Phase K: the
  switch is a router option, so nothing is read while traffic is off).
* ``openwrt_router.traffic_fine``: the 5-minute history and the last
  counter state per point (rule 8 of ``traffic_counters``). It is opened
  only once the module is on: while off no fine store exists at all.

**Throttling.** HA's ``async_delay_save`` moves a pending write further out
on every call, so a write is armed only when none is pending: the fine
store at most every ``HISTORY_FINE_SAVE_DELAY_S``, the coarse store
``HISTORY_COARSE_SAVE_DELAY_S`` after an hour bucket was completed.

**Size.** Each written section is measured exactly as HA writes it
(``prepare_save_json``). A part over its budget (``HISTORY_BUDGETS`` per
profile and store: infrastructure / client / rest) loses its oldest buckets until it fits
(``store_trimmed_<part>``); the rest of the fine store (counter states) is
left out over its budget. A payload still over the store limit is not
written; the last good one is kept (``save_over_size``).

**Switching off** writes both stores and keeps them: the history is never
deleted automatically (Vorgabe 2026-11-21). While the history is not live
the coarse section read at setup is written back unchanged with every
settings change.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Callable, Mapping
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.json import prepare_save_json

from . import core_store
from .const import (
    TRAFFIC_COARSE_STORE_KEY,
    TRAFFIC_COARSE_STORE_MAX_BYTES,
    TRAFFIC_FINE_STORE_KEY,
    TRAFFIC_FINE_STORE_MAX_BYTES,
    TRAFFIC_STORE_MINOR_VERSION,
    TRAFFIC_STORE_VERSION,
)
from .traffic_const import (
    HISTORY_BUDGETS,
    HISTORY_COARSE_SAVE_DELAY_S,
    HISTORY_FINE_SAVE_DELAY_S,
    HISTORY_PART_CLIENT,
    HISTORY_PART_INFRA,
    HISTORY_PART_REST,
    HISTORY_TRIM_ROUNDS,
)
from .traffic_history import STORE_COARSE, STORE_FINE, TrafficHistory
from .traffic_series import INFRA_SCOPES

_LOGGER = logging.getLogger(__name__)

_COUNTERS = (
    "writes_fine",
    "writes_coarse",
    "save_over_size",
    "load_failed_fine",
    "load_failed_coarse",
    "baselines_restored",
)


def _migrate_store(old_major: int, old_minor: int, data: Any) -> dict[str, Any]:
    """Store migration (version 1 is the first one): keep what is a dict."""
    return dict(data) if isinstance(data, Mapping) else {}


def store_bytes(key: str, payload: Any) -> int:
    """Bytes of a store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": TRAFFIC_STORE_VERSION,
        "minor_version": TRAFFIC_STORE_MINOR_VERSION,
        "key": key,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)


def _part_of(entry: Any) -> str:
    """Store part of one exported point entry (by its scope field)."""
    point = entry.get("p") if isinstance(entry, dict) else None
    scope = point[1] if isinstance(point, list) and len(point) > 1 else None
    return (
        HISTORY_PART_INFRA
        if scope in {s.value for s in INFRA_SCOPES}
        else HISTORY_PART_CLIENT
    )


class TrafficStore:
    """Loads, throttles and size-checks the fine and coarse stores."""

    def __init__(self, hass: HomeAssistant) -> None:
        """Nothing opened yet."""
        self.hass = hass
        self._coarse: Any = None
        self._fine: Any = None
        self.settings: Any = None
        self._coarse_history: Any = None  # stored section while not live
        self._last_fine: dict[str, Any] | None = None
        self._last_coarse_history: Any = None
        self.history: TrafficHistory | None = None
        self.baselines: Callable[[], list[dict[str, Any]]] | None = None
        self._fine_pending = False
        self._coarse_pending = False
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_bytes: dict[str, int | None] = {STORE_FINE: None, STORE_COARSE: None}

    @property
    def live(self) -> bool:
        """True while a history is bound (module on)."""
        return self.history is not None

    # -- load ----------------------------------------------------------------------------

    async def async_load_coarse(self) -> tuple[dict[str, Any], bool]:
        """Read the coarse store once (setup); returns (data, failed)."""
        self._coarse = core_store.create_store(
            self.hass,
            TRAFFIC_STORE_VERSION,
            TRAFFIC_COARSE_STORE_KEY,
            minor_version=TRAFFIC_STORE_MINOR_VERSION,
            migrate=_migrate_store,
            private=True,
            atomic_writes=True,
        )
        result = await core_store.async_load_store(
            self.hass, self._coarse, TRAFFIC_COARSE_STORE_KEY
        )
        if result.failed:
            self.counters["load_failed_coarse"] += 1
        data = result.data or {}
        self.settings = data.get("settings")
        self._coarse_history = data.get("history")
        self._last_coarse_history = self._coarse_history
        return data, result.failed

    async def async_bind(
        self,
        history: TrafficHistory,
        *,
        baselines: Callable[[], list[dict[str, Any]]],
        restore: Callable[[Any], int],
    ) -> int:
        """Module on: open the fine store, fill ``history``; invalid count.

        Never raises. A broken fine store is kept as ``.bak`` and the
        history starts with the coarse tiers only.
        """
        fine_section: Any = None
        stored_baselines: Any = None
        try:
            if self._fine is None:
                self._fine = core_store.create_store(
                    self.hass,
                    TRAFFIC_STORE_VERSION,
                    TRAFFIC_FINE_STORE_KEY,
                    minor_version=TRAFFIC_STORE_MINOR_VERSION,
                    migrate=_migrate_store,
                    private=True,
                    atomic_writes=True,
                )
            result = await core_store.async_load_store(
                self.hass, self._fine, TRAFFIC_FINE_STORE_KEY
            )
            if result.failed:
                self.counters["load_failed_fine"] += 1
            data = result.data or {}
            fine_section = data.get("history")
            stored_baselines = data.get("baselines")
        except Exception as err:  # noqa: BLE001 - start without the fine tier
            self.counters["load_failed_fine"] += 1
            _LOGGER.warning(
                "Traffic history (fine) not read (%s); starting without it",
                type(err).__name__,
            )
        invalid = history.import_payload(fine_section, self._coarse_history)
        try:
            self.counters["baselines_restored"] += restore(stored_baselines)
        except Exception as err:  # noqa: BLE001 - deltas restart with a gap
            _LOGGER.debug("Traffic baselines not restored (%s)", type(err).__name__)
        self.history = history
        self.baselines = baselines
        self._last_fine = None
        return invalid

    # -- payloads ------------------------------------------------------------------------

    def _budgets(self, store: str) -> dict[str, int]:
        name = self.history.profile.name if self.history is not None else ""
        profile = HISTORY_BUDGETS.get(name) or HISTORY_BUDGETS["compact"]
        return dict(profile.get(store) or {})

    def _fit(self, store: str, build: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        """The section of ``store``, trimmed part by part to the budgets."""
        assert self.history is not None
        budgets = self._budgets(store)
        section = build()
        for _round in range(HISTORY_TRIM_ROUNDS):
            over = False
            for part in (HISTORY_PART_INFRA, HISTORY_PART_CLIENT):
                points = {
                    pid: e
                    for pid, e in section["points"].items()
                    if _part_of(e) == part
                }
                if not points:
                    continue
                size = store_bytes(store, points)
                if size <= budgets.get(part, 0):
                    continue
                buckets = self.history.bucket_count(store, part)
                if buckets <= 0:
                    continue
                per = size / buckets
                drop = min(buckets, math.ceil((size - budgets.get(part, 0)) / per) + 1)
                if self.history.trim_oldest(store, part, drop):
                    over = True
            if not over:
                break
            section = build()
        return section

    def fine_payload(self) -> dict[str, Any]:
        """Data of the fine store (called by HA at write time)."""
        self._fine_pending = False
        if self.history is None:
            return self._last_fine or {}
        payload: dict[str, Any] = {
            "history": self._fit(STORE_FINE, self.history.export_fine)
        }
        if self.baselines is not None:
            states = self.baselines()
            rest = store_bytes(STORE_FINE, states)
            if rest <= self._budgets(STORE_FINE).get(HISTORY_PART_REST, 0):
                payload["baselines"] = states
            else:
                self.history.count_trimmed(HISTORY_PART_REST, len(states))
        size = store_bytes(TRAFFIC_FINE_STORE_KEY, payload)
        if size > TRAFFIC_FINE_STORE_MAX_BYTES:
            self.counters["save_over_size"] += 1
            _LOGGER.warning("Traffic history (fine) over its size limit; not written")
            return self._last_fine or {}
        self.last_bytes[STORE_FINE] = size
        self.counters["writes_fine"] += 1
        self._last_fine = payload
        return payload

    def coarse_payload(self) -> dict[str, Any]:
        """Data of the coarse store: settings and the hourly/daily history."""
        self._coarse_pending = False
        payload: dict[str, Any] = {"settings": self.settings}
        if self.history is not None:
            history = self._fit(STORE_COARSE, self.history.export_coarse)
            candidate = {**payload, "history": history}
            size = store_bytes(TRAFFIC_COARSE_STORE_KEY, candidate)
            if size > TRAFFIC_COARSE_STORE_MAX_BYTES:
                self.counters["save_over_size"] += 1
                _LOGGER.warning(
                    "Traffic history (coarse) over its size limit; not written"
                )
                history = self._last_coarse_history
            else:
                self.last_bytes[STORE_COARSE] = size
                self._last_coarse_history = history
            self._coarse_history = history
        if self._coarse_history is not None:
            payload["history"] = self._coarse_history
        self.counters["writes_coarse"] += 1
        return payload

    # -- writes --------------------------------------------------------------------------

    def schedule(self, *, coarse: bool) -> None:
        """Arm the delayed writes (at most one pending write per store)."""
        if self.history is None:
            return
        if self._fine is not None and not self._fine_pending:
            self._fine_pending = True
            self._fine.async_delay_save(self.fine_payload, HISTORY_FINE_SAVE_DELAY_S)
        if coarse and self._coarse is not None and not self._coarse_pending:
            self._coarse_pending = True
            self._coarse.async_delay_save(
                self.coarse_payload, HISTORY_COARSE_SAVE_DELAY_S
            )

    async def async_save_settings(self, settings: Any) -> None:
        """Write the coarse store now (settings change; history kept)."""
        self.settings = settings
        if self._coarse is not None:
            await self._coarse.async_save(self.coarse_payload())

    async def async_flush(self) -> None:
        """Write both stores now (switched off, released); never raises."""
        if self.history is None:
            return
        for store, build, name in (
            (self._fine, self.fine_payload, STORE_FINE),
            (self._coarse, self.coarse_payload, STORE_COARSE),
        ):
            if store is None:
                continue
            try:
                await store.async_save(build())
            except Exception as err:  # noqa: BLE001 - HA's final write retries
                _LOGGER.warning(
                    "Traffic history (%s) not written (%s)", name, type(err).__name__
                )

    async def async_unbind(self) -> None:
        """Module off or released: write everything, then let go of the history."""
        await self.async_flush()
        self.history = None
        self.baselines = None

    def stats(self) -> dict[str, Any]:
        """Sizes and counters (no ids)."""
        return {
            "live": self.live,
            "fine_bytes": self.last_bytes[STORE_FINE],
            "coarse_bytes": self.last_bytes[STORE_COARSE],
            "fine_max_bytes": TRAFFIC_FINE_STORE_MAX_BYTES,
            "coarse_max_bytes": TRAFFIC_COARSE_STORE_MAX_BYTES,
            **self.counters,
        }


__all__ = ["TrafficStore", "store_bytes"]
