"""Kit for the Network Time Machine index tests (Phases B/C, 1.51.0).

A Time Machine engine on a fake hass (``core_testkit.make_hass``) with the
store on ``core_testkit.FakeDisks`` (patched ``core_store.create_store``,
the store's real migrate function, delayed writes run on demand), the real
``fleet.FleetOutageTracker`` (its Repairs calls and timer patched), fake
coordinators that call their listeners like ``DataUpdateCoordinator`` and a
small fake core: the router registry (entry -> router id) and the
Configuration API surface the engine uses (subscribe, event prefix, module
key, emit). Everything reaches the index through the engine's own
listeners, never by writing marks directly.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from core_testkit import make_hass

from custom_components.openwrt_router import (
    config_api,
    enterprise_core,
    fleet,
    net_engine,
)
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_ENGINE,
    TIME_MACHINE_STORE_KEY,
)
from custom_components.openwrt_router.tm_engine import TimeMachine

T0 = 1_800_000_000.0
RID = {
    "r1": "rtr_" + "1" * 32,
    "r2": "rtr_" + "2" * 32,
    "r3": "rtr_" + "3" * 32,
}
KEY = b"k" * 32
SECRETS = (
    "02:00:5e",
    "02:00:5E",
    "020:",
    "192.168.",
    "10.0.",
    "phy0",
    "phy1",
    "Secret",
    "laptop",
    "wlan0",
)


class Clock:
    """Wall and monotonic clock of a test."""

    def __init__(self, t: float = T0) -> None:
        self.t = t
        self.mono = 1000.0

    def __call__(self) -> float:
        return self.t

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float) -> None:
        self.t += seconds
        self.mono += seconds

    def utc(self) -> datetime:
        return datetime.fromtimestamp(self.t, UTC)


class FakeApi:
    """The Configuration API surface the engine uses."""

    def __init__(self) -> None:
        self.listeners: list[Callable[[Any], None]] = []
        self.prefixes: list[tuple[str, str]] = []
        self.emitted: list[tuple[str, dict[str, Any]]] = []
        self.key: bytes | None = KEY
        self.key_calls = 0

    def subscribe(self, listener: Callable[[Any], None]) -> Callable[[], None]:
        self.listeners.append(listener)
        return lambda: self.listeners.remove(listener)

    def register_event_prefix(self, prefix: str, *, module: str) -> Callable[[], None]:
        self.prefixes.append((prefix, module))
        return lambda: None

    async def async_get_module_key(self, module: str, purpose: str = "") -> bytes:
        self.key_calls += 1
        if self.key is None:
            raise RuntimeError("no key")
        return self.key

    def emit(self, event_type: str, **kw: Any) -> None:
        self.emitted.append((event_type, kw))

    def publish(self, event: Any) -> None:
        for listener in list(self.listeners):
            listener(event)


class FakeCoordinator:
    """Listeners called like ``DataUpdateCoordinator``; no router call."""

    def __init__(self, data: Any = None) -> None:
        self.data = data
        self.last_update_success = True
        self._listeners: dict[Any, Any] = {}

    def async_add_listener(self, update_callback: Any) -> Callable[[], None]:
        key = object()
        self._listeners[key] = update_callback

        def remove() -> None:
            self._listeners.pop(key, None)

        return remove

    def poll(self, data: Any = None, *, ok: bool = True) -> None:
        self.last_update_success = ok
        if data is not None:
            self.data = data
        for listener in list(self._listeners.values()):
            listener()


def iface(
    phy: str, channel: int, band: str = "5g", htmode: str | None = "HE80"
) -> dict:
    out: dict[str, Any] = {
        "ifname": f"{phy}-ap0",
        "mode": "Master",
        "channel": channel,
        "band": band,
        "ssid": "Secret",
        "enabled": True,
    }
    if htmode is not None:
        out["htmode"] = htmode
    return out


def poll_data(
    *ifaces: dict[str, Any], hostname: str = "gw", dfs: Any = None, **kw: Any
) -> Any:
    """Poll data with the fields the engine reads (radios, fingerprint, DFS)."""
    return SimpleNamespace(
        ap_interfaces=list(ifaces),
        sta_interfaces=[],
        dfs=dfs or {},
        router_info={"hostname": hostname, "model": "m"},
        **kw,
    )


class World:
    """One HA instance with the Time Machine (see the module doc)."""

    def __init__(self, disks: Any, stack: contextlib.ExitStack, routers: int) -> None:
        self.disks = disks
        self.stack = stack
        self.clock = Clock()
        self.api = FakeApi()
        self.entries = [
            SimpleNamespace(entry_id=f"r{i + 1}", options={}, title=f"Router {i + 1}")
            for i in range(routers)
        ]
        self.hass = make_hass()
        self.hass.config_entries.async_entries = lambda *_a, **_k: list(self.entries)
        self.hass.bus.async_listen_once = MagicMock(return_value=lambda: None)
        self.coords = {
            e.entry_id: FakeCoordinator(poll_data(iface("phy1", 36)))
            for e in self.entries
        }
        self.core = SimpleNamespace(
            registry=SimpleNamespace(router_id_for_entry=RID.get),
            closed=False,
            loaded=True,
        )
        self.topology: Any = None
        stack.enter_context(
            patch.object(enterprise_core, "async_get_core", lambda _h: self.core)
        )

        async def get_api(_hass: Any, _version: int = 1) -> FakeApi:
            return self.api

        stack.enter_context(
            patch.object(config_api, "async_get_configuration_api", get_api)
        )
        stack.enter_context(patch.object(fleet, "async_raise_issue", MagicMock()))
        stack.enter_context(patch.object(fleet, "async_clear_issue", MagicMock()))
        stack.enter_context(
            patch.object(
                fleet, "async_call_later", MagicMock(return_value=lambda: None)
            )
        )
        stack.enter_context(
            patch.object(net_engine, "async_get_engine", self._ni_engine)
        )
        self.tracker = fleet.async_get_outage_tracker(self.hass)
        for entry in self.entries:
            self.tracker.register(entry.entry_id, entry.title, lambda: None)
        self.engine: TimeMachine | None = None

    def _ni_engine(self, _hass: Any) -> Any:
        if self.topology is None:
            return None
        return SimpleNamespace(topology=self.topology, loaded=True)

    @property
    def disk(self) -> Any:
        return self.disks[TIME_MACHINE_STORE_KEY]

    @property
    def stored(self) -> dict[str, Any] | None:
        data = self.disk.data
        return None if data is None else data["data"]

    async def start(self, *, clients: bool = False) -> TimeMachine:
        engine = TimeMachine(
            self.hass, clock=self.clock, monotonic=self.clock.monotonic
        )
        self.hass.data[DATA_TIME_MACHINE_ENGINE] = engine
        await engine.async_start(clients=clients)
        for entry in self.entries:
            engine.add_entry(entry.entry_id, self.coords[entry.entry_id])
        self.engine = engine
        return engine

    def flush(self) -> None:
        """Run the pending delayed write (what HA does after the delay)."""
        self.disks.flush_delayed()

    async def ha_stop_and_write(self) -> None:
        """HA shuts down: the stop listener, then HA's final write."""
        assert self.engine is not None
        self.engine._on_ha_stop(MagicMock())
        self.flush()
        self.engine.closed = True  # the old process is gone

    def marks(self, kind: str | None = None) -> list[Any]:
        assert self.engine is not None
        return sorted(
            (m for m in self.engine.index if kind is None or m.kind == kind),
            key=lambda m: (m.ts, m.seq),
        )

    def down(self, entry_id: str, error: str = "timeout") -> None:
        """The real tracker: a router crossed the failure threshold, reported."""
        self.tracker.report_down(entry_id, error, self.clock.utc())
        self.tracker._evaluate()

    def up(self, entry_id: str) -> None:
        self.tracker.report_up(entry_id)


@contextlib.contextmanager
def world(disks: Any, routers: int = 1) -> Iterator[World]:
    with contextlib.ExitStack() as stack:
        yield World(disks, stack, routers)
