"""Helpers for the WiFi RF Intelligence center tests (1.48.0 part 1).

Mocks only: fake coordinators with poll data built from the synthetic RF
fixtures, HA's Store on the in-memory FakeStore, a fake clock for wall and
monotonic time. No router, no Home Assistant instance, no network.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import rf_store
from custom_components.openwrt_router.const import (
    OPTION_WIFI_RF_ASSOCLIST,
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_LISTS,
    OPTION_WIFI_RF_SURVEY,
    WIFI_RF_STORE_KEY,
)
from custom_components.openwrt_router.rf_center import RfCenter

FIXTURES = Path(__file__).parent / "fixtures" / "rf"
RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
KEY = bytes(range(32))
T0 = 1_795_000_000.0  # 2026-11-18
MAC_A = "02:00:00:00:02:01"
MAC_B = "02:00:00:00:02:02"
READS = {
    "get_status": OPTION_WIFI_RF_GET_STATUS,
    "assoclist": OPTION_WIFI_RF_ASSOCLIST,
    "lists": OPTION_WIFI_RF_LISTS,
    "survey": OPTION_WIFI_RF_SURVEY,
}


def load(name: str) -> dict[str, Any]:
    data = json.loads((FIXTURES / name).read_text(encoding="utf-8"))
    data.pop("_comment", None)
    return data


class Clock:
    """Wall and monotonic time in one (tests move it by hand)."""

    def __init__(self, start: float = T0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


class FakeCoordinator:
    """Poll data plus HA's listener API (``async_add_listener``)."""

    def __init__(self, api: Any = None, interval_s: float = 60.0) -> None:
        self.data: Any = None
        self.api = api if api is not None else object()
        self.update_interval = timedelta(seconds=interval_s)
        self.listeners: list[Any] = []

    def async_add_listener(self, callback: Any) -> Any:
        self.listeners.append(callback)
        return lambda: self.listeners.remove(callback)

    def poll(self, data: Any) -> None:
        self.data = data
        for callback in list(self.listeners):
            callback()


def options(*reads: str, every: int = 1, enabled: bool = True) -> dict[str, Any]:
    out: dict[str, Any] = {
        OPTION_WIFI_RF_ENABLED: enabled,
        OPTION_WIFI_RF_EVERY_N_POLLS: every,
    }
    for name in reads:
        out[READS[name]] = True
    return out


def entry(entry_id: str = "e1", opts: dict[str, Any] | None = None) -> Any:
    return SimpleNamespace(entry_id=entry_id, options=dict(opts or {}))


def ap(
    ifname: str = "phy1-ap0",
    *,
    phy: str = "phy1",
    channel: int = 36,
    frequency: int = 5180,
    htmode: str = "HE80",
    center: int = 42,
    noise: int | None = -92,
    txpower: int | None = 20,
    country: str | None = "DE",
) -> dict[str, Any]:
    return {
        "ifname": ifname,
        "ssid": "example-ssid",
        "mode": "Master",
        "bssid": "02:00:00:00:01:01",
        "channel": channel,
        "frequency": frequency,
        "txpower": txpower,
        "htmode": htmode,
        "phy": phy,
        "center_chan1": center,
        "noise": noise,
        "country": country,
    }


def client(mac: str = MAC_A, ifname: str = "phy1-ap0", signal: int = -61) -> dict:
    return {
        "mac": mac,
        "signal": signal,
        "radio": ifname,
        "ssid": "example-ssid",
        "connected_since": 100,
        "tx_rate": 86_670_000,
        "airtime_rx": 4_000_000,
        "airtime_tx": 9_000_000,
    }


def poll_data(
    *,
    uptime: float,
    aps: list[dict[str, Any]] | None = None,
    clients: list[dict[str, Any]] | None = None,
    radio_names: dict[str, str] | None = None,
) -> Any:
    aps = [ap()] if aps is None else aps
    names = {"phy1-ap0": "radio1"} if radio_names is None else radio_names
    return SimpleNamespace(
        uptime=uptime,
        ap_interfaces=copy.deepcopy(aps),
        sta_interfaces=[],
        clients=copy.deepcopy([client()] if clients is None else clients),
        wifi_radios=[{"name": n, "ifname": i} for i, n in names.items()],
    )


def rf_hass() -> Any:
    """make_hass with real tasks (the center starts its rounds as tasks)."""
    hass = make_hass()

    def create_task(coro: Any, name: str | None = None, **_kw: Any) -> Any:
        return asyncio.get_running_loop().create_task(coro, name=name)

    hass.async_create_task = create_task
    return hass


@contextmanager
def rf_disk() -> Iterator[FakeDisk]:
    disk = FakeDisk()
    disk.path = f"/nonexistent/.storage/{WIFI_RF_STORE_KEY}"
    with patch.object(rf_store, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        yield disk


class Reader:
    """Stands in for ``api.async_rf_read``: answers per (kind, device)."""

    def __init__(self) -> None:
        self.answers: dict[tuple[str, str], Any] = {}
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, _api: Any, kind: str, device: str) -> dict[str, Any]:
        self.calls.append((kind, device))
        answer = self.answers.get((kind, device))
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        if answer is None:
            from custom_components.openwrt_router.api import RfReadError

            raise RfReadError("method_not_found", unsupported=True)
        return copy.deepcopy(answer)


async def new_center(
    hass: Any,
    *entries: tuple[Any, Any],
    clock: Clock | None = None,
    key: bytes | None = KEY,
    rids: dict[str, str] | None = None,
    capability: Any = None,
) -> tuple[RfCenter, Clock, Reader]:
    """A loaded center without a core: router ids, key and reads injected."""
    center = RfCenter(hass)
    clock = clock or Clock()
    reader = Reader()
    center.clock = clock
    center.monotonic = clock
    center.auto_bind = False
    center.module_key = key
    mapping = {"e1": RID1, "e2": RID2} if rids is None else rids
    center.router_id_of = mapping.get
    center.capability_of = capability or (lambda _rid, _name: (False, "not_detected"))
    center.read = reader
    await center.async_load()
    for config_entry, coordinator in entries:
        center.add_entry(config_entry, coordinator)
    return center, clock, reader


async def poll(center: RfCenter, coordinator: FakeCoordinator, data: Any) -> None:
    """One poll: the listener fires, then the RF round (if any) finishes."""
    coordinator.poll(data)
    await center.async_wait_rounds()


# --- measured scenario (read API, W6) ---------------------------------------------------


def busy_status(step: int, busy_pct: float = 80.0) -> dict[str, Any]:
    """hostapd get_status after ``step`` reads: ``busy_pct`` of the airtime busy."""
    out = load("hostapd_get_status_mt76_a.json")
    out["airtime"]["time"] += step * 300_000
    out["airtime"]["time_busy"] += int(step * 300_000 * busy_pct / 100)
    return out


def assoc(step: int) -> dict[str, Any]:
    """The mt76 assoclist after ``step`` polls: 1000 packets, 300 retries each."""
    out = load("iwinfo_assoclist_mt76.json")
    for station in out["results"]:
        station["tx"]["packets"] += step * 1000
        station["tx"]["retries"] += step * 300
    return out


async def measured_center(polls: int = 10) -> tuple[RfCenter, Reader]:
    """A ready center whose radio1 (``phy1-ap0``) is 80 % busy, retries 0.3."""
    coordinator = FakeCoordinator()
    center, clock, reader = await new_center(
        rf_hass(), (entry("e1", options("get_status", "assoclist")), coordinator)
    )
    clients = [client(MAC_A), client(MAC_B)]
    for step in range(polls):
        reader.answers[("get_status", "phy1-ap0")] = busy_status(step)
        reader.answers[("assoclist", "phy1-ap0")] = assoc(step)
        await poll(
            center, coordinator, poll_data(uptime=1000 + 300 * step, clients=clients)
        )
        clock.advance(300)  # the read floor of the extra reads
    reader.calls.clear()
    return center, reader
