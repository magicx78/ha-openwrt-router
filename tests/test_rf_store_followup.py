# ruff: noqa: F811  (the disk fixture is imported from another test module)
"""Follow-ups of the review of 1.52.3 (PR #74) for the WiFi RF history store.

1. the thread handover: the result of a write is applied in the event loop,
   the unload flush builds the payload in the executor, and ``dirty`` stays
   set for a poll that came after the snapshot;
2. a write that HA could not complete (known limit, see ``rf_store``): the
   next poll arms the next write and the history reaches the file;
3. a router forgotten while a write is under way does not stay in the kept
   payload, and the next write is armed at once;
4. ``drops.trimmed`` counts only buckets actually removed from memory;
5. the capacity with values as the sources deliver them (utilization and
   retry rate unrounded, the other series whole numbers) and in the worst
   case (every float field at full precision);
6. atomic writes;
7. the kept last good payload is released after the first good write.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import json
import random
import threading
from typing import Any
from unittest.mock import patch

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_rf_store_over_size_v1523 import (
    ALL,
    BERLIN,
    R1,
    R2,
    RID1,
    T0,
    _fill,
    _newest,
    _store,
    _written_newest,
    disk,  # noqa: F401
)

from custom_components.openwrt_router import rf_store
from custom_components.openwrt_router.const import (
    WIFI_RF_MAX_DAILY_BUCKETS,
    WIFI_RF_MAX_HOURLY_BUCKETS,
    WIFI_RF_MAX_RADIOS,
    WIFI_RF_MAX_STORE_BYTES,
    WIFI_RF_STORE_KEY,
)
from custom_components.openwrt_router.rf_aggregate import Agg
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_store import RfStore, ref_key, store_size

# --- 1. thread handover ---------------------------------------------------------------


async def _real_store(tmp_path: Any) -> tuple[Any, RfStore]:
    from homeassistant.core import CoreState, HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    hass.set_state(CoreState.running)
    store = RfStore(hass, tz=lambda: BERLIN)
    await store.async_load()
    return hass, store


async def test_the_result_of_a_write_is_applied_in_the_event_loop(tmp_path):
    hass, store = await _real_store(tmp_path)
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real = store._saved

    def spy(prepared: Any) -> None:
        seen.append(threading.get_ident())
        real(prepared)

    store._saved = spy  # type: ignore[method-assign]
    try:
        _fill(store, 3)
        await store.async_flush()
        await hass.async_block_till_done()
        assert seen == [loop_thread]
        assert store.last_save_bytes is not None
    finally:
        await hass.async_stop(force=True)


async def test_the_unload_flush_builds_the_payload_in_the_executor(tmp_path):
    hass, store = await _real_store(tmp_path)
    loop_thread = threading.get_ident()
    seen: list[int] = []
    real = store._prepare

    def spy(*args: Any) -> Any:
        seen.append(threading.get_ident())
        return real(*args)

    store._prepare = spy  # type: ignore[method-assign]
    try:
        _fill(store, 3)
        await store.async_flush()
        await hass.async_block_till_done()
        assert len(seen) == 1 and seen[0] != loop_thread
        path = tmp_path / ".storage" / WIFI_RF_STORE_KEY
        assert ref_key(R1) in path.read_text()
    finally:
        await hass.async_stop(force=True)


async def test_a_poll_after_the_snapshot_keeps_the_store_dirty(disk):
    store = await _store()
    _fill(store, 2)
    prepared = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    store.record(R1, ALL, T0 + 3600 * 2)  # a poll while the write is under way
    store._saved(prepared)
    assert store.dirty is True
    # without a poll in between the write clears it
    again = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    store._saved(again)
    assert store.dirty is False


# --- 2. a failed write (known limit) ------------------------------------------------


async def test_a_failed_write_is_recovered_by_the_next_poll(tmp_path):
    """HA's Store catches a failed write and gives no result back, so the
    store cannot know it (known limit, module docstring of ``rf_store``).
    The next poll marks the history dirty and arms the next write, which
    reaches the file."""
    from homeassistant.helpers import storage
    from homeassistant.util.file import WriteError

    hass, store = await _real_store(tmp_path)
    calls = {"n": 0}

    def flaky(real: Any) -> Any:
        def write(*args: Any, **kwargs: Any) -> Any:
            calls["n"] += 1
            if calls["n"] == 1:
                raise WriteError("disk full")
            return real(*args, **kwargs)

        return write

    path = tmp_path / ".storage" / WIFI_RF_STORE_KEY
    try:
        with (
            patch.object(rf_store, "WIFI_RF_SAVE_DELAY_SECONDS", 0.2),
            patch.object(storage, "write_utf8_file", flaky(storage.write_utf8_file)),
            patch.object(
                storage,
                "write_utf8_file_atomic",
                flaky(storage.write_utf8_file_atomic),
            ),
        ):
            store.record(R1, ALL, T0)
            store.schedule_save()
            for _ in range(50):
                await asyncio.sleep(0.02)
                if calls["n"]:
                    break
            await hass.async_block_till_done()
            assert calls["n"] == 1 and not path.exists()
            for i in range(1, 20):  # the polls go on
                store.record(R1, ALL, T0 + 60 * i)
                store.schedule_save()
                await asyncio.sleep(0.03)
            await asyncio.sleep(0.3)
            await hass.async_block_till_done()
        assert calls["n"] >= 2
        assert ref_key(R1) in json.loads(path.read_text())["data"]["radios"]
    finally:
        await hass.async_stop(force=True)


# --- 3. forget during a write ---------------------------------------------------------


async def test_a_router_forgotten_during_a_write_is_dropped_and_rewritten_at_once(disk):
    store = await _store()
    store.record(R1, {"utilization": 1.0}, T0)
    store.record(R2, {"utilization": 1.0}, T0)
    # executor: the write's snapshot is taken ...
    prepared = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    # ... loop: the router is forgotten meanwhile (arms a write at once) ...
    assert store.forget_router(RID1) is True
    armed = len(disk.delayed)
    # ... loop: the write's result arrives: its file still has the router
    store._saved(prepared)
    assert len(disk.delayed) == armed + 1
    kept = store._last_payload
    assert kept is None or ref_key(R1) not in kept["radios"]
    # the file just written still has the router: the next write is now
    func, delay = disk.delayed[-1]
    assert delay == 0
    assert ref_key(R1) not in func()["radios"]


async def test_forget_router_arms_a_write_at_once(disk):
    store = await _store()
    store.record(R1, {"utilization": 1.0}, T0)
    store.schedule_save()  # a pending write in 15 minutes
    assert store.forget_router(RID1) is True
    assert disk.delayed[-1][1] == 0


# --- 4. trimmed counts what memory lost -------------------------------------------------


async def test_overlapping_writes_count_each_trimmed_bucket_once(disk):
    store = await _store()
    _fill(store, 60)
    store.max_bytes = store_size(store._payload()) // 2
    # the unload flush and a delayed write take their snapshots together
    first = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    second = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    assert first.cuts and len(first.cuts) == len(second.cuts)
    store._saved(first)
    store._saved(second)
    assert store.drops["trimmed"] == len(first.cuts)


# --- 5. capacity ------------------------------------------------------------------------


@functools.cache
def _radio_at_caps(precision: str) -> Any:
    """One radio after 10 days of 60 s polls, filled to the bucket caps.

    ``source``: values as the sources deliver them (``rf_evaluate``):
    utilization ``100 * busy / active`` and the retry rate a packet ratio,
    both unrounded; noise, clients, health, roams and channel changes whole
    numbers. ``worst``: every float field of every bucket at full precision.
    """
    with patch.object(
        rf_store, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        store = RfStore(make_hass(), tz=lambda: BERLIN, max_bytes=10**12)
    rnd = random.Random(7)
    for i in range(10 * 1440):
        store.record(
            R1,
            {
                "utilization": rnd.uniform(2, 70),
                "retry_rate": rnd.uniform(0, 0.3),
                "noise": rnd.choice([-95, -94, -93, -92, None]),
                "clients": rnd.randint(0, 25),
                "health": rnd.randint(40, 100),
                "roams": rnd.choice([0, 0, 0, 1]),
                "channel_changes": 0,
            },
            T0 + 60 * i,
        )
    history = store.radios[R1]
    history.raw = {}
    for part, cap, step in (
        (history.hourly, WIFI_RF_MAX_HOURLY_BUCKETS, 3600),
        (history.daily, WIFI_RF_MAX_DAILY_BUCKETS, 86400),
    ):
        for buckets in part.values():
            ordered = sorted(buckets)
            for k in range(1, cap - len(ordered) + 1):
                buckets[ordered[0] - k * step] = buckets[ordered[k % len(ordered)]]
            if precision == "worst":
                for ts in buckets:
                    low, high = rnd.uniform(-95, 0), rnd.uniform(0, 100)
                    buckets[ts] = Agg(
                        60, rnd.uniform(-5000, 6000), low, high, rnd.randint(0, 3)
                    )
            assert len(buckets) == cap
    return history


def _fleet(precision: str, radios: int, **kw: Any) -> RfStore:
    with patch.object(
        rf_store, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        store = RfStore(make_hass(), tz=lambda: BERLIN, **kw)
    for n in range(radios):
        store.radios[RadioRef("rtr_" + f"{n:032x}", "radio0")] = copy.deepcopy(
            _radio_at_caps(precision)
        )
    return store


def _write(store: RfStore) -> Any:
    prepared = store._prepare(store._snapshot(), dict(store.drops), store._generation)
    store._saved(prepared)
    return prepared


def test_values_as_delivered_keep_eight_days_for_the_radio_cap():
    """Documented capacity (CHANGELOG, wifi-rf plan §8.3): with values as the
    sources deliver them, ``WIFI_RF_MAX_RADIOS`` radios at their bucket caps
    fit under the limit, nothing is trimmed."""
    store = _fleet("source", WIFI_RF_MAX_RADIOS)
    prepared = _write(store)
    assert prepared.size <= WIFI_RF_MAX_STORE_BYTES
    assert store.drops["trimmed"] == 0
    history = next(iter(store.radios.values()))
    assert len(history.hourly["utilization"]) == WIFI_RF_MAX_HOURLY_BUCKETS


def test_full_precision_everywhere_trims_the_radio_cap_but_keeps_six_days():
    """Worst case: every float field at full precision. The radio cap no
    longer fits (trimming starts at about 28 radios); the file stays under the
    limit, the newest buckets stay, and at least six days of hourly history
    are kept."""
    full = store_size(_fleet("worst", WIFI_RF_MAX_RADIOS)._payload())
    assert full > WIFI_RF_MAX_STORE_BYTES
    store = _fleet("worst", WIFI_RF_MAX_RADIOS)
    newest = {ref: _newest(h) for ref, h in store.radios.items()}
    prepared = _write(store)
    assert prepared.size <= WIFI_RF_MAX_STORE_BYTES
    assert store.drops["trimmed"] > 0
    for ref in store.radios:
        entry = prepared.payload["radios"][ref_key(ref)]
        assert _written_newest(entry) == newest[ref]
    kept = min(len(h.hourly["utilization"]) for h in store.radios.values())
    assert kept >= 6 * 24
    assert all(
        len(h.daily[n]) == WIFI_RF_MAX_DAILY_BUCKETS
        for h in store.radios.values()
        for n in h.daily
    )


@pytest.mark.parametrize(("radios", "fits"), [(27, True), (29, False)])
def test_full_precision_everywhere_starts_trimming_at_about_28_radios(radios, fits):
    size = store_size(_fleet("worst", radios)._payload())
    assert (size <= WIFI_RF_MAX_STORE_BYTES) is fits


# --- 6. atomic writes -------------------------------------------------------------------


def test_the_store_writes_atomically_off_the_event_loop():
    kwargs: dict[str, Any] = {}

    def fake(*args: Any, **kw: Any) -> FakeStore:
        kwargs.update(kw)
        return FakeStore(FakeDisk(), *args, **kw)

    with patch.object(rf_store, "Store", fake):
        RfStore(make_hass(), tz=lambda: BERLIN)
    assert kwargs.get("atomic_writes") is True
    assert kwargs.get("serialize_in_event_loop") is False
    assert kwargs.get("private") is True


# --- 7. the kept payload ------------------------------------------------------------------


async def test_the_last_good_payload_is_released_after_a_good_write(disk):
    first = await _store()
    _fill(first, 5)
    await first.async_flush()
    second = await _store()
    assert second._last_payload is not None  # the file as loaded
    second.record(R1, ALL, T0 + 3600 * 5)
    await second.async_flush()
    assert second._last_payload is None
    assert ref_key(R1) in disk.saves[-1]["radios"]


async def test_untrimmable_after_a_good_write_writes_the_history_not_empty(disk):
    store = await _store()
    store.record(R1, {"utilization": 5.0}, T0)
    await store.async_flush()
    store.max_bytes = store_size(disk.saves[-1]) + 10
    for n in range(6):  # one hour each: nothing left to trim
        store.record(RadioRef("rtr_" + f"{n + 7:032x}", "radio0"), ALL, T0 + 3600)
    await store.async_flush()
    written = disk.saves[-1]
    assert len(written["radios"]) == 7
    assert store.drops["save_over_size"] == 1
