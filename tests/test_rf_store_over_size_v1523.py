"""1.52.3: the WiFi RF history is written while HA runs and never wiped by size.

Since 1.48.0 three defects together could reset the whole RF history at a
shutdown:

a. ``schedule_save`` re-armed HA's delayed write after every poll, so the
   write never fired while HA ran (only at shutdown or the last unload);
b. a payload over the byte limit was refused instead of trimmed, and the
   history grows over the limit by design (13 radios, 7 series, 8 days);
c. the refused write fell back to ``{"radios": {}}`` because a file loaded
   at start did not count as the last good payload.

The tests do not depend on the value of ``WIFI_RF_MAX_STORE_BYTES``: they set
their own limit, except the one that pins the documented capacity.
"""

from __future__ import annotations

import asyncio
import copy
import functools
import logging
from datetime import datetime
from typing import Any
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import rf_store
from custom_components.openwrt_router.const import (
    WIFI_RF_MAX_DAILY_BUCKETS,
    WIFI_RF_MAX_HOURLY_BUCKETS,
    WIFI_RF_MAX_RADIOS,
    WIFI_RF_MAX_STORE_BYTES,
    WIFI_RF_SAVE_DELAY_SECONDS,
    WIFI_RF_STORE_KEY,
)
from custom_components.openwrt_router.rf_aggregate import Agg
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_store import RfStore, ref_key, store_size

RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
R1 = RadioRef(RID1, "radio0")
R2 = RadioRef(RID2, "radio1")
BERLIN = ZoneInfo("Europe/Berlin")
T0 = datetime(2026, 11, 20, 12, 0, tzinfo=ZoneInfo("UTC")).timestamp()
ALL = dict.fromkeys(rf_store.SERIES, 1.25)
# The drop keys of 1.52.2 (rf_store._DROP_KEYS before 1.52.3).
DROP_KEYS_1522 = (
    "radio_quota",
    "hourly_quota",
    "daily_quota",
    "raw_quota",
    "save_over_size",
    "load_invalid",
    "load_failed",
)


@pytest.fixture
def disk() -> Any:
    disk = FakeDisk()
    disk.path = f"/nonexistent/.storage/{WIFI_RF_STORE_KEY}"
    with patch.object(rf_store, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        yield disk


async def _store(**kw: Any) -> RfStore:
    store = RfStore(make_hass(), tz=lambda: BERLIN, **kw)
    await store.async_load()
    return store


def _fill(
    store: RfStore, hours: int, start: float = T0, refs: tuple = (R1, R2)
) -> None:
    for h in range(hours):
        for ref in refs:
            store.record(ref, ALL, start + 3600 * h)


def _newest(history: Any) -> dict[tuple[str, str], int]:
    out = {}
    for part, series in (("h", history.hourly), ("d", history.daily)):
        for name, buckets in series.items():
            if buckets:
                out[(part, name)] = max(buckets)
    return out


def _written_newest(entry: dict[str, Any]) -> dict[tuple[str, str], int]:
    out = {}
    for part in ("h", "d"):
        for name, buckets in entry.get(part, {}).items():
            if buckets:
                out[(part, name)] = max(int(ts) for ts in buckets)
    return out


@functools.cache
def _steady_radio() -> Any:
    """One radio after 9 days of 60 s polls with all 7 series (8 days of
    hourly buckets are full, the daily part has 9 days)."""
    with patch.object(
        rf_store, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        store = RfStore(make_hass(), tz=lambda: BERLIN, max_bytes=10**12)
    for i in range(9 * 1440):
        store.record(
            R1,
            {
                "utilization": round(10 + (i * 7) % 50 + 0.1 * (i % 9), 1),
                "noise": -92 + i % 5,
                "clients": i % 17,
                "retry_rate": round((i % 31) / 997, 4),
                "health": 50 + i % 50,
                "roams": i % 4 == 0,
                "channel_changes": 0,
            },
            T0 + 60 * i,
        )
    return store.radios[R1]


def _steady_store(store: RfStore, radios: int) -> None:
    """``radios`` copies of the steady radio, filled up to the bucket caps
    (worst case: every hourly and daily bucket a series may keep)."""
    history = copy.deepcopy(_steady_radio())
    history.raw = {}
    for part, cap, step in (
        (history.hourly, WIFI_RF_MAX_HOURLY_BUCKETS, 3600),
        (history.daily, WIFI_RF_MAX_DAILY_BUCKETS, 86400),
    ):
        for buckets in part.values():
            ordered = sorted(buckets)
            sample = buckets[ordered[len(ordered) // 2]]
            for k in range(1, cap - len(ordered) + 1):
                buckets[ordered[0] - k * step] = sample
            assert len(buckets) == cap
    for n in range(radios):
        store.radios[RadioRef("rtr_" + f"{n:032x}", "radio0")] = copy.deepcopy(history)


# --- a: one delayed write at a time -----------------------------------------------


async def test_repeated_schedule_save_arms_one_delayed_write(disk):
    store = await _store()
    for minute in range(10):
        store.record(R1, ALL, T0 + 60 * minute)
        store.schedule_save()
    assert len(disk.delayed) == 1
    func, delay = disk.delayed[0]
    assert delay == WIFI_RF_SAVE_DELAY_SECONDS == 900  # documented: 15 minutes
    assert ref_key(R1) in func()["radios"]
    # the write ran: the next change arms the next one
    store.record(R1, ALL, T0 + 3600)
    store.schedule_save()
    assert len(disk.delayed) == 2


async def test_the_store_serialises_off_the_event_loop():
    kwargs: dict[str, Any] = {}

    def fake(*args: Any, **kw: Any) -> FakeStore:
        kwargs.update(kw)
        return FakeStore(FakeDisk(), *args, **kw)

    with patch.object(rf_store, "Store", fake):
        RfStore(make_hass(), tz=lambda: BERLIN)
    assert kwargs.get("serialize_in_event_loop") is False


async def test_real_store_writes_while_polls_keep_coming(tmp_path):
    """HA's real Store: the write fires during HA's run although a poll
    calls ``schedule_save`` far more often than the delay (1.52.2: never)."""
    from homeassistant.core import CoreState, HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    hass.set_state(CoreState.running)
    store = RfStore(hass, tz=lambda: BERLIN)
    store.loaded = True
    path = tmp_path / ".storage" / WIFI_RF_STORE_KEY
    try:
        with patch.object(rf_store, "WIFI_RF_SAVE_DELAY_SECONDS", 0.3):
            for i in range(60):  # 3 s = 10 delays, one call every 0.05 s
                store.record(R1, ALL, T0 + 60 * i)
                store.schedule_save()
                await asyncio.sleep(0.05)
            await hass.async_block_till_done()
        assert store.last_save_bytes is not None
        assert path.exists() and ref_key(R1) in path.read_text()
    finally:
        await hass.async_stop(force=True)


async def test_real_store_final_write_after_loading_keeps_the_history(tmp_path):
    """Shutdown path: a good file, one more run over the limit, HA's final
    write. The file keeps every radio (1.52.2: ``{"radios": {}}``)."""
    from homeassistant.const import EVENT_HOMEASSISTANT_FINAL_WRITE
    from homeassistant.core import CoreState, HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    hass.set_state(CoreState.running)
    try:
        first = RfStore(hass, tz=lambda: BERLIN)
        await first.async_load()
        _fill(first, 40)
        await first.async_flush()
        good = store_size(first._payload())
        second = RfStore(hass, tz=lambda: BERLIN, max_bytes=good + 200)
        await second.async_load()
        _fill(second, 10, start=T0 + 3600 * 40)
        with patch.object(rf_store, "WIFI_RF_SAVE_DELAY_SECONDS", 3600):
            second.schedule_save()  # pending for an hour: only the final write
        hass.bus.async_fire(EVENT_HOMEASSISTANT_FINAL_WRITE)
        await hass.async_block_till_done()
        for _ in range(50):
            if second.last_save_bytes is not None:
                break
            await asyncio.sleep(0.02)
        third = RfStore(hass, tz=lambda: BERLIN, max_bytes=good + 200)
        await third.async_load()
        assert set(third.radios) == {R1, R2}
        assert third.drops["load_invalid"] == 0
        assert third.drops["trimmed"] > 0
        assert second.last_save_bytes <= good + 200
    finally:
        await hass.async_stop(force=True)


# --- b: trim instead of refuse ------------------------------------------------------


async def test_over_the_limit_trims_the_oldest_and_keeps_the_newest(disk, caplog):
    store = await _store()
    _fill(store, 60)
    full = store_size(store._payload())
    limit = full // 2
    store.max_bytes = limit
    newest = {ref: _newest(h) for ref, h in store.radios.items()}
    caplog.set_level(logging.DEBUG, logger=rf_store.__name__)
    await store.async_flush()
    written = disk.saves[-1]
    assert store_size(written) <= limit
    assert store.last_save_bytes == store_size(written)
    for ref in (R1, R2):
        assert _written_newest(written["radios"][ref_key(ref)]) == newest[ref]
    assert store.drops["trimmed"] > 0
    assert written["drops"]["trimmed"] == store.drops["trimmed"]
    assert store.drops["save_over_size"] == 0
    # memory and file agree
    assert written == store._payload()
    # fair by time: both radios start at (about) the same hour
    first = [
        min(map(int, written["radios"][ref_key(r)]["h"]["noise"])) for r in (R1, R2)
    ]
    assert abs(first[0] - first[1]) <= 3600
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    # a second trim of the same run is logged at debug only
    _fill(store, 30, start=T0 + 3600 * 60)
    await store.async_flush()
    assert store_size(disk.saves[-1]) <= limit
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == warnings
    again = await _store(max_bytes=limit)
    assert set(again.radios) == {R1, R2}
    assert again.drops["load_invalid"] == 0


async def test_trimming_goes_by_time_not_radio_by_radio(disk):
    """An old radio loses its oldest hours first; a young one keeps all."""
    store = await _store()
    _fill(store, 60, refs=(R1,))
    _fill(store, 20, start=T0 + 3600 * 40, refs=(R2,))
    young = {n: sorted(b) for n, b in store.radios[R2].hourly.items()}
    store.max_bytes = int(store_size(store._payload()) * 0.8)
    await store.async_flush()
    assert store.drops["trimmed"] > 0
    assert {n: sorted(b) for n, b in store.radios[R2].hourly.items()} == young
    assert len(store.radios[R1].hourly["noise"]) < 60
    assert store_size(disk.saves[-1]) <= store.max_bytes


async def test_hourly_goes_before_daily(disk):
    store = await _store()
    _fill(store, 24 * 4)
    daily = {r: copy.deepcopy(h.daily) for r, h in store.radios.items()}
    store.max_bytes = int(store_size(store._payload()) * 0.7)
    await store.async_flush()
    assert store.drops["trimmed"] > 0
    assert {r: h.daily for r, h in store.radios.items()} == daily


# --- c: never write empty because of size ------------------------------------------


async def test_first_save_over_the_limit_never_writes_an_empty_history(disk):
    """The real-instance signature of 1.52.2, inverted."""
    store = await _store(max_bytes=20_000)
    _fill(store, 60)
    assert store_size(store._payload()) > 20_000
    await store.async_flush()  # = shutdown / last unload
    written = disk.saves[-1]
    assert set(written["radios"]) == {ref_key(R1), ref_key(R2)}
    assert store_size(written) <= 20_000
    again = await _store(max_bytes=20_000)
    assert set(again.radios) == {R1, R2}
    assert again.stats()["last_save_bytes"] is None  # nothing written this run


async def test_growth_after_loading_a_good_file_is_trimmed_not_wiped(disk):
    first = await _store()
    _fill(first, 40)
    await first.async_flush()
    good = copy.deepcopy(disk.data)
    good_size = store_size(good)
    second = await _store(max_bytes=good_size + 200)
    assert second.radios[R1].hourly["utilization"]
    _fill(second, 10, start=T0 + 3600 * 40)
    await second.async_flush()
    written = disk.saves[-1]
    assert set(written["radios"]) == {ref_key(R1), ref_key(R2)}
    assert store_size(written) <= good_size + 200


async def test_untrimmable_payload_keeps_the_loaded_file(disk):
    """Only the newest bucket of every series left and still over: the file
    as loaded stays (1.52.2 wrote ``{"radios": {}}``)."""
    first = await _store()
    first.record(R1, {"utilization": 5.0}, T0)
    await first.async_flush()
    good = copy.deepcopy(disk.data)
    second = await _store(max_bytes=store_size(good) + 10)
    for n in range(6):  # six new radios, one hour each: nothing to trim
        second.record(RadioRef("rtr_" + f"{n + 7:032x}", "radio0"), ALL, T0 + 3600)
    await second.async_flush()
    assert disk.saves[-1]["radios"] == good["radios"]
    assert second.drops["save_over_size"] == 1
    assert second.dirty is True


async def test_a_forgotten_router_does_not_come_back_with_the_last_good_file(disk):
    first = await _store()
    first.record(R1, {"utilization": 5.0}, T0)
    first.record(R2, {"utilization": 5.0}, T0)
    await first.async_flush()
    second = await _store(max_bytes=store_size(disk.data) + 10)
    assert second.forget_router(RID1) is True
    for n in range(6):  # untrimmable growth: the last good file is written
        second.record(RadioRef("rtr_" + f"{n + 7:032x}", "radio0"), ALL, T0 + 3600)
    await second.async_flush()
    assert second.drops["save_over_size"] == 1
    assert set(disk.saves[-1]["radios"]) == {ref_key(R2)}


async def test_untrimmable_payload_without_a_file_is_written_anyway(disk):
    """No last good payload: the history is written over the limit (a
    warning) rather than an empty one."""
    store = await _store(max_bytes=500)
    store.record(R1, ALL, T0)
    await store.async_flush()
    assert ref_key(R1) in disk.saves[-1]["radios"]
    assert store.drops["save_over_size"] == 1


# --- steady state --------------------------------------------------------------------


@pytest.mark.parametrize("radios", [13, 32])
async def test_steady_state_stays_under_a_low_limit_after_trimming(disk, radios):
    limit = 2_000_000  # below the steady state of 13 radios: trimming must act
    store = await _store(max_bytes=limit)
    _steady_store(store, radios)
    assert store_size(store._payload()) > limit
    newest = {ref: _newest(h) for ref, h in store.radios.items()}
    await store.async_flush()
    written = disk.saves[-1]
    assert store_size(written) <= limit
    assert len(written["radios"]) == radios
    for ref in store.radios:
        assert _written_newest(written["radios"][ref_key(ref)]) == newest[ref]
    # memory follows the file: the next save does not trim again
    trimmed = store.drops["trimmed"]
    await store.async_flush()
    assert store.drops["trimmed"] == trimmed


def test_the_limit_holds_eight_days_of_hourly_history_for_the_radio_cap():
    """The documented capacity (CHANGELOG 1.52.3, wifi-rf plan §8.3): the full
    hourly history of ``WIFI_RF_MAX_RADIOS`` radios fits below the trim
    target, so nothing is trimmed in normal operation."""
    with patch.object(
        rf_store, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        store = RfStore(make_hass(), tz=lambda: BERLIN)
    _steady_store(store, WIFI_RF_MAX_RADIOS)
    history = next(iter(store.radios.values()))
    assert len(history.hourly["utilization"]) == WIFI_RF_MAX_HOURLY_BUCKETS
    size = store_size(store._payload())
    assert size <= WIFI_RF_MAX_STORE_BYTES * (1 - rf_store.WIFI_RF_TRIM_HEADROOM)
    store._data_to_save()
    assert store.drops["trimmed"] == 0


# --- compatibility ---------------------------------------------------------------------


def _file_1522() -> dict[str, Any]:
    """A store file in the form 1.52.2 writes (no ``trimmed`` key)."""
    bucket = [60, 75.0, 1.25, 1.25, 0]
    return {
        "radios": {
            ref_key(R1): {
                "h": {"noise": {"1763640000": bucket, "1763643600": bucket}},
                "d": {"noise": {"1763596800": [120, 150.0, 1.25, 1.25, 0]}},
            },
            ref_key(R2): {"h": {"clients": {"1763640000": bucket}}, "d": {}},
        },
        "drops": {**dict.fromkeys(DROP_KEYS_1522, 0), "radio_quota": 2},
    }


async def test_a_file_of_1_52_2_loads_unchanged(disk):
    disk.data = _file_1522()
    store = await _store()
    assert store.drops["load_invalid"] == 0
    assert store.drops["radio_quota"] == 2 and store.drops["trimmed"] == 0
    payload = store._payload()
    assert payload["radios"] == disk.data["radios"]
    assert {k: payload["drops"][k] for k in DROP_KEYS_1522} == disk.data["drops"]


async def test_a_file_of_1_52_3_loads_in_the_code_of_1_52_2(disk):
    """1.52.2's ``_apply`` reads only its own drop keys: ``trimmed`` (and any
    other unknown key) is ignored, the radios load as they are."""
    store = await _store(max_bytes=20_000)
    _fill(store, 60)
    await store.async_flush()
    assert disk.data["drops"]["trimmed"] > 0
    with patch.object(rf_store, "_DROP_KEYS", DROP_KEYS_1522):
        old = await _store()
    assert "trimmed" not in old.drops
    assert old.drops["load_invalid"] == 0
    assert set(old.radios) == {R1, R2}
    assert old._payload()["radios"] == disk.data["radios"]


# --- readers of the history ------------------------------------------------------------


async def test_trimmed_hours_read_as_gaps_not_values(disk):
    store = await _store()
    _fill(store, 60, refs=(R1,))
    store.max_bytes = store_size(store._payload()) // 2
    await store.async_flush()
    kept = min(store.radios[R1].hourly["utilization"])
    assert kept > T0
    now = T0 + 3600 * 59
    week = store.series(R1, "utilization", "7d", now)
    assert week["source"] == "hourly"
    before = [p for p in week["points"] if p["ts"] < kept]
    after = [p for p in week["points"] if kept <= p["ts"] <= now]
    assert before and all(p["mean"] is None and p["count"] == 0 for p in before)
    assert after and all(p["mean"] == pytest.approx(1.25) for p in after)


async def test_window_at_reads_a_trimmed_hour_as_unknown():
    """Time Machine (``tm_state`` -> ``RfCenter.window_at``): an hour that was
    trimmed is "unknown", never a value; a kept hour is still measured."""
    from rf_center_kit import RID1 as CENTER_RID
    from rf_center_kit import measured_center, rf_disk

    with rf_disk():
        center, _reader = await measured_center()
        store = center.store
        [ref] = [r for r in store.radios if r.router_id == CENTER_RID]
        utilization = store.radios[ref].hourly["utilization"]
        newest = max(utilization)
        without_old = store_size(store._payload())
        old = [newest - 3600 * k for k in range(30, 40)]
        for hour in old:
            utilization[hour] = Agg(60, 60 * 55.0, 50.0, 60.0, 0)
        before = center.window_at(CENTER_RID, old[-1], old[0] + 3600)
        assert before[ref.radio_id]["state"] == "measured"
        store.max_bytes = without_old  # the trim target lies below: all old go
        await store.async_flush()
        assert store.drops["trimmed"] > 0
        assert not set(old) & set(utilization)
        gone = center.window_at(CENTER_RID, old[-1], old[0] + 3600)
        assert gone[ref.radio_id]["state"] == "unknown"
        assert gone[ref.radio_id]["mean"] is None
        assert gone[ref.radio_id]["buckets"] == 0
        kept = center.window_at(CENTER_RID, newest, newest + 3600)
        assert kept[ref.radio_id]["state"] == "measured"


# --- diagnostics ---------------------------------------------------------------------


async def test_diagnostics_show_limit_last_size_and_trim_counter():
    from rf_center_kit import measured_center, rf_disk

    with rf_disk():
        center, _reader = await measured_center()
        await center.store.async_flush()
        block = center.diagnostics()["store"]
    assert block["max_bytes"] == WIFI_RF_MAX_STORE_BYTES
    assert isinstance(block["last_save_bytes"], int) and block["last_save_bytes"] > 0
    assert block["drops"]["trimmed"] == 0
