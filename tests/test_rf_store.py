"""History store of WiFi RF Intelligence (rf_store, 1.48.0, sub-step D).

Mocks only: HA's Store is the in-memory FakeStore of test_net_engine.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from unittest.mock import patch
from zoneinfo import ZoneInfo

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import rf_store
from custom_components.openwrt_router.const import (
    WIFI_RF_SAVE_DELAY_SECONDS,
    WIFI_RF_STORE_KEY,
)
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_store import (
    RfStore,
    local_day_key,
    local_day_start,
    parse_ref_key,
    ref_key,
)

RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
R1 = RadioRef(RID1, "radio0")
R2 = RadioRef(RID2, "radio1")
BERLIN = ZoneInfo("Europe/Berlin")
# 2026-11-20 12:00 UTC
T0 = datetime(2026, 11, 20, 12, 0, tzinfo=ZoneInfo("UTC")).timestamp()


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


def test_keys_round_trip_and_refuse_junk():
    assert parse_ref_key(ref_key(R1)) == R1
    for junk in ("x", f"{RID1}/a/b", "rtr_1/radio0", f"{RID1}/", None, 5):
        assert parse_ref_key(junk) is None


def test_local_days_follow_the_time_zone():
    # 23:30 UTC on Nov 20 is already Nov 21 in Berlin.
    late = datetime(2026, 11, 20, 23, 30, tzinfo=ZoneInfo("UTC")).timestamp()
    assert local_day_key(late, BERLIN) != local_day_key(T0, BERLIN)
    key = local_day_key(late, BERLIN)
    start = local_day_start(key, BERLIN)
    assert datetime.fromtimestamp(start, BERLIN).hour == 0
    assert datetime.fromtimestamp(start, BERLIN).day == 21
    assert key % 86400 == 0


async def test_record_and_read_the_windows(disk):
    store = await _store()
    for minute in range(90):
        store.record(
            R1, {"utilization": 20.0 + minute % 10, "noise": None}, T0 + 60 * minute
        )
    now = T0 + 89 * 60
    one = store.series(R1, "utilization", "1h", now)
    assert one["source"] == "raw" and one["resolution_s"] == 60
    assert all(p["mean"] is not None for p in one["points"][-30:])
    day = store.series(R1, "utilization", "24h", now)
    assert day["source"] == "hourly"
    assert [p["mean"] is not None for p in day["points"]].count(True) == 2
    month = store.series(R1, "utilization", "30d", now)
    assert month["source"] == "daily"
    last = month["points"][-1]
    assert last["count"] == 90
    assert datetime.fromtimestamp(last["ts"], BERLIN).hour == 0  # local midnight
    # Unknown values are gaps, never 0.
    noise = store.series(R1, "noise", "24h", now)
    assert all(p["mean"] is None for p in noise["points"])
    assert sum(p["invalid"] for p in noise["points"]) == 90


async def test_counter_series_report_totals(disk):
    store = await _store()
    for minute, value in enumerate([0, 1, 0, 2]):
        store.record(R1, {"roams": value}, T0 + 60 * minute)
    series = store.series(R1, "roams", "24h", T0 + 300)
    assert sum(p["total"] or 0 for p in series["points"]) == 3


async def test_quotas_are_separate_and_every_drop_is_counted(disk):
    store = await _store(max_radios=1, max_hourly=2)
    store.record(R1, {"utilization": 1.0, "clients": 3}, T0)
    store.record(R2, {"utilization": 1.0}, T0)  # second radio: over quota
    assert R2 not in store.radios and store.drops["radio_quota"] == 1
    for hour in range(1, 4):
        store.record(R1, {"utilization": 1.0}, T0 + 3600 * hour)
    # utilization ran out of hourly buckets; clients kept its own quota.
    assert store.drops["hourly_quota"] == 2
    assert len(store.radios[R1].hourly["utilization"]) == 2
    assert len(store.radios[R1].hourly["clients"]) == 1
    assert store.stats()["drops"]["hourly_quota"] == 2


async def test_save_is_delayed_and_flush_writes_now(disk):
    store = await _store()
    store.record(R1, {"utilization": 5.0}, T0)
    store.schedule_save()
    func, delay = disk.delayed[-1]
    assert delay == WIFI_RF_SAVE_DELAY_SECONDS
    payload = func()
    assert list(payload["radios"]) == [ref_key(R1)]
    await store.async_flush()
    assert disk.saves and ref_key(R1) in disk.saves[-1]["radios"]
    again = await _store()
    assert again.radios[R1].hourly["utilization"]


async def test_payload_over_the_byte_limit_keeps_the_last_good_one(disk):
    store = await _store(max_bytes=1500)
    store.record(R1, {"utilization": 5.0}, T0)
    good = store._data_to_save()
    assert good["radios"]
    for minute in range(1, 200):
        store.record(R1, {n: 1.0 for n in rf_store.SERIES}, T0 + 3600 * minute)
    assert store._data_to_save() == good
    assert store.drops["save_over_size"] == 1


async def test_nothing_but_numbers_is_stored(disk):
    store = await _store()
    store.record(R1, {"utilization": 5.0, "health": 70}, T0)
    text = json.dumps(store._data_to_save())
    for needle in ("ssid", "bssid", "mac", "cli_", "hostname"):
        assert needle not in text.lower()


async def test_forget_router_drops_only_that_router(disk):
    store = await _store()
    store.record(R1, {"utilization": 5.0}, T0)
    store.record(R2, {"utilization": 5.0}, T0)
    assert store.forget_router(RID1) is True
    assert set(store.radios) == {R2}
    assert store.forget_router(RID1) is False


async def test_invalid_entries_on_load_are_counted(disk):
    disk.data = {
        "radios": {
            "junk": {},
            ref_key(R1): {"h": {"utilization": {"7200": [1, 5.0, 5.0, 5.0, 0]}}},
            ref_key(R2): {"h": {"utilization": {"x": [1]}}},
        },
        "drops": {"radio_quota": 4, "bogus": 9},
    }
    store = await _store()
    assert set(store.radios) == {R1}
    assert store.drops["load_invalid"] == 2
    assert store.drops["radio_quota"] == 4


async def test_a_damaged_file_is_kept_and_counted(disk):
    disk.load_error = ValueError("broken json")
    with patch("custom_components.openwrt_router.net_engine._backup_file") as backup:
        store = await _store()
    backup.assert_called_once_with(disk.path)
    assert store.loaded and store.radios == {}
    assert store.drops["load_failed"] == 1
