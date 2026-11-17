"""B8: scale and cost of the client stability engine.

The table and AP views of 150 clients with 30 days of history stay cheap
enough for the event loop (no bucket is unpacked just to count data days or
to find the open hours), a poll of 1000 clients stays under the 20 ms ingest
budget, 150 clients x 30 days fit in the 3 MB default store and 1000 clients
are trimmed under the cap. The large histories are clones of a few clients
fed through the engine's public poll observer (hourly polls), rebuilt with
``ClientHistory.from_dict``. Timings are the best of several runs. MACs are
locally administered test values.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest
from test_client_engine import client
from test_client_routes import poll
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import client_engine, client_history
from custom_components.openwrt_router.client_analysis import data_days
from custom_components.openwrt_router.client_engine import (
    ClientStability,
    _store_size,
)
from custom_components.openwrt_router.client_history import (
    Bucket,
    ClientHistory,
    sum_buckets,
)
from custom_components.openwrt_router.client_views import (
    ap_view,
    clients_table,
    parse_table_query,
)

T0 = 1_800_000_000.0
HOUR = 3600.0
DAYS = 30
TEMPLATES = 3
_CACHE: dict[str, Any] = {}


def mac(i: int) -> str:
    return f"02:00:5E:{i >> 16 & 255:02X}:{i >> 8 & 255:02X}:{i & 255:02X}"


def engine() -> ClientStability:
    hass = make_hass()
    with patch.object(
        client_engine, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        cs = ClientStability(hass)
    cs.loaded = True
    return cs


def feed(cs: ClientStability, start: float, polls: int, step: float, *clients: Any):
    with patch.object(client_engine, "async_dispatcher_send", lambda *a: None):
        for k in range(polls):
            cs.on_poll(replace(poll("r1", start + k * step, *clients), interval=step))


def template() -> tuple[dict[str, Any], float]:
    """History of three clients over 30 days of hourly polls (built once)."""
    if "history" not in _CACHE:
        cs = engine()
        polls = DAYS * 24
        clients = [
            client(mac(i), signal=-50 - 10 * i, rx_rate=433300, hostname=f"h{i}")
            for i in range(TEMPLATES)
        ]
        feed(cs, T0, polls, HOUR, *clients)
        _CACHE["history"] = cs.history.to_dict()
        _CACHE["now"] = T0 + (polls - 1) * HOUR
    return _CACHE["history"], _CACHE["now"]


def cloned(n: int) -> tuple[ClientStability, float]:
    """An engine whose history holds ``n`` clones of the template clients."""
    data, now = template()
    rows = list(data["clients"].values())
    clients = {mac(1000 + i): rows[i % len(rows)] for i in range(n)}
    cs = engine()
    cs.settings = {**cs.settings, "max_store_mb": 8}
    cs.history = ClientHistory.from_dict({**data, "clients": clients}, DAYS)
    cs.last_now = now
    assert len(cs.history) == n
    return cs, now


def best_ms(call: Callable[[], Any], runs: int = 3) -> float:
    best = float("inf")
    for _ in range(runs):
        start = time.perf_counter()
        call()
        best = min(best, time.perf_counter() - start)
    return best * 1000


def unpacked_days(history: ClientHistory, m: str) -> int:
    """Reference count of days with observed time (unpacks every bucket)."""
    days = {d.day for d in history.days(m) if d.bucket.observed_s > 0}
    days |= {h.hour // 24 for h in history.hours(m) if h.bucket.observed_s > 0}
    return len(days)


class Unpacks:
    """Counts ``unpack_bucket`` calls of the history."""

    def __init__(self) -> None:
        self.calls = 0
        self._real = client_history.unpack_bucket

    def __call__(self, packed: Any) -> Any:
        self.calls += 1
        return self._real(packed)


@pytest.fixture
def unpacks() -> Any:
    counter = Unpacks()
    with patch.object(client_history, "unpack_bucket", counter):
        yield counter


# --- no unpacking just to count or to filter -------------------------------------


def test_observed_days_match_the_unpacked_count() -> None:
    cs, _now = cloned(TEMPLATES)
    for m in cs.history.macs():
        assert cs.history.observed_days(m) == unpacked_days(cs.history, m) == DAYS
    assert cs.history.observed_days(mac(99999)) == 0


def test_observed_days_count_open_hours_and_skip_empty_buckets() -> None:
    cs = engine()
    feed(cs, T0, 3, 60.0, client(mac(1)))  # open hours only
    assert cs.history.observed_days(mac(1)) == unpacked_days(cs.history, mac(1)) == 1
    feed(cs, T0 + 2 * 86400, 2, 60.0)  # the client is gone; nothing observed
    assert cs.history.observed_days(mac(1)) == unpacked_days(cs.history, mac(1))


def test_data_days_unpacks_no_bucket(unpacks: Unpacks) -> None:
    cs, _now = cloned(TEMPLATES)
    unpacks.calls = 0
    assert data_days(cs.history, mac(1000)) == DAYS
    assert unpacks.calls == 0


def test_open_only_hours_skip_the_closed_buckets(unpacks: Unpacks) -> None:
    cs, _now = cloned(1)
    m = mac(1000)
    expected = [h for h in cs.history.hours(m) if not h.closed]
    unpacks.calls = 0
    assert cs.history.hours(m, open_only=True) == expected
    assert unpacks.calls == 0
    assert all(not h.closed for h in expected)


def by_ap(pairs: Any) -> dict[str, Bucket]:
    grouped: dict[str, list[Bucket]] = {}
    for ap, bucket in pairs:
        grouped.setdefault(ap, []).append(bucket)
    return {ap: sum_buckets(items) for ap, items in grouped.items()}


def test_span_sums_like_the_hour_buckets() -> None:
    cs, now = cloned(TEMPLATES)
    feed(cs, now + HOUR, 3, 600.0, client(mac(1000), signal=-70))  # open hours
    last = int(now // HOUR) + 1
    windows = [(last - n + 1, last) for n in (1, 5, 24, 25, 48, 100, 167, 168)]
    windows += [(last - 72, last - 24), (last - 47, last - 24)]  # whole days only
    for m in cs.history.macs():
        for first, end in windows:
            hours = [(h.ap, h.bucket) for h in cs.history.hours(m, first, end)]
            span = cs.history.span(m, first, end)
            assert by_ap(span) == by_ap(hours), (m, first, end)


def test_span_reads_whole_days_from_the_day_buckets(unpacks: Unpacks) -> None:
    cs, now = cloned(1)
    last = int(now // HOUR)
    unpacks.calls = 0
    cs.history.span(mac(1000), last - 167, last)
    # at most 6 whole days plus 47 edge hours instead of 168 hour buckets
    assert unpacks.calls <= 6 + 47


def test_span_keeps_whole_days_after_the_hours_are_trimmed() -> None:
    cs, now = cloned(1)
    m, last = mac(1000), int(now // HOUR)
    first = (last // 24 - 3) * 24
    before = sum_buckets(b for _ap, b in cs.history.span(m, first, first + 23))
    assert before.observed_s == 86400
    cs.history.trim_closed_hours(last)
    after = sum_buckets(b for _ap, b in cs.history.span(m, first, first + 23))
    assert after == before


# --- view and ingest budgets ---------------------------------------------------------


def test_table_of_150_clients_with_30_days_stays_cheap() -> None:
    cs, now = cloned(150)
    query = parse_table_query({})
    first = best_ms(lambda: clients_table(cs, str, now, query), runs=1)
    again = best_ms(lambda: clients_table(cs, str, now, query))
    # dev machine: ~260 ms (patterns computed, cached per hour) / ~110 ms;
    # before B8 1100 / 730 ms. The budgets leave room for slower CI runners.
    assert first < 1000, first
    assert again < 400, again


def test_ap_view_of_150_clients_over_30_days_stays_cheap() -> None:
    cs, now = cloned(150)
    # dev machine ~115 ms, before B8 ~740 ms
    assert best_ms(lambda: ap_view(cs, str, now, "30d")) < 400


def test_poll_of_1000_clients_stays_under_the_ingest_budget() -> None:
    cs = engine()
    clients = [client(mac(i), signal=-55) for i in range(1000)]
    feed(cs, T0, 3, 60.0, *clients)
    best = float("inf")
    with patch.object(client_engine, "async_dispatcher_send", lambda *a: None):
        for k in range(3, 13):
            facts = poll("r1", T0 + k * 60.0, *clients)
            start = time.perf_counter()
            cs.on_poll(facts)
            best = min(best, time.perf_counter() - start)
    assert best * 1000 < 20.0, best * 1000


# --- store size ----------------------------------------------------------------------


def test_150_clients_over_30_days_fit_the_default_store() -> None:
    cs, _now = cloned(150)
    cs.settings = {**cs.settings, "max_store_mb": 3}
    payload = cs._data_to_save()
    assert cs.trimmed == 0
    assert _store_size(payload) == cs.last_save_bytes < 3_000_000


def test_1000_clients_over_30_days_are_trimmed_under_the_cap() -> None:
    cs, _now = cloned(1000)
    assert _store_size(cs._payload()) > 8_000_000
    payload = cs._data_to_save()
    assert cs.trimmed > 0
    assert _store_size(payload) == cs.last_save_bytes <= 8_000_000
