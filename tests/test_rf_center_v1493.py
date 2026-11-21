"""WiFi RF center, review findings R4 (retry rate) of 1.49.3. Mocks only."""

from __future__ import annotations

import json
from typing import Any

import pytest
from rf_center_kit import (
    MAC_A,
    MAC_B,
    FakeCoordinator,
    client,
    entry,
    load,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)

from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_incidents import RF_RETRY_KIND, candidates

ASSOC = load("iwinfo_assoclist_mt76.json")


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


def _later(per_mac: dict[str, tuple[int, int]]) -> dict[str, Any]:
    later = json.loads(json.dumps(ASSOC))
    for station in later["results"]:
        packets, retries = per_mac[station["mac"]]
        station["tx"]["packets"] += packets
        station["tx"]["retries"] += retries
    return later


async def _two_polls(per_mac: dict[str, tuple[int, int]]) -> Any:
    coordinator = FakeCoordinator()
    center, clock, reader = await new_center(
        rf_hass(), (entry("e1", options("assoclist")), coordinator)
    )
    clients = [client(MAC_A), client(MAC_B)]
    reader.answers[("assoclist", "phy1-ap0")] = ASSOC
    await poll(center, coordinator, poll_data(uptime=1000, clients=clients))
    reader.answers[("assoclist", "phy1-ap0")] = _later(per_mac)
    clock.advance(300)
    await poll(center, coordinator, poll_data(uptime=1300, clients=clients))
    return center


async def test_r4_clean_clients_count_once_the_driver_shows_it_counts(disk) -> None:
    """9000 clean packets + 1000 with 300 retries is 3 %, not 30 %."""
    center = await _two_polls({MAC_A: (1000, 300), MAC_B: (9000, 0)})
    (result,) = center.results.values()
    retry = result.metrics["retry_rate"]
    assert retry.is_measured
    assert retry.value == pytest.approx(300 / 10000)
    assert result.client_summary.retry_coverage == 1.0
    clean = next(a for a in result.assessments if a.client_mac == MAC_B)
    assert clean.retry_rate.is_measured and clean.retry_rate.value == 0.0
    kinds = [c.kind for c in candidates(center, result.ref.router_id)]
    assert RF_RETRY_KIND not in kinds


async def test_r4_all_zero_stays_unknown(disk) -> None:
    """No client with a retry: the driver may not count at all (mt76 + WED)."""
    center = await _two_polls({MAC_A: (1000, 0), MAC_B: (9000, 0)})
    (result,) = center.results.values()
    assert not result.metrics["retry_rate"].is_measured


async def test_r4_client_retry_rates_read_api_agrees(disk) -> None:
    center = await _two_polls({MAC_A: (1000, 300), MAC_B: (9000, 0)})
    (ref,) = center.results
    assert isinstance(ref, RadioRef)
    rates = center.client_retry_rates(ref.router_id, 3600)
    values = sorted(v["value"] for v in rates.values())
    assert values == [0.0, pytest.approx(0.3)]


def test_r4_retry_high_needs_enough_coverage() -> None:
    from types import SimpleNamespace

    from custom_components.openwrt_router.rf_incidents import (
        RETRY_MIN_COVERAGE,
        _retry,
    )
    from custom_components.openwrt_router.rf_models import metric_measured

    def result(coverage: float | None) -> Any:
        return SimpleNamespace(
            ref=RadioRef("rtr_x", "radio1"),
            radio=SimpleNamespace(devices=("phy1-ap0",), band="5g"),
            client_summary=SimpleNamespace(retry_coverage=coverage),
            metrics={"retry_rate": metric_measured(0.4, "iwinfo", measured_at=1.0)},
        )

    assert _retry(result(1.0)) is not None
    assert _retry(result(RETRY_MIN_COVERAGE)) is not None
    assert _retry(result(0.1)) is None  # one client of ten says nothing of the radio
    assert _retry(result(None)) is None


# --- R3: the allowed sample gap follows the real read interval -----------------------

STATUS_A = load("hostapd_get_status_mt76_a.json")
STATUS_B = load("hostapd_get_status_mt76_b.json")


@pytest.mark.parametrize("every", [10, 30, 60])
async def test_r3_utilization_is_measured_at_long_read_intervals(disk, every) -> None:
    coordinator = FakeCoordinator()
    center, clock, reader = await new_center(
        rf_hass(), (entry("e1", options("get_status", every=every)), coordinator)
    )
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    uptime = 1000
    await poll(center, coordinator, poll_data(uptime=uptime))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_B
    for _ in range(every):  # a poll takes a little longer than 60 s
        clock.advance(61)
        uptime += 61
        await poll(center, coordinator, poll_data(uptime=uptime))
    assert len(reader.calls) == 2
    (result,) = center.results.values()
    util = result.metrics["utilization"]
    assert util.is_measured, result.utilization.reason
