"""WiFi RF read API for other modules (wish W6 of Traffic Analytics, 1.49.1).

``RfCenter.radio_utilization`` / ``RfCenter.client_retry_rates`` against the
real center with fake coordinators and the synthetic RF fixtures (see
``rf_center_kit``). No router, no Home Assistant, no network.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from rf_center_kit import (
    KEY,
    MAC_A,
    MAC_B,
    RID1,
    RID2,
    FakeCoordinator,
    entry,
    measured_center,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)

from custom_components.openwrt_router.rf_center import (
    READ_API_VERSION,
    READ_REASON_NOT_MEASURED,
    READ_REASON_STALE,
    STATUS_OFF,
    STATUS_READY,
)
from custom_components.openwrt_router.rf_privacy import client_ref

HOUR = 3600


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


async def test_radio_utilization_gives_the_measured_radio(disk) -> None:
    center, reader = await measured_center()
    assert center.status == STATUS_READY
    radios = center.radio_utilization(RID1, HOUR, ["phy1-ap0", "phy9-ap3"])
    assert set(radios) == {"radio1"}  # the UCI radio name, never the netdev
    entry_ = radios["radio1"]
    assert entry_["v"] == READ_API_VERSION
    assert entry_["state"] == "measured" and entry_["reason"] is None
    assert entry_["mean"] == pytest.approx(80.0)
    assert entry_["valid_count"] >= 6
    assert isinstance(entry_["measured_at"], float)
    # only the names the caller passed and that belong to the radio come back
    assert entry_["interfaces"] == ["phy1-ap0"]
    assert center.radio_utilization(RID1, HOUR)["radio1"]["interfaces"] == []
    assert center.radio_utilization(RID2, HOUR) == {}
    assert reader.calls == []  # read only: no router call


async def test_client_retry_rates_use_client_refs_only(disk) -> None:
    center, reader = await measured_center()
    rates = center.client_retry_rates(RID1, HOUR)
    assert set(rates) == {client_ref(MAC_A, KEY), client_ref(MAC_B, KEY)}
    for rate in rates.values():
        assert rate["radio_id"] == "radio1"
        assert rate["state"] == "measured" and rate["reason"] is None
        assert rate["value"] == pytest.approx(0.3)
        assert isinstance(rate["measured_at"], float)
    text = json.dumps(rates).lower()
    assert MAC_A not in text and MAC_B not in text and "phy1-ap0" not in text
    assert reader.calls == []


async def test_unknown_is_none_with_a_reason_never_zero(disk) -> None:
    coordinator = FakeCoordinator()
    center, _clock, _reader = await new_center(
        rf_hass(), (entry("e1", options()), coordinator)
    )
    await poll(center, coordinator, poll_data(uptime=1000))
    radio = center.radio_utilization(RID1, HOUR)["radio1"]
    assert radio["state"] == "unknown"
    assert radio["reason"] == READ_REASON_NOT_MEASURED
    assert radio["mean"] is None and radio["valid_count"] is None
    rate = center.client_retry_rates(RID1, HOUR)[client_ref(MAC_A, KEY)]
    assert rate["value"] is None and rate["reason"] == rate["state"] != "measured"


async def test_an_evaluation_older_than_the_window_is_stale(disk) -> None:
    center, _reader = await measured_center()
    center.clock.advance(2 * HOUR)
    radio = center.radio_utilization(RID1, HOUR)["radio1"]
    assert radio["state"] == "unknown" and radio["reason"] == READ_REASON_STALE
    assert radio["mean"] is None
    for rate in center.client_retry_rates(RID1, HOUR).values():
        assert rate["value"] is None and rate["reason"] == READ_REASON_STALE


async def test_off_or_not_ready_reads_nothing(disk) -> None:
    coordinator = FakeCoordinator()
    center, _clock, reader = await new_center(rf_hass(), (entry("e1", {}), coordinator))
    await poll(center, coordinator, poll_data(uptime=1000))
    assert center.status == STATUS_OFF
    assert center.radio_utilization(RID1, HOUR) == {}
    assert center.client_retry_rates(RID1, HOUR) == {}
    keyless, _c, _r = await new_center(
        rf_hass(), (entry("e1", options()), FakeCoordinator()), key=None
    )
    assert keyless.radio_utilization(RID1, HOUR) == {}
    assert keyless.client_retry_rates(RID1, HOUR) == {}
    assert reader.calls == []


async def test_bad_arguments_read_nothing(disk) -> None:
    center, _reader = await measured_center(polls=2)
    for window in (0, -1, True, "1h", None):
        assert center.radio_utilization(RID1, window) == {}
        assert center.client_retry_rates(RID1, window) == {}
    assert center.radio_utilization(None, HOUR) == {}  # type: ignore[arg-type]
    # a bare string is not a list of names; too long names are ignored
    radio = center.radio_utilization(RID1, HOUR, "phy1-ap0")["radio1"]
    assert radio["interfaces"] == []
    radio = center.radio_utilization(RID1, HOUR, ["x" * 65, 3, "phy1-ap0"])
    assert radio["radio1"]["interfaces"] == ["phy1-ap0"]
