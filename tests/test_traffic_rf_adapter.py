"""Traffic <-> WiFi RF / Network Diagnostics adapters against the merged modules.

Since 1.49.1 the WiFi RF center has the read API Traffic asked for (wish
W6): ``radio_utilization`` and ``client_retry_rates``. The adapter reads
only through it (no ``results`` internals, no MAC, no AP interface name
leaves it). The contract tests run the real ``RfCenter`` with the synthetic
RF fixtures (``rf_center_kit``), so a change of the read API fails here.
"""

from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace
from typing import Any

import pytest
from core_testkit import make_hass
from rf_center_kit import MAC_A, MAC_B, RID1, measured_center, rf_disk

from custom_components.openwrt_router import const
from custom_components.openwrt_router.diag_runtime import NetDiagnostics
from custom_components.openwrt_router.diag_stats import LatencySummary
from custom_components.openwrt_router.rf_center import RfCenter
from custom_components.openwrt_router.traffic_const import (
    DIAG_DATA_KEY,
    REASON_INTERFACE_MISMATCH,
    REASON_MODULE_DISABLED,
    REASON_READ_FAILED,
    REASON_TOO_FEW_SAMPLES,
    SOURCE_NO_DATA,
    SOURCE_NOT_READY,
    SOURCE_READY,
    WIFI_RF_DATA_KEY,
)
from custom_components.openwrt_router.traffic_correlate import (
    MAX_RF_POINT_IDS,
    TrafficCorrelator,
    WifiRfAdapter,
)
from custom_components.openwrt_router.traffic_model import MeasurementPoint, Scope

RID = "rtr_" + "a" * 32
NOW = 1_800_000_000.0
PID = "tpt_" + "1" * 16
PID2 = "tpt_" + "2" * 16


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


def radio(mean: float | None, valid: int = 12, overload: bool | None = False, **kw):
    """One ``RfCenter.radio_utilization`` entry."""
    return {
        "v": 1,
        "state": "measured" if mean is not None else "unknown",
        "reason": None if mean is not None else "utilization_not_measured",
        "measured_at": NOW,
        "mean": mean,
        "valid_count": valid if mean is not None else None,
        "sustained_overload": overload,
        "interfaces": [],
        **kw,
    }


def rate(value: float | None, radio_id: str = "radio0") -> dict[str, Any]:
    """One ``RfCenter.client_retry_rates`` entry."""
    return {
        "v": 1,
        "radio_id": radio_id,
        "value": value,
        "state": "measured" if value is not None else "no_data",
        "reason": None if value is not None else "no_data",
        "measured_at": NOW,
    }


class FakeCenter:
    """The W6 read API with fixed answers (status like ``RfCenter``)."""

    def __init__(self, radios=None, rates=None, status="ready", reasons=()):
        self.radios = radios or {}
        self.rates = rates or {}
        self.status = status
        self.reasons = list(reasons)
        self.asked: list[Any] = []

    def not_ready_reasons(self) -> list[str]:
        return self.reasons

    def radio_utilization(self, router_id, window_s, interfaces=()):
        self.asked.append(list(interfaces))
        return self.radios if router_id == RID else {}

    def client_retry_rates(self, router_id, window_s):
        return self.rates if router_id == RID else {}


def test_data_keys_are_the_modules_keys() -> None:
    assert WIFI_RF_DATA_KEY == const.DATA_WIFI_RF_CENTER
    assert DIAG_DATA_KEY == const.DATA_NET_DIAGNOSTICS


def test_the_rf_read_api_exists_on_the_real_center() -> None:
    """Contract (W6): the methods and the state the adapter reads."""
    for name in ("radio_utilization", "client_retry_rates", "not_ready_reasons"):
        assert callable(getattr(RfCenter, name))
    assert isinstance(RfCenter.status, property)


def test_diagnostics_shapes_the_adapter_reads_exist() -> None:
    """W7: ``history_view`` and the LatencySummary fields used."""
    assert callable(getattr(NetDiagnostics, "history_view", None))
    names = {f.name for f in dataclasses.fields(LatencySummary)}
    assert {"answered", "lost", "coverage", "mean_ms", "loss_pct"} <= names


def test_real_center_switched_off_is_module_disabled() -> None:
    real = RfCenter(make_hass())
    status, rf = WifiRfAdapter(lambda: real).module()
    assert (status.state, status.reason) == (SOURCE_NOT_READY, REASON_MODULE_DISABLED)
    assert rf is None
    status, facts = WifiRfAdapter(lambda: real).facts(RID)
    assert facts is None and status.reason == REASON_MODULE_DISABLED


async def test_real_center_gives_values_per_radio_linked_to_points(disk) -> None:
    """Contract (W6): a measured radio of the real center reaches traffic."""
    center, reader = await measured_center()
    adapter = WifiRfAdapter(lambda: center)
    status, facts = adapter.facts(RID1, interfaces={"phy1-ap0": [PID2, PID]})
    assert status.state == SOURCE_READY and facts is not None
    (one,) = facts.per_radio
    assert one.radio_id == "radio1" and one.state == "measured"
    assert one.airtime_mean_pct == pytest.approx(80.0) and one.airtime_high is True
    assert one.measured_at is not None
    assert one.clients_measured == 2 and one.clients_high_retry == 2
    assert one.point_ids == (PID, PID2) and one.points_linked == 2
    assert facts.busiest_radio == "radio1" and facts.retries_high is True
    text = json.dumps(one.to_dict()).lower()
    for secret in (MAC_A, MAC_B, "phy1-ap0"):
        assert secret not in text
    assert reader.calls == []  # no extra router call


async def test_real_center_correlation_names_the_radio_and_its_points(disk) -> None:
    center, _reader = await measured_center()
    wan = MeasurementPoint(RID1, Scope.WAN, device="wan")
    station = MeasurementPoint(
        RID1, Scope.STATION, radio_id="phy1-ap0", client_ref="cli_" + "e" * 16
    )
    source = SimpleNamespace(points=lambda: [wan, station], window=lambda *a, **k: None)
    report = TrafficCorrelator().evaluate(
        source, now=center.clock(), wifi_rf=WifiRfAdapter(lambda: center)
    )
    (finding,) = report.findings
    airtime = next(o for o in finding.observations if o.indicator == "airtime_high")
    (per_radio,) = airtime.detail["per_radio"]
    assert per_radio["radio_id"] == "radio1"
    assert per_radio["point_ids"] == [station.point_id]
    assert "phy1-ap0" not in json.dumps(report.to_dict())


def test_not_ready_carries_the_centers_reason() -> None:
    rf = FakeCenter(status="not_ready", reasons=["no_core"])
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, "no_core")
    assert facts is None


def test_a_center_without_the_read_api_is_interface_mismatch() -> None:
    for module in (
        object(),
        SimpleNamespace(status="ready", results={}),  # the pre-W6 internals
        SimpleNamespace(
            status=3, radio_utilization=lambda *a: {}, client_retry_rates=None
        ),
    ):
        status, _ = WifiRfAdapter(lambda m=module: m).facts(RID)
        assert (status.state, status.reason) == (
            SOURCE_NOT_READY,
            REASON_INTERFACE_MISMATCH,
        )


def test_values_per_radio_and_router_summary() -> None:
    rf = FakeCenter(
        {
            "radio0": radio(85.0, interfaces=["phy0-ap0"]),
            "radio1": radio(20.0),
        },
        {
            "cli_" + "a" * 16: rate(0.4),
            "cli_" + "b" * 16: rate(0.1),
            "cli_" + "c" * 16: rate(None),
            "cli_" + "d" * 16: rate(0.05, "radio1"),
            "02:00:5e:00:53:01": rate(0.9),  # not a pseudonym: ignored
        },
    )
    status, facts = WifiRfAdapter(lambda: rf).facts(
        RID, interfaces={"phy0-ap0": [PID], "phy1-ap0": [PID2]}
    )
    assert rf.asked == [["phy0-ap0", "phy1-ap0"]]
    assert status.state == SOURCE_READY and facts is not None
    assert facts.radios == 2
    assert facts.busiest_radio == "radio0" and facts.airtime_mean_pct == 85.0
    assert facts.airtime_high is True
    assert facts.clients_measured == 3 and facts.clients_high_retry == 1
    assert facts.retries_high is True  # 1 of 3 >= 25 %
    r0, r1 = facts.per_radio
    assert (r0.radio_id, r0.point_ids, r0.clients_measured) == ("radio0", (PID,), 2)
    assert (r1.radio_id, r1.point_ids, r1.airtime_high) == ("radio1", (), False)


def test_unknown_or_thin_radios_are_none_with_reason_and_no_data() -> None:
    rf = FakeCenter({"radio0": radio(95.0, valid=2), "radio2": radio(None)})
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES)
    assert facts is None
    adapter = WifiRfAdapter(lambda: rf)
    thin = adapter._radio("radio0", rf.radios["radio0"], (), {})
    assert thin.airtime_mean_pct is None and thin.reason == REASON_TOO_FEW_SAMPLES
    unknown = adapter._radio("radio2", rf.radios["radio2"], (), {})
    assert unknown.airtime_mean_pct is None
    assert unknown.reason == "utilization_not_measured"


def test_sustained_overload_counts_without_a_mean() -> None:
    rf = FakeCenter({"radio0": radio(None, overload=True)})
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert status.state == SOURCE_READY and facts is not None
    assert facts.airtime_high is True and facts.busiest_radio is None


def test_broken_answers_are_read_failed() -> None:
    def boom(*_: Any) -> Any:
        raise RuntimeError("x")

    rf = FakeCenter()
    rf.radio_utilization = boom  # type: ignore[method-assign]
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, REASON_READ_FAILED)
    assert facts is None


def test_point_ids_per_radio_are_bounded_and_valid_only() -> None:
    many = [f"tpt_{i:016x}" for i in range(MAX_RF_POINT_IDS + 5)] + ["phy0-ap0"]
    rf = FakeCenter({"radio0": radio(50.0, interfaces=["phy0-ap0"])})
    _status, facts = WifiRfAdapter(lambda: rf).facts(RID, interfaces={"phy0-ap0": many})
    assert facts is not None
    (one,) = facts.per_radio
    assert len(one.point_ids) == MAX_RF_POINT_IDS
    assert one.points_linked == MAX_RF_POINT_IDS + 5
