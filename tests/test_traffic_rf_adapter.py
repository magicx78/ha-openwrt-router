"""Traffic <-> WiFi RF / Network Diagnostics adapters against the merged modules.

The WiFi RF center on main (1.48.0) has no ``radio_utilization`` /
``client_retry_rates`` read methods (wish W6). The adapter reads the
center's public evaluation state instead (``status``, ``results`` with
``RadioResult.summary`` and the clients' ``retry_rate``), the same state
``wifi_rf_entities`` reads, and never a MAC. These tests use the real RF
value classes so a change of their shape fails here.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace
from typing import Any

from core_testkit import make_hass

from custom_components.openwrt_router import const
from custom_components.openwrt_router.diag_runtime import NetDiagnostics
from custom_components.openwrt_router.diag_stats import LatencySummary
from custom_components.openwrt_router.rf_center import RfCenter
from custom_components.openwrt_router.rf_clients import ClientAssessment
from custom_components.openwrt_router.rf_evaluate import RadioResult
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_models import CapabilityState, Metric
from custom_components.openwrt_router.rf_utilization import UtilizationSummary
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
from custom_components.openwrt_router.traffic_correlate import WifiRfAdapter

RID = "rtr_" + "a" * 32
OTHER = "rtr_" + "b" * 32
NOW = 1_800_000_000.0


def summary(mean: float | None, valid: int = 12, overload: bool | None = False):
    return UtilizationSummary(
        current=mean,
        mean=mean,
        peak=mean,
        valid_count=valid,
        invalid_count=0,
        coverage=1.0,
        phases=(),
        sustained_overload=overload,
    )


def retry(value: float | None) -> SimpleNamespace:
    """A client assessment as far as the adapter reads it (``retry_rate``)."""
    metric = (
        Metric(None, CapabilityState.NO_DATA, "iwinfo.assoclist")
        if value is None
        else Metric(value, CapabilityState.MEASURED, "iwinfo.assoclist", NOW)
    )
    return SimpleNamespace(client_mac="aa:bb:cc:dd:ee:ff", retry_rate=metric)


def result(router_id: str, radio: str, util: Any, clients=(), at: float = NOW):
    return SimpleNamespace(
        ref=RadioRef(router_id, radio),
        summary=util,
        assessments=tuple(clients),
        measured_at=at,
    )


def center(*results: Any, status: str = "ready", reasons=()) -> SimpleNamespace:
    return SimpleNamespace(
        status=status,
        enabled=status != "off",
        not_ready_reasons=lambda: list(reasons),
        results={r.ref: r for r in results},
        clock=lambda: NOW,
    )


def test_data_keys_are_the_modules_keys() -> None:
    assert WIFI_RF_DATA_KEY == const.DATA_WIFI_RF_CENTER
    assert DIAG_DATA_KEY == const.DATA_NET_DIAGNOSTICS


def test_rf_shapes_the_adapter_reads_exist() -> None:
    """Contract: the attributes read from the merged WiFi RF code."""
    fields = {f.name for f in dataclasses.fields(RadioResult)}
    assert {"ref", "summary", "assessments", "measured_at"} <= fields
    assert "retry_rate" in {f.name for f in dataclasses.fields(ClientAssessment)}
    assert {"mean", "valid_count", "sustained_overload"} <= {
        f.name for f in dataclasses.fields(UtilizationSummary)
    }
    for name in ("status", "enabled", "not_ready_reasons"):
        assert hasattr(RfCenter, name)
    # W6 not built: the read methods the plan asked for are still missing.
    assert not hasattr(RfCenter, "radio_utilization")
    assert not hasattr(RfCenter, "client_retry_rates")


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


def test_not_ready_carries_the_centers_reason() -> None:
    adapter = WifiRfAdapter(lambda: center(status="not_ready", reasons=["no_core"]))
    status, facts = adapter.facts(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, "no_core")
    assert facts is None


def test_unknown_shape_is_interface_mismatch() -> None:
    for module in (
        object(),
        SimpleNamespace(status="ready", results=[]),
        SimpleNamespace(status=3, results={}),
    ):
        status, _ = WifiRfAdapter(lambda m=module: m).facts(RID)
        assert (status.state, status.reason) == (
            SOURCE_NOT_READY,
            REASON_INTERFACE_MISMATCH,
        )


def test_results_give_airtime_and_retries_of_one_router() -> None:
    rf = center(
        result(RID, "radio0", summary(85.0), [retry(0.4), retry(0.1), retry(None)]),
        result(RID, "radio1", summary(20.0), [retry(0.05)]),
        result(OTHER, "radio0", summary(99.0), [retry(0.9)]),
    )
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert status.state == SOURCE_READY
    assert facts is not None
    assert facts.radios == 2
    assert facts.busiest_radio == "radio0" and facts.airtime_mean_pct == 85.0
    assert facts.airtime_high is True
    assert facts.clients_measured == 3 and facts.clients_high_retry == 1
    assert facts.retries_high is True  # 1 of 3 >= 25 %


def test_stale_or_thin_results_are_no_data() -> None:
    rf = center(
        result(RID, "radio0", summary(95.0, valid=2)),
        result(RID, "radio1", summary(90.0), at=NOW - 7200),  # older than the hour
        result(RID, "radio2", None),
    )
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NO_DATA, REASON_TOO_FEW_SAMPLES)
    assert facts is None


def test_sustained_overload_counts_without_a_mean() -> None:
    rf = center(result(RID, "radio0", summary(None, valid=0, overload=True)))
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert status.state == SOURCE_READY and facts is not None
    assert facts.airtime_high is True and facts.busiest_radio is None


def test_broken_result_entries_are_read_failed() -> None:
    class Boom:
        @property
        def ref(self) -> Any:
            raise RuntimeError("x")

    rf = center()
    rf.results = {"k": Boom()}
    status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert (status.state, status.reason) == (SOURCE_NOT_READY, REASON_READ_FAILED)
    assert facts is None


def test_facts_carry_no_client_identity() -> None:
    rf = center(result(RID, "radio0", summary(85.0), [retry(0.4)]))
    _status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert "aa:bb" not in repr(facts)


def test_w6_methods_win_when_the_center_has_them() -> None:
    """Once W6 exists, its read methods are used instead of ``results``."""
    rf = center(result(RID, "radio0", summary(10.0)))
    rf.radio_utilization = lambda rid, w: {"phy9": summary(80.0).as_dict()}
    rf.client_retry_rates = lambda rid, w: {}
    _status, facts = WifiRfAdapter(lambda: rf).facts(RID)
    assert facts is not None and facts.busiest_radio == "phy9"
