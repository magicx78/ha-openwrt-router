"""Channel plan with WiFi RF measurements (Q4, release 1.48.0 part 2).

A same_channel/overlap finding leaves the Repairs issue (info only) when the
channel utilization of ALL its radios is freshly measured and low. Unknown,
unsupported, unreachable, stale, not ready or RF off: the issue stays as it
is today. RF off: findings, issue and log line exactly as before. Mocks
only: no router, no Home Assistant, no network.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from rf_center_kit import (
    RID1,
    RID2,
    FakeCoordinator,
    ap,
    entry,
    load,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)
from test_channel_plan import _Fleet

from custom_components.openwrt_router import rf_bridge
from custom_components.openwrt_router.channel_plan import (
    RF_STATUS,
    Radio,
    analyze,
    rf_downgraded,
)
from custom_components.openwrt_router.const import DATA_WIFI_RF_CENTER
from custom_components.openwrt_router.fleet import collect_radios, rf_pair_evidence
from custom_components.openwrt_router.rf_conflicts import (
    Conflict,
    ConflictKind,
    ConflictStatus,
    RadioRef,
    Severity,
)
from custom_components.openwrt_router.rf_models import (
    CapabilityState,
    Metric,
    metric_measured,
    metric_missing,
)

GW, AP2 = "gw", "ap2"
RIDS = {GW: RID1, AP2: RID2}
STATUS_A = load("hostapd_get_status_mt76_a.json")
CO_CHANNEL = ap("phy1-ap0", channel=36, htmode="HE20", center=36)
LOG_LINE = "Wi-Fi channel plan: %d conflict(s) across OpenWrt routers"
SOURCE = "hostapd.get_status"


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


@pytest.fixture
def fleet() -> Any:
    f = _Fleet()
    yield f
    f.stop()


def _status(busy_pct: float) -> Any:
    """hostapd get_status answers whose airtime counter delta is ``busy_pct``."""
    counters = {"time": 200_000_000, "time_busy": 60_000_000}

    def answer() -> dict[str, Any]:
        counters["time"] += 300_000
        counters["time_busy"] += int(3_000 * busy_pct)
        return {**STATUS_A, "airtime": {**STATUS_A["airtime"], **counters}}

    return answer


def _fleet_entry(entry_id: str) -> Any:
    item = MagicMock()
    item.entry_id = entry_id
    item.title = f"Router {entry_id}"
    item.runtime_data.coordinator.last_update_success = True
    item.runtime_data.coordinator.data.ap_interfaces = [CO_CHANNEL]
    item.runtime_data.coordinator.data.sta_interfaces = []
    return item


def _opts(busy: float | None, given: dict[str, Any] | None) -> dict[str, Any]:
    if given is not None:
        return given
    return options("get_status") if busy is not None else options()


async def _rf(
    fleet: Any,
    gw_busy: float | None,
    ap2_busy: float | None,
    *,
    ap2_opts: dict[str, Any] | None = None,
    **kw: Any,
) -> Any:
    """Two routers on channel 36 with RF, polled twice (300 s apart)."""
    coords = {GW: FakeCoordinator(api=GW), AP2: FakeCoordinator(api=AP2)}
    center, clock, reader = await new_center(
        rf_hass(),
        (entry(GW, _opts(gw_busy, None)), coords[GW]),
        (entry(AP2, _opts(ap2_busy, ap2_opts)), coords[AP2]),
        rids=RIDS,
        **kw,
    )

    async def read(api: Any, kind: str, device: str) -> dict[str, Any]:
        return await reader(api, kind, f"{api}:{device}")  # one reader, two routers

    center.read = read
    for eid, busy in ((GW, gw_busy), (AP2, ap2_busy)):
        if busy is not None:
            reader.answers[("get_status", f"{eid}:phy1-ap0")] = _status(busy)
    await _polls(center, clock, coords, 1000, 2)
    fleet.hass.data[DATA_WIFI_RF_CENTER] = center
    fleet.entries = [_fleet_entry(GW), _fleet_entry(AP2)]
    return SimpleNamespace(center=center, clock=clock, reader=reader, coords=coords)


async def _polls(center: Any, clock: Any, coords: Any, uptime: int, n: int) -> None:
    for i in range(n):
        data = poll_data(uptime=uptime + 300 * i, aps=[CO_CHANNEL], clients=[])
        for coord in coords.values():
            await poll(center, coord, data)
        clock.advance(300)


def _sensor(fleet: Any, entry_id: str = GW) -> Any:
    from custom_components.openwrt_router.sensor import OpenWrtChannelPlanSensor

    item = next(e for e in fleet.entries if e.entry_id == entry_id)
    coordinator = item.runtime_data.coordinator
    coordinator.router_info = {}
    sensor = OpenWrtChannelPlanSensor(coordinator, item)
    sensor.hass = fleet.hass
    return sensor


def _only_status(fleet: Any) -> dict[str, Any]:
    (finding,) = _sensor(fleet).extra_state_attributes["findings"]
    return finding[RF_STATUS]


def _evaluate(fleet: Any, times: int = 2) -> None:
    for _ in range(times):
        fleet.monitor.evaluate(GW)


# --- the two cases of Q4 --------------------------------------------------------------


async def test_q4_measured_low_on_all_radios_takes_the_pair_off_the_repair(
    disk, fleet, caplog
) -> None:
    await _rf(fleet, 10.0, 12.0)
    caplog.set_level(logging.INFO)
    _evaluate(fleet, 3)
    assert fleet.created == []  # info only: no Repairs issue, no log line
    assert "Wi-Fi channel plan" not in caplog.text
    # the sensor keeps the finding (state and attributes as before) and adds
    # the measured evidence
    sensor = _sensor(fleet)
    assert sensor.native_value == 1
    (finding,) = sensor.extra_state_attributes["findings"]
    assert finding["type"] == "same_channel"
    status = finding[RF_STATUS]
    assert status["status"] == "acceptable" and status["downgraded"] is True
    assert status["reason"] == "measured_low"
    assert sorted(r["utilization_pct"] for r in status["radios"]) == [10.0, 12.0]
    assert {r["source"] for r in status["radios"]} == {SOURCE}
    assert {r["state"] for r in status["radios"]} == {"measured"}
    assert all(isinstance(r["measured_at"], float) for r in status["radios"])
    text = repr(sensor.extra_state_attributes)
    for secret in (RID1, RID2, "02:00:00", "example-ssid"):
        assert secret not in text


async def test_q4_one_radio_not_measured_keeps_the_repair(disk, fleet) -> None:
    await _rf(fleet, 10.0, None)  # ap2: RF on, get_status not switched on
    _evaluate(fleet)
    (call,) = fleet.created
    assert call.kwargs["translation_placeholders"]["count"] == "1"
    status = _only_status(fleet)
    assert status["downgraded"] is False
    assert status["reason"] == "utilization_unknown"


async def test_q4_high_utilization_keeps_the_repair(disk, fleet) -> None:
    await _rf(fleet, 10.0, 90.0)
    _evaluate(fleet)
    assert len(fleet.created) == 1
    status = _only_status(fleet)
    assert status["status"] == "measured" and status["downgraded"] is False


async def test_q4_middle_band_keeps_the_repair(disk, fleet) -> None:
    await _rf(fleet, 10.0, 50.0)  # above "low", below "high"
    _evaluate(fleet)
    assert len(fleet.created) == 1
    assert _only_status(fleet)["reason"] == "utilization_not_low"


async def test_q4_unsupported_read_keeps_the_repair(disk, fleet) -> None:
    rf = await _rf(fleet, 10.0, None, ap2_opts=options("get_status"))
    assert ("get_status", f"{AP2}:phy1-ap0") in rf.reader.calls  # "unsupported"
    _evaluate(fleet)
    assert len(fleet.created) == 1
    status = _only_status(fleet)
    assert status["downgraded"] is False
    assert status["reason"] == "utilization_unknown"


async def test_q4_rf_off_on_one_router_keeps_the_repair(disk, fleet) -> None:
    await _rf(fleet, 10.0, None, ap2_opts=options(enabled=False))
    _evaluate(fleet)
    assert len(fleet.created) == 1
    assert _only_status(fleet)["reason"] == "radio_not_monitored"


async def test_q4_not_ready_keeps_the_repair(disk, fleet) -> None:
    rf = await _rf(fleet, 10.0, 12.0, key=None)  # no module key: not ready
    assert rf.center.status == "not_ready"
    _evaluate(fleet)
    assert len(fleet.created) == 1
    assert _only_status(fleet)["downgraded"] is False


async def test_q4_lost_measurement_keeps_the_repair(disk, fleet) -> None:
    rf = await _rf(fleet, 10.0, 12.0)
    rf.reader.answers.pop(("get_status", f"{AP2}:phy1-ap0"))  # now unsupported
    await _polls(rf.center, rf.clock, rf.coords, 1600, 1)
    _evaluate(fleet)
    assert len(fleet.created) == 1
    assert _only_status(fleet)["downgraded"] is False


async def test_q4_downgrade_ends_when_the_channel_gets_busy(disk, fleet) -> None:
    rf = await _rf(fleet, 10.0, 12.0)
    _evaluate(fleet)
    assert fleet.created == []
    rf.reader.answers[("get_status", f"{AP2}:phy1-ap0")] = _status(90.0)
    await _polls(rf.center, rf.clock, rf.coords, 1600, 2)
    _evaluate(fleet)
    assert len(fleet.created) == 1
    assert _only_status(fleet)["status"] == "measured"


# --- RF off: exactly as before ---------------------------------------------------------


def _record(center: Any, caplog: Any) -> tuple[Any, ...]:
    """Issue calls, log lines, findings and sensor attributes of one fleet."""
    fleet = _Fleet()
    try:
        if center is not None:
            fleet.hass.data[DATA_WIFI_RF_CENTER] = center
        fleet.entries = [_fleet_entry(GW), _fleet_entry(AP2)]
        caplog.clear()
        _evaluate(fleet, 3)
        evidence = rf_pair_evidence(fleet.hass)
        findings = analyze(collect_radios(fleet.hass), rf=evidence)
        messages = [r.getMessage() for r in caplog.records if "channel plan" in r.msg]
        created = [(c.args[1:], c.kwargs) for c in fleet.created]
        attributes = _sensor(fleet).extra_state_attributes
        return created, messages, findings, attributes, evidence
    finally:
        fleet.stop()


async def test_q4_rf_off_gives_the_same_findings_issue_and_log(disk, caplog) -> None:
    caplog.set_level(logging.INFO)
    coords = {GW: FakeCoordinator(api=GW), AP2: FakeCoordinator(api=AP2)}
    center, clock, reader = await new_center(
        rf_hass(), (entry(GW), coords[GW]), (entry(AP2), coords[AP2]), rids=RIDS
    )
    await _polls(center, clock, coords, 1000, 2)
    assert reader.calls == [] and not center.enabled  # RF off (the default)
    before = _record(None, caplog)  # no RF center at all
    after = _record(center, caplog)
    assert after == before
    created, messages, findings, _attributes, evidence = after
    assert evidence is None
    assert len(created) == 1
    assert messages == [LOG_LINE % 1]
    assert findings and all(RF_STATUS not in f for f in findings)


def test_q4_analyze_without_evidence_is_unchanged() -> None:
    radios = [
        Radio("gw", "Router gw", "phy1", "5g", 36, 20, 36),
        Radio("ap2", "Router ap2", "phy1", "5g", 36, 20, 36),
        Radio("ap2", "Router ap2", "phy0", "2.4g", 3, 20, 3),
    ]
    assert analyze(radios, rf=None) == analyze(radios)
    seen: list[tuple[str, str]] = []

    def rf(a: Radio, b: Radio) -> dict[str, Any] | None:
        seen.append((a.router, b.router))
        return None  # no evidence: the finding stays as it is

    assert analyze(radios, rf=rf) == analyze(radios)
    assert seen == [("Router ap2", "Router gw")]  # pair findings only
    assert not any(rf_downgraded(f) for f in analyze(radios))


# --- the decision itself (pure) ----------------------------------------------------------


def _result(router_id: str, util: Metric | None) -> Any:
    return SimpleNamespace(
        ref=RadioRef(router_id, "radio1"),
        radio=SimpleNamespace(phy="phy1", band="5g"),
        metrics={"utilization": util},
    )


def _fake_center(found: ConflictStatus, u1: Any, u2: Any) -> Any:
    r1, r2 = _result(RID1, u1), _result(RID2, u2)
    on = SimpleNamespace(enabled=True)
    conflict = Conflict(
        ConflictKind.CO_CHANNEL,
        "5g",
        (r1.ref, r2.ref),
        found,
        Severity.INFO,
        ("backhaul:uplink_pair",),
    )
    return SimpleNamespace(
        enabled=True,
        status="ready",
        routers={
            GW: SimpleNamespace(options=on, router_id=RID1),
            AP2: SimpleNamespace(options=on, router_id=RID2),
        },
        results={r1.ref: r1, r2.ref: r2},
        fleet=SimpleNamespace(conflicts=(conflict,)),
    )


A = Radio(AP2, "Router ap2", "phy1", "5g", 36, 20, 36)
B = Radio(GW, "Router gw", "phy1", "5g", 36, 20, 36)
LOW = metric_measured(10.0, SOURCE, measured_at=1.0)


@pytest.mark.parametrize(
    "other",
    [
        metric_missing(CapabilityState.NO_DATA, SOURCE),
        metric_missing(CapabilityState.UNSUPPORTED, SOURCE),
        metric_missing(CapabilityState.UNREACHABLE, SOURCE),
        Metric(10.0, CapabilityState.STALE, SOURCE, 1.0),
        None,
    ],
    ids=["no_data", "unsupported", "unreachable", "stale", "not_assessed"],
)
def test_q4_unknown_unsupported_or_stale_never_downgrades(other: Any) -> None:
    """The uplink pair's "acceptable" without a measurement does not count."""
    center = _fake_center(ConflictStatus.ACCEPTABLE, LOW, other)
    status = rf_bridge.channel_plan_evidence(center, A, B)
    assert status["downgraded"] is False
    assert status["reason"] == "utilization_unknown"


def test_q4_only_acceptable_with_both_low_downgrades() -> None:
    center = _fake_center(ConflictStatus.ACCEPTABLE, LOW, LOW)
    assert rf_bridge.channel_plan_evidence(center, A, B)["downgraded"] is True
    center = _fake_center(ConflictStatus.POTENTIAL, LOW, LOW)  # e.g. same router
    assert rf_bridge.channel_plan_evidence(center, A, B)["downgraded"] is False
    center.status = "not_ready"
    assert rf_bridge.channel_plan_evidence(center, A, B)["reason"] == "not_ready"


def test_q4_other_pair_finding_does_not_count() -> None:
    center = _fake_center(ConflictStatus.ACCEPTABLE, LOW, LOW)
    center.fleet.conflicts = ()
    status = rf_bridge.channel_plan_evidence(center, A, B)
    assert status["downgraded"] is False and status["reason"] == "no_rf_finding"


def test_q4_evidence_error_is_no_downgrade() -> None:
    broken = SimpleNamespace(enabled=True, routers=None)
    status = rf_bridge.channel_plan_evidence(broken, A, B)
    assert status["downgraded"] is False and status["reason"] == "error"


def test_q4_broken_rf_lookup_leaves_the_plan_alone(monkeypatch) -> None:
    def boom(_hass: Any) -> None:
        raise RuntimeError("broken")

    monkeypatch.setattr(rf_bridge, "channel_plan_evidence_of", boom)
    assert rf_pair_evidence(MagicMock()) is None
