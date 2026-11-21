"""WiFi RF findings in the existing Network Intelligence engine (1.48.0 part 2).

``rf_incidents.RfIncidentFeed`` feeds measured RF findings through the
public finding source hook as Wi-Fi events: no incident type, no rule, no
root. They link into existing incidents (radio change of the same radio,
router outage) and never suppress, excuse or rate anything. Mocks only:
no router, no Home Assistant, no network.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from rf_center_kit import (
    RID1,
    RID2,
    Clock,
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
from test_client_engine import M1, line
from test_client_engine import T0 as CT0
from test_client_engine import data as ni_data
from test_client_engine import setup as ni_setup
from test_diag_runtime import ni_disks  # noqa: F401 - fixture
from test_net_correlation import event, hit, inc_of, level

from custom_components.openwrt_router.client_engine import INFRA_ROOT_TYPES
from custom_components.openwrt_router.log_parser import WIFI_DISCONNECTED
from custom_components.openwrt_router.net_events import Category, Scope
from custom_components.openwrt_router.net_rules import (
    DEFAULT_SETTINGS,
    ROOT_TIERS,
    AlarmMachine,
    Topology,
    incident_area,
    radio_key,
)
from custom_components.openwrt_router.rf_conflicts import (
    Conflict,
    ConflictKind,
    ConflictStatus,
    RadioRef,
    Severity,
)
from custom_components.openwrt_router.rf_incidents import (
    RF_BUSY_KIND,
    RF_CONFLICT_KIND,
    RF_EVENT_KINDS,
    RF_EVENTS_PER_POLL_MAX,
    RF_REPEAT_HOLD_S,
    RF_RETRY_KIND,
    RfIncidentFeed,
)
from custom_components.openwrt_router.rf_models import (
    CapabilityState,
    Metric,
    metric_measured,
    metric_missing,
)

STATUS_A = load("hostapd_get_status_mt76_a.json")
R1 = "r1"
SOURCE = "hostapd.get_status"


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


# --- a fake center for the pure parts ------------------------------------------------


def _summary(sustained: bool | None) -> Any:
    return SimpleNamespace(
        sustained_overload=sustained, current=88.0, mean=81.5, peak=93.0
    )


def _result(
    radio_id: str,
    devices: tuple[str, ...],
    *,
    router_id: str = RID1,
    band: str = "5g",
    sustained: bool | None = None,
    retry: Metric | None = None,
) -> Any:
    util = metric_measured(85.0, SOURCE, measured_at=CT0)
    return SimpleNamespace(
        ref=RadioRef(router_id, radio_id),
        radio=SimpleNamespace(devices=devices, band=band),
        summary=_summary(sustained) if sustained is not None else None,
        metrics={"utilization": util, "retry_rate": retry},
    )


def _center(*results: Any, conflicts: tuple[Any, ...] = (), **kw: Any) -> Any:
    state = SimpleNamespace(
        options=SimpleNamespace(enabled=kw.get("enabled", True)), router_id=RID1
    )
    return SimpleNamespace(
        routers={R1: state},
        status=kw.get("status", "ready"),
        results={r.ref: r for r in results},
        fleet=SimpleNamespace(conflicts=conflicts),
    )


def _conflict(status: ConflictStatus, *refs: RadioRef) -> Conflict:
    return Conflict(
        ConflictKind.CO_CHANNEL,
        "5g",
        tuple(refs),
        status,
        Severity.WARNING,
        ("channel_plan:co_channel:5g", "utilization:radio1:85.0"),
    )


RADIO1 = ("radio1", ("phy1-ap0", "phy1-ap1"))
RADIO0 = ("radio0", ("phy0-ap0",))
RETRY_HIGH = metric_measured(0.31, "iwinfo.assoclist", measured_at=CT0)


# --- rules: events only -------------------------------------------------------------


def test_rf_kinds_are_events_only_never_rules_roots_or_areas() -> None:
    for kind in RF_EVENT_KINDS:
        assert kind not in ROOT_TIERS and kind not in INFRA_ROOT_TYPES
        assert kind not in DEFAULT_SETTINGS["thresholds"]
        assert incident_area(kind) is None
    feed = RfIncidentFeed(
        _center(
            _result(*RADIO1, sustained=True, retry=RETRY_HIGH),
            conflicts=(
                _conflict(
                    ConflictStatus.MEASURED,
                    RadioRef(RID1, "radio1"),
                    RadioRef(RID2, "radio1"),
                ),
            ),
        )
    )
    found = feed.findings(R1, None, CT0)
    assert sorted(f.kind for f in found) == sorted(RF_EVENT_KINDS)
    for f in found:
        assert f.event is True and f.rule is None and not f.hold
        assert f.category is Category.WIFI
        assert f.subject["iface"] == "phy1-ap0" and f.subject["band"] == "5g"
        text = repr((f.subject, f.params))
        assert RID1 not in text and RID2 not in text and "02:00" not in text


def test_only_measured_values_become_events() -> None:
    quiet = [
        _result(*RADIO1, sustained=False),
        _result(*RADIO1, retry=metric_measured(0.24, "iwinfo", measured_at=CT0)),
        _result(*RADIO1, retry=Metric(0.9, CapabilityState.STALE, "iwinfo", CT0)),
        _result(*RADIO1, retry=metric_missing(CapabilityState.UNSUPPORTED, "iwinfo")),
        _result(*RADIO1, retry=None),
    ]
    for result in quiet:
        assert RfIncidentFeed(_center(result)).findings(R1, None, CT0) == []
    for status in (ConflictStatus.POTENTIAL, ConflictStatus.ACCEPTABLE):
        refs = (RadioRef(RID1, "radio1"), RadioRef(RID2, "radio1"))
        center = _center(_result(*RADIO1), conflicts=(_conflict(status, *refs),))
        assert RfIncidentFeed(center).findings(R1, None, CT0) == []


def test_off_not_ready_or_unknown_router_gives_nothing() -> None:
    result = _result(*RADIO1, sustained=True)
    assert RfIncidentFeed(_center(result, enabled=False)).findings(R1, None, CT0) == []
    assert (
        RfIncidentFeed(_center(result, status="not_ready")).findings(R1, None, CT0)
        == []
    )
    assert RfIncidentFeed(_center(result)).findings("other", None, CT0) == []
    broken = SimpleNamespace(routers=None)
    assert RfIncidentFeed(broken).findings(R1, None, CT0) == []  # never raises


def test_on_change_only_with_a_repeat_hold_and_a_cap() -> None:
    center = _center(_result(*RADIO1, sustained=True))
    feed = RfIncidentFeed(center)
    assert [f.kind for f in feed.findings(R1, None, CT0)] == [RF_BUSY_KIND]
    assert feed.findings(R1, None, CT0 + 60) == []  # still busy: no repeat
    center.results = {}
    assert feed.findings(R1, None, CT0 + 120) == []  # calm again
    center.results = {r.ref: r for r in (_result(*RADIO1, sustained=True),)}
    assert feed.findings(R1, None, CT0 + 180) == []  # flapping: held
    center.results = {}
    feed.findings(R1, None, CT0 + RF_REPEAT_HOLD_S)
    center.results = {r.ref: r for r in (_result(*RADIO1, sustained=True),)}
    assert len(feed.findings(R1, None, CT0 + RF_REPEAT_HOLD_S + 60)) == 1
    many = [
        _result(f"radio{i}", (f"phy{i}-ap0",), sustained=True, retry=RETRY_HIGH)
        for i in range(8)
    ]
    assert len(RfIncidentFeed(_center(*many)).findings(R1, None, CT0)) == (
        RF_EVENTS_PER_POLL_MAX
    )


# --- case 27 -------------------------------------------------------------------------


def _rf_events(router: str) -> list[Any]:
    """The feed's findings for radio1 (phy1) and radio0 (phy0) as stored events."""
    center = _center(
        _result(*RADIO1, sustained=True), _result(*RADIO0, band="2g", retry=RETRY_HIGH)
    )
    found = RfIncidentFeed(center).findings(R1, None, CT0)
    return [
        event(f"{router}:rf{i}", CT0 + 10, router, f.kind, f.category, f.subject)
        for i, f in enumerate(found)
    ]


def _by_iface(events: list[Any], result: Any) -> dict[str, str | None]:
    return {e.subject["iface"]: result.events.get(e.id) for e in events}


def test_case_27_integration_into_existing_incidents_radio_change() -> None:
    """A radio change takes the RF events of THAT radio only."""
    m = AlarmMachine()
    radio = radio_key(R1, "phy1")
    m.update(CT0, [hit("wifi_radio_change", radio, R1, scope=Scope.RADIO)])
    events = _rf_events(R1)
    assert {e.kind for e in events} == {RF_BUSY_KIND, RF_RETRY_KIND}
    result = m.correlate(CT0 + 10, Topology(), events)
    root = inc_of(m, "wifi_radio_change", radio)
    assert _by_iface(events, result) == {"phy1-ap0": root.id, "phy0-ap0": None}
    # the RF events open nothing and change no incident
    assert [i.type for i in m.incidents()] == ["wifi_radio_change"]


def test_case_27_integration_into_existing_incidents_router_outage() -> None:
    """A router outage takes its own router's RF events, not another's."""
    m = AlarmMachine()
    m.update(CT0, [level("router_unreachable", R1, since=CT0)])
    mine, other = _rf_events(R1), _rf_events("r2")
    result = m.correlate(CT0 + 10, Topology(), [*mine, *other])
    root = inc_of(m, "router_unreachable", R1)
    assert all(result.events.get(e.id) == root.id for e in mine)
    assert all(e.id not in result.events for e in other)


def test_case_27_integration_into_existing_incidents_excuses_nothing() -> None:
    """RF events are no root: a mass disconnect stays its own incident."""
    m = AlarmMachine()
    m.update(CT0, [hit("wifi_mass_disconnect", R1, R1, count=8)])
    events = _rf_events(R1)
    result = m.correlate(CT0 + 10, Topology(), events)
    mass = inc_of(m, "wifi_mass_disconnect", R1)
    assert mass.parent_id is None and mass.cause is None
    assert all(result.events.get(e.id) in (None, mass.id) for e in events)


# --- engine path: RF on/off changes no incident, score or client rating ------------


def _busy_status() -> Any:
    counters = {"time": 200_000_000, "time_busy": 60_000_000}

    def answer() -> dict[str, Any]:
        counters["time"] += 300_000
        counters["time_busy"] += 270_000  # 90 % busy
        return {**STATUS_A, "airtime": {**STATUS_A["airtime"], **counters}}

    return answer


async def _run(rf_on: bool) -> SimpleNamespace:
    """16 polls of one router (5 minutes apart): NI, Client Stability, RF."""
    hass = rf_hass()
    engine, cs = await ni_setup(hass, R1)
    coord = FakeCoordinator(api=R1)
    opts = options("get_status") if rf_on else {}
    center, clock, reader = await new_center(
        hass, (entry(R1, opts), coord), rids={R1: RID1}, clock=Clock(CT0)
    )
    reader.answers[("get_status", "phy1-ap0")] = _busy_status()
    clients = [{"mac": M1, "radio": "phy1-ap0", "signal": -60}]
    for i in range(16):
        await poll(center, coord, poll_data(uptime=1000 + 300 * i, aps=[ap()]))
        lines = (line(WIFI_DISCONNECTED, 1),) if i == 12 else ()
        listed = [] if i == 12 else clients
        engine.ingest(R1, ni_data(listed, lines), clock(), 300.0)
        clock.advance(300)
    now = clock()
    return SimpleNamespace(
        engine=engine,
        cs=cs,
        center=center,
        now=now,
        rf=[e for e in engine.ring if e.kind in RF_EVENT_KINDS],
        other=[
            (e.kind, e.ts, e.parent_id)
            for e in engine.ring
            if e.kind not in RF_EVENT_KINDS
        ],
        incidents=[
            (i.type, i.scope_key, i.status, i.severity, i.parent_id)
            for i in engine.machine.incidents()
        ],
    )


async def test_case_27_integration_into_existing_incidents_engine_path(
    disk,
    ni_disks,  # noqa: F811
) -> None:
    on = await _run(rf_on=True)
    assert on.center.status == "ready"
    assert [e.kind for e in on.rf] == [RF_BUSY_KIND]  # once while it lasts
    (busy,) = on.rf
    assert busy.subject == {"band": "5g", "iface": "phy1-ap0"}
    assert busy.params["radio_id"] == "radio1"
    assert busy.params["source"] == SOURCE
    assert busy.params["current_pct"] == pytest.approx(90.0)
    on.center.close()  # leaves the engine
    assert not on.engine.__dict__.get("_diag_finding_sources")
    off = await _run(rf_on=False)
    assert off.rf == []
    # the same incidents, other events, NI scores and client rating
    assert on.incidents == off.incidents
    assert on.other == off.other
    assert on.engine.view.routers[R1].score == off.engine.view.routers[R1].score
    assert on.engine.view.fleet.score == off.engine.view.fleet.score
    assert on.cs.score(M1, on.now) == off.cs.score(M1, off.now)
    assert on.cs.score(M1, on.now) is not None
    assert on.cs.infra_routers(on.now) == off.cs.infra_routers(off.now) == frozenset()
    off.center.close()


def test_conflict_event_names_kind_and_peers_not_routers() -> None:
    refs = (RadioRef(RID1, "radio1"), RadioRef(RID2, "radio1"))
    center = _center(
        _result(*RADIO1), conflicts=(_conflict(ConflictStatus.MEASURED, *refs),)
    )
    (found,) = RfIncidentFeed(center).findings(R1, None, CT0)
    assert found.kind == RF_CONFLICT_KIND
    assert found.params == {
        "radio_id": "radio1",
        "conflict": "co_channel",
        "band": "5g",
        "radios": 2,
        "cross_router": True,
        "evidence_codes": ["channel_plan", "utilization"],
    }
