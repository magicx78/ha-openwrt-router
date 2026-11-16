"""Engine tests for P6 (network intelligence): bus event, maintenance,
exclusions, view for the entities, timer, persistence.

AK11: ``openwrt_router_incident_event`` fires exactly once per opened,
resolved and reopened root at or above ``notify_min_severity``, after the
settle time and never for a child. AK9: maintenance marks events, opens no
incident, fires nothing, and nothing fires late after it ends. The AK1
scenario with the real ``FleetOutageTracker`` checks that the mass
disconnect and the gateway port (roots for a moment) never reach the bus.
Router names are roles, MACs locally administered test values.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from test_net_correlation import (
    AP_TRUNK,
    CLIENTS20,
    Clock,
    _Harness,
    dt,
    feed,
    gw_poll,
    hit,
    level,
    rdata,
)
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_wifi import Log, client, disc

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.const import (
    ERROR_TYPE_TIMEOUT,
    EVENT_INCIDENT,
    INTEL_ANNOUNCE_HOLD_MAX_SECONDS,
    INTEL_ANNOUNCE_SETTLE_SECONDS,
    SIGNAL_NET_INTEL,
)
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import (
    Category,
    IncidentStatus,
    NetEvent,
    Scope,
    Severity,
)

T0 = 1_763_280_000.0
G, A, B = "gw", "ap1", "ap2"
MAC = "02:00:5E:10:00:01"
SETTLE = INTEL_ANNOUNCE_SETTLE_SECONDS


class Timers:
    """Captures ``async_call_later`` of the engine."""

    def __init__(self) -> None:
        self.calls: list[tuple[float, Any, MagicMock]] = []

    def __call__(self, hass: Any, delay: float, action: Any) -> MagicMock:
        cancel = MagicMock()
        self.calls.append((delay, action, cancel))
        return cancel

    @property
    def live(self) -> list[tuple[float, Any, MagicMock]]:
        return [c for c in self.calls if not c[2].called]


@pytest.fixture(autouse=True)
def timers() -> Any:
    t = Timers()
    with patch.object(net_engine, "async_call_later", t):
        yield t


@pytest.fixture
def clock() -> Any:
    c = Clock()
    with patch.object(net_engine, "time", c):
        yield c


@pytest.fixture
async def intel(clock: Clock) -> NetIntelligence:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        engine = NetIntelligence(make_hass())
        await engine.async_load()
    engine.hass.config_entries.async_get_entry.side_effect = lambda i: SimpleNamespace(
        title=f"Router {i}"
    )
    for router in (G, A):
        engine.register(router)
    return engine


def step(intel: NetIntelligence, now: float, *evidence: Any) -> None:
    intel._run_machine(now, list(evidence))


def fired(intel: NetIntelligence) -> list[dict[str, Any]]:
    return [
        c.args[1]
        for c in intel.hass.bus.async_fire.call_args_list
        if c.args[0] == EVENT_INCIDENT
    ]


def states(intel: NetIntelligence) -> list[tuple[str, str, str]]:
    return [(e["state"], e["type"], e["incident_id"]) for e in fired(intel)]


def wan(value: float = 1.0) -> Any:
    return level("wan_down", G, value=value)


def reconnects(n: int, router: str = A, start: int = 0, mac: str = MAC) -> list[Any]:
    return [
        hit(
            "wifi_reconnect_storm",
            mac,
            router,
            scope=Scope.CLIENT,
            event_id=f"{router}:{start + i}",
        )
        for i in range(n)
    ]


def open_of(intel: NetIntelligence, type_: str) -> list[Any]:
    return [
        i
        for i in intel.machine.incidents()
        if i.type == type_ and i.status is IncidentStatus.ACTIVE
    ]


# --- AK11: bus event ----------------------------------------------------------------


async def test_root_fires_once_after_the_settle_time(intel: NetIntelligence) -> None:
    step(intel, T0, wan())
    assert fired(intel) == []  # a parent may still come
    step(intel, T0 + SETTLE - 1, wan())
    assert fired(intel) == []
    step(intel, T0 + SETTLE, wan())
    step(intel, T0 + SETTLE + 60, wan())
    step(intel, T0 + SETTLE + 120, wan())
    [event] = fired(intel)
    [inc] = open_of(intel, "wan_down")
    assert event == {
        "state": "opened",
        "incident_id": inc.id,
        "type": "wan_down",
        "severity": "critical",
        "confidence": 1.0,
        "cause": None,
        "cause_status": None,
        "scope": "router",
        "routers": ["Router gw"],
        "entry_ids": [G],
        "device_id": None,  # no device registry in this test
    }
    step(intel, T0 + 400, wan(0.0))
    assert states(intel) == [
        ("opened", "wan_down", inc.id),
        ("resolved", "wan_down", inc.id),
    ]
    step(intel, T0 + 460, wan(0.0))
    assert len(fired(intel)) == 2


async def test_client_incident_carries_the_mac(intel: NetIntelligence) -> None:
    step(intel, T0, *reconnects(5))
    step(intel, T0 + SETTLE)
    [event] = fired(intel)
    assert event["scope"] == "client" and event["mac"] == MAC
    assert event["type"] == "wifi_reconnect_storm" and event["severity"] == "warning"
    assert "mac" not in fired_router_event(intel)


def fired_router_event(intel: NetIntelligence) -> dict[str, Any]:
    step(intel, T0 + 200, wan())
    step(intel, T0 + 200 + SETTLE, wan())
    return fired(intel)[-1]


async def test_below_notify_min_severity_stays_silent(intel: NetIntelligence) -> None:
    step(intel, T0, hit("wan_ip_changed", G, G))  # info
    step(intel, T0 + SETTLE + 10)
    assert open_of(intel, "wan_ip_changed") and fired(intel) == []
    intel.settings["notify_min_severity"] = "info"
    step(intel, T0 + SETTLE + 20)  # a candidate from now on: settle again
    assert fired(intel) == []
    step(intel, T0 + 2 * SETTLE + 20)
    assert [e["type"] for e in fired(intel)] == ["wan_ip_changed"]


async def test_resolved_before_the_settle_time_never_fires(
    intel: NetIntelligence,
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + 60, wan(0.0))
    step(intel, T0 + 600, wan(0.0))
    assert fired(intel) == []


async def test_reopened_fires_once_and_after_the_settle_time(
    intel: NetIntelligence,
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + SETTLE, wan())
    step(intel, T0 + 200, wan(0.0))
    step(intel, T0 + 260, wan())  # within the cooldown: same incident again
    [inc] = open_of(intel, "wan_down")
    assert inc.reopen_count == 1
    assert [s for s, _t, _i in states(intel)] == ["opened", "resolved"]
    step(intel, T0 + 260 + SETTLE, wan())
    step(intel, T0 + 260 + SETTLE + 60, wan())
    assert [s for s, _t, _i in states(intel)] == ["opened", "resolved", "reopened"]
    assert len({i for _s, _t, i in states(intel)}) == 1


async def test_acknowledged_fires_no_open_but_resolved(intel: NetIntelligence) -> None:
    step(intel, T0, wan())
    [inc] = open_of(intel, "wan_down")
    intel.machine.acknowledge(inc.id)
    step(intel, T0 + SETTLE * 2, wan())
    assert fired(intel) == []  # acknowledged before it was announced
    step(intel, T0 + 400, wan(0.0))
    assert fired(intel) == []  # never announced, so no "resolved" either
    # announced first, acknowledged later: "resolved" still comes
    step(intel, T0 + 1000, hit("system_reboot", G, G))
    step(intel, T0 + 1000 + SETTLE)
    [reboot] = open_of(intel, "system_reboot")
    intel.machine.acknowledge(reboot.id)
    step(intel, T0 + 1000 + 1800 + SETTLE)
    assert [s for s, _t, _i in states(intel)] == ["opened", "resolved"]


async def test_ignored_incident_stays_silent(intel: NetIntelligence) -> None:
    step(intel, T0, wan())
    step(intel, T0 + SETTLE, wan())
    [inc] = open_of(intel, "wan_down")
    intel.machine.ignore(inc.id, T0 + SETTLE)
    step(intel, T0 + 300, wan(0.0))
    step(intel, T0 + 400, wan())
    step(intel, T0 + 400 + SETTLE * 2, wan())
    assert [s for s, _t, _i in states(intel)] == ["opened"]


async def test_child_never_fires_and_a_root_waits_for_its_parent(
    intel: NetIntelligence,
) -> None:
    """A client storm at the AP, then the AP's outage within the settle time:
    the storm becomes a child and is never announced (AK1, AK11)."""
    step(intel, T0, *reconnects(5))
    step(
        intel,
        T0 + 60,
        level("router_unreachable", A, since=T0 - 30),
    )
    [storm] = [i for i in intel.machine.incidents() if i.type == "wifi_reconnect_storm"]
    assert storm.parent_id is not None
    step(intel, T0 + 60 + SETTLE, level("router_unreachable", A))
    assert [e["type"] for e in fired(intel)] == ["router_unreachable"]
    step(intel, T0 + 2000, level("router_unreachable", A))
    assert [e["type"] for e in fired(intel)] == ["router_unreachable"]


async def test_late_router_holds_announcements_up_to_the_maximum(
    intel: NetIntelligence,
) -> None:
    """A router that missed its poll may be going down: hold, at most 900 s."""
    intel._seen[A] = (T0 - 100, 60.0)  # late since T0 - 25
    intel._seen[G] = (T0, 60.0)
    step(intel, T0, wan())
    intel._seen[G] = (T0 + SETTLE + 30, 60.0)
    step(intel, T0 + SETTLE + 30, wan())
    assert fired(intel) == []
    intel._seen[G] = (T0 + INTEL_ANNOUNCE_HOLD_MAX_SECONDS, 60.0)
    step(intel, T0 + INTEL_ANNOUNCE_HOLD_MAX_SECONDS, wan())
    assert [e["state"] for e in fired(intel)] == ["opened"]


async def test_late_router_back_with_data_releases_the_hold(
    intel: NetIntelligence,
) -> None:
    intel._seen[A] = (T0 - 100, 60.0)
    step(intel, T0, wan())
    step(intel, T0 + SETTLE + 10, wan())
    assert fired(intel) == []
    intel._seen[A] = (T0 + SETTLE + 20, 60.0)  # its poll arrived
    step(intel, T0 + SETTLE + 20, wan())
    assert len(fired(intel)) == 1


async def test_settle_grows_with_the_longest_poll_interval(
    intel: NetIntelligence,
) -> None:
    intel._seen[G] = (T0, 300.0)  # SSH fallback interval
    intel._seen[A] = (T0, 60.0)
    assert intel._settle() == 330.0
    intel._seen[G] = (T0, 60.0)
    assert intel._settle() == SETTLE


async def test_announced_state_survives_a_restart(clock: Clock) -> None:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        first = NetIntelligence(make_hass())
        await first.async_load()
        first.register(G)
        step(first, T0, wan())
        step(first, T0 + SETTLE, wan())
        assert len(fired(first)) == 1
        await first.async_flush()
        second = NetIntelligence(make_hass())
        await second.async_load()
    second.register(G)
    step(second, T0 + 300, wan())
    step(second, T0 + 300 + SETTLE * 2, wan())
    assert fired(second) == []  # no second "opened" after the restart
    step(second, T0 + 900, wan(0.0))
    assert [e["state"] for e in fired(second)] == ["resolved"]


async def test_timer_announces_without_another_poll(
    intel: NetIntelligence, clock: Clock, timers: Timers
) -> None:
    clock.now = T0
    step(intel, T0, wan())
    assert fired(intel) == []
    [(delay, action, _cancel)] = timers.live
    assert delay == pytest.approx(SETTLE + 1)
    clock.now = T0 + delay
    action(None)
    assert [e["state"] for e in fired(intel)] == ["opened"]


async def test_timer_is_rearmed_and_cancelled(
    intel: NetIntelligence, clock: Clock, timers: Timers
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + 10, wan())
    assert len(timers.live) == 1  # the earlier timer was cancelled
    intel.close()
    assert timers.live == []


async def test_ak1_scenario_fires_only_the_outage(clock: Clock) -> None:
    """AP outage with 20 clients (P5 scenario): the mass disconnect and the
    gateway's port are roots for a moment, but the AP is late, so nothing
    is announced until the outage links them; only the outage fires."""
    disk = FakeDisk()
    harness = _Harness(routers=(G, A, B))
    try:
        with patch.object(
            net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)
        ):
            intel = NetIntelligence(make_hass())
            await intel.async_load()
        for router in (G, A, B):
            intel.register(router)
        intel._wan_gateways.add(G)
        intel.attach_outages(harness.tracker)
        f = SimpleNamespace(intel=intel, h=harness, clock=clock)
        log = Log()
        clients = [client(mac) for mac in CLIENTS20]
        for n in range(3):
            gw_poll(f, T0 + 60 * n)
            feed(f, A, T0 + 60 * n + 20, rdata(A, clients=clients, trunk=AP_TRUNK))
            feed(f, B, T0 + 60 * n + 40, rdata(B, clients=[], trunk=AP_TRUNK))
        lines = log.lines(
            *((200 + i / 10, disc(mac)) for i, mac in enumerate(CLIENTS20))
        )
        feed(f, A, T0 + 200, rdata(A, events=lines, clients=[], trunk=AP_TRUNK))
        for t in (240, 300, 360):
            gw_poll(f, T0 + t, lan3=False)
            feed(f, B, T0 + t + 20, rdata(B, clients=[], trunk=AP_TRUNK))
        f.clock.now = T0 + 380
        f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 260))
        gw_poll(f, T0 + 420, lan3=False)
        assert fired(intel) == []  # mass disconnect held: the AP is late
        f.clock.now = T0 + 470
        f.h.fire_timer()
        for t in (480, 540, 600):
            gw_poll(f, T0 + t, lan3=False)
            feed(f, B, T0 + t + 20, rdata(B, clients=[], trunk=AP_TRUNK))
        events = fired(intel)
        assert [(e["state"], e["type"], e["entry_ids"]) for e in events] == [
            ("opened", "router_unreachable", [A])
        ]
        f.clock.now = T0 + 700
        f.h.tracker.report_up(A)
        assert [e["state"] for e in fired(intel)] == ["opened", "resolved"]
    finally:
        harness.stop()


# --- AK9: maintenance ---------------------------------------------------------------


async def test_maintenance_opens_nothing_and_fires_nothing(
    intel: NetIntelligence,
) -> None:
    intel.set_maintenance(G, True)
    step(intel, T0, wan(), hit("system_reboot", G, G))
    step(intel, T0 + SETTLE * 3, wan())
    assert [i for i in intel.machine.incidents() if G in i.routers] == []
    assert fired(intel) == []
    assert intel.view.routers[G].maintenance is True


async def test_maintenance_marks_events_and_reboot_is_info(
    intel: NetIntelligence,
) -> None:
    reboot = NetEvent(
        id="gw:1",
        ts=T0,
        router=G,
        category=Category.SYSTEM,
        kind="system.reboot",
        severity=Severity.WARNING,
    )
    assert intel._mark(reboot) is reboot
    intel.set_maintenance(G, True)
    marked = intel._mark(reboot)
    assert marked.maintenance is True and marked.severity is Severity.INFO
    other = intel._mark(
        NetEvent(
            id="ap1:1", ts=T0, router=A, category=Category.LAN, kind="lan.port_flap"
        )
    )
    assert other.maintenance is False
    # outage events of a router in maintenance are marked too
    event = intel._outage_event(G, "router.unreachable", T0, Severity.WARNING, {})
    assert event.maintenance is True and list(intel.ring)[-1] is event


async def test_maintenance_off_brings_no_late_alarm(intel: NetIntelligence) -> None:
    """4 reconnects during maintenance and 4 after: the series restarts at
    the end of maintenance, so 8 within 10 min open nothing (AK9)."""
    intel.set_maintenance(A, True)
    step(intel, T0, *reconnects(4))
    intel.set_maintenance(A, False)
    step(intel, T0 + 60, *reconnects(4, start=10))
    assert open_of(intel, "wifi_reconnect_storm") == []
    step(intel, T0 + 120, *reconnects(1, start=20))
    assert len(open_of(intel, "wifi_reconnect_storm")) == 1  # normal operation


async def test_open_incident_still_resolves_during_maintenance(
    intel: NetIntelligence,
) -> None:
    step(intel, T0, wan())
    step(intel, T0 + SETTLE, wan())
    intel.set_maintenance(G, True)
    step(intel, T0 + 200, wan(0.0))
    assert open_of(intel, "wan_down") == []
    assert [e["state"] for e in fired(intel)] == ["opened", "resolved"]
    step(intel, T0 + 300, wan())  # back within the cooldown: no reopen
    assert open_of(intel, "wan_down") == []


async def test_pending_root_of_a_router_in_maintenance_is_not_announced(
    intel: NetIntelligence,
) -> None:
    step(intel, T0, wan())
    intel.set_maintenance(G, True)
    step(intel, T0 + SETTLE * 2, wan())
    assert fired(intel) == []


async def test_fleet_maintenance_window(intel: NetIntelligence) -> None:
    intel.settings["maintenance"]["fleet_until"] = T0 + 600
    step(intel, T0, wan(), *reconnects(5))
    assert intel.machine.incidents() == []
    assert intel.in_maintenance(A) and not intel.router_maintenance(A)
    step(intel, T0 + 700, *reconnects(5, start=10))
    assert not intel.in_maintenance(A)
    assert len(open_of(intel, "wifi_reconnect_storm")) == 1


async def test_maintenance_leaves_the_fleet_score(intel: NetIntelligence) -> None:
    for router in (G, A):
        intel.ingest(router, full(router), T0, T0, interval=60)
    assert intel.view.fleet.routers == 2
    intel.set_maintenance(A, True)
    assert intel.view.fleet.routers == 1 and intel.view.fleet.maintenance == 1
    assert intel.view.routers[A].score.score is not None


async def test_maintenance_is_stored(clock: Clock) -> None:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        first = NetIntelligence(make_hass())
        await first.async_load()
        first.register(G)
        first.set_maintenance(G, True)
        assert first._payload()["maintenance_routers"] == [G]
        await first.async_flush()
        second = NetIntelligence(make_hass())
        await second.async_load()
    assert second.router_maintenance(G)
    assert second.remove_router(G) and not second.router_maintenance(G)


# --- exclusions ---------------------------------------------------------------------


async def test_excluded_incident_type_and_router(intel: NetIntelligence) -> None:
    intel.settings["exclusions"]["incident_types"] = ["wan_down"]
    intel.settings["exclusions"]["routers"] = [A]
    step(intel, T0, wan(), *reconnects(5), hit("system_reboot", G, G))
    assert [i.type for i in intel.machine.incidents()] == ["system_reboot"]


async def test_excluded_router_leaves_the_fleet_score(intel: NetIntelligence) -> None:
    for router in (G, A):
        intel.ingest(router, full(router), T0, T0, interval=60)
    intel.settings["exclusions"]["routers"] = [A]
    step(intel, T0 + 10)
    assert intel.view.fleet.routers == 1


async def test_excluded_ssid_excludes_its_clients(intel: NetIntelligence) -> None:
    other = "02:00:5E:10:00:02"
    data = full(A)
    data.clients = [client(MAC), {**client(other), "radio": "phy9-ap0"}]
    intel.ingest(A, data, T0, T0, interval=60)
    assert intel._excluded_macs() == frozenset()
    intel.settings["exclusions"]["ssids"] = ["Test-Net-xyz"]
    assert intel._excluded_macs() == {MAC}
    intel.settings["exclusions"]["macs"] = [other.lower()]
    assert intel._excluded_macs() == {MAC, other}


# --- view for the entities ------------------------------------------------------------


def full(router: str) -> SimpleNamespace:
    """Coordinator data with every indicator read (gateway G has a WAN)."""
    return SimpleNamespace(
        ap_interfaces=[{"ifname": "phy1-ap0", "ssid": "Test-Net-xyz", "phy": "phy1"}],
        clients=[{"mac": "AA:BB:CC:00:00:01"}],
        log_status="ok",
        uptime=1000,
        cpu_load=5.0,
        memory_pressure={"pct": 30},
        service_instances={"dnsmasq": {}},
        localtime=T0,
        port_stats=[{"name": "lan1"}],
        wan_status={"wan_found": router == G, "uptime": 500},
        dhcp_pools=[{"name": "lan"}] if router == G else [],
        dhcp_leases={"x": {}},
        router_info={},
    )


async def test_view_unknown_before_data_and_scored_after(
    intel: NetIntelligence,
) -> None:
    step(intel, T0)
    assert intel.view.routers[G].score.score is None
    assert intel.view.fleet.score is None
    intel._wan_gateways.add(G)
    intel.ingest(G, full(G), T0 + 10, T0 + 10, interval=60)
    view = intel.view.routers[G]
    assert view.score.score == 100 and view.score.coverage == 1.0
    assert intel.view.fleet.score == 100


async def test_view_goes_unknown_when_data_gets_stale(
    intel: NetIntelligence, clock: Clock, timers: Timers
) -> None:
    intel.ingest(G, full(G), T0, T0, interval=60)
    assert intel.view.routers[G].score.score == 100
    clock.now = T0 + 181  # older than 3 poll intervals
    timers.live[-1][1](None)
    assert intel.view.routers[G].score.score is None


async def test_view_offline_router(intel: NetIntelligence) -> None:
    intel.ingest(A, full(A), T0, T0, interval=60)
    intel._down.add(A)
    step(intel, T0 + 10)
    view = intel.view.routers[A]
    assert view.score.offline and view.score.areas["system"]["score"] == 0


async def test_view_counts_and_critical(intel: NetIntelligence) -> None:
    step(intel, T0, wan(), *reconnects(5))
    assert intel.view.routers[G].incidents_active == 1
    assert intel.view.routers[G].critical is True
    assert intel.view.routers[A].incidents_active == 1
    assert intel.view.routers[A].critical is False
    assert intel.view.fleet.incidents_active == 2 and intel.view.fleet.critical


async def test_view_rolling_wifi_counts_and_wan_reconnects(
    intel: NetIntelligence,
) -> None:
    def ev(eid: str, ts: float, kind: str, count: int = 1) -> NetEvent:
        return NetEvent(
            id=eid, ts=ts, router=A, category=Category.WIFI, kind=kind, count=count
        )

    intel.ring.add(ev("ap1:1", T0 - 4000, "wifi.reconnect", 3))  # too old
    intel.ring.add(ev("ap1:2", T0 - 600, "wifi.reconnect", 2))
    intel.ring.add(ev("ap1:3", T0 - 60, "wifi.psk_mismatch"))
    intel.ring.add(ev("ap1:4", T0 - 50, "wifi.sae_failed"))
    intel.ring.add(ev("ap1:5", T0 - 40, "wifi.connected"))
    intel.counters.add(G, "wan.up", T0 - 3600)
    intel.counters.add(G, "wan.reconnect", T0 - 60, 2)
    intel.counters.add(G, "wan.down", T0 - 60)
    step(intel, T0)
    assert intel.view.routers[A].reconnects_1h == 2
    assert intel.view.routers[A].auth_errors_1h == 2
    assert intel.view.routers[G].wan_reconnects_24h == 3


async def test_view_is_pushed_by_dispatcher(intel: NetIntelligence) -> None:
    with patch.object(net_engine, "async_dispatcher_send") as send:
        step(intel, T0)
    send.assert_called_once_with(intel.hass, SIGNAL_NET_INTEL)


async def test_closed_engine_publishes_nothing(intel: NetIntelligence) -> None:
    intel.close()
    with patch.object(net_engine, "async_dispatcher_send") as send:
        intel._refresh(T0)
        intel.set_maintenance(G, True)
    send.assert_not_called()


async def test_view_failure_never_reaches_the_poll(
    intel: NetIntelligence, caplog: pytest.LogCaptureFixture
) -> None:
    with patch.object(net_engine, "router_score", side_effect=RuntimeError("x")):
        intel.ingest(G, full(G), T0, T0, interval=60)
    assert "could not update its entities" in caplog.text


async def test_diagnostics_carry_score_and_maintenance(intel: NetIntelligence) -> None:
    intel._wan_gateways.add(G)
    intel.ingest(G, full(G), T0, T0, interval=60)
    intel.set_maintenance(G, True)
    diag = intel.diagnostics(G, T0)
    assert diag["score"] == 100 and diag["coverage"] == 1.0
    assert diag["maintenance"] is True
    assert set(diag["score_areas"]) == {"wifi", "system", "lan", "wan", "dhcp_dns"}


# --- fleet anchor -------------------------------------------------------------------


async def test_fleet_anchor_first_claim_and_hand_over(intel: NetIntelligence) -> None:
    intel.register(B)
    made: list[tuple[str, str]] = []

    def create(platform: str, entry: str) -> Any:
        return lambda: made.append((platform, entry))

    intel.claim_fleet("sensor", A, create("sensor", A))
    intel.claim_fleet("sensor", G, create("sensor", G))
    intel.claim_fleet("binary_sensor", A, create("binary_sensor", A))
    intel.claim_fleet("sensor", B, create("sensor", B))
    assert intel.fleet_anchor == A
    assert made == [("sensor", A), ("binary_sensor", A)]
    # the anchor unloads (after its platforms): the smallest entry takes over
    intel.unregister(A)
    assert intel.fleet_anchor == B  # "ap2" < "gw"
    assert made[2:] == [("sensor", B)]
    # B's binary_sensor platform claims later: created at once
    intel.claim_fleet("binary_sensor", B, create("binary_sensor", B))
    assert made[3:] == [("binary_sensor", B)]
    # the old anchor comes back: B stays
    intel.register(A)
    intel.claim_fleet("sensor", A, create("sensor", A))
    assert intel.fleet_anchor == B and len(made) == 4
    intel.unregister(B)
    intel.unregister(G)
    assert intel.fleet_anchor == A
    intel.unregister(A)
    assert intel.fleet_anchor is None


async def test_fleet_hand_over_error_is_logged(
    intel: NetIntelligence, caplog: pytest.LogCaptureFixture
) -> None:
    intel.claim_fleet("sensor", A, lambda: None)

    def broken() -> None:
        raise RuntimeError("platform gone")

    intel.claim_fleet("sensor", G, broken)
    intel.unregister(A)
    assert intel.fleet_anchor == G
    assert "could not move the fleet entities" in caplog.text
