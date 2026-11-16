"""Tests for the P3 review fixes (plan 2026-11-16, P3 review H1, M1-M6, K1-K6).

Each review item has a test of the failure case that failed before the fix.
Shapes follow the read-only live check of 2026-11-16 (OpenWrt 25.12, one
gateway and five APs), anonymised: MACs 02:00:5e:..., addresses from the
documentation ranges, host names masked.
"""

from __future__ import annotations

import copy
import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_infra import (
    IP1,
    MAC1,
    MAC2,
    MAC3,
    MS0,
    T0,
    TH,
    WAN_IP1,
    WAN_IP2,
    R,
    by_kind,
    data,
    entry,
    open_incidents,
    port,
    run,
    wan,
)

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.api import _parse_lldpcli_json
from custom_components.openwrt_router.coordinator import LogBatch
from custom_components.openwrt_router.log_parser import LogCursor, LogEvent, parse_entry
from custom_components.openwrt_router.net_engine import NetIntelligence, infra_snapshot
from custom_components.openwrt_router.net_events import CauseStatus, Severity
from custom_components.openwrt_router.net_rules import (
    AlarmMachine,
    Finding,
    InfraSnapshot,
    InfraState,
    detect_infrastructure,
    finding_evidence,
    merge_settings,
    port_key,
)

LTE_IP = "198.51.100.2"
BRIDGE_ROUTER = ["Bridge", "Router"]  # what the live APs announce (Wlan off)


def feed(
    steps: list[tuple[float, dict[str, Any]]],
    fleet: frozenset[str] | None = None,
    state: InfraState | None = None,
) -> tuple[AlarmMachine, list[Finding], InfraState]:
    """Run the detectors and the alarm machine over ``(now, snapshot)`` steps."""
    machine = AlarmMachine(merge_settings(None))
    state = state if state is not None else InfraState()
    found: list[Finding] = []
    extra = {"fleet": fleet} if fleet is not None else {}
    for now, fields in steps:
        out = detect_infrastructure(state, InfraSnapshot(**fields), now, R, TH, **extra)
        found.extend(out)
        machine.update(
            now, [e for f in out if (e := finding_evidence(f, R)) is not None]
        )
    return machine, found, state


def types(machine: AlarmMachine) -> list[str]:
    return sorted(i.type for i in machine.incidents())


async def engine_on(disk: FakeDisk, *routers: str) -> NetIntelligence:
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        engine = NetIntelligence(make_hass())
        await engine.async_load()
    for router in routers:
        engine.register(router)
    return engine


def fetch(
    lines: list[dict[str, Any]],
    cursor: LogCursor,
    fetched_at: float | None,
    **fields: Any,
) -> Any:
    """Coordinator data with a log fetch (real cursor) read at ``fetched_at``."""
    result = cursor.ingest(lines)
    d = data(**fields)
    d.new_log_events = tuple(result.events)
    times = [e["time"] for e in lines]
    d.new_log_batch = LogBatch(
        baseline=result.baseline,
        missed=result.missed,
        first_time_ms=min(times) if times else None,
        last_id=cursor.last_id,
        last_time_ms=cursor.last_time,
        fetched_at=fetched_at,
    )
    return d


def line_at(log_id: int, epoch_s: float, msg: str = "crond[1803]: USER root") -> dict:
    return {
        "id": log_id,
        "time": int(epoch_s * 1000),
        "priority": 75,
        "source": 1,
        "msg": msg,
    }


# --- H1: WAN rules only on a gateway ----------------------------------------------

# A dumb AP that kept OpenWrt's default, unplugged ``wan`` section.
AP_WAN = {
    "connected": False,
    "interface": "wan",
    "ipv4": "",
    "uptime": 0,
    "proto": "dhcp",
    "wan_found": True,
}
# Live gateway: wan6 (dhcpv6) is up=false/pending in normal operation.
WAN6_PENDING = {
    "connected": False,
    "interface": "wan6",
    "ipv4": "",
    "uptime": 0,
    "proto": "dhcpv6",
    "wan_found": True,
}


def test_h1_dumb_ap_with_unplugged_wan_opens_nothing() -> None:
    machine, found, _ = feed(
        [
            (
                T0 + i * 60,
                {"uptime": 5000.0 + i * 60, "wan": AP_WAN, "wan_connected": False},
            )
            for i in range(5)
        ]
    )
    assert machine.incidents() == []
    assert not [f for f in found if f.kind.startswith("wan.")]


def test_h1_connected_wan_without_default_route_is_no_gateway() -> None:
    plugged = {**wan(), "default_route": False}
    machine, found, _ = feed(
        [
            (T0, {"wan": plugged, "wan_connected": True}),
            (
                T0 + 60,
                {"wan": {**AP_WAN, "default_route": False}, "wan_connected": False},
            ),
        ]
    )
    assert machine.incidents() == [] and not found


def test_h1_gateway_wan_down_still_raises_critical() -> None:
    machine, _found, state = feed(
        [
            (T0, {"wan": {**wan(), "default_route": True}, "wan_connected": True}),
            (T0 + 60, {"wan": wan(0, ""), "wan_connected": False}),
        ]
    )
    assert state.wan_gateway is True
    [inc] = machine.incidents()
    assert inc.type == "wan_down" and inc.severity is Severity.CRITICAL


def test_h1_wan6_pending_is_never_judged() -> None:
    machine, found, _ = feed(
        [
            (T0, {"wan": wan(), "wan_connected": True}),  # gateway learned on wan
            (T0 + 60, {"wan": WAN6_PENDING, "wan_connected": False}),
            (T0 + 120, {"wan": WAN6_PENDING, "wan_connected": False}),
        ]
    )
    assert machine.incidents() == []
    assert [f.kind for f in found] == ["wan.status"]  # only the IPv4 poll
    # wan6 alone never makes a gateway either
    machine, found, state = feed(
        [(T0, {"wan": {**WAN6_PENDING, "connected": True}, "wan_connected": True})]
    )
    assert not found and state.wan_gateway is False


@pytest.mark.asyncio
async def test_h1_gateway_memory_is_kept_in_the_store() -> None:
    disk = FakeDisk()
    engine = await engine_on(disk, R)
    engine.ingest(R, data(uptime=100, wan_status=wan(), wan_connected=True), T0)
    await engine.async_flush()
    assert R in disk.data["wan_gateways"]
    # HA restart during a WAN outage: the stored role keeps wan_down alive
    engine = await engine_on(disk, R)
    engine.ingest(
        R, data(uptime=200, wan_status=wan(0, ""), wan_connected=False), T0 + 100
    )
    assert open_incidents(engine, "wan_down")
    # a router never seen connected (dumb AP) raises nothing
    engine = await engine_on(FakeDisk(), R)
    engine.ingest(R, data(uptime=200, wan_status=AP_WAN, wan_connected=False), T0 + 100)
    assert engine.machine.incidents() == []
    # removing the router forgets its role
    assert engine.remove_router(R) is False
    engine2 = await engine_on(disk, R)
    assert engine2.remove_router(R) is True
    assert R not in engine2._data_to_save()["wan_gateways"]


# Live ``network.interface dump`` of the gateway (anonymised, trimmed).
GATEWAY_DUMP = {
    "interface": [
        {
            "interface": "lan",
            "up": True,
            "proto": "static",
            "device": "br-lan.10",
            "l3_device": "br-lan.10",
            "uptime": 1000500,
            "ipv4-address": [{"address": "192.0.2.10", "mask": 24}],
            "route": [],
        },
        {
            "interface": "wan",
            "up": True,
            "available": True,
            "proto": "static",
            "device": "wan",
            "l3_device": "wan",
            "uptime": 1000400,
            "ipv4-address": [{"address": "203.0.113.7", "mask": 24}],
            "route": [
                {
                    "target": "0.0.0.0",
                    "mask": 0,
                    "nexthop": "203.0.113.1",
                    "source": "0.0.0.0/0",
                }
            ],
        },
        {
            "interface": "wan6",
            "up": False,
            "pending": True,
            "available": True,
            "proto": "dhcpv6",
            "device": "wan",
            "route": [],
        },
        {"interface": "wg0", "up": True, "proto": "wireguard", "route": []},
    ]
}


@pytest.mark.asyncio
async def test_h1_wan_status_keeps_the_default_route(mock_api: Any) -> None:
    mock_api._call = AsyncMock(return_value=GATEWAY_DUMP)
    mock_api._read_wan_counters = AsyncMock(return_value=(1, 2))
    status = await mock_api.get_wan_status()
    assert status["interface"] == "wan" and status["default_route"] is True
    dump = copy.deepcopy(GATEWAY_DUMP)
    dump["interface"][1]["route"] = []
    mock_api._call = AsyncMock(return_value=dump)
    assert (await mock_api.get_wan_status())["default_route"] is False
    del dump["interface"][1]["route"]  # field missing: unknown
    mock_api._call = AsyncMock(return_value=dump)
    assert "default_route" not in await mock_api.get_wan_status()


# --- M1: clock skew in UTC from log times -----------------------------------------

OFFSET = 3600.0  # live: localtime - date -u = +3600 s on all six routers


def clock(now: float, error: float = 0.0, **fields: Any) -> dict[str, Any]:
    return {"localtime": now + OFFSET + error, "localtime_at": now, **fields}


def skew_values(found: list[Finding]) -> list[float | None]:
    return [f.value for f in found if f.kind == "system.clock_skew"]


def test_m1_whole_hour_utc_error_is_seen_in_the_log_times() -> None:
    # router UTC one hour ahead: localtime modulo 15 min looks perfect
    err = 3600.0
    _m, found, _ = feed(
        [
            (T0, clock(T0, err, log_fetched_at=T0)),
            (
                T0 + 60,
                clock(T0 + 60, err, log_fetched_at=T0 + 60, log_times=(T0 + 50 + err,)),
            ),
        ]
    )
    assert skew_values(found)[-1] == pytest.approx(err - 10)


def test_m1_lines_before_the_previous_fetch_are_skew_too() -> None:
    _m, found, _ = feed(
        [
            (T0, {"log_fetched_at": T0}),
            (T0 + 60, {"log_fetched_at": T0 + 60, "log_times": (T0 - 500,)}),
        ]
    )
    assert skew_values(found) == [500.0]


def test_m1_offset_is_learned_then_localtime_is_checked_absolutely() -> None:
    _m, found, state = feed(
        [
            (T0, clock(T0, log_fetched_at=T0)),
            (T0 + 60, clock(T0 + 60, log_fetched_at=T0 + 60, log_times=(T0 + 30,))),
            # no log lines: the learned offset makes 1000 s visible (modulo: 100)
            (T0 + 120, clock(T0 + 120, 1000.0)),
        ]
    )
    assert state.tz_offset == OFFSET
    assert skew_values(found)[-1] == 1000.0


def test_m1_offset_change_without_log_lines_waits_for_a_line() -> None:
    _m, found, _ = feed(
        [
            (T0, clock(T0, log_fetched_at=T0)),
            (T0 + 60, clock(T0 + 60, log_fetched_at=T0 + 60, log_times=(T0 + 30,))),
            # DST: localtime moves one hour, no line to tell DST from a fault
            (T0 + 120, clock(T0 + 120, 3600.0)),
            # the next line shows UTC is fine: new offset, no skew
            (
                T0 + 180,
                clock(T0 + 180, 3600.0, log_fetched_at=T0 + 180, log_times=(T0 + 170,)),
            ),
        ]
    )
    assert skew_values(found) == [0.0, 0.0, 0.0]


def test_m1_without_log_data_the_modulo_fallback_stays_blind() -> None:
    # documented blind spot: a whole quarter hour without any log line
    _m, found, _ = feed([(T0, clock(T0, 900.0))])
    assert skew_values(found) == [0.0]


@pytest.mark.asyncio
async def test_m1_engine_passes_log_fetch_times_to_the_detector() -> None:
    engine = await engine_on(FakeDisk(), R)
    cursor = LogCursor()
    err = 3600.0
    lines: list[dict[str, Any]] = []
    for i in range(5):
        now = T0 + i * 60
        lines.append(line_at(i + 1, now - 5 + err))
        engine.ingest(R, fetch(list(lines), cursor, now, uptime=100 + i * 60), now)
    [inc] = open_incidents(engine, "system_clock_skew")
    assert inc.scope_key == R


# --- M2: WAN failover (mwan3 wan -> lte) -------------------------------------------


def test_m2_failover_is_one_info_event_without_reconnect_or_ip_change() -> None:
    lte = {**wan(30, LTE_IP, "lte"), "proto": "qmi"}
    machine, found, _ = feed(
        [
            (T0, {"wan": wan(5000, WAN_IP1), "wan_connected": True}),
            (T0 + 60, {"wan": lte, "wan_connected": True}),
            (T0 + 120, {"wan": {**lte, "uptime": 90}, "wan_connected": True}),
            (T0 + 180, {"wan": wan(20, WAN_IP2), "wan_connected": True}),
        ]
    )
    kinds = [f.kind for f in found if f.event]
    assert kinds == ["wan.failover", "wan.failover"]
    [first, second] = by_kind(found, "wan.failover")
    assert first.severity is Severity.INFO and first.rule is None
    assert first.params == {"from": "wan", "to": "lte"}
    assert second.params == {"from": "lte", "to": "wan"}
    assert machine.incidents() == []


# --- M3: DHCPDECLINE is a client claim ---------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("arp", "status", "confidence"),
    [
        ({}, CauseStatus.HYPOTHESIS, 0.8),
        ({MAC1.lower(): IP1}, CauseStatus.HYPOTHESIS, 0.8),  # only the client itself
        ({MAC2.lower(): IP1}, CauseStatus.CONFIRMED, 1.0),  # a second MAC holds it
    ],
)
async def test_m3_decline_is_confirmed_only_by_a_second_mac(
    arp: dict[str, str], status: CauseStatus, confidence: float
) -> None:
    engine = await engine_on(FakeDisk(), R)
    cursor = LogCursor()
    first = [line_at(1, T0)]
    engine.ingest(R, fetch(first, cursor, T0, uptime=50), T0)
    decline = f"dnsmasq-dhcp[2345]: DHCPDECLINE(br-lan) {IP1} {MAC1.lower()}"
    lines = [*first, line_at(2, T0 + 30, decline)]
    engine.ingest(R, fetch(lines, cursor, T0 + 60, uptime=110, arp_table=arp), T0 + 60)
    [event] = [e for e in engine.ring if e.kind == "dhcp.decline"]
    assert event.cause == "ip_conflict"
    assert event.cause_status is status and event.confidence == confidence
    [inc] = open_incidents(engine, "dhcp_conflict")
    assert inc.cause_status is status


# --- M4: only infrastructure LLDP neighbours ---------------------------------------


def lldp(
    port_name: str, caps: list[str], chassis: str = MAC3, mgmt: Any = None
) -> dict:
    return {
        "local_interface": port_name,
        "chassis_id": chassis,
        "chassis_name": "chassis-c",
        "management_ip": mgmt,
        "port_id": "lan1",
        "capabilities": caps,
    }


def uplink_steps(neighbour: dict[str, Any]) -> list[tuple[float, dict[str, Any]]]:
    name = neighbour["local_interface"]
    return [
        (T0, {"lldp": (neighbour,), "ports": (port(name, carrier=True),)}),
        (T0 + 60, {"lldp": (), "ports": (port(name, carrier=False),)}),
    ]


def test_m4_station_neighbour_is_no_infrastructure_port() -> None:
    pc = lldp("lan3", ["Station"], chassis="02:00:5e:20:00:09")
    machine, found, _ = feed(uplink_steps(pc))
    assert not by_kind(found, "lan.uplink") and machine.incidents() == []


def test_m4_bridge_router_neighbour_is_an_uplink() -> None:
    machine, found, _ = feed(uplink_steps(lldp("lan1", BRIDGE_ROUTER)))
    assert by_kind(found, "lan.uplink")[-1].value == 1.0
    assert "lan_uplink_down" in types(machine)


@pytest.mark.parametrize(
    ("neighbour", "fleet"),
    [
        (lldp("eth0", [], chassis=MAC3.upper()), frozenset({MAC3.lower()})),
        (lldp("eth0", [], chassis="x", mgmt="192.0.2.10"), frozenset({"192.0.2.10"})),
    ],
)
def test_m4_fleet_identity_without_capabilities_is_an_uplink(
    neighbour: dict[str, Any], fleet: frozenset[str]
) -> None:
    _m, found, _ = feed(uplink_steps(neighbour), fleet=fleet)
    assert by_kind(found, "lan.uplink")
    _m, found, _ = feed(uplink_steps(neighbour), fleet=frozenset())
    assert not by_kind(found, "lan.uplink")


def test_m4_lldp_change_ignores_end_devices() -> None:
    state = InfraState()
    pc = lldp("lan3", ["Station"], chassis="02:00:5e:20:00:09")
    steps = [(T0, {"lldp": (pc,)})] + [
        (T0 + t, {"lldp": ()}) for t in (600, 1200, 1500)
    ]
    _m, found, _ = feed(steps, state=state)
    assert not by_kind(found, "lan.lldp_change")


@pytest.mark.asyncio
async def test_m4_engine_knows_the_fleet_identities() -> None:
    engine = await engine_on(FakeDisk(), "gw", "ap")
    engine.ingest(
        "ap", data(uptime=10, router_info={"mac": MAC3}), T0, host="192.0.2.20"
    )
    neighbour = [lldp("lan4", [], chassis=MAC3.lower())]
    for i, carrier in enumerate((True, False)):
        engine.ingest(
            "gw",
            data(
                uptime=10 + i * 60,
                lldp_neighbors=neighbour if carrier else [],
                lldp_status="ok",
                port_stats=[port("lan4", carrier=carrier)],
            ),
            T0 + i * 60,
            host="192.0.2.1",
        )
    [inc] = open_incidents(engine, "lan_uplink_down")
    assert inc.scope_key == port_key("gw", "lan4")


# Live ``lldpcli -f json show neighbors details`` shapes (anonymised).
def _live_port(chassis_mac: str, local_port: str) -> dict[str, Any]:
    return {
        local_port: {
            "via": "LLDP",
            "rid": "1",
            "age": "11 days, 13:51:02",
            "chassis": {
                "chassis-c": {
                    "id": {"type": "mac", "value": chassis_mac},
                    "descr": "OpenWrt 25.12.1",
                    "mgmt-ip": ["192.0.2.30", "fe80::1"],
                    "mgmt-iface": "12",
                    "capability": [
                        {"type": "Bridge", "enabled": True},
                        {"type": "Router", "enabled": True},
                        {"type": "Wlan", "enabled": False},
                        {"type": "Station", "enabled": False},
                    ],
                }
            },
            "port": {
                "id": {"type": "mac", "value": "02:00:5e:30:00:01"},
                "descr": "lan1",
                "ttl": "120",
            },
            "vlan": {"vlan-id": "10", "pvid": True, "value": "br-lan.10"},
        }
    }


@pytest.mark.parametrize(
    ("raw", "ports"),
    [
        ({"lldp": {"interface": _live_port(MAC3, "wan")}}, ["wan"]),  # one: object
        (
            {
                "lldp": {
                    "interface": [_live_port(MAC2, "lan1"), _live_port(MAC3, "lan3")]
                }
            },
            ["lan1", "lan3"],
        ),  # several: list
        ({"lldp": {}}, []),  # none: key missing
    ],
)
def test_m4_live_lldp_shapes(raw: dict[str, Any], ports: list[str]) -> None:
    neighbours = _parse_lldpcli_json(json.dumps(raw))
    assert [n["local_interface"] for n in neighbours] == ports
    for n in neighbours:
        assert n["capabilities"] == BRIDGE_ROUTER  # Wlan/Station off are dropped
        assert n["management_ip"] == "192.0.2.30"


# --- M5: our own service actions ---------------------------------------------------


@pytest.mark.asyncio
async def test_m5_control_service_records_the_action_time(mock_api: Any) -> None:
    mock_api._call = AsyncMock(return_value={})
    with patch("custom_components.openwrt_router.api.time.time", return_value=T0):
        assert await mock_api.control_service("dnsmasq", "restart") is True
        await mock_api.control_service("odhcpd", "enable")  # no process change
    assert mock_api.service_actions == {"dnsmasq": T0}


def svc(pid: int, running: bool = True) -> dict[str, Any]:
    return {"dnsmasq": {"cfg01411c": {"pid": pid, "running": running}}}


@pytest.mark.parametrize(("ago", "restarts"), [(30.0, 0), (300.0, 1)])
def test_m5_pid_change_right_after_our_restart_is_ignored(
    ago: float, restarts: int
) -> None:
    now = T0 + 60
    _m, found, _ = feed(
        [
            (T0, {"services": svc(100)}),
            (now, {"services": svc(222), "service_actions": {"dnsmasq": now - ago}}),
        ]
    )
    assert len(by_kind(found, "system.service_restart")) == restarts


def test_m5_slow_poll_our_restart_between_two_reads_is_ignored() -> None:
    # SSH fallback polls every 300 s: the button press lies between the reads
    now = T0 + 300
    _m, found, _ = feed(
        [
            (T0, {"services": svc(100)}),
            (now, {"services": svc(222), "service_actions": {"dnsmasq": T0 + 20}}),
        ]
    )
    assert not by_kind(found, "system.service_restart")


def test_m5_snapshot_reads_the_action_times() -> None:
    snap = infra_snapshot(data(service_actions={"dnsmasq": T0}))
    assert snap.service_actions == {"dnsmasq": T0}


# --- M6: flaps only on infrastructure and WAN ports --------------------------------


def flap_steps(name: str, n: int = 4) -> list[tuple[float, dict[str, Any]]]:
    steps = []
    for i in range(n):
        steps.append((T0 + i * 120, {"ports": (port(name, carrier=True),)}))
        steps.append((T0 + i * 120 + 60, {"ports": (port(name, carrier=False),)}))
    return steps


def test_m6_client_port_flaps_are_only_counted() -> None:
    machine, found, _ = feed(flap_steps("lan2"))  # a PC rebooting
    downs = by_kind(found, "lan.port_down")
    assert len(downs) == 4
    assert all(f.rule is None and not f.event for f in downs)
    assert machine.incidents() == []


def test_m6_wan_and_uplink_ports_still_flap() -> None:
    machine, _f, _ = feed(flap_steps("wan"))
    assert types(machine) == ["lan_port_flap"]


def test_m6_log_flaps_on_a_client_port_are_only_counted() -> None:
    def down(log_id: int) -> LogEvent:
        return LogEvent(
            category="link",
            kind="down",
            log_id=log_id,
            time_ms=MS0,
            interface="lan2",
            process="kernel",
        )

    _m, found, _ = feed(
        [
            (T0, {"ports": (port("lan2"),)}),
            (
                T0 + 60,
                {
                    "ports": (port("lan2"),),
                    "log_events": (down(1), down(2), down(3)),
                    "log_read": True,
                },
            ),
        ]
    )
    [flap] = by_kind(found, "lan.port_flap")
    assert flap.count == 3 and flap.rule is None and not flap.event


# --- K1: WAN up line after the WAN read --------------------------------------------


def test_k1_up_line_after_the_wan_read_is_not_counted_twice() -> None:
    def up(epoch_s: float) -> LogEvent:
        return LogEvent(
            category="iface",
            kind="up",
            log_id=int(epoch_s),
            time_ms=int(epoch_s * 1000),
            interface="wan",
            process="netifd",
        )

    _m, found, _ = feed(
        [
            (T0, {"wan": wan(5000), "wan_connected": True, "wan_at": T0 - 5}),
            # the reconnect happens after this poll's WAN read, before its log read
            (
                T0 + 60,
                {
                    "wan": wan(5060),
                    "wan_connected": True,
                    "wan_at": T0 + 55,
                    "log_events": (up(T0 + 57),),
                    "log_read": True,
                },
            ),
            # the next poll sees the new WAN session
            (T0 + 120, {"wan": wan(60), "wan_connected": True, "wan_at": T0 + 115}),
            (
                T0 + 180,
                {
                    "wan": wan(120),
                    "wan_connected": True,
                    "wan_at": T0 + 175,
                    "log_events": (),
                    "log_read": True,
                },
            ),
        ]
    )
    assert sum(f.count for f in by_kind(found, "wan.reconnect")) == 1


def test_k1_up_lines_before_the_wan_read_still_add_reconnects() -> None:
    def up(epoch_s: float) -> LogEvent:
        return LogEvent(
            category="iface",
            kind="up",
            log_id=int(epoch_s),
            time_ms=int(epoch_s * 1000),
            interface="wan",
            process="netifd",
        )

    _m, found, _ = feed(
        [
            (T0, {"wan": wan(5000), "wan_connected": True, "wan_at": T0}),
            (
                T0 + 60,
                {
                    "wan": wan(20),
                    "wan_connected": True,
                    "wan_at": T0 + 58,
                    "log_events": (up(T0 + 10), up(T0 + 30)),
                    "log_read": True,
                },
            ),
        ]
    )
    assert sum(f.count for f in by_kind(found, "wan.reconnect")) == 2


# --- K2: reboot from the boot time -------------------------------------------------


def test_k2_missed_reboot_is_found_from_the_boot_time() -> None:
    services = ["dnsmasq", "odhcpd", "wpad", "network"]
    _m, found, _ = feed(
        [
            (
                T0,
                {
                    "uptime": 100.0,
                    "services": {
                        n: {"i": {"pid": 10 + k, "running": True}}
                        for k, n in enumerate(services)
                    },
                },
            ),
            (
                T0 + 600,
                {
                    "uptime": 400.0,
                    "services": {
                        n: {"i": {"pid": 900 + k, "running": True}}
                        for k, n in enumerate(services)
                    },
                },
            ),
        ]
    )
    assert [f.kind for f in found if f.event] == ["system.reboot"]
    [reboot] = by_kind(found, "system.reboot")
    assert reboot.params["boot_shift_s"] == 300  # boot T0-100 -> T0+200


def test_k2_jitter_and_slow_polls_are_no_reboot() -> None:
    _m, found, _ = feed(
        [
            (T0, {"uptime": 1000.0, "localtime_at": T0 - 3}),
            (T0 + 60, {"uptime": 1040.0, "localtime_at": T0 + 58}),  # +18 s
            (T0 + 360, {"uptime": 1100.0, "poll_interval": 300.0}),  # +240 s
        ]
    )
    assert not by_kind(found, "system.reboot")


@pytest.mark.asyncio
async def test_k2_forward_clock_jump_is_no_reboot() -> None:
    engine = await engine_on(FakeDisk(), R)
    engine.ingest(R, data(uptime=100), T0, 1000.0)
    # HA wall clock jumps one hour ahead, only 60 s really passed
    engine.ingest(R, data(uptime=160), T0 + 3660, 1060.0)
    assert not [e for e in engine.ring if e.kind == "system.reboot"]


# --- K3: a stopped service does not escalate by itself -----------------------------


def test_k3_service_that_stays_down_keeps_its_severity() -> None:
    steps = [(T0, {"services": svc(100)})] + [
        (T0 + i * 60, {"services": svc(0, running=False)}) for i in range(1, 7)
    ]
    machine, found, _ = feed(steps)
    [inc] = machine.incidents()
    assert inc.type == "system_service_restart" and inc.severity is Severity.WARNING
    assert inc.occurrences == 1
    assert sum(1 for f in found if f.hold) == 5


def test_k3_three_real_restarts_still_escalate() -> None:
    steps = [(T0 + i * 60, {"services": svc(100 + i)}) for i in range(4)]
    machine, _f, _ = feed(steps)
    [inc] = machine.incidents()
    assert inc.severity is Severity.CRITICAL


# --- K4/K6: DNS lines --------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("msg", "kind", "cause"),
    [
        (
            (
                "dnsmasq[2345]: no servers found in /tmp/resolv.conf.d/resolv.conf.auto, "
                "will retry"
            ),
            "dns.no_servers",
            "dns_resolution",
        ),
        # src/forward.c send_from(): a reply to a client, not an upstream query
        (
            "dnsmasq[2345]: failed to send packet: Network unreachable",
            "dns.send_failed",
            None,
        ),
    ],
)
async def test_k4_k6_dns_lines_are_info(msg: str, kind: str, cause: str | None) -> None:
    engine = await engine_on(FakeDisk(), R)
    cursor = LogCursor()
    first = [line_at(1, T0)]
    engine.ingest(R, fetch(first, cursor, T0, uptime=50), T0)
    engine.ingest(
        R,
        fetch([*first, line_at(2, T0 + 30, msg)], cursor, T0 + 60, uptime=110),
        T0 + 60,
    )
    [event] = [e for e in engine.ring if e.kind == kind]
    assert event.severity is Severity.INFO and event.cause == cause


# --- K5: no ARP-based conflict -----------------------------------------------------


@pytest.mark.asyncio
async def test_k5_two_macs_for_one_ip_in_the_arp_map_are_no_conflict() -> None:
    # /proc/net/arp holds one entry per (IP, device); two MACs for one IP in
    # the merged map come from another device or a stale host hint.
    engine = await engine_on(FakeDisk(), R)
    arp = {MAC1.lower(): IP1, MAC2.lower(): IP1}
    for i in range(3):
        engine.ingest(R, data(uptime=100 + i * 60, arp_table=arp), T0 + i * 60)
    assert not [e for e in engine.ring if e.kind == "dhcp.ip_conflict"]
    assert not open_incidents(engine, "dhcp_conflict")


# --- live log lines (ap6, anonymised) ----------------------------------------------


@pytest.mark.parametrize(
    ("msg", "source", "expected"),
    [
        ("[   55.837957] br-lan: port 3(phy0-ap1) entered forwarding state", 0, None),
        ("[   55.441881] br-lan: port 3(phy0-ap1) entered disabled state", 0, None),
        (
            (
                "[ 1257.486661] ath10k_pci 0000:00:00.0: SWBA overrun on vdev 0, "
                "skipped old beacon"
            ),
            0,
            None,
        ),
        ("procd: - init complete -", 1, None),
        (
            "netifd: Network device 'phy0-ap1' link is up",
            1,
            ("link.up", "phy0-ap1", "netifd"),
        ),
    ],
)
def test_live_kernel_netifd_procd_lines(msg: str, source: int, expected: Any) -> None:
    event = parse_entry(entry(3, msg, source))
    if expected is None:
        assert event is None
    else:
        assert event is not None
        assert (event.key, event.interface, event.process) == expected


def test_live_wifi_link_line_is_no_port_flap() -> None:
    state = InfraState()
    run(state, T0, ports=(port("lan1"),))
    line = parse_entry(entry(4, "netifd: Network device 'phy0-ap1' link is down"))
    found = run(
        state, T0 + 60, ports=(port("lan1"),), log_events=(line,), log_read=True
    )
    assert not by_kind(found, "lan.port_flap")


def test_engine_snapshot_takes_wan_read_time_and_interval() -> None:
    snap = infra_snapshot(
        data(wan_status=wan(), wan_connected=True, wan_status_at=T0),
        poll_interval=120.0,
    )
    assert snap.wan_at == T0 and snap.poll_interval == 120.0
    assert not hasattr(snap, "arp")


@pytest.mark.asyncio
async def test_coordinator_listener_passes_host_and_interval() -> None:
    from datetime import timedelta

    engine = await engine_on(FakeDisk(), R)
    coordinator = MagicMock()
    coordinator.data = data(uptime=10)
    coordinator.update_interval = timedelta(seconds=120)
    coordinator.config_entry.data = {"host": "192.0.2.1"}
    with patch.object(engine, "ingest") as ingest:
        engine.async_ingest_coordinator(R, coordinator)
    kwargs = ingest.call_args.kwargs
    assert kwargs == {"host": "192.0.2.1", "interval": 120.0}
