"""Tests for the infrastructure detectors (plan 2026-11-16, P3).

Parser fixtures follow the read-only live checks (OpenWrt 25.12.1): logd
entries ``{"msg", "id", "priority", "source", "time"}``; kernel lines have
``source`` 0 and no process prefix. Kernel, netifd, procd, odhcpd and
dnsmasq resolver lines were not seen live (A6), their text follows the
upstream sources. ubus shapes follow L1 (``network.device status``), L4
(``service list``), L5 (``system info``) and L8 (WAN status). All
addresses are documentation ranges, MACs locally administered test values.
"""

from __future__ import annotations

import copy
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError
from custom_components.openwrt_router.coordinator import (
    LogBatch,
    OpenWrtCoordinatorData,
)
from custom_components.openwrt_router.log_parser import (
    CATEGORY_DNS,
    CATEGORY_IFACE,
    CATEGORY_LINK,
    CATEGORY_SYSTEM,
    COUNT_ONLY_KINDS,
    DNS_NO_SERVERS,
    EventLimiter,
    LogCursor,
    LogEvent,
    parse_entry,
)
from custom_components.openwrt_router.net_engine import NetIntelligence, infra_snapshot
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    IncidentStatus,
    Origin,
    Scope,
    Severity,
    Source,
)
from custom_components.openwrt_router.net_rules import (
    InfraSnapshot,
    InfraState,
    clock_skew,
    detect_infrastructure,
    merge_settings,
    port_key,
    service_key,
)

T0 = 1_763_280_000.0
MS0 = int(T0 * 1000)
R = "r1"
TH = merge_settings(None)["thresholds"]
MAC1 = "02:00:5E:10:00:01"
MAC2 = "02:00:5E:10:00:02"
MAC3 = "02:00:5E:10:00:03"
IP1 = "192.0.2.51"
WAN_IP1 = "203.0.113.7"
WAN_IP2 = "203.0.113.8"


def entry(log_id: int, msg: str, source: int = 1, offset_s: float = 0) -> dict:
    return {
        "id": log_id,
        "time": MS0 + int(offset_s * 1000) + log_id,
        "priority": 6,
        "source": source,
        "msg": msg,
    }


def run(state: InfraState, now: float, **fields: Any) -> list[Any]:
    return detect_infrastructure(state, InfraSnapshot(**fields), now, R, TH)


def by_kind(findings: list[Any], kind: str) -> list[Any]:
    return [f for f in findings if f.kind == kind]


# LLDP capability of a network device (live APs announce Bridge + Router).
BRIDGE: dict[str, Any] = {"capabilities": ["Bridge"]}
# lan1 is an uplink to another router (flaps only count on such ports).
LAN1_UPLINK = ({"local_interface": "lan1", "chassis_id": MAC3, **BRIDGE},)


def port(
    name: str = "lan1",
    *,
    up: bool = True,
    carrier: bool | None = None,
    speed: int | None = 1000,
    rx_bytes: int = 0,
    tx_bytes: int = 0,
    rx_packets: int = 0,
    tx_packets: int = 0,
    rx_errors: int | None = 0,
    tx_errors: int | None = 0,
) -> dict[str, Any]:
    return {
        "name": name,
        "up": up,
        "carrier": carrier,
        "speed_mbps": speed,
        "rx_bytes": rx_bytes,
        "tx_bytes": tx_bytes,
        "rx_packets": rx_packets,
        "tx_packets": tx_packets,
        "rx_errors": rx_errors,
        "tx_errors": tx_errors,
    }


# --- log parser: new processes ---------------------------------------------------


@pytest.mark.parametrize(
    ("msg", "source", "key", "iface", "name", "process"),
    [
        (
            "[  812.123456] mt7530-mdio mdio-bus:1f lan1: Link is Down",
            0,
            "link.down",
            "lan1",
            None,
            "kernel",
        ),
        (
            (
                "[  815.5] mt7530-mdio mdio-bus:1f lan1: Link is Up - 1Gbps/Full - "
                "flow control rx/tx"
            ),
            0,
            "link.up",
            "lan1",
            None,
            "kernel",
        ),
        ("kernel: [ 9.1] eth1: Link is Down", 1, "link.down", "eth1", None, "kernel"),
        (
            "netifd: Network device 'lan2' link is down",
            1,
            "link.down",
            "lan2",
            None,
            "netifd",
        ),
        ("netifd: Interface 'wan' is now up", 1, "iface.up", "wan", None, "netifd"),
        ("netifd: Interface 'wan' is now down", 1, "iface.down", "wan", None, "netifd"),
        (
            "netifd: Interface 'wan' has link connectivity loss",
            1,
            "iface.link_lost",
            "wan",
            None,
            "netifd",
        ),
        (
            (
                "procd: Instance dnsmasq::cfg01411c s in a crash loop 6 crashes, "
                "0 seconds since last crash"
            ),
            1,
            "system.service_crash_loop",
            "cfg01411c",
            "dnsmasq",
            "procd",
        ),
        (
            (
                "[ 4711.0] Out of memory: Killed process 2345 (dnsmasq) "
                "total-vm:4096kB, anon-rss:1024kB"
            ),
            0,
            "system.oom_kill",
            None,
            "dnsmasq",
            "kernel",
        ),
        (
            (
                "dnsmasq[2345]: no servers found in /tmp/resolv.conf.d/resolv.conf.auto, "
                "will retry"
            ),
            1,
            "dns.no_servers",
            None,
            None,
            "dnsmasq",
        ),
        (
            (
                "dnsmasq[2345]: Maximum number of concurrent DNS queries reached "
                "(max: 150)"
            ),
            1,
            "dns.query_limit",
            None,
            None,
            "dnsmasq",
        ),
        (
            "dnsmasq[2345]: failed to send packet: Network unreachable",
            1,
            "dns.send_failed",
            None,
            None,
            "dnsmasq",
        ),
        (
            (
                "odhcpd[1500]: Failed to send to ff02::1%lan@br-lan (Address not "
                "available)"
            ),
            1,
            "dhcp.odhcpd_error",
            None,
            None,
            "odhcpd",
        ),
    ],
)
def test_parser_infrastructure_lines(
    msg: str,
    source: int,
    key: str,
    iface: str | None,
    name: str | None,
    process: str,
) -> None:
    event = parse_entry(entry(7, msg, source))
    assert event is not None
    assert (event.key, event.interface, event.name, event.process) == (
        key,
        iface,
        name,
        process,
    )
    assert event.log_id == 7 and event.time_ms == MS0 + 7


@pytest.mark.parametrize(
    ("msg", "source"),
    [
        ("[ 1.0] random: crng init done", 0),  # kernel, not a known line
        ("crond[1803]: USER root pid 9000 cmd /usr/bin/ha-collect", 1),
        ("dropbear[3000]: Child connection from 192.0.2.10:50000", 1),
        ("netifd: Interface 'wan' is setting up now", 1),
        ("procd: - init complete -", 1),
        ("odhcpd[1500]: A default route is present but there is no public prefix", 1),
        ("dnsmasq[2345]: using nameserver 192.0.2.1#53", 1),
        ("usteer: some line", 1),
    ],
)
def test_parser_unknown_lines_are_no_data(msg: str, source: int) -> None:
    assert parse_entry(entry(1, msg, source)) is None


@pytest.mark.parametrize(
    "raw",
    [
        None,
        {},
        {"msg": "[ 1.0] lan1: Link is Down", "id": True, "source": 0},
        {"msg": 5, "id": 1, "source": 0},
        {"msg": "[ 1.0] lan1: Link is Down", "id": 1, "source": True, "time": "x"},
        {"msg": "netifd: Interface '' is now up", "id": 1},
        {"msg": "procd: Instance :: s in a crash loop", "id": 1},
    ],
)
def test_parser_broken_entries_never_raise(raw: Any) -> None:
    event = parse_entry(raw)
    assert event is None or event.time_ms == 0


def test_kernel_line_with_bool_source_is_not_kernel() -> None:
    # source True (== 1, not 0) and no prefix: no process -> no data
    assert parse_entry(entry(1, "[ 1.0] lan1: Link is Down", True)) is None  # type: ignore[arg-type]


def test_existing_dhcp_lines_still_win_over_dns_patterns() -> None:
    event = parse_entry(
        entry(1, f"dnsmasq-dhcp[2345]: DHCPDECLINE(br-lan) {IP1} {MAC1.lower()}")
    )
    assert event is not None and event.key == "dhcp.decline"


def test_infrastructure_lines_never_become_ha_bus_events() -> None:
    events = [
        parse_entry(entry(i, msg, src))
        for i, (msg, src) in enumerate(
            [
                ("[ 1.0] lan1: Link is Down", 0),
                ("netifd: Interface 'wan' is now up", 1),
                ("procd: Instance dnsmasq::a s in a crash loop", 1),
                ("dnsmasq[1]: no servers found in /tmp/x, will retry", 1),
                ("[ 2.0] Out of memory: Killed process 1 (x)", 0),
            ],
            start=1,
        )
    ]
    fire, suppressed = EventLimiter(per_fetch=10, window_ms=60_000).select(
        [e for e in events if e is not None], MS0
    )
    assert fire == [] and suppressed == 0


def test_link_and_iface_lines_are_count_only() -> None:
    for category, kind in (
        (CATEGORY_LINK, "up"),
        (CATEGORY_LINK, "down"),
        (CATEGORY_IFACE, "up"),
        (CATEGORY_IFACE, "down"),
        (CATEGORY_IFACE, "link_lost"),
    ):
        assert (category, kind) in COUNT_ONLY_KINDS
    assert (CATEGORY_SYSTEM, "service_crash_loop") not in COUNT_ONLY_KINDS
    assert (CATEGORY_DNS, DNS_NO_SERVERS) not in COUNT_ONLY_KINDS


# --- api: fields kept from existing replies -----------------------------------------


DEVICE_STATUS_L1 = {
    "lan1": {
        "up": True,
        "carrier": True,
        "devtype": "dsa",
        "speed": "1000F",
        "statistics": {
            "rx_bytes": 123456,
            "tx_bytes": 654321,
            "rx_packets": 1000,
            "tx_packets": 2000,
            "rx_errors": 3,
            "tx_errors": 0,
            "rx_dropped": 7,
            "tx_dropped": 0,
            "collisions": 0,
            "rx_crc_errors": 2,
        },
    },
    "lan2": {
        "up": True,
        "carrier": False,
        "devtype": "dsa",
        "speed": "-1F",
        "statistics": {"rx_bytes": 0, "tx_bytes": 0},
    },
    "br-lan": {"up": True, "devtype": "bridge", "statistics": {}},
}


@pytest.mark.asyncio
async def test_port_stats_keep_carrier_and_error_counters(mock_api: Any) -> None:
    ports = await mock_api.get_port_stats(device_status=DEVICE_STATUS_L1)
    lan1, lan2 = ports
    assert lan1["carrier"] is True
    assert (lan1["rx_errors"], lan1["tx_errors"], lan1["rx_crc_errors"]) == (3, 0, 2)
    assert (lan1["rx_dropped"], lan1["tx_dropped"], lan1["collisions"]) == (7, 0, 0)
    # fields the reply lacks are None (unknown), never 0
    assert lan2["carrier"] is False
    assert lan2["rx_errors"] is None and lan2["collisions"] is None


@pytest.mark.asyncio
async def test_port_stats_broken_counters_are_unknown(mock_api: Any) -> None:
    status = copy.deepcopy(DEVICE_STATUS_L1)
    status["lan1"]["statistics"].update(rx_errors=-1, tx_errors=True)
    status["lan1"]["carrier"] = "yes"
    [lan1, _] = await mock_api.get_port_stats(device_status=status)
    assert lan1["rx_errors"] is None and lan1["tx_errors"] is None
    assert lan1["carrier"] is None


SERVICE_LIST_L4 = {
    "dnsmasq": {
        "instances": {
            "cfg01411c": {
                "running": True,
                "pid": 2345,
                "command": ["/usr/sbin/dnsmasq", "-C", "/var/etc/dnsmasq.conf"],
                "term_timeout": 5,
                "respawn": {"threshold": 3600, "timeout": 5, "retry": 5},
            }
        }
    },
    "odhcpd": {"instances": {"instance1": {"running": True, "pid": 1500}}},
    "wpad": {
        "instances": {
            "hostapd": {"running": True, "pid": 1800},
            "wpa_supplicant": {"running": False},
        }
    },
    "broken": {"instances": ["not", "a", "dict"]},
}


@pytest.mark.asyncio
async def test_services_keep_pid_per_instance_of_all_services(mock_api: Any) -> None:
    mock_api._call = AsyncMock(return_value=SERVICE_LIST_L4)
    mock_api._get_rc_enabled = AsyncMock(return_value={})
    services = await mock_api.get_services(names=["dnsmasq"])
    # the switch list stays filtered and unchanged in shape
    assert services == [{"name": "dnsmasq", "running": True, "enabled": None}]
    assert mock_api.service_instances == {
        "dnsmasq": {"cfg01411c": {"pid": 2345, "running": True}},
        "odhcpd": {"instance1": {"pid": 1500, "running": True}},
        "wpad": {
            "hostapd": {"pid": 1800, "running": True},
            "wpa_supplicant": {"pid": None, "running": False},
        },
        "broken": {},
    }
    assert mock_api._call.await_count == 1


@pytest.mark.asyncio
async def test_services_without_service_list_have_no_instances(mock_api: Any) -> None:
    mock_api.service_instances = {"dnsmasq": {}}
    mock_api._call = AsyncMock(side_effect=OpenWrtMethodNotFoundError("acl"))
    mock_api._get_services_rc_list = AsyncMock(return_value=[])
    await mock_api.get_services()
    assert mock_api.service_instances is None


@pytest.mark.asyncio
async def test_router_status_keeps_localtime_with_read_time(mock_api: Any) -> None:
    info = {
        "localtime": 1763283600,
        "uptime": 5000,
        "load": [65536, 0, 0],
        "memory": {"total": 512 * 1024 * 1024, "free": 256 * 1024 * 1024},
    }
    mock_api._call = AsyncMock(return_value=info)
    mock_api._get_cpu_cores = AsyncMock(return_value=2)
    with patch("custom_components.openwrt_router.api.time.time", return_value=T0):
        status = await mock_api.get_router_status()
    assert status["localtime"] == 1763283600
    assert status["localtime_at"] == T0
    del info["localtime"]
    status = await mock_api.get_router_status()
    assert "localtime" not in status and "localtime_at" not in status


# --- detectors: system --------------------------------------------------------------


def test_reboot_needs_a_lower_uptime_and_never_fires_on_zero() -> None:
    state = InfraState()
    assert run(state, T0, uptime=5000.0) == []
    assert not by_kind(run(state, T0 + 60, uptime=0.0), "system.reboot")
    assert not by_kind(run(state, T0 + 120, uptime=None), "system.reboot")
    assert state.uptime == 5000.0  # unknown polls keep the last usable value
    assert not by_kind(run(state, T0 + 180, uptime=5180.0), "system.reboot")
    [reboot] = by_kind(run(state, T0 + 240, uptime=40.0), "system.reboot")
    assert reboot.event and reboot.rule == "system_reboot"
    assert reboot.scope is Scope.ROUTER and reboot.scope_key == R
    assert reboot.severity is Severity.WARNING
    assert reboot.origin is Origin.OBSERVED and reboot.source is Source.POLL
    assert reboot.params == {"uptime_s": 40, "previous_uptime_s": 5180}


def test_reboot_resets_baselines_so_nothing_else_fires() -> None:
    state = InfraState()
    services = {"dnsmasq": {"a": {"pid": 100, "running": True}}}
    ports = (port(rx_packets=5000, rx_errors=0, rx_bytes=10**6),)
    run(state, T0, uptime=9000.0, services=services, ports=ports)
    after = run(
        state,
        T0 + 60,
        uptime=30.0,
        services={"dnsmasq": {"a": {"pid": 7, "running": True}}},
        ports=(port(rx_packets=10, rx_errors=0, rx_bytes=100),),
    )
    kinds = {f.kind for f in after if f.event}
    assert kinds == {"system.reboot"}


def test_cpu_value_and_unknown() -> None:
    [cpu] = by_kind(run(InfraState(), T0, cpu_load=91.26), "system.cpu_load")
    assert cpu.rule == "system_cpu_high" and cpu.value == 91.3 and not cpu.event
    assert not by_kind(run(InfraState(), T0, cpu_load=None), "system.cpu_load")


def test_ram_mirrors_pressure_and_low_available() -> None:
    [ram] = by_kind(
        run(
            InfraState(),
            T0,
            memory_pressure={"pressure_ratio": 0.5, "available_bytes": 8 * 2**20},
        ),
        "system.memory_pressure",
    )
    assert ram.value == 85.0  # less than 16 MB available counts as high
    [ram] = by_kind(
        run(
            InfraState(),
            T0,
            memory_pressure={"pressure_ratio": 0.873, "available_bytes": 2**30},
        ),
        "system.memory_pressure",
    )
    assert ram.value == 87.3
    for broken in ({}, {"pressure_ratio": "x"}, {"pressure_ratio": 3.0}):
        assert not by_kind(
            run(InfraState(), T0, memory_pressure=broken), "system.memory_pressure"
        )


@pytest.mark.parametrize(
    ("diff", "skew"),
    [
        (0, 0),
        (3600, 0),  # router in UTC+1: offset, not skew
        (-5 * 3600 - 30, 30),
        (7200 + 150, 150),
        (19800 + 40, 40),  # UTC+5:30
        (-200, 200),
        (2 * 86400, 2 * 86400),  # far beyond any UTC offset
    ],
)
def test_clock_skew_ignores_the_utc_offset(diff: float, skew: float) -> None:
    assert clock_skew(T0 + diff, T0) == pytest.approx(skew)


def test_clock_skew_needs_both_values() -> None:
    [f] = by_kind(
        run(InfraState(), T0, localtime=T0 + 3600 + 130, localtime_at=T0),
        "system.clock_skew",
    )
    assert f.value == 130.0 and f.rule == "system_clock_skew"
    assert not by_kind(run(InfraState(), T0, localtime=T0), "system.clock_skew")


def test_conntrack_jump_against_the_hourly_median() -> None:
    state = InfraState()
    for i in range(40):
        found = by_kind(run(state, T0 + i * 60, conntrack=2000 + i), "system.conntrack")
        # no judgement before the history spans half the window (30 min)
        assert bool(found) is (i >= 30)
    [f] = by_kind(run(state, T0 + 40 * 60, conntrack=9000), "system.conntrack")
    assert f.rule == "system_conntrack_jump" and f.value > 3.0
    # below min_count a high ratio is not a jump
    [f] = by_kind(run(state, T0 + 41 * 60, conntrack=4000), "system.conntrack")
    assert f.value == 0.0
    # 0 = not readable: no sample, no value
    assert not by_kind(run(state, T0 + 42 * 60, conntrack=None), "system.conntrack")
    assert not by_kind(run(InfraState(), T0, conntrack=9000), "system.conntrack")


def test_service_pid_change_is_a_restart() -> None:
    state = InfraState()
    svc = {
        "dnsmasq": {"cfg1": {"pid": 2345, "running": True}},
        "rpcd": {"i": {"pid": 10, "running": True}},
    }
    assert run(state, T0, uptime=100.0, services=svc) == []
    svc2 = {
        "dnsmasq": {"cfg1": {"pid": 2400, "running": True}},
        "rpcd": {"i": {"pid": 11, "running": True}},  # not watched (ACL deploy)
    }
    [f] = [x for x in run(state, T0 + 60, uptime=160.0, services=svc2) if x.event]
    assert f.kind == "system.service_restart" and f.source is Source.PROCD
    assert f.scope_key == service_key(R, "dnsmasq")
    assert f.subject == {"service": "dnsmasq", "instance": "cfg1"}


def test_service_stop_keeps_feeding_until_running_again() -> None:
    state = InfraState()
    run(state, T0, services={"odhcpd": {"i": {"pid": 5, "running": True}}})
    stopped = {"odhcpd": {"i": {"pid": None, "running": False}}}
    [first] = run(state, T0 + 60, services=stopped)
    assert first.kind == "system.service_stopped" and first.event
    [again] = run(state, T0 + 120, services=stopped)
    assert again.kind == "system.service_stopped" and not again.event
    assert (
        run(state, T0 + 180, services={"odhcpd": {"i": {"pid": 9, "running": True}}})
        == []
    )


def test_service_unknown_or_removed_is_not_reported() -> None:
    state = InfraState()
    run(state, T0, services={"dnsmasq": {"a": {"pid": 5, "running": True}}})
    assert run(state, T0 + 60, services=None) == []  # not fetched: keep state
    assert run(state, T0 + 120, services={}) == []  # stopped by init script
    # an instance that was never seen running is not a crash
    run(state, T0 + 180, services={"wpad": {"w": {"pid": None, "running": False}}})
    assert (
        run(state, T0 + 240, services={"wpad": {"w": {"pid": None, "running": False}}})
        == []
    )
    # broken shapes never raise
    run(state, T0 + 300, services={"dnsmasq": ["x"], "wpad": {"w": "x", 5: {}}})


# --- detectors: LAN -------------------------------------------------------------------


def test_port_down_transitions_count_as_flaps() -> None:
    state = InfraState()
    run(state, T0, ports=(port(),), lldp=LAN1_UPLINK)
    [down] = [f for f in run(state, T0 + 60, ports=(port(up=False),)) if f.event]
    assert down.kind == "lan.port_down" and down.rule == "lan_port_flap"
    assert down.scope is Scope.PORT and down.scope_key == port_key(R, "lan1")
    [up] = by_kind(run(state, T0 + 120, ports=(port(),)), "lan.port_up")
    assert not up.event and up.rule is None  # counted only


def test_carrier_wins_over_up() -> None:
    state = InfraState()
    run(state, T0, ports=(port(up=True, carrier=True),))
    found = run(state, T0 + 60, ports=(port(up=True, carrier=False),))
    assert by_kind(found, "lan.port_down")


def test_log_flaps_add_only_what_the_poll_missed() -> None:
    def link(log_id: int, kind: str, process: str) -> LogEvent:
        return LogEvent(
            category="link",
            kind=kind,
            log_id=log_id,
            time_ms=MS0,
            interface="lan1",
            process=process,
        )

    state = InfraState()
    run(state, T0, ports=(port(),), lldp=LAN1_UPLINK)
    run(state, T0 + 60, ports=(port(up=False),))  # the poll saw one down
    lines = (
        link(1, "down", "kernel"),
        link(2, "down", "netifd"),  # same down, second writer
        link(3, "up", "kernel"),
        link(4, "down", "kernel"),
        link(5, "down", "netifd"),
        link(6, "up", "kernel"),
    )
    found = run(state, T0 + 120, ports=(port(),), log_events=lines, log_read=True)
    [flap] = by_kind(found, "lan.port_flap")
    assert flap.count == 1 and flap.source is Source.NETIFD and flap.event
    # nothing double counted on the next read
    assert not by_kind(
        run(state, T0 + 180, ports=(port(),), log_events=(), log_read=True),
        "lan.port_flap",
    )


def test_port_errors_ratio_and_counter_reset() -> None:
    state = InfraState()
    base = {"rx_packets": 10_000, "tx_packets": 10_000}
    run(state, T0, ports=(port(**base, rx_errors=0),))
    assert not by_kind(
        run(
            state,
            T0 + 120,
            ports=(port(rx_packets=11_000, tx_packets=10_000, rx_errors=5),),
        ),
        "lan.port_errors",
    )  # interval not over
    [f] = by_kind(
        run(
            state,
            T0 + 300,
            ports=(port(rx_packets=12_000, tx_packets=10_000, rx_errors=4),),
        ),
        "lan.port_errors",
    )
    assert f.value == pytest.approx(0.2) and f.rule == "lan_port_errors"
    # counter reset (driver reload): no value, new base
    assert not by_kind(
        run(state, T0 + 600, ports=(port(rx_packets=50, tx_packets=50, rx_errors=0),)),
        "lan.port_errors",
    )
    # too little traffic: no value
    assert not by_kind(
        run(
            state, T0 + 900, ports=(port(rx_packets=100, tx_packets=100, rx_errors=0),)
        ),
        "lan.port_errors",
    )


def test_port_errors_missing_counters_are_unknown() -> None:
    state = InfraState()
    for i in range(3):
        found = run(
            state,
            T0 + i * 400,
            ports=(port(rx_packets=i * 5000, rx_errors=None, tx_errors=None),),
        )
        assert not by_kind(found, "lan.port_errors")


def test_port_load_from_byte_deltas() -> None:
    state = InfraState()
    run(state, T0, ports=(port(speed=100, rx_bytes=0, tx_bytes=0),))
    # 600 MB in 60 s = 80 Mbit/s on a 100 Mbit/s link
    [f] = by_kind(
        run(state, T0 + 60, ports=(port(speed=100, rx_bytes=600_000_000),)),
        "lan.port_load",
    )
    assert f.value == 80.0 and f.rule == "lan_port_load"
    assert not by_kind(
        run(state, T0 + 120, ports=(port(speed=100, rx_bytes=5),)), "lan.port_load"
    )  # counter reset


def test_speed_drop_only_on_infrastructure_and_wan_ports() -> None:
    state = InfraState()
    lldp = (
        {"local_interface": "lan2", "chassis_id": MAC3, "port_id": "lan4", **BRIDGE},
    )
    run(
        state,
        T0,
        ports=(port("lan1"), port("lan2"), port("wan")),
        lldp=lldp,
    )
    found = run(
        state,
        T0 + 60,
        ports=(
            port("lan1", speed=100),
            port("lan2", speed=100),
            port("wan", speed=100),
        ),
        lldp=lldp,
    )
    drops = {f.subject["port"]: f.value for f in by_kind(found, "lan.port_speed")}
    assert drops == {"lan2": 1.0, "wan": 1.0}  # lan1 is an access port


def test_uplink_down_on_a_port_with_an_lldp_neighbour() -> None:
    state = InfraState()
    lldp = (
        {"local_interface": "lan4", "chassis_id": MAC3, "port_id": "lan1", **BRIDGE},
    )
    run(state, T0, ports=(port("lan4"),), lldp=lldp)
    # the neighbour vanishes from LLDP once the link is down; the role stays
    found = run(state, T0 + 60, ports=(port("lan4", up=False),), lldp=())
    [f] = by_kind(found, "lan.uplink")
    assert f.value == 1.0 and f.rule == "lan_uplink_down"
    assert f.origin is Origin.OBSERVED
    # no LLDP neighbour ever: no uplink judgement
    assert not by_kind(run(InfraState(), T0, ports=(port(up=False),)), "lan.uplink")


def test_lldp_change_needs_two_states() -> None:
    state = InfraState()
    a = {"local_interface": "lan4", "chassis_id": MAC2, "port_id": "lan1", **BRIDGE}
    b = {"local_interface": "lan4", "chassis_id": MAC3, "port_id": "lan1", **BRIDGE}
    assert not by_kind(run(state, T0, lldp=(a,)), "lan.lldp_change")
    assert not by_kind(run(state, T0 + 600, lldp=(b,)), "lan.lldp_change")
    assert not by_kind(run(state, T0 + 1200, lldp=(b,)), "lan.lldp_change")
    [f] = by_kind(run(state, T0 + 1500, lldp=(b,)), "lan.lldp_change")
    assert f.params["change"] == "changed" and f.source is Source.LLDP
    assert f.scope_key == port_key(R, "lan4") and f.event
    # LLDP unavailable: unknown, nothing changes
    assert not by_kind(run(state, T0 + 2400, lldp=None), "lan.lldp_change")
    # a neighbour that only flickered away is not reported
    run(state, T0 + 3000, lldp=())
    run(state, T0 + 3600, lldp=(b,))
    assert not by_kind(run(state, T0 + 6000, lldp=(b,)), "lan.lldp_change")


def test_new_lldp_neighbour_on_a_free_port_is_not_a_change() -> None:
    state = InfraState()
    run(state, T0, lldp=())
    new = ({"local_interface": "lan3", "chassis_id": MAC2, "port_id": "x", **BRIDGE},)
    for t in (600, 1200, 1800, 2400):
        assert not by_kind(run(state, T0 + t, lldp=new), "lan.lldp_change")


def test_ports_unknown_produce_nothing() -> None:
    state = InfraState()
    run(state, T0, ports=(port(),))
    assert run(state, T0 + 60, ports=None) == []
    assert state.ports["lan1"].link is True
    run(state, T0 + 120, ports=({"name": 5}, "x", {"name": "lan1", "up": "yes"}))


# --- detectors: WAN -------------------------------------------------------------------


def wan(uptime: int = 3600, ip: str = WAN_IP1, iface: str = "wan") -> dict:
    return {
        "connected": True,
        "interface": iface,
        "ipv4": ip,
        "uptime": uptime,
        "proto": "dhcp",
        "wan_found": True,
    }


def test_wan_down_and_reconnect() -> None:
    state = InfraState()
    [status] = by_kind(run(state, T0, wan=wan(), wan_connected=True), "wan.status")
    assert status.value == 0.0 and status.rule == "wan_down"
    assert status.source is Source.NETIFD
    found = run(state, T0 + 60, wan=wan(0, ""), wan_connected=False)
    assert by_kind(found, "wan.status")[0].value == 1.0
    [down] = by_kind(found, "wan.down")
    assert down.event and down.severity is Severity.CRITICAL
    [up] = by_kind(run(state, T0 + 120, wan=wan(30), wan_connected=True), "wan.up")
    assert up.rule == "wan_unstable" and up.event


def test_wan_reconnect_between_polls_via_uptime() -> None:
    state = InfraState()
    run(state, T0, wan=wan(3600), wan_connected=True)
    [f] = by_kind(run(state, T0 + 60, wan=wan(20), wan_connected=True), "wan.reconnect")
    assert f.rule == "wan_unstable"
    # wan uptime missing: unknown, no reconnect
    assert not by_kind(
        run(state, T0 + 120, wan={**wan(), "uptime": None}, wan_connected=True),
        "wan.reconnect",
    )


def test_wan_log_reconnects_beyond_the_poll() -> None:
    def up(log_id: int, iface: str = "wan") -> LogEvent:
        return LogEvent(
            category="iface",
            kind="up",
            log_id=log_id,
            time_ms=MS0,
            interface=iface,
            process="netifd",
        )

    state = InfraState()
    run(state, T0, wan=wan(3600), wan_connected=True)
    found = run(
        state,
        T0 + 60,
        wan=wan(3660),
        wan_connected=True,
        log_events=(up(1), up(2), up(3, "wan6"), up(4, "lan")),
        log_read=True,
    )
    [f] = by_kind(found, "wan.reconnect")
    assert f.count == 2 and f.rule == "wan_unstable"


def test_wan_ip_change_is_info() -> None:
    state = InfraState()
    run(state, T0, wan=wan(), wan_connected=True)
    run(state, T0 + 60, wan=wan(0, ""), wan_connected=False)  # keeps the old IP
    found = run(state, T0 + 120, wan=wan(10, WAN_IP2), wan_connected=True)
    [f] = by_kind(found, "wan.ip_changed")
    assert f.severity is Severity.INFO and f.subject == {"ip": WAN_IP2}
    assert f.params == {"previous": WAN_IP1}


def test_router_without_wan_or_unknown_wan_has_no_wan_findings() -> None:
    assert run(InfraState(), T0, wan=None, wan_connected=False) == []
    assert run(InfraState(), T0, wan=wan(), wan_connected=None) == []


# --- detectors: DHCP ------------------------------------------------------------------


def test_pool_usage_level() -> None:
    pools = ({"name": "lan", "interface": "lan", "size": 100, "usage_pct": 93.0},)
    [f] = by_kind(run(InfraState(), T0, dhcp_pools=pools), "dhcp.pool_usage")
    assert f.value == 93.0 and f.scope is Scope.SEGMENT
    assert f.subject == {"pool": "lan", "iface": "lan"}
    broken = ({"name": "x"}, {"usage_pct": 5}, "x")
    assert run(InfraState(), T0, dhcp_pools=broken) == []


# --- engine: snapshot and scenarios ---------------------------------------------------


def data(**fields: Any) -> OpenWrtCoordinatorData:
    """A fresh coordinator data object (real defaults) with ``fields`` set."""
    d = OpenWrtCoordinatorData()
    for key, value in fields.items():
        setattr(d, key, value)
    return d


def test_snapshot_treats_coordinator_defaults_as_unknown() -> None:
    snap = infra_snapshot(OpenWrtCoordinatorData())
    assert snap == InfraSnapshot()


def test_snapshot_reads_measured_values() -> None:
    snap = infra_snapshot(
        data(
            uptime=100,
            cpu_load=12.0,
            memory_pressure={"pressure_ratio": 0.4},
            localtime=1,
            localtime_at=2.0,
            active_connections=50,
            service_instances={"dnsmasq": {}},
            port_stats=[port()],
            wan_status=wan(),
            wan_connected=True,
            dhcp_leases={MAC1: {"ip": IP1}},
            dhcp_pools=[{"name": "lan", "usage_pct": 1.0}],
            arp_table={MAC1: IP1},
            lldp_neighbors=[{"local_interface": "lan1"}],
            lldp_status="ok",
        )
    )
    assert snap.uptime == 100 and snap.cpu_load == 12.0
    assert snap.conntrack == 50 and snap.localtime == 1.0
    assert snap.services == {"dnsmasq": {}} and snap.ports == (port(),)
    assert snap.wan is not None and snap.wan_connected is True
    assert snap.dhcp_pools and snap.lldp


def test_snapshot_cpu_without_uptime_is_unknown() -> None:
    snap = infra_snapshot(data(uptime=0, cpu_load=0.0, memory_pressure={"x": 1}))
    assert snap.cpu_load is None and snap.memory_pressure is None


def test_snapshot_pools_without_leases_and_lldp_errors_are_unknown() -> None:
    snap = infra_snapshot(
        data(
            dhcp_pools=[{"name": "lan", "usage_pct": 0.0}],
            dhcp_leases={},
            lldp_neighbors=[],
            lldp_status="error",
            wan_status={**wan(), "wan_found": False},
            service_instances=MagicMock(),
        )
    )
    assert snap.dhcp_pools is None and snap.lldp is None
    assert snap.wan is None and snap.services is None


async def make_engine(*routers: str) -> NetIntelligence:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        engine = NetIntelligence(make_hass())
        await engine.async_load()
    for router in routers:
        engine.register(router)
    return engine


def open_incidents(engine: NetIntelligence, type_: str) -> list[Any]:
    return [
        i
        for i in engine.machine.incidents()
        if i.type == type_ and i.status is IncidentStatus.ACTIVE
    ]


def log_poll(lines: list[dict], cursor: LogCursor, **fields: Any) -> Any:
    """Coordinator data with a log read through a real ``LogCursor``."""
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
    )
    return d


@pytest.mark.asyncio
async def test_scenario_lan_port_flapping_opens_one_port_incident() -> None:
    engine = await make_engine(R)
    t = T0
    uplink = {"lldp_neighbors": list(LAN1_UPLINK), "lldp_status": "ok"}
    for i in range(4):
        engine.ingest(R, data(uptime=1000 + i * 120, port_stats=[port()], **uplink), t)
        engine.ingest(
            R, data(uptime=1060 + i * 120, port_stats=[port(up=False)]), t + 60
        )
        t += 120
    [inc] = open_incidents(engine, "lan_port_flap")
    assert inc.scope is Scope.PORT and inc.scope_key == port_key(R, "lan1")
    assert inc.occurrences == 4 and inc.severity is Severity.WARNING
    assert [e.kind for e in engine.ring].count("lan.port_down") == 4
    assert engine.counters.hourly(R, "lan.port_up", t, 1) == 3


@pytest.mark.asyncio
async def test_scenario_wan_outage_critical_then_resolved() -> None:
    engine = await make_engine(R)
    engine.ingest(R, data(uptime=100, wan_status=wan(), wan_connected=True), T0)
    engine.ingest(
        R, data(uptime=160, wan_status=wan(0, ""), wan_connected=False), T0 + 60
    )
    [inc] = open_incidents(engine, "wan_down")
    assert inc.severity is Severity.CRITICAL
    [down] = [e for e in engine.ring if e.kind == "wan.down"]
    assert down.category is Category.WAN and down.source is Source.NETIFD
    engine.ingest(R, data(uptime=220, wan_status=wan(5), wan_connected=True), T0 + 120)
    assert not open_incidents(engine, "wan_down")
    assert [e.kind for e in engine.ring] == ["wan.down", "wan.up"]


@pytest.mark.asyncio
async def test_scenario_wan_unstable_after_three_reconnects() -> None:
    engine = await make_engine(R)
    t = T0
    connected = True
    for i in range(7):
        engine.ingest(
            R,
            data(
                uptime=100 + i * 60,
                wan_status=wan(60 if connected else 0, WAN_IP1 if connected else ""),
                wan_connected=connected,
            ),
            t,
        )
        connected = not connected
        t += 60
    [inc] = open_incidents(engine, "wan_unstable")
    assert inc.occurrences == 3


@pytest.mark.asyncio
async def test_scenario_dns_trouble_is_one_aggregated_hypothesis_event() -> None:
    engine = await make_engine(R)
    cursor = LogCursor()
    engine.ingest(R, log_poll([entry(1, "crond[1]: x")], cursor, uptime=50), T0)
    lines = [entry(1, "crond[1]: x")] + [
        entry(
            i,
            "dnsmasq[2345]: no servers found in /tmp/resolv.conf.d/"
            "resolv.conf.auto, will retry",
        )
        for i in range(2, 6)
    ]
    engine.ingest(R, log_poll(lines, cursor, uptime=110), T0 + 60)
    [event] = [e for e in engine.ring if e.category is Category.DNS]
    assert event.kind == "dns.no_servers" and event.count == 4
    assert event.cause == "dns_resolution"
    assert event.cause_status is CauseStatus.HYPOTHESIS
    assert event.confidence == 0.5 and event.severity is Severity.INFO
    assert engine.counters.hourly(R, "dns.no_servers", T0 + 60, 1) == 4
    assert engine.machine.incidents() == []  # DNS has no rule (plan b 3.22)


@pytest.mark.asyncio
async def test_scenario_dhcp_decline_and_full_pool() -> None:
    engine = await make_engine(R)
    cursor = LogCursor()
    leases = {MAC1: {"ip": IP1}}
    pools = [{"name": "lan", "interface": "lan", "usage_pct": 95.0}]
    engine.ingest(
        R,
        log_poll(
            [entry(1, "crond[1]: x")],
            cursor,
            uptime=50,
            dhcp_leases=leases,
            dhcp_pools=pools,
        ),
        T0,
    )
    decline = f"dnsmasq-dhcp[2345]: DHCPDECLINE(br-lan) {IP1} {MAC1.lower()}"
    engine.ingest(
        R,
        log_poll(
            [entry(1, "crond[1]: x"), entry(2, decline)],
            cursor,
            uptime=110,
            dhcp_leases=leases,
            dhcp_pools=[{**pools[0], "usage_pct": 99.0}],
            arp_table={MAC2.lower(): IP1},  # a second MAC holds the address
        ),
        T0 + 60,
    )
    [conflict] = open_incidents(engine, "dhcp_conflict")
    assert conflict.cause == "ip_conflict"
    assert conflict.cause_status is CauseStatus.CONFIRMED
    [pool] = open_incidents(engine, "dhcp_pool_full")
    assert pool.severity is Severity.CRITICAL  # escalated at 98 %
    [event] = [e for e in engine.ring if e.kind == "dhcp.decline"]
    assert event.cause == "ip_conflict"


@pytest.mark.asyncio
async def test_scenario_router_reboot() -> None:
    engine = await make_engine(R)
    svc = {"dnsmasq": {"a": {"pid": 100, "running": True}}}
    engine.ingest(
        R,
        data(
            uptime=86_000,
            service_instances=svc,
            port_stats=[port(rx_packets=10**6, rx_errors=10)],
        ),
        T0,
    )
    engine.ingest(
        R,
        data(
            uptime=45,
            service_instances={"dnsmasq": {"a": {"pid": 7, "running": True}}},
            port_stats=[port(rx_packets=20, rx_errors=0)],
        ),
        T0 + 120,
    )
    assert [e.kind for e in engine.ring] == ["system.reboot"]
    [inc] = open_incidents(engine, "system_reboot")
    assert inc.scope_key == R
    # uptime 0 (system info failed) after that: no second reboot
    engine.ingest(R, data(uptime=0), T0 + 180)
    engine.ingest(R, data(uptime=165), T0 + 240)
    assert [e.kind for e in engine.ring] == ["system.reboot"]


@pytest.mark.asyncio
async def test_scenario_log_rotation_baseline_lines_feed_no_detector() -> None:
    engine = await make_engine(R)
    cursor = LogCursor()
    engine.ingest(R, log_poll([entry(50, "crond[1]: x")], cursor, uptime=10), T0)
    engine.ingest(
        R, log_poll([entry(51, "crond[1]: x")], cursor, port_stats=[port()]), T0 + 60
    )
    # logd restarted: ids start again low; the old link lines are history
    restarted = [
        entry(1, "[ 3.0] lan1: Link is Down", 0),
        entry(2, "[ 5.0] lan1: Link is Up - 1Gbps/Full", 0),
        entry(3, "netifd: Interface 'wan' is now up"),
    ]
    found = log_poll(
        restarted,
        cursor,
        port_stats=[port()],
        wan_status=wan(),
        wan_connected=True,
    )
    assert found.new_log_batch.baseline
    engine.ingest(R, found, T0 + 120)
    assert not [e for e in engine.ring if e.kind in ("lan.port_flap", "wan.reconnect")]


@pytest.mark.asyncio
async def test_scenario_missing_log_and_missing_acl_rights() -> None:
    engine = await make_engine(R)
    # log not permitted (no batch), service list/ports/arp not readable
    for i in range(5):
        d = data(
            uptime=100 + i * 60,
            cpu_load=95.0,
            service_instances=None,
            port_stats=[],
            arp_table={},
            lldp_status="unavailable",
            log_status="not_permitted",
        )
        engine.ingest(R, d, T0 + i * 60)
    # CPU still measured (debounce 3): one incident, nothing else
    assert [i.type for i in engine.machine.incidents()] == ["system_cpu_high"]
    assert len(engine.ring) == 0


@pytest.mark.asyncio
async def test_scenario_duplicate_polls_and_lines_count_once() -> None:
    engine = await make_engine(R)
    cursor = LogCursor()
    engine.ingest(R, log_poll([entry(1, "crond[1]: x")], cursor, uptime=10), T0)
    crash = "procd: Instance dnsmasq::cfg1 s in a crash loop 6 crashes"
    lines = [entry(1, "crond[1]: x"), entry(2, crash), entry(3, crash)]
    d = log_poll(lines, cursor, uptime=70)
    engine.ingest(R, d, T0 + 60)
    engine.ingest(R, d, T0 + 61)  # failed poll re-sends the same data
    # the same lines read again (cursor dedup): nothing new
    engine.ingest(R, log_poll(lines, cursor, uptime=130), T0 + 120)
    [event] = [e for e in engine.ring if e.kind == "system.service_crash_loop"]
    assert event.count == 2 and event.subject == {"service": "dnsmasq", "iface": "cfg1"}
    assert event.source is Source.PROCD
    [inc] = open_incidents(engine, "system_service_restart")
    assert inc.scope_key == service_key(R, "dnsmasq") and inc.occurrences == 2


@pytest.mark.asyncio
async def test_reload_starts_detectors_fresh() -> None:
    engine = await make_engine(R)
    engine.ingest(R, data(uptime=9000), T0)
    engine.register(R)  # reload
    engine.ingest(R, data(uptime=50), T0 + 60)
    assert len(engine.ring) == 0  # first poll after a reload is a baseline
    engine.unregister(R)
    assert R not in engine._infra


@pytest.mark.asyncio
async def test_detector_error_never_reaches_the_poll(caplog: Any) -> None:
    engine = await make_engine(R)
    coordinator = MagicMock()
    coordinator.data = data(uptime=10)
    with patch.object(
        net_engine, "detect_infrastructure", side_effect=RuntimeError("boom")
    ):
        engine.async_ingest_coordinator(R, coordinator)
    assert "could not process a poll" in caplog.text


@pytest.mark.asyncio
async def test_clock_shift_moves_detector_times() -> None:
    engine = await make_engine(R)
    lldp = [{"local_interface": "lan4", "chassis_id": MAC3, "port_id": "x", **BRIDGE}]
    engine.ingest(
        R,
        data(
            uptime=10, port_stats=[port("lan4")], lldp_neighbors=lldp, lldp_status="ok"
        ),
        T0,
    )
    seen = engine._infra[R].ports["lan4"].infra_seen
    engine.ingest(R, data(uptime=70), T0 - 3600)  # HA clock jumped back 1 h
    assert engine._infra[R].ports["lan4"].infra_seen == seen - 3600
