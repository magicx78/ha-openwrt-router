"""Tests for the client stability engine (B2/B4 wiring): client_engine.py.

The adapter is tested as pure functions on hand-made ``PollFacts``; the
engine runs on top of a real ``NetIntelligence`` with the in-memory store
fakes of ``test_net_engine`` (a "restart" is a new engine reading the fake
disk). MACs are locally administered test values.
"""

from __future__ import annotations

import copy
import json
import logging
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import voluptuous as vol
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import client_engine, net_engine
from custom_components.openwrt_router.client_engine import (
    ClientStability,
    async_get_client_engine,
    async_get_client_stability,
    async_unload_client_stability,
    default_settings,
    infra_roots,
    merge_settings,
    poll_input,
    settings_from_store,
)
from custom_components.openwrt_router.client_history import (
    DC_ERROR,
    DC_INFRA,
    DC_LEAVE,
    EV_ASSOC_FAIL,
    EV_AUTH_FAIL,
    EV_BAND_CHANGE,
    EV_CONNECT,
    EV_DHCP_FAIL,
    EV_DISCONNECT,
    EV_RECONNECT,
    EV_ROAM,
    STATE_ONLINE,
    TR_END,
)
from custom_components.openwrt_router.const import (
    CLIENT_SAVE_DELAY_SECONDS,
    CLIENT_STORE_KEY,
    SIGNAL_CLIENT_STABILITY,
)
from custom_components.openwrt_router.coordinator import LogBatch
from custom_components.openwrt_router.log_parser import (
    CATEGORY_WIFI,
    WIFI_CONNECTED,
    WIFI_DEAUTH,
    WIFI_DISCONNECTED,
    WIFI_PSK_MISMATCH,
    LogEvent,
)
from custom_components.openwrt_router.net_engine import (
    NetIntelligence,
    PollFacts,
    async_get_net_intelligence,
    async_unload_net_intelligence,
)
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    Incident,
    IncidentStatus,
    NetEvent,
    Origin,
    Scope,
    Source,
)
from custom_components.openwrt_router.net_rules import Finding, wifi_context

T0 = 1_800_000_000.0
MS0 = int(T0 * 1000)
M1 = "02:00:5E:10:00:01"
M2 = "02:00:5E:10:00:02"
M3 = "02:00:5E:10:00:03"
IFACES = [
    {"ifname": "phy1-ap0", "ssid": "Test", "band": "5g", "phy": "phy1"},
    {"ifname": "phy0-ap0", "ssid": "Test", "band": "2.4g", "phy": "phy0"},
]


# --- helpers -----------------------------------------------------------------------


def client(mac: str, **kw: Any) -> dict[str, Any]:
    return {"mac": mac, "radio": "phy1-ap0", "signal": -60, **kw}


def facts(
    *clients: dict[str, Any] | None,
    router: str = "r1",
    now: float = T0,
    lines: tuple[LogEvent, ...] = (),
    **kw: Any,
) -> PollFacts:
    listed = None if clients == (None,) else list(clients)
    context = wifi_context(IFACES, listed)
    return PollFacts(
        router=router,
        now=now,
        interval=60.0,
        fresh_clients=context.clients is not None,
        context=context,
        wifi_lines=lines,
        **kw,
    )


def line(kind: str, n: int, mac: str = M1, reason: str | None = None) -> LogEvent:
    return LogEvent(
        category=CATEGORY_WIFI,
        kind=kind,
        log_id=n,
        time_ms=MS0 - 30_000 + n * 1000,
        mac=mac,
        interface="phy1-ap0",
        reason=reason,
    )


def finding(kind: str, mac: str = M1, **kw: Any) -> Finding:
    return Finding(
        kind=kind,
        category=Category.WIFI,
        source=Source.LOG,
        scope=Scope.CLIENT,
        scope_key=mac,
        event=True,
        **kw,
    )


def stored(kind: str, event_id: str, mac: str = M1) -> NetEvent:
    return NetEvent(
        id=event_id,
        ts=T0 - 5,
        router="r1",
        category=Category.WIFI,
        kind=kind,
        origin=Origin.OBSERVED,
        source=Source.LOG,
        subject={"mac": mac},
    )


def incident(
    inc_id: str,
    kind: str,
    routers: list[str],
    *,
    status: IncidentStatus = IncidentStatus.ACTIVE,
    last_seen: float = T0,
    parent: str | None = None,
    resolved_at: float | None = None,
    scope_key: str | None = None,
) -> Incident:
    return Incident(
        id=inc_id,
        type=kind,
        scope=Scope.ROUTER,
        scope_key=scope_key or (routers[0] if routers else ""),
        status=status,
        routers=routers,
        last_seen=last_seen,
        parent_id=parent,
        resolved_at=resolved_at,
        cause="router_reboot",
        cause_status=CauseStatus.CONFIRMED,
    )


def kinds(poll) -> list[str]:
    return [ev.kind for ev in poll.events]


@pytest.fixture
def disk() -> Any:
    """One fake disk for both stores (NI and client history)."""
    disks: dict[str, FakeDisk] = {}

    def store(*args: Any, **kw: Any) -> FakeStore:
        key = args[2]
        disk = disks.setdefault(key, FakeDisk())
        disk.path = f"/nonexistent/.storage/{key}"
        return FakeStore(disk, *args, **kw)

    with (
        patch.object(net_engine, "Store", store),
        patch.object(client_engine, "Store", store),
    ):
        yield disks


def cs_disk(disks: dict[str, FakeDisk]) -> FakeDisk:
    return disks.setdefault(CLIENT_STORE_KEY, FakeDisk())


async def setup(hass: Any, *routers: str) -> tuple[NetIntelligence, ClientStability]:
    engine = await async_get_net_intelligence(hass)
    for router in routers:
        engine.register(router)
    cs = await async_get_client_stability(hass, engine)
    return engine, cs


def data(clients: list[dict[str, Any]] | None, events=(), **kw: Any) -> Any:
    ids = [e.log_id for e in events]
    batch = LogBatch(
        baseline=False,
        missed=0,
        first_time_ms=MS0,
        last_id=max(ids) if ids else None,
        last_time_ms=MS0,
    )
    return SimpleNamespace(
        new_log_events=tuple(events),
        new_log_batch=batch,
        ap_interfaces=IFACES,
        clients=clients,
        log_status="ok",
        **kw,
    )


# --- adapter -----------------------------------------------------------------------


def test_client_list_maps_rates_band_signal_and_ip() -> None:
    poll = poll_input(
        facts(
            client(M1, rx_rate=433300, tx_rate=866700, hostname="phone", ip="x"),
            client(M2, radio="phy0-ap0", signal=5, ip=None),
            client(M3, radio="unknown0", signal=-130),
            lease_macs=frozenset({M2}),
        ),
        interval=60.0,
        infra={},
    )
    by = {c.mac: c for c in poll.clients}
    assert by[M1].rate_rx_kbit == 4333 and by[M1].rate_tx_kbit == 8667
    assert by[M1].band == "5g" and by[M1].rssi == -60
    assert by[M1].hostname == "phone" and by[M1].ip_visible
    assert by[M2].band == "2.4g" and by[M2].rssi is None  # positive = no dBm
    assert by[M2].ip_visible  # from the fleet leases
    assert by[M3].band is None and by[M3].rssi is None and not by[M3].ip_visible
    assert poll.fresh and poll.router == "r1" and poll.interval == 60.0


def test_no_client_list_is_not_fresh() -> None:
    poll = poll_input(facts(None), interval=60.0, infra={})
    assert not poll.fresh and poll.clients == ()


def test_log_lines_become_connects_and_disconnects_with_reasons() -> None:
    lines = (
        line(WIFI_DEAUTH, 1, reason="inactivity"),
        line(WIFI_DISCONNECTED, 2),  # pairs with the deauth line 1 s before
        line(WIFI_CONNECTED, 3),
        line(WIFI_DISCONNECTED, 20, M2),  # no partner: no reason
        line(WIFI_PSK_MISMATCH, 21),  # an auth line is not a disconnect
    )
    poll = poll_input(facts(lines=lines), interval=60.0, infra={})
    assert kinds(poll) == [EV_DISCONNECT, EV_DISCONNECT, EV_CONNECT, EV_DISCONNECT]
    reasons = [ev.reason for ev in poll.events]
    assert reasons == ["inactivity", "inactivity", None, None]
    assert poll.events[0].ts == (MS0 - 29_000) / 1000  # router time kept
    assert not any(ev.infra for ev in poll.events)


def test_implausible_line_time_falls_back_to_the_poll_time() -> None:
    old = LogEvent(CATEGORY_WIFI, WIFI_DISCONNECTED, 1, MS0 - 86_400_000, mac=M1)
    ahead = LogEvent(CATEGORY_WIFI, WIFI_CONNECTED, 2, MS0 + 3_600_000, mac=M1)
    none = LogEvent(CATEGORY_WIFI, WIFI_CONNECTED, 3, 0, mac=M1)
    poll = poll_input(facts(lines=(old, ahead, none)), interval=60.0, infra={})
    assert [ev.ts for ev in poll.events] == [T0, T0, T0]


def test_disconnect_at_a_router_with_an_open_root_is_infrastructure() -> None:
    lines = (line(WIFI_DISCONNECTED, 1, reason="timeout"),)
    poll = poll_input(facts(lines=lines), interval=60.0, infra={"r1": "inc-7"})
    [ev] = poll.events
    assert ev.infra and ev.incident_id == "inc-7"
    assert poll.infra == {"r1": "inc-7"}


def test_findings_and_stored_events_map_to_history_events() -> None:
    poll = poll_input(
        facts(
            findings=(
                finding("wifi.reconnect", count=3),
                finding("wifi.roam", params={"from_router": "r2", "to_router": "r1"}),
                finding("wifi.band_change", M2),
                finding("wifi.dhcp_after_connect", M2),
                finding("wifi.no_ip", M3),
                finding("wifi.roam", params={}),  # no target: skipped
            ),
            stored_events=(
                stored("wifi.psk_mismatch", "r1:1"),
                stored("wifi.psk_mismatch", "r1:2"),  # same attempt: not again
                stored("wifi.backhaul_auth_failed", "r1:3"),
                stored("wifi.assoc_rejected", "r1:4", M2),
            ),
            auth_attempts=frozenset({"r1:1", "r1:3"}),
        ),
        interval=60.0,
        infra={},
    )
    got = [(ev.kind, ev.mac, ev.router, ev.peer, ev.count) for ev in poll.events]
    assert got == [
        (EV_RECONNECT, M1, "r1", None, 3),
        (EV_ROAM, M1, "r1", "r2", 1),
        (EV_BAND_CHANGE, M2, "r1", None, 1),
        (EV_DHCP_FAIL, M2, "r1", None, 1),
        (EV_DHCP_FAIL, M3, "r1", None, 1),
        (EV_AUTH_FAIL, M1, "r1", None, 1),
        (EV_ASSOC_FAIL, M2, "r1", None, 1),
    ]


def test_excluded_macs_are_left_out() -> None:
    poll = poll_input(
        facts(
            client(M1),
            client(M2),
            lines=(line(WIFI_CONNECTED, 1, M2),),
            findings=(finding("wifi.reconnect", M2.lower()),),
            exclude=frozenset({M2}),
        ),
        interval=60.0,
        infra={},
    )
    assert [c.mac for c in poll.clients] == [M1]
    assert poll.events == ()


# --- infrastructure roots -----------------------------------------------------------


def test_infra_roots_open_roots_children_and_windows() -> None:
    roots = infra_roots(
        [
            incident("a", "router_unreachable", ["r1"]),
            # a child on r2 linked to the root: r2 is covered too
            incident("c", "wifi_mass_disconnect", ["r2"], parent="a"),
            # a WAN outage keeps Wi-Fi clients associated: no root
            incident("w", "wan_down", ["r3"]),
            # a reboot root long ago (still open): not any more
            incident("b", "system_reboot", ["r4"], last_seen=T0 - 900),
            # resolved two minutes ago: still counts, behind the port only
            incident(
                "d",
                "lan_port_flap",
                ["r5"],
                status=IncidentStatus.RESOLVED,
                resolved_at=T0 - 120,
                scope_key="r5:port:lan2",
            ),
            incident("d1", "wifi_reconnect_storm", ["r7"], parent="d"),
            # resolved ten minutes ago: not
            incident(
                "e",
                "lan_uplink_down",
                ["r6"],
                status=IncidentStatus.RESOLVED,
                resolved_at=T0 - 600,
                scope_key="r6:port:lan1",
            ),
            incident("e1", "wifi_reconnect_storm", ["r8"], parent="e"),
            # the lower tier wins on a router with two roots
            incident("f", "wifi_mass_disconnect", ["r1"]),
        ],
        T0,
    )
    assert roots == {"r1": "a", "r2": "a", "r7": "d"}


def test_wan_port_flap_on_the_gateway_is_not_infrastructure() -> None:
    # like wan_down: the gateway's Wi-Fi clients stay associated
    flap = incident("g", "lan_port_flap", ["gw"], scope_key="gw:port:wan")
    assert infra_roots([flap], T0) == {}


def test_port_roots_count_only_the_routers_behind_the_port() -> None:
    roots = infra_roots(
        [
            # P's port towards B is down (a level root, open for hours)
            incident("u", "lan_uplink_down", ["p"], scope_key="p:port:lan1"),
            incident("u1", "wifi_reconnect_storm", ["b"], parent="u"),
            # an AP's own uplink port flaps: NI links its drops as children
            incident("f", "lan_port_flap", ["q"], scope_key="q:port:lan"),
            incident("f1", "wifi_mass_disconnect", ["q"], parent="f"),
        ],
        T0,
    )
    assert roots == {"b": "u", "q": "f"}


def test_a_router_failing_on_credentials_is_never_infrastructure() -> None:
    roots = infra_roots(
        [incident("a", "router_unreachable", ["r1", "r2"])], T0, skip={"r1"}
    )
    assert roots == {"r2": "a"}


# --- settings -----------------------------------------------------------------------


def test_settings_validation() -> None:
    base = default_settings()
    merged = merge_settings(
        base,
        {
            "entity_macs": [M1.lower(), M1, M2.replace(":", "-")],
            "weights": {"signal": 40},
            "retention_days": 60,
        },
    )
    assert merged["entity_macs"] == [M1, M2]
    assert merged["weights"]["signal"] == 40.0
    assert merged["weights"]["disconnects"] == base["weights"]["disconnects"]
    for bad in (
        {"retention_days": 0},
        {"retention_days": True},
        {"entity_macs": [f"02:00:5E:10:01:{i:02X}" for i in range(26)]},
        {"entity_macs": ["nope"]},
        {"classes": [90, 95, 50, 25]},
        {"classes": [90, 75, 50]},
        {"max_store_mb": 9},
        {"weights": {"bogus": 1}},
        {"weights": dict.fromkeys(base["weights"], 0)},
        {"unknown": 1},
    ):
        with pytest.raises(vol.Invalid):
            merge_settings(base, bad)


def test_damaged_stored_settings_keep_defaults_per_field() -> None:
    got = settings_from_store(
        {"retention_days": "x", "enabled": False, "entity_macs": [M1]}
    )
    assert got["retention_days"] == default_settings()["retention_days"]
    assert got["enabled"] is False and got["entity_macs"] == [M1]
    assert settings_from_store("junk") == default_settings()


# --- engine: hook, store, life cycle --------------------------------------------------


@pytest.mark.asyncio
async def test_polls_through_the_engine_fill_the_history(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    assert async_get_client_engine(hass) is cs
    for k in range(5):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    live = cs.history.live(M1)
    assert live is not None and live.state == STATE_ONLINE and live.ap == "r1"
    assert cs.dirty


@pytest.mark.asyncio
async def test_observer_failure_does_not_reach_the_engine(
    disk, caplog: pytest.LogCaptureFixture
) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    with (
        patch.object(cs.history, "ingest", side_effect=RuntimeError("bug")),
        caplog.at_level(logging.WARNING, logger=net_engine.__name__),
    ):
        stored = engine.ingest(
            "r1",
            data([client(M1)], (line(WIFI_PSK_MISMATCH, 1),)),
            T0,
            interval=60.0,
        )
    assert stored == 1
    assert "poll observer failed" in caplog.text
    assert M1 not in caplog.text and M1.lower() not in caplog.text


@pytest.mark.asyncio
async def test_store_round_trip_and_unload_flush(disk) -> None:
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    for k in range(3):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    # one delayed write per window, with the planned delay
    delayed = cs_disk(disk).delayed
    assert len(delayed) == 1 and delayed[0][1] == CLIENT_SAVE_DELAY_SECONDS
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)
    assert async_get_client_engine(hass) is None
    saved = cs_disk(disk).saves
    assert len(saved) == 1
    assert M1 in saved[0]["history"]["clients"]

    hass2 = make_hass()
    _engine2, cs2 = await setup(hass2, "r1")
    assert not cs2.load_failed
    assert cs2.history.live(M1) is not None


@pytest.mark.asyncio
async def test_nothing_is_written_without_a_change(disk) -> None:
    hass = make_hass()
    await setup(hass, "r1")
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)
    assert cs_disk(disk).saves == [] and cs_disk(disk).delayed == []


@pytest.mark.asyncio
async def test_unload_waits_while_other_routers_remain(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1", "r2")
    engine.ingest("r1", data([client(M1)]), T0, interval=60.0)
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)
    assert async_get_client_engine(hass) is cs
    assert cs_disk(disk).saves == []


@pytest.mark.asyncio
async def test_unreadable_store_is_kept_as_backup(disk, store_dir) -> None:
    broken = cs_disk(disk)
    broken.load_error = json.JSONDecodeError("broken", "{", 0)
    path = store_dir / "openwrt_router.client_history"
    path.write_text("{", encoding="utf-8")
    broken.path = str(path)
    hass = make_hass()
    with patch.object(client_engine, "Store", lambda *a, **kw: FakeStore(broken, *a)):
        engine = await async_get_net_intelligence(hass)
        engine.register("r1")
        cs = await async_get_client_stability(hass, engine)
    assert cs.loaded and cs.load_failed
    assert (store_dir / "openwrt_router.client_history.bak").read_text() == "{"
    assert cs.diagnostics()["store_load_failed"] is True


@pytest.fixture
def store_dir() -> Any:
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


@pytest.mark.asyncio
async def test_disabled_stops_ingest_and_keeps_the_data(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest("r1", data([client(M1)]), T0, interval=60.0)
    cs.update_settings({"enabled": False})
    before = cs.history.to_dict()
    engine.ingest("r1", data([client(M1), client(M2)]), T0 + 60, interval=60.0)
    assert cs.history.to_dict() == before
    assert M1 in cs.history


@pytest.mark.asyncio
async def test_excluded_mac_is_forgotten(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest("r1", data([client(M1), client(M2)]), T0, interval=60.0)
    assert M2 in cs.history
    engine.settings["exclusions"] = {"macs": [M2.lower()]}
    engine.ingest("r1", data([client(M1), client(M2)]), T0 + 60, interval=60.0)
    assert M2 not in cs.history and M1 in cs.history


@pytest.mark.asyncio
async def test_disconnect_during_a_root_is_tagged_infra(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    for k in range(3):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    root = incident("root-1", "system_reboot", ["r1"], last_seen=T0 + 170)
    with patch.object(engine.machine, "peek", return_value=[root]):
        down = LogEvent(
            CATEGORY_WIFI,
            WIFI_DISCONNECTED,
            9,
            int((T0 + 175) * 1000),
            mac=M1,
            interface="phy1-ap0",
            reason="timeout",
        )
        for k in range(3, 9):
            events = (down,) if k == 3 else ()
            engine.ingest("r1", data([], events), T0 + k * 60, interval=60.0)
    ends = [t for t in cs.history.transitions(M1) if t.kind == TR_END]
    assert ends and ends[-1].cls == DC_INFRA
    assert ends[-1].incident_id == "root-1"


@pytest.mark.asyncio
async def test_auth_failure_of_the_router_is_not_infrastructure(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    for k in range(3):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    root = incident("root-1", "router_unreachable", ["r1"])
    down = LogEvent(
        CATEGORY_WIFI,
        WIFI_DISCONNECTED,
        9,
        int((T0 + 175) * 1000),
        mac=M1,
        interface="phy1-ap0",
        reason="timeout",
    )
    with (
        patch.object(engine.machine, "peek", return_value=[root]),
        patch.object(engine, "_auth_failed", return_value=frozenset({"r1"})),
    ):
        for k in range(3, 9):
            events = (down,) if k == 3 else ()
            engine.ingest("r1", data([], events), T0 + k * 60, interval=60.0)
    ends = [t for t in cs.history.transitions(M1) if t.kind == TR_END]
    assert ends and ends[-1].cls == DC_ERROR and ends[-1].incident_id is None


@pytest.mark.asyncio
async def test_leaving_client_on_the_port_owner_is_not_infrastructure(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "p", "b")
    for k in range(3):
        engine.ingest("p", data([client(M1)]), T0 + k * 60, interval=60.0)
    # P's port towards B is down; only B's drops are linked to it
    roots = [
        incident("u", "lan_uplink_down", ["p"], scope_key="p:port:lan1"),
        incident("u1", "wifi_reconnect_storm", ["b"], parent="u"),
    ]
    leave = LogEvent(
        CATEGORY_WIFI,
        WIFI_DISCONNECTED,
        9,
        int((T0 + 175) * 1000),
        mac=M1,
        interface="phy1-ap0",
        reason="local_request",
    )
    with patch.object(engine.machine, "peek", return_value=roots):
        assert cs.infra_routers(T0 + 180) == frozenset({"b"})
        for k in range(3, 9):
            events = (leave,) if k == 3 else ()
            engine.ingest("p", data([], events), T0 + k * 60, interval=60.0)
    ends = [t for t in cs.history.transitions(M1) if t.kind == TR_END]
    assert ends and ends[-1].cls == DC_LEAVE and ends[-1].incident_id is None


@pytest.mark.asyncio
async def test_clock_jump_back_moves_the_history(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest("r1", data([client(M1)]), T0, interval=60.0)
    first = cs.history.live(M1).first_seen
    engine.ingest("r1", data([client(M1)]), T0 - 86_400, interval=60.0)
    assert cs.history.live(M1).first_seen == first - 86_400


@pytest.mark.asyncio
async def test_removed_router_list_is_dropped(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1", "r2")
    engine.ingest("r2", data([client(M1)]), T0, interval=60.0)
    assert "r2" in cs.history.to_dict()["lists"]
    engine.remove_router("r2")
    assert "r2" not in cs.history.to_dict()["lists"]


@pytest.mark.asyncio
async def test_slow_polls_use_the_observed_interval(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    seen: list[float] = []
    real = cs.history.ingest
    with patch.object(
        cs.history, "ingest", side_effect=lambda p: (seen.append(p.interval), real(p))
    ):
        for t in (0, 60, 150, 600):
            engine.ingest("r1", data([client(M1)]), T0 + t, interval=60.0)
    assert seen == [60.0, 60.0, 90.0, 120.0]


@pytest.mark.asyncio
async def test_entity_view_is_throttled_and_dispatched(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    cs.update_settings({"entity_macs": [M1]})
    with patch.object(client_engine, "async_dispatcher_send") as send:
        for k in range(4):
            engine.ingest("r1", data([client(M1)]), T0 + k * 20, interval=20.0)
    # 0 s and 60 s publish, 20 s and 40 s do not
    assert send.call_count == 2
    assert send.call_args[0][1] == SIGNAL_CLIENT_STABILITY
    state = cs.entity_states[M1]
    assert state.connected and state.name == M1
    assert state.session_start is not None and state.last_disconnect is None


@pytest.mark.asyncio
async def test_disabling_clears_the_entity_view(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    cs.update_settings({"entity_macs": [M1]})
    engine.ingest("r1", data([client(M1)]), T0, interval=60.0)
    assert M1 in cs.entity_states
    with patch.object(client_engine, "async_dispatcher_send") as send:
        cs.update_settings({"enabled": False})
    assert cs.entity_states == {}  # the sensors go unavailable
    assert send.call_count == 1
    cs.update_settings({"enabled": True})
    assert M1 in cs.entity_states


@pytest.mark.asyncio
async def test_diagnostics_hold_counts_only(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest(
        "r1", data([client(M1, hostname="phone", ip="192.0.2.7")]), T0, interval=60.0
    )
    diag = cs.diagnostics()
    text = json.dumps(diag)
    assert diag["clients"] == 1 and diag["clients_by_state"] == {"online": 1}
    for secret in (M1, M1.lower(), "phone", "192.0.2.7"):
        assert secret not in text


@pytest.mark.asyncio
async def test_store_size_cap_trims_in_the_planned_order(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    macs = [f"00:11:22:33:{i // 256:02X}:{i % 256:02X}" for i in range(40)]
    for k in range(0, 72 * 60, 10):
        engine.ingest(
            "r1", data([client(m) for m in macs]), T0 + k * 60, interval=600.0
        )
    full = cs._data_to_save()
    size = cs.last_save_bytes
    assert size is not None and size > 20_000
    hours = sum(len(c.get("h", [])) for c in full["history"]["clients"].values())
    # 1. a little too large: old closed hours go, every client stays
    with patch.object(client_engine, "_MB", int(size * 0.85) // 3):
        trimmed = cs._data_to_save()
    assert cs.last_save_bytes <= size * 0.85
    assert len(trimmed["history"]["clients"]) == len(macs)
    left = sum(len(c.get("h", [])) for c in trimmed["history"]["clients"].values())
    assert left < hours
    # 2. far too large: whole clients go, least recently active first
    with patch.object(client_engine, "_MB", int(size * 0.2) // 3):
        cs._data_to_save()
    assert cs.last_save_bytes <= size * 0.2
    assert 0 < len(cs.history) < len(macs)
    assert cs.trimmed > 0


# --- no added router calls ----------------------------------------------------------


@pytest.mark.asyncio
async def test_client_stability_adds_no_router_calls() -> None:
    import time as time_module

    import test_poll_no_ssh as model

    from custom_components.openwrt_router.api import OpenWrtAPI

    clients = {
        "freq": 5180,
        "clients": {
            M1.lower(): {
                "auth": True,
                "assoc": True,
                "authorized": True,
                "rate": {"rx": 433300, "tx": 866700},
                "signal": -60,
            }
        },
    }

    async def run(with_cs: bool) -> tuple[int, ClientStability | None]:
        session = model._ubus_session()
        api = OpenWrtAPI(
            host="192.0.2.1",
            port=80,
            username="root",
            password="pw",
            session=session,
            protocol="http",
        )
        api._lldp_checked = True
        api._lldp_available = False
        api._lldp_last_fetch = time_module.monotonic()
        coordinator = model._make_coordinator(api)
        hass = make_hass()
        with (
            patch.object(
                net_engine, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
            ),
            patch.object(
                client_engine,
                "Store",
                lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw),
            ),
        ):
            engine = await async_get_net_intelligence(hass)
            engine.register("r1")
            cs = await async_get_client_stability(hass, engine) if with_cs else None
        model._MODE["empty_tables"] = False
        with (
            patch.dict(model.RESPONSES, {("hostapd.phy1-ap0", "get_clients"): clients}),
            patch(
                "custom_components.openwrt_router.api.asyncssh.connect",
                AsyncMock(side_effect=AssertionError("SSH must not be used")),
            ),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for _n in range(3):
                coordinator.data = await coordinator._async_update_data()
                engine.async_ingest_coordinator("r1", coordinator)
        return session.post.call_count, cs

    calls_without, _ = await run(False)
    calls_with, cs = await run(True)
    assert calls_with == calls_without > 0
    assert cs is not None and M1 in cs.history


# --- 1.43: store format, SSID, trailing hour, week cache --------------------------

# A client history exactly as 1.42.0 wrote it (generated with the 1.42.0
# client_history.py: three polls, one auth failure, no "lf" field).
HISTORY_142: dict[str, Any] = {
    "v": 1,
    "mark": 500000,
    "lists": {"r1": [1800000120.0, 60.0, 0, [M1]]},
    "clients": {
        M1: {
            "m": {
                "p": 1,
                "fs": 1800000000.0,
                "ls": 1800000120.0,
                "la": 1800000120.0,
                "hn": "phone",
                "ht": 1800000000.0,
                "ip": "192.0.2.10",
                "it": 1800000000.0,
            },
            "l": {
                "s": "online",
                "si": 1800000000.0,
                "ap": "r1",
                "b": "5g",
                "r": -55,
                "acc": 1800000120.0,
                "ss": 1800000000.0,
                "sk": 0,
                "gp": 0,
                "gt": 1,
            },
            "aps": ["r1"],
            "ho": [
                "500000:0:120,120,,1,,,,,,,,,,,,,1,,,3,-165,-55,-55,,3,3000,1500,3,,120"
            ],
            "tr": ["1800000000.0|start|0||||1"],
        }
    },
}


@pytest.mark.asyncio
async def test_a_1_42_store_loads_without_loss(disk) -> None:
    cs_disk(disk).data = {
        "settings": {**default_settings(), "retention_days": 14},
        "history": copy.deepcopy(HISTORY_142),
        "saved_at": T0 + 120,
    }
    hass = make_hass()
    _engine, cs = await setup(hass, "r1")
    assert not cs.load_failed
    assert cs.settings["retention_days"] == 14
    assert cs.history.to_dict() == HISTORY_142
    assert cs.history.live(M1).last_failure is None  # 1.42 did not keep it
    assert cs.ssid(M1) is None
    payload = cs._data_to_save()
    assert payload["history"] == HISTORY_142
    assert payload["ssids"] == {}


@pytest.mark.asyncio
async def test_last_ssid_survives_a_restart(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest("r1", data([client(M1)]), T0, interval=60.0)
    assert cs.ssid(M1) == "Test"
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)
    assert cs_disk(disk).saves[-1]["ssids"] == {M1: "Test"}
    _engine2, cs2 = await setup(make_hass(), "r1")
    assert cs2.ssid(M1) == "Test"


@pytest.mark.asyncio
async def test_stored_ssids_are_validated_and_bounded_by_the_history(disk) -> None:
    cs_disk(disk).data = {
        "settings": default_settings(),
        "history": copy.deepcopy(HISTORY_142),
        "ssids": {M1.lower(): "Home", "bad": "x", M2: "Guest", M3: 5},
    }
    _engine, cs = await setup(make_hass(), "r1")
    assert cs.ssid(M1) == "Home"
    assert cs.ssid(M2) is None  # not in the history
    for bad in ([], "x", {M1: "y" * 40}):
        cs_disk(disk).data = {"history": copy.deepcopy(HISTORY_142), "ssids": bad}
        hass = make_hass()
        _engine, cs = await setup(hass, "r1")
        assert cs.ssid(M1) is None and not cs.load_failed
        await async_unload_client_stability(hass)


@pytest.mark.asyncio
async def test_forgotten_clients_leave_no_ssid_in_the_store(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    engine.ingest("r1", data([client(M1), client(M2)]), T0, interval=60.0)
    cs.history.forget(M2)
    assert cs._data_to_save()["ssids"] == {M1: "Test"}


@pytest.mark.asyncio
async def test_trailing_hour_marks_the_memory_start_after_a_restart(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    for k in range(90):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    now = T0 + 89 * 60
    stats, result = cs.window_trailing_hour(M1, now)
    assert stats.start == now - 3600 and stats.memory_from is None
    assert stats.bucket.rssi_n == 61
    assert stats.coverage == 1.0 and result.score is not None
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)

    later = now + 60
    with patch.object(client_engine, "_wall_clock", return_value=later - 20):
        engine2, cs2 = await setup(make_hass(), "r1")
    engine2.ingest("r1", data([client(M1)]), later, interval=60.0)
    stats2, _result = cs2.window_trailing_hour(M1, later)
    assert stats2.memory_from == later - 20  # samples only since the load
    assert stats2.bucket.rssi_n == 1
    assert stats2.bucket.online_s == pytest.approx(3600, abs=1)
    assert cs2.window_trailing_hour("02:00:5E:10:00:99", later) is None


@pytest.mark.asyncio
async def test_week_values_are_cached_per_hour(disk) -> None:
    hass = make_hass()
    engine, cs = await setup(hass, "r1")
    for k in range(3):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    now = T0 + 120
    first = cs.week_values(M1, now)
    assert first.availability_7d == 1.0
    with patch.object(cs, "window", side_effect=AssertionError("not cached")):
        assert cs.week_values(M1, now + 60) is first
    assert cs.week_values(M1, now + 3600) is not first  # next hour
    again = cs.week_values(M1, now)
    cs.update_settings({"classes": [95, 80, 60, 30]})
    assert cs.week_values(M1, now) is not again  # settings change the score
    assert cs.week_values("02:00:5E:10:00:99", now) is None


@pytest.mark.asyncio
async def test_memory_start_is_set_when_the_store_loads(disk) -> None:
    """Before the first poll after a restart the 1 h view already names the
    restart (HA downtime is not shown as fully measured)."""
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    for k in range(90):
        engine.ingest("r1", data([client(M1)]), T0 + k * 60, interval=60.0)
    now = T0 + 89 * 60
    await async_unload_net_intelligence(hass, "r1")
    await async_unload_client_stability(hass)

    loaded = now + 600  # HA was down for 10 minutes
    with patch.object(client_engine, "_wall_clock", return_value=loaded):
        _engine2, cs2 = await setup(make_hass(), "r1")
    stats, _result = cs2.window_trailing_hour(M1, loaded + 30)  # no poll yet
    assert stats.memory_from == loaded
    assert stats.bucket.rssi_n == 0
