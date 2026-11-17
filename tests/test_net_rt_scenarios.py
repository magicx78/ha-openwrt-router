"""Scenario suite of the realtime root-cause package (RT7, RT10).

Path D: events come from the router log, read on every poll, and from the
poll itself. Scenarios of plan table 2.7 not already covered elsewhere:
5 (one unstable client among quiet ones: peer comparison), 6 (uplink port
flapping plus client drops as one incident), 7 (shared DNS failure without
a DNS probe). Router names are roles, MACs locally administered test values.
"""

from __future__ import annotations

from typing import Any

import pytest
from test_net_correlation import (
    CLIENTS20,
    T0,
    A,
    B,
    G,
    event,
    hit,
    inc_of,
    inferred_tree,
    level,
    observed_tree,
    roots,
    storm,
)
from test_net_infra import entry, log_poll, make_engine
from test_net_wifi import (
    MAC1,
    MAC2,
    MAC3,
    MAC4,
    Log,
    client,
    conn,
    data,
    disc,
    engine,  # noqa: F401  (fixture)
    events_of,
    open_incidents,
)

from custom_components.openwrt_router.log_parser import LogCursor
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    Incident,
    Scope,
)
from custom_components.openwrt_router.net_rules import (
    AlarmMachine,
    CauseLevel,
    events_by_id,
    incident_cause_level,
    port_key,
)


def level_of(intel: NetIntelligence, inc: Incident) -> CauseLevel:
    return incident_cause_level(inc, events_by_id(intel.ring))


def unstable(intel: NetIntelligence, others: list[dict[str, Any]], rounds: int = 8):
    """``MAC1`` drops and comes back every 70 s; ``others`` stay connected."""
    log = Log()
    me = client(MAC1, signal=-62)
    for n in range(rounds):
        base = n * 70
        lines = log.lines((base + 10, disc(MAC1)), (base + 15, conn(MAC1)))
        intel.ingest("r1", data(lines, [me, *others]), T0 + base + 60)


# --- scenario 5: one unstable ESP32, peer comparison --------------------------------


@pytest.mark.asyncio
async def test_scenario_5_one_unstable_client_among_quiet_peers(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """Three other clients on the same radio stay connected: the problem is
    on the client side (its radio path or the device), not the AP."""
    unstable(engine, [client(m) for m in (MAC2, MAC3, MAC4)])
    [inc] = open_incidents(engine, "wifi_reconnect_storm")
    assert inc.scope_key == MAC1
    assert (inc.cause, inc.cause_status) == ("client_side", CauseStatus.HYPOTHESIS)
    last = events_of(engine, "wifi.reconnect")[-1]
    assert last.params["peers_ok"] == 3
    causes = [c["cause"] for c in last.params["causes"]]
    assert causes[0] == "client_side"
    assert "power_supply" not in causes  # an AP power problem hits all clients
    # log lines and the peer comparison: two independent indicators
    assert level_of(engine, inc) is CauseLevel.LIKELY
    assert open_incidents(engine, "wifi_mass_disconnect") == []


@pytest.mark.asyncio
async def test_scenario_5_too_few_peers_stays_open(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """Two quiet peers are no comparison: the causes stay open."""
    unstable(engine, [client(m) for m in (MAC2, MAC3)])
    [inc] = open_incidents(engine, "wifi_reconnect_storm")
    assert inc.cause == "weak_signal" and inc.cause_status is CauseStatus.HYPOTHESIS
    assert events_of(engine, "wifi.reconnect")[-1].params["peers_ok"] == 2
    assert level_of(engine, inc) is CauseLevel.POSSIBLE


@pytest.mark.asyncio
async def test_scenario_5_peers_on_another_radio_do_not_count(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    others = [client(m, iface="phy0-ap0") for m in (MAC2, MAC3, MAC4)]
    unstable(engine, others)
    assert events_of(engine, "wifi.reconnect")[-1].params["peers_ok"] == 0


@pytest.mark.asyncio
async def test_scenario_5_peers_with_drops_of_their_own_do_not_count(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """A peer that drops in the same read is no quiet peer."""
    log = Log()
    everyone = [client(m) for m in (MAC1, MAC2, MAC3, MAC4)]
    lines = log.lines(
        (10, disc(MAC1)),
        (11, disc(MAC2)),
        (15, conn(MAC1)),
        (16, conn(MAC2)),
    )
    engine.ingest("r1", data(lines, everyone), T0 + 60)
    by_mac = {e.subject["mac"]: e for e in events_of(engine, "wifi.reconnect")}
    assert by_mac[MAC1].params["peers_ok"] == 2
    assert by_mac[MAC2].params["peers_ok"] == 2


@pytest.mark.asyncio
async def test_scenario_5_no_client_list_means_no_comparison(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    log = Log()
    lines = log.lines((10, disc(MAC1)), (15, conn(MAC1)))
    poll = data(lines)
    poll.clients = None  # the client list could not be read
    engine.ingest("r1", poll, T0 + 60)
    [last] = events_of(engine, "wifi.reconnect")
    assert "peers_ok" not in last.params


# --- scenario 6: uplink port flapping plus client drops -----------------------------


def flap(key: str, router: str) -> Any:
    """Evidence that opens a port flap incident (3 link drops at once)."""
    return hit("lan_port_flap", key, router, scope=Scope.PORT, count=3)


def test_scenario_6_gateway_port_flap_explains_the_ap_behind_it() -> None:
    """The gateway port facing ap1 flaps; ap1 loses all clients, clients of
    ap1 and of ap2 behind it reconnect: one root, everything below it."""
    m = AlarmMachine()
    key = port_key(G, "lan3")
    m.update(T0, [flap(key, G)])
    m.update(
        T0 + 20,
        [
            hit("wifi_mass_disconnect", A, A, count=8),
            storm(CLIENTS20[0], A),
            storm(CLIENTS20[1], B),
        ],
    )
    m.correlate(T0 + 20, observed_tree())
    root = inc_of(m, "lan_port_flap", key)
    assert [r.id for r in roots(m)] == [root.id]
    mass = inc_of(m, "wifi_mass_disconnect", A)
    assert mass.parent_id == root.id
    assert (mass.cause, mass.cause_status) == ("port_flap", CauseStatus.CONFIRMED)
    for mac in CLIENTS20[:2]:
        child = inc_of(m, "wifi_reconnect_storm", mac)
        assert child.parent_id == root.id
        assert child.cause == "port_flap"


def test_scenario_6_flap_of_the_aps_own_uplink_port() -> None:
    """ap1's own port towards the gateway flaps (seen on ap1)."""
    m = AlarmMachine()
    key = port_key(A, "lan1")
    m.update(T0, [flap(key, A)])
    m.update(T0 + 20, [storm(CLIENTS20[0], A), storm(CLIENTS20[1], G)])
    m.correlate(T0 + 20, observed_tree())
    root = inc_of(m, "lan_port_flap", key)
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id == root.id
    # the gateway's own clients are not behind ap1
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[1]).parent_id is None


def test_scenario_6_inferred_edge_is_a_hypothesis() -> None:
    m = AlarmMachine()
    key = port_key(G, "lan3")
    m.update(T0, [flap(key, G)])
    m.update(T0 + 20, [storm(CLIENTS20[0], A)])
    m.correlate(T0 + 20, inferred_tree())
    child = inc_of(m, "wifi_reconnect_storm", CLIENTS20[0])
    assert child.parent_id == inc_of(m, "lan_port_flap", key).id
    assert child.cause_status is CauseStatus.HYPOTHESIS
    assert child.confidence <= 0.6


def test_scenario_6_unrelated_port_and_late_drops_are_no_children() -> None:
    m = AlarmMachine()
    m.update(T0, [flap(port_key(G, "lan9"), G)])
    m.update(T0 + 20, [storm(CLIENTS20[0], A)])
    m.correlate(T0 + 20, observed_tree())
    assert inc_of(m, "wifi_reconnect_storm", CLIENTS20[0]).parent_id is None
    m2 = AlarmMachine()
    m2.update(T0, [flap(port_key(G, "lan3"), G)])
    m2.update(T0 + 200, [storm(CLIENTS20[0], A)])  # after the +60 s window
    m2.correlate(T0 + 200, observed_tree())
    assert inc_of(m2, "wifi_reconnect_storm", CLIENTS20[0]).parent_id is None


def test_scenario_6_wifi_events_behind_the_port_follow_it() -> None:
    m = AlarmMachine()
    key = port_key(G, "lan3")
    m.update(T0, [flap(key, G)])
    events = [
        event("ap1:1", T0 + 10, A, "wifi.disassoc", Category.WIFI, {"mac": "x"}),
        event("gw:2", T0 + 10, G, "wifi.disassoc", Category.WIFI, {"mac": "y"}),
    ]
    result = m.correlate(T0 + 20, observed_tree(), events)
    assert result.events == {"ap1:1": inc_of(m, "lan_port_flap", key).id}


def test_scenario_6_uplink_down_still_explains_a_port_flap_behind_it() -> None:
    """The port flap root sits below an uplink outage (tier order)."""
    m = AlarmMachine()
    up_key = port_key(G, "lan3")
    m.update(T0, [level("lan_uplink_down", up_key, router=G, scope=Scope.PORT)])
    m.update(T0 + 10, [flap(port_key(A, "lan2"), A)])
    m.correlate(T0 + 10, observed_tree())
    flap_inc = inc_of(m, "lan_port_flap", port_key(A, "lan2"))
    assert flap_inc.parent_id == inc_of(m, "lan_uplink_down", up_key).id


# --- scenario 7: shared DNS failure (no DNS probe, F4 open) -------------------------


@pytest.mark.asyncio
async def test_scenario_7_shared_dns_failure_is_one_event_not_per_client() -> None:
    """Without a DNS probe (F4) the NI sees DNS only in dnsmasq lines: one
    aggregated event with a hypothesis, no incident per client."""
    intel = await make_engine("r1")
    cursor = LogCursor()
    intel.ingest("r1", log_poll([entry(1, "crond[1]: x")], cursor, uptime=50), T0)
    lines = [entry(1, "crond[1]: x")] + [
        entry(i, "dnsmasq[2345]: no servers found in /tmp/resolv.conf.d/x, will retry")
        for i in range(2, 8)
    ]
    intel.ingest("r1", log_poll(lines, cursor, uptime=110), T0 + 60)
    [dns] = [e for e in intel.ring if e.category is Category.DNS]
    assert dns.count == 6
    assert (dns.cause, dns.cause_status) == ("dns_resolution", CauseStatus.HYPOTHESIS)
    assert not [i for i in intel.machine.incidents() if i.scope is Scope.CLIENT]
