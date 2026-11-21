"""Network intelligence incident types of the diagnostics (1.47.0, part 2).

``wan_gateway_changed`` and ``dns_server_changed``: fed by the network
diagnostics run time from its change findings (``ni_change_findings``),
linked by the marked block at the end of ``net_rules.py``. Pure machine
tests in both directions (where a link must exist and where it must not)
plus the engine path from a poll to the incident. Router names are roles,
addresses documentation values. No network, no Home Assistant.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

from test_client_engine import data as ni_data
from test_client_engine import setup as ni_setup
from test_diag_runtime import (
    RID1,
    T0,
    disk,  # noqa: F401 - fixture
    make_diag,
    ni_disks,  # noqa: F401 - fixture
    wan_status,
)
from test_net_correlation import CLIENTS20 as CLIENTS
from test_net_correlation import (
    A,
    G,
    event,
    hit,
    inc_of,
    level,
    observed_tree,
    roots,
    storm,
)
from test_net_engine import make_hass

from custom_components.openwrt_router.diag_core import EVENT_GATEWAY_CHANGED
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    ChangeRecord,
    Classification,
    Finding,
)
from custom_components.openwrt_router.diag_runtime import (
    async_release_net_diagnostics,
    ni_change_findings,
)
from custom_components.openwrt_router.net_events import Category
from custom_components.openwrt_router.net_rules import (
    DEFAULT_SETTINGS,
    DIAG_CHANGE_TYPES,
    DIAG_DNS_SERVER_CHANGED_KIND,
    DIAG_DNS_SERVER_CHANGED_TYPE,
    DIAG_GATEWAY_CHANGED_KIND,
    DIAG_GATEWAY_CHANGED_TYPE,
    LAN_UNREACHABLE_KEY,
    ROOT_TIERS,
    AlarmMachine,
    Topology,
)

GW_CHANGED = DIAG_GATEWAY_CHANGED_TYPE
DNS_CHANGED = DIAG_DNS_SERVER_CHANGED_TYPE


def changes(router: str, at_key: str | None = None) -> list[Any]:
    key = at_key or router
    return [hit(GW_CHANGED, key, router), hit(DNS_CHANGED, key, router)]


def parent(m: AlarmMachine, type_: str, key: str) -> str | None:
    return inc_of(m, type_, key).parent_id


# --- rules ---------------------------------------------------------------------------


def test_types_are_fixed_info_rules_never_roots_and_not_user_settings() -> None:
    assert {GW_CHANGED, DNS_CHANGED} == DIAG_CHANGE_TYPES
    for type_ in DIAG_CHANGE_TYPES:
        assert type_ not in ROOT_TIERS
        assert type_ not in DEFAULT_SETTINGS["thresholds"]
    m = AlarmMachine()
    m.update(T0, changes(G))
    for type_ in DIAG_CHANGE_TYPES:
        inc = inc_of(m, type_, G)
        assert inc.severity.value == "info"


# --- case 24: correlation -------------------------------------------------------------


def test_case_24_incident_correlation() -> None:
    """Adopted only where a technical dependency exists (same router)."""
    # 1. wan_down of the same router adopts both; of another router never
    m = AlarmMachine()
    m.update(T0, [level("wan_down", G)])
    m.update(T0 + 30, [*changes(G), *changes(A)])
    m.correlate(T0 + 30, observed_tree())
    root = inc_of(m, "wan_down", G)
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, G) == root.id
        assert inc_of(m, type_, G).cause == "wan_down"
        assert parent(m, type_, A) is None  # ap1 sits behind gw: no link

    # 2. router_unreachable / system_reboot of the same router, after the
    #    outage began only (a change from before is no follow-up)
    m = AlarmMachine()
    m.update(T0 - 60, changes(A, "before"))
    m.update(T0, [level("router_unreachable", A, since=T0)])
    m.update(T0 + 120, [*changes(A), *changes(G)])
    m.correlate(T0 + 120, Topology())
    root = inc_of(m, "router_unreachable", A)
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, A) == root.id
        assert parent(m, type_, "before") is None
        assert parent(m, type_, G) is None
    m = AlarmMachine()
    m.update(T0, [hit("system_reboot", A, A)])
    m.update(T0 + 30, changes(A))
    m.correlate(T0 + 30, Topology())
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, A) == inc_of(m, "system_reboot", A).id

    # 3. the uplink's outage (gw down, ap1 behind it) does not adopt ap1's
    #    change: no dependency of ap1's next hop on gw's reachability from HA
    m = AlarmMachine()
    m.update(T0, [level("router_unreachable", G, since=T0)])
    m.update(T0 + 30, changes(A))
    m.correlate(T0 + 30, observed_tree())
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, A) is None

    # 4. lan_unreachable: unchanged existing behaviour, it adopts every
    #    router incident in its window, these two included
    m = AlarmMachine()
    m.update(T0, [level("lan_unreachable", LAN_UNREACHABLE_KEY, router="")])
    m.update(T0 + 10, changes(A))
    m.correlate(T0 + 10, observed_tree())
    lan = inc_of(m, "lan_unreachable", LAN_UNREACHABLE_KEY)
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, A) == lan.id

    # 5. other roots of the same router never adopt them
    m = AlarmMachine()
    m.update(T0, [hit("wifi_mass_disconnect", A, A, count=8)])
    m.update(T0 + 10, changes(A))
    m.correlate(T0 + 10, observed_tree())
    for type_ in DIAG_CHANGE_TYPES:
        assert parent(m, type_, A) is None


def test_change_incidents_never_adopt_or_silence_anything() -> None:
    m = AlarmMachine()
    m.update(T0, changes(G))
    m.update(T0 + 10, [hit("wan_unstable", G, G, count=3), storm(CLIENTS[0], G)])
    m.correlate(T0 + 10, observed_tree())
    for type_ in DIAG_CHANGE_TYPES:
        assert inc_of(m, type_, G).children == 0
    assert parent(m, "wan_unstable", G) is None
    assert parent(m, "wifi_reconnect_storm", CLIENTS[0]) is None
    open_roots = {i.type for i in roots(m)}
    assert {"wan_unstable", "wifi_reconnect_storm"} <= open_roots


def test_change_events_follow_the_same_rule() -> None:
    m = AlarmMachine()
    m.update(T0, [level("wan_down", G)])
    events = [
        event("gw:1", T0 + 5, G, DIAG_GATEWAY_CHANGED_KIND, Category.WAN),
        event("gw:2", T0 + 6, G, DIAG_DNS_SERVER_CHANGED_KIND, Category.DNS),
        event("ap1:3", T0 + 5, A, DIAG_GATEWAY_CHANGED_KIND, Category.WAN),
        event("ap1:4", T0 + 6, A, DIAG_DNS_SERVER_CHANGED_KIND, Category.DNS),
        # an existing DNS kind keeps its existing link
        event("gw:5", T0 + 7, G, "dns.no_servers", Category.DNS),
    ]
    result = m.correlate(T0 + 10, Topology(), events)
    root = inc_of(m, "wan_down", G)
    assert result.events == {"gw:1": root.id, "gw:2": root.id, "gw:5": root.id}


# --- the NI findings and the engine path ---------------------------------------------


def _change(kind: Classification, previous: Any, current: Any) -> Finding:
    from custom_components.openwrt_router.diag_core import point_for
    from custom_components.openwrt_router.diag_model import (
        CauseClass,
        Severity,
    )

    return Finding(
        point=point_for(RID1),
        classification=kind,
        severity=Severity.INFO,
        summary_key="x",
        recommendation_key="y",
        cause_class=CauseClass.CONFIRMED,
        family=AddressFamily.IPV4,
        change=ChangeRecord(previous, current),
    )


def test_ni_findings_carry_no_address() -> None:
    found = ni_change_findings(
        "r1",
        [
            _change(Classification.GATEWAY_CHANGED, "192.0.2.1", "192.0.2.2"),
            _change(
                Classification.DNS_SERVER_CHANGED,
                ("192.0.2.53",),
                ("192.0.2.53", "192.0.2.54"),
            ),
            _change(Classification.LAN_PROBLEM, None, None),  # not a change type
        ],
    )
    assert [f.rule for f in found] == [GW_CHANGED, DNS_CHANGED]
    assert [f.kind for f in found] == [
        DIAG_GATEWAY_CHANGED_KIND,
        DIAG_DNS_SERVER_CHANGED_KIND,
    ]
    assert all(f.event and f.scope_key == "r1" for f in found)
    assert found[0].params == {"family": "ipv4"}
    assert found[1].params == {"servers": 2}
    assert "192.0.2." not in json.dumps([f.params for f in found])


async def test_engine_opens_the_change_incident_from_a_poll(
    disk,  # noqa: F811
    ni_disks,  # noqa: F811
) -> None:
    """One poll -> exactly one NI incident and one core change event.

    The coordinator holds the data NI ingests (as in HA), so the NI finding
    source and the poll observer see the same poll: the change is computed
    once and taken over, never reported twice (review L1).
    """
    hass = make_hass()
    engine, _cs = await ni_setup(hass, "r1")
    diag = await make_diag(hass, "r1")
    emitted: list[str] = []
    diag._binding.api = SimpleNamespace(
        emit=lambda **kw: emitted.append(kw["event_type"])
    )
    diag._binding.events_ok = True
    diag._module_key = bytes(range(32))
    coord = diag._entries["r1"]

    def ingest(uptime: int, gw: str, at: float) -> None:
        coord.data = ni_data([], uptime=uptime, wan_status=wan_status(gw=gw))
        engine.ingest("r1", coord.data, at, 60.0)

    ingest(5000, "192.0.2.1", T0)
    assert not [i for i in engine.machine.incidents() if i.type in DIAG_CHANGE_TYPES]
    assert emitted == []
    ingest(5060, "192.0.2.2", T0 + 60)
    [inc] = [i for i in engine.machine.incidents() if i.type == GW_CHANGED]
    assert inc.scope_key == "r1" and inc.parent_id is None
    assert emitted.count(EVENT_GATEWAY_CHANGED) == 1
    kinds = [e.kind for e in engine.ring]
    assert kinds.count(DIAG_GATEWAY_CHANGED_KIND) == 1
    stored = json.dumps([e.params for e in engine.ring], default=str)
    assert "192.0.2.2" not in stored and "192.0.2.1" not in stored
    # the same poll again (a coordinator repeat): nothing new anywhere
    engine.ingest("r1", coord.data, T0 + 90, 60.0)
    assert emitted.count(EVENT_GATEWAY_CHANGED) == 1
    assert [e.kind for e in engine.ring].count(DIAG_GATEWAY_CHANGED_KIND) == 1
    # a router that restarts settles first: no change incident, no event
    ingest(30, "192.0.2.3", T0 + 120)
    assert len([i for i in engine.machine.incidents() if i.type == GW_CHANGED]) == 1
    assert emitted.count(EVENT_GATEWAY_CHANGED) == 1
    diag._binding.api = None
    await async_release_net_diagnostics(hass, "r1")
    # released: the source is gone, a change opens nothing new
    engine.ingest(
        "r1",
        ni_data([], uptime=9000, wan_status=wan_status(gw="192.0.2.4")),
        T0 + 180,
        60.0,
    )
    assert [e.kind for e in engine.ring].count(DIAG_GATEWAY_CHANGED_KIND) == 1


async def test_module_off_feeds_no_change_incident(
    disk,  # noqa: F811
    ni_disks,  # noqa: F811
) -> None:
    hass = make_hass()
    engine, _cs = await ni_setup(hass, "r1")
    await make_diag(hass, "r1", enabled=False)
    for i, gw in enumerate(("192.0.2.1", "192.0.2.2")):
        engine.ingest(
            "r1",
            ni_data([], uptime=5000 + 60 * i, wan_status=wan_status(gw=gw)),
            T0 + 60 * i,
            60.0,
        )
    assert not [i for i in engine.machine.incidents() if i.type in DIAG_CHANGE_TYPES]
    await async_release_net_diagnostics(hass, "r1")
