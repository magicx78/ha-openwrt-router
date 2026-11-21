"""Context of a diagnostics finding (release 1.47.0, part 2).

``diag_context.py`` (pure rules) and the run time's two read-only sources:
the Configuration Manager's drift events (areas from two stored versions)
and the Security Center's incidents. A context gives at most PROBABLE, lists
its evidence and says "context_unavailable" for a missing source; it never
raises the finding's own class. Case 27: the module off and on (passive)
leave the coordinator, the network intelligence incidents and the router
calls as they are. Mocks only, addresses are documentation values.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

from test_client_engine import setup as ni_setup
from test_coordinator import _make_coordinator
from test_diag_chain import ICMP, OK, TCP, TIMEOUT, ext, facts, probe
from test_diag_runtime import (
    RID1,
    T0,
    Clock,
    disk,  # noqa: F401 - fixture
    make_diag,
    ni_disks,  # noqa: F401 - fixture
    poll,
    wan_status,
)

from custom_components.openwrt_router.api import diag_interface_facts
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.diag_chain import classify, evaluate_chain
from custom_components.openwrt_router.diag_context import (
    CONTEXT_AVAILABLE,
    CONTEXT_MAX_CLASS,
    CONTEXT_PARTIAL,
    CONTEXT_UNAVAILABLE,
    HYP_FIREWALL,
    ConfigChange,
    SecurityIncident,
    SourceState,
    SourceView,
    context_for,
)
from custom_components.openwrt_router.diag_core import point_for
from custom_components.openwrt_router.diag_model import (
    CauseClass,
    Classification,
    Severity,
    Stage,
)
from custom_components.openwrt_router.diag_runtime import (
    async_release_net_diagnostics,
)
from custom_components.openwrt_router.net_rules import DIAG_CHANGE_TYPES

WINDOW = 1800.0
NOT_STRONGER = {CauseClass.PROBABLE, CauseClass.POSSIBLE, CauseClass.UNKNOWN}


def ready(*items: Any, since: float = T0 - 7200) -> SourceView:
    return SourceView(SourceState.READY, since=since, items=tuple(items))


def drift(areas: tuple[str, ...] | None, at: float = T0 - 600) -> ConfigChange:
    return ConfigChange(router_id=RID1, at=at, ref="drift_1", areas=areas)


def links_of(ctx: Any, source: str) -> list[dict[str, Any]]:
    data = ctx.to_dict()
    return data["configuration" if source == "config" else "security"][
        "changes" if source == "config" else "incidents"
    ]


def with_sources(diag: Any, *, areas: list[str] | None, security: Any = None) -> None:
    """The run time's source seams: drift check on, a bound core."""
    diag.config_runtime_of = lambda: SimpleNamespace(
        drift_check_enabled=lambda rid: True
    )
    diag.security_center_of = lambda: security
    diag._binding.api = MagicMock()  # a bound core (no call is made on it)
    diag._config_since = T0 - 7200

    async def drift_areas(note: Any) -> list[str] | None:
        return areas

    diag.drift_areas_of = drift_areas


async def drift_event(diag: Any, hass: Any, *, at: float = T0 - 600) -> None:
    diag._config_event(
        SimpleNamespace(
            type=CoreEventType.DRIFT_DETECTED.value,
            router_id=RID1,
            source="configuration_manager",
            data={"drift_id": "drift_1", "baseline_version_id": "bk_1"},
            ts=at,
        )
    )
    await asyncio.gather(*hass.tasks)


def facts_with(**changes: Any) -> dict[str, Any]:
    status = wan_status()
    status["diag_facts"] = {**status["diag_facts"], **changes}
    return status


# --- named cases -------------------------------------------------------------------


async def test_case_11_vlan_interface_down(disk) -> None:  # noqa: F811
    from core_testkit import make_hass

    hass = make_hass()
    diag = await make_diag(hass, "r1")
    with_sources(diag, areas=["vlan"])
    await drift_event(diag, hass)
    down = facts_with(down_interfaces=[{"name": "iot", "vlan": True}])
    poll(diag, "r1", T0, wan_status=down)
    state = diag._routers[RID1]
    assert state.finding.classification is Classification.LAN_PROBLEM
    # the down interface itself is direct evidence: the finding's own class
    assert state.finding.cause_class is CauseClass.CONFIRMED
    ctx = diag.router_context(RID1)
    data = ctx.to_dict()
    assert data["cause_class"] == "confirmed"  # unchanged by the context
    [link] = data["configuration"]["changes"]
    assert link["area"] == "vlan" and link["hypothesis"] == "config_change_vlan"
    assert link["cause_class"] == CONTEXT_MAX_CLASS.value == "probable"
    assert "interface_down_vlan" in link["evidence"]
    assert data["configuration"]["state"] == CONTEXT_AVAILABLE
    assert data["security"]["state"] == CONTEXT_UNAVAILABLE  # no center
    assert data["security"]["incidents"] is None
    # the overview counts the down interface, names it nowhere
    view = diag.overview()["routers"][RID1]
    assert view["down_interfaces"] == 1 and "iot" not in str(diag.overview())
    await async_release_net_diagnostics(hass, "r1")


async def test_case_12_missing_route(disk) -> None:  # noqa: F811
    from core_testkit import make_hass

    hass = make_hass()
    diag = await make_diag(hass, "r1")
    # the drift touched routing, vlan and firewall at once
    with_sources(diag, areas=["firewall", "routing", "vlan"])
    await drift_event(diag, hass)
    poll(diag, "r1", T0, wan_status=facts_with(ipv4_default_route=False))
    finding = diag._routers[RID1].finding
    assert finding.classification is Classification.ROUTING_PROBLEM
    assert finding.cause_class is not CauseClass.CONFIRMED
    data = diag.router_context(RID1).to_dict()
    assert data["classification"] == "routing_problem"
    [link] = data["configuration"]["changes"]
    # a routing problem: only the routing change, never VLAN or firewall
    assert (link["area"], link["cause_class"]) == ("routing", "probable")
    assert not [h for h in data["hypotheses"] if "vlan" in h or "firewall" in h]
    await async_release_net_diagnostics(hass, "r1")


def test_case_13_firewall_caused_connectivity_problem() -> None:
    # ICMP to the next hop unanswered, TCP to it and the internet fine
    point = point_for(RID1)
    chain = evaluate_chain(
        point,
        [
            probe(Stage.GATEWAY, TIMEOUT, ICMP, "gw", point=point),
            probe(Stage.GATEWAY, OK, TCP, "gw-tcp", point=point),
            *ext(OK, "ext-a", "ext-b", point=point),
        ],
        facts(),
    )
    finding = classify(chain)
    assert finding.classification is Classification.POSSIBLE_FIREWALL_RESTRICTION
    assert finding.severity is Severity.INFO  # not an outage
    ctx = context_for(
        finding,
        RID1,
        T0,
        config=ready(drift(("firewall",))),
        security=ready(),
        window=WINDOW,
    )
    data = ctx.to_dict()
    [link] = data["configuration"]["changes"]
    assert link["cause_class"] == "possible"
    assert link["hypothesis"] == HYP_FIREWALL
    assert data["classification"] not in ("wan_problem", "gateway_problem")
    assert data["cause_class"] == "possible"


async def test_case_27_existing_functions_unchanged(disk, ni_disks) -> None:  # noqa: F811
    """Off vs on (passive): same coordinator data keys (plus only additive
    fields), the same NI incidents for a fixture, the same router calls."""
    from core_testkit import make_hass

    interfaces = [
        {"interface": "lan", "up": True, "proto": "static", "dns-server": []},
        {
            "interface": "wan",
            "up": True,
            "proto": "dhcp",
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": "192.0.2.1"}],
            "dns-server": ["192.0.2.53"],
        },
    ]

    def wan(connected: bool, gw: str = "192.0.2.1") -> dict[str, Any]:
        dump = [dict(i) for i in interfaces]
        dump[1]["route"] = [{"target": "0.0.0.0", "mask": 0, "nexthop": gw}]
        dump[1]["up"] = connected
        return {
            "connected": connected,
            "interface": "wan",
            "ipv4": "203.0.113.7",
            "uptime": 1000,
            "wan_found": True,
            "diag_facts": diag_interface_facts(dump, dump[1]),
        }

    async def run(enabled: bool, statuses: list[dict[str, Any]]) -> dict[str, Any]:
        hass = make_hass()
        engine, _cs = await ni_setup(hass, "r1")
        diag = await make_diag(hass, "r1", enabled=enabled, clock=Clock())
        coord, api = _make_coordinator()
        diag._entries["r1"] = coord  # the module reads this coordinator
        api.get_wan_status = AsyncMock(side_effect=statuses)
        keys: list[frozenset[str]] = []
        for i, _ in enumerate(statuses):
            data = await coord._async_update_data()
            coord.data = data  # what the DataUpdateCoordinator does
            keys.append(frozenset(data.as_dict()))
            engine.ingest("r1", data, T0 + 60 * i, 60.0)
        incidents = sorted(
            (i.type, i.scope_key, i.status.value, i.parent_id is None)
            for i in engine.machine.incidents()
        )
        calls = len(api.mock_calls)
        await async_release_net_diagnostics(hass, "r1")
        return {"keys": keys, "incidents": incidents, "calls": calls}

    fixture = [wan(True), wan(False), wan(False), wan(True)]
    off = await run(False, [dict(s) for s in fixture])
    on = await run(True, [dict(s) for s in fixture])
    for off_keys, on_keys in zip(off["keys"], on["keys"], strict=True):
        assert off_keys <= on_keys  # nothing removed
        assert on_keys == off_keys  # and the module adds no coordinator key
    assert on["incidents"] == off["incidents"]
    assert any(t == "wan_down" for t, *_ in off["incidents"])
    assert on["calls"] == off["calls"]  # no extra router call
    # with a next-hop change only the two new types are added (additive)
    changed = [wan(True), wan(True, gw="192.0.2.2")]
    off = await run(False, [dict(s) for s in changed])
    on = await run(True, [dict(s) for s in changed])
    extra = [i for i in on["incidents"] if i not in off["incidents"]]
    assert extra and {t for t, *_ in extra} <= DIAG_CHANGE_TYPES
    assert all(i in on["incidents"] for i in off["incidents"])
    assert on["calls"] == off["calls"]


# --- sources -------------------------------------------------------------------------


async def test_missing_disabled_or_late_sources_are_named(disk) -> None:  # noqa: F811
    from core_testkit import make_hass

    hass = make_hass()
    diag = await make_diag(hass, "r1")
    poll(diag, "r1", T0, wan_status=facts_with(ipv4_default_route=False))
    # no Configuration Manager, no Security Center
    diag.config_runtime_of = lambda: None
    diag.security_center_of = lambda: None
    data = diag.router_context(RID1).to_dict()
    assert data["configuration"] == {
        "state": CONTEXT_UNAVAILABLE,
        "reason": "configuration_manager_not_running",
        "changes": None,
    }
    assert data["security"]["state"] == CONTEXT_UNAVAILABLE
    assert data["security"]["reason"] == "security_center_not_running"
    # drift check off for this router / center off / center not ready
    diag.config_runtime_of = lambda: SimpleNamespace(
        drift_check_enabled=lambda rid: False
    )
    diag.security_center_of = lambda: SimpleNamespace(enabled=False)
    data = diag.router_context(RID1).to_dict()
    assert data["configuration"]["reason"] == "drift_check_off"
    assert data["security"]["reason"] == "security_center_off"
    diag.security_center_of = lambda: SimpleNamespace(
        enabled=True, ready=False, not_ready_reason="module_key_missing"
    )
    assert diag.router_context(RID1).to_dict()["security"]["reason"] == (
        "module_key_missing"
    )
    # listening since after the window start: partial, not "no change"
    with_sources(diag, areas=None)
    diag._config_since = T0 - 60
    data = diag.router_context(RID1).to_dict()
    assert data["configuration"]["state"] == CONTEXT_PARTIAL
    assert data["configuration"]["changes"] == []
    await async_release_net_diagnostics(hass, "r1")


async def test_security_incidents_are_context_only_and_cached(disk) -> None:  # noqa: F811
    from core_testkit import make_hass

    hass = make_hass()
    diag = await make_diag(hass, "r1")
    calls: list[dict[str, Any]] = []

    def overview(**kw: Any) -> dict[str, Any]:
        calls.append(kw)
        return {
            "incidents": [
                {
                    "id": "sec_1",
                    "type": "port_scan",
                    "category": "network",
                    "severity": "warning",
                    "router_id": RID1,
                    "last_seen": T0 - 120,
                }
            ]
        }

    center = SimpleNamespace(enabled=True, ready=True, overview=overview)
    with_sources(diag, areas=None, security=center)
    poll(diag, "r1", T0, wan_status=facts_with(ipv4_default_route=False))
    first = diag.router_context(RID1).to_dict()
    second = diag.router_context(RID1).to_dict()
    assert first == second and len(calls) == 1  # cached for a minute
    assert calls[0]["router_id"] == RID1 and calls[0]["since"] == T0 - WINDOW
    [link] = first["security"]["incidents"]
    assert link["cause_class"] in {c.value for c in NOT_STRONGER}
    assert link["cause_class"] != "confirmed"
    assert first["cause_class"] == "probable"  # the finding's own class
    await async_release_net_diagnostics(hass, "r1")


async def test_drift_with_unknown_areas_and_a_later_change(disk) -> None:  # noqa: F811
    from core_testkit import make_hass

    hass = make_hass()
    diag = await make_diag(hass, "r1")
    with_sources(diag, areas=None)  # areas cannot be resolved
    await drift_event(diag, hass)
    poll(diag, "r1", T0, wan_status=facts_with(ipv4_default_route=False))
    note = next(iter(diag._config_notes.values()))
    assert note["state"] == "pending"
    [link] = diag.router_context(RID1).to_dict()["configuration"]["changes"]
    assert link["hypothesis"] == "config_change_area_unknown"
    assert link["cause_class"] == "possible"
    # the context never outlives a forgotten router
    diag._forget_router(RID1)
    assert not diag._config_notes
    await async_release_net_diagnostics(hass, "r1")


def test_context_classes_are_capped() -> None:
    finding = classify(
        evaluate_chain(
            point_for(RID1),
            (),
            __import__(
                "custom_components.openwrt_router.diag_runtime", fromlist=["x"]
            ).chain_facts(
                wan_status(),
                {
                    **wan_status()["diag_facts"],
                    "down_interfaces": [{"name": "iot", "vlan": True}],
                },
            ),
        )
    )
    assert finding.cause_class is CauseClass.CONFIRMED
    for at in (T0 - 60, T0 + 60):  # before and after the finding
        ctx = context_for(
            finding,
            RID1,
            T0,
            config=ready(drift(("vlan", "interface"), at=at)),
            security=ready(
                SecurityIncident(RID1, T0 - 30, "sec_1", "x", "network", "warning")
            ),
            window=WINDOW,
        )
        for link in ctx.links:
            assert link.cause_class in NOT_STRONGER
        if at > T0:
            assert {link.cause_class for link in ctx.links} <= {
                CauseClass.POSSIBLE,
                CauseClass.UNKNOWN,
            }
    # the HA point: router configuration changes are not its context
    ha = context_for(
        finding, None, T0, config=ready(drift(("vlan",))), security=ready()
    ).to_dict()
    assert ha["configuration"]["reason"] == "not_applicable"
    assert ha["configuration"]["changes"] is None
