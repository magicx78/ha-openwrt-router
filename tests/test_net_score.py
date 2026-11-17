"""Tests for the health score (network intelligence P6, plan c6, AK4).

Pure functions: score indicators from coordinator data (``area_inputs``),
the router score with "not applicable" and ``unknown`` areas, offline
routers, acknowledged / ignored / child incidents, and the fleet score.
Router names are roles.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from custom_components.openwrt_router.net_engine import area_inputs
from custom_components.openwrt_router.net_events import (
    Incident,
    IncidentStatus,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_rules import (
    SCORE_AREAS,
    AreaInput,
    RouterScore,
    counted_incidents,
    fleet_score,
    incident_area,
    merge_settings,
    router_score,
)

S = merge_settings(None)
G, A = "gw", "ap1"
FULL = {area: AreaInput(fresh=2, total=2) for area in SCORE_AREAS}


def inc(
    type_: str,
    *,
    router: str = G,
    severity: Severity = Severity.WARNING,
    status: IncidentStatus = IncidentStatus.ACTIVE,
    confidence: float = 1.0,
    parent: str | None = None,
    id_: str | None = None,
) -> Incident:
    return Incident(
        id=id_ or f"{type_}:{router}",
        type=type_,
        scope=Scope.ROUTER,
        scope_key=router,
        status=status,
        severity=severity,
        confidence=confidence,
        parent_id=parent,
        routers=[router],
    )


def full_data(**overrides: Any) -> SimpleNamespace:
    """Coordinator data of a gateway with everything read."""
    values: dict[str, Any] = {
        "ap_interfaces": [{"ifname": "phy0-ap0"}],
        "clients": [{"mac": "02:00:00:00:00:01"}],
        "log_status": "ok",
        "uptime": 1000,
        "cpu_load": 5.0,
        "memory_pressure": {"pct": 30},
        "service_instances": {"dnsmasq": {}},
        "localtime": 1_763_280_000.0,
        "port_stats": [{"name": "lan1"}],
        "wan_status": {"wan_found": True, "uptime": 500},
        "dhcp_pools": [{"name": "lan"}],
        "dhcp_leases": {"02:00:00:00:00:01": {}},
    }
    values.update(overrides)
    return SimpleNamespace(**values)


# --- indicators ---------------------------------------------------------------------


def test_area_inputs_full_gateway_covers_every_area() -> None:
    areas = area_inputs(full_data(), fresh=True, gateway=True)
    for area in SCORE_AREAS:
        assert areas[area].applicable, area
        assert areas[area].fresh == areas[area].total, area


def test_area_inputs_without_data_has_only_the_system_area_unread() -> None:
    areas = area_inputs(None, fresh=True, gateway=True)
    assert set(areas) == {"system"}
    assert areas["system"].fresh == 0 and areas["system"].total == 5


def test_area_inputs_stale_data_counts_nothing() -> None:
    areas = area_inputs(full_data(), fresh=False, gateway=True)
    assert all(a.fresh == 0 for a in areas.values())


def test_area_inputs_not_applicable_areas() -> None:
    """A dumb AP: no WAN role, no ports, no pools -> those areas do not apply."""
    data = full_data(port_stats=[], dhcp_pools=[], wan_status={"wan_found": False})
    areas = area_inputs(data, fresh=True, gateway=False)
    assert not areas["wan"].applicable
    assert not areas["lan"].applicable
    assert not areas["dhcp_dns"].applicable
    assert areas["wifi"].applicable and areas["system"].applicable


def test_area_inputs_defaults_that_mean_not_measured() -> None:
    """uptime 0 (CPU and RAM not trusted), no log, no WAN flag, no leases."""
    data = full_data(
        uptime=0,
        log_status="error",
        wan_status={},
        dhcp_leases={},
        service_instances={},
        localtime=None,
        clients=None,
    )
    areas = area_inputs(data, fresh=True, gateway=True)
    assert areas["system"].fresh == 1  # only "reachable"
    assert areas["wifi"].fresh == 0
    assert areas["wan"].fresh == 0
    assert areas["dhcp_dns"].fresh == 1  # pools only


# --- router score -------------------------------------------------------------------


def test_full_coverage_without_incidents_is_100() -> None:
    result = router_score(G, FULL, [], S)
    assert result.score == 100 and result.coverage == 1.0


def test_no_data_is_unknown_never_100() -> None:
    """AK4: right after start (nothing read) the score is unknown."""
    result = router_score(G, area_inputs(None, fresh=True, gateway=False), [], S)
    assert result.score is None and result.coverage == 0.0
    result = router_score(G, {}, [], S)
    assert result.score is None


def test_stale_data_is_unknown() -> None:
    areas = area_inputs(full_data(), fresh=False, gateway=True)
    assert router_score(G, areas, [], S).score is None


def test_not_applicable_areas_do_not_lower_the_coverage() -> None:
    areas = {
        "wifi": AreaInput(fresh=2, total=2),
        "system": AreaInput(fresh=5, total=5),
        "lan": AreaInput(applicable=False),
        "wan": AreaInput(applicable=False),
        "dhcp_dns": AreaInput(applicable=False),
    }
    result = router_score(A, areas, [], S)
    assert result.score == 100 and result.coverage == 1.0
    assert set(result.areas) == {"wifi", "system"}


def test_area_below_min_coverage_is_unknown_and_left_out() -> None:
    """Wi-Fi 1 of 4 (0.25 < 0.3): unknown; its incident does not count."""
    areas = {
        "wifi": AreaInput(fresh=1, total=4),
        "system": AreaInput(fresh=5, total=5),
    }
    result = router_score(A, areas, [inc("wifi_reconnect_storm", router=A)], S)
    assert result.areas["wifi"]["score"] is None
    assert result.score == 100
    # coverage over all applicable areas, the unknown one included (c6)
    assert result.coverage == pytest.approx((30 * 0.25 + 25) / 55, abs=0.01)


def test_low_coverage_makes_the_score_unknown() -> None:
    areas = {
        "wifi": AreaInput(fresh=0, total=2),
        "system": AreaInput(fresh=5, total=5),
        "lan": AreaInput(fresh=0, total=1),
    }
    result = router_score(A, areas, [], S)  # 25 / 70 = 0.36 < 0.5
    assert result.score is None and result.coverage == pytest.approx(0.36)


def test_penalties_by_severity_and_confidence() -> None:
    incidents = [
        inc("system_cpu_high"),  # warning 15
        inc("wan_down", severity=Severity.CRITICAL, confidence=0.5),  # 20
    ]
    result = router_score(G, FULL, incidents, S)
    assert result.areas["system"]["score"] == 85
    assert result.areas["wan"]["score"] == 80
    expected = (30 * 100 + 25 * 85 + 15 * 100 + 20 * 80 + 10 * 100) / 100
    assert result.score == round(expected)


def test_acknowledged_counts_half_ignored_and_resolved_not_at_all() -> None:
    incidents = [
        inc("system_cpu_high", status=IncidentStatus.ACKNOWLEDGED),
        inc("lan_port_flap", status=IncidentStatus.IGNORED),
        inc("wan_unstable", status=IncidentStatus.RESOLVED),
    ]
    result = router_score(G, FULL, incidents, S)
    assert result.areas["system"]["score"] == 92  # 100 - 7.5
    assert result.areas["lan"]["score"] == 100
    assert result.areas["wan"]["score"] == 100


def test_children_are_not_counted() -> None:
    root = inc("router_unreachable", id_="root")
    child = inc("wifi_reconnect_storm", parent="root")
    result = router_score(G, FULL, [root, child], S)
    assert result.areas["wifi"]["score"] == 100
    assert result.areas["system"]["score"] == 85
    # the parent resolved but is still known: the child stays a child
    root.status = IncidentStatus.RESOLVED
    assert router_score(G, FULL, [root, child], S).areas["wifi"]["score"] == 100
    # parent gone (pruned): the child counts on its own
    assert router_score(G, FULL, [child], S).areas["wifi"]["score"] == 85


def test_other_routers_incidents_do_not_count() -> None:
    result = router_score(G, FULL, [inc("system_cpu_high", router=A)], S)
    assert result.score == 100


def test_area_score_floors_at_zero() -> None:
    incidents = [
        inc("wan_down", severity=Severity.CRITICAL, id_=f"w{i}") for i in range(4)
    ]
    assert router_score(G, FULL, incidents, S).areas["wan"]["score"] == 0


def test_offline_router_is_measured_zero_in_system_only() -> None:
    result = router_score(G, FULL, [], S, offline=True)
    assert result.offline
    assert result.areas["system"] == {"score": 0, "coverage": 1.0}
    assert result.areas["wifi"]["score"] is None
    # 25 of 100 covered: unknown as a router score (AK4: offline -> unknown)
    assert result.score is None and result.coverage == 0.25
    only_system = {"system": AreaInput(fresh=5, total=5)}
    assert router_score(G, only_system, [], S, offline=True).score == 0


def test_incident_areas() -> None:
    assert incident_area("router_unreachable") == "system"
    assert incident_area("lan_unreachable") == "system"
    assert incident_area("dhcp_pool_full") == "dhcp_dns"
    assert incident_area("wifi_auth_wave") == "wifi"
    assert incident_area("wan_ip_changed") == "wan"
    assert incident_area("lan_port_errors") == "lan"
    assert incident_area("something_new") is None


def test_counted_incidents_roots_only() -> None:
    root = inc("router_unreachable", id_="root")
    child = inc("wifi_reconnect_storm", parent="root")
    ignored = inc("system_cpu_high", status=IncidentStatus.IGNORED)
    assert counted_incidents([root, child, ignored]) == [root]


# --- fleet score --------------------------------------------------------------------


def test_fleet_score_is_weighted_by_coverage() -> None:
    scores = {
        G: RouterScore(score=100, coverage=1.0, areas={}),
        A: RouterScore(score=40, coverage=0.5, areas={}),
    }
    value, coverage = fleet_score(scores, S)
    assert value == round((100 * 1.0 + 40 * 0.5) / 1.5)
    assert coverage == 0.75


def test_fleet_score_offline_router_counts_zero_with_system_share() -> None:
    scores = {
        G: RouterScore(score=100, coverage=1.0, areas={}),
        A: RouterScore(score=None, coverage=0.25, areas={}, offline=True),
    }
    value, _coverage = fleet_score(scores, S)
    assert value == round(100 / 1.25)


def test_fleet_score_unknown_routers_drop_out_and_empty_is_unknown() -> None:
    scores = {
        G: RouterScore(score=90, coverage=1.0, areas={}),
        A: RouterScore(score=None, coverage=0.2, areas={}),
    }
    assert fleet_score(scores, S)[0] == 90
    assert fleet_score({}, S) == (None, 0.0)
    only_unknown = {A: RouterScore(score=None, coverage=0.2, areas={})}
    assert fleet_score(only_unknown, S)[0] is None
