"""Self-Healing, package E (1.53.0): the Preflight Safety Engine.

Order tests (Phase 7 order §22) covered here: 8 (a failed preflight
blocks), 9 (router offline), 26 (parallel repair requests: a second action
on the same router, on a router behind it, fleet concurrency) and 27
(maintenance mode). Further:

* every one of the thirteen checks in pass / fail / unknown /
  not_applicable where the catalog allows it;
* an unknown fact never passes a critical check (property over every
  check that passes and every fact it read);
* a result cannot be built or mutated into "green" (no verdict input,
  ``replace`` re-runs, ``object.__setattr__`` is caught as ``tampered``,
  the action is validated against the catalog again);
* the state fingerprint is stable for equal facts and changes with each
  relevant fact (and not with ages, percentages, client counts);
* result expiry runs on the safety clock of the real store: a wall-clock
  jump changes nothing;
* a held router and a paused fleet block; ``service.restart`` of a
  service disabled on purpose; management-path loss on the access point
  three others hang behind; a backup that exists but cannot be restored;
* the collector makes zero router calls (the recorded call list of
  ``full_router_kit``) and reports unknown, never a guess, for missing or
  stale data.

No router, no network.
"""

from __future__ import annotations

import ast
import dataclasses
import math
import pathlib
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import full_router_kit as kit
import pytest
from core_testkit import make_hass
from test_heal_store_v1530 import Clock, advance, disks, open_store  # noqa: F401

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hpol
from custom_components.openwrt_router import heal_preflight as hp
from custom_components.openwrt_router.net_events import IncidentStatus
from custom_components.openwrt_router.net_rules import Topology, Uplink

CS = hp.CheckStatus
S = hm.ActionState
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
R3 = "rtr_" + "3" * 32
R4 = "rtr_" + "4" * 32
R5 = "rtr_" + "5" * 32
T0 = 1_790_000_000.0
SAFE0 = 5_000.0
BKP = "bkp_" + "a" * 32
BKP_OLD = "bkp_" + "b" * 32
APR = "apr_" + "c" * 32
DNSMASQ = {"service": "dnsmasq"}
ODHCPD = {"service": "odhcpd"}
RADIO0 = {"radio": "radio0"}
CAPS_ALL = tuple((c, "available") for c in hp.CAPABILITIES_READ)


def k(value: Any, source: str = "test", age: float | None = None) -> hp.Fact:
    return hp.known(value, source, age)


def u(reason: str = "test_unknown") -> hp.Fact:
    return hp.unknown(reason, "test")


GREEN: dict[str, Any] = {
    "poll_ok": True,
    "poll_age_s": 10.0,
    "poll_interval_s": 60.0,
    "record_active": True,
    "identity_status": "confirmed",
    "identity_bindings": 1,
    "role": "gateway",
    "capabilities": CAPS_ALL,
    "login_is_root": False,
    "acl_blocked": (),
    "lock_holder": "none",
    "router_repairs": 0,
    "fleet_repairs": 0,
    "related_repairs": 0,
    "held": False,
    "fleet_paused": False,
    "loop_blocks": (),
    "config_manager_busy": False,
    "ni_maintenance": False,
    "component_windows": (),
    "run_path": "approval",
    "memory_pressure_pct": 40.0,
    "memory_available_bytes": 64 * 1024 * 1024,
    "cpu_load_pct": 20.0,
    "uptime_s": 86_400,
    "security_findings": 0,
    "uplink_incidents": 0,
    "degraded_dependants": 0,
    "dependants": 0,
    "upstream_hops": 0,
    "wireless_uplink": False,
    "services": (("dnsmasq", True, True), ("odhcpd", True, True)),
    "radios": ("radio0", "radio1"),
    "interfaces": ("lan", "wan", "wan6"),
    "clients_on_router": 12,
    "lease_routers": 2,
    "lease_clients": 9,
    "backups": ((BKP, int(T0) - 3600, "ok", "valid", True),),
    "diag_enabled": True,
}


def facts(
    *,
    router_id: str = R1,
    safe_at: float = SAFE0,
    wall_at: float = T0,
    **over: Any,
) -> hp.PreflightFacts:
    """Green facts of R1 with ``over`` applied (a Fact or a plain value)."""
    values: dict[str, hp.Fact] = {}
    for name, value in {**GREEN, **over}.items():
        values[name] = value if isinstance(value, hp.Fact) else k(value)
    return hp.PreflightFacts(
        router_id=router_id, safe_at=safe_at, wall_at=wall_at, **values
    )


def run(action: str, params: Any = None, **kw: Any) -> hp.PreflightResult:
    approval = kw.pop("approval", None)
    limits = kw.pop("limits", hp.DEFAULT_PREFLIGHT_LIMITS)
    return hp.run_preflight(
        facts(**kw), action, params, approval=approval, limits=limits
    )


def chk(result: hp.PreflightResult, cid: str) -> hp.CheckResult:
    return result.check(cid)


def record(
    *,
    router_id: str = R1,
    action_type: str = "service.restart",
    params: Any = None,
    incident_id: str = "inc-1",
) -> hm.RemediationAction:
    params = DNSMASQ if params is None and action_type == "service.restart" else params
    va = hc.validate(action_type, params)
    return hm.RemediationAction.new(
        router_id=router_id,
        action_type=action_type,
        params=dict(va.params),
        ts=T0,
        incident_id=incident_id,
        components=va.components,
    )


def at_state(state: S, **kw: Any) -> hm.RemediationAction:
    a = record(**kw)
    path = [S.ANALYZED, S.PROPOSED, S.PREFLIGHT]
    if state is S.WAITING_APPROVAL:
        path.append(S.WAITING_APPROVAL)
    elif state in (S.APPROVED, S.EXECUTING):
        path.append(S.APPROVED)
        if state is S.EXECUTING:
            path.append(S.EXECUTING)
    elif state is S.PROPOSED:
        path = [S.ANALYZED, S.PROPOSED]
    for to in path:
        a = hm.transition(a, to, actor=hm.Actor.ENGINE, ts=T0, reason="step")
    assert a.state is state
    return a


def approved(
    f: hp.PreflightFacts,
    rec: hm.RemediationAction | None = None,
    *,
    expires_in: float = 600.0,
    **approval: Any,
) -> hm.RemediationAction:
    """``rec`` with an approval bound to the fingerprint of ``f``."""
    rec = rec or record()
    fp = hp.state_fingerprint(f)
    values: dict[str, Any] = {
        "status": hm.ApprovalStatus.APPROVED,
        "guard_approval_id": APR,
        "binding_hash": hp.expected_binding(rec, fp),
        "requested_by": hm.Actor.ENGINE,
        "decided_by": hm.Actor.ADMIN,
        "expires_at": f.wall_at + expires_in,
    }
    values.update(approval)
    return dataclasses.replace(
        rec, state_fingerprint=fp, approval=hm.Approval(**values)
    )


# ---------------------------------------------------------------------------
# Shape of the module
# ---------------------------------------------------------------------------


def test_the_thirteen_check_ids_in_order() -> None:
    assert hp.PREFLIGHT_CHECK_IDS == (
        "router_reachable",
        "identity_unique",
        "action_supported",
        "permissions_present",
        "no_concurrent_repair",
        "maintenance_window_ok",
        "no_critical_state",
        "management_path_available",
        "components_known",
        "config_captured",
        "backup_present",
        "recovery_path_checked",
        "approval_valid",
    )
    for action in hc.CATALOG:
        params = _params_for(action)
        r = run(action, params)
        assert tuple(c.check for c in r.checks) == hp.PREFLIGHT_CHECK_IDS


def _params_for(action: str) -> dict[str, str]:
    return {
        "service.restart": DNSMASQ,
        "wifi.radio_restart": RADIO0,
        "config.restore": {"version_id": BKP},
        "interface.cycle": {"interface": "wan"},
    }.get(action, {})


_FORBIDDEN_ANYWHERE = ("homeassistant", "aiohttp", "asyncssh")
_FORBIDDEN_MODULES = {"api", "coordinator", "time", "datetime", "socket", "subprocess"}
_LAZY_ONLY = {
    "heal_engine",
    "heal_store",
    "enterprise_core",
    "net_engine",
    "security_center",
    "diag_runtime",
    "config_api",
}


def test_the_core_imports_nothing_from_home_assistant_or_the_api() -> None:
    """No HA, api, coordinator, clock or socket anywhere; the modules bound
    to HA only inside the collector (lazy)."""
    tree = ast.parse(pathlib.Path(hp.__file__).read_text())

    def mods(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Import):
            return [a.name for a in node.names]
        if isinstance(node, ast.ImportFrom):
            return [node.module or ""]
        return []

    for node in ast.walk(tree):
        for mod in mods(node):
            assert not mod.startswith(_FORBIDDEN_ANYWHERE), mod
            assert mod.split(".")[0] not in _FORBIDDEN_MODULES, mod
    for node in tree.body:
        for mod in mods(node):
            assert mod not in _LAZY_ONLY, mod


# ---------------------------------------------------------------------------
# Order test 8: a failed preflight blocks
# ---------------------------------------------------------------------------


def test_order_8_green_read_actions_are_clear() -> None:
    r = run("observe.evaluate")
    assert r.verdict is hp.Verdict.CLEAR and r.blocking == ()
    assert r.executable_now is True  # the only action of the release
    r = run("diag.refresh", run_path="auto")
    assert r.verdict is hp.Verdict.CLEAR
    assert r.in_release is False and r.executable_now is False


@pytest.mark.parametrize(
    ("over", "check"),
    [
        ({"poll_ok": False}, "router_reachable"),
        ({"held": True}, "no_concurrent_repair"),
        ({"fleet_paused": True}, "no_concurrent_repair"),
        ({"ni_maintenance": True}, "maintenance_window_ok"),
        ({"capabilities": (("transport.ubus", "unavailable"),)}, "action_supported"),
        ({"run_path": u()}, "approval_valid"),
    ],
)
def test_order_8_a_failed_critical_check_blocks(over: dict, check: str) -> None:
    r = run("diag.refresh", run_path="auto", **({} if "run_path" in over else over))
    if "run_path" in over:
        r = run("diag.refresh", **over)
    assert r.verdict is hp.Verdict.BLOCKED
    assert check in r.blocking
    assert r.check(check).blocks
    assert r.executable_now is False
    assert r.validity(
        router_id=R1, action_type="diag.refresh", params={}, safe_now=SAFE0
    ) is hp.Validity.BLOCKED


def test_order_8_a_non_critical_fail_does_not_block() -> None:
    # identity of a read-only refresh is reported, not blocking
    r = run("diag.refresh", run_path="auto", identity_status="unverified")
    c = r.check("identity_unique")
    assert c.status is CS.FAIL and c.critical is False and not c.blocks
    assert r.verdict is hp.Verdict.CLEAR


def test_order_8_every_writing_action_is_blocked_today() -> None:
    """Even on the greenest facts: rights are not verified, the rest is
    disabled in the catalog."""
    for action in hc.CATALOG:
        entry = hc.CATALOG[action]
        if not entry.writes:
            continue
        for root in (True, False):
            f = facts(login_is_root=root, run_path="approval")
            rec = approved(f, record(action_type=action, params=_params_for(action)))
            r = hp.run_preflight(f, action, _params_for(action), approval=rec)
            assert r.verdict is hp.Verdict.BLOCKED, action
            assert "permissions_present" in r.blocking or "action_supported" in r.blocking


# ---------------------------------------------------------------------------
# Order test 9: router offline
# ---------------------------------------------------------------------------


def test_order_9_router_offline_blocks_every_router_call() -> None:
    for action in ("diag.refresh", "service.restart", "wifi.radio_restart"):
        r = run(action, _params_for(action), poll_ok=False, run_path="auto")
        c = r.check("router_reachable")
        assert c.status is CS.FAIL and c.reason == "last_poll_failed"
        assert c.critical and "router_reachable" in r.blocking
    # the router's own state is not read from an old poll
    r = run("service.restart", DNSMASQ, poll_ok=False)
    assert r.check("no_critical_state").status is CS.UNKNOWN
    assert r.check("components_known").status is CS.UNKNOWN
    # nothing to reach for an evaluation
    assert run("observe.evaluate", poll_ok=False).verdict is hp.Verdict.CLEAR


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"poll_age_s": 121.0}, "poll_stale"),
        ({"poll_age_s": -5.0}, "poll_time_ahead"),
        ({"poll_age_s": u("no_successful_poll")}, "no_successful_poll"),
        ({"poll_interval_s": u("interval_unknown")}, "interval_unknown"),
        ({"poll_ok": u("router_not_loaded")}, "router_not_loaded"),
    ],
)
def test_router_reachable_is_unknown_without_a_fresh_poll(
    over: dict, reason: str
) -> None:
    r = run("diag.refresh", run_path="auto", **over)
    c = r.check("router_reachable")
    assert c.status is CS.UNKNOWN and c.reason == reason and c.blocks


def test_router_reachable_pass_and_not_applicable() -> None:
    r = run("diag.refresh", run_path="auto", poll_age_s=119.0)
    assert r.check("router_reachable").status is CS.PASS
    c = run("observe.evaluate").check("router_reachable")
    assert c.status is CS.NOT_APPLICABLE and not c.critical
    # a restore has no router call of its own but writes: reachable applies
    r = run("config.restore", {"version_id": BKP})
    assert r.check("router_reachable").status is CS.PASS


# ---------------------------------------------------------------------------
# Each check in each state
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("over", "status", "reason"),
    [
        ({}, CS.PASS, "identity_confirmed_unique"),
        ({"identity_status": "changed"}, CS.FAIL, "identity_changed"),
        (
            {"identity_status": "duplicate_suspected"},
            CS.FAIL,
            "identity_duplicate_suspected",
        ),
        ({"identity_status": "unverified"}, CS.FAIL, "identity_unverified"),
        ({"identity_bindings": 2}, CS.FAIL, "identity_shared"),
        ({"identity_bindings": 0}, CS.FAIL, "identity_unbound"),
        ({"record_active": False}, CS.FAIL, "record_not_active"),
        ({"identity_status": u("core_not_running")}, CS.UNKNOWN, "core_not_running"),
        ({"identity_bindings": u()}, CS.UNKNOWN, "test_unknown"),
    ],
)
def test_identity_unique(over: dict, status: CS, reason: str) -> None:
    c = run("service.restart", DNSMASQ, **over).check("identity_unique")
    assert (c.status, c.reason, c.critical) == (status, reason, True)


def test_identity_not_applicable_without_router_call() -> None:
    c = run("observe.evaluate", identity_status="changed").check("identity_unique")
    assert c.status is CS.NOT_APPLICABLE


@pytest.mark.parametrize(
    ("action", "params", "over", "status", "reason"),
    [
        ("diag.refresh", {}, {}, CS.PASS, "catalog_ready_capabilities_present"),
        ("observe.evaluate", {}, {"capabilities": u()}, CS.PASS, None),
        ("router.reboot", {}, {}, CS.FAIL, "action_disabled"),
        ("wifi.radio_restart", RADIO0, {}, CS.FAIL, "action_disabled"),
        ("diag.ha_probes", {}, {"diag_enabled": False}, CS.FAIL, "diagnostics_off"),
        ("diag.ha_probes", {}, {"diag_enabled": u()}, CS.UNKNOWN, "test_unknown"),
        (
            "service.restart",
            DNSMASQ,
            {"capabilities": (("transport.ubus", "available"),)},
            CS.UNKNOWN,
            "capability_unknown:data.services",
        ),
        (
            "service.restart",
            DNSMASQ,
            {
                "capabilities": (
                    ("transport.ubus", "unavailable"),
                    ("data.services", "available"),
                )
            },
            CS.FAIL,
            "capability_unavailable:transport.ubus",
        ),
        ("service.restart", DNSMASQ, {"capabilities": u()}, CS.UNKNOWN, None),
        ("service.restart", {"service": "wpad"}, {}, CS.FAIL, "param_value_invalid"),
        ("client.kick", {}, {}, CS.FAIL, None),
    ],
)
def test_action_supported(
    action: str, params: dict, over: dict, status: CS, reason: str | None
) -> None:
    c = run(action, params, **over).check("action_supported")
    assert c.status is status and c.critical is True
    if reason is not None:
        assert c.reason == reason


@pytest.mark.parametrize(
    ("action", "params", "over", "status", "reason"),
    [
        ("diag.refresh", {}, {}, CS.PASS, "poll_reads_work"),
        ("diag.refresh", {}, {"poll_ok": False}, CS.UNKNOWN, "poll_rights_not_shown"),
        ("diag.refresh", {}, {"poll_age_s": 500.0}, CS.UNKNOWN, "poll_stale"),
        ("service.restart", DNSMASQ, {}, CS.FAIL, "acl_does_not_grant"),
        (
            "service.restart",
            DNSMASQ,
            {"login_is_root": True},
            CS.UNKNOWN,
            "root_rights_not_verified",
        ),
        ("service.restart", DNSMASQ, {"login_is_root": u()}, CS.UNKNOWN, "test_unknown"),
        (
            "service.restart",
            DNSMASQ,
            {"login_is_root": True, "acl_blocked": ("rc/init",)},
            CS.FAIL,
            "method_acl_blocked",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"login_is_root": True, "acl_blocked": u()},
            CS.UNKNOWN,
            "test_unknown",
        ),
        ("wifi.radio_restart", RADIO0, {}, CS.UNKNOWN, "deployed_acl_not_verified"),
        (
            "wifi.radio_restart",
            RADIO0,
            {"acl_blocked": ("network.wireless/down",)},
            CS.FAIL,
            "method_acl_blocked",
        ),
        ("config.restore", {"version_id": BKP}, {}, CS.FAIL, "no_router_method"),
        ("observe.evaluate", {}, {}, CS.NOT_APPLICABLE, "no_router_call"),
        ("diag.ha_probes", {}, {}, CS.NOT_APPLICABLE, "no_router_rights_needed"),
    ],
)
def test_permissions_present(
    action: str, params: dict, over: dict, status: CS, reason: str
) -> None:
    c = run(action, params, **over).check("permissions_present")
    assert (c.status, c.reason) == (status, reason)
    assert c.critical is (status is not CS.NOT_APPLICABLE and hc.CATALOG[action].writes)


@pytest.mark.parametrize(
    ("over", "status", "reason"),
    [
        ({}, CS.PASS, "no_other_repair"),
        ({"held": True}, CS.FAIL, "router_held"),
        ({"fleet_paused": True}, CS.FAIL, "fleet_paused"),
        ({"lock_holder": "engine"}, CS.FAIL, "repair_running"),
        ({"lock_holder": "external"}, CS.FAIL, "external_write_running"),
        ({"router_repairs": 1}, CS.FAIL, "repair_running"),
        ({"related_repairs": 1}, CS.FAIL, "repair_on_related_router"),
        ({"fleet_repairs": 1}, CS.FAIL, "fleet_concurrency_reached"),
        (
            {"loop_blocks": ("service.restart|service:dnsmasq|breaker_open",)},
            CS.FAIL,
            "breaker_open",
        ),
        (
            {"loop_blocks": ("service.restart|service:dnsmasq|cooling_down",)},
            CS.FAIL,
            "cooling_down",
        ),
        (
            {"loop_blocks": ("service.restart|service:odhcpd|breaker_open",)},
            CS.PASS,
            "no_other_repair",
        ),
        ({"lock_holder": u()}, CS.UNKNOWN, "test_unknown"),
        ({"related_repairs": u("topology_unknown")}, CS.UNKNOWN, "topology_unknown"),
        ({"held": u()}, CS.UNKNOWN, "test_unknown"),
        ({"loop_blocks": u()}, CS.UNKNOWN, "test_unknown"),
    ],
)
def test_no_concurrent_repair(over: dict, status: CS, reason: str) -> None:
    c = run("service.restart", DNSMASQ, **over).check("no_concurrent_repair")
    assert (c.status, c.reason, c.critical) == (status, reason, True)


def test_no_concurrent_repair_for_reads_and_evaluations() -> None:
    c = run("observe.evaluate", held=True).check("no_concurrent_repair")
    assert c.status is CS.NOT_APPLICABLE
    # a refresh (Risk 1) respects a hold, but no lock or repair count
    c = run("diag.refresh", held=True).check("no_concurrent_repair")
    assert c.status is CS.FAIL and c.blocks
    c = run("diag.refresh", lock_holder="engine", fleet_repairs=3).check(
        "no_concurrent_repair"
    )
    assert c.status is CS.PASS


@pytest.mark.parametrize(
    ("action", "params", "over", "status", "critical", "reason"),
    [
        ("service.restart", DNSMASQ, {}, CS.PASS, False, "no_maintenance"),
        (
            "service.restart",
            DNSMASQ,
            {"run_path": "auto", "ni_maintenance": True},
            CS.FAIL,
            True,
            "in_maintenance",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"ni_maintenance": True},
            CS.FAIL,
            False,
            "in_maintenance",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"run_path": "auto", "component_windows": ("service:dnsmasq",)},
            CS.FAIL,
            True,
            "component_in_maintenance",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"run_path": "auto", "component_windows": ("service:odhcpd",)},
            CS.PASS,
            True,
            "no_maintenance",
        ),
        (
            "router.reboot",
            {},
            {"run_path": "auto", "component_windows": ("service:odhcpd",)},
            CS.FAIL,
            True,
            "component_in_maintenance",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"run_path": u("mode_unknown")},
            CS.UNKNOWN,
            True,
            "mode_unknown",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"run_path": "auto", "ni_maintenance": u("ni_not_loaded")},
            CS.UNKNOWN,
            True,
            "ni_not_loaded",
        ),
        ("observe.evaluate", {}, {"ni_maintenance": True}, CS.NOT_APPLICABLE, False, None),
    ],
)
def test_maintenance_window_ok(
    action: str, params: dict, over: dict, status: CS, critical: bool, reason: Any
) -> None:
    c = run(action, params, **over).check("maintenance_window_ok")
    assert (c.status, c.critical) == (status, critical)
    if reason is not None:
        assert c.reason == reason


@pytest.mark.parametrize(
    ("over", "status", "reason"),
    [
        ({}, CS.PASS, "no_dangerous_state"),
        ({"memory_pressure_pct": 90.0}, CS.FAIL, "memory_pressure_high"),
        ({"memory_available_bytes": 8 * 1024 * 1024}, CS.FAIL, "memory_pressure_high"),
        ({"cpu_load_pct": 150.0}, CS.FAIL, "router_overloaded"),
        ({"uptime_s": 120}, CS.FAIL, "recent_reboot"),
        ({"security_findings": 1}, CS.FAIL, "open_security_finding"),
        ({"uplink_incidents": 1}, CS.FAIL, "incident_on_uplink"),
        ({"degraded_dependants": 2}, CS.FAIL, "dependants_degraded"),
        ({"config_manager_busy": True}, CS.FAIL, "config_operation_running"),
        (
            {"security_findings": u("security_center_off")},
            CS.UNKNOWN,
            "security_center_off",
        ),
        ({"memory_pressure_pct": u()}, CS.UNKNOWN, "memory_unknown"),
        ({"cpu_load_pct": u()}, CS.UNKNOWN, "cpu_load_unknown"),
        ({"poll_age_s": 1000.0}, CS.UNKNOWN, "poll_stale"),
        ({"poll_ok": False}, CS.UNKNOWN, "router_state_unknown"),
    ],
)
def test_no_critical_state(over: dict, status: CS, reason: str) -> None:
    c = run("service.restart", DNSMASQ, **over).check("no_critical_state")
    assert (c.status, c.reason, c.critical) == (status, reason, True)


def test_no_critical_state_not_applicable_for_reads() -> None:
    c = run("diag.refresh", memory_pressure_pct=99.0).check("no_critical_state")
    assert c.status is CS.NOT_APPLICABLE and not c.blocks


def test_recent_reboot_limit_is_configurable() -> None:
    limits = hp.PreflightLimits(recent_reboot_s=3600)
    c = run("service.restart", DNSMASQ, uptime_s=1800, limits=limits)
    assert c.check("no_critical_state").reason == "recent_reboot"
    with pytest.raises(hp.PreflightError):
        hp.PreflightLimits(recent_reboot_s=10)
    with pytest.raises(hp.PreflightError):
        hp.PreflightLimits(valid_for_s=3600)
    with pytest.raises(hp.PreflightError):
        hp.PreflightLimits(valid_for_s=True)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("action", "params", "over", "status", "reason"),
    [
        ("service.restart", DNSMASQ, {"dependants": 3}, CS.PASS, "service_restart_keeps_paths"),
        ("router.reboot", {}, {}, CS.FAIL, "cuts_own_management_path"),
        ("wifi.radio_restart", RADIO0, {}, CS.PASS, "radio_carries_no_path"),
        ("wifi.radio_restart", RADIO0, {"wireless_uplink": True}, CS.FAIL, "own_uplink_wireless"),
        (
            "wifi.radio_restart",
            RADIO0,
            {"wireless_uplink": u("sta_detection_inconclusive")},
            CS.UNKNOWN,
            "sta_detection_inconclusive",
        ),
        (
            "wifi.radio_restart",
            RADIO0,
            {"dependants": 1},
            CS.UNKNOWN,
            "dependant_uplink_medium_unknown",
        ),
        ("interface.cycle", {"interface": "lan"}, {}, CS.FAIL, "interface_carries_management_path"),
        ("interface.cycle", {"interface": "wan"}, {}, CS.UNKNOWN, "interface_path_unknown"),
        ("observe.evaluate", {}, {}, CS.NOT_APPLICABLE, "no_disruption"),
        ("diag.refresh", {}, {}, CS.NOT_APPLICABLE, "no_disruption"),
    ],
)
def test_management_path_available(
    action: str, params: dict, over: dict, status: CS, reason: str
) -> None:
    c = run(action, params, **over).check("management_path_available")
    assert (c.status, c.reason) == (status, reason)


@pytest.mark.parametrize(
    ("action", "params", "over", "status", "reason"),
    [
        ("service.restart", DNSMASQ, {}, CS.PASS, "service_known_enabled"),
        (
            "service.restart",
            DNSMASQ,
            {"services": (("dnsmasq", False, False),)},
            CS.FAIL,
            "service_disabled_on_purpose",
        ),
        (
            "service.restart",
            ODHCPD,
            {"services": (("dnsmasq", True, True),)},
            CS.UNKNOWN,
            "service_not_in_poll",
        ),
        (
            "service.restart",
            DNSMASQ,
            {"services": (("dnsmasq", True, None),)},
            CS.UNKNOWN,
            "service_enabled_unknown",
        ),
        ("service.restart", DNSMASQ, {"services": u()}, CS.UNKNOWN, "test_unknown"),
        ("service.restart", DNSMASQ, {"poll_age_s": 999.0}, CS.UNKNOWN, "poll_stale"),
        ("wifi.radio_restart", RADIO0, {}, CS.PASS, "radio_known"),
        (
            "wifi.radio_restart",
            {"radio": "radio3"},
            {},
            CS.UNKNOWN,
            "radio_not_identified",
        ),
        ("interface.cycle", {"interface": "wan"}, {}, CS.PASS, "interface_known"),
        (
            "interface.cycle",
            {"interface": "wan6"},
            {"interfaces": ("lan", "wan")},
            CS.FAIL,
            "interface_absent",
        ),
        ("config.restore", {"version_id": BKP}, {}, CS.PASS, "version_known"),
        ("config.restore", {"version_id": BKP_OLD}, {}, CS.FAIL, "backup_not_found"),
        ("router.reboot", {}, {}, CS.PASS, "router_is_component"),
        ("router.reboot", {}, {"record_active": False}, CS.FAIL, "record_not_active"),
        ("observe.evaluate", {}, {}, CS.NOT_APPLICABLE, "no_component"),
    ],
)
def test_components_known(
    action: str, params: dict, over: dict, status: CS, reason: str
) -> None:
    c = run(action, params, **over).check("components_known")
    assert (c.status, c.reason) == (status, reason)


def _bk(age_s: float, status: str = "ok", validation: str = "valid", sha: bool = True) -> tuple:
    return (BKP, int(T0 - age_s), status, validation, sha)


@pytest.mark.parametrize(
    ("backups", "captured", "present"),
    [
        ((_bk(3600),), (CS.PASS, "current_snapshot"), (CS.PASS, "validated_backup")),
        ((), (CS.FAIL, "no_snapshot"), (CS.FAIL, "no_backup")),
        ((_bk(2 * 86400),), (CS.FAIL, "snapshot_outdated"), (CS.FAIL, "backup_outdated")),
        (
            (_bk(60, validation="unverified"),),
            (CS.PASS, "current_snapshot"),
            (CS.FAIL, "backup_not_validated"),
        ),
        (
            (_bk(60, status="partial"),),
            (CS.PASS, "current_snapshot"),
            (CS.FAIL, "no_backup"),
        ),
        ((_bk(60, sha=False),), (CS.PASS, "current_snapshot"), (CS.FAIL, "no_backup")),
        ((_bk(60, status="failed"),), (CS.FAIL, "no_snapshot"), (CS.FAIL, "no_backup")),
        ((_bk(-600),), (CS.UNKNOWN, "snapshot_time_ahead"), (CS.UNKNOWN, "backup_time_ahead")),
        (u("core_not_running"), (CS.UNKNOWN, "core_not_running"), (CS.UNKNOWN, "core_not_running")),
    ],
)
def test_config_captured_and_backup_present(
    backups: Any, captured: tuple, present: tuple
) -> None:
    r = run("config.restore", {"version_id": BKP}, backups=backups)
    c1, c2 = r.check("config_captured"), r.check("backup_present")
    assert (c1.status, c1.reason) == captured and c1.critical
    assert (c2.status, c2.reason) == present and c2.critical


def test_config_checks_not_applicable_for_actions_without_config_change() -> None:
    for action in hc.CATALOG:
        if action in hp.CONFIG_CHANGING:
            continue
        r = run(action, _params_for(action), backups=())
        for cid in ("config_captured", "backup_present"):
            c = r.check(cid)
            assert c.status is CS.NOT_APPLICABLE, (action, cid)
            assert c.reason == "action_changes_no_config"


def test_recovery_path_checked() -> None:
    c = run("service.restart", DNSMASQ).check("recovery_path_checked")
    assert (c.status, c.reason) == (CS.PASS, "manual_recovery_statement")
    assert c.detail == ("applies_saved_config_no_undo_manual_if_not_back",)
    for action in ("router.reboot", "interface.cycle"):
        c = run(action, _params_for(action)).check("recovery_path_checked")
        assert (c.status, c.reason) == (CS.FAIL, "no_recovery_mechanism"), action
    c = run("wifi.radio_restart", RADIO0).check("recovery_path_checked")
    assert (c.status, c.reason) == (CS.PASS, "second_call_while_path_holds")
    c = run("wifi.radio_restart", RADIO0, wireless_uplink=True).check(
        "recovery_path_checked"
    )
    assert (c.status, c.reason) == (CS.FAIL, "second_call_needs_path")
    c = run("wifi.radio_restart", RADIO0, dependants=2).check("recovery_path_checked")
    assert c.status is CS.UNKNOWN and c.blocks
    for action in ("observe.evaluate", "diag.refresh", "diag.ha_probes"):
        c = run(action).check("recovery_path_checked")
        assert c.status is CS.NOT_APPLICABLE


def test_backup_present_but_restore_unavailable_fails_recovery() -> None:
    caps = tuple(
        (c, "unavailable" if c == "config.restore" else "available")
        for c in hp.CAPABILITIES_READ
    )
    r = run("config.restore", {"version_id": BKP}, capabilities=caps)
    assert r.check("backup_present").status is CS.PASS
    c = r.check("recovery_path_checked")
    assert c.status is CS.FAIL and c.blocks
    assert c.reason == "restore_unavailable_dry_run_only"
    assert "backup_present_not_restorable" in c.detail
    # capability unknown is no better
    caps_unknown = tuple(p for p in caps if p[0] != "config.restore")
    c = run("config.restore", {"version_id": BKP}, capabilities=caps_unknown).check(
        "recovery_path_checked"
    )
    assert c.status is CS.FAIL
    # a restore that could run, with a validated backup: the recovery is known
    c = run("config.restore", {"version_id": BKP}).check("recovery_path_checked")
    assert (c.status, c.reason) == (CS.PASS, "restore_verified")
    c = run(
        "config.restore", {"version_id": BKP}, backups=(_bk(60, validation="unverified"),)
    ).check("recovery_path_checked")
    assert (c.status, c.reason) == (CS.FAIL, "backup_not_validated")


# -- approval ---------------------------------------------------------------------------


def test_approval_valid_pass_and_not_applicable() -> None:
    f = facts()
    r = hp.run_preflight(f, "service.restart", DNSMASQ, approval=approved(f))
    c = r.check("approval_valid")
    assert (c.status, c.reason) == (CS.PASS, "approval_bound_and_current")
    c = run("diag.refresh", run_path="auto").check("approval_valid")
    assert c.status is CS.NOT_APPLICABLE
    c = run("observe.evaluate").check("approval_valid")
    assert c.status is CS.NOT_APPLICABLE
    # a Risk-1 read outside Auto-Heal needs the person
    c = run("diag.refresh", run_path="approval").check("approval_valid")
    assert (c.status, c.reason) == (CS.FAIL, "no_approval")


def test_a_write_needs_an_approval_also_in_auto_heal() -> None:
    """Risk 2 and up never runs on its own: the approval is required whatever
    the mode (Auto-Heal ends at Risk 1)."""
    for action in ("service.restart", "wifi.radio_restart", "router.reboot"):
        c = run(action, _params_for(action), run_path="auto").check("approval_valid")
        assert (c.status, c.reason, c.critical) == (CS.FAIL, "no_approval", True), action
    c = run("service.restart", DNSMASQ, run_path=u("mode_unknown")).check(
        "approval_valid"
    )
    assert c.status is CS.FAIL and c.blocks


def _approval_case(name: str) -> tuple[hp.PreflightFacts, Any]:
    f = facts()
    if name == "none":
        return f, None
    if name == "pending":
        return f, approved(f, status=hm.ApprovalStatus.PENDING)
    if name == "expired_status":
        return f, approved(f, status=hm.ApprovalStatus.EXPIRED)
    if name == "no_guard":
        return f, approved(f, guard_approval_id=None)
    if name == "other_router":
        return f, approved(f, record(router_id=R2))
    if name == "other_params":
        return f, approved(f, record(params=ODHCPD))
    if name == "other_action":
        return f, approved(f, record(action_type="diag.refresh", params={}))
    if name == "state_changed":
        return facts(fleet_repairs=0, loop_blocks=("x|y|cooling_down",)), approved(f)
    if name == "expired":
        return f, approved(f, expires_in=-1.0)
    if name == "too_long":
        return f, approved(f, expires_in=hp.APPROVAL_TTL_MAX_S + 60)
    if name == "no_expiry":
        return f, approved(f, expires_at=None)
    if name == "no_binding":
        return f, approved(f, binding_hash=None)
    raise AssertionError(name)


@pytest.mark.parametrize(
    ("case", "reason"),
    [
        ("none", "no_approval"),
        ("pending", "approval_not_granted"),
        ("expired_status", "approval_expired"),
        ("no_guard", "approval_not_from_guard"),
        ("other_router", "approval_for_other_action"),
        ("other_params", "approval_for_other_action"),
        ("other_action", "approval_for_other_action"),
        ("state_changed", "approval_bound_to_other_state"),
        ("expired", "approval_expired"),
        ("too_long", "approval_expiry_implausible"),
        ("no_expiry", "approval_without_expiry"),
        ("no_binding", "approval_bound_to_other_state"),
    ],
)
def test_approval_valid_fails(case: str, reason: str) -> None:
    f, rec = _approval_case(case)
    c = hp.run_preflight(f, "service.restart", DNSMASQ, approval=rec).check(
        "approval_valid"
    )
    assert (c.status, c.reason, c.critical) == (CS.FAIL, reason, True)


def test_an_approval_is_only_a_remediation_action() -> None:
    f = facts()
    rec = approved(f)
    fake = SimpleNamespace(**{n: getattr(rec, n) for n in ("router_id", "action_type", "params", "approval")})
    with pytest.raises(hp.PreflightError):
        hp.run_preflight(f, "service.restart", DNSMASQ, approval=fake)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Unknown never passes a critical check
# ---------------------------------------------------------------------------


def _green_variants() -> list[tuple[str, dict, hp.PreflightFacts, Any]]:
    """Actions on facts where as many checks as possible pass."""
    out = []
    restore_caps = CAPS_ALL
    for action in hc.CATALOG:
        params = _params_for(action)
        f = facts(login_is_root=True, capabilities=restore_caps)
        rec = None
        if hc.CATALOG[action].writes:
            rec = approved(f, record(action_type=action, params=params))
        out.append((action, params, f, rec))
    out.append(("diag.refresh", {}, facts(run_path="auto"), None))
    out.append(("diag.ha_probes", {}, facts(run_path="auto"), None))
    return out


def test_unknown_never_passes_a_critical_check() -> None:
    """For every check that passes and every fact it read: with that fact
    unknown, the check no longer passes, and a clear verdict turns blocked."""
    tried = 0
    for action, params, f, rec in _green_variants():
        base = hp.run_preflight(f, action, params, approval=rec)
        for c in base.checks:
            if c.status is not CS.PASS or not c.critical:
                continue
            for name in c.facts_used:
                g = dataclasses.replace(f, **{name: u("forced")})
                r = hp.run_preflight(g, action, params, approval=rec)
                after = r.check(c.check)
                assert after.status in (CS.UNKNOWN, CS.FAIL), (action, c.check, name)
                assert after.blocks and r.verdict is hp.Verdict.BLOCKED
                tried += 1
    assert tried > 60


def test_making_any_fact_unknown_never_unblocks() -> None:
    for action, params, f, rec in _green_variants():
        base = hp.run_preflight(f, action, params, approval=rec)
        passed = {c.check for c in base.checks if c.critical and c.status is CS.PASS}
        for name, _fact in f.fact_items():
            g = dataclasses.replace(f, **{name: u("forced")})
            r = hp.run_preflight(g, action, params, approval=rec)
            now = {c.check for c in r.checks if c.critical and c.status is CS.PASS}
            assert now <= passed, (action, name, now - passed)
            if base.verdict is hp.Verdict.BLOCKED:
                assert r.verdict is hp.Verdict.BLOCKED, (action, name)


def test_all_unknown_blocks_every_action_but_the_evaluation() -> None:
    blank = hp.PreflightFacts(router_id=R1, safe_at=SAFE0, wall_at=T0)
    for _name, fact in blank.fact_items():
        assert fact.value is None and fact.reason == "not_collected"
    for action in hc.CATALOG:
        r = hp.run_preflight(blank, action, _params_for(action))
        expected = hp.Verdict.CLEAR if action == "observe.evaluate" else hp.Verdict.BLOCKED
        assert r.verdict is expected, action


# ---------------------------------------------------------------------------
# A result cannot be forged
# ---------------------------------------------------------------------------


def test_no_verdict_or_check_can_be_handed_in() -> None:
    f = facts()
    for name in (
        "verdict",
        "checks",
        "blocking",
        "fingerprint",
        "valid_until",
        "executable_now",
        "in_release",
        "router_id",
        "safe_at",
    ):
        with pytest.raises(TypeError):
            hp.PreflightResult(  # type: ignore[call-arg]
                facts=f, action_type="service.restart", params=DNSMASQ, **{name: None}
            )
    r = hp.run_preflight(f, "service.restart", DNSMASQ)
    with pytest.raises((TypeError, ValueError)):
        dataclasses.replace(r, verdict=hp.Verdict.CLEAR)  # type: ignore[call-arg]
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.verdict = hp.Verdict.CLEAR  # type: ignore[misc]


def test_replace_re_runs_every_check() -> None:
    f = facts(run_path="auto")
    r = hp.run_preflight(f, "diag.refresh", {})
    assert r.clear
    r2 = dataclasses.replace(r, facts=dataclasses.replace(f, held=k(True)))
    assert r2.verdict is hp.Verdict.BLOCKED and "no_concurrent_repair" in r2.blocking
    r3 = dataclasses.replace(r, action_type="router.reboot")
    assert r3.verdict is hp.Verdict.BLOCKED


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("verdict", hp.Verdict.CLEAR),
        ("blocking", ()),
        ("checks", ()),
        ("valid_until", 1e10),
        ("safe_at", 1e10),
        ("fingerprint", "0" * 64),
        ("router_id", R2),
        ("executable_now", True),
    ],
)
def test_a_mutated_result_is_tampered(field_name: str, value: Any) -> None:
    r = hp.run_preflight(facts(), "service.restart", DNSMASQ)
    assert r.verdict is hp.Verdict.BLOCKED
    object.__setattr__(r, field_name, value)
    if field_name == "executable_now":
        # executable_now is not trusted by validity: the verdict still is
        assert r.validity(
            router_id=R1, action_type="service.restart", params=DNSMASQ, safe_now=SAFE0
        ) in (hp.Validity.TAMPERED, hp.Validity.BLOCKED)
        return
    assert (
        r.validity(
            router_id=R1 if field_name != "router_id" else R2,
            action_type="service.restart",
            params=DNSMASQ,
            safe_now=SAFE0,
        )
        is hp.Validity.TAMPERED
    )


def test_swapping_the_facts_behind_the_back_is_tampered() -> None:
    green = facts(run_path="auto")
    r = hp.run_preflight(facts(run_path="auto", held=True), "diag.refresh", {})
    assert not r.clear
    object.__setattr__(r, "facts", green)
    assert (
        r.validity(router_id=R1, action_type="diag.refresh", params={}, safe_now=SAFE0)
        is hp.Validity.TAMPERED
    )


def test_inputs_are_typed_exactly() -> None:
    f = facts()

    class SubFacts(hp.PreflightFacts):  # type: ignore[misc]
        pass

    with pytest.raises(hp.PreflightError):
        hp.run_preflight(SimpleNamespace(**{n: getattr(f, n) for n in ("router_id", "safe_at", "wall_at")}), "observe.evaluate")  # type: ignore[arg-type]
    with pytest.raises(hp.PreflightError):
        hp.run_preflight(f, "observe.evaluate", limits=SimpleNamespace(valid_for_s=10_000))  # type: ignore[arg-type]
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(router_id=R1, safe_at=SAFE0, wall_at=T0, held=SimpleNamespace(value=False))  # type: ignore[arg-type]
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(router_id="router-1", safe_at=SAFE0, wall_at=T0)
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(router_id=R1, safe_at=math.nan, wall_at=T0)
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(router_id=R1, safe_at=SAFE0, wall_at=T0, held=k(3))
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(router_id=R1, safe_at=SAFE0, wall_at=T0, dependants=k(-1))
    with pytest.raises(hp.PreflightError):
        hp.PreflightFacts(
            router_id=R1, safe_at=SAFE0, wall_at=T0, services=k((("dnsmasq", "yes", True),))
        )


def test_the_action_is_validated_against_the_catalog_again() -> None:
    f = facts(run_path="auto")
    for action, params in (
        ("diag.refresh", {"extra": "1"}),
        ("Diag.refresh", {}),
        ("service.restart", {"service": "wpad"}),
        ("client.block", {}),
        (None, None),
        ("config.restore", {"version_id": "bkp_xyz"}),
    ):
        r = hp.run_preflight(f, action, params)
        assert r.verdict is hp.Verdict.BLOCKED, action
        assert r.catalog_refusal is not None
        assert r.check("action_supported").status is CS.FAIL
        assert r.executable_now is False
        assert r.validity(
            router_id=R1, action_type="diag.refresh", params={}, safe_now=SAFE0
        ) is hp.Validity.OTHER_ACTION


def test_params_are_read_once_and_frozen() -> None:
    params = {"service": "dnsmasq"}
    r = hp.run_preflight(facts(), "service.restart", params)
    params["service"] = "odhcpd"
    assert dict(r.params) == {"service": "dnsmasq"}
    with pytest.raises(TypeError):
        r.params["service"] = "odhcpd"  # type: ignore[index]


def test_facts_reject_addresses_and_secrets_shapes() -> None:
    for bad in ("192.168.1.1", "02:00:00:00:0a:0a", "fe80::1", "two words", "pw=x y"):
        with pytest.raises(hp.PreflightError):
            hp.known(bad, "test")
    with pytest.raises(hp.PreflightError):
        hp.Fact(value=None, source="test")  # unknown without a reason
    with pytest.raises(hp.PreflightError):
        hp.known(math.inf, "test")
    with pytest.raises(hp.PreflightError):
        hp.Fact(value=object(), source="test")
    with pytest.raises(hp.PreflightError):
        hp.unknown("Not A Code")


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def _other_value(name: str, value: Any) -> Any:
    alt = {
        "identity_status": "changed",
        "role": "access_point",
        "capabilities": (("transport.ubus", "unavailable"),),
        "acl_blocked": ("rc/init",),
        "lock_holder": "engine",
        "loop_blocks": ("service.restart|service:dnsmasq|breaker_open",),
        "component_windows": ("service:dnsmasq",),
        "run_path": "auto",
        "services": (("dnsmasq", False, True),),
        "radios": ("radio0",),
        "interfaces": ("lan",),
        "backups": (),
    }
    if name in alt:
        return alt[name]
    if isinstance(value, bool):
        return not value
    if isinstance(value, int):
        return value + 1
    raise AssertionError(name)


def test_the_fingerprint_is_stable_and_follows_each_relevant_fact() -> None:
    assert hp.state_fingerprint(facts()) == hp.state_fingerprint(facts())
    assert len(hp.state_fingerprint(facts())) == 64
    # every non-volatile fact
    base = hp.state_fingerprint(facts())
    seen = set()
    for name in hp.FINGERPRINT_FACTS:
        g = facts(**{name: _other_value(name, GREEN[name])})
        fp = hp.state_fingerprint(g)
        assert fp != base, name
        assert hp.state_fingerprint(facts(**{name: u()})) != base, name
        seen.add(fp)
    assert len(seen) == len(hp.FINGERPRINT_FACTS)
    # another router
    assert hp.state_fingerprint(facts(router_id=R2)) != base


def test_the_fingerprint_ignores_noise_but_not_thresholds() -> None:
    base = hp.state_fingerprint(facts())
    for over in (
        {"poll_age_s": 50.0},
        {"memory_pressure_pct": 60.0},
        {"memory_available_bytes": 32 * 1024 * 1024},
        {"cpu_load_pct": 80.0},
        {"uptime_s": 100_000},
        {"clients_on_router": 40},
        {"lease_clients": 1},
        {"incident_severity": "critical"},
        {"safe_at": SAFE0 + 50},
        {"wall_at": T0 + 50},
    ):
        assert hp.state_fingerprint(facts(**over)) == base, over
    for over in (
        {"poll_age_s": 500.0},
        {"poll_ok": False},
        {"memory_pressure_pct": 90.0},
        {"cpu_load_pct": 150.0},
        {"uptime_s": 60},
    ):
        assert hp.state_fingerprint(facts(**over)) != base, over


def test_the_fingerprint_carries_no_address_or_secret() -> None:
    view = hp._fingerprint_view(facts(), hp.DEFAULT_PREFLIGHT_LIMITS)
    text = repr(view)
    assert "192." not in text and "pw" not in text
    r = hp.run_preflight(facts(), "service.restart", DNSMASQ)
    blob = repr(r.to_dict())
    assert kit.CLIENT_MAC not in blob


# ---------------------------------------------------------------------------
# Binding and expiry on the safety clock
# ---------------------------------------------------------------------------


def test_a_result_is_bound_to_router_action_and_params() -> None:
    r = run("diag.refresh", {}, run_path="auto")
    v = hp.Validity
    assert r.validity(router_id=R1, action_type="diag.refresh", params={}, safe_now=SAFE0) is v.VALID
    assert r.validity(router_id=R2, action_type="diag.refresh", params={}, safe_now=SAFE0) is v.OTHER_ROUTER
    assert r.validity(router_id=R1, action_type="diag.ha_probes", params={}, safe_now=SAFE0) is v.OTHER_ACTION
    assert r.validity(router_id=R1, action_type="diag.refresh", params={"x": "y"}, safe_now=SAFE0) is v.OTHER_ACTION
    r = hp.run_preflight(facts(), "service.restart", DNSMASQ)
    assert r.validity(router_id=R1, action_type="service.restart", params=ODHCPD, safe_now=SAFE0) is v.OTHER_ACTION


def test_a_result_expires_on_the_safety_clock() -> None:
    r = run("diag.refresh", {}, run_path="auto")
    v = hp.Validity

    def at(safe: Any) -> hp.Validity:
        return r.validity(router_id=R1, action_type="diag.refresh", params={}, safe_now=safe)

    assert r.valid_until == SAFE0 + hp.VALID_FOR_DEFAULT_S
    assert at(SAFE0 + 119.9) is v.VALID
    assert at(SAFE0 + 120) is v.EXPIRED
    assert at(SAFE0 - 1) is v.NOT_YET
    assert at(math.nan) is v.EXPIRED and at(True) is v.EXPIRED and at("now") is v.EXPIRED
    short = run("diag.refresh", {}, run_path="auto", limits=hp.PreflightLimits(valid_for_s=10))
    assert short.validity(router_id=R1, action_type="diag.refresh", params={}, safe_now=SAFE0 + 10) is v.EXPIRED


async def test_a_wall_clock_jump_does_not_extend_or_end_a_result(disks: Any) -> None:
    """Expiry runs on the store's safety clock: a jump of the wall clock
    (forward a day, back a day) changes nothing; real time does."""
    clock = Clock()
    store, _ = await open_store(clock)
    f = hp.facts_from_sources(hp.FactSources(store=store), R1, wall_now=clock())
    g = dataclasses.replace(
        facts(safe_at=f.safe_at, wall_at=f.wall_at, run_path="auto"),
    )
    r = hp.run_preflight(g, "diag.refresh", {})
    assert r.clear

    def validity() -> hp.Validity:
        return r.validity(
            router_id=R1, action_type="diag.refresh", params={}, safe_now=store.now()
        )

    assert validity() is hp.Validity.VALID
    clock.now += 86_400  # wall clock jumps forward a day, no real time
    assert validity() is hp.Validity.VALID
    clock.now -= 2 * 86_400  # and back two days
    assert validity() is hp.Validity.VALID
    advance(store, clock, 119)
    assert validity() is hp.Validity.VALID
    advance(store, clock, 2)
    assert validity() is hp.Validity.EXPIRED


# ---------------------------------------------------------------------------
# Held router, paused fleet (real store)
# ---------------------------------------------------------------------------


async def test_a_held_router_and_a_paused_fleet_block(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    src = hp.FactSources(store=store)
    f = hp.facts_from_sources(src, R1, wall_now=clock())
    assert f.held.value is False and f.fleet_paused.value is False
    safe = store.now()
    store.loop.place_hold(
        hm.RouterHold(router_id=R1, reason=hm.HoldReason.OUTCOME_UNKNOWN, since=safe)
    )
    f = hp.facts_from_sources(src, R1, wall_now=clock())
    assert f.held.value is True and f.held.source == "heal_store.loop.holds"
    assert f.run_path.value == "observe"  # a held router is observed only
    for action in ("diag.refresh", "service.restart"):
        r = hp.run_preflight(
            dataclasses.replace(facts(run_path="auto"), held=f.held), action, _params_for(action)
        )
        c = r.check("no_concurrent_repair")
        assert c.status is CS.FAIL and c.reason == "router_held" and c.blocks
    # the other router is not held, the fleet pauses
    f2 = hp.facts_from_sources(src, R2, wall_now=clock())
    assert f2.held.value is False
    store.loop.fleet = hm.FleetPause(paused_until=safe + 3600, since=safe, reason="fleet_breaker")
    f2 = hp.facts_from_sources(src, R2, wall_now=clock())
    assert f2.fleet_paused.value is True
    r = hp.run_preflight(
        dataclasses.replace(facts(run_path="auto"), fleet_paused=f2.fleet_paused),
        "diag.refresh",
        {},
    )
    assert r.check("no_concurrent_repair").reason == "fleet_paused"
    assert r.verdict is hp.Verdict.BLOCKED


# ---------------------------------------------------------------------------
# Order test 26: parallel repair requests (collector on the real store)
# ---------------------------------------------------------------------------


class FakeRegistry:
    """The core's Router Registry (read side): entry id <-> router id."""

    def __init__(self, routers: dict[str, str], role: str = "gateway") -> None:
        self.routers = routers
        self.flags: dict[str, tuple[Any, ...]] = {}
        self.role = role
        self.caps: dict[str, Any] = {
            c: SimpleNamespace(state="available") for c in hp.CAPABILITIES_READ
        }
        self.macs: dict[str, frozenset[str]] = {}

    def _record(self, entry_id: str, rid: str) -> Any:
        return SimpleNamespace(
            router_id=rid,
            state="active",
            identity=SimpleNamespace(
                entry_id=entry_id,
                identity_flags=self.flags.get(entry_id, ()),
                role=self.role,
                mac_addresses=self.macs.get(entry_id, frozenset()),
            ),
            capabilities=self.caps,
        )

    def find(self, router_id: str) -> Any:
        for e, rid in self.routers.items():
            if rid == router_id:
                return self._record(e, rid)
        return None

    def list(self, **_kw: Any) -> tuple[Any, ...]:
        return tuple(self._record(e, rid) for e, rid in self.routers.items())


class FakeNI:
    def __init__(self, topology: Topology) -> None:
        self.loaded = True
        self.topology = topology
        self.maintenance: set[str] = set()
        self.incidents: list[Any] = []
        self.ring: list[Any] = []
        self.machine = SimpleNamespace(peek=lambda: list(self.incidents), last_now=T0)

    def in_maintenance(self, entry_id: str) -> bool:
        return entry_id in self.maintenance


ROUTERS = {"e1": R1, "e2": R2, "e3": R3, "e4": R4, "e5": R5}


def mesh() -> Topology:
    """e1 gateway; e2 hangs on e1; e3, e4, e5 hang on e2 (an AP with three
    behind it)."""
    return Topology(
        uplinks={
            "e2": Uplink(parent="e1"),
            "e3": Uplink(parent="e2"),
            "e4": Uplink(parent="e2"),
            "e5": Uplink(parent="e2"),
        },
        gateways=frozenset({"e1"}),
    )


def sources(store: Any, entry_id: str, **kw: Any) -> hp.FactSources:
    kw.setdefault("registry", FakeRegistry(ROUTERS))
    kw.setdefault("ni", FakeNI(mesh()))
    return hp.FactSources(store=store, entry_id=entry_id, **kw)


def _with(f: hp.PreflightFacts, *names: str, base: hp.PreflightFacts | None = None) -> hp.PreflightFacts:
    """Green facts with the named facts taken from the collected ``f``."""
    base = base or facts()
    return dataclasses.replace(base, **{n: getattr(f, n) for n in names})


_CONC = ("lock_holder", "router_repairs", "related_repairs", "fleet_repairs", "held", "fleet_paused", "loop_blocks")


async def test_order_26_second_action_on_the_same_router(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    first = at_state(S.WAITING_APPROVAL)
    store.actions[first.action_id] = first
    second = record(params=ODHCPD, incident_id="inc-2")
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock(), exclude_action_id=second.action_id)
    assert f.router_repairs.value == 1
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", ODHCPD)
    c = r.check("no_concurrent_repair")
    assert c.status is CS.FAIL and c.reason == "repair_running" and c.blocks
    # its own record does not count against itself
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock(), exclude_action_id=first.action_id)
    assert f.router_repairs.value == 0
    # a proposal still being planned is no repair yet
    del store.actions[first.action_id]
    planned = at_state(S.PROPOSED)
    store.actions[planned.action_id] = planned
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock())
    assert f.router_repairs.value == 0
    # an external write (a button) holds the router lock
    lock_id = store.try_external_lock(R1, "button.reboot", clock())
    assert lock_id is not None
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock())
    assert f.lock_holder.value == "external"
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", DNSMASQ)
    assert r.check("no_concurrent_repair").reason == "external_write_running"


async def test_order_26_a_repair_on_a_router_behind_or_above(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    busy = at_state(S.EXECUTING, router_id=R4)  # e4 hangs on e2
    store.actions[busy.action_id] = busy
    # e2: e4 is behind it
    f = hp.facts_from_sources(sources(store, "e2"), R2, wall_now=clock())
    assert f.related_repairs.value == 1 and f.dependants.value == 3
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", DNSMASQ)
    c = r.check("no_concurrent_repair")
    assert c.status is CS.FAIL and "repair_on_related_router" in c.detail
    # e1: e4 is behind it too (two hops)
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock())
    assert f.related_repairs.value == 1
    # e3 hangs on e2 next to e4: not related, but the fleet limit of one holds
    f = hp.facts_from_sources(sources(store, "e3"), R3, wall_now=clock())
    assert f.related_repairs.value == 0 and f.fleet_repairs.value == 1
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", DNSMASQ)
    c = r.check("no_concurrent_repair")
    assert c.status is CS.FAIL and c.reason == "fleet_concurrency_reached"
    # without topology: related repairs are unknown, never zero
    f = hp.facts_from_sources(sources(store, "e3", ni=None), R3, wall_now=clock())
    assert f.related_repairs.value is None and f.related_repairs.reason == "topology_unknown"


async def test_order_26_fleet_concurrency(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    f = hp.facts_from_sources(sources(store, "e5"), R5, wall_now=clock())
    assert f.fleet_repairs.value == 0
    other = at_state(S.APPROVED, router_id=R1)
    store.actions[other.action_id] = other
    f = hp.facts_from_sources(sources(store, "e5"), R5, wall_now=clock())
    assert f.fleet_repairs.value == hm.FLEET_CONCURRENCY_DEFAULT
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", DNSMASQ)
    assert "fleet_concurrency_reached" in r.check("no_concurrent_repair").detail
    # a read-only refresh is not held back by repairs elsewhere
    r = hp.run_preflight(_with(f, *_CONC, base=facts(run_path="auto")), "diag.refresh", {})
    assert r.check("no_concurrent_repair").status is CS.PASS


async def test_loop_protection_of_the_store_reaches_the_check(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    safe = store.now()
    key = (R1, "service.restart", "service:dnsmasq")
    store.loop.breakers[key] = hm.BreakerRecord(state=hm.BreakerState.OPEN, opened_at=safe)
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock())
    assert f.loop_blocks.value == ("service.restart|service:dnsmasq|breaker_open",)
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", DNSMASQ)
    assert r.check("no_concurrent_repair").reason == "breaker_open"
    r = hp.run_preflight(_with(f, *_CONC), "service.restart", ODHCPD)
    assert r.check("no_concurrent_repair").status is CS.PASS


# ---------------------------------------------------------------------------
# Order test 27: maintenance mode
# ---------------------------------------------------------------------------


async def test_order_27_maintenance(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    ni = FakeNI(mesh())
    ni.maintenance.add("e2")
    f = hp.facts_from_sources(sources(store, "e2", ni=ni), R2, wall_now=clock())
    assert f.ni_maintenance.value is True
    auto = _with(f, "ni_maintenance", "component_windows", base=facts(run_path="auto"))
    r = hp.run_preflight(auto, "service.restart", DNSMASQ)
    c = r.check("maintenance_window_ok")
    assert c.status is CS.FAIL and c.blocks and c.reason == "in_maintenance"
    # the read-only refresh in Auto-Heal waits for the window too
    assert "maintenance_window_ok" in hp.run_preflight(auto, "diag.refresh", {}).blocking
    # with a person deciding, maintenance is shown, not blocking
    appr = _with(f, "ni_maintenance", "component_windows", base=facts(run_path="approval"))
    c = hp.run_preflight(appr, "service.restart", DNSMASQ).check("maintenance_window_ok")
    assert c.status is CS.FAIL and not c.critical and not c.blocks
    # a service window of the store, wall clock or safety clock
    safe = store.now()
    store.add_maintenance(
        hm.MaintenanceWindow(
            window_id="mtw_" + "d" * 32,
            scope=hm.MaintenanceScope.SERVICE,
            router_id=R1,
            target="dnsmasq",
            start=clock() - 60,
            end=clock() + 600,
            reason="admin",
            created_by=hm.Actor.ADMIN,
        )
    )
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=clock())
    assert f.component_windows.value == ("service:dnsmasq",)
    auto = _with(f, "ni_maintenance", "component_windows", base=facts(run_path="auto"))
    assert hp.run_preflight(auto, "service.restart", DNSMASQ).check(
        "maintenance_window_ok"
    ).reason == "component_in_maintenance"
    assert hp.run_preflight(auto, "service.restart", ODHCPD).check(
        "maintenance_window_ok"
    ).status is CS.PASS
    del safe


# ---------------------------------------------------------------------------
# service.restart of a service disabled on purpose
# ---------------------------------------------------------------------------


def test_service_restart_of_a_service_disabled_on_purpose() -> None:
    f = facts(services=(("dnsmasq", False, False), ("odhcpd", True, True)))
    r = hp.run_preflight(f, "service.restart", DNSMASQ, approval=approved(f))
    c = r.check("components_known")
    assert c.status is CS.FAIL and c.reason == "service_disabled_on_purpose" and c.blocks
    ctx = hp.risk_context_for(f, "service.restart", DNSMASQ)
    assert ctx.service_enabled is False
    f2 = dataclasses.replace(f, incident_type=k("dns_failure"), incident_severity=k("warning"))
    inc = hp.incident_facts_for(f2, "service.restart", DNSMASQ)
    assert inc is not None and inc.target_fact is None  # "not running" is no fault
    # the policy says Not Safe for the same facts
    d = hpol.decide(
        hpol.DecisionInput(
            action_type="service.restart", params=DNSMASQ, incident=inc, context=ctx
        )
    )
    assert d.outcome is hm.DecisionOutcome.NOT_SAFE


# ---------------------------------------------------------------------------
# Management-path loss on the AP three others hang behind
# ---------------------------------------------------------------------------


async def test_management_path_of_the_ap_with_three_behind(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    f = hp.facts_from_sources(
        sources(store, "e2", registry=FakeRegistry(ROUTERS, role="access_point")),
        R2,
        wall_now=clock(),
    )
    assert f.dependants.value == 3 and f.upstream_hops.value == 1
    assert f.role.value == "access_point"
    g = _with(f, "dependants", "upstream_hops", "role")
    r = hp.run_preflight(g, "router.reboot", {})
    c = r.check("management_path_available")
    assert c.status is CS.FAIL and "cuts_dependants_path" in c.detail and c.blocks
    r = hp.run_preflight(g, "wifi.radio_restart", RADIO0)
    c = r.check("management_path_available")
    assert c.status is CS.UNKNOWN and c.reason == "dependant_uplink_medium_unknown"
    assert c.blocks
    assert r.check("recovery_path_checked").blocks
    r = hp.run_preflight(g, "interface.cycle", {"interface": "lan"})
    assert r.check("management_path_available").status is CS.FAIL
    # the service restart keeps every path: the check passes, others block
    r = hp.run_preflight(g, "service.restart", DNSMASQ)
    assert r.check("management_path_available").status is CS.PASS
    ctx = hp.risk_context_for(g, "wifi.radio_restart", RADIO0)
    assert ctx.dependants == 3 and ctx.role == "access_point"
    assert ctx.target_carries_dependants is None and ctx.target_on_mgmt_path is None
    va = hc.validate("wifi.radio_restart", RADIO0)
    assert hpol.classify_risk(va, ctx).risk_class is hm.RiskClass.HIGH


# ---------------------------------------------------------------------------
# The collector: zero router calls, unknown instead of guesses
# ---------------------------------------------------------------------------


async def _polled() -> tuple[Any, list[Any]]:
    calls: list[Any] = []
    coordinator = kit.make_coordinator(make_hass(), kit.make_api(calls))
    await kit.full_polls(coordinator)
    return coordinator, calls


async def test_the_collector_makes_zero_router_calls(disks: Any) -> None:
    """After two polls of the real api and coordinator: collecting (also
    through ``collect_preflight_facts`` and ``preflight_for``) adds no call
    to the recorded list and never refreshes."""
    coordinator, calls = await _polled()
    recorded = list(calls)
    assert len(recorded) > 0
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_refresh = AsyncMock()
    clock = Clock(time.time())
    store, _ = await open_store(clock)
    api = coordinator.api
    src = sources(store, "e1", coordinator=coordinator, api=api)
    f = hp.facts_from_sources(src, R1, wall_now=time.time())
    assert calls == recorded
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()
    # what the poll holds is known, with source and age
    assert f.poll_ok.value is True and f.poll_ok.source == "coordinator.last_update_success"
    assert f.poll_interval_s.value == 60.0
    assert 0 <= f.poll_age_s.value < 60
    services = dict((n, (run_, en)) for n, run_, en in f.services.value)
    assert services["dnsmasq"] == (True, True)
    assert "odhcpd" not in services  # not polled: unknown for its restart
    assert f.services.source == "coordinator.data.services"
    assert f.services.age_s == f.poll_age_s.value
    assert f.login_is_root.value is True and f.acl_blocked.value == ()
    assert f.interfaces.known and "wan" in f.interfaces.value
    assert f.radios.known
    assert f.uptime_s.known and f.memory_pressure_pct.known
    assert f.clients_on_router.value == coordinator.data.client_count
    r = hp.run_preflight(f, "service.restart", ODHCPD)
    assert r.check("components_known").reason == "service_not_in_poll"
    assert r.check("permissions_present").reason == "root_rights_not_verified"
    assert repr(f.to_dict()).count("192.0.2.1") == 0
    assert kit.CLIENT_MAC not in repr(f.to_dict())

    # the hass-side entry point, wired to the same objects
    entry = SimpleNamespace(
        entry_id="e1", runtime_data=SimpleNamespace(coordinator=coordinator, api=api)
    )
    hass = make_hass([entry])
    engine = SimpleNamespace(loaded=True, closed=False, store=store, clock=time.time)
    core = SimpleNamespace(
        loaded=True,
        closed=False,
        registry=FakeRegistry(ROUTERS),
        versions=SimpleNamespace(loaded=True, records=lambda rid: ()),
        manager=SimpleNamespace(locked=lambda rid: False),
    )
    with (
        patch("custom_components.openwrt_router.heal_engine.async_get_self_healing", return_value=engine),
        patch("custom_components.openwrt_router.enterprise_core.async_get_core", return_value=core),
        patch("custom_components.openwrt_router.net_engine.async_get_engine", return_value=FakeNI(mesh())),
        patch("custom_components.openwrt_router.security_center.async_get_security_center", return_value=None),
        patch("custom_components.openwrt_router.diag_runtime.async_get_net_diagnostics", return_value=None),
    ):
        g = hp.collect_preflight_facts(hass, R1)
        res = hp.preflight_for(hass, R1, "service.restart", DNSMASQ)
    assert calls == recorded
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()
    assert g.services.value == f.services.value
    assert g.config_manager_busy.value is False and g.backups.value == ()
    assert g.security_findings.reason == "security_center_not_running"
    assert g.diag_enabled.reason == "diagnostics_not_running"
    assert res.verdict is hp.Verdict.BLOCKED
    assert res.check("no_critical_state").status is CS.UNKNOWN  # Security Center


async def test_stale_or_missing_poll_data_is_unknown(disks: Any) -> None:
    coordinator, calls = await _polled()
    recorded = list(calls)
    clock = Clock(time.time())
    store, _ = await open_store(clock)
    # the last poll is an hour old: nothing of it is used
    later = time.time() + 3600
    f = hp.facts_from_sources(
        sources(store, "e1", coordinator=coordinator, api=coordinator.api), R1, wall_now=later
    )
    for name in ("services", "radios", "interfaces", "memory_pressure_pct", "cpu_load_pct", "uptime_s", "clients_on_router", "lease_clients"):
        fact = getattr(f, name)
        assert fact.value is None and fact.reason in ("poll_stale", "poll_not_fresh"), name
    r = hp.run_preflight(f, "diag.refresh", {})
    assert r.check("router_reachable").reason == "poll_stale"
    # the last poll failed: nothing of the old data is used either
    coordinator.last_update_success = False
    f = hp.facts_from_sources(
        sources(store, "e1", coordinator=coordinator, api=coordinator.api), R1, wall_now=time.time()
    )
    assert f.poll_ok.value is False and f.services.reason == "poll_failed"
    # no router entry loaded at all
    f = hp.facts_from_sources(sources(store, "e1"), R1, wall_now=time.time())
    assert f.poll_ok.reason == "router_not_loaded"
    assert f.login_is_root.reason == "router_not_loaded"
    # nothing of the core, NI, Security Center or diagnostics
    f = hp.facts_from_sources(hp.FactSources(store=store), R1, wall_now=time.time())
    assert f.identity_status.reason == "core_not_running"
    assert f.capabilities.reason == "core_not_running"
    assert f.dependants.reason == "ni_not_loaded"
    assert f.related_repairs.reason == "topology_unknown"
    assert f.security_findings.reason == "security_center_not_running"
    assert f.backups.reason == "core_not_running"
    assert f.config_manager_busy.reason == "core_not_running"
    assert f.diag_enabled.reason == "diagnostics_not_running"
    assert f.incident_type.reason == "no_incident"
    assert calls == recorded


async def test_the_collector_reads_cpu_and_sta_honestly(disks: Any) -> None:
    coordinator, _calls = await _polled()
    clock = Clock(time.time())
    store, _ = await open_store(clock)
    data = coordinator.data
    data.load_average = []
    data.sta_interfaces = []
    f = hp.facts_from_sources(
        sources(store, "e1", coordinator=coordinator, api=coordinator.api), R1, wall_now=time.time()
    )
    assert f.cpu_load_pct.reason == "cpu_load_not_measured"
    assert f.wireless_uplink.reason == "sta_detection_inconclusive"
    data.sta_interfaces = [{"ifname": "wlan0", "mode": "sta", "bssid": "aa", "signal": -60}]
    f = hp.facts_from_sources(
        sources(store, "e1", coordinator=coordinator, api=coordinator.api), R1, wall_now=time.time()
    )
    assert f.wireless_uplink.value is True


async def test_the_collector_without_store_or_engine() -> None:
    with pytest.raises(hp.PreflightError):
        hp.facts_from_sources(hp.FactSources(store=None), R1, wall_now=T0)
    hass = make_hass()
    with (
        patch("custom_components.openwrt_router.heal_engine.async_get_self_healing", return_value=None),
        pytest.raises(hp.PreflightError),
    ):
        hp.collect_preflight_facts(hass, R1)


async def test_the_collector_reads_security_center_identity_and_backups(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    reg = FakeRegistry(ROUTERS)
    from custom_components.openwrt_router.core_models import IdentityFlag

    reg.flags["e1"] = (IdentityFlag.DUPLICATE_SUSPECTED,)
    sc = SimpleNamespace(
        enabled=True,
        incidents={
            "a": {"router_id": R1, "status": "open"},
            "b": {"router_id": R1, "status": "resolved"},
            "c": {"router_id": R2, "status": "open"},
        },
    )
    created = SimpleNamespace(tzinfo=1, timestamp=lambda: T0 - 600)
    versions = SimpleNamespace(
        loaded=True,
        records=lambda rid: (
            SimpleNamespace(
                backup_id=BKP,
                created_at=created,
                status=SimpleNamespace(value="ok"),
                validation=SimpleNamespace(status=SimpleNamespace(value="valid")),
                sha256="f" * 64,
            ),
        ),
    )
    f = hp.facts_from_sources(
        sources(store, "e1", registry=reg, security=sc, versions=versions, config_locked=lambda r: True),
        R1,
        wall_now=T0,
    )
    assert f.identity_status.value == "duplicate_suspected"
    assert f.identity_bindings.value == 1
    assert f.security_findings.value == 1
    assert f.backups.value == ((BKP, int(T0 - 600), "ok", "valid", True),)
    assert f.config_manager_busy.value is True
    sc.enabled = False
    f = hp.facts_from_sources(sources(store, "e1", security=sc), R1, wall_now=T0)
    assert f.security_findings.value is None and f.security_findings.reason == "security_center_off"


async def test_the_collector_reads_the_incident(disks: Any) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    ni = FakeNI(mesh())
    ni.incidents.append(
        SimpleNamespace(
            id="inc-9",
            type="dns_failure",
            status=IncidentStatus.ACTIVE,
            severity=SimpleNamespace(value="warning"),
            confidence=0.8,
            parent_id=None,
            cause_status=None,
            evidence=[],
            routers=["e1"],
            last_seen=T0 - 30,
        )
    )
    f = hp.facts_from_sources(sources(store, "e3", ni=ni), R3, wall_now=T0, incident_id="inc-9")
    assert f.incident_type.value == "dns_failure"
    assert f.incident_severity.value == "warning"
    assert f.incident_is_root.value is True
    # e3 hangs on e2 on e1: the incident on e1 is on its uplink
    assert f.uplink_incidents.value == 1
    f1 = hp.facts_from_sources(sources(store, "e1", ni=ni), R1, wall_now=T0)
    assert f1.uplink_incidents.value == 0 and f1.degraded_dependants.value == 0
    f2 = hp.facts_from_sources(sources(store, "e2", ni=ni), R2, wall_now=T0)
    assert f2.uplink_incidents.value == 1
    g = dataclasses.replace(facts(), **{n: getattr(f, n) for n, _ in f.fact_items() if n.startswith("incident_")})
    inc = hp.incident_facts_for(g, "service.restart", DNSMASQ)
    assert inc is not None
    assert inc.incident_type == "dns_failure" and inc.severity == "warning"
    assert inc.temporal_only is None and inc.cause_outside_router is None
    assert inc.target_fact is None  # dnsmasq runs
    assert hp.incident_facts_for(facts()) is None


# ---------------------------------------------------------------------------
# Facts for the policy
# ---------------------------------------------------------------------------


def test_risk_context_from_green_facts() -> None:
    ctx = hp.risk_context_for(facts(), "service.restart", DNSMASQ)
    assert type(ctx) is hpol.RiskContext
    assert ctx.reachable is True and ctx.identity_confirmed is True
    assert ctx.role == "gateway" and ctx.dependants == 0
    assert ctx.service_enabled is True
    assert ctx.service_dependant_routers == 2 and ctx.service_dependant_clients == 9
    assert ctx.service_config_unapplied is None  # package G
    assert ctx.clients_on_router == 12 and ctx.clients_on_target is None
    assert ctx.open_security_findings == 0
    assert ctx.in_maintenance is False and ctx.concurrent_repair is False
    assert ctx.breaker_open is False and ctx.diag_enabled is True
    inp = hpol.DecisionInput(action_type="service.restart", params=DNSMASQ, context=ctx)
    assert hpol.decide(inp).outcome is not None


def test_risk_context_keeps_unknown_unknown() -> None:
    blank = hp.PreflightFacts(router_id=R1, safe_at=SAFE0, wall_at=T0)
    ctx = hp.risk_context_for(blank, "service.restart", DNSMASQ)
    for name in (
        "role",
        "identity_confirmed",
        "reachable",
        "dependants",
        "service_enabled",
        "service_dependant_routers",
        "service_dependant_clients",
        "clients_on_router",
        "open_security_findings",
        "in_maintenance",
        "concurrent_repair",
        "breaker_open",
        "diag_enabled",
    ):
        assert getattr(ctx, name) is None, name
    ctx = hp.risk_context_for(facts(poll_ok=False), "service.restart", DNSMASQ)
    assert ctx.reachable is False and ctx.service_enabled is None
    assert ctx.clients_on_router is None
    # zero leases seen is no proof that nothing depends on the service
    ctx = hp.risk_context_for(facts(lease_routers=0, lease_clients=0), "service.restart", DNSMASQ)
    assert ctx.service_dependant_routers is None and ctx.service_dependant_clients is None


def test_risk_context_maps_the_facts() -> None:
    f = facts(
        identity_status="changed",
        held=False,
        router_repairs=1,
        ni_maintenance=False,
        component_windows=("service:dnsmasq",),
        loop_blocks=("service.restart|service:dnsmasq|breaker_open",),
        security_findings=2,
    )
    ctx = hp.risk_context_for(f, "service.restart", DNSMASQ)
    assert ctx.identity_confirmed is False
    assert ctx.concurrent_repair is True and ctx.in_maintenance is True
    assert ctx.breaker_open is True and ctx.open_security_findings == 2
    ctx = hp.risk_context_for(facts(), "interface.cycle", {"interface": "lan"})
    assert ctx.target_on_mgmt_path is True
    ctx = hp.risk_context_for(facts(), "wifi.radio_restart", RADIO0)
    assert ctx.target_on_mgmt_path is False and ctx.target_is_wireless_uplink is False
    with pytest.raises(hc.CatalogError):
        hp.risk_context_for(facts(), "client.kick", {})
    with pytest.raises(hp.PreflightError):
        hp.risk_context_for(SimpleNamespace(), "observe.evaluate", {})  # type: ignore[arg-type]


def test_a_running_but_down_service_is_a_direct_target_fact() -> None:
    f = facts(
        services=(("dnsmasq", False, True),),
        incident_type="dns_failure",
        incident_severity="critical",
        incident_confidence=0.9,
        incident_is_root=True,
        incident_cause_status="confirmed",
        incident_cause_level="likely",
        incident_families=2,
        incident_fresh=True,
    )
    inc = hp.incident_facts_for(f, "service.restart", DNSMASQ)
    assert inc is not None and inc.target_fact is hpol.TargetFact.DIRECT
    assert inc.cause_level is hm.CauseLevel.LIKELY
    assert inc.cause_status is hm.CauseStatus.CONFIRMED
    assert inc.source_families == 2 and inc.evidence_fresh is True


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def test_model_checks_and_json() -> None:
    r = run("service.restart", DNSMASQ)
    checks = r.to_model_checks()
    assert [c.check for c in checks] == list(hp.PREFLIGHT_CHECK_IDS)
    by_id = {c.check: c for c in checks}
    assert by_id["config_captured"].outcome is hm.CheckOutcome.PASS
    assert by_id["config_captured"].reason == "not_applicable"
    assert by_id["permissions_present"].outcome is hm.CheckOutcome.FAIL
    d = r.to_dict()
    assert d["verdict"] == "blocked" and d["executable_now"] is False
    assert [c["check"] for c in d["checks"]] == list(hp.PREFLIGHT_CHECK_IDS)
    assert d["facts"]["services"]["source"] == "test"
    assert set(hp.FINGERPRINT_FACTS).isdisjoint(hp.VOLATILE_FACTS)
