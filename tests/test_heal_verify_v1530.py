"""Self-Healing package H: post-remediation verification (heal_verify.py).

Order tests (§22): 15 failed repair, 16 successful verification, 17 failed
verification, 21 lost management connection, 23 router reboot during the
execution; plus the hard rules of the package order:

* unknown never counts as success, on EVERY criterion;
* "successful" needs a measured improvement and no measured worsening;
* any measured worsening wins (``new_fault``, escalate);
* with no executed write the only good outcome is "cleared by itself";
* settle time and maximum wait on the safety clock, at the boundaries;
* the result is bound to action and snapshots (inconsistent edits caught);
* no names, addresses or secrets in a result;
* the snapshot builder makes zero router calls (recorded call list).

Closed sets are pinned by literal lists. The random test has its own
oracle, written from the inputs.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import random
import time
from datetime import UTC, datetime
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock

import full_router_kit as kit
import pytest
from core_testkit import make_hass

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_preflight as hp
from custom_components.openwrt_router import heal_verify as hv
from custom_components.openwrt_router.heal_model import CallResult
from custom_components.openwrt_router.heal_model import VerificationResult as VR
from custom_components.openwrt_router.net_rules import Topology, Uplink

R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
ACT = "rem_" + "a" * 32
ACT2 = "rem_" + "b" * 32
INC = "inc-7"
T0 = 10_000.0  # safety-clock time the action finished (or observing began)
BEFORE_AT = T0 - 10
AFTER_AT = T0 + 700
NOW = T0 + 720
DNSMASQ = {"service": "dnsmasq"}
ODHCPD = {"service": "odhcpd"}
C = hv.Comparison

# Literal lists (never iterate the constant under test to pin it).
CRITERIA_LITERAL = (
    "incident_cleared",
    "service_running",
    "interface_up",
    "radio_aps_present",
    "service_restarted",
    "router_rebooted",
    "radio_restarted",
    "interface_cycled",
    "config_matches_version",
    "management_path",
    "clients_within_tolerance",
    "radio_clients_within_tolerance",
    "services_still_running",
    "interfaces_still_up",
    "wan_not_lost",
    "ap_interfaces_kept",
    "dependants_not_degraded",
    "no_new_incidents",
    "no_unplanned_reboot",
)
GUARDS_LITERAL = (
    "management_path",
    "clients_within_tolerance",
    "radio_clients_within_tolerance",
    "services_still_running",
    "interfaces_still_up",
    "wan_not_lost",
    "ap_interfaces_kept",
    "dependants_not_degraded",
    "no_new_incidents",
    "no_unplanned_reboot",
)
FACTS_LITERAL = (
    "management_path",
    "clients",
    "radio_clients",
    "services",
    "service_pids",
    "interfaces",
    "wan",
    "ap_interfaces",
    "uptime_s",
    "log_ok",
    "dependants_degraded",
    "incident_status",
    "incident_reopen_count",
    "incident_resolve_reason",
    "incident_resolved_age_s",
    "other_incidents",
)
ACTIONS_LITERAL = (
    "observe.evaluate",
    "diag.refresh",
    "diag.ha_probes",
    "service.restart",
    "wifi.radio_restart",
    "router.reboot",
    "config.restore",
    "interface.cycle",
)
WRITES_LITERAL = (
    "service.restart",
    "wifi.radio_restart",
    "router.reboot",
    "config.restore",
    "interface.cycle",
)
PARAMS = {
    "service.restart": DNSMASQ,
    "wifi.radio_restart": {"radio": "radio0"},
    "config.restore": {"version_id": "bkp_" + "c" * 32},
    "interface.cycle": {"interface": "wan"},
}
# The facts each criterion reads in the green scenario (literal).
READS = {
    "incident_cleared": (
        "incident_status",
        "incident_reopen_count",
        "incident_resolve_reason",
        "incident_resolved_age_s",
    ),
    "service_running": ("services",),
    "interface_up": ("interfaces",),
    "radio_aps_present": ("ap_interfaces",),
    "service_restarted": ("service_pids",),
    "router_rebooted": ("uptime_s",),
    "radio_restarted": (),
    "interface_cycled": (),
    "config_matches_version": (),
    "management_path": ("management_path",),
    "clients_within_tolerance": ("clients",),
    "radio_clients_within_tolerance": ("radio_clients",),
    "services_still_running": ("services",),
    "interfaces_still_up": ("interfaces",),
    "wan_not_lost": ("wan",),
    "ap_interfaces_kept": ("ap_interfaces",),
    "dependants_not_degraded": ("dependants_degraded",),
    "no_new_incidents": ("other_incidents",),
    "no_unplanned_reboot": ("uptime_s",),
}


WALL0 = 1_800_000_000.0  # wall time at safety time 0 in the helpers


def k(value: Any, age: float | None = 0.0) -> hp.Fact:
    """A known fact measured ``age`` seconds before its snapshot."""
    return hp.known(value, "test", age)


def u(reason: str = "test_unknown") -> hp.Fact:
    return hp.unknown(reason, "test")


def _wrap(value: Any) -> hp.Fact:
    return value if isinstance(value, hp.Fact) else k(value)


GREEN_BEFORE = {
    "management_path": True,
    "clients": 10,
    "radio_clients": (("phy0-ap0", 4), ("phy1-ap0", 6)),
    "services": (("dnsmasq", True), ("dropbear", True), ("firewall", False)),
    "service_pids": (("dnsmasq", 100), ("dropbear", 1)),
    "interfaces": (("lan", True), ("wan", True)),
    "wan": "up",
    "ap_interfaces": 2,
    "uptime_s": 5000,
    "log_ok": True,
    "dependants_degraded": 0,
    "incident_status": "active",
    "incident_reopen_count": 0,
    "incident_resolve_reason": "open",
    "incident_resolved_age_s": u("incident_not_resolved"),
    "other_incidents": (),
}
GREEN_AFTER = {
    **GREEN_BEFORE,
    "service_pids": (("dnsmasq", 200), ("dropbear", 1)),
    "uptime_s": 5710,
    "incident_status": "resolved",
    "incident_resolve_reason": "cleared",
    "incident_resolved_age_s": 300.0,
}


_DEFAULT_WALL = object()


def snap(
    base: dict[str, Any] | None = None,
    *,
    at: float = BEFORE_AT,
    router: str = R1,
    incident: str = INC,
    wall: Any = _DEFAULT_WALL,
    **over: Any,
) -> hv.VerifySnapshot:
    values = {**(GREEN_BEFORE if base is None else base), **over}
    return hv.VerifySnapshot(
        router_id=router,
        incident_id=incident,
        taken_at=at,
        wall_at=WALL0 + at if wall is _DEFAULT_WALL else wall,
        **{n: _wrap(v) for n, v in values.items()},
    )


def before(**over: Any) -> hv.VerifySnapshot:
    return snap(GREEN_BEFORE, at=over.pop("at", BEFORE_AT), **over)


def after(**over: Any) -> hv.VerifySnapshot:
    return snap(GREEN_AFTER, at=over.pop("at", AFTER_AT), **over)


def aged(base: dict[str, Any], age: float, **over: Any) -> dict[str, Any]:
    """Every known value of ``base`` measured ``age`` seconds earlier."""
    out = {}
    for name, value in {**base, **over}.items():
        if isinstance(value, hp.Fact):
            out[name] = value
        else:
            out[name] = k(value, age)
    return out


_DEFAULT = object()


def run(
    action: str = "service.restart",
    params: Any = _DEFAULT,
    call: CallResult | None = CallResult.OK,
    b: Any = _DEFAULT,
    a: Any = _DEFAULT,
    started: float = T0,
    now: float = NOW,
    action_id: str = ACT,
) -> hv.VerifyResult:
    return hv.verify(
        action_id=action_id,
        action_type=action,
        params=PARAMS.get(action, {}) if params is _DEFAULT else params,
        call_result=call,
        before=before() if b is _DEFAULT else b,
        after=after() if a is _DEFAULT else a,
        started_at=started,
        judged_at=now,
    )


def not_run(action: str, call: CallResult | None = None) -> CallResult | None:
    """A call result for "nothing was executed": ``None`` (no call at all)
    is only allowed on a read-only action; a write that did not run was
    refused (REJECTED)."""
    if call is None and hc.CATALOG[action].writes:
        return CallResult.REJECTED
    return call


def comparisons(r: hv.VerifyResult) -> dict[str, hv.Comparison]:
    return {c.criterion: c.comparison for c in r.criteria}


# ---------------------------------------------------------------------------
# Purity and closed sets
# ---------------------------------------------------------------------------

_FORBIDDEN_ANYWHERE = ("homeassistant", "aiohttp", "asyncssh")
_FORBIDDEN_MODULES = {"api", "coordinator", "time", "datetime", "socket", "subprocess"}
_NEVER = {
    "heal_engine",
    "heal_store",
    "enterprise_core",
    "net_engine",
    "security_center",
    "diag_runtime",
    "config_api",
    "heal_executor",
}


def test_the_module_imports_nothing_from_home_assistant_or_the_api() -> None:
    """Pure: no HA, api, coordinator, clock, socket; no engine or store."""
    tree = ast.parse(pathlib.Path(hv.__file__).read_text())
    seen: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            seen += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            seen.append(node.module or "")
    assert seen, "no imports found"
    for mod in seen:
        assert not mod.startswith(_FORBIDDEN_ANYWHERE), mod
        assert mod.split(".")[0] not in _FORBIDDEN_MODULES, mod
        assert mod.split(".")[-1] not in _NEVER, mod
    # no call that reads a clock or awaits anything
    src = pathlib.Path(hv.__file__).read_text()
    for word in ("time.time", "monotonic", "datetime.now", "await ", "async def"):
        assert word not in src, word


def test_the_closed_sets_are_pinned() -> None:
    assert hv.CRITERIA == CRITERIA_LITERAL
    assert hv.GUARDS == GUARDS_LITERAL
    assert hv.SNAPSHOT_FACTS == FACTS_LITERAL
    assert tuple(f.name for f in dataclasses.fields(hv.VerifySnapshot)) == (
        "router_id",
        "incident_id",
        "taken_at",
        "wall_at",
        *FACTS_LITERAL,
    )
    assert [v.value for v in VR] == [
        "resolved",
        "partial",
        "not_resolved",
        "unknown",
        "new_fault",
    ]
    assert [v.value for v in hv.Comparison] == [
        "improved",
        "held",
        "not_improved",
        "worse",
        "unknown",
    ]
    assert [v.value for v in hv.Role] == ["primary", "state", "effect", "guard"]
    assert [v.value for v in hv.Attribution] == [
        "action",
        "action_unconfirmed",
        "no_write",
    ]
    assert [v.value for v in hv.Binding] == [
        "valid",
        "tampered",
        "other_action",
        "other_snapshot",
    ]
    assert hv.VERDICT_KEYS == {
        "repaired_by_action",
        "repaired_execution_unconfirmed",
        "cleared_by_itself",
        "partially_repaired",
        "action_did_not_help",
        "not_cleared",
        "worse_after_action",
        "worse_without_action",
        "cannot_tell",
    }
    assert dict(hv.WRITE_CRITERIA) == {
        "service.restart": ("service_running", "service_restarted"),
        "wifi.radio_restart": ("radio_aps_present", "radio_restarted"),
        "interface.cycle": ("interface_up", "interface_cycled"),
        "router.reboot": ("router_rebooted",),
        "config.restore": ("config_matches_version",),
    }
    assert dict(hv.REPLACED_GUARD) == {
        "wifi.radio_restart": ("ap_interfaces_kept",),
        "router.reboot": ("no_unplanned_reboot",),
    }
    roles = {
        "incident_cleared": "primary",
        "service_running": "state",
        "interface_up": "state",
        "radio_aps_present": "state",
        "service_restarted": "effect",
        "router_rebooted": "effect",
        "radio_restarted": "effect",
        "interface_cycled": "effect",
        "config_matches_version": "effect",
        **dict.fromkeys(GUARDS_LITERAL, "guard"),
    }
    assert {k_: v.value for k_, v in hv.ROLE_OF.items()} == roles
    assert hv.VALUE_CODES == {
        "active",
        "acknowledged",
        "resolved",
        "ignored",
        "other",
        "up",
        "down",
        "absent",
    }
    assert hv.WAN_STATES == ("up", "down", "absent")
    assert hv.OPEN_STATES == ("active", "acknowledged")
    assert hv.NOTICED_SEVERITIES == ("warning", "critical")
    assert hv.RESOLVE_MEASURED == "cleared" and hv.RESOLVE_QUIET == "quiet"


def test_the_time_and_tolerance_constants_are_pinned() -> None:
    assert hv.VERIFY_SETTLE_S == 600
    assert hv.VERIFY_MAX_WAIT_S == 3600
    assert hv.BEFORE_MAX_AGE_S == 300
    assert hv.AFTER_MAX_AGE_S == 180
    assert hv.CLIENT_DROP_PCT == 30
    assert hv.CLIENT_DROP_MIN == 2
    assert hv.VERIFY_CLEAR_HOLD_S == 300
    assert hv.CLIENT_SMALL_BELOW == 7
    assert hv.CLIENT_SMALL_DROP == 1
    assert [hv.client_drop_allowed(n) for n in (0, 1, 6, 7, 10, 13, 100)] == [
        1,
        1,
        1,
        2,
        3,
        3,
        30,
    ]


def test_the_catalog_still_has_these_actions_and_writes() -> None:
    assert tuple(hc.CATALOG) == ACTIONS_LITERAL
    assert tuple(a for a, e in hc.CATALOG.items() if e.writes) == WRITES_LITERAL


_GUARDS_NOT_REBOOT = tuple(g for g in GUARDS_LITERAL if g != "no_unplanned_reboot")
_GUARDS_NOT_AP = tuple(g for g in GUARDS_LITERAL if g != "ap_interfaces_kept")


@pytest.mark.parametrize(
    ("action", "executed", "expected"),
    [
        *[(a, False, ("incident_cleared", *GUARDS_LITERAL)) for a in ACTIONS_LITERAL],
        ("observe.evaluate", True, ("incident_cleared", *GUARDS_LITERAL)),
        ("diag.refresh", True, ("incident_cleared", *GUARDS_LITERAL)),
        ("diag.ha_probes", True, ("incident_cleared", *GUARDS_LITERAL)),
        (
            "service.restart",
            True,
            (
                "incident_cleared",
                "service_running",
                "service_restarted",
                *GUARDS_LITERAL,
            ),
        ),
        (
            "wifi.radio_restart",
            True,
            (
                "incident_cleared",
                "radio_aps_present",
                "radio_restarted",
                *_GUARDS_NOT_AP,
            ),
        ),
        (
            "interface.cycle",
            True,
            ("incident_cleared", "interface_up", "interface_cycled", *GUARDS_LITERAL),
        ),
        (
            "router.reboot",
            True,
            ("incident_cleared", "router_rebooted", *_GUARDS_NOT_REBOOT),
        ),
        (
            "config.restore",
            True,
            ("incident_cleared", "config_matches_version", *GUARDS_LITERAL),
        ),
    ],
)
def test_criteria_per_action_type(action: str, executed: bool, expected: tuple) -> None:
    assert hv.criteria_for(action, executed=executed) == expected


def test_every_write_of_the_catalog_needs_its_own_criteria(monkeypatch) -> None:
    hv._check_registry()  # the shipped registry is sound
    smaller = dict(hv.WRITE_CRITERIA)
    del smaller["router.reboot"]
    monkeypatch.setattr(hv, "WRITE_CRITERIA", MappingProxyType(smaller))
    with pytest.raises(hv.VerifyError):
        hv._check_registry()
    no_effect = {**dict(hv.WRITE_CRITERIA), "router.reboot": ()}
    no_effect["router.reboot"] = ()
    monkeypatch.setattr(
        hv, "WRITE_CRITERIA", MappingProxyType({**smaller, "router.reboot": ()})
    )
    with pytest.raises(hv.VerifyError):
        hv._check_registry()
    monkeypatch.setattr(
        hv,
        "WRITE_CRITERIA",
        MappingProxyType({**smaller, "router.reboot": ("no_new_incidents",)}),
    )
    with pytest.raises(hv.VerifyError):
        hv._check_registry()


def test_a_bad_replaced_guard_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(
        hv, "REPLACED_GUARD", MappingProxyType({"router.reboot": ("nothing",)})
    )
    with pytest.raises(hv.VerifyError):
        hv._check_registry()
    monkeypatch.setattr(
        hv, "REPLACED_GUARD", MappingProxyType({"diag.refresh": ("management_path",)})
    )
    with pytest.raises(hv.VerifyError):
        hv._check_registry()


# ---------------------------------------------------------------------------
# The five classes (order tests 15, 16, 17)
# ---------------------------------------------------------------------------


def test_order_16_successful_verification_of_a_service_restart() -> None:
    r = run()
    assert r.result is VR.RESOLVED
    assert r.attribution is hv.Attribution.ACTION
    assert r.credited_to_action is True
    assert r.final is True and r.escalate is False and r.executed is True
    assert r.verdict_key == "repaired_by_action"
    assert comparisons(r) == {
        "incident_cleared": C.IMPROVED,
        "service_running": C.HELD,
        "service_restarted": C.IMPROVED,
        **dict.fromkeys(GUARDS_LITERAL, C.HELD),
    }
    assert r.reasons == (
        "incident_cleared.improved",
        "service_running.held",
        "service_restarted.improved",
    )
    assert r.criterion("incident_cleared").reason == "incident_cleared_measured"
    assert r.router_id == R1 and r.incident_id == INC


def test_order_16_a_stopped_service_running_again_is_resolved() -> None:
    b = before(
        services=(("dnsmasq", False), ("dropbear", True)),
        service_pids=(("dropbear", 1),),
    )
    r = run(b=b)
    assert r.result is VR.RESOLVED
    assert r.criterion("service_running").comparison is C.IMPROVED
    assert r.criterion("service_restarted").reason == "new_pid"


def test_order_17_incident_still_open_is_not_resolved() -> None:
    a = after(
        incident_status="active",
        incident_resolve_reason="open",
        incident_resolved_age_s=u(),
    )
    r = run(a=a)
    assert r.result is VR.NOT_RESOLVED
    assert r.final is False  # it may still clear before the maximum wait
    assert r.verdict_key == "action_did_not_help"
    assert r.credited_to_action is False and r.escalate is False
    assert r.criterion("incident_cleared").reason == "incident_still_open"
    r = run(a=a, now=T0 + 3600, started=T0)
    assert r.result is VR.UNKNOWN  # the after-snapshot is stale by then
    r = run(
        a=after(
            at=T0 + 3500,
            incident_status="active",
            incident_resolve_reason="open",
            incident_resolved_age_s=u(),
        ),
        now=T0 + 3600,
    )
    assert r.result is VR.NOT_RESOLVED and r.final is True


def test_order_15_failed_repair_partial_and_not_resolved() -> None:
    # the service came back (state improved), the incident did not clear
    b = before(
        services=(("dnsmasq", False), ("dropbear", True)),
        service_pids=(("dropbear", 1),),
    )
    a = after(
        incident_status="active",
        incident_resolve_reason="open",
        incident_resolved_age_s=u(),
    )
    r = run(b=b, a=a)
    assert r.result is VR.PARTIAL
    assert r.verdict_key == "partially_repaired"
    assert r.credited_to_action is False and r.escalate is False
    assert r.reasons == (
        "incident_cleared.not_improved",
        "service_running.improved",
    )
    # incident cleared, but the service is still down: partial as well
    b = before(
        services=(("dnsmasq", False), ("dropbear", True)),
        service_pids=(("dropbear", 1), ("dnsmasq", 5)),
    )
    a = after(
        services=(("dnsmasq", False), ("dropbear", True)),
        service_pids=(("dnsmasq", 6), ("dropbear", 1)),
    )
    r = run(b=b, a=a)
    assert r.result is VR.PARTIAL
    assert comparisons(r)["service_running"] is C.NOT_IMPROVED
    # the restart was not seen and the incident is still open: not resolved
    a = after(
        service_pids=(("dnsmasq", 100), ("dropbear", 1)),
        incident_status="active",
        incident_resolve_reason="open",
        incident_resolved_age_s=u(),
    )
    r = run(a=a)
    assert r.result is VR.NOT_RESOLVED
    assert r.criterion("service_restarted").reason == "restart_not_seen"


def test_partial_becomes_final_only_at_the_maximum_wait() -> None:
    b = before(
        services=(("dnsmasq", False), ("dropbear", True)),
        service_pids=(("dropbear", 1),),
    )
    open_ = {
        "incident_status": "active",
        "incident_resolve_reason": "open",
        "incident_resolved_age_s": u(),
    }
    r = run(b=b, a=after(at=T0 + 3500, **open_), now=T0 + 3599.999)
    assert (r.result, r.final) == (VR.PARTIAL, False)
    r = run(b=b, a=after(at=T0 + 3500, **open_), now=T0 + 3600)
    assert (r.result, r.final) == (VR.PARTIAL, True)


def test_cleared_but_the_restart_not_seen_is_never_credited() -> None:
    a = after(service_pids=(("dnsmasq", 100), ("dropbear", 1)))
    r = run(a=a)
    assert r.result is VR.UNKNOWN
    assert r.final is True
    assert r.reasons == ("action_effect_not_seen", "service_restarted.not_improved")
    assert r.credited_to_action is False and r.verdict_key == "cannot_tell"
    # no running instance after
    r = run(a=after(service_pids=(("dropbear", 1),)))
    assert r.result is VR.UNKNOWN
    assert r.criterion("service_restarted").reason == "no_running_instance"


def test_new_fault_wins_over_the_improvement() -> None:
    r = run(a=after(management_path=False))
    assert r.result is VR.NEW_FAULT
    assert r.escalate is True and r.final is True
    assert r.verdict_key == "worse_after_action"
    assert r.credited_to_action is False
    assert r.reasons == ("management_path.worse",)
    assert r.criterion("incident_cleared").comparison is C.IMPROVED


def test_the_unknown_class_when_after_evidence_is_missing() -> None:
    r = run(a=None)
    assert r.result is VR.UNKNOWN
    assert r.reasons == ("after_snapshot_missing",)
    assert r.final is False and r.criteria == ()
    r = run(a=None, now=T0 + 3600)
    assert r.final is True
    r = run(b=None, a=None)
    assert r.reasons == ("before_snapshot_missing",) and r.final is True
    r = run(b=None)
    assert r.result is VR.UNKNOWN and r.reasons == ("before_snapshot_missing",)
    assert r.router_id == R1  # taken from the after-snapshot


def test_inconclusive_call_is_never_credited() -> None:
    r = run(call=CallResult.INCONCLUSIVE)
    assert r.result is VR.RESOLVED
    assert r.attribution is hv.Attribution.ACTION_UNCONFIRMED
    assert r.credited_to_action is False
    assert r.verdict_key == "repaired_execution_unconfirmed"
    r = run(call=CallResult.INCONCLUSIVE, a=after(clients=0))
    assert r.verdict_key == "worse_after_action" and r.escalate is True
    a = after(
        incident_status="active",
        incident_resolve_reason="open",
        incident_resolved_age_s=u(),
    )
    assert run(call=CallResult.INCONCLUSIVE, a=a).verdict_key == "action_did_not_help"


# ---------------------------------------------------------------------------
# Order tests 21 and 23
# ---------------------------------------------------------------------------


def test_order_21_lost_management_connection_is_a_new_fault() -> None:
    lost = {n: u("poll_failed") for n in FACTS_LITERAL if n != "management_path"}
    a = snap(GREEN_AFTER, at=AFTER_AT, management_path=False, **lost)
    r = run(a=a)
    assert r.result is VR.NEW_FAULT
    assert r.escalate is True
    assert "management_path.worse" in r.reasons
    # the same without an action: escalated, never blamed on an action
    r = run(call=CallResult.REJECTED, a=a)
    assert r.result is VR.NEW_FAULT and r.verdict_key == "worse_without_action"
    assert r.attribution is hv.Attribution.NO_WRITE


def test_order_23_router_reboot_during_execution_is_a_new_fault() -> None:
    r = run(a=after(uptime_s=120))
    assert r.result is VR.NEW_FAULT
    assert r.reasons == ("no_unplanned_reboot.worse",)
    assert r.criterion("no_unplanned_reboot").reason == "router_rebooted_unplanned"
    # a planned reboot: the reboot is its effect, not a worsening
    r = run("router.reboot", a=after(uptime_s=120))
    assert r.result is VR.RESOLVED
    assert r.criterion("router_rebooted").reason == "uptime_reset"
    assert "no_unplanned_reboot" not in comparisons(r)
    r = run("router.reboot")  # uptime went on: the reboot was not seen
    assert r.result is VR.UNKNOWN and r.reasons[0] == "action_effect_not_seen"


# ---------------------------------------------------------------------------
# Rule 4: nothing executed -> "cleared by itself" is the only good outcome
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action", ACTIONS_LITERAL)
@pytest.mark.parametrize("call", [None, CallResult.REJECTED])
def test_no_write_cleared_is_cleared_by_itself(action: str, call: Any) -> None:
    r = run(action, call=not_run(action, call))
    assert r.result is VR.RESOLVED
    assert r.attribution is hv.Attribution.NO_WRITE
    assert r.verdict_key == "cleared_by_itself"
    assert r.credited_to_action is False and r.executed is False
    assert tuple(comparisons(r)) == ("incident_cleared", *GUARDS_LITERAL)


@pytest.mark.parametrize(
    "action", ["observe.evaluate", "diag.refresh", "diag.ha_probes"]
)
@pytest.mark.parametrize("call", [CallResult.OK, CallResult.INCONCLUSIVE])
def test_a_read_only_action_is_never_credited(action: str, call: Any) -> None:
    r = run(action, call=call)
    assert r.attribution is hv.Attribution.NO_WRITE
    assert r.verdict_key == "cleared_by_itself"
    assert r.credited_to_action is False


def test_in_release_1_53_nothing_can_be_credited() -> None:
    """1.53.0 runs only ``observe.evaluate`` (no router call): whatever the
    call result, a clearing is "cleared by itself"."""
    assert hc.EXECUTABLE_IN_RELEASE == frozenset({"observe.evaluate"})
    for action in hc.EXECUTABLE_IN_RELEASE:
        for call in (None, CallResult.OK, CallResult.REJECTED, CallResult.INCONCLUSIVE):
            r = run(action, call=call)
            assert (r.result, r.verdict_key, r.credited_to_action) == (
                VR.RESOLVED,
                "cleared_by_itself",
                False,
            )


def test_no_write_reaches_only_four_classes_and_never_partial() -> None:
    rng = random.Random(53)
    seen = set()
    for _ in range(3000):
        b, a, _ = _random_pair(rng)
        action = rng.choice(ACTIONS_LITERAL)
        call = not_run(action, rng.choice([None, CallResult.REJECTED]))
        r = run(action, call=call, b=b, a=a)
        seen.add(r.result)
        assert r.result is not VR.PARTIAL
        assert r.credited_to_action is False
        if r.result is VR.RESOLVED:
            assert r.verdict_key == "cleared_by_itself"
    assert seen == {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT}


# ---------------------------------------------------------------------------
# Unknown never counts as success - on every criterion
# ---------------------------------------------------------------------------


def _cases() -> list[tuple[str, bool]]:
    out = [(a, False) for a in ACTIONS_LITERAL]
    out += [(a, True) for a in WRITES_LITERAL]
    return out


def _spoil(name: str, side: str, how: str) -> hp.Fact:
    """The green fact made unusable: unknown, measured too long ago (stale:
    before the 300 s before the start, or inside the settle time), or of
    unknown age (review PR #83, P1-1)."""
    if how == "unknown":
        return u()
    value = (GREEN_BEFORE if side == "before" else GREEN_AFTER)[name]
    if how == "age_unknown":
        return k(value, None)
    return k(value, 400.0 if side == "before" else 150.0)


@pytest.mark.parametrize("how", ["unknown", "stale", "age_unknown"])
@pytest.mark.parametrize(("action", "executed"), _cases())
def test_unknown_on_any_fact_a_criterion_reads_never_gives_success(
    action: str, executed: bool, how: str
) -> None:
    call = CallResult.OK if executed else not_run(action)
    green = run(action, call=call)
    reached = set()
    for cid, names in READS.items():
        if cid not in comparisons(green):
            continue
        for name in names:
            for side in ("before", "after"):
                if name == "incident_resolved_age_s" and side == "before":
                    continue  # the open incident has no resolved age
                if name == "incident_resolve_reason" and side == "before":
                    continue  # not read before (open)
                bad = {name: _spoil(name, side, how)}
                b = before(**bad) if side == "before" else before()
                a = after(**bad) if side == "after" else after()
                r = run(action, call=call, b=b, a=a)
                assert r.result is VR.UNKNOWN, (action, cid, name, side)
                assert r.credited_to_action is False
                assert comparisons(r)[cid] is C.UNKNOWN, (cid, name, side)
                reached.add(cid)
    always_unknown = {"radio_restarted", "interface_cycled", "config_matches_version"}
    compared = set(comparisons(green))
    assert reached == compared - always_unknown
    for cid in compared & always_unknown:
        assert comparisons(green)[cid] is C.UNKNOWN


# facts no criterion of these cases reads in the green scenario (literal)
UNREAD = {
    ("service.restart", True): {"log_ok"},
    ("router.reboot", True): {"log_ok", "service_pids"},
}


@pytest.mark.parametrize("how", ["unknown", "stale", "age_unknown"])
@pytest.mark.parametrize(("action", "executed"), _cases())
def test_unknown_on_any_fact_never_turns_into_success(
    action: str, executed: bool, how: str
) -> None:
    """Every fact, each side: unknown or stale gives success only for facts
    that no criterion reads (pinned literally)."""
    call = CallResult.OK if executed else not_run(action)
    green = run(action, call=call).result
    unread = UNREAD.get((action, executed), {"log_ok", "service_pids"})
    for name in FACTS_LITERAL:
        for side in ("before", "after"):
            spoilt = (GREEN_BEFORE if side == "before" else GREEN_AFTER)[name]
            if how != "unknown" and isinstance(spoilt, hp.Fact):
                continue  # already unknown in the green scenario
            bad = {name: _spoil(name, side, how)}
            b = before(**bad) if side == "before" else before()
            a = after(**bad) if side == "after" else after()
            r = run(action, call=call, b=b, a=a)
            if name in unread:
                assert r.result is green, (name, side)
            elif green is VR.RESOLVED and not (
                side == "before"
                and name in ("incident_resolved_age_s", "incident_resolve_reason")
            ):
                assert r.result is VR.UNKNOWN, (name, side)


def test_quiet_needs_log_coverage() -> None:
    a = after(incident_resolve_reason="quiet")
    assert run(a=a).criterion("incident_cleared").reason == "incident_quiet_with_logs"
    assert run(a=a).result is VR.RESOLVED
    r = run(a=after(incident_resolve_reason="quiet", log_ok=False))
    assert r.result is VR.UNKNOWN
    assert r.criterion("incident_cleared").reason == "quiet_without_log_coverage"
    r = run(a=after(incident_resolve_reason="quiet", log_ok=u()))
    assert r.criterion("incident_cleared").reason == "log_ok_unknown_after"


@pytest.mark.parametrize(
    ("over_b", "over_a", "reason", "comparison"),
    [
        (
            {},
            {"incident_resolve_reason": "no_data"},
            "resolved_without_evidence",
            C.UNKNOWN,
        ),
        (
            {},
            {"incident_resolve_reason": "router_removed"},
            "resolved_without_evidence",
            C.UNKNOWN,
        ),
        (
            {},
            {"incident_resolve_reason": "ignore_expired"},
            "resolved_without_evidence",
            C.UNKNOWN,
        ),
        ({"incident_status": "resolved"}, {}, "incident_not_open_before", C.UNKNOWN),
        ({"incident_status": "ignored"}, {}, "incident_ignored", C.UNKNOWN),
        ({"incident_status": "weird"}, {}, "incident_not_open_before", C.UNKNOWN),
        ({}, {"incident_status": "ignored"}, "incident_ignored", C.UNKNOWN),
        ({}, {"incident_status": "weird"}, "incident_status_unrecognised", C.UNKNOWN),
        (
            {},
            {"incident_status": "acknowledged"},
            "incident_still_open",
            C.NOT_IMPROVED,
        ),
        (
            {"incident_status": "acknowledged"},
            {},
            "incident_cleared_measured",
            C.IMPROVED,
        ),
        ({}, {"incident_reopen_count": 1}, "incident_recurred", C.NOT_IMPROVED),
        (
            {"incident_reopen_count": 2},
            {"incident_reopen_count": 1},
            "incident_history_inconsistent",
            C.UNKNOWN,
        ),
        (
            {},
            {"incident_resolved_age_s": 700.0},
            "incident_cleared_measured",
            C.IMPROVED,
        ),
        ({}, {"incident_resolved_age_s": 700.001}, "resolved_before_start", C.UNKNOWN),
        ({}, {"incident_status": u()}, "incident_status_unknown_after", C.UNKNOWN),
        ({"incident_status": u()}, {}, "incident_status_unknown_before", C.UNKNOWN),
        (
            {"incident_reopen_count": u()},
            {},
            "incident_reopen_count_unknown_before",
            C.UNKNOWN,
        ),
    ],
)
def test_the_incident_criterion(over_b, over_a, reason, comparison) -> None:
    c = run(b=before(**over_b), a=after(**over_a)).criterion("incident_cleared")
    assert (c.reason, c.comparison) == (reason, comparison)


def test_incident_criterion_shows_closed_codes_only() -> None:
    c = run(b=before(incident_status="weird")).criterion("incident_cleared")
    assert (c.before, c.after) == ("other", "resolved")


# ---------------------------------------------------------------------------
# Any measured worsening wins; the guards one by one
# ---------------------------------------------------------------------------

WORSE_AFTER = {
    "management_path": {"management_path": False},
    "clients_within_tolerance": {"clients": 6},
    "services_still_running": {"services": (("dnsmasq", True), ("dropbear", False))},
    "interfaces_still_up": {"interfaces": (("lan", True), ("wan", False))},
    "wan_not_lost": {"wan": "down"},
    "ap_interfaces_kept": {"ap_interfaces": 1},
    "dependants_not_degraded": {"dependants_degraded": 1},
    "no_new_incidents": {"other_incidents": ("inc-9",)},
    "no_unplanned_reboot": {"uptime_s": 100},
    "radio_clients_within_tolerance": {
        "radio_clients": (("phy0-ap0", 4), ("phy1-ap0", 4))
    },
}


@pytest.mark.parametrize("guard", GUARDS_LITERAL)
@pytest.mark.parametrize("call", [CallResult.OK, CallResult.REJECTED])
def test_each_guard_worse_is_a_new_fault(guard: str, call: Any) -> None:
    r = run(call=call, a=after(**WORSE_AFTER[guard]))
    assert r.result is VR.NEW_FAULT
    assert r.reasons == (f"{guard}.worse",)
    assert r.escalate is True and r.final is True
    assert r.criterion("incident_cleared").comparison is C.IMPROVED
    # worse also wins over an unknown elsewhere
    r = run(
        call=call,
        a=after(clients=u(), **WORSE_AFTER[guard])
        if guard != "clients_within_tolerance"
        else after(wan=u(), **WORSE_AFTER[guard]),
    )
    assert r.result is VR.NEW_FAULT


def test_worse_target_state_is_a_new_fault() -> None:
    r = run(
        a=after(services=(("dnsmasq", False), ("dropbear", True), ("firewall", False)))
    )
    assert r.result is VR.NEW_FAULT
    assert r.reasons == ("service_running.worse",)
    # the target is not counted twice by the services guard
    assert r.criterion("services_still_running").comparison is C.HELD
    # a service missing from the after-list stopped
    r = run(a=after(services=(("dnsmasq", True),)))
    assert r.reasons == ("services_still_running.worse",)
    assert (
        r.criterion("services_still_running").before,
        r.criterion("services_still_running").after,
    ) == (1, 0)


@pytest.mark.parametrize(
    ("b", "a", "comparison"),
    [
        (10, 7, C.HELD),
        (10, 6, C.WORSE),
        # a drop to 0 from any positive count is always worse
        (1, 0, C.WORSE),
        (2, 0, C.WORSE),
        (3, 0, C.WORSE),
        (50, 0, C.WORSE),
        (0, 0, C.HELD),
        # below 7 clients a loss of more than one is worse
        (2, 1, C.HELD),
        (6, 5, C.HELD),
        (6, 4, C.WORSE),
        (3, 1, C.WORSE),
        # from 7 on the old rule: more than max(2, 30 %)
        (7, 5, C.HELD),
        (7, 4, C.WORSE),
        (10, 11, C.IMPROVED),
        (100, 70, C.HELD),
        (100, 69, C.WORSE),
    ],
)
def test_client_tolerance_boundaries(b: int, a: int, comparison: C) -> None:
    r = run(b=before(clients=b), a=after(clients=a))
    assert r.criterion("clients_within_tolerance").comparison is comparison


@pytest.mark.parametrize(
    ("b", "a", "comparison", "reason"),
    [
        ("up", "up", C.HELD, "wan_held"),
        ("up", "down", C.WORSE, "wan_lost"),
        ("up", "absent", C.WORSE, "wan_lost"),
        ("down", "up", C.IMPROVED, "wan_back"),
        ("absent", "up", C.IMPROVED, "wan_back"),
        ("absent", "absent", C.HELD, "no_wan"),
        ("down", "down", C.NOT_IMPROVED, "wan_still_down"),
        ("down", "absent", C.UNKNOWN, "wan_changed_shape"),
        ("absent", "down", C.UNKNOWN, "wan_changed_shape"),
    ],
)
def test_wan_guard(b: str, a: str, comparison: C, reason: str) -> None:
    c = run(b=before(wan=b), a=after(wan=a)).criterion("wan_not_lost")
    assert (c.comparison, c.reason) == (comparison, reason)


def test_guards_that_improve_or_stay_bad_are_not_worse() -> None:
    r = run(
        b=before(
            management_path=True,
            interfaces=(("lan", True), ("wan", False)),
            services=(("dnsmasq", True), ("firewall", False)),
            dependants_degraded=2,
            other_incidents=("inc-3",),
            ap_interfaces=1,
        ),
        a=after(
            interfaces=(("lan", True), ("wan", True)),
            services=(("dnsmasq", True), ("firewall", True)),
            dependants_degraded=0,
            other_incidents=(),
            ap_interfaces=2,
        ),
    )
    assert r.result is VR.RESOLVED
    got = comparisons(r)
    assert got["interfaces_still_up"] is C.IMPROVED
    assert got["services_still_running"] is C.IMPROVED
    assert got["dependants_not_degraded"] is C.IMPROVED
    assert got["no_new_incidents"] is C.IMPROVED
    assert got["ap_interfaces_kept"] is C.IMPROVED
    # management path down before and after: not worse, but no success
    r = run(
        call=CallResult.REJECTED,
        b=before(management_path=False),
        a=after(management_path=False),
    )
    assert comparisons(r)["management_path"] is C.NOT_IMPROVED
    # cleared, but the way in is still down: never a success (review P3-10,
    # DECIDED: no write -> unknown, an executed write -> not resolved)
    assert r.result is VR.UNKNOWN and r.final is False
    assert r.reasons == ("management_path.not_improved",)
    r = run(b=before(management_path=False), a=after(management_path=False))
    assert r.result is VR.NOT_RESOLVED
    assert r.reasons == ("incident_cleared.improved", "management_path.not_improved")
    assert r.verdict_key == "action_did_not_help"
    r = run(call=CallResult.REJECTED, b=before(management_path=False))
    assert comparisons(r)["management_path"] is C.IMPROVED


def test_a_new_incident_swapped_for_an_old_one_is_still_new() -> None:
    r = run(b=before(other_incidents=("inc-3",)), a=after(other_incidents=("inc-4",)))
    assert r.result is VR.NEW_FAULT
    assert r.criterion("no_new_incidents").after == 1


# ---------------------------------------------------------------------------
# The other write types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "action", ["wifi.radio_restart", "interface.cycle", "config.restore"]
)
def test_writes_whose_effect_cannot_be_measured_are_never_resolved(action: str) -> None:
    r = run(action)
    assert r.result is VR.UNKNOWN
    assert r.credited_to_action is False
    assert r.final is False
    assert run(action, a=after(at=T0 + 3500), now=T0 + 3600).final is True
    effect = hv.WRITE_CRITERIA[action][-1]
    assert (
        r.criterion(effect).reason
        == {
            "wifi.radio_restart": "radio_restart_not_measurable",
            "interface.cycle": "interface_cycle_not_measurable",
            "config.restore": "config_version_not_tracked",
        }[action]
    )


def test_radio_restart_state_target_replaces_the_ap_guard() -> None:
    r = run("wifi.radio_restart", b=before(ap_interfaces=1), a=after(ap_interfaces=2))
    assert r.criterion("radio_aps_present").comparison is C.IMPROVED
    r = run("wifi.radio_restart", a=after(ap_interfaces=1))
    assert r.result is VR.NEW_FAULT and r.reasons == ("radio_aps_present.worse",)
    r = run("wifi.radio_restart", b=before(ap_interfaces=0), a=after(ap_interfaces=0))
    assert r.criterion("radio_aps_present").comparison is C.NOT_IMPROVED


def test_interface_cycle_target() -> None:
    r = run("interface.cycle", b=before(interfaces=(("lan", True), ("wan", False))))
    assert r.criterion("interface_up").comparison is C.IMPROVED
    assert r.criterion("interfaces_still_up").comparison is C.HELD  # target excluded
    r = run("interface.cycle", a=after(interfaces=(("lan", True), ("wan", False))))
    assert r.reasons == ("interface_up.worse",)
    r = run("interface.cycle", b=before(interfaces=(("lan", True),)))
    assert r.criterion("interface_up").reason == "interface_not_in_before"
    r = run(
        "interface.cycle",
        b=before(interfaces=(("lan", True), ("wan", False))),
        a=after(interfaces=(("lan", True), ("wan", False))),
    )
    assert r.criterion("interface_up").comparison is C.NOT_IMPROVED


def test_service_restart_of_a_service_missing_before_is_unknown() -> None:
    r = run(params=ODHCPD)
    c = r.criterion("service_running")
    assert (c.reason, c.comparison) == ("service_not_in_before", C.UNKNOWN)
    assert r.result is VR.UNKNOWN
    # even when it runs afterwards with a new pid: no "before" to compare
    a = after(
        services=(("dnsmasq", True), ("dropbear", True), ("odhcpd", True)),
        service_pids=(("dnsmasq", 100), ("dropbear", 1), ("odhcpd", 77)),
    )
    r = run(params=ODHCPD, a=a)
    assert r.criterion("service_restarted").comparison is C.IMPROVED
    assert r.criterion("service_running").comparison is C.UNKNOWN
    assert r.result is VR.UNKNOWN and r.credited_to_action is False


# ---------------------------------------------------------------------------
# Time on the safety clock, at the boundaries
# ---------------------------------------------------------------------------


def test_settle_time_boundary() -> None:
    r = run(a=after(at=T0 + 599.0), now=T0 + 599.999)
    assert r.result is VR.UNKNOWN
    assert r.reasons == ("settle_time_not_reached",) and r.final is False
    r = run(a=after(at=T0 + 600, incident_resolved_age_s=300.0), now=T0 + 600)
    assert r.result is VR.RESOLVED
    r = run(a=after(at=T0 + 599.999, incident_resolved_age_s=300.0), now=T0 + 610)
    assert r.reasons == ("after_snapshot_too_early",) and r.final is False
    r = run(a=after(at=T0 + 599.999, incident_resolved_age_s=300.0), now=T0 + 3600)
    # pinned to one outcome (review P3-10): the too-early gate, and final
    assert r.reasons == ("after_snapshot_too_early",) and r.final is True
    assert r.settle_until == T0 + 600 and r.max_wait_until == T0 + 3600


def test_settle_time_hides_a_worsening_other_than_an_early_loss() -> None:
    r = run(a=after(at=T0 + 300, clients=2), now=T0 + 300)
    assert r.result is VR.UNKNOWN and r.reasons == ("settle_time_not_reached",)
    assert r.escalate is False
    # shown as unknown: the after-facts were measured inside the settle time
    assert r.criterion("clients_within_tolerance").reason == "clients_stale_after"


def test_a_fresh_loss_of_the_way_in_or_of_wan_escalates_at_once() -> None:
    """Review P2-7: no settle time, and the gate does not override it."""
    r = run(a=after(at=T0 + 300, management_path=False), now=T0 + 300)
    assert r.result is VR.NEW_FAULT and r.escalate is True and r.final is True
    assert r.reasons == ("management_path.worse",)
    r = run(a=after(at=T0 + 1, wan="down"), now=T0 + 2)
    assert r.result is VR.NEW_FAULT and r.reasons == ("wan_not_lost.worse",)
    # also when the after-snapshot is too early for everything else
    r = run(a=after(at=T0 + 599, wan="absent"), now=T0 + 700)
    assert r.result is VR.NEW_FAULT and r.reasons == ("wan_not_lost.worse",)
    assert run(a=after(at=T0 + 599), now=T0 + 700).reasons == (
        "after_snapshot_too_early",
    )
    # a loss measured before the start is not a fresh loss after it
    r = run(a=after(at=T0 + 300, management_path=k(False, 301.0)), now=T0 + 300)
    assert r.result is VR.UNKNOWN and r.reasons == ("settle_time_not_reached",)
    assert r.criterion("management_path").reason == "management_path_stale_after"
    # a loss measured exactly at the start counts (boundary)
    r = run(a=after(at=T0 + 300, management_path=k(False, 300.0)), now=T0 + 300)
    assert r.result is VR.NEW_FAULT
    # a stale after-snapshot showing the loss stays unknown
    r = run(a=after(at=T0 + 300, management_path=False), now=T0 + 480.001)
    assert r.result is VR.UNKNOWN and r.reasons == ("after_snapshot_stale",)
    # nor does an unknown age count
    r = run(a=after(at=T0 + 300, wan=k("down", None)), now=T0 + 300)
    assert r.result is VR.UNKNOWN
    # only these two guards: a lost client count still waits
    assert hv.EARLY_LOSS == ("management_path", "wan_not_lost")


def test_max_wait_boundary() -> None:
    r = run(a=after(at=T0 + 3600, incident_resolved_age_s=300.0), now=T0 + 3600)
    assert r.result is VR.RESOLVED
    r = run(a=after(at=T0 + 3600.001, incident_resolved_age_s=300.0), now=T0 + 3600.001)
    assert r.result is VR.UNKNOWN
    assert r.reasons == ("after_snapshot_beyond_max_wait",) and r.final is True
    open_ = {
        "incident_status": "active",
        "incident_resolve_reason": "open",
        "incident_resolved_age_s": u(),
    }
    r = run(a=after(at=T0 + 3500, **open_), now=T0 + 3599.999)
    assert r.result is VR.NOT_RESOLVED and r.final is False
    r = run(a=after(at=T0 + 3500, **open_), now=T0 + 3600)
    assert r.result is VR.NOT_RESOLVED and r.final is True


def test_after_snapshot_age_boundary() -> None:
    assert run(a=after(at=T0 + 700), now=T0 + 880).result is VR.RESOLVED
    r = run(a=after(at=T0 + 700), now=T0 + 880.001)
    assert r.reasons == ("after_snapshot_stale",) and r.final is False
    r = run(a=after(at=T0 + 700), now=T0 + 721)
    assert r.result is VR.RESOLVED
    r = run(a=after(at=T0 + 730), now=T0 + 720)
    # a later snapshot may still be usable: not final (review P3-10)
    assert r.reasons == ("after_snapshot_in_future",) and r.final is False
    # boundary (review survivor G7): taken exactly now is not in the future
    assert run(a=after(at=T0 + 720), now=T0 + 720).result is VR.RESOLVED
    r = run(a=after(at=T0 + 720.001), now=T0 + 720)
    assert r.reasons == ("after_snapshot_in_future",)
    r = run(a=after(at=T0 + 3600.5), now=T0 + 3600)
    assert r.reasons == ("after_snapshot_in_future",) and r.final is True


def test_before_snapshot_boundaries() -> None:
    assert run(b=before(at=T0 - 300)).result is VR.RESOLVED
    r = run(b=before(at=T0 - 300.001))
    assert r.reasons == ("before_snapshot_stale",) and r.final is True
    assert run(b=before(at=T0)).result is VR.RESOLVED
    r = run(b=before(at=T0 + 0.001))
    assert r.reasons == ("before_snapshot_after_start",) and r.final is True
    r = run(now=T0 - 1)
    assert r.reasons == ("judged_before_start",) and r.final is True


def test_a_wall_clock_jump_neither_shortens_nor_stretches_the_waits() -> None:
    """The safety clock follows monotonic time within a run; the result
    takes safety times only."""
    w0 = 1_800_000_000.0
    c0 = hm.SafetyClock().observe(w0)
    start = c0.safe
    b = before(at=start - 5)

    def judge(clock: hm.SafetyClock) -> hv.VerifyResult:
        return run(
            b=b,
            a=after(at=clock.safe, incident_resolved_age_s=clock.safe - start),
            started=start,
            now=clock.safe,
        )

    # a day ahead after 300 real seconds: still settling
    c1 = c0.observe(w0 + 86_400, elapsed=300)
    assert c1.safe == start + 300
    assert judge(c1).reasons == ("settle_time_not_reached",)
    # two days back after 299.999 more: still settling (not stretched past)
    c2 = c1.observe(w0 - 2 * 86_400, elapsed=299.999)
    assert judge(c2).reasons == ("settle_time_not_reached",)
    c3 = c2.observe(w0 - 2 * 86_400 + 1, elapsed=0.001)
    assert c3.safe == start + 600
    assert judge(c3).result is VR.RESOLVED
    # and the maximum wait: real time only
    c4 = c3
    for wall_step in (10, -3, 7, 1):  # jumps of days, 750 real seconds each
        c4 = c4.observe(w0 + wall_step * 86_400, elapsed=750)
    assert c4.safe == start + 3600
    assert judge(c4).result is VR.RESOLVED
    c5 = c4.observe(w0, elapsed=0.002)
    assert judge(c5).reasons == ("after_snapshot_beyond_max_wait",)


# ---------------------------------------------------------------------------
# Binding and tamper detection
# ---------------------------------------------------------------------------


def _binding_of(r: hv.VerifyResult, **over: Any) -> hv.Binding:
    args = {
        "action_id": ACT,
        "action_type": "service.restart",
        "params": DNSMASQ,
        "before": before(),
        "after": after(),
        **over,
    }
    return r.check_binding(**args)


def test_the_result_is_bound_to_action_params_and_snapshots() -> None:
    r = run()
    assert _binding_of(r) is hv.Binding.VALID
    assert _binding_of(r, action_id=ACT2) is hv.Binding.OTHER_ACTION
    assert (
        _binding_of(r, action_type="router.reboot", params={})
        is hv.Binding.OTHER_ACTION
    )
    assert _binding_of(r, params=ODHCPD) is hv.Binding.OTHER_ACTION
    assert _binding_of(r, params={"service": "wpad"}) is hv.Binding.OTHER_ACTION
    assert _binding_of(r, params="dnsmasq") is hv.Binding.OTHER_ACTION
    assert _binding_of(r, before=before(clients=9)) is hv.Binding.OTHER_SNAPSHOT
    assert _binding_of(r, after=after(clients=9)) is hv.Binding.OTHER_SNAPSHOT
    assert _binding_of(r, after=after(at=AFTER_AT + 1)) is hv.Binding.OTHER_SNAPSHOT
    assert _binding_of(r, after=None) is hv.Binding.OTHER_SNAPSHOT
    assert _binding_of(r, before="x") is hv.Binding.OTHER_SNAPSHOT
    assert _binding_of(r, after=after(incident_status=u())) is hv.Binding.OTHER_SNAPSHOT
    r_none = run(a=None)
    assert _binding_of(r_none, after=None) is hv.Binding.VALID
    assert _binding_of(r_none) is hv.Binding.OTHER_SNAPSHOT


DERIVED_LITERAL = (
    "router_id",
    "incident_id",
    "attribution",
    "executed",
    "criteria",
    "result",
    "reasons",
    "final",
    "escalate",
    "credited_to_action",
    "verdict_key",
    "settle_until",
    "max_wait_until",
    "binding",
)
FORGED = {
    "router_id": R2,
    "incident_id": "inc-8",
    "attribution": hv.Attribution.NO_WRITE,
    "executed": False,
    "criteria": (),
    "result": VR.NEW_FAULT,
    "reasons": ("x",),
    "final": False,
    "escalate": True,
    "credited_to_action": False,
    "verdict_key": "cannot_tell",
    "settle_until": T0,
    "max_wait_until": T0 + 99_999,
    "binding": "0" * 64,
}


def test_derived_fields_cannot_be_passed_in() -> None:
    assert hv.VerifyResult.__dataclass_fields__.keys() >= set(DERIVED_LITERAL)
    for name in DERIVED_LITERAL:
        assert hv.VerifyResult.__dataclass_fields__[name].init is False, name
    with pytest.raises(TypeError):
        hv.VerifyResult(
            action_id=ACT,
            action_type="service.restart",
            params=DNSMASQ,
            before=before(),
            after=after(),
            started_at=T0,
            judged_at=NOW,
            result=VR.RESOLVED,
        )


@pytest.mark.parametrize("name", DERIVED_LITERAL)
def test_a_changed_derived_field_is_tampered(name: str) -> None:
    r = run()  # repaired by the action: every forgery differs from it
    assert getattr(r, name) != FORGED[name]
    object.__setattr__(r, name, FORGED[name])
    assert _binding_of(r) is hv.Binding.TAMPERED


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("action_id", ACT2),
        ("action_type", "router.reboot"),
        ("params", MappingProxyType({"service": "odhcpd"})),
        ("params", {"service": "dnsmasq"}),
        ("call_result", None),
        ("call_result", "ok"),
        ("started_at", T0 - 1),
        ("judged_at", NOW + 1),
        ("after", None),
        ("before", "x"),
    ],
)
def test_a_changed_input_is_tampered(name: str, value: Any) -> None:
    r = run()
    object.__setattr__(r, name, value)
    assert _binding_of(r) is hv.Binding.TAMPERED


def test_a_shared_fact_changed_in_place_is_tampered() -> None:
    a = after()
    r = run(a=a)
    object.__setattr__(a.management_path, "value", False)
    assert _binding_of(r, after=after()) is hv.Binding.TAMPERED


def test_a_snapshot_field_changed_in_place_is_tampered() -> None:
    r = run()
    object.__setattr__(r.after, "taken_at", AFTER_AT + 5)
    assert _binding_of(r, after=after(at=AFTER_AT + 5)) is hv.Binding.TAMPERED
    r = run()
    object.__setattr__(r.after, "clients", "many")
    assert _binding_of(r) is hv.Binding.TAMPERED


def test_a_pinned_constant_changed_at_run_time_is_tampered(monkeypatch) -> None:
    r = run()
    monkeypatch.setattr(hv, "VERIFY_SETTLE_S", 60)
    assert _binding_of(r) is hv.Binding.TAMPERED


def test_replace_re_derives() -> None:
    r = run()
    worse = dataclasses.replace(r, after=after(management_path=False))
    assert worse.result is VR.NEW_FAULT and worse.binding != r.binding
    with pytest.raises(TypeError):
        dataclasses.replace(r, result=VR.RESOLVED)


def test_known_limit_a_fully_consistent_forgery_is_not_seen() -> None:
    """Documented limit (docs §7.2): no secret, so inputs and derived
    fields changed alike are consistent and pass."""
    r = run(a=after(management_path=False))
    assert r.result is VR.NEW_FAULT
    good = run()
    for name in ("after", *DERIVED_LITERAL):
        object.__setattr__(r, name, getattr(good, name))
    assert r.result is VR.RESOLVED
    assert _binding_of(r) is hv.Binding.VALID


def test_the_binding_digest_covers_every_input() -> None:
    base = run().binding
    variants = [
        run(action_id=ACT2),
        run(call=CallResult.INCONCLUSIVE),
        run(started=T0 + 1, b=before(at=T0 - 10)),
        run(now=NOW + 1),
        run(b=before(clients=11)),
        run(a=after(clients=11)),
        run(b=before(clients=hp.known(10, "other_source"))),
        run(params=ODHCPD),
        run("router.reboot", params={}),
    ]
    digests = {v.binding for v in variants}
    assert base not in digests and len(digests) == len(variants)


@pytest.mark.parametrize(
    ("name", "value"), [("VERIFY_SETTLE_S", 650), ("VERIFY_MAX_WAIT_S", 3000)]
)
def test_the_binding_digest_covers_the_time_constants(monkeypatch, name, value) -> None:
    """Same inputs, same class, other constants: another digest (a result
    judged under other waits is never taken for this one)."""
    base = run()
    monkeypatch.setattr(hv, name, value)
    other = run()
    assert other.result is base.result is VR.RESOLVED
    assert other.binding != base.binding


# ---------------------------------------------------------------------------
# Validation (exact types, bounds)
# ---------------------------------------------------------------------------


class _StrSub(str):
    pass


class _SnapSub(hv.VerifySnapshot):
    pass


@pytest.mark.parametrize(
    "over",
    [
        {"action_id": "rem_" + "A" * 32},
        {"action_id": "act_" + "a" * 32},
        {"action_id": _StrSub(ACT)},
        {"action_type": "shell.run"},
        {"action_type": "service.restart", "params": {"service": "wpad"}},
        {"action_type": "service.restart", "params": {}},
        {"action_type": "service.restart", "params": "dnsmasq"},
        {"call_result": "ok"},
        {"started_at": float("nan")},
        {"started_at": float("inf")},
        {"started_at": True},
        {"judged_at": -1.0},
        {"judged_at": "1"},
        {"judged_at": hm.TIME_MAX + 1},
    ],
)
def test_bad_inputs_are_refused(over: dict) -> None:
    args = {
        "action_id": ACT,
        "action_type": "service.restart",
        "params": DNSMASQ,
        "call_result": CallResult.OK,
        "before": before(),
        "after": after(),
        "started_at": T0,
        "judged_at": NOW,
        **over,
    }
    with pytest.raises(hv.VerifyError):
        hv.verify(**args)


def test_snapshots_of_other_routers_or_incidents_or_types_are_refused() -> None:
    with pytest.raises(hv.VerifyError):
        run(a=after(router=R2))
    with pytest.raises(hv.VerifyError):
        run(a=after(incident="inc-8"))
    sub = _SnapSub(router_id=R1, incident_id=INC, taken_at=AFTER_AT)
    with pytest.raises(hv.VerifyError):
        run(a=sub)
    with pytest.raises(hv.VerifyError):
        run(
            b=SimpleNamespace(**before().__dict__)
            if hasattr(before(), "__dict__")
            else {"x": 1}
        )


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("management_path", 1),
        ("clients", -1),
        ("clients", True),
        ("clients", 1.0),
        ("clients", 2**53 + 1),
        ("services", (("dnsmasq", 1),)),
        ("services", (("dnsmasq", True), ("dnsmasq", False))),
        ("services", (("dns masq", True),)),
        ("services", (("-dnsmasq", True),)),
        ("services", (("x" * 65, True),)),
        ("services", ("dnsmasq",)),
        ("service_pids", (("dnsmasq", 0),)),
        ("service_pids", (("dnsmasq", True),)),
        ("service_pids", (("dnsmasq", 1.5),)),
        ("interfaces", (("lan", "up"),)),
        ("interfaces", (("la n", True),)),
        ("radio_clients", (("phy0-ap0", -1),)),
        ("radio_clients", (("phy0-ap0", True),)),
        ("radio_clients", (("phy0-ap0", 1), ("phy0-ap0", 2))),
        ("radio_clients", (("phy 0", 1),)),
        ("radio_clients", ("phy0-ap0",)),
        ("wan", "sideways"),
        ("ap_interfaces", -2),
        ("incident_resolved_age_s", -0.5),
        ("incident_resolved_age_s", True),
        ("other_incidents", ("inc-1", "inc-1")),
        ("other_incidents", ("INC 1",)),
        ("other_incidents", "inc-1"),
        ("log_ok", "yes"),
    ],
)
def test_bad_fact_shapes_are_refused(name: str, value: Any) -> None:
    with pytest.raises((hv.VerifyError, hp.PreflightError)):
        before(**{name: k(value)})


def test_snapshot_fields_are_validated_exactly() -> None:
    with pytest.raises(hv.VerifyError):
        snap(router="rtr_" + "Z" * 32)
    with pytest.raises(hv.VerifyError):
        snap(router=_StrSub(R1))
    with pytest.raises(hv.VerifyError):
        snap(incident="192.168.1.1")
    with pytest.raises(hv.VerifyError):
        snap(incident="02:00:00:00:0a:0a")
    with pytest.raises(hv.VerifyError):
        snap(incident="")
    with pytest.raises(hv.VerifyError):
        snap(at=float("nan"))
    with pytest.raises(hv.VerifyError):
        snap(at=-1)

    class FactSub(hp.Fact):
        __slots__ = ()

    with pytest.raises(hv.VerifyError):
        before(clients=FactSub(value=1, source="test"))
    with pytest.raises(hv.VerifyError):
        hv.VerifySnapshot(
            router_id=R1,
            incident_id=INC,
            taken_at=1.0,
            clients=SimpleNamespace(value=1, source="t", reason=None, age_s=None),
        )
    # replace runs the checks again
    with pytest.raises(hv.VerifyError):
        dataclasses.replace(before(), wan=k("sideways"))
    # a default fact is unknown, never known
    s = hv.VerifySnapshot(router_id=R1, incident_id=INC, taken_at=1.0)
    assert all(
        f.value is None and f.reason == "not_collected" for _, f in s.fact_items()
    )


@pytest.mark.parametrize(
    "over",
    [
        {"criterion": "made_up"},
        {"role": hv.Role.GUARD},
        {"role": "primary"},
        {"comparison": "improved"},
        {"reason": "Bad Reason"},
        {"reason": "a:b"},
        {"before": "dnsmasq"},
        {"after": -1},
        {"after": 2**53 + 1},
        {"after": 1.5},
        {"before": ("active",)},
    ],
)
def test_criterion_validation(over: dict) -> None:
    args = {
        "criterion": "incident_cleared",
        "role": hv.Role.PRIMARY,
        "comparison": C.IMPROVED,
        "reason": "incident_cleared_measured",
        "before": "active",
        "after": "resolved",
        **over,
    }
    with pytest.raises(hv.VerifyError):
        hv.Criterion(**args)


def test_params_are_read_once_and_frozen() -> None:
    class Flaky(dict):
        reads = 0

        def items(self):  # type: ignore[override]
            Flaky.reads += 1
            return super().items()

    r = run(params=Flaky(DNSMASQ))
    assert isinstance(r.params, MappingProxyType) and dict(r.params) == DNSMASQ
    with pytest.raises(TypeError):
        r.params["service"] = "odhcpd"  # type: ignore[index]


# ---------------------------------------------------------------------------
# No names, addresses or secrets in a result
# ---------------------------------------------------------------------------


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k_, v in value.items() for s in (*_strings(k_), *_strings(v))]
    if isinstance(value, list | tuple):
        return [s for v in value for s in _strings(v)]
    return []


def test_a_result_carries_codes_counts_and_ids_only() -> None:
    names = (("guestzone7", True), ("lan", True))
    services = (("dnsmasq", True), ("mycustomsvc", True))
    b = before(interfaces=names, services=services)
    a = after(interfaces=names, services=services)
    for r in (
        run(b=b, a=a),
        run(b=b, a=after(interfaces=(("lan", True),), services=services)),
    ):
        blob = r.to_dict()
        strings = _strings(blob)
        assert "guestzone7" not in repr(blob) and "mycustomsvc" not in repr(blob)
        allowed = (
            set(hv.CRITERIA)
            | hv.VERDICT_KEYS
            | hv.VALUE_CODES
            | {v.value for v in VR}
            | {v.value for v in hv.Attribution}
            | {v.value for v in hv.Comparison}
            | {v.value for v in hv.Role}
            | {v.value for v in CallResult}
            | {ACT, R1, INC, "service.restart", "service", "dnsmasq", r.binding}
            | set(blob)
            | {k_ for c in blob["criteria"] for k_ in c}
        )
        for s in strings:
            assert (
                s in allowed or s in r.reasons or s in {c.reason for c in r.criteria}
            ), s
        model = r.to_verification().to_dict()
        assert "guestzone7" not in repr(model) and "mycustomsvc" not in repr(model)


def test_to_verification_is_a_valid_model_part() -> None:
    r = run()
    v = r.to_verification()
    assert type(v) is hm.Verification
    assert v.result is VR.RESOLVED
    assert hm.Verification.from_dict(v.to_dict()) == v
    assert [c.check for c in v.checks] == list(comparisons(r))
    outcome = {c.check: c.outcome.value for c in v.checks}
    assert outcome["incident_cleared"] == "pass"
    assert outcome["service_running"] == "pass"  # held
    r = run(a=after(management_path=False, wan=u()))
    outcome = {c.check: c.outcome.value for c in r.to_verification().checks}
    assert outcome["management_path"] == "fail"
    assert outcome["wan_not_lost"] == "unknown"
    assert r.to_verification().before["management_path"] is True
    assert r.to_verification().after["management_path"] is False
    assert run(a=None).to_verification().checks == ()


def test_to_dict_shape() -> None:
    d = run().to_dict()
    assert list(d) == [
        "action_id",
        "action_type",
        "params",
        "call_result",
        "router_id",
        "incident_id",
        "result",
        "attribution",
        "executed",
        "verdict_key",
        "credited_to_action",
        "final",
        "escalate",
        "reasons",
        "criteria",
        "started_at",
        "judged_at",
        "settle_until",
        "max_wait_until",
        "before_taken_at",
        "after_taken_at",
        "binding",
    ]
    assert d["result"] == "resolved" and d["call_result"] == "ok"
    assert d["before_taken_at"] == BEFORE_AT and d["after_taken_at"] == AFTER_AT
    assert run(call=CallResult.REJECTED, a=None).to_dict()["after_taken_at"] is None


# ---------------------------------------------------------------------------
# Random scenarios with an oracle written from the inputs
# ---------------------------------------------------------------------------


def _maybe(rng: random.Random, value: Any, p: float = 0.08) -> Any:
    return u() if rng.random() < p else value


EARLY_AT = T0 + 300  # an after-snapshot inside the settle time
EARLY_NOW = T0 + 320


def _random_pair(
    rng: random.Random, p_change: float = 0.07, *, timing: bool = False
) -> tuple[hv.VerifySnapshot, hv.VerifySnapshot, float]:
    """A before-side drawn at random, and an after-side that mostly repeats
    it: each fact changes with ``p_change`` and is unknown with 3 %.

    ``timing``: also draw fact ages (some too old, some unknown), an early
    after-snapshot judged inside the settle time, a wall-clock jump, and
    how long the clearing held. Returns (before, after, judged_at)."""

    def pick(*options: Any) -> Any:
        return rng.choice(options)

    def services(running: bool) -> tuple:
        return (("dnsmasq", running), ("dropbear", rng.random() < 0.95))

    def pids(running: bool) -> tuple:
        return ((("dnsmasq", pick(100, 200)),) if running else ()) + (("dropbear", 1),)

    running = rng.random() < 0.7
    b = {
        "management_path": rng.random() < 0.95,
        "clients": rng.randint(0, 12),
        "radio_clients": (("phy0-ap0", rng.randint(0, 8)), ("phy1-ap0", 4)),
        "services": services(running),
        "service_pids": pids(running),
        "interfaces": (("lan", True), ("wan", rng.random() < 0.9)),
        "wan": pick("up", "up", "up", "down", "absent"),
        "ap_interfaces": pick(0, 1, 2, 2),
        "uptime_s": 5000,
        "log_ok": rng.random() < 0.8,
        "dependants_degraded": pick(0, 0, 0, 1),
        "incident_status": pick("active", "active", "acknowledged", "resolved"),
        "incident_reopen_count": 0,
        "incident_resolve_reason": "open",
        "incident_resolved_age_s": u("incident_not_resolved"),
        "other_incidents": pick((), (), (), ("inc-3",)),
    }
    status = pick("resolved", "resolved", "active", "acknowledged", "ignored")
    running_after = rng.random() < 0.85
    a = {
        **b,
        "services": services(running_after),
        "service_pids": pids(running_after),
        "uptime_s": 5700,
        "incident_status": status,
        "incident_resolve_reason": pick("cleared", "cleared", "quiet", "no_data")
        if status == "resolved"
        else "open",
        "incident_resolved_age_s": pick(10.0, 299.0, 300.0, 300.0, 500.0, 699.0, 800.0)
        if status == "resolved"
        else u("incident_not_resolved"),
    }
    changes = {
        "management_path": lambda: rng.random() < 0.5,
        "clients": lambda: rng.randint(0, 12),
        "radio_clients": lambda: pick(
            (("phy0-ap0", rng.randint(0, 8)), ("phy1-ap0", rng.randint(0, 6))),
            (("phy1-ap0", 4),),
        ),
        "interfaces": lambda: (("lan", True), ("wan", rng.random() < 0.5)),
        "wan": lambda: pick("up", "down", "absent"),
        "ap_interfaces": lambda: pick(0, 1, 2, 3),
        "uptime_s": lambda: pick(100, 4999, 5000),
        "log_ok": lambda: rng.random() < 0.5,
        "dependants_degraded": lambda: pick(0, 1, 2),
        "incident_reopen_count": lambda: 1,
        "other_incidents": lambda: pick((), ("inc-3",), ("inc-4",), ("inc-3", "inc-4")),
    }
    for name, draw in changes.items():
        if rng.random() < p_change:
            a[name] = draw()
    b = {n: _maybe(rng, v, 0.03) for n, v in b.items()}
    a = {n: _maybe(rng, v, 0.03) for n, v in a.items()}
    a_at, now = AFTER_AT, NOW
    wall_b, wall_a = WALL0 + BEFORE_AT, WALL0 + AFTER_AT
    if timing:
        if rng.random() < 0.15:
            a_at, now = EARLY_AT, EARLY_NOW
        wall_a = WALL0 + a_at
        if rng.random() < 0.04:
            wall_a = pick(None, wall_a + 1.5, wall_a - 1.5, wall_a + 1.0)
        if rng.random() < 0.02:
            wall_b = None

        def age_b() -> float | None:
            # 0..300 s before the start is fine; older or unknown is not
            return pick(0.0, 0.0, 0.0, 0.0, 290.0, 291.0, 400.0, None)

        def age_a() -> float | None:
            # measured after the settle time / after the start / before it
            return pick(0.0, 0.0, 0.0, 0.0, 50.0, 200.0, 701.0, None)

        b = {
            n: v if isinstance(v, hp.Fact) or rng.random() > 0.08 else k(v, age_b())
            for n, v in b.items()
        }
        a = {
            n: v if isinstance(v, hp.Fact) or rng.random() > 0.08 else k(v, age_a())
            for n, v in a.items()
        }
    return (
        snap(b, at=BEFORE_AT, wall=wall_b),
        snap(a, at=a_at, wall=wall_a),
        now,
    )


# What each writing action targets in PARAMS (literal, not from the module).
_TARGET = {"service.restart": "dnsmasq", "interface.cycle": "wan"}


def _val(s: hv.VerifySnapshot, name: str, earliest: float, latest: Any) -> Any:
    """The value of a fact if it is known and measured in [earliest,
    latest] (``latest`` None: no upper limit), else None."""
    fact = getattr(s, name)
    if fact.value is None or fact.age_s is None or fact.age_s < 0:
        return None
    measured = s.taken_at - fact.age_s
    if measured < earliest or (latest is not None and measured > latest):
        return None
    return fact.value


def _bv(b: hv.VerifySnapshot, name: str) -> Any:
    return _val(b, name, T0 - 300, T0)


def _av(a: hv.VerifySnapshot, name: str) -> Any:
    return _val(a, name, T0 + 600, None)


def _oracle_incident(b: hv.VerifySnapshot, a: hv.VerifySnapshot) -> str:
    """ "cleared", "open" or "unknown" for the target incident."""
    status_b, status_a = _bv(b, "incident_status"), _av(a, "incident_status")
    if status_b not in ("active", "acknowledged") or status_a is None:
        return "unknown"
    reopen_b = _bv(b, "incident_reopen_count")
    reopen_a = _av(a, "incident_reopen_count")
    if reopen_b is None or reopen_a is None:
        return "unknown"
    if reopen_a > reopen_b or status_a in ("active", "acknowledged"):
        return "open"  # recurred, or still open
    if status_a != "resolved":
        return "unknown"
    how = _av(a, "incident_resolve_reason")
    age = _av(a, "incident_resolved_age_s")
    if how is None or age is None:
        return "unknown"
    if b.wall_at is None or a.wall_at is None:
        return "unknown"
    if abs((a.wall_at - b.wall_at) - (a.taken_at - b.taken_at)) > 1.0:
        return "unknown"  # the wall clock jumped
    if a.taken_at - age < T0:
        return "unknown"  # cleared before the action
    if how == "quiet" and _av(a, "log_ok") is not True:
        return "unknown"
    if how not in ("cleared", "quiet"):
        return "unknown"
    if age - a.incident_status.age_s < 300:
        return "unknown"  # the clearing has not held 300 s yet
    return "cleared"


def _client_worse(before: int, after: int) -> bool:
    if before > 0 and after == 0:
        return True
    allowed = 1 if before < 7 else max(2, before * 30 // 100)
    return before - after > allowed


def _oracle_guard(
    guard: str, action: str, wrote: bool, b: hv.VerifySnapshot, a: Any
) -> str:
    """ "worse", "bad" (bad on both sides), "unknown" or "ok"; ``a`` maps a
    fact name to its after-value (None if unusable)."""
    fact = {
        "management_path": "management_path",
        "clients_within_tolerance": "clients",
        "radio_clients_within_tolerance": "radio_clients",
        "services_still_running": "services",
        "interfaces_still_up": "interfaces",
        "wan_not_lost": "wan",
        "ap_interfaces_kept": "ap_interfaces",
        "dependants_not_degraded": "dependants_degraded",
        "no_new_incidents": "other_incidents",
        "no_unplanned_reboot": "uptime_s",
    }[guard]
    bv, av = _bv(b, fact), a(fact)
    if bv is None or av is None:
        return "unknown"
    if guard == "management_path":
        return "worse" if bv and not av else "bad" if not av else "ok"
    if guard == "clients_within_tolerance":
        return "worse" if _client_worse(bv, av) else "ok"
    if guard == "radio_clients_within_tolerance":
        after = dict(av)
        lost = any(_client_worse(n, after.get(r, 0)) for r, n in bv)
        return "worse" if lost else "ok"
    if guard in ("services_still_running", "interfaces_still_up"):
        skip = _TARGET.get(action) if wrote else None
        after = dict(av)
        lost = any(on and after.get(n) is not True for n, on in bv if n != skip)
        return "worse" if lost else "ok"
    if guard == "wan_not_lost":
        if bv == "up":
            return "ok" if av == "up" else "worse"
        if av == "up" or bv == av == "absent":
            return "ok"
        return "bad" if bv == av == "down" else "unknown"
    if guard == "ap_interfaces_kept":
        return "worse" if av < bv else "ok"
    if guard == "dependants_not_degraded":
        return "worse" if av > bv else "bad" if av > 0 else "ok"
    if guard == "no_new_incidents":
        return "worse" if set(av) - set(bv) else "bad" if av else "ok"
    return "worse" if av < bv else "ok"  # no_unplanned_reboot


def _oracle_target(
    action: str, b: hv.VerifySnapshot, a: hv.VerifySnapshot
) -> tuple[str, str]:
    """(state, effect) of an executed write: state "worse", "improved",
    "held", "bad", "unknown" or "none"; effect "seen", "not_seen" or
    "unknown"."""

    def av(name: str) -> Any:
        return _av(a, name)

    if action == "service.restart":
        bs, as_ = _bv(b, "services"), av("services")
        if bs is None or as_ is None or "dnsmasq" not in dict(bs):
            state = "unknown"
        else:
            on_b, on_a = dict(bs)["dnsmasq"], dict(as_).get("dnsmasq") is True
            state = (
                "worse"
                if on_b and not on_a
                else "improved"
                if on_a and not on_b
                else "held"
                if on_b
                else "bad"
            )
        pb, pa = _bv(b, "service_pids"), av("service_pids")
        if pb is None or pa is None:
            return state, "unknown"
        before = {p for n, p in pb if n == "dnsmasq"}
        after = {p for n, p in pa if n == "dnsmasq"}
        return state, "seen" if after and not after & before else "not_seen"
    if action == "interface.cycle":
        bi, ai = _bv(b, "interfaces"), av("interfaces")
        if bi is None or ai is None or "wan" not in dict(bi):
            return "unknown", "unknown"
        on_b, on_a = dict(bi)["wan"], dict(ai).get("wan") is True
        state = (
            "worse"
            if on_b and not on_a
            else "improved"
            if on_a and not on_b
            else "held"
            if on_b
            else "bad"
        )
        return state, "unknown"  # a cycle is not measurable from memory
    if action == "wifi.radio_restart":
        bc, ac = _bv(b, "ap_interfaces"), av("ap_interfaces")
        if bc is None or ac is None:
            return "unknown", "unknown"
        state = (
            "worse"
            if ac < bc
            else "improved"
            if ac > bc
            else "held"
            if ac > 0
            else "bad"
        )
        return state, "unknown"
    if action == "router.reboot":
        ub, ua = _bv(b, "uptime_s"), av("uptime_s")
        if ub is None or ua is None:
            return "none", "unknown"
        return "none", "seen" if ua < ub else "not_seen"
    return "none", "unknown"  # config.restore: the version is not tracked


def _oracle(
    action: str,
    b: hv.VerifySnapshot,
    a: hv.VerifySnapshot,
    call: Any,
    now: float = NOW,
) -> VR:
    """The expected class from the inputs and the rules of the package
    order and the PR #83 review (not from the module)."""
    writes = action in WRITES_LITERAL
    wrote = writes and call in (CallResult.OK, CallResult.INCONCLUSIVE)
    replaced = {
        "wifi.radio_restart": ("ap_interfaces_kept",),
        "router.reboot": ("no_unplanned_reboot",),
    }.get(action, ())
    guards = [g for g in GUARDS_LITERAL if not (wrote and g in replaced)]
    # a fresh, measured loss of the way in or of WAN: at once (P2-7)
    early = any(
        _oracle_guard(g, action, wrote, b, lambda n: _val(a, n, T0, None)) == "worse"
        for g in ("management_path", "wan_not_lost")
    )
    if not early and (now < T0 + 600 or a.taken_at < T0 + 600):
        return VR.UNKNOWN  # inside the settle time
    if a.taken_at > now or now - a.taken_at > 180:
        return VR.UNKNOWN
    if early:
        return VR.NEW_FAULT
    seen = {g: _oracle_guard(g, action, wrote, b, lambda n: _av(a, n)) for g in guards}
    incident = _oracle_incident(b, a)
    state, effect = _oracle_target(action, b, a) if wrote else ("none", "seen")
    if "worse" in seen.values() or state == "worse":
        return VR.NEW_FAULT
    if "unknown" in seen.values() or incident == "unknown":
        return VR.UNKNOWN
    if state == "unknown" or effect == "unknown":
        return VR.UNKNOWN
    cleared = incident == "cleared"
    if effect == "not_seen":
        return VR.UNKNOWN if cleared else VR.NOT_RESOLVED
    if cleared and "bad" in seen.values():
        return VR.NOT_RESOLVED if wrote else VR.UNKNOWN
    if cleared and state != "bad":
        return VR.RESOLVED
    if cleared or state == "improved":
        return VR.PARTIAL
    return VR.NOT_RESOLVED


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
@pytest.mark.parametrize("action", ACTIONS_LITERAL)
def test_random_scenarios_against_the_oracle(action: str, seed: int) -> None:
    """Every action type, with ages, early losses, wall jumps and the
    clearing hold drawn at random (review PR #83, P3-10)."""
    rng = random.Random(f"{action}/{seed}")
    seen: dict[VR, int] = {}
    for _ in range(800):
        b, a, now = _random_pair(rng, timing=True)
        call = not_run(
            action,
            rng.choice(
                [None, CallResult.OK, CallResult.INCONCLUSIVE, CallResult.REJECTED]
            ),
        )
        r = run(action, call=call, b=b, a=a, now=now)
        expected = _oracle(action, b, a, call, now)
        assert r.result is expected, (b, a, call, now, r.reasons)
        seen[r.result] = seen.get(r.result, 0) + 1
        # the hard rules, again on every case
        if r.result is VR.RESOLVED:
            got = comparisons(r)
            assert got["incident_cleared"] is C.IMPROVED
            assert C.UNKNOWN not in got.values() and C.WORSE not in got.values()
            assert C.NOT_IMPROVED not in (
                got[g] for g in got if hv.ROLE_OF[g] is hv.Role.GUARD
            )
            for cid, comparison in got.items():
                if hv.ROLE_OF[cid] is hv.Role.STATE:
                    assert comparison in (C.IMPROVED, C.HELD), cid
                if hv.ROLE_OF[cid] is hv.Role.EFFECT:
                    assert comparison is C.IMPROVED, cid
        assert r.escalate is (r.result is VR.NEW_FAULT)
        # the primary is never "held" (it changed or it did not)
        if r.criteria:
            assert r.criterion("incident_cleared").comparison is not C.HELD
        assert r.credited_to_action is (
            r.result is VR.RESOLVED
            and call is CallResult.OK
            and action in WRITES_LITERAL
        )


# What the random runs of each action type can reach (literal): a write
# whose effect memory cannot measure never resolves or is partial.
_REACHABLE = {
    "observe.evaluate": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "diag.refresh": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "diag.ha_probes": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "service.restart": set(VR),
    "wifi.radio_restart": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "router.reboot": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "config.restore": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
    "interface.cycle": {VR.RESOLVED, VR.NOT_RESOLVED, VR.UNKNOWN, VR.NEW_FAULT},
}


@pytest.mark.parametrize("action", ACTIONS_LITERAL)
def test_the_random_runs_reach_every_class_they_can(action: str) -> None:
    """The oracle runs above are not vacuous: across the seeds every class
    the action can reach was drawn."""
    seen: set[VR] = set()
    for seed in (1, 2, 3, 4, 5):
        rng = random.Random(f"{action}/{seed}")
        for _ in range(800):
            b, a, now = _random_pair(rng, timing=True)
            call = not_run(
                action,
                rng.choice(
                    [None, CallResult.OK, CallResult.INCONCLUSIVE, CallResult.REJECTED]
                ),
            )
            seen.add(run(action, call=call, b=b, a=a, now=now).result)
    assert seen == _REACHABLE[action]


# ---------------------------------------------------------------------------
# The snapshot builder: memory only, zero router calls
# ---------------------------------------------------------------------------

W0 = 1_800_000_000.0


class FakeNI:
    def __init__(
        self, incidents: list[Any] | None = None, last_now: float = W0
    ) -> None:
        self.loaded = True
        self.topology = Topology(
            uplinks={"e2": Uplink(parent="e1"), "e3": Uplink(parent="e2")},
            gateways=frozenset({"e1"}),
        )
        self.incidents = incidents or []
        self.machine = SimpleNamespace(
            peek=lambda: list(self.incidents), last_now=last_now
        )


def inc(
    id_: str = INC,
    status: str = "active",
    *,
    routers: tuple[str, ...] = ("e1",),
    severity: str = "warning",
    parent: str | None = None,
    reopen: int = 0,
    resolve_reason: str | None = None,
    resolved_at: float | None = None,
) -> Any:
    return SimpleNamespace(
        id=id_,
        status=SimpleNamespace(value=status),
        routers=list(routers),
        severity=SimpleNamespace(value=severity),
        parent_id=parent,
        reopen_count=reopen,
        resolve_reason=resolve_reason,
        resolved_at=resolved_at,
    )


def fake_coordinator(**data: Any) -> Any:
    base = {
        "last_seen": W0 - 5,
        "client_count": 3,
        "services": [
            {"name": "dnsmasq", "running": True, "enabled": True},
            {"name": "firewall", "running": False, "enabled": True},
        ],
        "service_instances": {"dnsmasq": {"i1": {"pid": 42, "running": True}}},
        "network_interfaces": [
            {"logical_name": "lan", "status": "up", "ipv4_addr": "192.0.2.1"},
            {"logical_name": "wan", "status": "down"},
        ],
        "vlans_stale": False,
        "wan_status": {"wan_found": True, "ipv4": "198.51.100.1"},
        "wan_connected": True,
        "ap_interfaces": [{"ifname": "phy0-ap0"}, {"ifname": "phy1-ap0"}],
        "uptime": 9000,
        "log_status": "ok",
        "router_info": {"hostname": "kitchen-router"},
        "clients": [
            {
                "mac": "02:00:00:00:0a:0a",
                "hostname": "phone-of-anna",
                "radio": "phy0-ap0",
            }
        ],
        **data,
    }
    return SimpleNamespace(
        last_update_success=True,
        update_interval=SimpleNamespace(total_seconds=lambda: 60.0),
        data=SimpleNamespace(**base),
    )


def build(
    coordinator: Any = None,
    ni: Any = None,
    *,
    entry_id: str | None = "e1",
    wall: float = W0,
    safe: float = T0,
    incident_id: str = INC,
) -> hv.VerifySnapshot:
    src = hp.FactSources(store=None, entry_id=entry_id, coordinator=coordinator, ni=ni)
    s = hv.snapshot_from_sources(src, R1, incident_id, safe_now=safe, wall_now=wall)
    assert s is not None
    return s


def test_builder_reads_what_is_in_memory() -> None:
    ni = FakeNI(
        [
            inc(),
            inc("inc-9", routers=("e1",), severity="critical"),
            inc("inc-10", routers=("e1",), severity="info"),
            inc("inc-11", routers=("e2",)),
            inc("inc-12", routers=("e1",), parent="inc-9"),
            inc("inc-13", status="resolved", routers=("e1",)),
            inc("inc-14", routers=("e3",), severity="info"),
        ]
    )
    s = build(fake_coordinator(), ni)
    v = {n: f.value for n, f in s.fact_items()}
    assert v == {
        "management_path": True,
        "clients": 3,
        "radio_clients": (("phy0-ap0", 1),),
        "services": (("dnsmasq", True), ("firewall", False)),
        "service_pids": (("dnsmasq", 42),),
        "interfaces": (("lan", True), ("wan", False)),
        "wan": "up",
        "ap_interfaces": 2,
        "uptime_s": 9000,
        "log_ok": True,
        "dependants_degraded": 2,  # e2 and e3 behind e1 carry active roots
        "incident_status": "active",
        "incident_reopen_count": 0,
        "incident_resolve_reason": "open",
        "incident_resolved_age_s": None,
        "other_incidents": ("inc-9",),
    }
    assert s.incident_resolved_age_s.reason == "incident_not_resolved"
    assert s.taken_at == T0
    assert s.management_path.age_s == 5.0
    blob = repr(s.to_dict())
    for secret in ("192.0.2.1", "198.51.100.1", "02:00:00:00:0a:0a", "kitchen", "anna"):
        assert secret not in blob


def test_builder_resolved_incident_and_age() -> None:
    ni = FakeNI(
        [inc(status="resolved", resolve_reason="cleared", resolved_at=W0 - 250)]
    )
    s = build(fake_coordinator(), ni)
    assert s.incident_resolve_reason.value == "cleared"
    assert s.incident_resolved_age_s.value == 250.0
    ni = FakeNI([inc(status="resolved", resolve_reason=None, resolved_at=W0 - 1)])
    assert (
        build(fake_coordinator(), ni).incident_resolve_reason.reason
        == "resolve_reason_unknown"
    )
    ni = FakeNI([inc(status="resolved", resolve_reason="cleared", resolved_at=None)])
    assert (
        build(fake_coordinator(), ni).incident_resolved_age_s.reason
        == "resolved_at_unknown"
    )
    ni = FakeNI([inc(status="resolved", resolve_reason="cleared", resolved_at=W0 + 5)])
    assert (
        build(fake_coordinator(), ni).incident_resolved_age_s.reason
        == "wall_clock_behind_ni"
    )
    ni = FakeNI(
        [inc(status="resolved", resolve_reason="cleared", resolved_at=W0 + 0.5)]
    )
    assert build(fake_coordinator(), ni).incident_resolved_age_s.value == 0.0
    ni = FakeNI([inc(status="ignored", reopen=2)])
    s = build(fake_coordinator(), ni)
    assert (s.incident_status.value, s.incident_reopen_count.value) == ("ignored", 2)
    ni = FakeNI([inc(status="Bad Status")])
    assert build(fake_coordinator(), ni).incident_status.reason == "status_unknown"
    ni = FakeNI([SimpleNamespace(**{**inc().__dict__, "reopen_count": -1})])
    assert (
        build(fake_coordinator(), ni).incident_reopen_count.reason
        == "reopen_count_unknown"
    )
    assert (
        build(fake_coordinator(), FakeNI([])).incident_status.reason
        == "incident_unknown"
    )


def test_builder_failed_stale_or_missing_poll_is_never_good() -> None:
    coord = fake_coordinator()
    coord.last_update_success = False
    s = build(coord, FakeNI([inc()]))
    assert s.management_path.value is False  # measured: the poll failed
    for name in (
        "clients",
        "services",
        "service_pids",
        "interfaces",
        "wan",
        "ap_interfaces",
        "uptime_s",
        "log_ok",
    ):
        assert getattr(s, name).reason == "poll_failed", name
    # stale: more than two intervals old (the boundary is 120 s)
    assert (
        build(
            fake_coordinator(last_seen=W0 - 120), FakeNI([inc()], W0)
        ).management_path.value
        is True
    )
    s = build(fake_coordinator(last_seen=W0 - 120.5), FakeNI([inc()]))
    assert s.management_path.reason == "poll_stale"
    assert s.services.reason == "poll_stale"
    # a wall clock set back behind the poll
    s = build(fake_coordinator(last_seen=W0 + 2), FakeNI([inc()]))
    assert s.management_path.reason == "wall_clock_behind_poll"
    assert build(fake_coordinator(last_seen=W0 + 0.5)).management_path.value is True
    assert build(None).management_path.reason == "router_not_loaded"
    coord = fake_coordinator()
    coord.last_update_success = None
    assert build(coord).management_path.reason == "poll_state_unknown"
    coord = fake_coordinator(last_seen=None)
    assert build(coord).management_path.reason == "no_successful_poll"
    coord = fake_coordinator()
    coord.update_interval = None
    assert build(coord).management_path.reason == "interval_unknown"


def test_builder_network_intelligence_freshness() -> None:
    names = (
        "dependants_degraded",
        "incident_status",
        "incident_reopen_count",
        "incident_resolve_reason",
        "incident_resolved_age_s",
        "other_incidents",
    )
    for ni, reason in [
        (None, "ni_not_loaded"),
        (SimpleNamespace(loaded=False), "ni_not_loaded"),
        (FakeNI([inc()], last_now=W0 - 120.5), "ni_stale"),
        (FakeNI([inc()], last_now=W0 + 2), "wall_clock_behind_ni"),
        (FakeNI([inc()], last_now=None), "ni_time_unknown"),
    ]:
        s = build(fake_coordinator(), ni)
        for n in names:
            assert getattr(s, n).reason == reason, (n, reason)
    s = build(fake_coordinator(), FakeNI([inc()]), entry_id=None)
    assert s.incident_status.reason == "entry_unknown"
    s = build(fake_coordinator(), FakeNI([inc()], last_now=W0 - 120))
    assert s.incident_status.value == "active"
    coord = fake_coordinator()
    coord.update_interval = None
    assert build(coord, FakeNI([inc()])).incident_status.reason == "interval_unknown"
    ni = FakeNI([inc()])
    ni.topology = Topology(uplinks={}, gateways=frozenset({"e9"}))
    assert (
        build(fake_coordinator(), ni).dependants_degraded.reason
        == "router_not_in_topology"
    )
    ni = FakeNI([inc(), inc("Bad Id!", routers=("e1",))])
    assert (
        build(fake_coordinator(), ni).other_incidents.reason == "incident_id_unreadable"
    )


def test_builder_odd_poll_data_is_unknown_not_guessed() -> None:
    s = build(
        fake_coordinator(
            services=[],
            service_instances=None,
            network_interfaces=[],
            wan_status={},
            ap_interfaces=None,
            uptime=0,
            log_status=None,
            client_count=-1,
        ),
        FakeNI([inc()]),
    )
    assert {
        n: getattr(s, n).reason
        for n in (
            "services",
            "service_pids",
            "interfaces",
            "wan",
            "ap_interfaces",
            "uptime_s",
            "log_ok",
            "clients",
        )
    } == {
        "services": "services_not_polled",
        "service_pids": "service_instances_not_fetched",
        "interfaces": "interfaces_not_polled",
        "wan": "wan_unknown",
        "ap_interfaces": "ap_interfaces_unknown",
        "uptime_s": "uptime_missing",
        "log_ok": "log_status_unknown",
        "clients": "clients_unknown",
    }
    s = build(fake_coordinator(vlans_stale=True))
    assert s.interfaces.reason == "interfaces_stale"
    s = build(
        fake_coordinator(
            network_interfaces=[{"logical_name": "lan", "status": "pending"}]
        )
    )
    assert s.interfaces.reason == "interface_status_unreadable"
    s = build(
        fake_coordinator(
            network_interfaces=[
                {"logical_name": "lan", "status": "up"},
                {"logical_name": "lan", "status": "down"},
            ]
        )
    )
    assert s.interfaces.reason == "interfaces_ambiguous"
    s = build(fake_coordinator(services=[{"name": "a", "running": True}] * 2))
    assert s.services.reason == "services_ambiguous"
    s = build(
        fake_coordinator(
            services=[{"name": f"s{i}", "running": True} for i in range(65)]
        )
    )
    assert s.services.reason == "too_many_entries"
    s = build(fake_coordinator(wan_status={"wan_found": False}))
    assert s.wan.value == "absent"
    s = build(fake_coordinator(wan_connected=False))
    assert s.wan.value == "down"
    s = build(fake_coordinator(wan_connected="yes"))
    assert s.wan.reason == "wan_unknown"
    s = build(fake_coordinator(log_status="pending"))
    assert s.log_ok.value is False
    # names like IoT or 4g are names (kept in the snapshot only)
    s = build(
        fake_coordinator(
            network_interfaces=[
                {"logical_name": "IoT", "status": "up"},
                {"logical_name": "4g", "status": "down"},
            ]
        )
    )
    assert s.interfaces.value == (("4g", False), ("IoT", True))
    # a stopped instance needs no pid
    s = build(
        fake_coordinator(
            service_instances={
                "dnsmasq": {
                    "c": {"pid": 7, "running": False},
                    "d": {"pid": 8, "running": True},
                }
            }
        )
    )
    assert s.service_pids.value == (("dnsmasq", 8),)


_GOOD_SERVICE = {"name": "dnsmasq", "running": True}
_GOOD_IFACE = {"logical_name": "lan", "status": "up"}
_GOOD_CLIENT = {"mac": "02:00:00:00:0a:0b", "radio": "phy0-ap0"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("services", [_GOOD_SERVICE, {"name": "192.168 1", "running": True}]),
        ("services", [_GOOD_SERVICE, {"name": "odhcpd"}]),
        ("services", [_GOOD_SERVICE, {"name": "odhcpd", "running": "yes"}]),
        ("services", [_GOOD_SERVICE, {"name": None, "running": True}]),
        ("services", [_GOOD_SERVICE, "odhcpd"]),
        (
            "service_instances",
            {
                "dnsmasq": {
                    "a": {"pid": 0, "running": True},
                    "d": {"pid": 8, "running": True},
                }
            },
        ),
        ("service_instances", {"dnsmasq": {"b": {"pid": True, "running": True}}}),
        ("service_instances", {"dnsmasq": {"b": {"pid": 8}}}),
        ("service_instances", {"dnsmasq": {"b": "x"}}),
        ("service_instances", {"dnsmasq": ["x"]}),
        (
            "service_instances",
            {
                "dnsmasq": {"d": {"pid": 8, "running": True}},
                "bad name": {"x": {"pid": 9, "running": True}},
            },
        ),
        ("network_interfaces", [_GOOD_IFACE, {"status": "up"}]),
        ("network_interfaces", [_GOOD_IFACE, "wan"]),
        ("network_interfaces", [_GOOD_IFACE, {"logical_name": "w an", "status": "up"}]),
        ("network_interfaces", [_GOOD_IFACE, {"logical_name": "wan"}]),
        ("ap_interfaces", [{"ifname": "phy0-ap0"}, "phy1-ap0"]),
        ("clients", [_GOOD_CLIENT, {"mac": "02:00:00:00:0a:0c"}]),
        ("clients", [_GOOD_CLIENT, {"mac": "02:00:00:00:0a:0c", "radio": ""}]),
        ("clients", [_GOOD_CLIENT, "02:00:00:00:0a:0c"]),
    ],
)
def test_one_unreadable_row_makes_the_whole_fact_unknown(
    field: str, value: Any
) -> None:
    """Review PR #83, P1-2: never skip a row, never keep the readable part."""
    fact, reason = {
        "services": ("services", "service_row_unreadable"),
        "service_instances": ("service_pids", "service_instance_unreadable"),
        "network_interfaces": ("interfaces", None),
        "ap_interfaces": ("ap_interfaces", "ap_interface_unreadable"),
        "clients": ("radio_clients", "client_radio_unreadable"),
    }[field]
    got = getattr(build(fake_coordinator(**{field: value})), fact)
    assert got.value is None
    if reason is None:
        assert got.reason in ("interface_row_unreadable", "interface_status_unreadable")
    else:
        assert got.reason == reason


class _Raises:
    def __getattr__(self, name: str) -> Any:
        raise RuntimeError(name)


def test_builder_never_raises() -> None:
    raising_ni = SimpleNamespace(loaded=True, machine=_Raises(), topology=_Raises())
    s = build(_Raises(), raising_ni)
    assert all(f.value is None for _, f in s.fact_items())
    assert s.management_path.reason == "collector_error"
    assert s.incident_status.reason == "collector_error"
    coord = fake_coordinator()
    coord.data = _Raises()
    s = build(coord)
    assert s.management_path.reason == "collector_error"

    # a fresh poll whose data raises inside the state part
    class HalfData:
        last_seen = W0

        def __getattr__(self, name: str) -> Any:
            raise RuntimeError(name)

    coord = fake_coordinator()
    coord.data = HalfData()
    s = build(coord, FakeNI([inc()]))
    assert s.management_path.value is True
    assert s.services.reason == "collector_error"
    assert s.incident_status.value == "active"
    # own inputs unusable: None, never an exception
    src = hp.FactSources(store=None, entry_id="e1", coordinator=fake_coordinator())
    for args in [
        (src, "rtr_bad", INC, T0, W0),
        (src, R1, "Bad Id", T0, W0),
        (src, R1, INC, float("nan"), W0),
        (src, R1, INC, T0, "now"),
        ("src", R1, INC, T0, W0),
        (src, _StrSub(R1), INC, T0, W0),
    ]:
        assert (
            hv.snapshot_from_sources(
                args[0], args[1], args[2], safe_now=args[3], wall_now=args[4]
            )
            is None
        )


def test_builder_shape_guard_turns_bad_values_unknown(monkeypatch) -> None:
    monkeypatch.setattr(
        hv, "_state", lambda src, mgmt: {"clients": hp.known(-5, "x"), "wan": "up"}
    )
    s = build(fake_coordinator(), FakeNI([inc()]))
    assert s.clients.reason == "value_unreadable"
    assert s.wan.reason == "value_unreadable"


def test_a_wall_clock_jump_ahead_makes_the_builder_unknown_not_good() -> None:
    s = build(fake_coordinator(), FakeNI([inc()]), wall=W0 + 86_400)
    assert s.management_path.reason == "poll_stale"
    assert s.incident_status.reason == "ni_stale"
    r = run(call=CallResult.REJECTED, a=dataclasses.replace(s, taken_at=AFTER_AT))
    assert r.result is VR.UNKNOWN


async def test_the_builder_makes_zero_router_calls() -> None:
    """Two polls of the real api and coordinator (recorded call list), then
    before- and after-snapshots and the verification: no call is added,
    nothing is refreshed, the result is "cleared by itself"."""
    calls: list[Any] = []
    coordinator = kit.make_coordinator(make_hass(), kit.make_api(calls))
    await kit.full_polls(coordinator)
    recorded = list(calls)
    assert len(recorded) > 0
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_refresh = AsyncMock()
    wall = time.time()
    ni = FakeNI([inc()], last_now=wall)
    src = hp.FactSources(
        store=None, entry_id="e1", coordinator=coordinator, api=coordinator.api, ni=ni
    )
    b = hv.snapshot_from_sources(src, R1, INC, safe_now=T0 - 5, wall_now=wall)
    assert b is not None
    assert calls == recorded
    assert b.management_path.value is True
    assert b.services.value == (
        ("dnsmasq", True),
        ("dropbear", True),
        ("firewall", False),
    )
    assert b.service_pids.value == (("dnsmasq", 3820), ("dropbear", 1))
    assert b.wan.value == "up" and b.log_ok.value is True
    assert b.clients.value == coordinator.data.client_count
    assert b.interfaces.known and b.uptime_s.known and b.ap_interfaces.known
    blob = repr(b.to_dict())
    assert "192.0.2.1" not in blob and kit.CLIENT_MAC not in blob
    hostname = coordinator.data.router_info.get("hostname")
    assert not hostname or hostname not in blob
    assert b.radio_clients.known and b.wall_at == wall
    # the incident clears by itself (Network Intelligence measured it), and
    # has held 300 s; wall and safety time move alike (705 s each), the
    # last poll 5 s before the after-snapshot
    wall_a = wall + 705
    ni.incidents = [
        inc(status="resolved", resolve_reason="cleared", resolved_at=wall_a - 300)
    ]
    a = hv.snapshot_from_sources(src, R1, INC, safe_now=T0 + 700, wall_now=wall_a)
    assert a is not None and a.management_path.reason == "poll_stale"
    coordinator.data.last_seen = datetime.fromtimestamp(wall_a - 5, UTC)
    ni.machine.last_now = wall_a
    a = hv.snapshot_from_sources(src, R1, INC, safe_now=T0 + 700, wall_now=wall_a)
    assert a is not None and a.incident_status.value == "resolved"
    assert a.management_path.age_s == pytest.approx(5.0)
    r = hv.verify(
        action_id=ACT,
        action_type="observe.evaluate",
        params={},
        call_result=None,
        before=b,
        after=a,
        started_at=T0,
        judged_at=T0 + 710,
    )
    assert r.result is VR.RESOLVED and r.verdict_key == "cleared_by_itself"
    assert r.credited_to_action is False
    assert calls == recorded
    coordinator.async_request_refresh.assert_not_awaited()
    coordinator.async_refresh.assert_not_awaited()


# ---------------------------------------------------------------------------
# Review of PR #83: one test per item (each fails on 6d6e277)
# ---------------------------------------------------------------------------

_GREEN_CLIENTS = GREEN_AFTER["clients"]


def test_p1_1_after_facts_measured_before_the_settle_time_are_unknown() -> None:
    """A fresh after-snapshot of old data is old data (probe A)."""
    old = snap(aged(GREEN_AFTER, 900.0), at=AFTER_AT)
    r = run("observe.evaluate", call=None, a=old)
    assert r.result is VR.UNKNOWN and r.credited_to_action is False
    assert r.criterion("management_path").reason == "management_path_stale_after"
    # boundary: measured exactly at the end of the settle time counts
    r = run(a=after(clients=k(_GREEN_CLIENTS, 100.0)))
    assert r.result is VR.RESOLVED
    r = run(a=after(clients=k(_GREEN_CLIENTS, 100.001)))
    assert r.result is VR.UNKNOWN
    assert r.reasons == ("clients_within_tolerance.unknown",)
    assert r.criterion("clients_within_tolerance").reason == "clients_stale_after"
    # an unknown or negative age is never a measuring time
    for age in (None, -1.0):
        r = run(a=after(clients=k(_GREEN_CLIENTS, age)))
        assert r.result is VR.UNKNOWN, age


def test_p1_1_before_facts_must_be_measured_in_the_300_s_before_the_start() -> None:
    # before at T0 - 10: an age of 290 s is measured at T0 - 300
    assert run(b=before(clients=k(10, 290.0))).result is VR.RESOLVED
    r = run(b=before(clients=k(10, 290.001)))
    assert r.result is VR.UNKNOWN
    assert r.criterion("clients_within_tolerance").reason == "clients_stale_before"
    r = run(b=before(clients=k(10, None)))
    assert r.criterion("clients_within_tolerance").reason == "clients_stale_before"
    # a before-snapshot taken after the start is refused by the gate; the
    # rows it shows are not measured before the start either
    r = run(b=before(at=T0 + 5))
    assert r.reasons == ("before_snapshot_after_start",)
    assert r.criterion("clients_within_tolerance").reason == "clients_stale_before"
    r = run(b=before(at=T0 + 5, clients=k(10, 5.0)))
    assert r.criterion("clients_within_tolerance").comparison is C.HELD
    # the age rule reaches the incident too
    r = run(b=before(incident_status=k("active", 400.0)))
    assert r.criterion("incident_cleared").reason == "incident_status_stale_before"
    assert r.result is VR.UNKNOWN


def test_p1_1_services_carried_forward_by_the_coordinator_are_unknown() -> None:
    """When ``service list`` fails, the coordinator copies the last poll's
    services forward (``service_instances`` stays None): never measured."""
    s = build(fake_coordinator(service_instances=None))
    assert s.services.value is None
    assert s.services.reason == "services_freshness_unknown"
    assert s.service_pids.reason == "service_instances_not_fetched"
    # the same services with this poll's instances are measured
    assert build(fake_coordinator()).services.known


def test_p1_1_a_failed_poll_is_measured_only_with_its_start() -> None:
    coord = fake_coordinator()
    coord.last_update_success = False
    s = build(coord)
    assert s.management_path.value is False and s.management_path.age_s is None
    coord._failure_since = datetime.fromtimestamp(W0 - 120, UTC)
    s = build(coord)
    assert s.management_path.value is False
    assert s.management_path.age_s == pytest.approx(120.0)
    # a failed poll of unknown start is not a fresh, measured loss
    r = run(a=after(at=T0 + 300, management_path=k(False, None)), now=T0 + 300)
    assert r.result is VR.UNKNOWN and r.escalate is False
    # SSH fallback (300 s interval), poll 590 s old: known, but too old
    coord = fake_coordinator(last_seen=W0 - 590)
    coord.update_interval = SimpleNamespace(total_seconds=lambda: 300.0)
    s = build(coord, FakeNI([inc()]), safe=BEFORE_AT)
    assert s.management_path.value is True and s.management_path.age_s == 590.0
    r = run(b=dataclasses.replace(before(), management_path=s.management_path))
    assert r.criterion("management_path").reason == "management_path_stale_before"


def test_p2_3_the_clearing_must_hold_300_s() -> None:
    r = run(a=after(incident_resolved_age_s=299.999))
    assert r.result is VR.UNKNOWN and r.final is False
    assert r.criterion("incident_cleared").reason == "clearing_not_held_long_enough"
    assert run(a=after(incident_resolved_age_s=300.0)).result is VR.RESOLVED
    # held until Network Intelligence's last look, not until the snapshot
    r = run(a=after(incident_status=k("resolved", 50.0), incident_resolved_age_s=349.0))
    assert r.criterion("incident_cleared").reason == "clearing_not_held_long_enough"
    r = run(a=after(incident_status=k("resolved", 50.0), incident_resolved_age_s=350.0))
    assert r.result is VR.RESOLVED
    # a reopen inside the hold is no success: the next look sees it open
    r = run(
        a=after(
            incident_status="active",
            incident_reopen_count=1,
            incident_resolve_reason="open",
            incident_resolved_age_s=u(),
        )
    )
    assert (
        r.result is VR.NOT_RESOLVED and r.reasons[0] == "incident_cleared.not_improved"
    )
    assert r.criterion("incident_cleared").reason == "incident_recurred"
    # at the maximum wait a clearing that has not held is final, never good
    r = run(
        a=after(at=T0 + 3500, incident_resolved_age_s=200.0),
        now=T0 + 3600,
    )
    assert r.result is VR.UNKNOWN and r.final is True
    assert r.verdict_key == "cannot_tell"


def test_p2_5_a_wall_clock_jump_between_the_snapshots_is_unknown() -> None:
    for wall, result, reason in (
        (WALL0 + AFTER_AT + 1.0, VR.RESOLVED, "incident_cleared_measured"),
        (WALL0 + AFTER_AT - 1.0, VR.RESOLVED, "incident_cleared_measured"),
        (WALL0 + AFTER_AT + 1.001, VR.UNKNOWN, "wall_clock_jump"),
        (WALL0 + AFTER_AT - 1.001, VR.UNKNOWN, "wall_clock_jump"),
        (WALL0 + AFTER_AT + 86_400, VR.UNKNOWN, "wall_clock_jump"),
        (None, VR.UNKNOWN, "wall_time_unknown"),
    ):
        r = run(a=after(wall=wall))
        assert (r.result, r.criterion("incident_cleared").reason) == (
            result,
            reason,
        ), wall
    r = run(b=before(wall=None))
    assert r.criterion("incident_cleared").reason == "wall_time_unknown"
    # the builder keeps the wall time it was given
    assert build(fake_coordinator(), FakeNI([inc()]), wall=W0 + 7).wall_at == W0 + 7
    assert after(wall=WALL0).to_dict()["wall_at"] == WALL0


def test_p2_6_clients_are_judged_per_radio() -> None:
    # 10 -> 8 in total is within tolerance, but phy0 lost 3 of 4
    r = run(a=after(clients=8, radio_clients=(("phy0-ap0", 1), ("phy1-ap0", 7))))
    assert r.criterion("clients_within_tolerance").comparison is C.HELD
    assert r.result is VR.NEW_FAULT
    assert r.reasons == ("radio_clients_within_tolerance.worse",)
    c = r.criterion("radio_clients_within_tolerance")
    assert (c.reason, c.before, c.after) == ("radio_clients_dropped", 2, 1)
    # a radio gone after has 0 clients
    r = run(a=after(radio_clients=(("phy1-ap0", 10),)))
    assert r.criterion("radio_clients_within_tolerance").comparison is C.WORSE
    # one client less on a small radio is held, a new radio is more
    r = run(a=after(radio_clients=(("phy0-ap0", 3), ("phy1-ap0", 6))))
    assert r.criterion("radio_clients_within_tolerance").comparison is C.HELD
    r = run(a=after(radio_clients=(("phy0-ap0", 4), ("phy1-ap0", 6), ("phy2-ap0", 1))))
    assert r.criterion("radio_clients_within_tolerance").comparison is C.IMPROVED
    # counts only, never radio names in the result
    assert "phy0" not in repr(r.to_dict())
    # the builder counts the clients per AP interface
    s = build(
        fake_coordinator(
            clients=[
                {"mac": "02:00:00:00:0a:01", "radio": "phy0-ap0"},
                {"mac": "02:00:00:00:0a:02", "radio": "phy0-ap0"},
                {"mac": "02:00:00:00:0a:03", "radio": "phy1-ap0"},
            ]
        )
    )
    assert s.radio_clients.value == (("phy0-ap0", 2), ("phy1-ap0", 1))
    assert build(fake_coordinator(clients=[])).radio_clients.value == ()
    assert build(fake_coordinator(clients=None)).radio_clients.reason == (
        "clients_unknown"
    )


_END = {
    # verdict -> (state, counts_as_failure, credited, hold) after a call
    "repaired_by_action": (hm.ActionState.RESOLVED, False, True, False),
    "repaired_execution_unconfirmed": (
        hm.ActionState.MANUAL_RECOVERY_REQUIRED,
        True,
        False,
        False,
    ),
    "partially_repaired": (hm.ActionState.FAILED, True, False, False),
    "action_did_not_help": (hm.ActionState.FAILED, True, False, False),
    "cleared_by_itself": (hm.ActionState.FAILED, True, False, False),
    "not_cleared": (hm.ActionState.FAILED, True, False, False),
    "worse_after_action": (hm.ActionState.ESCALATED, True, False, True),
    "worse_without_action": (hm.ActionState.ESCALATED, True, False, True),
    "cannot_tell": (hm.ActionState.MANUAL_RECOVERY_REQUIRED, True, False, False),
}


def _final_results() -> dict[tuple[str, bool], hv.VerifyResult]:
    """One final result per (verdict key, executed) the inputs can give."""
    rng = random.Random(84)
    out: dict[tuple[str, bool], hv.VerifyResult] = {}
    for _ in range(4000):
        action = rng.choice(ACTIONS_LITERAL)
        call = not_run(
            action,
            rng.choice(
                [None, CallResult.OK, CallResult.INCONCLUSIVE, CallResult.REJECTED]
            ),
        )
        b, a, _ = _random_pair(rng, 0.15)
        a = dataclasses.replace(a, taken_at=T0 + 3500, wall_at=WALL0 + T0 + 3500)
        r = run(action, call=call, b=b, a=a, now=T0 + 3600)
        assert r.final is True
        out.setdefault((r.verdict_key, r.executed), r)
    late = {"a": after(at=T0 + 3500, wall=WALL0 + T0 + 3500), "now": T0 + 3600}
    for call in (CallResult.OK, CallResult.INCONCLUSIVE):
        r = run(call=call, **late)
        out.setdefault((r.verdict_key, r.executed), r)
    return out


def test_p2_4_the_end_state_goes_by_verdict_key_and_the_real_table() -> None:
    assert set(hv._AFTER_CALL) == hv.VERDICT_KEYS == set(_END)
    results = _final_results()
    assert {key for key, _ in results} == hv.VERDICT_KEYS
    for (key, executed), r in results.items():
        for interrupted in (False, True):
            end = hv.planned_end(
                r, from_state=hm.ActionState.VERIFYING, interrupted=interrupted
            )
            state, failure, credited, hold = _END[key]
            if interrupted and state is hm.ActionState.FAILED:
                state = hm.ActionState.MANUAL_RECOVERY_REQUIRED
            assert (end.state, end.counts_as_failure, end.credited, end.hold) == (
                state,
                failure,
                credited,
                hold,
            ), key
            # the move exists in heal_model's table, for the engine
            rule = hm.TRANSITIONS[(hm.ActionState.VERIFYING, end.state)]
            assert hm.Actor.ENGINE in rule.actors
            if hm.Precondition.NOT_INTERRUPTED in rule.requires:
                assert interrupted is False
            assert end.credited is (key == "repaired_by_action")
            # from a proposal (Observe): only when nothing was executed
            if executed:
                with pytest.raises(hv.VerifyError):
                    hv.planned_end(
                        r, from_state=hm.ActionState.PROPOSED, interrupted=interrupted
                    )
                continue
            end = hv.planned_end(
                r, from_state=hm.ActionState.PROPOSED, interrupted=interrupted
            )
            if key == "cleared_by_itself":
                assert end == hv.PlannedEnd(
                    state=hm.ActionState.CANCELLED,
                    counts_as_failure=False,
                    credited=False,
                    hold=False,
                )
                assert hm.can_transition(
                    hm.ActionState.PROPOSED, end.state, hm.Actor.ENGINE
                )
            elif key == "worse_without_action":
                # the engine may not escalate a proposal: hold, no move
                assert not hm.can_transition(
                    hm.ActionState.PROPOSED, hm.ActionState.ESCALATED, hm.Actor.ENGINE
                )
                assert end == hv.PlannedEnd(
                    state=None, counts_as_failure=False, credited=False, hold=True
                )
            else:
                assert end is None, key


def test_p2_4_planned_end_refuses_what_it_cannot_judge() -> None:
    r = run(a=after(at=T0 + 300), now=T0 + 300)
    assert r.final is False
    assert (
        hv.planned_end(r, from_state=hm.ActionState.VERIFYING, interrupted=False)
        is None
    )
    good = run()
    for state in hm.ActionState:
        if state in (hm.ActionState.VERIFYING, hm.ActionState.PROPOSED):
            continue
        with pytest.raises(hv.VerifyError):
            hv.planned_end(good, from_state=state, interrupted=False)
    for bad in ({"from_state": "verifying"}, {"interrupted": 0}):
        args = {"from_state": hm.ActionState.VERIFYING, "interrupted": False, **bad}
        with pytest.raises(hv.VerifyError):
            hv.planned_end(good, **args)
    forged = run()
    object.__setattr__(forged, "verdict_key", "repaired_by_action")
    object.__setattr__(forged, "result", VR.RESOLVED)
    object.__setattr__(forged, "reasons", ("x",))
    with pytest.raises(hv.VerifyError):
        hv.planned_end(forged, from_state=hm.ActionState.VERIFYING, interrupted=False)
    with pytest.raises(hv.VerifyError):
        hv.planned_end(
            good.to_dict(), from_state=hm.ActionState.VERIFYING, interrupted=False
        )


# P3-8: one boundary test for each survivor of the reviewer's mutation run


def test_p3_8_t2_a_target_missing_after_has_stopped() -> None:
    r = run(a=after(services=(("dropbear", True), ("firewall", False))))
    assert r.criterion("service_running").comparison is C.WORSE
    assert r.criterion("service_running").reason == "service_stopped"
    r = run("interface.cycle", a=after(interfaces=(("lan", True),)))
    assert r.criterion("interface_up").comparison is C.WORSE


def test_p3_8_r1_an_overlapping_pid_is_not_a_restart() -> None:
    a = after(service_pids=(("dnsmasq", 100), ("dnsmasq", 300), ("dropbear", 1)))
    r = run(a=a)
    c = r.criterion("service_restarted")
    assert (c.comparison, c.reason) == (C.NOT_IMPROVED, "restart_not_seen")
    assert r.result is VR.UNKNOWN and r.credited_to_action is False


def test_p3_8_r3_r4_uptime_boundaries() -> None:
    # equal uptime: no reboot seen, for a planned reboot either
    r = run("router.reboot", a=after(uptime_s=5000))
    c = r.criterion("router_rebooted")
    assert (c.comparison, c.reason) == (C.NOT_IMPROVED, "uptime_not_reset")
    assert run("router.reboot", a=after(uptime_s=4999)).result is VR.RESOLVED
    # one second less uptime: an unplanned reboot
    r = run(a=after(uptime_s=4999))
    assert r.result is VR.NEW_FAULT
    assert r.reasons == ("no_unplanned_reboot.worse",)
    assert run(a=after(uptime_s=5000)).result is VR.RESOLVED


def test_p3_8_x3_an_interface_cycle_not_executed_excludes_nothing() -> None:
    down = after(interfaces=(("lan", False), ("wan", True)))
    for call in (CallResult.REJECTED, CallResult.OK):
        r = run("interface.cycle", call=call, a=down)
        assert r.criterion("interfaces_still_up").comparison is C.WORSE, call
        assert r.result is VR.NEW_FAULT
    # executed: only its own target is left to the target criterion
    r = run("interface.cycle", a=after(interfaces=(("lan", True), ("wan", False))))
    assert r.criterion("interfaces_still_up").comparison is C.HELD
    assert r.criterion("interface_up").comparison is C.WORSE
    # not executed: the target counts like any other interface
    r = run(
        "interface.cycle",
        call=CallResult.REJECTED,
        a=after(interfaces=(("lan", True), ("wan", False))),
    )
    assert r.criterion("interfaces_still_up").comparison is C.WORSE


def test_p3_8_u1_s8_result_type_and_log_error() -> None:
    r = run()
    object.__setattr__(r, "result", "resolved")
    assert _binding_of(r) is hv.Binding.TAMPERED
    s = build(fake_coordinator(log_status="error"))
    assert s.log_ok.value is False
    r = run(a=after(incident_resolve_reason="quiet", log_ok=False))
    assert r.criterion("incident_cleared").reason == "quiet_without_log_coverage"
    assert r.result is VR.UNKNOWN


@pytest.mark.parametrize(
    ("name", "forge"),
    [
        ("final", int),
        ("escalate", int),
        ("executed", int),
        ("credited_to_action", int),
        ("attribution", str),
        ("result", str),
        ("settle_until", int),
        ("max_wait_until", int),
        ("verdict_key", _StrSub),
        ("binding", _StrSub),
        ("router_id", _StrSub),
        ("incident_id", _StrSub),
        ("reasons", list),
    ],
)
def test_p3_9_derived_fields_must_have_their_exact_type(name: str, forge: Any) -> None:
    r = run()
    forged = forge(getattr(r, name))
    assert type(forged) is not type(getattr(r, name))
    assert getattr(r, name) == forged or name == "reasons"  # equal: only the type
    object.__setattr__(r, name, forged)
    assert _binding_of(r) is hv.Binding.TAMPERED


def test_p3_9_parts_of_the_derived_tuples_have_their_exact_type() -> None:
    r = run()
    c = r.criteria[0]
    odd = dataclasses.replace(c)
    object.__setattr__(odd, "comparison", "improved")
    assert odd == c
    object.__setattr__(r, "criteria", (odd, *r.criteria[1:]))
    assert _binding_of(r) is hv.Binding.TAMPERED
    r = run()
    object.__setattr__(r, "reasons", tuple(_StrSub(x) for x in r.reasons))
    assert _binding_of(r) is hv.Binding.TAMPERED

    # a criterion subclass that claims to equal anything
    class _Agreeable(hv.Criterion):
        __slots__ = ()

        def __eq__(self, other: object) -> bool:
            return True

        __hash__ = hv.Criterion.__hash__

    r = run()
    c = r.criteria[0]
    sneaky = _Agreeable(**{f.name: getattr(c, f.name) for f in dataclasses.fields(c)})
    assert (sneaky,) == (c,)
    object.__setattr__(r, "criteria", (sneaky, *r.criteria[1:]))
    assert _binding_of(r) is hv.Binding.TAMPERED
    r = run()
    object.__setattr__(r, "criteria", list(r.criteria))
    assert _binding_of(r) is hv.Binding.TAMPERED


@pytest.mark.parametrize(
    "bad",
    [
        {"management_path": False},
        {"wan": "down"},
        {"dependants_degraded": 1},
        {"other_incidents": ("inc-3",)},
    ],
)
def test_p3_10_a_guard_bad_on_both_sides_never_resolves(bad: dict) -> None:
    """DECIDED: an executed write -> not resolved; nothing written ->
    unknown (it cannot be told whether the router is well)."""
    b, a = before(**bad), after(**bad)
    r = run(b=b, a=a)
    assert r.result is VR.NOT_RESOLVED and r.verdict_key == "action_did_not_help"
    assert r.reasons[0] == "incident_cleared.improved"
    for action, call in (
        ("service.restart", CallResult.REJECTED),
        ("observe.evaluate", None),
    ):
        r = run(action, call=call, b=b, a=a)
        assert r.result is VR.UNKNOWN and r.credited_to_action is False
        assert r.verdict_key == "cannot_tell"
    # bad before, well after: the guard improved, that is fine
    assert run(b=b).result is VR.RESOLVED


def test_p3_10_acknowledged_incidents_are_still_open() -> None:
    ni = FakeNI(
        [
            inc(),
            inc("inc-9", status="acknowledged", routers=("e1",), severity="critical"),
            inc("inc-11", status="acknowledged", routers=("e2",)),
        ]
    )
    s = build(fake_coordinator(), ni)
    assert s.other_incidents.value == ("inc-9",)
    assert s.dependants_degraded.value == 1


@pytest.mark.parametrize("action", WRITES_LITERAL)
def test_p3_10_no_call_result_on_a_write_is_refused(action: str) -> None:
    with pytest.raises(hv.VerifyError):
        run(action, call=None)
    r = run(action, call=CallResult.REJECTED)
    object.__setattr__(r, "call_result", None)
    assert r._untampered() is False
    # a read-only action may have no call at all
    assert run("diag.refresh", call=None).verdict_key == "cleared_by_itself"


def test_p3_10_the_stored_form_is_to_dict_and_plain_json() -> None:
    import json

    r = run()
    d = r.to_dict()
    assert json.loads(json.dumps(d)) == d
    assert all(
        type(v) in (str, int, float, bool, list, dict, type(None)) for v in d.values()
    )
