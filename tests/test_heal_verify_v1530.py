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
    "services_still_running": ("services",),
    "interfaces_still_up": ("interfaces",),
    "wan_not_lost": ("wan",),
    "ap_interfaces_kept": ("ap_interfaces",),
    "dependants_not_degraded": ("dependants_degraded",),
    "no_new_incidents": ("other_incidents",),
    "no_unplanned_reboot": ("uptime_s",),
}


def k(value: Any) -> hp.Fact:
    return hp.known(value, "test")


def u(reason: str = "test_unknown") -> hp.Fact:
    return hp.unknown(reason, "test")


def _wrap(value: Any) -> hp.Fact:
    return value if isinstance(value, hp.Fact) else k(value)


GREEN_BEFORE = {
    "management_path": True,
    "clients": 10,
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


def snap(
    base: dict[str, Any] | None = None,
    *,
    at: float = BEFORE_AT,
    router: str = R1,
    incident: str = INC,
    **over: Any,
) -> hv.VerifySnapshot:
    values = {**(GREEN_BEFORE if base is None else base), **over}
    return hv.VerifySnapshot(
        router_id=router,
        incident_id=incident,
        taken_at=at,
        **{n: _wrap(v) for n, v in values.items()},
    )


def before(**over: Any) -> hv.VerifySnapshot:
    return snap(GREEN_BEFORE, at=over.pop("at", BEFORE_AT), **over)


def after(**over: Any) -> hv.VerifySnapshot:
    return snap(GREEN_AFTER, at=over.pop("at", AFTER_AT), **over)


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
    assert [hv.client_drop_allowed(n) for n in (0, 1, 6, 7, 10, 13, 100)] == [
        2,
        2,
        2,
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
    r = run(call=None, a=a)
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
    r = run(action, call=call)
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
        b, a = _random_pair(rng)
        action = rng.choice(ACTIONS_LITERAL)
        call = rng.choice([None, CallResult.REJECTED])
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


@pytest.mark.parametrize(("action", "executed"), _cases())
def test_unknown_on_any_fact_a_criterion_reads_never_gives_success(
    action: str, executed: bool
) -> None:
    call = CallResult.OK if executed else None
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
                b = before(**{name: u()}) if side == "before" else before()
                a = after(**{name: u()}) if side == "after" else after()
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


@pytest.mark.parametrize(("action", "executed"), _cases())
def test_unknown_on_any_fact_never_turns_into_success(
    action: str, executed: bool
) -> None:
    """Every fact, each side: unknown gives success only for facts that no
    criterion reads (pinned literally)."""
    call = CallResult.OK if executed else None
    green = run(action, call=call).result
    unread = UNREAD.get((action, executed), {"log_ok", "service_pids"})
    for name in FACTS_LITERAL:
        for side in ("before", "after"):
            b = before(**{name: u()}) if side == "before" else before()
            a = after(**{name: u()}) if side == "after" else after()
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
}


@pytest.mark.parametrize("guard", GUARDS_LITERAL)
@pytest.mark.parametrize("call", [CallResult.OK, None])
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
        (1, 0, C.HELD),
        (2, 0, C.HELD),
        (3, 0, C.WORSE),
        (0, 0, C.HELD),
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
    r = run(call=None, b=before(management_path=False), a=after(management_path=False))
    assert comparisons(r)["management_path"] is C.NOT_IMPROVED
    assert r.result is VR.RESOLVED  # cleared by itself, nothing got worse
    r = run(call=None, b=before(management_path=False))
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
    assert r.criterion("service_running").reason == "service_not_in_before"
    assert r.result is VR.UNKNOWN


# ---------------------------------------------------------------------------
# Time on the safety clock, at the boundaries
# ---------------------------------------------------------------------------


def test_settle_time_boundary() -> None:
    r = run(a=after(at=T0 + 599.0), now=T0 + 599.999)
    assert r.result is VR.UNKNOWN
    assert r.reasons == ("settle_time_not_reached",) and r.final is False
    r = run(a=after(at=T0 + 600, incident_resolved_age_s=100.0), now=T0 + 600)
    assert r.result is VR.RESOLVED
    r = run(a=after(at=T0 + 599.999, incident_resolved_age_s=100.0), now=T0 + 610)
    assert r.reasons == ("after_snapshot_too_early",) and r.final is False
    r = run(a=after(at=T0 + 599.999, incident_resolved_age_s=100.0), now=T0 + 3600)
    assert r.reasons[0] in ("after_snapshot_too_early",) and r.final is True
    assert r.settle_until == T0 + 600 and r.max_wait_until == T0 + 3600


def test_settle_time_hides_even_a_worsening() -> None:
    r = run(a=after(at=T0 + 300, management_path=False), now=T0 + 300)
    assert r.result is VR.UNKNOWN and r.reasons == ("settle_time_not_reached",)
    assert r.escalate is False
    assert r.criterion("management_path").comparison is C.WORSE  # shown, not judged


def test_max_wait_boundary() -> None:
    r = run(a=after(at=T0 + 3600, incident_resolved_age_s=10.0), now=T0 + 3600)
    assert r.result is VR.RESOLVED
    r = run(a=after(at=T0 + 3600.001, incident_resolved_age_s=10.0), now=T0 + 3600.001)
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
    ]
    digests = {v.binding for v in variants}
    assert base not in digests and len(digests) == len(variants)


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
        ("services", (("Dnsmasq", True),)),
        ("services", ("dnsmasq",)),
        ("service_pids", (("dnsmasq", 0),)),
        ("service_pids", (("dnsmasq", True),)),
        ("service_pids", (("dnsmasq", 1.5),)),
        ("interfaces", (("lan", "up"),)),
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
    assert run(call=None, a=None).to_dict()["after_taken_at"] is None


# ---------------------------------------------------------------------------
# Random scenarios with an oracle written from the inputs
# ---------------------------------------------------------------------------


def _maybe(rng: random.Random, value: Any, p: float = 0.08) -> Any:
    return u() if rng.random() < p else value


def _random_pair(
    rng: random.Random, p_change: float = 0.07
) -> tuple[hv.VerifySnapshot, hv.VerifySnapshot]:
    """A before-side drawn at random, and an after-side that mostly repeats
    it: each fact changes with ``p_change`` and is unknown with 3 %."""

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
        "services": services(running),
        "service_pids": pids(running),
        "interfaces": (("lan", True), ("wan", rng.random() < 0.9)),
        "wan": pick("up", "up", "up", "down", "absent"),
        "ap_interfaces": pick(1, 2, 2),
        "uptime_s": 5000,
        "log_ok": rng.random() < 0.8,
        "dependants_degraded": pick(0, 0, 1),
        "incident_status": pick("active", "active", "acknowledged", "resolved"),
        "incident_reopen_count": 0,
        "incident_resolve_reason": "open",
        "incident_resolved_age_s": u("incident_not_resolved"),
        "other_incidents": pick((), (), ("inc-3",)),
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
        "incident_resolved_age_s": pick(10.0, 300.0, 699.0, 800.0)
        if status == "resolved"
        else u("incident_not_resolved"),
    }
    changes = {
        "management_path": lambda: rng.random() < 0.5,
        "clients": lambda: rng.randint(0, 12),
        "interfaces": lambda: (("lan", True), ("wan", rng.random() < 0.5)),
        "wan": lambda: pick("up", "down", "absent"),
        "ap_interfaces": lambda: pick(1, 2),
        "uptime_s": lambda: pick(100, 5000),
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
    return snap(b, at=BEFORE_AT), snap(a, at=AFTER_AT)


def _val(s: hv.VerifySnapshot, name: str) -> Any:
    return getattr(s, name).value


def _oracle_incident(b: hv.VerifySnapshot, a: hv.VerifySnapshot) -> str:
    """ "cleared", "open" or "unknown" for the target incident."""
    status_b, status_a = _val(b, "incident_status"), _val(a, "incident_status")
    reopen_b, reopen_a = (
        _val(b, "incident_reopen_count"),
        _val(a, "incident_reopen_count"),
    )
    if status_b not in ("active", "acknowledged") or status_a is None:
        return "unknown"
    if reopen_b is None or reopen_a is None:
        return "unknown"
    if reopen_a > reopen_b or status_a in ("active", "acknowledged"):
        return "open"  # recurred, or still open
    if status_a != "resolved":
        return "unknown"
    how = _val(a, "incident_resolve_reason")
    age = _val(a, "incident_resolved_age_s")
    if how is None or age is None or AFTER_AT - age < T0:
        return "unknown"
    if how == "cleared":
        return "cleared"
    if how == "quiet" and _val(a, "log_ok") is True:
        return "cleared"
    return "unknown"


def _oracle(b: hv.VerifySnapshot, a: hv.VerifySnapshot, call: Any) -> VR:
    """The expected class for ``service.restart`` of dnsmasq, from the
    inputs and the rules of the package order (not from the module)."""
    wrote = call in (CallResult.OK, CallResult.INCONCLUSIVE)
    worse = unknown_ = False

    def need(*names: str) -> bool:
        nonlocal unknown_
        if any(_val(b, n) is None or _val(a, n) is None for n in names):
            unknown_ = True
            return False
        return True

    # guards
    if (
        need("management_path")
        and _val(b, "management_path")
        and not _val(a, "management_path")
    ):
        worse = True
    if need("clients") and _val(a, "clients") < _val(b, "clients") - max(
        2, _val(b, "clients") * 3 // 10
    ):
        worse = True
    if need("services"):
        bs, as_ = dict(_val(b, "services")), dict(_val(a, "services"))
        for name, on in bs.items():
            if wrote and name == "dnsmasq":
                continue
            if on and not as_.get(name, False):
                worse = True
    if need("interfaces"):
        bi, ai = dict(_val(b, "interfaces")), dict(_val(a, "interfaces"))
        if any(on and not ai.get(n, False) for n, on in bi.items()):
            worse = True
    if need("wan"):
        wb, wa = _val(b, "wan"), _val(a, "wan")
        if wb == "up" and wa != "up":
            worse = True
        elif {wb, wa} == {"down", "absent"}:
            unknown_ = True
    if need("ap_interfaces") and _val(a, "ap_interfaces") < _val(b, "ap_interfaces"):
        worse = True
    if need("dependants_degraded") and _val(a, "dependants_degraded") > _val(
        b, "dependants_degraded"
    ):
        worse = True
    if need("other_incidents") and set(_val(a, "other_incidents")) - set(
        _val(b, "other_incidents")
    ):
        worse = True
    if need("uptime_s") and _val(a, "uptime_s") < _val(b, "uptime_s"):
        worse = True
    # the incident
    cleared = False
    incident = _oracle_incident(b, a)
    cleared = incident == "cleared"
    unknown_ = unknown_ or incident == "unknown"
    # the targets of an executed restart
    state_improved = state_bad = False
    effect_seen = True
    if wrote:
        if need("services"):
            bs, as_ = dict(_val(b, "services")), dict(_val(a, "services"))
            if "dnsmasq" not in bs:
                unknown_ = True
            elif bs["dnsmasq"] and not as_.get("dnsmasq", False):
                worse = True
            elif not bs["dnsmasq"] and as_.get("dnsmasq", False):
                state_improved = True
            elif not bs["dnsmasq"]:
                state_bad = True
        if need("service_pids"):
            pb = {p for n, p in _val(b, "service_pids") if n == "dnsmasq"}
            pa = {p for n, p in _val(a, "service_pids") if n == "dnsmasq"}
            effect_seen = bool(pa) and not (pa & pb)
    if worse:
        return VR.NEW_FAULT
    if unknown_:
        return VR.UNKNOWN
    if wrote and not effect_seen:
        return VR.UNKNOWN if cleared else VR.NOT_RESOLVED
    if cleared and not state_bad:
        return VR.RESOLVED
    if cleared or state_improved:
        return VR.PARTIAL
    return VR.NOT_RESOLVED


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_random_scenarios_against_the_oracle(seed: int) -> None:
    rng = random.Random(seed)
    seen: dict[VR, int] = {}
    for _ in range(2000):
        b, a = _random_pair(rng)
        call = rng.choice(
            [None, CallResult.OK, CallResult.INCONCLUSIVE, CallResult.REJECTED]
        )
        r = run(call=call, b=b, a=a)
        expected = _oracle(b, a, call)
        assert r.result is expected, (b, a, call, r.reasons)
        seen[r.result] = seen.get(r.result, 0) + 1
        # the hard rules, again on every case
        if r.result is VR.RESOLVED:
            got = comparisons(r)
            assert got["incident_cleared"] is C.IMPROVED
            assert C.UNKNOWN not in got.values() and C.WORSE not in got.values()
            for cid, comparison in got.items():
                if hv.ROLE_OF[cid] is hv.Role.STATE:
                    assert comparison in (C.IMPROVED, C.HELD), cid
                if hv.ROLE_OF[cid] is hv.Role.EFFECT:
                    assert comparison is C.IMPROVED, cid
        assert r.escalate is (r.result is VR.NEW_FAULT)
        assert r.credited_to_action is (
            r.result is VR.RESOLVED and call is CallResult.OK
        )
    assert set(seen) == set(VR), seen


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
        "clients": [{"mac": "02:00:00:00:0a:0a", "hostname": "phone-of-anna"}],
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
    # unreadable names are left out, never copied
    s = build(
        fake_coordinator(
            services=[
                {"name": "192.168.1.1", "running": True},
                {"name": "dnsmasq", "running": True},
            ]
        )
    )
    assert s.services.value == (("dnsmasq", True),)
    s = build(
        fake_coordinator(
            service_instances={
                "dnsmasq": {
                    "a": {"pid": 0, "running": True},
                    "b": {"pid": True, "running": True},
                    "c": {"pid": 7, "running": False},
                    "d": {"pid": 8, "running": True},
                },
                "Bad": {"x": {"pid": 9, "running": True}},
            }
        )
    )
    assert s.service_pids.value == (("dnsmasq", 8),)


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
    r = run(call=None, a=dataclasses.replace(s, taken_at=AFTER_AT))
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
    # the incident clears by itself (Network Intelligence measured it)
    ni.incidents = [inc(status="resolved", resolve_reason="cleared", resolved_at=wall)]
    a = hv.snapshot_from_sources(src, R1, INC, safe_now=T0 + 700, wall_now=wall + 60)
    assert a is not None
    ni.machine.last_now = wall + 60
    a = hv.snapshot_from_sources(src, R1, INC, safe_now=T0 + 700, wall_now=wall + 60)
    assert a is not None and a.incident_status.value == "resolved"
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
