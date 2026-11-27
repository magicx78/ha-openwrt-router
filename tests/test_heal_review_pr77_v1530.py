"""Self-Healing, package D: the points of the independent review of PR #77.

Each test is the reviewer's attack turned around (it failed on the reviewed
head d4bf071) or closes a test gap the reviewer's mutations showed:

* P1-1 a decision cannot be forged: ``gate`` takes the ``DecisionInput``,
  runs the catalog and ``decide`` itself and refuses anything else;
* P1-2 unknown attempt history is never read as "no failures";
* P2-3 ``held`` / ``fleet_paused`` / ``module_enabled`` must be real bools;
* P2-4 a ``ValidatedAction`` can only hold the catalog's own entry;
* P2-5 role and topology: who depends on this router's DNS/DHCP;
* P2-6 at most N attempts in ANY 24 h span of safety time (policy and store);
* P2-7 a booking never shortens a running cooldown (policy and store);
* P2-8 an attempt whose outcome was never recorded counts as not resolved;
* P2-9 open owner questions are provisional strict defaults, not decisions;
* P2-10 the honest rollback statement of ``service.restart`` and the
  unapplied-configuration fact;
* P2-11 the reviewer's surviving mutations;
* P3 limits objects, interleaved refusals, dedupe components, one source
  for maintenance, the ``diag.refresh`` interval, ``dhcp.*``,
  ``PolicyLimits`` errors, the "cause outside the router" fact.

Pure: no Home Assistant instance, no router, no network.
"""

from __future__ import annotations

import dataclasses
import pathlib
from collections.abc import Iterator, Mapping
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hp
from custom_components.openwrt_router import heal_store as hs

O = hm.DecisionOutcome
P = hp.Permission
M = hm.HealMode
RC = hm.RiskClass
EV = hp.OutcomeEvent
R1 = "rtr_" + "1" * 32
T0 = 1_790_000_000.0
DAY = 86400
DNSMASQ = {"service": "dnsmasq"}
KEY = (R1, "service.restart", "service:dnsmasq")
ROOT = pathlib.Path(__file__).resolve().parents[1]


def ctx(**over: Any) -> hp.RiskContext:
    base: dict[str, Any] = {
        "role": "gateway",
        "identity_confirmed": True,
        "reachable": True,
        "dependants": 0,
        "target_on_mgmt_path": False,
        "target_is_wireless_uplink": False,
        "target_carries_dependants": False,
        "service_enabled": True,
        "service_dependant_routers": 0,
        "service_dependant_clients": 12,
        "service_config_unapplied": False,
        "clients_on_router": 12,
        "clients_on_target": 4,
        "open_security_findings": 0,
        "in_maintenance": False,
        "concurrent_repair": False,
        "breaker_open": False,
        "diag_enabled": True,
    }
    base.update(over)
    return hp.RiskContext(**base)


def inc(**over: Any) -> hp.IncidentFacts:
    base: dict[str, Any] = {
        "incident_type": "system_service_restart",
        "severity": "critical",
        "cause_level": hm.CauseLevel.CONFIRMED,
        "cause_status": hm.CauseStatus.CONFIRMED,
        "confidence": 0.9,
        "source_families": 2,
        "is_root": True,
        "temporal_only": False,
        "evidence_fresh": True,
        "target_fact": hp.TargetFact.DIRECT,
        "cause_outside_router": False,
    }
    base.update(over)
    return hp.IncidentFacts(**base)


def dinput(
    action_type: Any = "service.restart", params: Any = "default", **over: Any
) -> hp.DecisionInput:
    if isinstance(params, str) and params == "default":
        params = DNSMASQ if action_type == "service.restart" else {}
    kw: dict[str, Any] = {
        "incident": inc(),
        "context": ctx(),
        "prior_failed_attempts": 0,
        "config_change_24h": False,
    }
    kw.update(over)
    return hp.DecisionInput(action_type=action_type, params=params, **kw)


GATE_OK: dict[str, Any] = {
    "module_enabled": True,
    "held": False,
    "fleet_paused": False,
    "guards_green": True,
}


def gate(inp: Any, *, mode: hm.HealMode = M.APPROVAL, allowlist: Any = (), **over: Any):
    kw = dict(GATE_OK)
    kw.update(over)
    return hp.gate(inp, mode=mode, allowlist=allowlist, **kw)


def allow(action_type: str, **params: str) -> hm.AllowEntry:
    return hm.AllowEntry(action_type=action_type, params=params, max_risk=1)


# ---------------------------------------------------------------------------
# P1-1: a decision cannot be forged; the gate decides itself
# ---------------------------------------------------------------------------


def test_a_good_input_passes_the_gate_and_carries_the_policys_own_decision() -> None:
    inp = dinput()
    v = gate(inp)
    assert v.permission is P.NEEDS_APPROVAL
    assert v.decision == hp.decide(inp)
    assert v.decision.outcome is O.REQUIRES_APPROVAL


@pytest.mark.parametrize(
    "params",
    [
        {"service": "wpad"},
        {"service": "dnsmasq; reboot"},
        {"service": "dnsmasq", "extra": "x"},
        {},
        None,
        {"service": "DNSMASQ"},
    ],
)
def test_the_gate_refuses_params_outside_the_closed_set(params: Any) -> None:
    for mode in M:
        v = gate(dinput("service.restart", params), mode=mode)
        assert v.permission is P.NONE, (params, mode)
        assert v.decision.outcome is O.UNSUPPORTED
        assert v.executable_now is False


def test_the_gate_takes_no_decision_object_at_all() -> None:
    """The reviewer's relabelled decisions cannot even be handed in."""
    real = hp.decide(dinput(context=ctx(service_enabled=False)))
    assert real.outcome is O.NOT_SAFE
    forged = dataclasses.replace(real, outcome=O.REQUIRES_APPROVAL)
    with pytest.raises(hp.PolicyError):
        gate(forged)
    probe = hp.decide(dinput("diag.ha_probes", context=ctx(diag_enabled=False)))
    assert probe.outcome is O.UNSUPPORTED
    with pytest.raises(hp.PolicyError):
        gate(
            dataclasses.replace(probe, outcome=O.RECOMMENDED),
            mode=M.AUTO_HEAL,
            allowlist=(allow("diag.ha_probes"),),
        )


def test_a_relabelled_input_is_decided_again_not_trusted() -> None:
    """Not Safe stays Not Safe and Unsupported stays Unsupported through the
    gate, whatever the caller thinks the outcome was."""
    v = gate(dinput(context=ctx(service_enabled=False)))
    assert v.permission is P.NONE
    assert v.decision.outcome is O.NOT_SAFE
    v = gate(
        dinput("diag.ha_probes", context=ctx(diag_enabled=False)),
        mode=M.AUTO_HEAL,
        allowlist=(allow("diag.ha_probes"),),
    )
    assert v.permission is P.NONE
    assert v.decision.outcome is O.UNSUPPORTED


def test_a_subclass_of_the_input_is_refused() -> None:
    class Sneaky(hp.DecisionInput):
        __slots__ = ()

    with pytest.raises(hp.PolicyError):
        gate(Sneaky(action_type="diag.refresh", params={}))


def test_replace_on_an_input_validates_again() -> None:
    inp = dinput()
    bad = dataclasses.replace(inp, params={"service": "wpad"})
    assert gate(bad).permission is P.NONE
    with pytest.raises(hp.PolicyError):
        dataclasses.replace(inp, prior_failed_attempts=-1)


class _TocMap(Mapping):
    """A mapping that answers differently on each read (TOCTOU)."""

    def __init__(self) -> None:
        self.n = 0

    def __getitem__(self, key: str) -> str:
        self.n += 1
        return "dnsmasq" if self.n == 1 else "wpad"

    def __iter__(self) -> Iterator[str]:
        return iter(["service"])

    def __len__(self) -> int:
        return 1


def test_a_value_is_read_once_and_the_checked_value_is_kept() -> None:
    va = hc.validate("service.restart", _TocMap())
    assert dict(va.params) == DNSMASQ
    assert isinstance(va.params, MappingProxyType)
    inp = dinput("service.restart", _TocMap())
    assert isinstance(inp.params, MappingProxyType)
    assert dict(inp.params) == DNSMASQ
    assert gate(inp).decision.params == DNSMASQ


def test_the_input_holds_a_frozen_copy_of_the_params() -> None:
    params = {"service": "dnsmasq"}
    inp = dinput("service.restart", params)
    params["service"] = "wpad"
    assert dict(inp.params) == DNSMASQ
    assert gate(inp).permission is P.NEEDS_APPROVAL


# ---------------------------------------------------------------------------
# P1-2: unknown history is never harmless
# ---------------------------------------------------------------------------


def test_unknown_attempt_history_is_insufficient_evidence_for_a_write() -> None:
    two = hp.decide(dinput(prior_failed_attempts=2))
    assert two.outcome is O.INSUFFICIENT_EVIDENCE
    unknown = hp.decide(dinput(prior_failed_attempts=None))
    assert unknown.outcome is O.INSUFFICIENT_EVIDENCE
    assert unknown.why_not == "history_unknown" or any(
        h.code == "history_unknown" and h.blocking for h in unknown.hits
    )
    assert unknown.next_step == hp.DIAGNOSE_STEP


def test_the_default_history_of_an_input_is_unknown() -> None:
    inp = hp.DecisionInput(
        action_type="service.restart",
        params=DNSMASQ,
        incident=inc(),
        context=ctx(),
        config_change_24h=False,
    )
    assert inp.prior_failed_attempts is None
    assert hp.decide(inp).outcome is O.INSUFFICIENT_EVIDENCE


def test_unknown_history_costs_points_like_an_unknown_attempt() -> None:
    known = hp.score(inc(), prior_failed_attempts=0, config_change_24h=False)
    unknown = hp.score(inc(), prior_failed_attempts=None, config_change_24h=False)
    line = {c.factor: c for c in unknown.contributions}["prior_attempts"]
    assert line.reason == "prior_attempts_unknown"
    assert line.points == hp.PRIOR_ATTEMPT_POINTS
    assert unknown.total < known.total


def test_unknown_history_does_not_block_a_read() -> None:
    d = hp.decide(dinput("diag.refresh", prior_failed_attempts=None))
    assert d.outcome is O.RECOMMENDED


def test_an_unknown_severity_counts_like_info() -> None:
    s = hp.score(inc(severity=None), prior_failed_attempts=0, config_change_24h=False)
    line = {c.factor: c for c in s.contributions}["severity"]
    assert line.reason == "severity_unknown"
    assert line.points == hp.SEVERITY_POINTS["info"]


@pytest.mark.parametrize("fact", hc.CATALOG["service.restart"].needs_facts)
def test_each_unknown_fact_of_a_restart_blocks_it(fact: str) -> None:
    d = hp.decide(dinput(context=dataclasses.replace(ctx(), **{fact: None})))
    assert d.outcome in (O.INSUFFICIENT_EVIDENCE, O.NOT_SAFE), fact
    assert d.risk.risk_class is RC.HIGH
    assert fact in d.risk.missing


# ---------------------------------------------------------------------------
# P2-3: only real bools in the gate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["held", "fleet_paused", "module_enabled"])
@pytest.mark.parametrize("bad", [None, 0, 1, "no", 0.0])
def test_the_gate_refuses_anything_but_a_bool(name: str, bad: Any) -> None:
    inp = dinput("diag.refresh")
    for mode in M:
        v = gate(inp, mode=mode, allowlist=(allow("diag.refresh"),), **{name: bad})
        assert v.permission is P.NONE, (name, bad, mode)
        assert "gate_input_invalid" in v.reasons


@pytest.mark.parametrize("bad", [None, 1, "yes"])
def test_guards_green_must_be_true_for_auto_heal(bad: Any) -> None:
    v = gate(
        dinput("diag.refresh"),
        mode=M.AUTO_HEAL,
        allowlist=(allow("diag.refresh"),),
        guards_green=bad,
    )
    assert v.permission is P.NEEDS_APPROVAL
    assert "guards_not_green" in v.reasons


def test_effective_mode_reads_an_unknown_hold_or_pause_as_observe() -> None:
    for kw in ({"held": None}, {"fleet_paused": None}, {"module_enabled": None}):
        args: dict[str, Any] = {
            "module_enabled": True,
            "held": False,
            "fleet_paused": False,
        }
        args.update(kw)
        for risk in RC:
            assert hp.effective_mode(M.AUTO_HEAL, risk=risk, **args) is M.OBSERVE


# ---------------------------------------------------------------------------
# P2-4: a ValidatedAction holds only the catalog's own entry
# ---------------------------------------------------------------------------


def test_a_forged_catalog_entry_cannot_be_wrapped() -> None:
    real = hc.CATALOG["router.reboot"]
    forged = dataclasses.replace(
        real,
        base_risk=RC.READ_ONLY,
        disruption=hc.Disruption.NONE,
        writes=False,
        needs_facts=(),
    )
    with pytest.raises(hc.CatalogError) as err:
        hc.ValidatedAction(entry=forged)
    assert err.value.code == "entry_not_in_catalog"


def test_a_validated_action_checks_its_params_and_components() -> None:
    real = hc.CATALOG["service.restart"]
    with pytest.raises(hc.CatalogError):
        hc.ValidatedAction(entry=real, params={"service": "wpad"})
    with pytest.raises(hc.CatalogError):
        hc.ValidatedAction(entry=real, params={})
    va = hc.validate("service.restart", DNSMASQ)
    with pytest.raises(hc.CatalogError):
        dataclasses.replace(va, params={"service": "dnsmasq; reboot"})
    other = hm.Component(kind=hm.ComponentKind.SERVICE, name="odhcpd")
    with pytest.raises(hc.CatalogError):
        dataclasses.replace(va, components=(other,))
    built = hc.ValidatedAction(entry=real, params=DNSMASQ)
    assert built == va
    assert built.components == (
        hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),
    )


def test_classify_risk_takes_only_a_validated_action() -> None:
    with pytest.raises(hp.PolicyError):
        hp.classify_risk(SimpleNamespace(entry=hc.CATALOG["router.reboot"]), ctx())  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# P2-5: role and topology
# ---------------------------------------------------------------------------


def test_who_depends_on_the_dns_dhcp_shows_in_the_rules_and_the_impact() -> None:
    gateway = hp.decide(
        dinput(
            context=ctx(
                role="gateway",
                dependants=5,
                service_dependant_routers=5,
                service_dependant_clients=60,
                clients_on_router=12,
            )
        )
    )
    small_ap = hp.decide(
        dinput(
            context=ctx(
                role="access_point",
                dependants=0,
                service_dependant_routers=0,
                service_dependant_clients=3,
                clients_on_router=3,
            )
        )
    )
    assert "service_serves_other_routers" in gateway.risk.reasons
    assert "service_serves_other_routers" not in small_ap.risk.reasons
    assert gateway.impact["service_dependant_routers"] == 5
    assert gateway.impact["service_dependant_clients"] == 60
    assert small_ap.impact["service_dependant_clients"] == 3
    explained = gateway.explanation()
    assert explained["impact"]["service_dependant_routers"] == 5
    summary = next(r for r in explained["rules"] if r["code"] == "impact_summary")
    assert summary["detail"]["service_dependant_routers"] == 5
    assert summary["detail"]["service_dependant_clients"] == 60
    # the owner keeps the restart at Risk 2 on a gateway: approval, never lower
    assert gateway.risk.risk_class is RC.MEDIUM
    assert small_ap.risk.risk_class >= hc.CATALOG["service.restart"].base_risk
    assert gateway.outcome is O.REQUIRES_APPROVAL
    impact = gateway.to_impact()
    assert impact.clients_on_router == 12
    assert impact.clients_on_component == 60
    assert impact.est_outage_s == hc.CATALOG["service.restart"].est_outage_s


@pytest.mark.parametrize(
    "fact",
    ["dependants", "role", "service_dependant_routers", "service_dependant_clients"],
)
def test_role_and_topology_are_needed_facts_of_a_restart(fact: str) -> None:
    assert fact in hc.CATALOG["service.restart"].needs_facts
    d = hp.decide(dinput(context=dataclasses.replace(ctx(), **{fact: None})))
    assert d.risk.assessed is False
    assert d.outcome is O.INSUFFICIENT_EVIDENCE


# ---------------------------------------------------------------------------
# P2-6, P2-7, P2-8: sliding window, cooldown, pending outcomes
# ---------------------------------------------------------------------------


def _store(limits: hm.LoopLimits) -> hs.SelfHealingStore:
    store = hs.SelfHealingStore(MagicMock())
    store.settings = hm.HealSettings(limits=limits)
    return store


def _action() -> hm.RemediationAction:
    return hm.RemediationAction.new(
        router_id=R1,
        action_type="service.restart",
        ts=T0,
        params=DNSMASQ,
        components=(hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
    )


def _policy_run(times: list[float], limits: hm.LoopLimits) -> list[str | None]:
    """Try an attempt at each time (policy); book it when allowed."""
    rec: hm.AttemptRecord | None = None
    out: list[str | None] = []
    for t in times:
        v = hp.loop_verdict(
            [KEY],
            attempts={KEY: rec} if rec else {},
            breakers={},
            fleet=hm.FleetPause(),
            limits=limits,
            safe_now=t,
        )
        out.append(v.reason)
        if v.allowed:
            rec = dataclasses.replace(
                hp.book_attempt(rec, limits, t), last_result="resolved"
            )
    return out


def _store_run(times: list[float], limits: hm.LoopLimits) -> list[str | None]:
    store = _store(limits)
    action = _action()
    keys = action.loop_keys
    out: list[str | None] = []
    for t in times:
        reason = store._attempt_refusal(action, t)
        out.append(reason)
        if reason is None:
            booked, _n = store._next_attempts(action, t)
            for k, att in booked.items():
                store.loop.attempts[k] = dataclasses.replace(
                    att, last_result="resolved"
                )
    del keys
    return out


def test_at_most_n_attempts_in_any_24h_span() -> None:
    """The reviewer's schedule: 0, 86000, 89600, 91400 s."""
    lim = hm.LoopLimits()  # 2 per 24 h, 30 min cooldown
    times = [T0, T0 + 86000, T0 + 89600, T0 + 93200]
    got = _policy_run(times, lim)
    assert got[:3] == [None, None, None]
    assert got[3] == "max_attempts"
    assert _store_run(times, lim) == got


def test_the_retry_time_is_when_the_oldest_attempt_leaves_the_span() -> None:
    lim = hm.LoopLimits()
    rec = hp.book_attempt(None, lim, T0)
    rec = hp.book_attempt(rec, lim, T0 + 7200)
    v = hp.loop_verdict(
        [KEY],
        attempts={KEY: rec},
        breakers={},
        fleet=hm.FleetPause(),
        limits=lim,
        safe_now=T0 + 20000,
    )
    assert v.reason == "max_attempts"
    assert v.retry_at == T0 + DAY
    ok = hp.loop_verdict(
        [KEY],
        attempts={KEY: rec},
        breakers={},
        fleet=hm.FleetPause(),
        limits=lim,
        safe_now=T0 + DAY,
    )
    assert ok.allowed


def test_policy_and_store_agree_on_random_schedules() -> None:
    import random

    rng = random.Random(77)
    for _ in range(200):
        lim = hm.LoopLimits(
            cooldown_s=rng.choice([600, 1800]),
            max_attempts_24h=rng.randint(1, 3),
            backoff_base_s=rng.choice([600, 1800]),
            backoff_cap_s=rng.choice([3600, 86400]),
        )
        t = T0
        times = []
        for _step in range(8):
            t += rng.choice([0, 600, 1800, 3600, 20000, 50000, 86000, 90000])
            times.append(t)
        assert _policy_run(times, lim) == _store_run(times, lim), times


def test_a_booking_never_shortens_a_running_cooldown() -> None:
    long = hm.AttemptRecord(
        count=1, window_start=T0, last_at=T0, cooldown_until=T0 + 200_000, recent=(T0,)
    )
    short = hm.LoopLimits(cooldown_s=600, backoff_base_s=600, backoff_cap_s=3600)
    at = T0 + 100_000
    booked = hp.book_attempt(long, short, at)
    assert booked.cooldown_until == T0 + 200_000
    store = _store(short)
    action = _action()
    for k in action.loop_keys:
        store.loop.attempts[k] = long
    out, _n = store._next_attempts(action, at)
    assert all(a.cooldown_until == T0 + 200_000 for a in out.values())


def test_the_reviewers_cooldown_case() -> None:
    lim3 = hm.LoopLimits(
        cooldown_s=600, backoff_base_s=600, backoff_cap_s=86400, max_attempts_24h=3
    )
    a = hp.book_attempt(None, lim3, T0)
    a = hp.book_attempt(a, lim3, T0 + 80_000)
    a = hp.book_attempt(a, lim3, T0 + 85_000)
    before = a.cooldown_until
    b = hp.book_attempt(a, lim3, T0 + 86_500)
    assert b.cooldown_until >= before


def test_an_unrecorded_outcome_counts_as_not_resolved() -> None:
    lim = hm.LoopLimits()
    rec = dataclasses.replace(hp.book_attempt(None, lim, T0), last_result="resolved")
    rec2 = hp.book_attempt(rec, lim, T0 + 90_000)
    assert rec2.last_result is None  # pending: no outcome recorded yet
    assert hp.prior_failed_attempts([KEY], {KEY: rec2}, T0 + 95_000) == 1
    store = _store(lim)
    action = _action()
    for k in action.loop_keys:
        store.loop.attempts[k] = rec
    out, _n = store._next_attempts(action, T0 + 90_000)
    assert all(a.last_result is None for a in out.values())


def test_a_resolved_last_attempt_still_leaves_the_earlier_ones_counted() -> None:
    lim = hm.LoopLimits(max_attempts_24h=3)
    rec = hp.book_attempt(None, lim, T0)
    rec = hp.book_attempt(rec, lim, T0 + 4000)
    rec = dataclasses.replace(rec, last_result="resolved")
    assert hp.prior_failed_attempts([KEY], {KEY: rec}, T0 + 5000) == 1


def test_an_attempt_record_of_the_current_main_loads_strictly() -> None:
    """Files written before the sliding window have no ``recent``: every
    counted attempt is taken as made at the last attempt (the latest time
    known), so the record blocks at least as long as before."""
    old = {
        "count": 2,
        "window_start": T0,
        "last_at": T0 + 80_000,
        "cooldown_until": T0 + 83_600,
        "backoff_step": 1,
        "last_result": None,
    }
    rec = hm.AttemptRecord.from_dict(old)
    assert rec.recent == (T0 + 80_000, T0 + 80_000)
    lim = hm.LoopLimits()
    v = hp.loop_verdict(
        [KEY],
        attempts={KEY: rec},
        breakers={},
        fleet=hm.FleetPause(),
        limits=lim,
        safe_now=T0 + DAY + 1000,
    )
    assert v.reason == "max_attempts"
    assert v.retry_at == T0 + 80_000 + DAY
    again = hm.AttemptRecord.from_dict(rec.to_dict())
    assert again == rec
    row = {"router_id": KEY[0], "action_type": KEY[1], "ref": KEY[2], **old}
    loop = hm.LoopState.from_dict({"attempts": [row]})
    assert loop.attempts[KEY].recent == (T0 + 80_000, T0 + 80_000)


def test_the_store_minor_version_marks_the_additive_field() -> None:
    assert hs.HEAL_STORE_VERSION == 1
    assert hs.HEAL_STORE_MINOR_VERSION == 2
    assert hs._migrate(1, 1, {"loop": {}}) == {"loop": {}}


def test_recent_attempt_times_are_bounded_and_checked() -> None:
    with pytest.raises(hm.HealModelError):
        hm.AttemptRecord(recent=(T0,) * (hm.RECENT_ATTEMPTS_MAX + 1))
    with pytest.raises(hm.HealModelError):
        hm.AttemptRecord(recent=(float("nan"),))
    lim = hm.LoopLimits(max_attempts_24h=3, cooldown_s=600, backoff_base_s=600)
    rec = None
    for i in range(6):
        rec = hp.book_attempt(rec, lim, T0 + i * 30_000)
    assert rec is not None
    assert len(rec.recent) <= hm.RECENT_ATTEMPTS_MAX


# ---------------------------------------------------------------------------
# P2-9: open owner questions are provisional
# ---------------------------------------------------------------------------


def test_the_catalog_does_not_call_open_questions_owner_decisions() -> None:
    doc = hc.__doc__ or ""
    assert "Owner decisions" not in doc
    assert "PROVISIONAL" in doc


def test_the_docs_mark_q5_to_q7_as_provisional() -> None:
    text = (ROOT / "docs" / "self-healing.md").read_text(encoding="utf-8")
    for q in ("| Q5 |", "| Q6 |", "| Q7 |"):
        row = next(line for line in text.splitlines() if line.startswith(q))
        assert "entschieden" not in row.lower(), row
        assert "vorläufig" in row.lower(), row


# ---------------------------------------------------------------------------
# P2-10: honest rollback statement and the saved configuration
# ---------------------------------------------------------------------------


def test_the_restart_says_it_applies_the_saved_configuration() -> None:
    e = hc.CATALOG["service.restart"]
    assert e.rollback_statement == "applies_saved_config_no_undo_manual_if_not_back"
    assert e.rollback is hc.RollbackKind.MANUAL_RECOVERY
    assert "service_config_unapplied" in e.needs_facts


def test_an_unapplied_configuration_makes_the_restart_not_safe() -> None:
    d = hp.decide(dinput(context=ctx(service_config_unapplied=True)))
    assert d.outcome is O.NOT_SAFE
    assert d.why_not == "service_config_unapplied"
    unknown = hp.decide(dinput(context=ctx(service_config_unapplied=None)))
    assert unknown.outcome is O.INSUFFICIENT_EVIDENCE
    ok = hp.decide(dinput(context=ctx(service_config_unapplied=False)))
    assert ok.outcome is O.REQUIRES_APPROVAL


def test_the_general_config_change_penalty_stays() -> None:
    s = hp.score(inc(), prior_failed_attempts=0, config_change_24h=True)
    line = {c.factor: c for c in s.contributions}["config_change"]
    assert line.points == hp.CONFIG_CHANGE_POINTS == -20


# ---------------------------------------------------------------------------
# P2-11: the reviewer's surviving mutations
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "bkp_" + "a" * 32 + ";reboot",
        "bkp_" + "a" * 33,
        "bkp_" + "a" * 32 + "\n",
        "bkp_" + "a" * 31,
        "bkp_" + "A" * 32,
    ],
)
def test_a_backup_id_must_match_completely(bad: str) -> None:
    with pytest.raises(hc.CatalogError):
        hc.validate("config.restore", {"version_id": bad})
    assert hc.validate("config.restore", {"version_id": "bkp_" + "a" * 32})


def test_an_unknown_root_alone_blocks_a_write() -> None:
    d = hp.decide(dinput(incident=inc(is_root=None)))
    assert d.outcome is O.INSUFFICIENT_EVIDENCE
    assert d.why_not == "root_unknown"
    assert [h.code for h in d.hits if h.blocking] == ["root_unknown"]


def test_clean_refusals_count_towards_the_fleet_pause() -> None:
    fleet = hm.FleetPause()
    lim = hm.LoopLimits()
    for i in range(lim.fleet_failure_threshold):
        up = hp.record_outcome(
            [(R1, "service.restart", f"service:x{i}")],
            EV.REJECTED,
            automatic=False,
            attempts={},
            breakers={},
            fleet=fleet,
            limits=lim,
            safe_now=T0 + i,
        )
        fleet = up.fleet
    assert fleet.paused(T0 + 10)
    assert fleet.reason == "fleet_failures"


def _score_input(confidence: float) -> hp.DecisionInput:
    # possible 15 + confirmed status 10 + no family 0 + direct 30 = 55
    return dinput(
        incident=inc(
            cause_level=hm.CauseLevel.POSSIBLE,
            cause_status=hm.CauseStatus.CONFIRMED,
            source_families=0,
            confidence=confidence,
        )
    )


def test_the_score_threshold_boundary() -> None:
    below = hp.decide(_score_input(0.4))
    at = hp.decide(_score_input(0.5))
    assert below.score.total == 59
    assert at.score.total == 60
    assert below.outcome is O.INSUFFICIENT_EVIDENCE
    assert below.why_not == "score_below_threshold"
    assert at.outcome is O.REQUIRES_APPROVAL


@pytest.mark.parametrize(
    "bad", [1.01, 2.0, -0.01, float("nan"), float("inf"), True, False, "0.5"]
)
def test_a_confidence_outside_0_to_1_is_refused(bad: Any) -> None:
    with pytest.raises(hp.PolicyError):
        inc(confidence=bad)


# ---------------------------------------------------------------------------
# P3
# ---------------------------------------------------------------------------


def test_only_a_real_policy_limits_object_is_accepted() -> None:
    fake = SimpleNamespace(
        score_min=0, manual_failures_to_open=9, auto_failures_to_open=9
    )
    with pytest.raises(hp.PolicyError):
        hp.decide(dinput(), fake)  # type: ignore[arg-type]
    with pytest.raises(hp.PolicyError):
        gate(dinput(), limits=fake)
    with pytest.raises(hp.PolicyError):
        hp.record_outcome(
            [KEY],
            EV.REJECTED,
            automatic=False,
            attempts={},
            breakers={},
            fleet=hm.FleetPause(),
            limits=hm.LoopLimits(),
            safe_now=T0,
            policy=fake,  # type: ignore[arg-type]
        )


def test_policy_limits_raise_the_policy_error() -> None:
    with pytest.raises(hp.PolicyError):
        hp.PolicyLimits(score_min=59)
    with pytest.raises(hp.PolicyError):
        hp.PolicyLimits(manual_failures_to_open=3)


def test_manual_refusals_between_successes_still_open_the_breaker() -> None:
    br: dict[Any, hm.BreakerRecord] = {}
    fleet = hm.FleetPause()
    opened_at = None
    for i, ev in enumerate([EV.REJECTED, EV.RESOLVED, EV.REJECTED]):
        up = hp.record_outcome(
            [KEY],
            ev,
            automatic=False,
            attempts={},
            breakers=br,
            fleet=fleet,
            limits=hm.LoopLimits(),
            safe_now=T0 + i * 100_000,
        )
        br, fleet = up.breakers, up.fleet
        if up.opened:
            opened_at = i
    assert br[KEY].state is hm.BreakerState.OPEN
    assert opened_at == 2


def test_dedupe_takes_its_components_from_the_catalog() -> None:
    loop = hm.LoopState()
    comp = hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq")
    loop.component_dedupe[hm.component_dedupe_id(R1, comp)] = "rem_" + "a" * 32
    v = hp.dedupe_verdict(
        loop,
        router_id=R1,
        action_type="service.restart",
        params=DNSMASQ,
        incident_id=None,
    )
    assert v.kind == "component"
    with pytest.raises(hc.CatalogError):
        hp.dedupe_verdict(
            loop,
            router_id=R1,
            action_type="service.restart",
            params={"service": "wpad"},
            incident_id=None,
        )
    with pytest.raises(TypeError):
        hp.dedupe_verdict(  # type: ignore[call-arg]
            loop,
            router_id=R1,
            action_type="service.restart",
            params=DNSMASQ,
            incident_id=None,
            components=(),
        )


def test_maintenance_has_one_source_the_context() -> None:
    with pytest.raises(TypeError):
        gate(dinput("diag.refresh"), in_maintenance=False)
    v = gate(
        dinput("diag.refresh", context=ctx(in_maintenance=True)),
        mode=M.AUTO_HEAL,
        allowlist=(allow("diag.refresh"),),
    )
    assert v.permission is P.NEEDS_APPROVAL
    assert "in_maintenance" in v.reasons
    v = gate(
        dinput("diag.refresh", context=ctx(in_maintenance=None)),
        mode=M.AUTO_HEAL,
        allowlist=(allow("diag.refresh"),),
    )
    assert v.permission is P.NEEDS_APPROVAL
    v = gate(
        dinput("diag.refresh"),
        mode=M.AUTO_HEAL,
        allowlist=(allow("diag.refresh"),),
    )
    assert v.permission is P.AUTO_RUN


def test_diag_refresh_keeps_its_interval_of_five_minutes() -> None:
    assert hc.CATALOG["diag.refresh"].min_interval_s == 300
    assert hp.interval_verdict("diag.refresh", last_run_at=None, safe_now=T0).allowed
    v = hp.interval_verdict("diag.refresh", last_run_at=T0, safe_now=T0 + 299)
    assert v.reason == "min_interval"
    assert v.retry_at == T0 + 300
    assert hp.interval_verdict(
        "diag.refresh", last_run_at=T0, safe_now=T0 + 300
    ).allowed
    with pytest.raises(hc.CatalogError):
        hp.interval_verdict("firewall.x", last_run_at=None, safe_now=T0)
    row = next(r for r in hc.catalog_table() if r["action_type"] == "diag.refresh")
    assert row["min_interval_s"] == 300


def test_dhcp_lease_actions_are_never_in_the_catalog() -> None:
    for bad in ("dhcp.lease_delete", "dhcp.flush"):
        with pytest.raises(hc.CatalogError) as err:
            hc.validate(bad, {})
        assert err.value.code == "never_dhcp_lease_delete"
    d = hp.decide(dinput("dhcp.lease_delete", {}))
    assert d.outcome is O.UNSUPPORTED
    assert d.why_not == "never_dhcp_lease_delete"
    assert "never_dhcp_lease_delete" in hp.REASON_TEXT_DE


def test_a_cause_outside_the_router_blocks_the_restart() -> None:
    outside = hp.decide(dinput(incident=inc(cause_outside_router=True)))
    assert outside.outcome is O.NOT_SAFE
    assert outside.why_not == "cause_outside_router"
    unknown = hp.decide(dinput(incident=inc(cause_outside_router=None)))
    assert unknown.outcome is O.INSUFFICIENT_EVIDENCE
    assert any(h.code == "cause_location_unknown" for h in unknown.hits)
    inside = hp.decide(dinput(incident=inc(cause_outside_router=False)))
    assert inside.outcome is O.REQUIRES_APPROVAL


def test_every_new_code_has_a_german_text() -> None:
    for code in (
        "history_unknown",
        "service_serves_other_routers",
        "service_config_unapplied",
        "cause_outside_router",
        "cause_location_unknown",
        "gate_input_invalid",
        "min_interval",
        "never_dhcp_lease_delete",
        "entry_not_in_catalog",
    ):
        assert code in hp.REASON_TEXT_DE, code
        assert code in hp.RULE_CODES or code in hc.REFUSAL_CODES, code


# ---------------------------------------------------------------------------
# Mutations that survived once the docs test was green (each test below
# fails with the named mutation applied)
# ---------------------------------------------------------------------------


def test_a_radio_restart_counts_the_clients_on_the_radio_not_the_router() -> None:
    """Reviewer M5: the radio's own clients decide ``clients_affected``."""
    va = hc.validate("wifi.radio_restart", {"radio": "radio0"})
    quiet_radio = hp.classify_risk(va, ctx(clients_on_router=30, clients_on_target=0))
    assert "clients_affected" not in quiet_radio.reasons
    busy_radio = hp.classify_risk(va, ctx(clients_on_router=0, clients_on_target=3))
    assert "clients_affected" in busy_radio.reasons


def test_every_router_reboot_is_on_the_management_path() -> None:
    """Reviewer M6: a reboot cuts HA's path even when the fact says no."""
    va = hc.validate("router.reboot", {})
    risk = hp.classify_risk(va, ctx(target_on_mgmt_path=False))
    assert "target_on_management_path" in risk.reasons
    assert risk.risk_class is RC.HIGH


def test_an_entry_never_covers_a_risk_above_its_own_max_risk() -> None:
    """Reviewer M19: ``max_risk`` of the entry is a limit of its own."""
    entry = hm.AllowEntry(action_type="observe.evaluate", params={}, max_risk=0)
    assert hp.is_allowlisted([entry], "observe.evaluate", {}, RC.READ_ONLY)
    assert not hp.is_allowlisted([entry], "observe.evaluate", {}, RC.LOW)


def test_an_assessed_high_risk_is_named_as_not_safe() -> None:
    """Reviewer M22: Risk 3 without any other hard reason still carries the
    ``risk_high_no_recovery`` Not-Safe hit (there is no rollback)."""
    d = hp.decide(dinput("interface.cycle", {"interface": "lan"}))
    assert d.risk.assessed and d.risk.risk_class is RC.HIGH
    hit = next(h for h in d.hits if h.code == "risk_high_no_recovery")
    assert hit.outcome is O.NOT_SAFE and hit.blocking
    assert d.outcome is O.UNSUPPORTED  # disabled comes first


def test_auto_heal_never_runs_a_decision_that_requires_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reviewer M26, defence in depth: should ``decide`` ever return
    Requires Approval at Risk 1, Auto-Heal still asks for an approval."""
    real = hp.decide

    def asks(inp: hp.DecisionInput, limits: Any = hp.DEFAULT_POLICY_LIMITS):
        return dataclasses.replace(real(inp, limits), outcome=O.REQUIRES_APPROVAL)

    allowlist = (allow("diag.refresh"),)
    ok = gate(dinput("diag.refresh"), mode=M.AUTO_HEAL, allowlist=allowlist)
    assert ok.permission is P.AUTO_RUN
    monkeypatch.setattr(hp, "decide", asks)
    v = gate(dinput("diag.refresh"), mode=M.AUTO_HEAL, allowlist=allowlist)
    assert v.permission is P.NEEDS_APPROVAL
    assert "risk_above_auto_limit" in v.reasons


def test_the_gate_checks_the_input_type_before_anything_else() -> None:
    """N1a: even when the module is off or a switch is not a bool, anything
    but a ``DecisionInput`` is an error, not a quiet refusal."""
    decision = hp.decide(dinput())
    with pytest.raises(hp.PolicyError):
        gate(decision, module_enabled=False)
    with pytest.raises(hp.PolicyError):
        gate(decision, held=None)


def test_decide_takes_only_the_exact_input_type() -> None:
    """N1b/N1c: a subclass or a look-alike is never decided."""

    class Sneaky(hp.DecisionInput):
        __slots__ = ()

    with pytest.raises(hp.PolicyError):
        hp.decide(Sneaky(action_type="diag.refresh", params={}))
    look_alike = SimpleNamespace(
        **{f.name: getattr(dinput(), f.name) for f in dataclasses.fields(dinput())}
    )
    with pytest.raises(hp.PolicyError):
        hp.decide(look_alike)  # type: ignore[arg-type]


def test_the_gate_checks_limits_before_any_early_refusal() -> None:
    """N27b: a fake limits object is an error even on an early refusal."""
    fake = SimpleNamespace(
        score_min=0, manual_failures_to_open=9, auto_failures_to_open=9
    )
    with pytest.raises(hp.PolicyError):
        gate(dinput(), limits=fake, module_enabled=False)
    with pytest.raises(hp.PolicyError):
        gate(dinput(), limits=fake, held=None)


def test_with_a_lowered_limit_the_retry_waits_for_the_right_attempt() -> None:
    """N32: three attempts booked under a limit of 3, then the limit is
    lowered to 2 - the next attempt may run when the SECOND oldest leaves
    the span (only then are fewer than 2 left), not the oldest."""
    three = hm.LoopLimits(max_attempts_24h=3)
    att = None
    for t in (T0, T0 + 3600, T0 + 7200):
        att = hp.book_attempt(att, three, t)
    assert att is not None and att.recent == (T0, T0 + 3600, T0 + 7200)
    now = T0 + 20_000  # after the cooldown
    v = hp.loop_verdict(
        [KEY],
        attempts={KEY: att},
        breakers={},
        fleet=hm.FleetPause(),
        limits=hm.LoopLimits(max_attempts_24h=2),
        safe_now=now,
    )
    assert v.reason == "max_attempts"
    assert v.retry_at == T0 + 3600 + DAY


def test_a_resolved_result_only_excuses_the_attempt_it_belongs_to() -> None:
    """N35: when the stored last attempt is not the newest time in the span
    (an inconsistent record), nothing is excused - strict reading."""
    rec = hm.AttemptRecord(
        count=2,
        window_start=T0,
        last_at=T0,
        recent=(T0, T0 + 100),
        last_result="resolved",
    )
    assert hp.prior_failed_attempts([KEY], {KEY: rec}, T0 + 200) == 2
    consistent = dataclasses.replace(rec, last_at=T0 + 100)
    assert hp.prior_failed_attempts([KEY], {KEY: consistent}, T0 + 200) == 1
