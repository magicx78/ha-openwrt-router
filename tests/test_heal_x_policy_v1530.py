"""Self-Healing, package X (1.53.0): the leftover review nits of package D
and the store's refusal during a fleet pause.

Each test failed before its fix (or kills a mutation that survived the
review of PR #77):

* g ``gate`` re-validates its frozen inputs (``replace``) and takes the
  validated action from its own decision: mutation through
  ``object.__setattr__`` or a mapping that answers differently on each read
  cannot yield a permission the facts do not justify;
* h a booking past the limit keeps a backoff at least as long as the old
  fixed-window rule (``recent`` keeps only 3 times);
* i ``interval_verdict`` with an unknown last run refuses a write;
* j the three surviving mutations: the catalog identity check (``is``, not
  ``==``), ``PolicyLimits`` by exact type (not ``isinstance``), the
  sliding-window edge below one second;
* k ``ATTEMPT_WINDOW_S`` is defined once, in the model;
* the store's durable step into EXECUTING refuses during a fleet pause, in
  the same order as the policy's ``loop_verdict``.

Pure except the store tests (FakeDisks, a mocked hass): no router, no
network.
"""

from __future__ import annotations

import ast
import dataclasses
import pathlib
import random
from collections.abc import Iterator, Mapping
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import FakeDisks
from test_heal_review_pr77_v1530 import GATE_OK, allow, ctx, dinput, gate, inc
from test_heal_store_v1530 import (
    R1,
    T0,
    Clock,
    advance,
    disks,
    execute,
    new_action,
    open_store,
    to_approved,
)

from custom_components.openwrt_router import heal_catalog as hc
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_policy as hp
from custom_components.openwrt_router import heal_store as hs

O = hm.DecisionOutcome
P = hp.Permission
M = hm.HealMode
DAY = 86400
DNSMASQ = {"service": "dnsmasq"}
ROOT = pathlib.Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "openwrt_router"

__all__ = ["disks"]  # fixture used here


# ---------------------------------------------------------------------------
# g: the gate re-validates its frozen inputs
# ---------------------------------------------------------------------------


class _Flip(Mapping):
    """Answers the next value of ``seq`` on every read (counts the reads)."""

    def __init__(self, seq: list[str]) -> None:
        self.seq = seq
        self.n = 0

    def __getitem__(self, key: str) -> str:
        value = self.seq[min(self.n, len(self.seq) - 1)]
        self.n += 1
        return value

    def __iter__(self) -> Iterator[str]:
        return iter(["service"])

    def __len__(self) -> int:
        return 1


@pytest.mark.parametrize(
    "seq",
    [
        ["dnsmasq", "odhcpd"],
        ["odhcpd", "dnsmasq"],
        ["dnsmasq", "wpad"],
        ["wpad", "dnsmasq"],
        ["dnsmasq", "dnsmasq; reboot"],
    ],
)
def test_the_gate_reads_slipped_in_params_once(seq: list[str]) -> None:
    """A mapping slipped in after construction is read exactly once per gate
    call, and the decision is about the value that was checked."""
    inp = dinput()
    flip = _Flip(seq)
    object.__setattr__(inp, "params", flip)
    v = gate(inp)
    assert flip.n == 1
    first = seq[0]
    if first in hc.SERVICE_NAMES:
        assert v.decision is not None
        assert dict(v.decision.params) == {"service": first}
        assert v.permission is P.NEEDS_APPROVAL
    else:
        assert v.permission is P.NONE


def test_raw_params_slipped_in_after_construction_are_checked() -> None:
    inp = dinput()
    object.__setattr__(inp, "params", {"service": "wpad"})
    assert gate(inp).permission is P.NONE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("service_enabled", 0),
        ("open_security_findings", -1),
        ("service_config_unapplied", 0),
        ("role", "GATEWAY"),
        ("identity_confirmed", 1),
        ("reachable", "yes"),
        ("in_maintenance", 0),
        ("clients_on_router", 1.5),
    ],
)
def test_a_context_changed_after_construction_is_refused(
    field: str, value: Any
) -> None:
    c = ctx()
    object.__setattr__(c, field, value)
    v = gate(dinput(context=c))
    assert v.permission is P.NONE
    assert v.reasons == ("gate_input_invalid",)
    with pytest.raises(hp.PolicyError):
        hp.decide(dinput(context=c))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_families", -1),
        ("confidence", 2.0),
        ("severity", "CRITICAL"),
        ("is_root", 1),
        ("temporal_only", 0),
        ("cause_level", "certain"),
    ],
)
def test_incident_facts_changed_after_construction_are_refused(
    field: str, value: Any
) -> None:
    i = inc()
    object.__setattr__(i, field, value)
    v = gate(dinput(incident=i))
    assert v.permission is P.NONE
    assert v.reasons == ("gate_input_invalid",)


def test_a_context_swapped_for_a_lookalike_is_refused() -> None:
    inp = dinput()

    class Sub(hp.RiskContext):  # type: ignore[misc]
        __slots__ = ()

    object.__setattr__(inp, "context", Sub(**dataclasses.asdict(ctx())))
    assert gate(inp).reasons == ("gate_input_invalid",)
    object.__setattr__(inp, "context", object())
    assert gate(inp).reasons == ("gate_input_invalid",)
    other = dinput()
    object.__setattr__(other, "incident", ctx())
    assert gate(other).reasons == ("gate_input_invalid",)
    third = dinput()
    object.__setattr__(third, "prior_failed_attempts", -3)
    assert gate(third).reasons == ("gate_input_invalid",)


def test_limits_changed_after_construction_are_refused() -> None:
    limits = hp.PolicyLimits()
    object.__setattr__(limits, "score_min", 0)
    with pytest.raises(hp.PolicyError):
        gate(dinput(prior_failed_attempts=3), limits=limits)
    with pytest.raises(hp.PolicyError):
        hp.decide(dinput(), limits)


def test_the_gate_takes_the_action_from_its_own_decision() -> None:
    """The decision records the catalog refusal; the gate does not validate
    the input a second time on its own."""
    d = hp.decide(dinput("firewall.open", {}))
    assert d.refusal == "never_firewall"
    assert hp.decide(dinput()).refusal is None
    v = gate(dinput("firewall.open", {}))
    assert v.reasons == ("never_firewall",)
    assert v.decision is not None and v.decision.refusal == "never_firewall"


def test_the_catalog_entry_comes_from_the_decision_not_the_input() -> None:
    """Should a decision ever name another action than its input, the gate
    reads the entry (and so ``in_release``) from the decision (kills the
    mutation that validates ``inp`` again)."""
    other = hp.decide(dinput("diag.refresh"))
    assert other.action_type == "diag.refresh"
    with patch.object(hp, "decide", lambda inp, limits=None: other):
        v = gate(
            dinput("observe.evaluate"),
            mode=M.AUTO_HEAL,
            allowlist=(allow("diag.refresh"),),
        )
    assert v.permission is P.AUTO_RUN
    assert v.in_release is False and v.executable_now is False
    assert "not_in_release" in v.reasons


def test_a_good_input_still_passes_after_the_revalidation() -> None:
    assert gate(dinput()).permission is P.NEEDS_APPROVAL
    v = gate(
        dinput("diag.refresh"), mode=M.AUTO_HEAL, allowlist=(allow("diag.refresh"),)
    )
    assert v.permission is P.AUTO_RUN


# ---------------------------------------------------------------------------
# h: booking past the limit never shortens the backoff
# ---------------------------------------------------------------------------


def _old_book(att: dict | None, lim: hm.LoopLimits, safe: float) -> dict:
    """The fixed-window rule before the review of PR #77 (the reviewer's)."""
    a = att or {"count": 0, "window_start": None, "cooldown_until": None}
    fresh = not (a["window_start"] is not None and safe < a["window_start"] + DAY)
    count = 1 if fresh else a["count"] + 1
    step = min(count - 1, hm.BACKOFF_STEP_MAX)
    backoff = min(lim.backoff_base_s * 2**step, lim.backoff_cap_s)
    return {
        "count": count,
        "window_start": safe if fresh else a["window_start"],
        "cooldown_until": safe + max(lim.cooldown_s, backoff),
    }


def _limits(rng: random.Random) -> hm.LoopLimits:
    base = rng.choice([600, 1800, 3600])
    return hm.LoopLimits(
        cooldown_s=rng.choice([600, 1800, 7200]),
        max_attempts_24h=rng.choice([1, 2, 3]),
        backoff_base_s=base,
        backoff_cap_s=86400,
    )


@pytest.mark.parametrize("seed", range(6))
def test_bookings_past_the_limit_keep_the_longer_backoff(seed: int) -> None:
    """Booked whether the limit allows it or not (the pure function must be
    safe on its own): the cooldown is never shorter than the old rule's."""
    rng = random.Random(seed)
    for _ in range(300):
        lim = _limits(rng)
        old: dict | None = None
        new: hm.AttemptRecord | None = None
        t = T0
        for _step in range(10):
            t += rng.choice([1, 60, 600, 1800, 3600, 20000, 80000, 86399, 90000])
            old = _old_book(old, lim, t)
            new = hp.book_attempt(new, lim, t)
            assert new.cooldown_until >= old["cooldown_until"], (lim, t - T0)


def test_five_bookings_in_a_row_keep_doubling() -> None:
    lim = hm.LoopLimits(cooldown_s=600, backoff_base_s=600, max_attempts_24h=2)
    rec = None
    waits = []
    for i in range(6):
        t = T0 + i
        rec = hp.book_attempt(rec, lim, t)
        waits.append(rec.cooldown_until - t)
    # the 4th and later bookings are past the limit: still growing
    assert waits[3] < waits[4] < waits[5]


def test_allowed_bookings_are_unchanged() -> None:
    lim = hm.LoopLimits()
    rec = hp.book_attempt(None, lim, T0)
    assert rec.backoff_step == 0 and rec.cooldown_until == T0 + 1800
    rec = hp.book_attempt(rec, lim, T0 + 3600)
    assert rec.backoff_step == 1 and rec.cooldown_until == T0 + 3600 + 3600


async def test_the_store_books_like_the_policy_also_past_the_limit(
    disks: FakeDisks,
) -> None:
    rng = random.Random(3)
    clock = Clock()
    store, _ = await open_store(clock)
    action = hm.RemediationAction.new(
        router_id=R1,
        action_type="service.restart",
        ts=T0,
        params=DNSMASQ,
        components=(hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
    )
    keys = action.loop_keys
    for _ in range(40):
        lim = _limits(rng)
        store.set_settings(hm.HealSettings(limits=lim))
        store.loop.attempts.clear()
        t = T0
        for _step in range(8):
            t += rng.choice([1, 600, 3600, 86000, 90000])
            booked, _n = store._next_attempts(action, t)
            assert booked == hp.book_attempts(keys, store.loop.attempts, lim, t)
            store.loop.attempts.update(booked)


# ---------------------------------------------------------------------------
# i: an unknown last run refuses a write
# ---------------------------------------------------------------------------


def test_an_unknown_last_run_refuses_a_write() -> None:
    v = hp.interval_verdict("service.restart", last_run_at=None, safe_now=T0)
    assert v.allowed is False
    assert v.reason == "interval_unknown"
    assert v.retry_at is None
    assert "interval_unknown" in hp.LOOP_CODES
    assert hp.REASON_TEXT_DE["interval_unknown"]
    for action_type in ("wifi.radio_restart", "router.reboot", "interface.cycle"):
        assert not hp.interval_verdict(
            action_type, last_run_at=None, safe_now=T0
        ).allowed


def test_never_ran_must_be_said_for_a_write() -> None:
    assert hp.interval_verdict(
        "service.restart", last_run_at=None, safe_now=T0, never_ran=True
    ).allowed
    with pytest.raises(hp.PolicyError):
        hp.interval_verdict(
            "service.restart", last_run_at=T0, safe_now=T0, never_ran=True
        )
    with pytest.raises(hp.PolicyError):
        hp.interval_verdict(
            "service.restart", last_run_at=None, safe_now=T0, never_ran=1
        )


def test_read_only_actions_keep_never_ran_for_unknown() -> None:
    for action_type in ("observe.evaluate", "diag.refresh", "diag.ha_probes"):
        assert hp.interval_verdict(action_type, last_run_at=None, safe_now=T0).allowed
    assert hp.interval_verdict("service.restart", last_run_at=T0, safe_now=T0).allowed


# ---------------------------------------------------------------------------
# j: the three mutations that survived the review of PR #77
# ---------------------------------------------------------------------------


def test_an_equal_copy_of_a_catalog_entry_is_refused() -> None:
    """``is``, not ``==``: an equal copy (``replace`` without changes) is
    not the catalog's own entry."""
    for action_type, entry in hc.CATALOG.items():
        copy = dataclasses.replace(entry)
        assert copy == entry and copy is not entry
        params = {
            p.name: (p.choices[0] if p.choices else "bkp_" + "a" * 32)
            for p in entry.params
        }
        with pytest.raises(hc.CatalogError) as err:
            hc.ValidatedAction(entry=copy, params=params)
        assert err.value.code == "entry_not_in_catalog", action_type
        hc.ValidatedAction(entry=entry, params=params)


def test_a_limits_subclass_that_skips_validation_is_refused() -> None:
    class Loose(hp.PolicyLimits):  # type: ignore[misc]
        __slots__ = ()

        def __post_init__(self) -> None:
            return None  # no bounds check

    loose = Loose(score_min=0)
    assert isinstance(loose, hp.PolicyLimits) and loose.score_min == 0
    with pytest.raises(hp.PolicyError):
        gate(dinput(prior_failed_attempts=3), limits=loose)
    with pytest.raises(hp.PolicyError):
        hp.decide(dinput(), loose)
    with pytest.raises(hp.PolicyError):
        hp.record_outcome(
            [("k",)],
            hp.OutcomeEvent.REJECTED,
            automatic=False,
            attempts={},
            breakers={},
            fleet=hm.FleetPause(),
            limits=hm.LoopLimits(),
            safe_now=T0,
            policy=loose,
        )


@pytest.mark.parametrize("below", [0.5, 0.001, 0.25])
def test_the_sliding_window_edge_below_one_second(below: float) -> None:
    rec = hm.AttemptRecord(
        count=1, window_start=T0, last_at=T0, cooldown_until=T0 + 1, recent=(T0,)
    )
    inside = T0 + DAY - below
    assert rec.times_in_window(inside) == (T0,)
    assert rec.times_in_window(T0 + DAY) == ()
    lim = hm.LoopLimits(max_attempts_24h=1, cooldown_s=600)

    def verdict(at: float) -> hp.LoopVerdict:
        return hp.loop_verdict(
            [("k",)],
            attempts={("k",): rec},
            breakers={},
            fleet=hm.FleetPause(),
            limits=lim,
            safe_now=at,
        )

    assert verdict(inside).reason == "max_attempts"
    assert verdict(inside).retry_at == T0 + DAY
    assert verdict(T0 + DAY).allowed
    assert hp.prior_failed_attempts([("k",)], {("k",): rec}, inside) == 1
    assert hp.prior_failed_attempts([("k",)], {("k",): rec}, T0 + DAY) == 0


# ---------------------------------------------------------------------------
# k: one definition of the attempt window
# ---------------------------------------------------------------------------


def _assigned_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            out |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            out.add(node.target.id)
    return out


def test_the_attempt_window_is_defined_once_in_the_model() -> None:
    assert "ATTEMPT_WINDOW_S" in _assigned_names(COMPONENT / "heal_model.py")
    for name in ("heal_store.py", "heal_policy.py", "heal_engine.py"):
        assert "ATTEMPT_WINDOW_S" not in _assigned_names(COMPONENT / name), name
    assert hs.ATTEMPT_WINDOW_S is hm.ATTEMPT_WINDOW_S
    assert hp.ATTEMPT_WINDOW_S is hm.ATTEMPT_WINDOW_S


# ---------------------------------------------------------------------------
# The store refuses the durable step during a fleet pause (docs §15)
# ---------------------------------------------------------------------------


async def test_the_durable_step_refuses_during_a_fleet_pause(
    disks: FakeDisks,
) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    action_id = store.add(new_action()).action.action_id
    to_approved(store, action_id)
    safe = store.now()
    store.loop.fleet = hm.FleetPause(
        paused_until=safe + 3600, since=safe, reason="fleet_failures"
    )
    result = await execute(store, action_id)
    assert result.ok is False and result.reason == "fleet_paused"
    assert store.get(action_id).state is hm.ActionState.APPROVED
    assert store.loop.attempts == {}
    assert store.loop.locks == {}
    # the pause ends (on the safety clock): the step goes through
    advance(store, clock, 3600)
    assert (await execute(store, action_id, ts=T0 + 4000)).ok


async def test_an_open_breaker_is_named_before_the_fleet_pause(
    disks: FakeDisks,
) -> None:
    clock = Clock()
    store, _ = await open_store(clock)
    action = new_action()
    action_id = store.add(action).action.action_id
    to_approved(store, action_id)
    safe = store.now()
    store.loop.fleet = hm.FleetPause(paused_until=safe + 3600, since=safe)
    for key in action.loop_keys:
        store.loop.breakers[key] = hm.BreakerRecord(
            state=hm.BreakerState.OPEN, opened_at=safe
        )
    assert (await execute(store, action_id)).reason == "breaker_open"


@pytest.mark.parametrize("seed", range(4))
async def test_policy_and_store_refuse_alike_with_fleet_pauses(
    disks: FakeDisks, seed: int
) -> None:
    rng = random.Random(seed)
    clock = Clock()
    store, _ = await open_store(clock)
    action = hm.RemediationAction.new(
        router_id=R1,
        action_type="service.restart",
        ts=T0,
        params=DNSMASQ,
        components=(hm.Component(kind=hm.ComponentKind.SERVICE, name="dnsmasq"),),
    )
    keys = action.loop_keys
    lim = hm.LoopLimits()
    store.set_settings(hm.HealSettings(limits=lim))
    safe = T0
    for _step in range(60):
        safe += rng.choice([0, 300, 1800, 3600, 40000, 90000])
        if rng.random() < 0.3:
            store.loop.fleet = hm.FleetPause(
                paused_until=safe + rng.choice([-10, 600, 7200]), since=safe
            )
        if rng.random() < 0.1:
            store.loop.breakers[keys[0]] = hm.BreakerRecord(
                state=hm.BreakerState.OPEN, opened_at=safe
            )
        mine = hp.loop_verdict(
            keys,
            attempts=store.loop.attempts,
            breakers=store.loop.breakers,
            fleet=store.loop.fleet,
            limits=lim,
            safe_now=safe,
        )
        theirs = store._attempt_refusal(action, safe)
        assert mine.reason == theirs
        if mine.allowed:
            booked, _n = store._next_attempts(action, safe)
            store.loop.attempts.update(booked)


def test_the_docs_no_longer_say_the_store_ignores_the_pause() -> None:
    text = (ROOT / "docs" / "self-healing.md").read_text(encoding="utf-8")
    assert "lehnt während einer Flotten-Pause noch **nicht** ab" not in text
    assert "aber **keine Flotten-Pause**" not in text


__all__ += ["GATE_OK"]
