"""Self-Healing (Phase 7), package C1: the engine skeleton (Observe only).

Developer document: ``docs/self-healing.md`` §2 (module layout), §5.2
(safety clock), §9 (decision), §11 (routes) and §15 (package C1).

**What it does.** One engine per HA instance, created with the first loaded
router entry while the fleet switch ``self_healing_enabled`` is on (the
default) and stopped with the last one (the lifecycle of the Time Machine
engine, ``tm_engine``). At start it loads ``heal_store`` (which applies the
restart rule before anything else: an interrupted action becomes "unknown,
needs verification" and is never executed), then listens to the incident
announcements of Network Intelligence (``EVENT_INCIDENT``, roots only, after
NI's settle time) with a ``@callback`` receiver, and ticks every
``TICK_S`` (5 minutes) to read the safety clock, prune and reconcile.

**The event is a trigger only.** Anyone inside HA can fire
``EVENT_INCIDENT`` (an automation, another integration); the REST and
WebSocket APIs fire with origin remote, which the engine ignores. Of a
local event only the incident id is used: state, routers, type and cause
are read from Network Intelligence's own incident. NI not loaded, or the
incident unknown to NI: nothing happens (counted). A new record needs NI's
own record that it announced the incident for its current open period
(``NetIntelligence.announced_reopen_count``); records close only when NI
shows the incident resolved, ignored, gone or a silent child.

An announced root incident on exactly one router that is in the engine,
enabled and LOADED (``ConfigEntryState``) with a router id becomes one
record per open period (``RemediationAction.new``, action
``observe.evaluate``, no router call) through ``SelfHealingStore.add``:
dedupe and limits are the store's job, refusals are counted here, never
raised. NI announces an incident once per open period and deferred
incidents live in memory only, so the start, every added router and every
tick also adopt announced roots without a record (at most
``RECONCILE_MAX`` per run, same path and guards). The record then moves
through the read-only part of the state machine only:

* DETECTED -> ANALYZED with the cause as Network Intelligence reported it
  (code, status, level, confidence, source families; never recomputed);
* ANALYZED -> PROPOSED with the outcome of the decision interface
  (:class:`HealDecider`). The default (:class:`ObserveOnlyDecider`)
  proposes nothing executable: ``insufficient_evidence`` with an
  unassessed risk. The engine clamps any decider: an incident whose cause
  is neither confirmed nor backed by two source families (time or a single
  indicator only) is ``insufficient_evidence``, and in this release nothing
  is executable (``no_write_path``).

The engine never goes past PROPOSED: no PREFLIGHT, no approval, no
execution, no router call, no HA service, no entity, no bus event. A record
whose incident resolves (NI shows it resolved, ignored, gone or
re-parented as a child) is closed DETECTED /
ANALYZED / PROPOSED -> CANCELLED by the engine with the wall time at which
the engine saw it. Holds and the fleet pause of the store are respected
(the effective mode stays Observe) and shown (``heal_views``).

**Performance.** Event driven plus one tick every 5 minutes; reads only
memory (NI's incidents, the core's registry); store writes are the store's
delayed writes. No coordinator listener, no refresh, no poll.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import math
import re
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, fields, replace
from datetime import timedelta
from types import MappingProxyType
from typing import Any, Final, Protocol, runtime_checkable

from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Event, EventOrigin, HomeAssistant, callback
from homeassistant.helpers.event import async_track_time_interval

from . import heal_catalog as hc
from . import heal_policy as hp
from .const import (
    DATA_SELF_HEALING_ENGINE,
    DOMAIN,
    EVENT_INCIDENT,
    OPTION_SELF_HEALING_ENABLED,
)
from .core_models import ROUTER_ID_PREFIX, is_valid_id
from .heal_model import (
    ROUTER_COMPONENT,
    TERMINAL_STATES,
    TIME_MAX,
    ActionState,
    Actor,
    AllowEntry,
    AttemptRecord,
    BreakerRecord,
    BreakerState,
    Cause,
    CauseLevel,
    CauseStatus,
    Change,
    Decision,
    DecisionOutcome,
    Factor,
    HealMode,
    HealModelError,
    Impact,
    LoopKey,
    RemediationAction,
    Risk,
    RiskClass,
    RouterHold,
    component_dedupe_id,
    component_ref,
    incident_dedupe_id,
)
from .heal_store import HealStoreError, LoadResult, SelfHealingStore

_LOGGER = logging.getLogger(__name__)

MODULE: Final = "self_healing"
# The safety clock must be read at least every 5 minutes while HA runs
# (docs §5.2): a longer gap is capped at 900 s per observation.
TICK_S: Final = 300.0
# The one action type of this package: evaluate existing data (catalog
# row ``observe.evaluate``, design §7: no router call, Risk 0 by nature;
# the record still carries the decider's risk, unassessed by default).
OBSERVE_ACTION: Final = "observe.evaluate"
# 1.53.0 is Observe only: no write path exists at all (owner decision).
WRITE_PATH_AVAILABLE: Final = False
# Deferred root incidents (the store returned the router's open record):
# retried when that record closes or on the tick; the oldest drop first.
PENDING_MAX: Final = 200
# Announced root incidents without a record that one start or one tick
# turns into records (the rest follow on the next ticks).
RECONCILE_MAX: Final = 20
# Longest incident id taken from an event (NI's ids are ``inc-N``).
INCIDENT_ID_MAX: Final = 64
# Independent source families a hypothesis needs (design §9, NI's
# ``LIKELY_FAMILIES``): fewer is time or one indicator only.
EVIDENCE_FAMILIES_MIN: Final = 2
# Deferred incidents the reconcile need not look at again while their
# router's slot holder is unchanged (package X, c); the oldest drop first.
SKIP_MEMO_MAX: Final = 1000
# Open periods whose store-level dedupe was counted once (package X, b).
DEDUPE_SEEN_MAX: Final = 1000
# Record params that only tie an observe record to its incident period
# (``observe.evaluate`` itself takes none): incident id and first seen.
_BOOKKEEPING_PARAMS: Final = frozenset({"incident", "first_seen"})
# A provider's candidate: action and params within these bounds.
_CANDIDATE_ACTION_MAX: Final = 64
_CANDIDATE_PARAMS_MAX: Final = 8
_CANDIDATE_VALUE_MAX: Final = 64
_PARAM_KEY_RE: Final = re.compile(r"[a-z][a-z0-9_]{0,47}")
_PLAYBOOK_RE: Final = re.compile(r"[a-z][a-z0-9_.]{0,63}")
_PLAYBOOK_VERSION_MAX: Final = 1000
# Bounds of the explanation in a plan (plain JSON only).
_EXPLAIN_DEPTH: Final = 6
_EXPLAIN_ITEMS: Final = 64
_EXPLAIN_STR: Final = 256
# States the engine may close itself (engine-actor edges to CANCELLED that
# need no approval context): the planning part of this package.
_CLOSABLE: Final = frozenset(
    {ActionState.DETECTED, ActionState.ANALYZED, ActionState.PROPOSED}
)
# Event states that make the engine look at an incident (a trigger only).
_EVENT_STATES: Final = frozenset({"opened", "reopened", "resolved"})
_ACTIVE_STATUS: Final = "active"
# NI incident status -> the reason its records close with
_CLOSED_STATUS: Final[Mapping[str, str]] = {
    "resolved": "incident_cleared",
    "ignored": "incident_ignored",
}

# Engine-side blocker codes of a plan (``plan_for``), always codes.
BLOCK_NO_WRITE_PATH: Final = "no_write_path"
BLOCK_MODE_OBSERVE: Final = "mode_observe"
BLOCK_ROUTER_HELD: Final = "router_held"
BLOCK_FLEET_PAUSED: Final = "fleet_paused"
BLOCK_MODULE_DISABLED: Final = "module_disabled"
BLOCK_IN_MAINTENANCE: Final = "in_maintenance"
BLOCK_IDENTITY: Final = "identity_not_confirmed"
BLOCK_ROUTER_NOT_LOADED: Final = "router_not_loaded"
BLOCK_EVIDENCE: Final = "insufficient_evidence_sources"
BLOCK_NOT_EXECUTABLE: Final = "nothing_executable"
BLOCK_NOT_PLANNING: Final = "not_in_planning"

_COUNTERS: Final = (
    "incidents_seen",
    "records_created",
    "deduplicated",
    "deferred",
    "refused_capacity",
    "refused_invalid",
    "skipped_child",
    "skipped_no_single_router",
    "skipped_router_not_loaded",
    "skipped_router_disabled",
    "skipped_no_router_id",
    "skipped_module_disabled",
    "skipped_bad_event",
    "skipped_remote_event",
    "skipped_ni_unavailable",
    "skipped_unknown_incident",
    "skipped_not_announced",
    "reconciled",
    "analyzed",
    "proposed",
    "closed",
    "decider_failed",
    "decision_clamped",
    "ticks",
    "errors",
)


# --- the decision interface (package D plugs in here) ---------------------------------


@dataclass(frozen=True, slots=True)
class DecisionContext:
    """What a decider may read about one record (immutable; no router data
    beyond codes and counts, no entry id, no name)."""

    action: RemediationAction
    router_id: str
    configured_mode: HealMode
    effective_mode: HealMode
    hold: RouterHold | None
    fleet_paused: bool
    module_enabled: bool
    in_maintenance: bool
    router_loaded: bool
    identity_status: str | None  # core IdentityStatus value
    role: str | None  # core RouterRole value
    cause: Cause | None
    source_families: tuple[str, ...]
    # the cause is confirmed or backed by EVIDENCE_FAMILIES_MIN families
    evidence_sufficient: bool
    write_path_available: bool = WRITE_PATH_AVAILABLE
    # package X: what else the engine holds in memory (read-only copies)
    # Network Intelligence was asked about maintenance (else unknown)
    maintenance_known: bool = False
    # the record's incident is a root in NI now (None: NI does not say)
    incident_is_root: bool | None = None
    # the loop state on the safety clock: attempts and breakers per key
    attempts: Mapping[LoopKey, AttemptRecord] = field(
        default_factory=lambda: MappingProxyType({})
    )
    breakers: Mapping[LoopKey, BreakerRecord] = field(
        default_factory=lambda: MappingProxyType({})
    )
    safe_now: float | None = None
    allowlist: tuple[AllowEntry, ...] = ()


@dataclass(frozen=True, slots=True)
class Proposal:
    """A decider's answer; the engine validates and clamps it."""

    decision: Decision
    risk: Risk = field(default_factory=Risk)
    playbook_id: str | None = None
    playbook_version: int | None = None
    prerequisites: tuple[str, ...] = ()
    planned_changes: tuple[Change, ...] = ()
    expected_impact: Impact | None = None
    # the decider would execute something; never honoured in 1.53.0
    executable: bool = False
    # the catalog action the decision is about (None: the record's own)
    action_type: str | None = None
    # plain JSON explaining the decision (shown by the plans route only)
    explanation: Mapping[str, Any] | None = None


@runtime_checkable
class HealDecider(Protocol):
    """Decision and risk for one record (package D: ``heal_policy``).

    Must be pure and fast: no I/O, no router call, no store change, no
    HA call; the engine calls it in the event loop, also for the read-only
    ``plans`` route. An exception is counted and the default is used.
    """

    def propose(self, context: DecisionContext) -> Proposal:
        """The proposal for ``context.action``."""


class ObserveOnlyDecider:
    """The default until package D: proposes nothing executable.

    ``insufficient_evidence`` with score 0 and an unassessed risk (the
    model's default: the highest class, so a record no one assessed never
    passes a hold as read-only).
    """

    def propose(self, context: DecisionContext) -> Proposal:
        """Always the same conservative answer."""
        del context
        return Proposal(
            decision=Decision(
                outcome=DecisionOutcome.INSUFFICIENT_EVIDENCE,
                score=0.0,
                factors=(
                    Factor(factor="policy", value=0.0, reason="no_decision_policy"),
                ),
                why=None,
                why_not="no_decision_policy",
            ),
            risk=Risk(risk_class=RiskClass.HIGH, reasons=("not_assessed",)),
        )


DEFAULT_DECIDER: Final[HealDecider] = ObserveOnlyDecider()

# Outcomes that never lead to a write (the clamp keeps these as they are).
_NON_ACTING: Final = frozenset(
    {
        DecisionOutcome.INSUFFICIENT_EVIDENCE,
        DecisionOutcome.UNSUPPORTED,
        DecisionOutcome.NOT_SAFE,
    }
)


# --- the policy of package D behind the decision interface (package X) ----------------


class HealFactsError(ValueError):
    """A provider's facts are not acceptable (the message names the field)."""


def _facts_fail(what: str) -> HealFactsError:
    return HealFactsError(f"invalid {what}")


def _candidate_params(value: Any) -> Mapping[str, Any]:
    """A read-only copy of a candidate's params (each value read once)."""
    if not isinstance(value, Mapping):
        raise _facts_fail("candidate_params")
    try:
        items = list(value.items())
    except Exception as err:  # anything odd is invalid
        raise _facts_fail("candidate_params") from err
    if len(items) > _CANDIDATE_PARAMS_MAX:
        raise _facts_fail("candidate_params")
    out: dict[str, Any] = {}
    for key, raw in items:
        if not isinstance(key, str) or _PARAM_KEY_RE.fullmatch(key) is None:
            raise _facts_fail("candidate_params")
        if (
            isinstance(raw, bool)
            or raw is None
            or isinstance(raw, int)
            and abs(raw) <= 2**53
            or isinstance(raw, float)
            and math.isfinite(raw)
            or isinstance(raw, str)
            and len(raw) <= _CANDIDATE_VALUE_MAX
        ):
            out[key] = raw
        else:
            raise _facts_fail("candidate_params")
    return MappingProxyType(out)


@dataclass(frozen=True, kw_only=True, slots=True)
class HealFacts:
    """What a facts provider knows beyond the engine (None: unknown).

    The seam for packages E (preflight facts) and F (playbooks): a provider
    names the candidate action of a record (default: the record's own
    ``observe.evaluate``) and the facts the engine does not hold - the
    router's reachability, clients, dependants, the target service, open
    findings, the evidence's freshness and target fact, a recent
    configuration change, the playbook. Validated on construction and again
    whenever the engine takes it (``replace``). Facts the engine holds win
    over the provider's (:class:`PolicyDecider`).
    """

    candidate_action: str | None = None
    candidate_params: Mapping[str, Any] | None = None
    context: hp.RiskContext | None = None
    incident: hp.IncidentFacts | None = None
    config_change_24h: bool | None = None
    playbook_id: str | None = None
    playbook_version: int | None = None

    def __post_init__(self) -> None:
        """Validate; ``context`` and ``incident`` are checked again."""
        action = self.candidate_action
        if action is not None and (
            not isinstance(action, str) or not 0 < len(action) <= _CANDIDATE_ACTION_MAX
        ):
            raise _facts_fail("candidate_action")
        if self.candidate_params is not None:
            if action is None:
                raise _facts_fail("candidate_params")
            object.__setattr__(
                self, "candidate_params", _candidate_params(self.candidate_params)
            )
        try:
            if self.context is not None:
                if type(self.context) is not hp.RiskContext:
                    raise _facts_fail("context")
                object.__setattr__(self, "context", replace(self.context))
            if self.incident is not None:
                if type(self.incident) is not hp.IncidentFacts:
                    raise _facts_fail("incident")
                object.__setattr__(self, "incident", replace(self.incident))
        except HealFactsError:
            raise
        except Exception as err:  # anything odd is invalid
            raise _facts_fail("facts") from err
        if (
            self.config_change_24h is not None
            and type(self.config_change_24h) is not bool
        ):
            raise _facts_fail("config_change_24h")
        if self.playbook_id is not None and (
            not isinstance(self.playbook_id, str)
            or _PLAYBOOK_RE.fullmatch(self.playbook_id) is None
        ):
            raise _facts_fail("playbook_id")
        version = self.playbook_version
        if version is not None and (
            type(version) is not int or not 1 <= version <= _PLAYBOOK_VERSION_MAX
        ):
            raise _facts_fail("playbook_version")


UNKNOWN_FACTS: Final = HealFacts()


@runtime_checkable
class HealFactsProvider(Protocol):
    """The seam for packages E and F: facts about one record's router.

    Called by :class:`PolicyDecider` for every decision (the plans route
    too), in the event loop: pure and fast, no I/O, no router call, no
    store change. It gets a copy of the context. Anything but a valid
    :class:`HealFacts` (an exception, another type, a value set after
    construction) counts as "nothing known" and is counted.
    """

    def facts(self, context: DecisionContext) -> HealFacts:
        """The facts for ``context.action``."""


class UnknownFactsProvider:
    """The default until packages E/F: knows nothing beyond the engine."""

    def facts(self, context: DecisionContext) -> HealFacts:
        """Every fact unknown; the candidate is the record's own action."""
        del context
        return UNKNOWN_FACTS


def _catalog_params(action: RemediationAction) -> Mapping[str, Any]:
    """The catalog params of a record's own action.

    An observe record carries its incident period as params (bookkeeping);
    ``observe.evaluate`` takes none. They map to ``{}`` only when they are
    exactly that bookkeeping of this record; anything else goes to the
    catalog as it is (and is refused there).
    """
    params = action.params
    if (
        action.action_type == OBSERVE_ACTION
        and set(params) <= _BOOKKEEPING_PARAMS
        and params.get("incident") == action.incident_id
    ):
        return {}
    return params


def _candidate_keys(
    router_id: str, action_type: Any, params: Mapping[str, Any]
) -> tuple[LoopKey, ...] | None:
    """The loop keys of a candidate (None: not a catalog action)."""
    va, _refusal = hc.try_validate(action_type, params)
    if va is None:
        return None
    return tuple(
        dict.fromkeys(
            (router_id, va.action_type, component_ref(c))
            for c in (tuple(va.components) or (ROUTER_COMPONENT,))
        )
    )


def _facts_known(inp: hp.DecisionInput) -> tuple[list[str], list[str]]:
    """Names of the facts the decision knew and did not know."""
    known: list[str] = []
    unknown: list[str] = []
    parts: list[Any] = [inp.context]
    if inp.incident is not None:
        parts.append(inp.incident)
    for part in parts:
        for f in fields(part):
            (unknown if getattr(part, f.name) is None else known).append(f.name)
    for name in ("prior_failed_attempts", "config_change_24h"):
        (unknown if getattr(inp, name) is None else known).append(name)
    return known, unknown


def _texts_de(codes: Iterable[Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for code in codes:
        if isinstance(code, str) and code in hp.REASON_TEXT_DE:
            out[code] = hp.REASON_TEXT_DE[code]
    return out


def _explanation(verdict: hp.GateVerdict, inp: hp.DecisionInput) -> dict[str, Any]:
    """The policy's explanation, the gate and the facts (plain JSON)."""
    decision = verdict.decision
    policy = decision.explanation() if decision is not None else None
    known, unknown = _facts_known(inp)
    codes: list[Any] = list(verdict.reasons)
    if policy is not None:
        codes += [policy["why"], policy["why_not"], policy.get("refusal")]
        codes += [r["code"] for r in policy["rules"]]
        for line in policy["score"]["contributions"]:
            codes += [line["factor"], line["reason"]]
        codes += policy["risk"]["reasons"]
    return {
        "policy": policy,
        "gate": {
            "permission": verdict.permission.value,
            "effective_mode": verdict.effective_mode.value,
            "reasons": list(verdict.reasons),
            "allowlisted": verdict.allowlisted,
            "in_release": verdict.in_release,
            # 1.53.0 executes nothing, whatever the gate would allow
            "executable_now": False,
        },
        "facts": {"known": known, "unknown": unknown},
        "texts_de": _texts_de(codes),
    }


class PolicyDecider:
    """The policy of package D (``heal_policy``) as the engine's decider.

    Maps the :class:`DecisionContext` to a ``heal_policy.DecisionInput``
    and asks :func:`heal_policy.gate`, which decides itself; the proposal is
    built from the gate's own decision and is never executable. Facts the
    engine holds in memory are filled and win over a provider's: role,
    identity confirmed, maintenance, breaker state, root or child, cause
    level, status and confidence, source families, incident type, failed
    attempts in 24 h (loop state on the safety clock). Mode, hold, fleet
    pause and the module switch go to the gate. Everything else comes from
    the facts provider (:class:`HealFactsProvider`) or stays unknown.

    A policy error propagates: the engine counts it (``decider_failed``)
    and uses :class:`ObserveOnlyDecider` instead.
    """

    def __init__(
        self,
        provider: HealFactsProvider | None = None,
        *,
        limits: hp.PolicyLimits | None = None,
    ) -> None:
        """``provider`` None: :class:`UnknownFactsProvider`."""
        self.provider: HealFactsProvider = (
            provider if provider is not None else UnknownFactsProvider()
        )
        self.limits = hp.DEFAULT_POLICY_LIMITS if limits is None else limits
        self.counters: dict[str, int] = {"facts_failed": 0, "facts_invalid": 0}

    def _facts(self, context: DecisionContext) -> HealFacts:
        try:
            raw = self.provider.facts(replace(context))
        except Exception as err:  # noqa: BLE001 - nothing known instead
            self.counters["facts_failed"] += 1
            _LOGGER.debug("Self-Healing facts failed (%s)", type(err).__name__)
            return UNKNOWN_FACTS
        if type(raw) is not HealFacts:
            self.counters["facts_invalid"] += 1
            return UNKNOWN_FACTS
        try:
            return replace(raw)  # validated again: a later change is refused
        except Exception as err:  # noqa: BLE001 - nothing known instead
            self.counters["facts_invalid"] += 1
            _LOGGER.debug("Self-Healing facts invalid (%s)", type(err).__name__)
            return UNKNOWN_FACTS

    def decision_input(
        self, context: DecisionContext, facts: HealFacts
    ) -> hp.DecisionInput:
        """The policy's input: the engine's facts over the provider's."""
        action = context.action
        if facts.candidate_action is not None:
            action_type: Any = facts.candidate_action
            params: Mapping[str, Any] = facts.candidate_params or {}
        else:
            action_type, params = action.action_type, _catalog_params(action)
        keys = _candidate_keys(context.router_id, action_type, params)
        prior: int | None = None
        breaker_open: bool | None = None
        if keys is not None and context.safe_now is not None:
            prior = hp.prior_failed_attempts(keys, context.attempts, context.safe_now)
            breaker_open = any(
                (br := context.breakers.get(k)) is not None
                and br.state is BreakerState.OPEN
                for k in keys
            )
        identity = (
            None
            if context.identity_status is None
            else context.identity_status == "confirmed"
        )
        maintenance: bool | None = (
            True
            if context.in_maintenance is True
            else (False if context.maintenance_known else None)
        )
        risk_context = replace(
            facts.context or hp.RiskContext(),
            role=context.role if context.role in hp.ROLES else None,
            identity_confirmed=identity,
            in_maintenance=maintenance,
            breaker_open=breaker_open,
        )
        incident: hp.IncidentFacts | None = None
        if action.incident_id is not None:
            cause = context.cause
            incident = replace(
                facts.incident or hp.IncidentFacts(),
                incident_type=action.incident_type,
                cause_level=cause.level if cause is not None else CauseLevel.UNKNOWN,
                cause_status=(
                    cause.status if cause is not None else CauseStatus.HYPOTHESIS
                ),
                confidence=cause.confidence if cause is not None else None,
                source_families=min(len(context.source_families), 64),
                is_root=context.incident_is_root,
            )
        return hp.DecisionInput(
            action_type=action_type,
            params=params,
            incident=incident,
            context=risk_context,
            prior_failed_attempts=prior,
            config_change_24h=facts.config_change_24h,
        )

    def propose(self, context: DecisionContext) -> Proposal:
        """The gate's own decision as a proposal (never executable)."""
        facts = self._facts(context)
        inp = self.decision_input(context, facts)
        verdict = hp.gate(
            inp,
            mode=context.configured_mode,
            allowlist=context.allowlist,
            module_enabled=context.module_enabled,
            held=context.hold is not None,
            fleet_paused=context.fleet_paused,
            guards_green=None,
            limits=self.limits,
        )
        if type(verdict) is not hp.GateVerdict:
            raise TypeError("not a gate verdict")
        explanation = _explanation(verdict, inp)
        decision = verdict.decision
        if decision is None:
            # refused before deciding (module off): the safe default
            return replace(DEFAULT_DECIDER.propose(context), explanation=explanation)
        changes: tuple[Change, ...] = ()
        acting = decision.outcome not in _NON_ACTING
        if decision.writes and acting and decision.action_type is not None:
            va = hc.validate(decision.action_type, decision.params)
            changes = tuple(
                Change(kind=c.kind.value, target=c.name, effect=va.action_type)
                for c in (tuple(va.components) or (ROUTER_COMPONENT,))
            )
        return Proposal(
            decision=decision.to_model(),
            risk=decision.risk.to_model(),
            playbook_id=facts.playbook_id,
            playbook_version=facts.playbook_version,
            planned_changes=changes,
            expected_impact=decision.to_impact() if decision.writes else None,
            executable=False,
            action_type=decision.action_type,
            explanation=explanation,
        )


def _plain(value: Any, depth: int = 0) -> Any:
    """Plain, bounded JSON of an explanation (anything else: None)."""
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 2**53 else None
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return value[:_EXPLAIN_STR]
    if depth >= _EXPLAIN_DEPTH:
        return None
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        try:
            items = list(value.items())[:_EXPLAIN_ITEMS]
        except Exception:  # noqa: BLE001 - an odd mapping shows nothing
            return None
        for key, item in items:
            if isinstance(key, str):
                out[key[:_EXPLAIN_STR]] = _plain(item, depth + 1)
        return out
    if isinstance(value, list | tuple):
        return [_plain(item, depth + 1) for item in value[:_EXPLAIN_ITEMS]]
    return None


@dataclass(frozen=True, slots=True)
class Plan:
    """What the ``plans`` route reports for one open record (read only)."""

    action: RemediationAction
    proposal: Proposal
    executable: bool
    blockers: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """JSON form: codes, counts and ids only."""
        decision = self.proposal.decision
        return {
            "action_id": self.action.action_id,
            "router_id": self.action.router_id,
            "state": self.action.state.value,
            "incident_id": self.action.incident_id,
            "incident_type": self.action.incident_type,
            "action_type": self.action.action_type,
            "decision": decision.to_dict(),
            "risk": self.proposal.risk.to_dict(),
            "playbook_id": self.proposal.playbook_id,
            "playbook_version": self.proposal.playbook_version,
            "proposed_action_type": _str(self.proposal.action_type),
            "planned_changes": [c.to_dict() for c in self.proposal.planned_changes],
            "executable": self.executable,
            "blockers": list(self.blockers),
            "explanation": (
                _plain(self.proposal.explanation)
                if isinstance(self.proposal.explanation, Mapping)
                else None
            ),
        }


# --- helpers ----------------------------------------------------------------------------


def _str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _value(raw: Any) -> str | None:
    """An enum's value or a plain string."""
    return _str(getattr(raw, "value", raw))


def _confidence(raw: Any) -> float | None:
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        return None
    value = float(raw)
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        return None
    return round(value, 4)


def _reopen(inc: Any) -> int:
    """The incident's reopen count (0 when missing or odd)."""
    value = getattr(inc, "reopen_count", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _seen_at(value: Any) -> float | None:
    """A first-seen time rounded to milliseconds (None: missing or odd)."""
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if not math.isfinite(value) or not 0 < value <= TIME_MAX:
        return None
    return round(float(value), 3)


def _first_seen(inc: Any) -> float | None:
    """When NI first saw the incident (None: NI does not say)."""
    return _seen_at(getattr(inc, "first_seen", None))


def _same_incident(action: RemediationAction, first_seen: float | None) -> bool:
    """The record belongs to this incident, not to an older one with the
    same id (NI numbers incidents again from 1 after its store was reset;
    package X, d).

    Unknown on either side: the id decides (records of C1 carry no first
    seen). NI moves ``first_seen`` back after a backward clock jump
    (``_shift``), never forward: a later first seen is another incident.
    """
    stored = _seen_at(action.params.get("first_seen"))
    return stored is None or first_seen is None or first_seen <= stored


def _event_incident_id(data: Any) -> str | None:
    """The incident id of a well-formed announcement, else None.

    Only the shape is checked (state, id, the router list); the values are
    never used beyond the id: the incident itself is read from NI.
    """
    if not isinstance(data, Mapping):
        return None
    try:
        state = data.get("state")
        incident_id = data.get("incident_id")
        entry_ids = data.get("entry_ids", [])
    except Exception:  # noqa: BLE001 - an odd mapping is a bad event
        return None
    if not isinstance(state, str) or state not in _EVENT_STATES:
        return None
    if not isinstance(incident_id, str) or not 0 < len(incident_id) <= INCIDENT_ID_MAX:
        return None
    if entry_ids is not None and (
        not isinstance(entry_ids, list)
        or not all(isinstance(e, str) for e in entry_ids)
    ):
        return None
    return incident_id


def _entries(hass: HomeAssistant) -> list[Any]:
    try:
        entries = hass.config_entries.async_entries(DOMAIN)
    except Exception:  # noqa: BLE001 - a broken registry is "no entries"
        return []
    return list(entries) if isinstance(entries, list) else []


def self_healing_enabled(hass: HomeAssistant) -> bool:
    """The fleet switch: on unless a router entry has it off.

    The options flow writes the value through to every entry, so all agree;
    should they not, any entry that says off switches the module off (the
    stricter reading). An entry without the option counts as on (default).
    """
    for entry in _entries(hass):
        options = getattr(entry, "options", None)
        if (
            isinstance(options, Mapping)
            and options.get(OPTION_SELF_HEALING_ENABLED) is False
        ):
            return False
    return True


def _read_only(proposal: Proposal, context: DecisionContext) -> bool:
    """The proposal is a Risk 0 read-only step (the C1 clamp lets it pass).

    Its action (the proposal's, else the record's) is in the catalog,
    writes nothing and has base risk 0, the proposed risk is 0 and nothing
    is planned to change. Anything else, an unknown action too, counts as
    a write (package X).
    """
    action_type = proposal.action_type or context.action.action_type
    found = hc.CATALOG.get(action_type) if isinstance(action_type, str) else None
    return (
        found is not None
        and not found.writes
        and found.base_risk is RiskClass.READ_ONLY
        and proposal.risk.risk_class is RiskClass.READ_ONLY
        and not proposal.planned_changes
    )


# --- the engine -------------------------------------------------------------------------


class HealEngine:
    """The running Self-Healing engine of one HA instance (Observe only)."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] | None = time.monotonic,
        store: SelfHealingStore | None = None,
        decider: HealDecider | None = None,
    ) -> None:
        """Nothing is read or attached before :meth:`async_start`."""
        self.hass = hass
        self.clock = clock
        self.monotonic = monotonic
        self.store = store or SelfHealingStore(hass, clock=clock, monotonic=monotonic)
        self.decider: HealDecider = decider or DEFAULT_DECIDER
        self.entries: set[str] = set()
        self.loaded = False
        self.closed = False
        self.load_result: LoadResult | None = None
        self.counters: dict[str, int] = dict.fromkeys(_COUNTERS, 0)
        self.last_tick_mono: float | None = None
        self._api: Any = None
        self._bind_task: asyncio.Task[Any] | None = None
        self._unsubs: list[Callable[[], None]] = []
        # incident id -> None: announced roots whose router had an open
        # record (oldest first; bounded)
        self._pending: OrderedDict[str, None] = OrderedDict()
        # (incident id, reopen, first seen) -> (router slot id, holder id):
        # deferred incidents not looked at again while the holder of their
        # router's slot is the same (bounded; package X, c)
        self._skip_memo: OrderedDict[tuple[str, int, float | None], tuple[str, str]] = (
            OrderedDict()
        )
        # open periods whose store-level dedupe was counted (package X, b)
        self._dedupe_seen: OrderedDict[tuple[str, int, float | None], None] = (
            OrderedDict()
        )

    # -- start / stop ------------------------------------------------------------------

    async def async_start(self) -> None:
        """Load the store (restart rule first), then listen and tick."""
        self.load_result = await self.store.async_load()
        if self.load_result.recovered:
            _LOGGER.info(
                "Self-Healing: %d interrupted action(s) set to need verification "
                "after a restart; none is executed again",
                len(self.load_result.recovered),
            )
        self.loaded = True
        self._unsubs.append(
            self.hass.bus.async_listen(EVENT_INCIDENT, self._on_incident)
        )
        self._unsubs.append(
            async_track_time_interval(
                self.hass, self._on_tick, timedelta(seconds=TICK_S)
            )
        )
        await self.async_bind_core()
        self.last_tick_mono = self._mono()
        self._guard("start reconcile", self.reconcile)

    async def async_stop(self) -> None:
        """Detach everything and write the store a last time."""
        self.closed = True
        for unsub in self._unsubs:
            with contextlib.suppress(Exception):
                unsub()
        self._unsubs.clear()
        task, self._bind_task = self._bind_task, None
        if task is not None and not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
        self._pending.clear()
        self._skip_memo.clear()
        self._dedupe_seen.clear()
        await self.store.async_close()

    async def async_bind_core(self) -> None:
        """The core's Configuration API (registry); None while it is down."""
        if self._api is not None or self.closed:
            return
        try:
            from .config_api import async_get_configuration_api

            self._api = await async_get_configuration_api(self.hass, 1)
        except Exception as err:  # noqa: BLE001 - runs on without router ids
            _LOGGER.debug("Self-Healing: no core yet (%s)", type(err).__name__)
            self._api = None

    def add_entry(self, entry_id: str) -> None:
        """A router entry is loaded."""
        self.entries.add(entry_id)

    async def async_add_entries(self, entry_ids: Iterable[str]) -> None:
        """Routers are (being) loaded: bind the core, then reconcile, so an
        announced incident of a router that is already LOADED gets its
        record now and not only on the next tick."""
        for entry_id in entry_ids:
            self.add_entry(entry_id)
        await self.async_bind_core()
        self._guard("reconcile", self.reconcile)

    def remove_entry(self, entry_id: str) -> None:
        """A router entry is unloaded (its records stay)."""
        self.entries.discard(entry_id)

    # -- reading the world (memory only) -----------------------------------------------

    def _mono(self) -> float | None:
        return None if self.monotonic is None else float(self.monotonic())

    def _ni(self) -> Any:
        from .net_engine import async_get_engine

        engine = async_get_engine(self.hass)
        return engine if engine is not None and engine.loaded else None

    def _incidents(self, ni: Any) -> dict[str, Any]:
        return {inc.id: inc for inc in ni.machine.peek()}

    def _record_of(self, entry_id: str) -> Any:
        if self._api is None:
            return None
        try:
            return self._api.registry.get_by_entry(entry_id)
        except Exception:  # noqa: BLE001 - not registered (yet)
            return None

    def router_id_for_entry(self, entry_id: str) -> str | None:
        """The core router id of an entry (Unified Router Identity)."""
        record = self._record_of(entry_id)
        rid = getattr(record, "router_id", None)
        if _value(getattr(record, "state", None)) not in (None, "active"):
            return None  # an orphaned record is no live router
        return rid if is_valid_id(rid, ROUTER_ID_PREFIX) else None

    def entry_for_router(self, router_id: str) -> str | None:
        """The entry id of a router id (None when the core does not know it)."""
        if self._api is None:
            return None
        try:
            record = self._api.registry.find(router_id)
        except Exception:  # noqa: BLE001
            return None
        return _str(getattr(getattr(record, "identity", None), "entry_id", None))

    def _identity(self, router_id: str) -> tuple[str | None, str | None]:
        """(identity status, role) as codes; (None, None) when unknown."""
        if self._api is None:
            return None, None
        try:
            from .core_models import primary_identity_status

            record = self._api.registry.find(router_id)
            identity = getattr(record, "identity", None)
            if identity is None:
                return None, None
            status = primary_identity_status(identity.identity_flags).value
            return status, _value(identity.role)
        except Exception:  # noqa: BLE001 - unknown identity
            return None, None

    def _entry_usable(self, entry_id: str) -> str | None:
        """None when the entry is in the engine, enabled and LOADED, else
        the counter. An entry still setting up, whose setup failed or whose
        unload failed is no router to act on (review of PR #78)."""
        if entry_id not in self.entries:
            return "skipped_router_not_loaded"
        try:
            entry = self.hass.config_entries.async_get_entry(entry_id)
        except Exception:  # noqa: BLE001
            entry = None
        if entry is None or getattr(entry, "disabled_by", None) is not None:
            return "skipped_router_disabled"
        if getattr(entry, "state", None) is not ConfigEntryState.LOADED:
            return "skipped_router_not_loaded"
        return None

    def router_loaded(self, router_id: str) -> bool:
        """The router's entry is in the engine, enabled and LOADED."""
        entry_id = self.entry_for_router(router_id)
        return entry_id is not None and self._entry_usable(entry_id) is None

    def module_enabled(self) -> bool:
        """The module switch of the store's settings (default on)."""
        return self.store.settings.enabled is True

    # -- events ------------------------------------------------------------------------

    def _guard(self, name: str, func: Callable[..., Any], *args: Any) -> Any:
        try:
            return func(*args)
        except Exception as err:  # noqa: BLE001 - never breaks the caller
            self.counters["errors"] += 1
            _LOGGER.warning("Self-Healing %s failed (%s)", name, type(err).__name__)
            return None

    @callback
    def _on_incident(self, event: Event) -> None:
        """A Network Intelligence announcement: a trigger, nothing more.

        An event fired from outside HA (REST or WebSocket API: origin
        remote) is not even a trigger. Inside HA anyone can fire the event
        too (an automation, another integration), so its fields are never
        trusted: :meth:`handle_incident` reads the incident from Network
        Intelligence itself.
        """
        if self.closed or not self.loaded:
            return
        origin = getattr(event, "origin", EventOrigin.local)
        if origin is not EventOrigin.local:
            self.counters["skipped_remote_event"] += 1
            return
        self._guard("incident", self.handle_incident, getattr(event, "data", None))

    def handle_incident(self, data: Any) -> None:
        """Bring one incident in line with Network Intelligence.

        The event names the incident and nothing else counts: its state,
        routers, type and cause come from NI's own incident. NI not loaded,
        or the incident unknown to NI: nothing (counted). Resolved or
        ignored in NI: its records close. Active in NI and announced by NI
        for its current open period: a record (:meth:`_detect`).
        """
        incident_id = _event_incident_id(data)
        if incident_id is None:
            self.counters["skipped_bad_event"] += 1
            return
        self.counters["incidents_seen"] += 1
        ni = self._ni()
        if ni is None:
            self.counters["skipped_ni_unavailable"] += 1
            return
        known = self._incidents(ni)
        inc = known.get(incident_id)
        if inc is None:
            self.counters["skipped_unknown_incident"] += 1
            return
        status = _value(getattr(inc, "status", None))
        if status in _CLOSED_STATUS:
            self._pending.pop(incident_id, None)
            if self._close_incident(
                incident_id, _CLOSED_STATUS[status], _first_seen(inc)
            ):
                self._retry_pending(ni, known)
            return
        if status != _ACTIVE_STATUS:
            return  # acknowledged: no new record, an open one stays
        reopen = _reopen(inc)
        self._detect(
            inc,
            ni,
            known,
            reason="incident_reopened" if reopen else "incident_opened",
        )

    @callback
    def _on_tick(self, _now: Any = None) -> None:
        """Every ``TICK_S``: safety clock, prune, reconcile (memory only)."""
        if self.closed:
            return
        self.counters["ticks"] += 1
        self.last_tick_mono = self._mono()
        self._guard("tick", self.tick)

    def tick(self) -> None:
        """Read the safety clock, prune, bind the core, reconcile."""
        self.store.now()
        self.store.prune()
        if self._api is None and (self._bind_task is None or self._bind_task.done()):
            self._bind_task = self.hass.async_create_task(
                self.async_bind_core(), name="openwrt_router self-healing core"
            )
        self.reconcile()

    # -- detect, analyse, propose ------------------------------------------------------

    @staticmethod
    def _announced(ni: Any, inc: Any) -> bool:
        """NI announced ``inc`` on the bus for its current open period.

        NI's own record of what it announced: a root at or above
        ``notify_min_severity``, after its settle time, not only on routers
        in maintenance (``NetIntelligence._announce``). Unknown: no.
        """
        getter = getattr(ni, "announced_reopen_count", None)
        if not callable(getter):
            return False
        try:
            count = getter(inc.id)
        except Exception:  # noqa: BLE001 - unknown is "not announced"
            return False
        return (
            isinstance(count, int)
            and not isinstance(count, bool)
            and count == _reopen(inc)
        )

    def _periods(self) -> dict[str, list[RemediationAction]]:
        """Observe records by incident id (one pass over the store)."""
        index: dict[str, list[RemediationAction]] = {}
        for action in self.store.actions.values():
            if action.action_type == OBSERVE_ACTION and action.incident_id:
                index.setdefault(action.incident_id, []).append(action)
        return index

    def _recorded(
        self,
        incident_id: str,
        reopen: int,
        first_seen: float | None,
        index: Mapping[str, list[RemediationAction]] | None = None,
    ) -> bool:
        """An observe record of this incident's open period exists (in any
        state): one record per period, also after it closed. The same id
        with a later first seen is another incident (package X, d)."""
        found = (index if index is not None else self._periods()).get(incident_id, ())
        return any(
            a.incident_reopen == reopen and _same_incident(a, first_seen) for a in found
        )

    def _close_stale(self, incident_id: str, first_seen: float | None) -> None:
        """Close open records of an older incident with the same id."""
        if first_seen is None:
            return
        for action in self.store.open_actions():
            if (
                action.incident_id == incident_id
                and action.action_type == OBSERVE_ACTION
                and not _same_incident(action, first_seen)
            ):
                self._close(action, "incident_gone")

    def _detect(
        self,
        inc: Any,
        ni: Any,
        known: Mapping[str, Any],
        *,
        reason: str,
        deferred: bool = False,
        count: bool = True,
        index: dict[str, list[RemediationAction]] | None = None,
    ) -> str:
        """One root incident of NI -> one record. Returns the outcome code.

        ``count`` False (the reconcile of every tick): skips are not counted,
        so the counters say what happened to announcements, not how often
        the tick looked. ``index``: the observe records by incident id of
        one reconcile (:meth:`_periods`), kept up to date here.
        """

        def skip(counter: str, outcome: str) -> str:
            if count:
                self.counters[counter] += 1
            return outcome

        incident_id = inc.id
        if not self.module_enabled():
            return skip("skipped_module_disabled", "module_disabled")
        if _value(getattr(inc, "status", None)) != _ACTIVE_STATUS:
            # resolved, ignored or acknowledged: never a new record, whatever
            # NI's announcement record says (package X, a)
            return "not_active"
        if not self._announced(ni, inc):
            return skip("skipped_not_announced", "not_announced")
        if self._is_child(ni, inc, known):
            return skip("skipped_child", "child")
        from .net_engine import FLEET_ROUTER

        raw = getattr(inc, "routers", None)
        routers = [
            r
            for r in dict.fromkeys(
                r
                for r in (raw if isinstance(raw, list | tuple) else ())
                if isinstance(r, str)
            )
            if r != FLEET_ROUTER
        ]
        if len(routers) != 1:
            return skip("skipped_no_single_router", "no_single_router")
        entry_id = routers[0]
        skipped = self._entry_usable(entry_id)
        if skipped is not None:
            return skip(skipped, skipped)
        router_id = self.router_id_for_entry(entry_id)
        if router_id is None:
            return skip("skipped_no_router_id", "no_router_id")
        reopen = _reopen(inc)
        first_seen = _first_seen(inc)
        if self._recorded(incident_id, reopen, first_seen, index):
            # a repeat of a recorded period (or an event reusing its id):
            # not counted, so no event can drive a counter (package X, b)
            return "deduplicated"
        # an older incident with the same id (NI reset) still holds a record
        self._close_stale(incident_id, first_seen)
        period = (incident_id, reopen, first_seen)
        slot = component_dedupe_id(router_id, ROUTER_COMPONENT)
        holder = self._slot_holder(slot, incident_id)
        if holder is not None:
            # the router's open record belongs to another incident: retry
            # when it closes (design §10: one open action per component),
            # without building a record each time (package X, c)
            return self._defer(period, slot, holder, deferred=deferred, count=count)
        params: dict[str, Any] = {"incident": incident_id}
        if first_seen is not None:
            params["first_seen"] = first_seen
        try:
            action = RemediationAction.new(
                router_id=router_id,
                action_type=OBSERVE_ACTION,
                ts=self.clock(),
                actor=Actor.ENGINE,
                reason=reason,
                params=params,
                incident_id=incident_id,
                incident_type=_str(getattr(inc, "type", None)),
                incident_reopen=reopen,
            )
        except HealModelError:
            return skip("refused_invalid", "invalid")
        try:
            result = self.store.add(action)
        except HealStoreError:
            return skip("refused_capacity", "refused")
        if not result.created:
            if (
                result.dedupe == "component"
                and result.action.incident_id != incident_id
            ):
                return self._defer(
                    period,
                    slot,
                    result.action.action_id,
                    deferred=deferred,
                    count=count,
                )
            if count and period not in self._dedupe_seen:
                # counted once per open period (package X, b)
                self._dedupe_seen[period] = None
                while len(self._dedupe_seen) > DEDUPE_SEEN_MAX:
                    self._dedupe_seen.popitem(last=False)
                self.counters["deduplicated"] += 1
            return "deduplicated"
        self.counters["records_created"] += 1
        self._skip_memo.pop(period, None)
        if index is not None:
            index.setdefault(incident_id, []).append(action)
        if self._in_maintenance(ni, entry_id):
            with contextlib.suppress(HealStoreError, HealModelError):
                self.store.update_flags(action.action_id, in_maintenance=True)
        self._advance(action.action_id, inc, ni)
        return "created"

    def _slot_holder(self, slot: str, incident_id: str) -> str | None:
        """The open record of another incident that holds the router's slot
        (the store would answer "component"), or None.

        Only when no record holds this incident's own dedupe id: then the
        store's answer would be "incident" first, and that is not a deferral.
        """
        loop = self.store.loop
        holder = loop.component_dedupe.get(slot)
        if holder is None:
            return None
        if loop.incident_dedupe.get(incident_dedupe_id(incident_id)) is not None:
            return None
        held = self.store.get(holder)
        if held is None or held.incident_id == incident_id:
            return None
        return holder

    def _defer(
        self,
        period: tuple[str, int, float | None],
        slot: str,
        holder: str,
        *,
        deferred: bool,
        count: bool,
    ) -> str:
        incident_id = period[0]
        self._pending[incident_id] = None
        self._pending.move_to_end(incident_id)
        while len(self._pending) > PENDING_MAX:
            self._pending.popitem(last=False)
        self._skip_memo[period] = (slot, holder)
        self._skip_memo.move_to_end(period)
        while len(self._skip_memo) > SKIP_MEMO_MAX:
            self._skip_memo.popitem(last=False)
        if not deferred and count:
            self.counters["deferred"] += 1
        return "deferred"

    def _still_waiting(self, inc: Any) -> bool:
        """A deferred incident whose router slot has the same holder as when
        it was deferred: nothing to look at (package X, c; memory only)."""
        incident_id = getattr(inc, "id", None)
        if not isinstance(incident_id, str):
            return False
        found = self._skip_memo.get((incident_id, _reopen(inc), _first_seen(inc)))
        if found is None:
            return False
        slot, holder = found
        return self.store.loop.component_dedupe.get(slot) == holder

    def _is_child(self, ni: Any, inc: Any, known: Mapping[str, Any]) -> bool:
        if getattr(inc, "parent_id", None) is None:
            return False
        from .net_rules import suppressed_child

        return suppressed_child(inc, known, getattr(ni.machine, "last_now", None))

    @staticmethod
    def _in_maintenance(ni: Any, entry_id: str) -> bool:
        try:
            return bool(ni.in_maintenance(entry_id))
        except Exception:  # noqa: BLE001
            return False

    def _cause(self, ni: Any, inc: Any) -> tuple[Cause | None, tuple[str, ...]]:
        """The cause as NI reports it (never recomputed) and its families."""
        if inc is None:
            return None, ()
        families: tuple[str, ...] = ()
        level: str | None = None
        try:
            from .net_rules import cause_families, events_by_id, incident_cause_level

            wanted = {e.get("id") for e in inc.evidence if isinstance(e, Mapping)}
            events = events_by_id(e for e in ni.ring if e.id in wanted)
            families = tuple(sorted(cause_families(inc, events)))
            level = incident_cause_level(inc, events).value
        except Exception as err:  # noqa: BLE001 - without families: unknown
            _LOGGER.debug("Self-Healing: no cause families (%s)", type(err).__name__)
        code = _str(getattr(inc, "cause", None))
        if code is None:
            return None, families
        try:
            cause = Cause(
                code=code,
                status=_value(getattr(inc, "cause_status", None))
                or CauseStatus.HYPOTHESIS,
                level=level or CauseLevel.UNKNOWN,
                confidence=_confidence(getattr(inc, "confidence", None)),
                source_families=families,
            )
        except HealModelError:
            return None, families
        return cause, families

    def _advance(self, action_id: str, inc: Any, ni: Any) -> None:
        """DETECTED -> ANALYZED -> PROPOSED, as far as the record is.

        A step the store or the model refuses is counted (``errors``) and
        the record stays where it is; the tick tries again.
        """
        try:
            self._advance_steps(action_id, inc, ni)
        except (HealStoreError, HealModelError) as err:
            self.counters["errors"] += 1
            _LOGGER.debug("Self-Healing: step refused (%s)", type(err).__name__)

    def _advance_steps(self, action_id: str, inc: Any, ni: Any) -> None:
        action = self.store.get(action_id)
        if action is None:
            return
        if action.state is ActionState.DETECTED:
            cause, _families = self._cause(ni, inc) if ni is not None else (None, ())
            action = self.store.apply(
                action_id,
                ActionState.ANALYZED,
                actor=Actor.ENGINE,
                ts=self.clock(),
                reason="cause_from_incident" if cause else "no_cause_reported",
                changes={"cause": cause},
            )
            self.counters["analyzed"] += 1
        if action.state is ActionState.ANALYZED:
            context = self.context_for(action)
            proposal, _clamped = self._decide(context)
            changes: dict[str, Any] = {
                "decision": proposal.decision,
                "risk": proposal.risk,
                "playbook_id": proposal.playbook_id,
                "playbook_version": proposal.playbook_version,
                "prerequisites": proposal.prerequisites,
                "planned_changes": proposal.planned_changes,
            }
            if proposal.expected_impact is not None:
                changes["expected_impact"] = proposal.expected_impact
            try:
                self.store.apply(
                    action_id,
                    ActionState.PROPOSED,
                    actor=Actor.ENGINE,
                    ts=self.clock(),
                    reason=f"decision_{proposal.decision.outcome.value}",
                    changes=changes,
                )
            except HealModelError:
                # a decider value the model refuses: the safe default instead
                self.counters["decider_failed"] += 1
                fallback = DEFAULT_DECIDER.propose(context)
                self.store.apply(
                    action_id,
                    ActionState.PROPOSED,
                    actor=Actor.ENGINE,
                    ts=self.clock(),
                    reason=f"decision_{fallback.decision.outcome.value}",
                    changes={"decision": fallback.decision, "risk": fallback.risk},
                )
            self.counters["proposed"] += 1

    def effective_mode(self, router_id: str) -> HealMode:
        """The mode in force for anything that acts (Risk 1 or more), as
        the policy sees it (``heal_policy.effective_mode``): Observe with
        the module off, on a held router and during a fleet pause."""
        store = self.store
        safe = store.now()
        return hp.effective_mode(
            store.settings.router(router_id).mode,
            module_enabled=self.module_enabled(),
            held=store.loop.hold_on(router_id, safe) is not None,
            fleet_paused=store.loop.fleet.paused(safe),
            risk=RiskClass.LOW,
        )

    def _is_root_now(self, ni: Any, action: RemediationAction) -> bool | None:
        """The record's incident is a root in NI now (None: NI does not say)."""
        if ni is None or action.incident_id is None:
            return None
        known = self._incidents(ni)
        inc = known.get(action.incident_id)
        if inc is None or not _same_incident(action, _first_seen(inc)):
            return None
        return not self._is_child(ni, inc, known)

    def context_for(self, action: RemediationAction) -> DecisionContext:
        """The decider's view of one record (reads the safety clock)."""
        rid = action.router_id
        store = self.store
        safe = store.now()
        entry_id = self.entry_for_router(rid)
        ni = self._ni()
        status, role = self._identity(rid)
        cause = action.cause
        families = cause.source_families if cause is not None else ()
        sufficient = cause is not None and (
            cause.status is CauseStatus.CONFIRMED
            or len(families) >= EVIDENCE_FAMILIES_MIN
        )
        hold = store.loop.hold_on(rid, safe)
        fleet_paused = store.loop.fleet.paused(safe)
        module = self.module_enabled()
        configured = store.settings.router(rid).mode
        maintenance_known = ni is not None and entry_id is not None
        return DecisionContext(
            action=action,
            router_id=rid,
            configured_mode=configured,
            effective_mode=hp.effective_mode(
                configured,
                module_enabled=module,
                held=hold is not None,
                fleet_paused=fleet_paused,
                risk=RiskClass.LOW,
            ),
            hold=hold,
            fleet_paused=fleet_paused,
            module_enabled=module,
            in_maintenance=bool(
                action.flags.in_maintenance
                or (maintenance_known and self._in_maintenance(ni, entry_id))
            ),
            router_loaded=entry_id is not None and self._entry_usable(entry_id) is None,
            identity_status=status,
            role=role,
            cause=cause,
            source_families=tuple(families),
            evidence_sufficient=sufficient,
            maintenance_known=maintenance_known,
            incident_is_root=self._is_root_now(ni, action),
            attempts=MappingProxyType(dict(store.loop.attempts)),
            breakers=MappingProxyType(dict(store.loop.breakers)),
            safe_now=safe,
            allowlist=tuple(store.settings.router(rid).allowlist),
        )

    def _decide(self, context: DecisionContext) -> tuple[Proposal, bool]:
        """The decider's proposal, validated and clamped. (proposal, clamped)"""
        try:
            proposal = self.decider.propose(context)
            if (
                not isinstance(proposal, Proposal)
                or not isinstance(proposal.decision, Decision)
                or not isinstance(proposal.risk, Risk)
            ):
                raise TypeError("not a Proposal")
        except Exception as err:  # noqa: BLE001 - the safe default instead
            self.counters["decider_failed"] += 1
            _LOGGER.debug("Self-Healing decider failed (%s)", type(err).__name__)
            proposal = DEFAULT_DECIDER.propose(context)
        clamped = False
        if (
            not context.evidence_sufficient
            and proposal.decision.outcome not in _NON_ACTING
            and not _read_only(proposal, context)
        ):
            # time or one indicator alone never leads to an acting outcome
            # (design §9: insufficient evidence)
            try:
                decision = Decision(
                    outcome=DecisionOutcome.INSUFFICIENT_EVIDENCE,
                    score=min(proposal.decision.score, 0.59),
                    factors=proposal.decision.factors,
                    why=None,
                    why_not=BLOCK_EVIDENCE,
                )
            except HealModelError:
                decision = DEFAULT_DECIDER.propose(context).decision
            proposal = replace(proposal, decision=decision, executable=False)
            clamped = True
        if clamped:
            self.counters["decision_clamped"] += 1
        return proposal, clamped

    def plan_for(self, action: RemediationAction) -> Plan:
        """What would be proposed and what would block, read only.

        Calls the decider on the current facts; creates nothing, changes no
        record, no approval. Executable is always False in 1.53.0.
        """
        context = self.context_for(action)
        proposal, clamped = self._decide(context)
        blockers: list[str] = []
        if not WRITE_PATH_AVAILABLE:
            blockers.append(BLOCK_NO_WRITE_PATH)
        if action.state not in _CLOSABLE:
            blockers.append(BLOCK_NOT_PLANNING)
        if not context.module_enabled:
            blockers.append(BLOCK_MODULE_DISABLED)
        if context.effective_mode is HealMode.OBSERVE:
            blockers.append(BLOCK_MODE_OBSERVE)
        if context.hold is not None:
            blockers.append(BLOCK_ROUTER_HELD)
        if context.fleet_paused:
            blockers.append(BLOCK_FLEET_PAUSED)
        if context.in_maintenance:
            blockers.append(BLOCK_IN_MAINTENANCE)
        if not context.router_loaded:
            blockers.append(BLOCK_ROUTER_NOT_LOADED)
        if context.identity_status != "confirmed":
            blockers.append(BLOCK_IDENTITY)
        if clamped or not context.evidence_sufficient:
            blockers.append(BLOCK_EVIDENCE)
        if not proposal.executable or proposal.decision.outcome in _NON_ACTING:
            blockers.append(BLOCK_NOT_EXECUTABLE)
        return Plan(
            action=action,
            proposal=proposal,
            executable=False,
            blockers=tuple(dict.fromkeys(blockers)),
        )

    # -- close and reconcile -----------------------------------------------------------

    def _close(self, action: RemediationAction, reason: str) -> bool:
        if action.state not in _CLOSABLE:
            return False
        try:
            self.store.apply(
                action.action_id,
                ActionState.CANCELLED,
                actor=Actor.ENGINE,
                ts=self.clock(),
                reason=reason,
            )
        except (HealStoreError, HealModelError) as err:
            _LOGGER.debug("Self-Healing: not closed (%s)", type(err).__name__)
            return False
        self.counters["closed"] += 1
        return True

    def _close_incident(
        self, incident_id: str, reason: str, first_seen: float | None = None
    ) -> bool:
        """Close the open records of one incident; True if any closed.

        Only records of this incident: an older incident with the same id
        (NI reset) is closed as gone by the reconcile (package X, d).
        """
        closed = False
        for action in self.store.open_actions():
            if (
                action.incident_id == incident_id
                and action.action_type == OBSERVE_ACTION
                and _same_incident(action, first_seen)
            ):
                closed = self._close(action, reason) or closed
        return closed

    def reconcile(self) -> None:
        """Bring the open records in line with Network Intelligence.

        Without a loaded NI nothing is closed or made (unknown is not
        "cleared"). A record whose incident resolved, was ignored, is gone
        or became a silent child is closed; one left in DETECTED or
        ANALYZED (a restart between the steps) moves on. Deferred incidents
        are retried, then announced roots without a record are adopted.
        """
        ni = self._ni()
        if ni is None:
            return
        known = self._incidents(ni)
        for action in self.store.open_actions():
            if action.action_type != OBSERVE_ACTION or action.incident_id is None:
                continue
            if action.state not in _CLOSABLE:
                continue  # a later package's state: never touched here
            inc = known.get(action.incident_id)
            status = _value(getattr(inc, "status", None))
            if inc is None or not _same_incident(action, _first_seen(inc)):
                self._close(action, "incident_gone")
            elif status in _CLOSED_STATUS:
                self._close(action, _CLOSED_STATUS[status])
            elif self._is_child(ni, inc, known):
                self._close(action, "incident_now_child")
            elif action.state is not ActionState.PROPOSED:
                self._advance(action.action_id, inc, ni)
        index = self._periods()
        self._retry_pending(ni, known, index)
        self._adopt(ni, known, index)

    def _adopt(
        self,
        ni: Any,
        known: Mapping[str, Any],
        index: dict[str, list[RemediationAction]] | None = None,
    ) -> None:
        """Announced active roots on one loaded router without a record of
        their open period get one (review of PR #78).

        Deferred incidents are lost on a restart and NI announces an
        incident once per open period (stored), so without this an open
        incident would never get its record. The same path and guards as
        an announcement (:meth:`_detect`), at most ``RECONCILE_MAX`` new
        records per call, skips not counted. Memory only; an incident still
        waiting for the same holder is not looked at again (package X, c).
        """
        if not self.module_enabled():
            return
        if index is None:
            index = self._periods()
        created = 0
        for inc in known.values():
            if created >= RECONCILE_MAX:
                return
            incident_id = getattr(inc, "id", None)
            if not isinstance(incident_id, str) or incident_id in self._pending:
                continue
            if _value(getattr(inc, "status", None)) != _ACTIVE_STATUS:
                continue
            if self._recorded(incident_id, _reopen(inc), _first_seen(inc), index):
                continue
            if self._still_waiting(inc):
                continue
            if not self._announced(ni, inc):
                continue
            outcome = self._detect(
                inc, ni, known, reason="incident_reconciled", count=False, index=index
            )
            if outcome == "created":
                created += 1
                self.counters["reconciled"] += 1

    def _retry_pending(
        self,
        ni: Any = None,
        known: Mapping[str, Any] | None = None,
        index: dict[str, list[RemediationAction]] | None = None,
    ) -> None:
        if not self._pending:
            return
        if ni is None:
            ni = self._ni()
            if ni is None:
                return
        if known is None:
            known = self._incidents(ni)
        if index is None:
            index = self._periods()
        for incident_id in list(self._pending):
            inc = known.get(incident_id)
            if inc is None or _value(getattr(inc, "status", None)) != _ACTIVE_STATUS:
                self._pending.pop(incident_id, None)
                continue
            if self._still_waiting(inc):
                continue  # same holder: nothing changed (package X, c)
            outcome = self._detect(
                inc, ni, known, reason="incident_deferred", deferred=True, index=index
            )
            if outcome != "deferred":
                self._pending.pop(incident_id, None)

    # -- reading for routes and diagnostics --------------------------------------------

    def router_ids(self) -> list[str]:
        """Loaded routers first, then routers that only have records."""
        out: dict[str, bool] = {}
        for entry_id in sorted(self.entries):
            rid = self.router_id_for_entry(entry_id)
            if rid is not None:
                out[rid] = True
        for action in self.store.actions.values():
            out.setdefault(action.router_id, False)
        for rid in self.store.settings.routers:
            out.setdefault(rid, False)
        return list(out)

    def last_activity(self) -> float | None:
        """Wall time of the newest transition of any record."""
        stamps = [a.updated_at for a in self.store.actions.values()]
        return max(stamps) if stamps else None

    def pending_count(self) -> int:
        """Deferred root incidents waiting for their router's record."""
        return len(self._pending)

    def stats(self) -> dict[str, Any]:
        """Counters and sizes (no ids)."""
        mono = self._mono()
        return {
            "loaded": self.loaded,
            "routers_loaded": len(self.entries),
            "core_bound": self._api is not None,
            "pending": len(self._pending),
            "tick_s": TICK_S,
            "last_tick_s_ago": (
                None
                if mono is None or self.last_tick_mono is None
                else round(max(0.0, mono - self.last_tick_mono), 1)
            ),
            "decider": type(self.decider).__name__,
            **self.counters,
            **(
                dict(self.decider.counters)
                if isinstance(self.decider, PolicyDecider)
                else {}
            ),
        }


def count_by_state(actions: Iterable[RemediationAction]) -> dict[str, int]:
    """Records per state (every state listed, terminal ones too)."""
    counts = dict.fromkeys((s.value for s in ActionState), 0)
    for action in actions:
        counts[action.state.value] += 1
    return counts


def open_count(actions: Iterable[RemediationAction]) -> int:
    """Records not in a terminal state."""
    return sum(1 for a in actions if a.state not in TERMINAL_STATES)


# --- life cycle -------------------------------------------------------------------------

_LOCK_KEY: Final = f"{DOMAIN}_self_healing_lock"


@callback
def async_get_self_healing(hass: HomeAssistant) -> HealEngine | None:
    """The running engine, or None (off, or no router loaded)."""
    engine = hass.data.get(DATA_SELF_HEALING_ENGINE)
    return engine if isinstance(engine, HealEngine) and not engine.closed else None


def _lock(hass: HomeAssistant) -> asyncio.Lock:
    lock = hass.data.get(_LOCK_KEY)
    if not isinstance(lock, asyncio.Lock):
        lock = hass.data[_LOCK_KEY] = asyncio.Lock()
    return lock


# The states of an entry whose own setup calls async_setup_self_healing:
# SETUP_IN_PROGRESS while async_setup_entry runs, LOADED on a later call.
_SETUP_STATES: Final = (ConfigEntryState.SETUP_IN_PROGRESS, ConfigEntryState.LOADED)
_NO_CONFIG_DIR_KEY: Final = f"{DOMAIN}_self_healing_no_config_dir"


def _loaded_entry_ids(hass: HomeAssistant) -> list[str]:
    """Entries that are LOADED and have run their setup (runtime data with a
    coordinator). Runtime data alone is not enough: a setup that failed
    after setting it leaves it behind (review of PR #78)."""
    out: list[str] = []
    for entry in _entries(hass):
        if getattr(entry, "disabled_by", None) is not None:
            continue
        if getattr(entry, "state", None) is not ConfigEntryState.LOADED:
            continue
        runtime = getattr(entry, "runtime_data", None)
        if getattr(runtime, "coordinator", None) is not None:
            out.append(entry.entry_id)
    return out


def _config_dir_usable(hass: HomeAssistant) -> bool:
    """HA's Store writes below ``hass.config.config_dir``; without a real
    one (a mocked hass) it would write into the working directory. No
    engine then, said once per instance."""
    config_dir = getattr(getattr(hass, "config", None), "config_dir", None)
    if isinstance(config_dir, str) and config_dir:
        return True
    if not hass.data.get(_NO_CONFIG_DIR_KEY):
        hass.data[_NO_CONFIG_DIR_KEY] = True
        _LOGGER.warning("Self-Healing not started: no configuration directory")
    return False


async def _async_engine(hass: HomeAssistant) -> HealEngine | None:
    engine = async_get_self_healing(hass)
    if engine is None:
        if not _config_dir_usable(hass):
            return None
        # the policy of package D decides (package X); the C1 default stays
        # the fallback when it fails
        engine = HealEngine(hass, decider=PolicyDecider())
        hass.data[DATA_SELF_HEALING_ENGINE] = engine
        try:
            await engine.async_start()
        except Exception:
            hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
            with contextlib.suppress(Exception):
                await engine.async_stop()
            raise
        from .heal_views import async_register_self_healing_views

        async_register_self_healing_views(hass)
    return engine


async def async_setup_self_healing(hass: HomeAssistant, entry: Any) -> None:
    """Add a router at the end of its own setup; off, nothing is created
    (no store, no route).

    Called from the entry's ``async_setup_entry``, so the entry is still in
    SETUP_IN_PROGRESS (or LOADED on a later call); any other state is no
    router to add. The engine acts on it once it is LOADED. The switch is
    read again inside the lock: the options flow may have switched the
    module off while this setup waited (review of PR #78).
    """
    if not self_healing_enabled(hass):
        return
    if getattr(entry, "disabled_by", None) is not None:
        return
    if getattr(entry, "state", None) not in _SETUP_STATES:
        return
    async with _lock(hass):
        if not self_healing_enabled(hass):
            return
        engine = await _async_engine(hass)
        if engine is None:
            return
        await engine.async_add_entries([entry.entry_id])


async def async_release_self_healing(hass: HomeAssistant, entry_id: str) -> None:
    """Drop an unloaded router; after the last one stop and write."""
    async with _lock(hass):
        engine = async_get_self_healing(hass)
        if engine is None:
            return
        engine.remove_entry(entry_id)
        if engine.entries:
            return
        hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
        await engine.async_stop()


async def async_apply_self_healing_option(hass: HomeAssistant, *, on: bool) -> None:
    """The options flow changed the switch (no reload); never raises."""
    try:
        async with _lock(hass):
            engine = async_get_self_healing(hass)
            if not on:
                if engine is not None:
                    hass.data.pop(DATA_SELF_HEALING_ENGINE, None)
                    await engine.async_stop()
                return
            loaded = _loaded_entry_ids(hass)
            if not loaded:
                return
            engine = await _async_engine(hass)
            if engine is None:
                return
            await engine.async_add_entries(loaded)
    except Exception as err:  # noqa: BLE001 - the form never fails because of it
        _LOGGER.warning("Self-Healing option not applied (%s)", type(err).__name__)


__all__ = [
    "DEDUPE_SEEN_MAX",
    "DEFAULT_DECIDER",
    "MODULE",
    "OBSERVE_ACTION",
    "SKIP_MEMO_MAX",
    "TICK_S",
    "UNKNOWN_FACTS",
    "WRITE_PATH_AVAILABLE",
    "DecisionContext",
    "HealDecider",
    "HealEngine",
    "HealFacts",
    "HealFactsError",
    "HealFactsProvider",
    "ObserveOnlyDecider",
    "Plan",
    "PolicyDecider",
    "Proposal",
    "UnknownFactsProvider",
    "async_apply_self_healing_option",
    "async_get_self_healing",
    "async_release_self_healing",
    "async_setup_self_healing",
    "count_by_state",
    "open_count",
    "self_healing_enabled",
]
