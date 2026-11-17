"""Tests for the Network Quality Score: diag_score.py.

Pure logic: no network, no Home Assistant, no wall clock.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from custom_components.openwrt_router import diag_score as dsc
from custom_components.openwrt_router.diag_score import (
    COMP_DNS,
    COMP_GATEWAY,
    COMP_JITTER,
    COMP_LATENCY,
    COMP_LOSS,
    COMP_STABILITY,
    COMP_WAN,
    COMPONENT_WEIGHTS,
    MIN_COVERAGE,
    MIN_OBSERVATION_S,
    NETWORK_WORST_MARGIN,
    STATUS_NOT_APPLICABLE,
    STATUS_OK,
    STATUS_UNKNOWN,
    Reading,
    ScoreInputs,
    combine_scores,
    compute_score,
    inputs_from_summaries,
    piecewise,
)
from custom_components.openwrt_router.diag_stats import (
    DAY_S,
    DNS_NOERROR,
    DNS_TIMEOUT,
    DnsSample,
    Sample,
    summarize,
    summarize_dns,
)

T0 = 20834 * DAY_S
R = 300.0


def full_inputs(**overrides: object) -> ScoreInputs:
    base = ScoreInputs(
        wan_availability=Reading(99.95),
        packet_loss=Reading(1.0),
        latency=Reading(50.0),
        jitter=Reading(10.0),
        dns_failure=Reading(0.0),
        dns_response=Reading(100.0),
        gateway_reachability=Reading(99.0),
        router_restarts=Reading(0.0),
        observation_seconds=DAY_S,
    )
    return dataclasses.replace(base, **overrides)


def comp(result, name):
    return next(c for c in result.components if c.name == name)


# --- module hygiene -----------------------------------------------------------


def test_module_is_pure() -> None:
    src = Path(dsc.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.module == "diag_stats"
            else:
                assert node.module in {
                    "__future__",
                    "dataclasses",
                    "collections.abc",
                    "typing",
                }
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name in {"itertools", "logging", "math"}
    assert "homeassistant" not in src
    assert "time.time" not in src and "datetime.now" not in src
    assert "_LOGGER = logging.getLogger(__name__)" in src


def test_weights_sum_to_100_and_cover_all_components() -> None:
    assert sum(COMPONENT_WEIGHTS.values()) == 100
    assert set(COMPONENT_WEIGHTS) == {
        COMP_WAN,
        COMP_LOSS,
        COMP_LATENCY,
        COMP_JITTER,
        COMP_DNS,
        COMP_GATEWAY,
        COMP_STABILITY,
    }


def test_piecewise_linear() -> None:
    pts = ((0.0, 100.0), (10.0, 0.0))
    assert piecewise(-5.0, pts) == 100.0
    assert piecewise(0.0, pts) == 100.0
    assert piecewise(2.5, pts) == 75.0
    assert piecewise(10.0, pts) == 0.0
    assert piecewise(99.0, pts) == 0.0
    rising = ((90.0, 0.0), (99.0, 80.0), (99.9, 100.0))
    assert piecewise(94.5, rising) == pytest.approx(40.0)
    with pytest.raises(ValueError):
        piecewise(1.0, ((1.0, 0.0),))
    with pytest.raises(ValueError):
        piecewise(1.0, ((2.0, 0.0), (1.0, 5.0)))


def test_reading_validation() -> None:
    with pytest.raises(ValueError):
        Reading(1.0, coverage=1.5)
    with pytest.raises(ValueError):
        Reading(float("nan"))
    assert not Reading(None, coverage=1.0).has_data
    assert not Reading(5.0, coverage=0.0).has_data
    assert Reading(5.0, coverage=0.2).has_data


# --- the score ----------------------------------------------------------------


def test_case_25_quality_score_calculation() -> None:
    result = compute_score(full_inputs())
    # wan 99.95 -> 100, loss 1 % -> 80, latency 50 ms -> 80, jitter 10 ms -> 85,
    # dns min(0 % -> 100, 100 ms -> 80) = 80, gateway 99 % -> 80, restarts 0 -> 100
    expected = {
        COMP_WAN: 100.0,
        COMP_LOSS: 80.0,
        COMP_LATENCY: 80.0,
        COMP_JITTER: 85.0,
        COMP_DNS: 80.0,
        COMP_GATEWAY: 80.0,
        COMP_STABILITY: 100.0,
    }
    for name, value in expected.items():
        c = comp(result, name)
        assert c.score == pytest.approx(value), name
        assert c.status == STATUS_OK and c.coverage == 1.0
        assert c.weight == COMPONENT_WEIGHTS[name]
    # (25*100 + 20*80 + 15*80 + 10*85 + 15*80 + 10*80 + 5*100) / 100
    assert result.score == pytest.approx(86.5)
    assert result.coverage == 1.0
    assert result.observation_seconds == DAY_S
    assert result.low_confidence is False
    # the breakdown carries the inputs that were used
    assert dict(comp(result, COMP_DNS).inputs) == {
        "failure_pct": 0.0,
        "response_ms": 100.0,
    }
    assert dict(comp(result, COMP_LATENCY).inputs) == {"latency_ms": 50.0}

    perfect = compute_score(
        full_inputs(
            packet_loss=Reading(0.0),
            latency=Reading(5.0),
            jitter=Reading(1.0),
            dns_response=Reading(10.0),
            gateway_reachability=Reading(100.0),
        )
    )
    assert perfect.score == 100.0
    awful = compute_score(
        full_inputs(
            wan_availability=Reading(50.0),
            packet_loss=Reading(30.0),
            latency=Reading(900.0),
            jitter=Reading(200.0),
            dns_failure=Reading(50.0),
            gateway_reachability=Reading(10.0),
            router_restarts=Reading(9.0),
        )
    )
    assert awful.score == 0.0


def test_score_with_zero_data_is_none_with_coverage_0() -> None:
    result = compute_score(ScoreInputs())
    assert result.score is None
    assert result.coverage == 0.0
    assert result.observation_seconds == 0.0
    assert result.low_confidence is True
    assert all(
        c.status == STATUS_UNKNOWN and c.score is None for c in result.components
    )
    # readings present but empty are the same as missing
    empty = compute_score(
        ScoreInputs(latency=Reading(None), packet_loss=Reading(3.0, coverage=0.0))
    )
    assert empty.score is None and empty.coverage == 0.0


def test_case_17_missing_measurements_lower_coverage_not_score() -> None:
    # no WAN data and no DNS data: excluded from the mean, coverage drops
    partial = compute_score(
        full_inputs(wan_availability=None, dns_failure=None, dns_response=None)
    )
    assert comp(partial, COMP_WAN).status == STATUS_UNKNOWN
    assert comp(partial, COMP_WAN).score is None
    assert comp(partial, COMP_DNS).status == STATUS_UNKNOWN
    # (20*80 + 15*80 + 10*85 + 10*80 + 5*100) / 60: the missing parts add nothing
    assert partial.score == pytest.approx(82.5)
    assert partial.coverage == pytest.approx(0.6)
    assert partial.low_confidence is False

    # very little data: still shown, but flagged
    thin = compute_score(
        ScoreInputs(
            latency=Reading(50.0), jitter=Reading(10.0), observation_seconds=DAY_S
        )
    )
    assert thin.score == pytest.approx((15 * 80 + 10 * 85) / 25)
    assert thin.coverage == pytest.approx(0.25)
    assert thin.coverage < MIN_COVERAGE and thin.low_confidence is True

    # partial coverage of one component lowers coverage, not the score
    half = compute_score(full_inputs(latency=Reading(50.0, coverage=0.5)))
    assert half.score == pytest.approx(86.5)
    assert half.coverage == pytest.approx(1 - 15 * 0.5 / 100)

    # gaps in the probes lower coverage; loss is computed from measured probes only
    samples = [Sample.answered(T0 + i * R, 20.0) for i in range(6)] + [
        Sample.gap(T0 + (6 + i) * R) for i in range(6)
    ]
    s = summarize(samples)
    inputs = inputs_from_summaries(path=s, observation_seconds=DAY_S)
    from_gaps = compute_score(inputs)
    assert comp(from_gaps, COMP_LOSS).score == 100.0  # gaps are not loss
    assert comp(from_gaps, COMP_LOSS).coverage == pytest.approx(0.5)
    assert from_gaps.coverage < 0.5 and from_gaps.low_confidence is True

    # a short observation is low confidence even at full coverage
    short = compute_score(full_inputs(observation_seconds=MIN_OBSERVATION_S - 1))
    assert short.coverage == 1.0 and short.low_confidence is True


def test_not_applicable_is_not_missing() -> None:
    # an AP has no WAN: not applicable leaves score and coverage alone
    ap = compute_score(
        full_inputs(wan_availability=None, not_applicable=frozenset({COMP_WAN}))
    )
    assert comp(ap, COMP_WAN).status == STATUS_NOT_APPLICABLE
    assert ap.coverage == 1.0
    assert ap.score == pytest.approx((8650 - 2500) / 75)
    with pytest.raises(ValueError):
        ScoreInputs(not_applicable=frozenset({"bogus"}))
    everything_na = compute_score(
        ScoreInputs(not_applicable=frozenset(COMPONENT_WEIGHTS))
    )
    assert everything_na.score is None and everything_na.coverage == 0.0


def test_dns_component_from_summary() -> None:
    dns = summarize_dns(
        [DnsSample(T0 + i * R, DNS_NOERROR, 20.0) for i in range(8)]
        + [DnsSample(T0 + (8 + i) * R, DNS_TIMEOUT) for i in range(2)]
    )
    result = compute_score(inputs_from_summaries(dns=dns, observation_seconds=DAY_S))
    c = comp(result, COMP_DNS)
    # 20 % failures -> 0 points; response time 20 ms would be 100: the minimum wins
    assert c.score == 0.0
    assert dict(c.inputs) == {
        "failure_pct": pytest.approx(20.0),
        "response_ms": pytest.approx(20.0),
    }
    # all queries timed out: failure counts, missing response time does not hide it
    dead = summarize_dns([DnsSample(T0 + i * R, DNS_TIMEOUT) for i in range(3)])
    assert comp(compute_score(inputs_from_summaries(dns=dead)), COMP_DNS).score == 0.0


def test_gateway_reachability_from_summary() -> None:
    gw = summarize(
        [Sample.answered(T0 + i * R, 1.0) for i in range(99)]
        + [Sample.lost(T0 + 99 * R)]
    )
    result = compute_score(inputs_from_summaries(gateway=gw, observation_seconds=DAY_S))
    c = comp(result, COMP_GATEWAY)
    assert dict(c.inputs) == {"reachability_pct": pytest.approx(99.0)}
    assert c.score == pytest.approx(80.0)


# --- aggregation --------------------------------------------------------------


def _router(score: float, *, coverage: float = 1.0, obs: float = DAY_S):
    """A router result with one component holding the given score."""
    return dataclasses.replace(
        compute_score(full_inputs(observation_seconds=obs)),
        score=score,
        coverage=coverage,
        low_confidence=coverage < MIN_COVERAGE or obs < MIN_OBSERVATION_S,
    )


def test_network_unmeasured_router_lowers_coverage_not_score() -> None:
    net = combine_scores({"a": _router(90.0), "b": _router(80.0), "c": None})
    assert net.score == pytest.approx(85.0)
    assert net.coverage == pytest.approx(2 / 3)
    assert {c.name for c in net.components} == {"a", "b", "c"}
    assert next(c for c in net.components if c.name == "c").status == STATUS_UNKNOWN


def test_network_is_capped_by_worst_confident_router() -> None:
    net = combine_scores({"a": _router(95.0), "b": _router(95.0), "c": _router(40.0)})
    assert net.score == pytest.approx(40.0 + NETWORK_WORST_MARGIN)
    # a low-confidence router does not drag the network down through the cap
    weak = combine_scores(
        {"a": _router(95.0), "b": _router(95.0), "c": _router(40.0, coverage=0.2)}
    )
    assert weak.score == pytest.approx((95 + 95 + 40) / 3, abs=0.05)  # rounded to 0.1
    assert weak.coverage == pytest.approx((1 + 1 + 0.2) / 3)


def test_network_weights_and_empty() -> None:
    net = combine_scores(
        {"gw": _router(60.0), "ap": _router(80.0)}, weights={"gw": 3.0}
    )
    assert net.score == pytest.approx((3 * 60 + 80) / 4)
    empty = combine_scores({})
    assert empty.score is None and empty.coverage == 0.0
    none_measured = combine_scores({"a": None, "b": None})
    assert none_measured.score is None and none_measured.coverage == 0.0
    with pytest.raises(ValueError):
        combine_scores({"a": _router(60.0)}, weights={"a": 0.0})


def test_network_observation_is_shortest_measured() -> None:
    net = combine_scores(
        {"a": _router(90.0, obs=DAY_S), "b": _router(90.0, obs=600.0), "c": None}
    )
    assert net.observation_seconds == 600.0
    assert net.low_confidence is True


def test_segment_and_wan_use_the_same_function() -> None:
    wan = compute_score(
        ScoreInputs(
            wan_availability=Reading(99.0),
            packet_loss=Reading(0.0),
            latency=Reading(20.0),
            jitter=Reading(5.0),
            observation_seconds=DAY_S,
            not_applicable=frozenset({COMP_DNS, COMP_GATEWAY, COMP_STABILITY}),
        )
    )
    assert wan.coverage == 1.0
    assert wan.score == pytest.approx(
        (25 * 80 + 20 * 100 + 15 * 100 + 10 * 100) / 70, abs=0.05
    )
