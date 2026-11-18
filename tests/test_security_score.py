"""Tests for security_score (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json

from custom_components.openwrt_router.security_model import (
    DataSource,
    Severity,
    SourceStatus,
    source_status,
)
from custom_components.openwrt_router.security_score import (
    DEFAULT_EXPECTED_SOURCES,
    FACTOR_ACTIVITY,
    FACTOR_AUTH,
    FACTOR_CONFIG,
    FACTOR_COVERAGE,
    FACTOR_INCIDENTS,
    FACTOR_SEGMENTATION,
    FACTOR_UNKNOWN,
    compute_score,
    incident_load,
    monitoring_coverage,
    score_cap,
)

NOW = 1_700_000_000.0
CLEAN = {
    FACTOR_INCIDENTS: 0,
    FACTOR_CONFIG: 0,
    FACTOR_AUTH: 0,
    FACTOR_ACTIVITY: 0,
    FACTOR_UNKNOWN: 0,
    FACTOR_SEGMENTATION: 0,
}


def all_ok(
    *, without: tuple[str, ...] = (), stale: tuple[str, ...] = ()
) -> dict[str, SourceStatus]:
    out = {}
    for src in DEFAULT_EXPECTED_SOURCES | {DataSource.CONNTRACK_STATS}:
        if src in without:
            continue
        last = NOW - 5000 if src in stale else NOW
        out[src] = source_status(src, now=NOW, last_ok=last)
    return out


def test_case15_score_calculation() -> None:
    perfect = compute_score(CLEAN, all_ok())
    assert perfect.coverage == 100 and perfect.cap == 100
    assert perfect.score == 100
    values = {
        **CLEAN,
        FACTOR_INCIDENTS: incident_load([Severity.CRITICAL, Severity.WARNING]),
        FACTOR_AUTH: 2,
        FACTOR_UNKNOWN: 2,
    }
    result = compute_score(values, all_ok())
    incidents = result.factor(FACTOR_INCIDENTS)
    assert incidents is not None
    assert incidents.weight == 30 and incidents.deduction == 30  # 4 * 10, capped
    auth = result.factor(FACTOR_AUTH)
    assert auth is not None and auth.deduction == 10
    unknown = result.factor(FACTOR_UNKNOWN)
    assert unknown is not None and unknown.deduction == 5
    assert result.score == 100 - 30 - 10 - 5
    for factor in result.factors:
        assert factor.reason  # every factor explains itself
    assert json.loads(json.dumps(result.to_dict()))["score"] == result.score
    assert incident_load(["warning", "bogus"]) == 2.0  # unknown never counts 0


def test_case16_missing_sources_never_perfect() -> None:
    result = compute_score(CLEAN, all_ok(without=(DataSource.FIREWALL_LOG,)))
    assert result.coverage < 100
    assert result.score is not None and result.score < 100
    assert result.score <= result.cap < 100
    stale = compute_score(CLEAN, all_ok(stale=(DataSource.WIFI_EVENTS,)))
    assert stale.score is not None and stale.score < 100
    auth = stale.factor(FACTOR_AUTH)
    assert auth is not None and not auth.assessable and auth.deduction is None
    nothing = compute_score(CLEAN, {})
    assert nothing.score is None and nothing.coverage == 0
    assert "unknown" in nothing.reason
    unknown_values = compute_score({}, all_ok())
    assert unknown_values.score is None  # no factor value: unknown, not 100


def test_case16_not_assessable_is_not_a_zero_deduction() -> None:
    st = all_ok(without=(DataSource.CONFIG_DRIFT,))
    result = compute_score(CLEAN, st)
    config = result.factor(FACTOR_CONFIG)
    assert config is not None
    assert not config.assessable and config.deduction is None
    assert "not assessable" in config.reason
    assert DataSource.CONFIG_DRIFT in config.missing
    seg = result.factor(FACTOR_SEGMENTATION)
    assert seg is not None and seg.assessable  # firewall log still covers it
    no_value = compute_score({**CLEAN, FACTOR_AUTH: None}, all_ok())
    auth = no_value.factor(FACTOR_AUTH)
    assert auth is not None and not auth.assessable


def test_case07_missing_dns_logs_lower_coverage() -> None:
    full = monitoring_coverage(all_ok())
    no_dns = monitoring_coverage(all_ok(without=(DataSource.DNS_QUERY_LOG,)))
    assert full.coverage == 100
    assert no_dns.coverage < 100
    assert no_dns.missing == (DataSource.DNS_QUERY_LOG,)
    result = compute_score(CLEAN, all_ok(without=(DataSource.DNS_QUERY_LOG,)))
    assert result.score is not None and result.score < 100
    activity = result.factor(FACTOR_ACTIVITY)
    assert activity is not None and activity.assessable  # firewall log remains


def test_coverage_factor_and_cap_formula() -> None:
    assert score_cap(100) == 100
    assert score_cap(99) == 99
    assert score_cap(50) == 75
    assert score_cap(0) == 50
    half = all_ok(stale=(DataSource.WIFI_EVENTS,))
    assert (
        monitoring_coverage(half).coverage
        < monitoring_coverage(half, stale_credit=0.5).coverage
    )
    result = compute_score(CLEAN, all_ok(without=(DataSource.FIREWALL_LOG,)))
    cov = result.factor(FACTOR_COVERAGE)
    assert cov is not None and cov.deduction is not None and cov.deduction > 0
    assert monitoring_coverage({}, expected=()).coverage == 0


def test_review_l1_non_finite_value_is_not_assessable() -> None:
    for bad in (float("nan"), float("inf"), float("-inf")):
        result = compute_score({**CLEAN, FACTOR_INCIDENTS: bad}, all_ok())
        incidents = result.factor(FACTOR_INCIDENTS)
        assert incidents is not None and not incidents.assessable
        assert incidents.deduction is None and "not assessable" in incidents.reason
        assert result.score is not None and result.score < 100


def test_review_l4_limited_factor_is_partial_never_plain_none() -> None:
    clean = compute_score(CLEAN, all_ok())
    assert clean.score == 100 and clean.coverage == 100
    limited = compute_score(
        CLEAN, all_ok(), limitations={FACTOR_SEGMENTATION: ("dest_zone_unknown",)}
    )
    seg = limited.factor(FACTOR_SEGMENTATION)
    assert seg is not None and seg.assessable and seg.partial
    assert "dest_zone_unknown" in seg.reason and "partial" in seg.reason
    assert limited.coverage < 100 and limited.score is not None
    assert limited.score <= limited.cap < 100
    # an "any source" factor with one expected source missing is partial too
    no_dns = compute_score(CLEAN, all_ok(without=(DataSource.DNS_QUERY_LOG,)))
    activity = no_dns.factor(FACTOR_ACTIVITY)
    assert activity is not None and activity.assessable and activity.partial
    assert DataSource.DNS_QUERY_LOG in activity.reason
    for factor in (*limited.factors, *no_dns.factors):
        if factor.partial:
            assert factor.reason.endswith(")") and "partial" in factor.reason
