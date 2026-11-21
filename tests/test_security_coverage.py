"""Security Center 1.46.2, part 1: the coverage never drops when a source arrives.

Observed on v1.46.0: the gateway started to deliver firewall lines by syslog
and the coverage fell from 71 to 65 (cap 86 to 82). Two causes: the fleet
status of a source was the WORST over all routers (access points never
deliver firewall or DNS lines, so ``firewall_log`` stayed "missing"), and
the limitation ``dest_zone_unknown`` of ``fw_inter_vlan`` (now available on
the gateway) cost the coverage 5.26 points on top of the missing source.

Every test started red. No device, no Home Assistant instance: statuses are
built here or come from the syslog receiver on loopback.
"""

from __future__ import annotations

from itertools import combinations
from typing import Any
from unittest.mock import patch

import pytest
from test_net_engine import make_hass
from test_security_center import (
    MODULE_KEY,
    RID1,
    RID2,
    center_for,
    disks,  # noqa: F401 - fixture
)
from test_security_review2 import poll_facts
from test_security_review3 import keyed_center
from test_security_syslog import LOOP, NOV18, Clock, fw_line

from custom_components.openwrt_router.security_center import (
    SecurityCenter,
    merge_settings,
)
from custom_components.openwrt_router.security_model import (
    Availability,
    DataSource,
    SourceStatus,
)
from custom_components.openwrt_router.security_rules import DetectorResult
from custom_components.openwrt_router.security_score import (
    DEFAULT_EXPECTED_SOURCES,
    DEFAULT_RULES,
    FACTOR_COVERAGE,
    compute_score,
)
from custom_components.openwrt_router.security_syslog import (
    SyslogLimits,
    SyslogReceiver,
)

EXPECTED = sorted(DEFAULT_EXPECTED_SOURCES)
FACTORS = [r.id for r in DEFAULT_RULES if r.id != FACTOR_COVERAGE]
VALUES: dict[str, float | None] = dict.fromkeys(FACTORS, 0.0)
FW = DataSource.FIREWALL_LOG.value
DNS = DataSource.DNS_QUERY_LOG.value


def status(source: str, ok: bool) -> SourceStatus:
    if ok:
        return SourceStatus(
            source=source, availability=Availability.AVAILABLE, last_ok=NOV18
        )
    return SourceStatus(
        source=source, availability=Availability.NOT_AVAILABLE, reason="no_data_yet"
    )


def statuses_of(available: set[str]) -> dict[str, SourceStatus]:
    return {s: status(s, s in available) for s in EXPECTED}


def own_factors(source: str) -> list[str]:
    return [r.id for r in DEFAULT_RULES if source in r.sources]


def with_limit(
    limits: dict[str, tuple[str, ...]], factors: list[str], what: str
) -> dict[str, tuple[str, ...]]:
    return {**limits, **{f: (*limits.get(f, ()), what) for f in factors}}


# --- property: a source that arrives with a limitation never lowers anything ------------


@pytest.mark.parametrize("source", EXPECTED)
def test_cov_mono_source_arrives_with_a_limitation_never_lowers(source: str) -> None:
    others = [s for s in EXPECTED if s != source]
    every = dict.fromkeys(FACTORS, ("capacity",))
    for k in range(len(others) + 1):
        for avail in combinations(others, k):
            for before_limits in ({}, every):
                before = compute_score(
                    VALUES, statuses_of(set(avail)), limitations=before_limits
                )
                after = compute_score(
                    VALUES,
                    statuses_of({*avail, source}),
                    limitations=with_limit(
                        before_limits, own_factors(source), "dest_zone_unknown"
                    ),
                )
                case = (source, avail, bool(before_limits))
                assert after.coverage >= before.coverage, case
                assert after.cap >= before.cap, case


@pytest.mark.parametrize("source", EXPECTED)
def test_cov_fleet_one_router_delivers_never_lowers(source: str) -> None:
    """Two routers; the source arrives on ONE of them, with a limitation."""
    others = set(EXPECTED) - {source}
    before_fleet = {RID1: statuses_of(others), RID2: statuses_of(others)}
    after_fleet = {RID1: statuses_of({*others, source}), RID2: statuses_of(others)}
    before = compute_score(VALUES, SecurityCenter._flat(before_fleet))
    after = compute_score(
        VALUES,
        SecurityCenter._flat(after_fleet),
        limitations=with_limit({}, own_factors(source), "dest_zone_unknown"),
    )
    assert after.coverage >= before.coverage
    assert after.cap >= before.cap
    if source in (FW, DNS):  # fleet sources: one delivering router is enough
        assert after.coverage > before.coverage


def test_cov_limits_are_capped_below_one_source_share() -> None:
    every = dict.fromkeys(FACTORS, ("capacity",))
    full = compute_score(VALUES, statuses_of(set(EXPECTED)))
    limited = compute_score(VALUES, statuses_of(set(EXPECTED)), limitations=every)
    one_missing = compute_score(VALUES, statuses_of(set(EXPECTED) - {FW}))
    assert full.coverage == 100
    assert 100 - limited.coverage < 100 / len(EXPECTED)
    assert limited.coverage > one_missing.coverage
    # a limitation still counts while all expected sources of its factor work
    seg = compute_score(
        VALUES,
        statuses_of(set(EXPECTED)),
        limitations={"segmentation": ("dest_zone_unknown",)},
    )
    assert seg.coverage < 100
    # ... but not while one of them is missing fleet-wide (counted once)
    no_fw = compute_score(
        VALUES,
        statuses_of(set(EXPECTED) - {FW}),
        limitations={"segmentation": ("dest_zone_unknown",)},
    )
    assert no_fw.coverage == one_missing.coverage


# --- regression: the observed state ------------------------------------------------------


def _router(available: set[str]) -> dict[str, SourceStatus]:
    out = statuses_of(available)
    out[DataSource.ROUTER_UPTIME.value] = status(DataSource.ROUTER_UPTIME.value, True)
    return out


async def test_cov_observed_gateway_firewall_lines_raise_the_coverage(
    disks,  # noqa: F811
) -> None:
    center = await keyed_center(make_hass(), "r1", "r2")
    base = set(EXPECTED) - {FW, DNS}
    before = {RID1: _router(base), RID2: _router(base)}  # gateway, access point
    with patch.object(center, "_all_statuses", return_value=before):
        score = center.overview(actor=None, now=NOV18)["score"]
    assert (score["coverage"], score["cap"]) == (71, 86)  # as observed
    # the gateway delivers firewall lines; fw_inter_vlan becomes available
    # there and reports dest_zone_unknown
    after = {RID1: _router({*base, FW}), RID2: _router(base)}
    center._results[("fw_inter_vlan", RID1)] = DetectorResult(
        detector_id="fw_inter_vlan",
        router_id=RID1,
        status=Availability.AVAILABLE,
        limitation="dest_zone_unknown",
    )
    with patch.object(center, "_all_statuses", return_value=after):
        view = center.overview(actor=None, now=NOV18)
    score = view["score"]
    assert (score["coverage"], score["cap"]) != (65, 82)  # the observed drop
    assert (score["coverage"], score["cap"]) == (79, 90)
    assert FW in view["coverage"]["available"]
    assert DNS in view["coverage"]["missing"]
    assert view["coverage"]["fleet"][FW] == {
        "routers_delivering": 1,
        "routers": 2,
        "rate_limited": 0,
    }
    assert view["coverage"]["fleet"][DNS]["routers_delivering"] == 0
    # the other sources keep the worst-status rule
    one_ap_down = {
        RID1: _router({*base, FW}),
        RID2: _router(base - {DataSource.WIFI_EVENTS.value}),
    }
    with patch.object(center, "_all_statuses", return_value=one_ap_down):
        cov = center.overview(actor=None, now=NOV18)["coverage"]
    assert DataSource.WIFI_EVENTS.value in cov["missing"]


# --- the log path view and the coverage list agree ---------------------------------------


async def _syslog_center(
    burst: int = 1000,
) -> tuple[Any, SyslogReceiver]:
    clock = Clock()
    made: list[SyslogReceiver] = []

    def factory(*, port: int, on_backlog: Any = None) -> SyslogReceiver:
        rx = SyslogReceiver(
            port=0,
            host=LOOP,
            clock=clock,
            on_backlog=on_backlog,
            limits=SyslogLimits(
                sender_rate=0.0,
                sender_burst=burst,
                total_rate=0.0,
                total_burst=1000,
            ),
        )
        made.append(rx)
        return rx

    center = await center_for(make_hass(), "r1", "r2", enabled=False)
    center.syslog_factory = factory
    center.senders_of = lambda: {LOOP: RID1}  # only the gateway sends
    center.settings = merge_settings(
        center.settings, {"enabled": True, "log_path": "syslog"}
    )
    await center.async_activate()
    center._module_key = MODULE_KEY
    rx = center.syslog
    assert rx is not None and rx.listening
    return center, rx


def _log_status(view: dict[str, Any], source: str) -> dict[str, Any]:
    return next(s for s in view["log_path"]["status"] if s["source"] == source)


def _class(view: dict[str, Any], source: str) -> str:
    cov = view["coverage"]
    return next(k for k in ("available", "stale", "missing") if source in cov[k])


async def test_cov_agree_log_path_and_coverage_list(disks) -> None:  # noqa: F811
    center, rx = await _syslog_center()
    # on the allowlist but nothing delivered yet: missing in both views
    center.on_poll(poll_facts("r1", NOV18))
    quiet = center.overview(actor=None, now=NOV18)
    assert _class(quiet, FW) == "missing"
    assert _log_status(quiet, FW)["availability"] == "not_available"
    assert _log_status(quiet, FW)["routers_delivering"] == 0
    # the gateway delivers firewall lines; the access point never does
    for i in range(3):
        rx.receive(fw_line(i, NOV18), (LOOP, 514))
    center.on_poll(poll_facts("r1", NOV18 + 1))
    center.on_poll(poll_facts("r2", NOV18 + 1))
    view = center.overview(actor=None, now=NOV18 + 1)
    for source in (FW, DNS):
        status_ = _log_status(view, source)
        expected = "available" if status_["availability"] == "available" else None
        assert _class(view, source) == (expected or "missing"), source
        assert status_["routers"] == 2
        assert {k: status_[k] for k in ("routers_delivering", "routers")} == {
            k: view["coverage"]["fleet"][source][k]
            for k in ("routers_delivering", "routers")
        }
    assert _class(view, FW) == "available"
    assert _log_status(view, FW)["routers_delivering"] == 1
    assert _class(view, DNS) == "missing"
    detections = center.detections_view(now=NOV18 + 1)
    assert _log_status(detections, FW) == _log_status(view, FW)
    # per router it stays honest: the access point delivers nothing
    assert detections["sources"][RID2][FW]["availability"] == "not_available"
    center.close()


async def test_cov_ratelimit_supplier_stays_limited(disks) -> None:  # noqa: F811
    center, rx = await _syslog_center(burst=5)
    for i in range(10):  # the sender's burst is used up: lines are lost
        rx.receive(fw_line(i, NOV18), (LOOP, 514))
    assert rx.stats().dropped_rate == 5
    center.on_poll(poll_facts("r1", NOV18 + 1))
    view = center.overview(actor=None, now=NOV18 + 1)
    fleet = view["coverage"]["fleet"][FW]
    assert fleet == {"routers_delivering": 1, "routers": 2, "rate_limited": 1}
    assert _log_status(view, FW)["reason"] == "rate_limited"
    assert _log_status(view, FW)["rate_limited"] == 1
    det = next(d for d in view["detections"] if d["id"] == "fw_blocked")
    assert det["availability"] == "limited"
    # with every source of the log factors usable, lost lines cost coverage
    # (less than one source share), and never "fine"
    full = {RID1: _router(set(EXPECTED)), RID2: _router(set(EXPECTED) - {FW, DNS})}
    with patch.object(center, "_all_statuses", return_value=full):
        limited = center.overview(actor=None, now=NOV18 + 1)
        with patch.object(center, "_log_limited_routers", return_value=frozenset()):
            calm = center.overview(actor=None, now=NOV18 + 1)
    assert calm["coverage"]["fleet"][FW]["rate_limited"] == 0
    assert limited["coverage"]["fleet"][FW]["rate_limited"] == 1
    assert limited["coverage"]["value"] < calm["coverage"]["value"]
    assert calm["coverage"]["value"] - limited["coverage"]["value"] < 100 / 7
    assert _log_status(limited, DNS)["reason"] == "rate_limited"
    center.close()
