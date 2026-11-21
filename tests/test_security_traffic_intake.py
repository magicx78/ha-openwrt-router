"""Security Center takes Traffic Analytics indicators (wish W2, 1.49.1).

End to end over the real core bus: Traffic's ``SecurityIndicators`` emits
``traffic_analytics.indicator`` with ``api.emit``; the center (subscribed
through ``api.subscribe``) keeps one timeline note with the evidence_ref,
never an incident and no trust indicator. No router, no network.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from config_manager_kit import cm_env, drain, stop
from core_test_provider import short_tmp_path  # noqa: F401 - short tmp_path
from core_testkit import FakeDisks
from test_net_engine import FakeDisk
from test_security_center import NO_SCHEDULE, _core_center

from custom_components.openwrt_router import const, security_center
from custom_components.openwrt_router.security_center import (
    SEC_TRAFFIC_PER_HOUR,
    TRAFFIC_EVENT_TYPE,
    TRAFFIC_INDICATORS,
    traffic_indicator_hint,
)
from custom_components.openwrt_router.traffic_const import (
    EVENT_INDICATOR,
    INDICATORS,
    MODULE_NAME,
    REASON_MODULE_DISABLED,
    REASON_NO_INDICATOR_INTAKE,
    SECURITY_DATA_KEY,
    SOURCE_MODULE_MISSING,
    SOURCE_NOT_CONNECTED,
    SOURCE_NOT_READY,
    SOURCE_READY,
)
from custom_components.openwrt_router.traffic_correlate import SecurityIndicators

REF = "evr_" + "0123456789abcdef"
CLI = "cli_" + "a" * 16
PID = "tpt_" + "b" * 16


@pytest.fixture
def core_disks():
    with FakeDisks().patch() as fake:
        yield fake


def payload(**over: Any) -> dict[str, Any]:
    """``data`` of a Traffic indicator event (schema v1, see _publish)."""
    out = {
        "v": 1,
        "indicator": "unusual_traffic_volume",
        "evidence_ref": REF,
        "candidate_id": "cand_1",
        "point": PID,
        "kind": "wan_spike",
        "observed": 9.5e8,
        "threshold": 2.0e8,
        "window_s": 300,
        "coverage": "partial",
        "wording": "traffic_deviation_not_an_attack",
        "security_center": "ready",
    }
    out.update(over)
    return out


def emit(env: Any, data: dict[str, Any], **kw: Any) -> None:
    env.api.emit(
        EVENT_INDICATOR,
        source=MODULE_NAME,
        router_id=kw.pop("router_id", env.rid),
        dedup_key=kw.pop("dedup_key", f"{PID}:{data.get('evidence_ref')}"),
        data=data,
        client_ref=CLI,
        confidence=0.6,
        classification="traffic_indicator",
        **kw,
    )


async def bound(core_disks: Any, tmp_path: Any, *, enabled: bool = True) -> Any:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    env.api.register_event_prefix("traffic_analytics.", module=MODULE_NAME)
    center = await _core_center(env, FakeDisk(), enabled=enabled)
    return env, center


def notes(center: Any) -> list[dict[str, Any]]:
    return [t for t in center.timeline if t["kind"] == "traffic_indicator"]


def test_the_contract_names_match_traffic() -> None:
    assert TRAFFIC_EVENT_TYPE == EVENT_INDICATOR
    assert security_center.TRAFFIC_EVENT_SOURCE == MODULE_NAME
    assert frozenset(INDICATORS) == TRAFFIC_INDICATORS
    assert SECURITY_DATA_KEY == const.DATA_SECURITY_CENTER


async def test_an_indicator_is_a_timeline_note_never_an_incident(
    core_disks, tmp_path
) -> None:
    env, center = await bound(core_disks, tmp_path)
    assert center.accepts_traffic_indicators is True
    before = dict(center.incidents)
    emit(env, payload())
    await drain(env.hass)
    (note,) = notes(center)
    assert note["router_id"] == env.rid
    assert note["evidence_ref"] == REF
    assert note["type"] == "unusual_traffic_volume"
    assert note["severity"] == "info" and note["category"] == "system"
    assert "Angriff" in note["text"]  # "kein Beleg für einen Angriff"
    # no traffic pseudonym is kept, no incident, no trust indicator
    assert CLI not in repr(center.timeline) and PID not in repr(center.timeline)
    assert note["client_ref"] is None and note["has_client"] is False
    assert center.incidents == before
    assert len(center.trust) == 0
    assert center.counters["traffic_indicators"] == 1
    # the same evidence reference again: counted, not noted twice
    emit(env, payload(), dedup_key="other")
    await drain(env.hass)
    assert len(notes(center)) == 1
    assert center.counters["traffic_indicators_duplicate"] == 1
    await stop(env)


async def test_invalid_indicators_are_refused(core_disks, tmp_path) -> None:
    env, center = await bound(core_disks, tmp_path)
    bad = [
        payload(v=2),
        payload(v=True),
        payload(indicator="port_scan"),
        payload(evidence_ref="evr_XYZ"),
        payload(evidence_ref="02:00:5e:00:53:01"),
        payload(kind="Wan Spike!"),
        payload(observed="lots"),
        payload(observed=float("inf")),
        payload(window_s=-5),
        payload(coverage="everything"),
    ]
    for i, data in enumerate(bad):
        emit(env, data, dedup_key=f"bad{i}")
    emit(env, payload(evidence_ref="evr_" + "1" * 16), router_id=None)
    await drain(env.hass)
    assert notes(center) == []
    assert center.counters["traffic_indicators_invalid"] == len(bad) + 1
    await stop(env)


async def test_the_hourly_limit_counts_the_rest(core_disks, tmp_path) -> None:
    env, center = await bound(core_disks, tmp_path)
    for i in range(SEC_TRAFFIC_PER_HOUR + 5):
        emit(env, payload(evidence_ref=f"evr_{i:016x}"), dedup_key=f"d{i}")
    await drain(env.hass)
    assert len(notes(center)) == SEC_TRAFFIC_PER_HOUR
    assert center.counters["traffic_indicators_limited"] == 5
    await stop(env)


async def test_center_off_takes_nothing_and_fails_nothing(core_disks, tmp_path) -> None:
    env, center = await bound(core_disks, tmp_path, enabled=False)
    assert center.accepts_traffic_indicators is False
    emit(env, payload())
    await drain(env.hass)
    assert notes(center) == []
    assert center.counters["traffic_indicators"] == 0
    await stop(env)


def test_the_hint_keeps_no_traffic_identity() -> None:
    event = SimpleNamespace(
        source=MODULE_NAME,
        type=EVENT_INDICATOR,
        router_id="rtr_" + "1" * 32,
        ts=1_800_000_000.0,
        data=payload(),
        confidence=0.6,
        client_ref=CLI,
    )
    hint = traffic_indicator_hint(event)
    assert hint is not None
    assert set(hint) == {
        "ts",
        "router_id",
        "indicator",
        "evidence_ref",
        "kind",
        "observed",
        "threshold",
        "window_s",
        "coverage",
        "confidence",
    }
    other = SimpleNamespace(**{**vars(event), "source": "x"})
    assert traffic_indicator_hint(other) is None


def test_traffic_reports_the_link_state_honestly() -> None:
    def status(center: Any) -> tuple[str, str | None]:
        st = SecurityIndicators(security=lambda: center).security_status()
        return st.state, st.reason

    assert status(None) == (SOURCE_MODULE_MISSING, "module_not_loaded")
    assert status(object()) == (SOURCE_NOT_CONNECTED, REASON_NO_INDICATOR_INTAKE)
    off = SimpleNamespace(accepts_traffic_indicators=False)
    assert status(off) == (SOURCE_NOT_READY, REASON_MODULE_DISABLED)
    on = SimpleNamespace(accepts_traffic_indicators=True)
    assert status(on) == (SOURCE_READY, None)

    def broken() -> Any:
        raise RuntimeError("x")

    assert SecurityIndicators(security=broken).security_status().state == (
        SOURCE_NOT_READY
    )


async def test_traffic_engine_sees_the_running_center(core_disks, tmp_path) -> None:
    env, center = await bound(core_disks, tmp_path)
    from custom_components.openwrt_router.traffic_engine import TrafficEngine

    engine = TrafficEngine(env.hass)
    link = engine.indicators.summary()["security_center"]
    assert (link["state"], link["reason"]) == (SOURCE_READY, None)
    center.deactivate()
    link = engine.indicators.summary()["security_center"]
    assert (link["state"], link["reason"]) == (SOURCE_NOT_READY, REASON_MODULE_DISABLED)
    await stop(env)
