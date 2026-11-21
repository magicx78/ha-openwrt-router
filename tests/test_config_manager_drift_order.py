"""Drift summary after a restart: the NEWEST detection and acknowledgement win.

The core's ``api.events`` returns audit entries oldest first (``limit``
keeps the newest, still oldest first; see test_core_api_events_order.py).
These tests build every drift and acknowledgement through the real core
(real audit, real ``ConfigurationApi.events``), restart, and read what the
configuration manager rebuilt from the audit. No event list is built or
sorted by hand.
"""

from __future__ import annotations

from typing import Any

import pytest
from config_manager_kit import ON, cm_env, restart, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import ADMIN_ID, FakeDisks, user_actor

from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router.const import OPTION_CONFIG_DRIFT_CHECK
from custom_components.openwrt_router.core_models import (
    CoreEvent,
    CoreEventType,
    DriftAckState,
)

ADMIN = user_actor(ADMIN_ID)
OPTIONS = {**ON, OPTION_CONFIG_DRIFT_CHECK: True}


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _two_drifts(env: Any) -> tuple[Any, Any]:
    """Baseline, then an older drift (1 critical) and a newer one (2 critical)."""
    runtime = env.runtime
    await runtime.async_backup_now(env.rid, actor=ADMIN, wait=True)
    live = env.provider.live(env.rid)
    live["firewall"] = {**live["firewall"], "changed": {"x": "1"}}
    older = await runtime.async_check_drift(env.rid, actor=ADMIN)
    env.clock.advance(hours=2)
    live["dropbear"] = {"changed": {"y": "2"}}
    newer = await runtime.async_check_drift(env.rid, actor=ADMIN)
    assert older.drift_id and newer.drift_id and older.drift_id != newer.drift_id
    assert (older.critical_count, newer.critical_count) == (1, 2)
    return older, newer


def _detections(env: Any) -> tuple[CoreEvent, ...]:
    return env.api.events(
        router_id=env.rid, types=[str(CoreEventType.DRIFT_DETECTED)], limit=20
    )


async def test_newest_detection_is_the_current_drift_after_restart(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=OPTIONS)
    older, newer = await _two_drifts(env)
    # what the core really hands over: oldest first
    assert [e.data["drift_id"] for e in _detections(env)] == [
        older.drift_id,
        newer.drift_id,
    ]

    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert state.drift is not None
    assert state.drift["drift_id"] == newer.drift_id
    assert state.drift["critical_count"] == 2
    assert state.drift["state"] == "open"
    assert state.drift_ids >= {older.drift_id, newer.drift_id}
    await stop(env)


async def test_acknowledged_older_drift_does_not_hide_the_open_newer_one(
    disks, tmp_path
):
    env = await cm_env(disks, tmp_path, options=OPTIONS)
    older, newer = await _two_drifts(env)
    await env.api.async_acknowledge_drift(
        env.rid, older.drift_id, state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )

    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert state.drift is not None
    assert state.drift["drift_id"] == newer.drift_id
    assert state.drift["state"] == "open"
    await stop(env)


async def test_newest_acknowledgement_of_a_drift_wins(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=OPTIONS)
    runtime = env.runtime
    await runtime.async_backup_now(env.rid, actor=ADMIN, wait=True)
    live = env.provider.live(env.rid)
    live["firewall"] = {**live["firewall"], "changed": {"x": "1"}}
    report = await runtime.async_check_drift(env.rid, actor=ADMIN)
    await env.api.async_acknowledge_drift(
        env.rid, report.drift_id, state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )
    env.clock.advance(minutes=5)
    await env.api.async_acknowledge_drift(
        env.rid, report.drift_id, state=DriftAckState.KNOWN, actor=ADMIN
    )
    acks = env.api.events(
        router_id=env.rid, types=[str(CoreEventType.DRIFT_ACKNOWLEDGED)], limit=20
    )
    assert [e.data["state"] for e in acks] == ["acknowledged", "known"]

    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert state.drift is not None
    assert state.drift["drift_id"] == report.drift_id
    assert state.drift["state"] == "known"
    await stop(env)


async def test_summary_does_not_depend_on_the_list_order(disks, tmp_path):
    """Same entries newest first give the same summary (time decides)."""
    env = await cm_env(disks, tmp_path, options=OPTIONS)
    older, newer = await _two_drifts(env)
    await env.api.async_acknowledge_drift(
        env.rid, newer.drift_id, state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )
    events = env.api.events(
        router_id=env.rid,
        types=[
            str(CoreEventType.DRIFT_DETECTED),
            str(CoreEventType.DRIFT_ACKNOWLEDGED),
        ],
        limit=20,
    )
    summaries = []
    for ordered in (events, tuple(reversed(events))):
        state = cm.RouterState(router_id=env.rid, entry_id=env.entries[0].entry_id)
        env.runtime._drift_from_events(state, ordered)
        summaries.append((state.drift, state.drift_ids))
    assert summaries[0] == summaries[1]
    assert summaries[0][0]["drift_id"] == newer.drift_id
    assert summaries[0][0]["state"] == "acknowledged"
    assert summaries[0][1] == {older.drift_id, newer.drift_id}
    await stop(env)


async def test_repeated_older_drift_counts_from_its_newest_repeat(disks, tmp_path):
    """A drift seen again (deduplicated: one entry, newer ``last_repeat_at``)
    after another drift is the current one again."""
    env = await cm_env(disks, tmp_path, options=OPTIONS)
    older, newer = await _two_drifts(env)
    live = env.provider.live(env.rid)
    del live["dropbear"]  # back to exactly the older drift
    env.clock.advance(hours=2)
    again = await env.runtime.async_check_drift(env.rid, actor=ADMIN)
    assert again.drift_id == older.drift_id
    detections = _detections(env)
    assert [e.data["drift_id"] for e in detections] == [
        older.drift_id,
        newer.drift_id,
    ]
    assert detections[0].repeat_count == 1  # one entry, repeated

    env = await restart(env)
    state = env.runtime.routers[env.rid]
    assert state.drift is not None
    assert state.drift["drift_id"] == older.drift_id
    assert state.drift["critical_count"] == 1
    await stop(env)
