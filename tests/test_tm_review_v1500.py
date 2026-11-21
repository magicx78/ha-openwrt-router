"""1.50.0 review before the merge: marks that went missing silently.

Each test rebuilds one case of the independent review (scripts under
``review-tm-a``) with data made on the source modules' own write paths: the
real enterprise core audit (``emit``), Network Intelligence fed with polls
(``ingest``), its incident machine (``AlarmMachine.update``) and the
Security Center timeline (``_timeline``, the path its rules use). The
answers are read through ``tm_query.async_timeline`` as the route does.

* S1: a source whose read is used up by client entries hid older marks
  (``marks`` 0, state ``empty``, ``next_until`` null).
* S2: the core audit with two rings: the page edge was the oldest entry of
  both rings, and without ``until`` the older half was never reachable.
* S3: NI incidents were read in ``incidents_page`` order (status, severity),
  not by time: resolved incidents inside the window fell out.
* K1: rounding to milliseconds put the edge mark on two pages.
* K2: per-source ``state`` and ``oldest`` told a non-admin about marks he
  may not see.
* K4: marks of one timestamp at the cut edge of a source were split, the
  rest of them lost.

No router, no HA instance, no network; MACs locally administered.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import patch

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_net_correlation import level
from test_tm_views import close, full_env, wrong_keys

from custom_components.openwrt_router import tm_query, tm_sources
from custom_components.openwrt_router.core_models import CoreEventType

DAY = 86_400.0


@pytest.fixture
def disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


async def walk(
    hass: Any,
    params: dict[str, str],
    *,
    now: float,
    admin: bool = True,
    max_pages: int = 60,
) -> list[dict[str, Any]]:
    """Every page of one window, as the panel walks it with ``next_until``."""
    bodies: list[dict[str, Any]] = []
    until = params["until"]
    while True:
        query = tm_query.parse_query({**params, "until": until}, now)
        body = await tm_query.async_timeline(hass, query, admin=admin, now=now)
        bodies.append(body)
        if body["next_until"] is None:
            return bodies
        assert body["next_until"] < float(until), "paging must go back in time"
        assert len(bodies) < max_pages, "paging does not end"
        until = str(body["next_until"])


def ids(bodies: list[dict[str, Any]]) -> list[str]:
    return [m["id"] for b in bodies for m in b["marks"]]


def window(world: Any, *, now: float, days: float = 1.0) -> dict[str, str]:
    return {"from": str(int(now - days * DAY + 10)), "until": str(int(now) + 1)}


# --- S1 ---------------------------------------------------------------------------------


def client_bursts(world: Any, start: float, polls: int, per_poll: int) -> None:
    """Client events only (a wrong key), ``per_poll`` stations per poll."""
    for n in range(polls):
        wrong_keys(world.engine, start + 60 * n, per_poll, first=10_000 + n * per_poll)


async def test_s1_client_entries_never_hide_older_ni_marks(disks, tmp_path) -> None:
    world = await full_env(disks, tmp_path)
    client_bursts(world, world.start + 900, 30, 20)
    ring = list(world.engine.ring)
    wan = [e for e in ring if e.kind.startswith("wan.")]
    clients = [e for e in ring if "mac" in e.subject]
    assert wan and len(clients) > 500  # more than the old read limit
    now = world.start + 7200
    [body] = await walk(
        world.env.hass, {**window(world, now=now), "source": "ni_events"}, now=now
    )
    shown = [m for m in body["marks"] if m["title_key"].startswith("ni_events.wan.")]
    assert len(shown) == len(wan)
    [source] = body["sources"]
    assert source["state"] == "ok" and source["count"] == len(body["marks"])
    assert body["omitted_client_marks"] == len(clients)
    await close(world)


async def test_s1_a_cut_source_never_looks_quiet_and_paging_goes_on(
    disks, tmp_path
) -> None:
    """With a read limit below the store (patched), the cut is visible."""
    world = await full_env(disks, tmp_path)
    client_bursts(world, world.start + 900, 30, 20)
    wan = [e for e in world.engine.ring if e.kind.startswith("wan.")]
    now = world.start + 7200
    params = {**window(world, now=now), "source": "ni_events"}
    with patch.object(tm_sources, "NI_EVENTS_READ_LIMIT", 50):
        bodies = await walk(world.env.hass, params, now=now)
    first = bodies[0]
    [source] = first["sources"]
    assert first["marks"] == []  # the newest 50 are client events
    assert source["truncated"] is True
    assert source["state"] != "empty"  # a cut source is not a quiet one
    assert source["cut"] == "next_page"
    assert first["truncated"] is True and first["next_until"] is not None
    seen = [m for b in bodies for m in b["marks"]]
    assert len(ids(bodies)) == len(set(ids(bodies)))
    assert len([m for m in seen if m["title_key"].startswith("ni_events.wan.")]) == len(
        wan
    )
    await close(world)


# --- S2 ---------------------------------------------------------------------------------


def audit_history(world: Any, *, count: int, security: int) -> float:
    """``count`` general and ``security`` security-ring entries, 13..7 days ago."""
    base = world.env.clock.utc() - timedelta(days=13)
    audit = world.env.core.audit
    for i in range(count):
        audit.emit(
            CoreEventType.ROUTER_CAPABILITIES_CHANGED,
            router_id=world.env.rid,
            dedup_key=f"gen{i}",
            now=base + timedelta(minutes=10 * i),
        )
    for i in range(security):
        audit.emit(
            CoreEventType.ROUTER_CAPABILITIES_CHANGED,
            router_id=world.env.rid,
            dedup_key=f"sec{i}",
            security_relevant=True,
            now=base + timedelta(seconds=30, days=i),
        )
    return base.timestamp()


def audit_ids(world: Any, since: float, until: float) -> set[str]:
    """Event ids of every stored non-client audit entry in the window."""
    events = world.env.core.audit.events(since=datetime.fromtimestamp(since, UTC))
    return {
        e.event_id
        for e in events
        if since <= e.ts.timestamp() < until
        and e.client_ref is None
        and not tm_sources._audit_concerns_client(e)
    }


async def test_s2_every_audit_entry_of_the_window_is_reachable(disks, tmp_path) -> None:
    world = await full_env(disks, tmp_path)
    audit_history(world, count=800, security=3)
    now = world.start + 3600
    params = {**window(world, now=now, days=14), "source": "core_audit", "limit": "500"}
    bodies = await walk(world.env.hass, params, now=now)
    shown = [m["ref"]["id"] for b in bodies for m in b["marks"]]
    assert len(shown) == len(set(shown))
    expected = audit_ids(world, float(params["from"]), float(params["until"]))
    assert len(expected) > 800
    assert set(shown) == expected
    await close(world)


async def test_s2_the_cut_edge_of_two_rings_is_the_newer_one(disks, tmp_path) -> None:
    """General ring cut (read limit patched to 100), security ring whole."""
    world = await full_env(disks, tmp_path)
    audit_history(world, count=800, security=3)
    now = world.start + 3600
    params = {**window(world, now=now, days=14), "source": "core_audit", "limit": "500"}
    with patch.object(tm_sources, "AUDIT_READ_LIMIT", 100):
        bodies = await walk(world.env.hass, params, now=now)
    general = world.env.core.audit.events(ring="general")
    edge = sorted(e.ts.timestamp() for e in general)[-100]  # oldest of the newest 100
    first = bodies[0]
    assert first["marks"] and all(m["ts"] >= edge for m in first["marks"])
    assert first["sources"][0]["cut"] == "next_page"
    shown = ids(bodies)
    assert len(shown) == len(set(shown))
    # the security ring is whole: all of it comes, on a later page
    security = {e.event_id for e in world.env.core.audit.events(ring="security")}
    seen_refs = {m["ref"]["id"] for b in bodies for m in b["marks"]}
    in_window = audit_ids(world, float(params["from"]), float(params["until"]))
    assert security & in_window <= seen_refs
    # the general ring cannot be read further back without ``until``: said so
    assert bodies[-1]["sources"][0]["cut"] == "unreachable"
    assert bodies[-1]["sources"][0]["state"] != "empty"
    await close(world)


# --- S3 ---------------------------------------------------------------------------------


async def test_s3_resolved_incidents_of_the_window_are_not_left_out(
    disks, tmp_path
) -> None:
    """205 open incidents sort before 10 resolved ones in ``incidents_page``."""
    world = await full_env(disks, tmp_path)
    machine = world.engine.machine
    t1, t2, t3 = (world.start + s for s in (600, 1200, 1800))
    keep = [level("wan_down", f"e1:keep{i}", router="e1") for i in range(205)]
    gone = [f"e1:gone{i}" for i in range(10)]
    machine.update(t1, [*keep, *(level("wan_down", k, router="e1") for k in gone)])
    machine.update(
        t2, [*keep, *(level("wan_down", k, value=0.0, router="e1") for k in gone)]
    )
    machine.update(t3, keep)
    resolved = {
        i.id for i in machine.peek() if i.scope_key in gone and i.resolved_at == t2
    }
    assert len(resolved) == 10
    now = world.start + 7200
    bodies = await walk(
        world.env.hass, {**window(world, now=now), "source": "ni_incidents"}, now=now
    )
    marks = [m for b in bodies for m in b["marks"] if m["kind"] == "incident_resolved"]
    assert {m["ref"]["id"] for m in marks} >= resolved
    assert all(b["sources"][0]["truncated"] is False for b in bodies)
    assert len(ids(bodies)) == len(set(ids(bodies)))
    await close(world)


# --- K1 ---------------------------------------------------------------------------------


async def test_k1_microsecond_timestamps_page_without_doubles_or_gaps(
    disks, tmp_path
) -> None:
    world = await full_env(disks, tmp_path)
    base = world.env.clock.utc() + timedelta(seconds=5)
    for i in range(40):
        world.env.core.audit.emit(
            CoreEventType.ROUTER_CAPABILITIES_CHANGED,
            router_id=world.env.rid,
            dedup_key=f"us{i}",
            now=base + timedelta(microseconds=1700 * i + 600),
        )
    now = world.start + 3600
    params = {**window(world, now=now), "source": "core_audit", "limit": "7"}
    bodies = await walk(world.env.hass, params, now=now)
    shown = [m["ref"]["id"] for b in bodies for m in b["marks"]]
    assert len(shown) == len(set(shown)), "a mark came on two pages"
    assert set(shown) == audit_ids(world, float(params["from"]), float(params["until"]))
    for body in bodies:  # a page's marks lie in its own window
        until = body["window"]["until"]
        assert all(body["window"]["from"] <= m["ts"] < until for m in body["marks"])
    await close(world)


# --- K2 ---------------------------------------------------------------------------------


async def test_k2_a_non_admin_learns_nothing_of_marks_he_cannot_see(
    disks, tmp_path
) -> None:
    world = await full_env(disks, tmp_path)
    hidden_at = world.start - 1800.5  # older than everything else
    world.center._timeline(
        hidden_at,
        "drift",
        category="config",
        severity="warning",
        router_id=world.env.rid,
        text="Drift",
    )
    now = world.start + 3600
    narrow = {
        "from": str(hidden_at - 1),
        "until": str(hidden_at + 1),
        "source": "security_timeline",
    }
    wide = {**window(world, now=now), "source": "security_timeline"}
    for admin in (True, False):
        [only] = await walk(world.env.hass, narrow, now=now, admin=admin)
        [body] = await walk(world.env.hass, wide, now=now, admin=admin)
        [one] = only["sources"]
        [all_] = body["sources"]
        marks = body["marks"]
        oldest = min((m["ts"] for m in marks), default=None)
        assert all_["oldest"] == oldest and all_["count"] == len(marks)
        if admin:
            assert (one["state"], one["count"]) == ("ok", 1)
            assert one["oldest"] == pytest.approx(hidden_at, abs=0.001)
            assert oldest == pytest.approx(hidden_at, abs=0.001)
        else:
            assert one == {
                "id": "security_timeline",
                "state": "empty",
                "reason": None,
                "count": 0,
                "oldest": None,
                "truncated": False,
                "cut": None,
            }
            assert only["truncated"] is False and only["next_until"] is None
            assert oldest is None or oldest > hidden_at + 1
            assert all(m["group"] in tm_sources.NON_ADMIN_GROUPS for m in marks)
    await close(world)


# --- K4 ---------------------------------------------------------------------------------


def statuses(world: Any, at: float, count: int, tag: str) -> None:
    for i in range(count):
        world.center._timeline(
            at,
            "status",
            category="system",
            severity="info",
            router_id=None,
            text=f"Status {tag}{i}",
        )


async def test_k4_one_timestamp_at_the_cut_edge_stays_together(disks, tmp_path) -> None:
    world = await full_env(disks, tmp_path)
    x, y = world.start + 2000.25, world.start + 2500.75
    statuses(world, x, 6, "x")
    statuses(world, y, 6, "y")
    now = world.start + 3600
    params = {
        "from": str(world.start + 1900),
        "until": str(world.start + 2600),
        "source": "security_timeline",
    }
    with patch.object(tm_sources, "SECURITY_READ_LIMIT", 9):
        bodies = await walk(world.env.hass, params, now=now)
    shown = ids(bodies)
    assert len(shown) == len(set(shown)) == 12
    # no page holds only part of one timestamp of this source
    for body in bodies:
        per_ts: dict[float, int] = {}
        for m in body["marks"]:
            per_ts[m["ts"]] = per_ts.get(m["ts"], 0) + 1
        assert all(n == 6 for n in per_ts.values())
    await close(world)


async def test_k4_one_timestamp_larger_than_the_read_is_cut_and_flagged(
    disks, tmp_path
) -> None:
    world = await full_env(disks, tmp_path)
    x = world.start + 2000.25
    statuses(world, x, 6, "x")
    now = world.start + 3600
    params = {
        "from": str(world.start + 1900),
        "until": str(world.start + 2600),
        "source": "security_timeline",
    }
    with patch.object(tm_sources, "SECURITY_READ_LIMIT", 4):
        bodies = await walk(world.env.hass, params, now=now)
    shown = ids(bodies)
    assert len(shown) == len(set(shown)) == 4  # ends, no doubles
    [cut] = [b for b in bodies if b["marks"]]
    assert cut["truncated"] is True and cut["sources"][0]["truncated"] is True
    await close(world)
