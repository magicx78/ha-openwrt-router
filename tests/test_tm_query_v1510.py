"""Network Time Machine 1.51.0: the timeline over the own index.

Doubles between sources (which source wins), rights after the doubles,
the incident read limit of review N1 and the additive answer fields. The
own index is filled through the engine (``tm_index_kit``) or, for the audit
references, through the real enterprise core of ``test_tm_views.full_env``.
"""

from __future__ import annotations

import dataclasses
from typing import Any
from unittest.mock import patch

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_net_correlation import T0 as NI_T0
from test_net_correlation import clock, fleet  # noqa: F401 - fixtures
from test_tm_sources import NI_ROUTERS, ak1, read, request
from test_tm_views import around, close, full_env, http
from tm_index_kit import RID, T0, world

from custom_components.openwrt_router import tm_query, tm_sources
from custom_components.openwrt_router.config_api import ConfigurationApi
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.net_events import MAX_INCIDENTS, IncidentStatus
from custom_components.openwrt_router.tm_sources import SourceResult

R1 = RID["r1"]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


@pytest.fixture
def core_disks():
    with FakeDisks().patch() as fake:
        yield fake


def own_query(**kw: Any) -> tm_query.Query:
    return tm_query.Query(
        kw.pop("since", T0 - 60),
        kw.pop("until", T0 + 86_400),
        sources=tm_sources.INDEX_SOURCE_IDS,
        **kw,
    )


# --- which source wins -------------------------------------------------------------------


async def test_the_audit_wins_over_its_reference_until_it_is_gone(
    core_disks, tmp_path
) -> None:
    world_ = await full_env(core_disks, tmp_path)
    env = world_.env
    env.core.audit.emit(
        CoreEventType.DRIFT_DETECTED,
        router_id=env.rid,
        dedup_key="tm-1",
        now=env.clock.utc(),
    )
    assert world_.tm.counters["refs_taken"] == 1
    async with http(env.hass) as h:
        both = (await h.get(params=around(world_))).data
        by_id = {s["id"]: s for s in both["sources"]}
        assert (by_id["tm_refs"]["count"], by_id["tm_refs"]["duplicates"]) == (0, 1)
        drifts = [m for m in both["marks"] if m["kind"] == "config_drift"]
        assert "tm_refs" not in {m["source"] for m in drifts}
        # the audit ring evicted the entry: the reference keeps it
        with patch.object(ConfigurationApi, "events", lambda *a, **k: ()):
            alone = (await h.get(params=around(world_))).data
        [ref] = [m for m in alone["marks"] if m["source"] == "tm_refs"]
        assert ref["kind"] == "config_drift"
        assert ref["title_key"] == "core_audit.configuration.drift_detected"
        assert ref["ref"]["module"] == "core_audit" and ref["ref"]["id"]
        audit_ids = {m["ref"]["id"] for m in drifts if m["source"] == "core_audit"}
        assert ref["ref"]["id"] in audit_ids
        h.assert_private()
    await close(world_)


def _mark(source: str, kind: str, ts: float) -> dict[str, Any]:
    return tm_sources.make_mark(
        source=source,
        source_id=f"{kind}{ts}",
        ts=ts,
        kind=kind,
        severity="warning",
        router_id=R1,
        routers=tm_sources.RouterMap(),
        fleet=False,
        code=kind,
        ref=tm_sources.ref_of("network_intelligence", "event", "e1"),
    )


def test_the_index_wins_over_the_same_ni_event_only() -> None:
    """Review S1: same meaning, same router, close in time (else it stays)."""
    down = _mark("tm_index", "router_down", T0 + 50)
    down.update(end=T0 + 1000, end_state="closed")
    index = SourceResult("tm_index", "ok", marks=[down])

    def ni_result() -> SourceResult:
        return SourceResult(
            "ni_events",
            "ok",
            marks=[
                _mark("ni_events", "router_down", T0 + 260),  # inside: dropped
                _mark("ni_events", "router_down", T0 + 2000),  # after its end
                _mark("ni_events", "wan_event", T0 + 60),  # the index has none
            ],
        )

    ni = ni_result()
    body = tm_query.merge(
        [ni, index],
        tm_query.Query(T0, T0 + 3000, sources=("ni_events", "tm_index")),
        admin=False,
        now=T0 + 3000,
    )
    by_id = {s["id"]: s for s in body["sources"]}
    assert by_id["ni_events"]["duplicates"] == 1 and by_id["ni_events"]["count"] == 2
    assert [(m["source"], m["ts"]) for m in body["marks"]] == [
        ("ni_events", T0 + 2000),
        ("ni_events", T0 + 60),
        ("tm_index", T0 + 50),
    ]
    # an unreadable index drops nothing
    index.state = "unreadable"
    body = tm_query.merge(
        [ni_result(), index],
        tm_query.Query(T0, T0 + 3000, sources=("ni_events", "tm_index")),
        admin=True,
        now=T0 + 3000,
    )
    assert {s["id"]: s["duplicates"] for s in body["sources"]}["ni_events"] == 0
    assert len([m for m in body["marks"] if m["source"] == "ni_events"]) == 3


# --- rights after the doubles -----------------------------------------------------------


async def test_non_admin_sees_infrastructure_of_the_index_only(disks) -> None:
    with world(disks) as w:
        await w.start()
        coord = w.coords["r1"]
        for host in ("a", "a", "b", "b"):
            coord.poll(_data(host))
        w.down("r1")
        admin = await tm_query.async_timeline(
            w.hass, own_query(), admin=True, now=w.clock.t
        )
        user = await tm_query.async_timeline(
            w.hass, own_query(), admin=False, now=w.clock.t
        )
    assert {m["kind"] for m in admin["marks"]} == {
        "tm_started",
        "config_fingerprint_changed",
        "router_down",
    }
    [down] = user["marks"]
    assert (down["kind"], down["end_state"], down["end"]) == (
        "router_down",
        "open",
        None,
    )
    by_id = {s["id"]: s for s in user["sources"]}
    assert (by_id["tm_index"]["count"], by_id["tm_index"]["oldest"]) == (1, down["ts"])
    assert by_id["tm_refs"]["reason"] == by_id["tm_clients"]["reason"] == "admin_only"
    assert user["status"] == "ok" and user["v"] == 1


def _data(host: str) -> Any:
    from tm_index_kit import iface, poll_data

    return poll_data(iface("phy1", 36), hostname=host)


async def test_index_sources_say_when_the_engine_is_not_running(disks) -> None:
    with world(disks) as w:
        body = await tm_query.async_timeline(w.hass, own_query(), admin=True, now=T0)
    assert {s["id"]: (s["state"], s["reason"]) for s in body["sources"]} == {
        "tm_index": ("unreadable", "not_running"),
        "tm_refs": ("unreadable", "not_running"),
        "tm_clients": ("unreadable", "not_running"),
    }
    assert body["status"] == "partial"


def test_new_query_values_are_checked() -> None:
    query = tm_query.parse_query({"source": "tm_clients,tm_index"}, T0)
    assert query.sources == ("tm_index", "tm_clients")
    assert (
        tm_query.parse_query({"kind": "client_flapping"}, T0).kind == "client_flapping"
    )
    with pytest.raises(tm_query.QueryError):
        tm_query.parse_sessions_query({"client": "cli_" + "a" * 16}, T0)
    with pytest.raises(tm_query.QueryError):
        tm_query.parse_sessions_query({"source": "tm_index"}, T0)


# --- review N1: the incident read limit follows the store --------------------------------


async def test_more_active_incidents_than_the_cap_are_read_whole(fleet) -> None:  # noqa: F811
    intel = ak1(fleet)
    base = next(i for i in intel.machine.peek() if i.type == "router_unreachable")
    for n in range(MAX_INCIDENTS + 5):  # active ones are never pruned
        extra = dataclasses.replace(
            base,
            id=f"inc-n1-{n}",
            scope_key=f"n1-{n}",
            status=IncidentStatus.ACTIVE,
            first_seen=NI_T0 - 50_000,
            resolved_at=None,
            reopened_at=None,
        )
        intel.machine._incidents[extra.id] = extra
    assert len(intel.machine.peek()) > tm_sources.NI_INCIDENTS_READ_LIMIT
    result = await read(
        intel.hass, "ni_incidents", request(NI_T0 - 10, NI_T0 + 700), NI_ROUTERS
    )
    assert result.state == "ok" and result.truncated is False
    assert result.unreachable is False
    kinds = [
        m["kind"] for m in result.marks if m["title_key"].endswith("router_unreachable")
    ]
    assert kinds == ["incident_resolved", "incident_opened"]
