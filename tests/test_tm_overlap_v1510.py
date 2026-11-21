"""Network Time Machine 1.51.0: intervals that reach into the window.

An interval of the own index (outage, client session, …) belongs to the
timeline window when it overlaps it, not only when it begins in it (the
sessions route did that already). Rule after the review before the merge
(S4, ``tm_query`` module doc): such a mark ``spans_in``; it never stands in
``marks`` and never counts against ``limit``; the server answers it only
with ``spans=1``, in ``spanning`` (newest start first, at most
``SPANNING_MAX``, ``spanning_truncated``), the same on every page that asks
for it. The panel asks on the first page only. Marks come through the real
write paths (``tm_index_kit``: the real outage tracker, the engine's
listeners; Phase C through the real Client Stability of
``test_tm_clients_v1510``).

Also here: what switching the Time Machine off deletes and keeps.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import dataclasses
from typing import Any
from unittest.mock import patch

import pytest
from core_testkit import FakeDisks
from test_client_engine import M1, disk  # noqa: F401
from test_tm_clients_v1510 import clients_world, step
from tm_index_kit import RID, T0, world

from custom_components.openwrt_router import tm_query, tm_sources
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_ENGINE,
    OPTION_TIME_MACHINE_ENABLED,
)
from custom_components.openwrt_router.tm_engine import (
    async_apply_time_machine_options,
    async_get_time_machine,
)
from custom_components.openwrt_router.tm_store import TimeMachineStore

R1, R2, R3 = RID["r1"], RID["r2"], RID["r3"]
HOUR = 3600.0


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def query(since: float, until: float, **kw: Any) -> tm_query.Query:
    return tm_query.Query(since, until, sources=tm_sources.INDEX_SOURCE_IDS, **kw)


async def walk(
    hass: Any, q: tm_query.Query, *, admin: bool = True, now: float, pages: int = 50
) -> list[dict[str, Any]]:
    """Every page of one window like the tab: ``spans=1`` on the first page
    only, then ``cursor = next_cursor`` with the same window."""
    out = []
    q = dataclasses.replace(q, spans=True)
    for _ in range(pages):
        body = await tm_query.async_timeline(hass, q, admin=admin, now=now)
        out.append(body)
        if body["next_cursor"] is None:
            return out
        q = dataclasses.replace(
            q, cursor=tm_query._cursor(body["next_cursor"]), spans=False
        )
    raise AssertionError("the walk does not end")


def spans(body: dict[str, Any]) -> list[dict[str, Any]]:
    assert not [m for m in body["marks"] if m["spans_in"]], "spanning in marks"
    return body["spanning"]


# --- overlap ------------------------------------------------------------------------------


async def test_an_open_outage_that_began_before_the_window_is_shown(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.down("r1")  # at T0, still open
        w.clock.advance(2 * HOUR)
        now = w.clock.t
        window = (T0 + HOUR, now + 1)
        body = await tm_query.async_timeline(
            w.hass, query(*window, spans=True), admin=True, now=now
        )
        plain = await tm_query.async_timeline(
            w.hass, query(*window), admin=True, now=now
        )
        user = await tm_query.async_timeline(
            w.hass, query(*window, spans=True), admin=False, now=now
        )
        other = await tm_query.async_timeline(
            w.hass, query(*window, router_id=R2, spans=True), admin=True, now=now
        )
    [down] = spans(body)
    assert (down["kind"], down["ts"], down["end"], down["end_state"]) == (
        "router_down",
        T0,
        None,
        "open",
    )
    assert down["spans_in"] is True and down["router_id"] == R1
    assert body["marks"] == [] and body["next_until"] is None
    assert body["spanning_truncated"] is False
    # without spans=1: never
    assert plain["marks"] == [] and plain["spanning"] == []
    # infrastructure: a non-admin sees it as well; filters apply as to every mark
    assert [m["id"] for m in spans(user)] == [down["id"]]
    assert spans(other) == []
    src = {s["id"]: s for s in body["sources"]}["tm_index"]
    assert (src["state"], src["count"], src["oldest"]) == ("ok", 0, None)


async def test_a_closed_outage_counts_while_it_overlaps_the_window(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.down("r1")
        w.clock.advance(1800)
        w.up("r1")
        w.coords["r1"].poll()  # closes the outage at T0 + 1800
        w.clock.advance(2 * HOUR)
        now = w.clock.t
        inside = await tm_query.async_timeline(
            w.hass, query(T0 + 600, now, spans=True), admin=True, now=now
        )
        at_end = await tm_query.async_timeline(
            w.hass, query(T0 + 1800, now, spans=True), admin=True, now=now
        )
        after = await tm_query.async_timeline(
            w.hass, query(T0 + 1800.001, now, spans=True), admin=True, now=now
        )
    [down] = spans(inside)
    assert (down["kind"], down["end_state"], down["end"]) == (
        "router_down",
        "closed",
        pytest.approx(T0 + 1800),
    )
    # the up mark at the end is an ordinary mark of the window
    assert [m["kind"] for m in inside["marks"]] == ["router_up"]
    assert [m["kind"] for m in spans(at_end)] == ["router_down"]  # ends at from
    assert spans(after) == []  # ended before the window


async def test_paging_shows_each_spanning_mark_once_on_the_first_page(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        w.down("r1")  # T0, open: spans into the window
        w.clock.advance(600)
        w.down("r3")  # T0 + 600, closed inside the window: spans in as well
        w.clock.advance(HOUR)
        w.up("r3")
        w.coords["r3"].poll()
        since = w.clock.t
        for _ in range(4):  # four outages of r2 inside the window
            w.clock.advance(300)
            w.down("r2")
            w.clock.advance(300)
            w.up("r2")
            w.coords["r2"].poll()
        now = w.clock.t + 1
        pages = await walk(w.hass, query(since - 1, now, limit=3), now=now)
        whole = await tm_query.async_timeline(
            w.hass, query(since - 1, now), admin=True, now=now
        )
    assert len(pages) > 2
    ids = [m["id"] for p in pages for m in p["marks"]]
    assert len(ids) == len(set(ids)), "a mark came twice"
    assert set(ids) == {m["id"] for m in whole["marks"]}
    # only the first page carries them (the walk asks there only)
    assert [m["router_id"] for m in spans(pages[0])] == [R3, R1]
    assert all(spans(p) == [] for p in pages[1:])
    assert pages[-1]["next_cursor"] is None


def test_a_cut_source_never_holds_back_the_spanning_marks() -> None:
    routers = tm_sources.RouterMap({}, {R1: "Router 1"})
    since, until = T0, T0 + HOUR

    def mark(source: str, sid: str, ts: float, **kw: Any) -> dict[str, Any]:
        m = tm_sources.make_mark(
            source=source, source_id=sid, ts=ts, kind=kw.pop("kind", "router_down"),
            severity="warning", router_id=R1, routers=routers, fleet=False,
            code="timeout", ref=tm_sources.ref_of("time_machine", "mark", sid),
        )  # fmt: skip
        m.update(kw)
        return m

    span = mark("tm_index", "m1", T0 - 600, end_state="open", spans_in=True)
    newer = mark("ni_events", "e2", T0 + 2400, kind="wan_event")
    edge = mark("ni_events", "e1", T0 + 1800, kind="wan_event")
    # the read of ni_events was cut: complete only down to its oldest read entry
    ni = tm_sources.SourceResult(
        "ni_events", "ok", marks=[newer, edge], truncated=True,
        edge=T0 + 1800, oldest=T0 + 1800,
    )  # fmt: skip
    index = tm_sources.SourceResult("tm_index", "ok", spanning=[span])
    first = tm_query.merge(
        [index, ni], tm_query.Query(since, until, spans=True), admin=True, now=until
    )
    assert [m["id"] for m in first["marks"]] == [newer["id"]]
    assert [m["id"] for m in first["spanning"]] == [span["id"]]
    assert first["next_until"] == tm_sources.ms_next(T0 + 1800)
    assert first["next_cursor"] == tm_query.cursor_of(tm_sources.ms_next(T0 + 1800))


async def test_more_spanning_marks_than_the_cap_are_flagged(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        for entry in ("r1", "r2"):
            w.down(entry)
            w.clock.advance(60)
        w.clock.advance(HOUR)
        now = w.clock.t
        with patch.object(tm_query, "SPANNING_MAX", 1):
            [page] = await walk(w.hass, query(now - 60, now, limit=1), now=now)
    # not on ``limit``: the window is empty, one of two spanning marks shown
    assert page["marks"] == [] and page["truncated"] is False
    assert [m["router_id"] for m in page["spanning"]] == [R2]
    assert page["spanning_truncated"] is True


async def test_a_client_session_that_began_before_the_window_spans_in(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        start = w.marks("client_session")[0].ts
        for _ in range(60):  # an hour later, still connected
            step(w, [M1], [])
        body = await tm_query.async_timeline(
            w.hass, query(w.t - 600, w.t, spans=True), admin=True, now=w.t
        )
        user = await tm_query.async_timeline(
            w.hass, query(w.t - 600, w.t, spans=True), admin=False, now=w.t
        )
    [session] = [m for m in spans(body) if m["kind"] == "client_session"]
    assert session["spans_in"] is True and session["end_state"] == "open"
    assert session["ts"] == pytest.approx(start)
    assert not [m for m in spans(user) if m["group"] == "clients"]


# --- switching off ---------------------------------------------------------------------


async def test_switching_off_deletes_the_clients_and_keeps_the_infrastructure(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        w.down("r2")
        old_clients = {m.seq for m in w.engine.index if m.client is not None}
        assert old_clients
        await async_apply_time_machine_options(w.hass, on=False, clients=True)
        assert async_get_time_machine(w.hass) is None
        rows = w.stored["marks"]
        kinds = [r.split("|")[2] for r in rows]
        # written at once: no client mark is left, the infrastructure stays
        assert not [k for k in kinds if k.startswith("client_")]
        assert "router_down" in kinds and "tm_disabled" in kinds
        down = next(r for r in rows if r.split("|")[2] == "router_down")
        assert down.split("|")[7] == "u"  # the open outage ended unknown
        assert w.stored["stop"] == "disabled"
        # switched on again: the infrastructure history is there
        for entry in w.entries:
            entry.options[OPTION_TIME_MACHINE_ENABLED] = True
        engine = await w.start(clients=True)
        assert [m.kind for m in engine.index if m.kind == "router_down"]
        # the old client history is gone; a client still connected starts anew
        again = [m for m in engine.index if m.client is not None]
        assert not {m.seq for m in again} & old_clients
        assert all(m.derived and m.params.get("resumed") == 1 for m in again)


async def test_switching_off_without_a_running_engine_deletes_the_clients(
    disks, disk
) -> None:
    # A store with client marks while no engine runs (e.g. every router
    # unloaded); the Time Machine is switched off with the client switch
    # still on: the client marks go, the rest stays.
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1], [])
        w.down("r2")
        await w.engine.async_stop("unloaded")
        w.hass.data.pop(DATA_TIME_MACHINE_ENGINE, None)
        assert any("|client_session|" in r for r in w.stored["marks"])
        await async_apply_time_machine_options(w.hass, on=False, clients=True)
        rows = w.stored["marks"]
        assert not any("|client_" in r for r in rows)
        assert any("|router_down|" in r for r in rows)


async def test_nothing_is_trimmed_while_the_time_machine_is_off(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.down("r1")
        await w.engine.async_stop("disabled")
        before = list(w.stored["marks"])
        w.clock.advance(30 * 86_400)  # far past the 14 days of retention
        store = TimeMachineStore(w.hass)
        loaded = await store.async_load()
        assert not loaded.failed
        assert list(w.stored["marks"]) == before  # no engine, no trimming
        assert len(list(store.index)) == len(before)
