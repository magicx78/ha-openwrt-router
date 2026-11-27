"""1.52.2: what the views "Zustand" and "Vergleich" of the tab "Zeitreise"
get from the server for the same moment, and a disabled router.

Found after 1.52.1 (the "Nachher" column of a comparison said "unbekannt"
where "Zustand" showed a value for the same moment):

* ``/compare`` builds its ``before`` and ``after`` blocks with the same
  ``state_body`` as ``/state``; the ``after`` block is ``/state`` at ``t2``.
  The panel now takes each cell of the comparison from these blocks (with
  the views of "Zustand"); ``changes`` keeps its meaning (``unknown`` when a
  side is unknown, never counted as a change) and adds, strictly additive,
  the reason of each side (``from_reason`` / ``to_reason``) to
  ``reachable``, ``role`` and ``uplink``.
* The scenario of the diagnosis: a 1.51.0 store file (its time is known, no
  router was followed: ``not_observed``), the update, polls, an HA restart
  and polls again; ``t1`` in the 1.51.0 time, ``t2`` now. With and without
  the restart.
* A config entry the user disabled keeps its router id in the registry and
  appears in the answers; it is never set up, so every value is unknown.
  Each router of ``/state`` and of the ``before`` / ``after`` blocks of
  ``/compare`` now says ``entry``: ``"enabled"``, ``"disabled"`` (the entry's
  ``disabled_by`` is set) or null (no config entry, only history). The
  rest of the answer is unchanged: an older panel reads it as before.

``tmFixtureCompare.json`` (frontend tests) holds the answers of this world;
it is not written by hand. Regenerate after a deliberate change::

    TM_WRITE_FIXTURE=1 python -m pytest tests/test_tm_compare_display_v1522.py
"""

# ruff: noqa: F811  (pytest fixtures imported from test_tm_state_v1520)
from __future__ import annotations

import contextlib
import json
import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
from test_tm_state_v1520 import FIXTURE, Run, disks  # noqa: F401 - fixture
from tm_index_kit import RID, SECRETS, world

from custom_components.openwrt_router import tm_sources, tm_state
from custom_components.openwrt_router.net_rules import Topology, Uplink

R1, R2, R3 = RID["r1"], RID["r2"], RID["r3"]
VALUES = ("reachable", "role", "uplink", "radios")
# the keys of a router in /state before 1.52.2 (an older panel reads these)
KEYS_1521 = {
    "router_id",
    "router_name",
    "reachable",
    "role",
    "uplink",
    "radios",
    "traffic",
    "utilization",
}
FIXTURE_COMPARE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/timemachine"
    / "tmFixtureCompare.json"
)


def _by_id(block: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {r["router_id"]: r for r in block["routers"]}


async def _start(w: Any, set_up: list[str]) -> None:
    """Start the engine with only the entries HA sets up (not the disabled)."""
    real = w.entries
    w.entries = [e for e in real if e.entry_id in set_up]
    await w.start()
    w.entries = real


async def _ask(w: Any, t1: float, t2: float) -> tuple[dict, dict]:
    now = w.clock.t
    state = await tm_state.async_state(
        w.hass, tm_state.StateQuery(t2), admin=True, now=now
    )
    cmp = await tm_state.async_compare(
        w.hass, tm_state.CompareQuery(t1, t2), admin=True, now=now
    )
    return state, cmp


@contextlib.asynccontextmanager
async def after_update(disks: Any, *, restart: bool) -> AsyncIterator[Any]:
    """The diagnosis: a 1.51.0 file, the update, polls (and a restart)."""
    old = json.loads(FIXTURE.read_text())
    with world(disks, routers=3) as w:
        yield await _prepare(w, old, restart=restart)


async def _prepare(w: Any, old: dict[str, Any], *, restart: bool) -> Any:
    for e in w.entries:
        e.options["time_machine_enabled"] = True
        e.disabled_by = None
    w.entries[2].disabled_by = "user"  # never set up
    w.coords.pop("r3")
    w.disk.data = json.loads(json.dumps(old))
    w.clock.t = old["data"]["saved_at"] + 600
    await _start(w, ["r1", "r2"])
    # r1 the gateway, r2 behind it: a known uplink of null and one of r1
    w.topology = Topology(uplinks={"r2": Uplink("r1")}, gateways=frozenset({"r1"}))
    run = Run(w)
    del run.radios["r3"]
    run.polls(30)
    if restart:
        await w.ha_stop_and_write()
        w.clock.advance(120)
        await _start(w, ["r1", "r2"])
    run.polls(20)
    w.run = run
    w.t_old = old["data"]["saved_at"] - 60  # 1.51.0 time: known, no router followed
    return w


@pytest.mark.parametrize("restart", [True, False])
async def test_the_after_block_of_compare_is_the_state_at_the_same_moment(
    disks, restart: bool
) -> None:
    async with after_update(disks, restart=restart) as w:
        t2 = w.clock.t - 1
        state, cmp = await _ask(w, w.t_old, t2)
        assert state["known"] and cmp["before"]["known"] and cmp["after"]["known"]
        # the same moment, the same answer: every router, every value
        st, after, before = _by_id(state), _by_id(cmp["after"]), _by_id(cmp["before"])
        assert set(st) == set(after) == set(before) == {R1, R2, R3}
        for rid in (R1, R2, R3):
            assert st[rid] == after[rid], rid
        # what the panel shows in "Nachher": the known values of "Zustand"
        assert (after[R1]["uplink"]["value"], after[R1]["uplink"]["reason"]) == (
            None,
            None,
        )  # known: no router before it
        assert after[R2]["uplink"]["value"]["router_id"] == R1
        for rid in (R1, R2):
            assert after[rid]["radios"]["state"] == "ok"
            assert [i["channel"] for i in after[rid]["radios"]["items"]] == [36]
            # and "Vorher" is unknown with its own reason
            for name in VALUES:
                assert before[rid][name]["reason"] == "not_observed", (rid, name)
        # the differences stay unknown (never a change) and now name each side's reason
        ch = {c["router_id"]: c for c in cmp["changes"]["routers"]}
        for rid in (R1, R2):
            for name in ("reachable", "role", "uplink"):
                d = ch[rid][name]
                assert d["state"] == "unknown", (rid, name)
                assert (d["from_reason"], d["to_reason"]) == ("not_observed", None)
            assert ch[rid]["uplink"]["to"] == after[rid]["uplink"]["value"]
            assert ch[rid]["radios"][0]["state"] == "unknown"


async def test_a_disabled_entry_is_marked_in_state_and_compare(disks) -> None:
    async with after_update(disks, restart=False) as w:
        now = w.clock.t
        state, cmp = await _ask(w, now - 600, now - 1)
        st = _by_id(state)
        # one disabled entry among three: marked, its values unknown (never set up)
        assert {rid: st[rid]["entry"] for rid in st} == {
            R1: "enabled",
            R2: "enabled",
            R3: "disabled",
        }
        assert all(st[R3][name]["reason"] == "not_observed" for name in VALUES)
        # additive: everything an older panel reads is unchanged
        assert set(st[R3]) == KEYS_1521 | {"entry"}
        for side in ("before", "after"):
            assert _by_id(cmp[side])[R3]["entry"] == "disabled", side
            assert _by_id(cmp[side])[R1]["entry"] == "enabled", side
        # the comparison: unknown on both sides, never counted as a change
        c3 = next(c for c in cmp["changes"]["routers"] if c["router_id"] == R3)
        assert {c3[k]["state"] for k in ("reachable", "role", "uplink")} == {"unknown"}
        assert [x["state"] for x in c3["radios"]] == ["unknown"]
        assert (c3["uplink"]["from_reason"], c3["uplink"]["to_reason"]) == (
            "not_observed",
            "not_observed",
        )
        # the two enabled routers are the same at both moments
        assert R1 not in {c["router_id"] for c in cmp["changes"]["routers"]}


async def test_a_router_disabled_later_keeps_its_history(disks) -> None:
    async with after_update(disks, restart=False) as w:
        known = w.clock.t - 1
        # more than TOPOLOGY_SETTLE_S later (the end of a section settles
        # the uplink and the role before it) ...
        w.run.polls(20)
        # ... the user disables r2: HA unloads it (the engine stops following it)
        w.engine.remove_entry("r2")
        w.entries[1].disabled_by = "user"
        w.coords.pop("r2")
        del w.run.radios["r2"]
        w.run.polls(5)
        now = w.clock.t
        state, cmp = await _ask(w, known, now - 1)
        before, after = _by_id(cmp["before"]), _by_id(cmp["after"])
        # "entry" is the entry now (the same in both blocks); the history stays
        assert before[R2]["entry"] == after[R2]["entry"] == "disabled"
        assert before[R2]["reachable"] == {
            "value": True,
            "derived": True,
            "reason": None,
        }
        assert before[R2]["uplink"]["value"]["router_id"] == R1
        assert all(after[R2][name]["reason"] is not None for name in VALUES)
        assert _by_id(state)[R2] == after[R2]


def test_router_map_reads_disabled_by_and_stays_equal_without_it() -> None:
    plain = tm_sources.RouterMap({"e1": R1}, {R1: "Router 1"})
    assert plain.entry_of(R1) == tm_sources.ENTRY_ENABLED
    assert plain.entry_of(R2) is None  # no config entry: only history
    off = tm_sources.RouterMap({"e1": R1}, {R1: None}, frozenset({R1}))
    assert off.entry_of(R1) == tm_sources.ENTRY_DISABLED
    assert tm_sources.RouterMap() == tm_sources.RouterMap()
    assert {tm_sources.ENTRY_ENABLED, tm_sources.ENTRY_DISABLED} == {
        "enabled",
        "disabled",
    }


async def test_the_compare_fixture_is_the_real_answer(disks) -> None:
    """``tmFixtureCompare.json``: the answers the frontend tests read."""
    out: dict[str, Any] = {}
    async with after_update(disks, restart=True) as w:
        t_known = w.clock.t - 1
        state, cmp = await _ask(w, w.t_old, t_known)
        out["state_after_update"] = state
        # before unknown (not_observed), after known
        out["compare_after_update"] = cmp
        # the mirror: before known, after unknown (r2 down; more than
        # TOPOLOGY_SETTLE_S after t_known, so its uplink there is settled)
        w.run.polls(20)
        w.down("r2")
        w.run.failing.add("r2")
        w.run.polls(5)
        _state, mirror = await _ask(w, t_known, w.clock.t - 1)
        out["compare_router_down"] = mirror
        # r2 disabled later: known history before, unknown and disabled now
        w.run.failing.discard("r2")
        w.engine.remove_entry("r2")
        w.entries[1].disabled_by = "user"
        w.coords.pop("r2")
        del w.run.radios["r2"]
        w.run.polls(30)
        state, cmp = await _ask(w, t_known, w.clock.t - 1)
        out["state_disabled"] = state
        out["compare_disabled"] = cmp
        # the same moments in a later comparison: both sides after the disable
        _s, cmp2 = await _ask(w, w.clock.t - 600, w.clock.t - 1)
        out["compare_disabled_both"] = cmp2
    # the scenarios the frontend tests rely on
    st = _by_id(out["state_disabled"])
    assert st[R3]["entry"] == "disabled" and st[R2]["entry"] == "disabled"
    assert all(st[R2][name]["reason"] for name in VALUES)
    disabled = out["compare_disabled"]
    assert _by_id(disabled["before"])[R2]["reachable"]["value"] is True
    both = out["compare_disabled_both"]
    for rid in (R2, R3):
        for side in ("before", "after"):
            assert all(_by_id(both[side])[rid][n]["reason"] for n in VALUES)
    up = _by_id(out["compare_router_down"]["before"])[R2]
    assert up["uplink"]["value"]["router_id"] == R1
    assert up["radios"]["state"] == "ok"
    down = _by_id(out["compare_router_down"]["after"])[R2]
    assert down["reachable"]["value"] is False
    assert down["uplink"]["reason"] == "router_down"
    assert down["radios"]["state"] == "unknown"
    text = json.dumps(out, indent=1, ensure_ascii=False) + "\n"
    for needle in SECRETS:
        assert needle not in text, needle
    if os.environ.get("TM_WRITE_FIXTURE") == "1":
        FIXTURE_COMPARE.write_text(text, encoding="utf-8")
    assert FIXTURE_COMPARE.read_text(encoding="utf-8") == text, (
        "tmFixtureCompare.json differs from the answers; regenerate it with "
        "TM_WRITE_FIXTURE=1 (see the module docstring)"
    )
