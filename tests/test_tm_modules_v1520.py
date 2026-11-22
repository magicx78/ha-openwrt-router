"""Network Time Machine 1.52.0: clients across modules, jump targets,
leftovers of 1.51.0, no router call and the cost on a full store.

Phase E through the real enterprise core and the real Security Center of
``test_tm_views.full_env``: a module writes an audit entry with its own
``client_ref``; the Time Machine attributes it with the module's own
"pseudonym for MAC" function to the MACs its client recorder knows (the
real recorder on the real Client Stability), never by comparing ``cli_…``
values of two modules.
"""

# ruff: noqa: F811  (pytest fixtures imported from other test modules)
from __future__ import annotations

import ast
import asyncio
import copy
import json
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import full_router_kit as kit
import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from rf_center_kit import KEY as RF_KEY
from rf_center_kit import MAC_A, RID1, measured_center, rf_disk
from test_client_engine import M1, M2, client, data, disk  # noqa: F401
from test_tm_clients_v1510 import clients_world, step
from test_tm_query_v1510 import _mark
from test_tm_views import close, full_env
from test_traffic_engine import (
    _reset_pending,  # noqa: F401 - autouse fixture
    enabled,
    start,
    two_polls,
)
from tm_index_kit import RID, T0, world

from custom_components.openwrt_router import (
    net_engine,
    tm_query,
    tm_sources,
    tm_state,
    traffic_correlate,
)
from custom_components.openwrt_router.client_engine import async_get_client_stability
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.security_model import EVENT_PREFIX, MODULE_SOURCE
from custom_components.openwrt_router.tm_export import async_export
from custom_components.openwrt_router.tm_sources import (
    JUMP_TARGETS,
    KIND_GROUP,
    KIND_NO_TAB,
    KIND_TABS,
    SourceResult,
    jump_target,
)
from custom_components.openwrt_router.traffic_correlate import TrafficReadApi
from custom_components.openwrt_router.traffic_engine import async_get_traffic_engine

R1 = RID["r1"]
PACKAGE = Path(tm_sources.__file__).parent


@pytest.fixture
def core_disks():
    with FakeDisks().patch() as fake:
        yield fake


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# --- Phase E: one client across modules ---------------------------------------------


async def _clients_env(core_disks: Any, tmp_path: Any) -> Any:
    world_ = await full_env(core_disks, tmp_path)
    env = world_.env
    await async_get_client_stability(env.hass, world_.engine)
    await world_.tm.async_set_clients(True)
    assert world_.tm.recorder is not None and world_.tm.recorder.attached
    t = env.clock.utc().timestamp()
    for i in range(3):
        world_.engine.ingest("e1", data([client(M1)]), t + 60 * i, interval=60.0)
    world_.now = t + 600
    return world_


def _traffic_api(key: bytes) -> TrafficReadApi:
    """The real read API over an engine that only holds its module key."""
    return TrafficReadApi(SimpleNamespace(active=True, _module_key=key))


async def test_two_modules_same_mac_different_pseudonyms_one_client(
    core_disks, tmp_path
) -> None:
    world_ = await _clients_env(core_disks, tmp_path)
    env, center, tm = world_.env, world_.center, world_.tm
    traffic = _traffic_api(b"t" * 32)
    sec_ref = center.client_ref_for_mac(M1)
    traffic_ref = traffic.client_ref_for_mac(M1)
    assert sec_ref and traffic_ref and sec_ref != traffic_ref  # own keys
    unknown_ref = center.client_ref_for_mac(M2)  # M2 never seen by the recorder
    env.core.audit.register_event_prefix(
        "traffic_analytics.", module="traffic_analytics"
    )
    now = env.clock.utc()
    for event_type, source, ref in (
        (f"{EVENT_PREFIX}tm_test", MODULE_SOURCE, sec_ref),
        ("traffic_analytics.tm_test", "traffic_analytics", traffic_ref),
        # the Security Center's pseudonym written by another module: no match
        ("traffic_analytics.tm_cross", "traffic_analytics", sec_ref),
        (f"{EVENT_PREFIX}tm_other", MODULE_SOURCE, unknown_ref),
    ):
        env.core.audit.emit(event_type, source=source, client_ref=ref, now=now)
    [(hexed, mac)] = tm.recorder._macs.items()
    assert mac == M1
    with patch.object(
        traffic_correlate, "async_get_traffic_read_api", lambda _h: traffic
    ):
        query = tm_query.Query(
            world_.start - 3600, world_.now + 60, sources=("core_audit",)
        )
        body = await tm_query.async_timeline(
            env.hass, query, admin=True, now=world_.now
        )
        found = {
            m["title_key"]: m["client"]
            for m in body["marks"]
            if m["title_key"].endswith(("tm_test", "tm_cross", "tm_other"))
        }
        assert found == {
            "core_audit.security_center.tm_test": f"tmc_{hexed}",
            "core_audit.traffic_analytics.tm_test": f"tmc_{hexed}",
        }
        assert body["omitted_client_marks"] >= 2  # cross + unknown: left out
        text = json.dumps(body)
        assert "cli_" not in text and M1 not in text
        # the client filter (admins) finds both, a non-admin may not send it
        one = tm_query.Query(
            query.since, query.until, sources=("core_audit",), client=f"tmc_{hexed}"
        )
        mine = await tm_query.async_timeline(env.hass, one, admin=True, now=world_.now)
        assert len(mine["marks"]) == 2
        user = await tm_query.async_timeline(
            env.hass, query, admin=False, now=world_.now
        )
        assert not [m for m in user["marks"] if m.get("client")]
        # forgotten: no longer attributed (nothing cached)
        tm.recorder.forget_client(hexed)
        again = await tm_query.async_timeline(
            env.hass, query, admin=True, now=world_.now
        )
        assert not [m for m in again["marks"] if m.get("client")]
    await close(world_)


def test_resolver_ambiguous_and_failing_modules() -> None:
    recorder = SimpleNamespace(
        _macs={"a" * 16: M1, "b" * 16: M2}, name_of=lambda _h: None, attached=True
    )
    funcs = {
        "security_center": lambda mac: "cli_same",  # two MACs, one value
        "traffic_analytics": MagicMock(side_effect=RuntimeError("boom")),
        "wifi_rf": lambda mac: None,
    }
    with patch.object(tm_sources, "module_pseudonym", lambda _h, m: funcs.get(m)):
        resolver = tm_sources.ClientResolver(MagicMock(), recorder)
        assert resolver.resolve("security_center", "cli_same") is None
        assert resolver.resolve("traffic_analytics", "cli_x") is None
        assert resolver.resolve("wifi_rf", "cli_x") is None
        assert resolver.resolve("net_diagnostics", "cli_x") is None


# --- foreign read functions change nothing ------------------------------------------


async def test_rf_window_at_and_pseudonym_change_nothing(disk) -> None:
    runs = []
    for call in (False, True):
        with rf_disk():
            center, reader = await measured_center()
            if call:
                for _ in range(3):
                    center.window_at(RID1, T0 - 86_400, T0 + 86_400)
                    center.client_ref_for_mac(MAC_A)
            runs.append(
                (
                    copy.deepcopy(center.diagnostics()),
                    center.radio_utilization(RID1, 3600),
                    center.client_retry_rates(RID1, 3600),
                    reader.calls,
                )
            )
    assert runs[0] == runs[1]
    center, reader = await measured_center()
    hour = center.window_at(RID1, center.clock() - 4 * 3600, center.clock() + 3600)
    assert [v["series"] for v in hour.values()] == ["utilization"]
    [radio] = hour.values()
    assert radio["mean"] == pytest.approx(80.0) and radio["state"] == "measured"
    assert "phy1-ap0" not in json.dumps(hour)
    assert reader.calls == []  # read only
    from custom_components.openwrt_router.rf_privacy import client_ref

    assert center.client_ref_for_mac(MAC_A) == client_ref(MAC_A, RF_KEY)
    assert center.window_at(RID1, 1.0, 1.0) == {}
    assert center.window_at("x", 0.0, 10.0) == {}


async def test_traffic_window_at_and_pseudonym_change_nothing(disks) -> None:
    from core_testkit import make_hass

    runs = []
    for call in (False, True):
        hass = make_hass()
        enabled(disks)
        engine, coord = await start(hass)
        await two_polls(engine, coord, hass)
        api = traffic_correlate.TrafficReadApi(engine)
        [wan] = [p for p in api.points() if p["scope"] == "wan"]
        wall = engine.wall()
        if call:
            for _ in range(3):
                api.window_at(wan["point_id"], wall - 3600, wall + 3600)
                api.client_ref_for_mac(M1)
        await two_polls(engine, coord, hass)
        runs.append(
            (
                api.status(),
                api.points(),
                api.latest(wan["router_id"]),
                api.window(wan["point_id"], "1h"),
                len(engine.book),
            )
        )
        await engine.async_stop() if hasattr(engine, "async_stop") else None
        assert async_get_traffic_engine(hass) is engine
    assert runs[0] == runs[1]
    got = api.window_at(wan["point_id"], engine.wall() - 3600, engine.wall() + 60)
    assert got["state"] in ("available", "unavailable") and got["resolution_s"] == 3600
    assert api.window_at(wan["point_id"], 1.0, 1.0)["reason"] == "unknown_window"
    assert api.window_at("nope", 0.0, 60.0)["reason"] == "unknown_point"


# --- Phase F: every ref has a target or explicitly none --------------------------------


def _ref_literals() -> set[tuple[str, str]]:
    """Every ``ref_of("<module>", "<type>" | a if c else b)`` in the package."""
    found: set[tuple[str, str]] = set()
    for path in PACKAGE.glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "ref_of"
            ):
                continue
            module, kind = node.args[0], node.args[1]
            assert isinstance(module, ast.Constant), (path.name, node.lineno)
            options = (
                [kind.body, kind.orelse] if isinstance(kind, ast.IfExp) else [kind]
            )
            for option in options:
                assert isinstance(option, ast.Constant), (path.name, node.lineno)
                found.add((module.value, option.value))
    return found


def test_every_ref_the_backend_makes_has_a_target_or_explicitly_none() -> None:
    literals = _ref_literals()
    assert ("time_machine", "mark") in literals and len(literals) >= 9
    assert literals <= set(JUMP_TARGETS), literals - set(JUMP_TARGETS)
    # audit entries: by their kind; every kind an audit type can get
    audit_kinds = {kind for _prefix, kind in tm_sources._MODULE_KINDS}
    audit_kinds |= {"config_drift", "audit_event"}
    assert audit_kinds <= set(KIND_TABS) | KIND_NO_TAB
    assert not set(KIND_TABS) & KIND_NO_TAB
    assert set(KIND_TABS) | KIND_NO_TAB <= set(KIND_GROUP)
    for kind in audit_kinds:
        ref = tm_sources.ref_of("core_audit", "event", "evt_" + "0" * 32)
        target = jump_target(ref, kind)
        assert (target is None) == (kind in KIND_NO_TAB), kind
    version = jump_target(tm_sources.ref_of("config_manager", "version", None, "bk_1"))
    assert version is not None and version["tab"] == "config"
    assert jump_target(tm_sources.ref_of("network_intelligence", "incident")) is None
    assert jump_target({"module": "x", "type": "y"}) is None
    assert jump_target(None) is None


# --- leftovers of 1.51.0 -------------------------------------------------------------


def test_min_severity_never_drops_both_entries_of_one_event() -> None:
    """The own mark is a reason to drop the NI double only when it passes the
    rights and filters of the query (leftover 1 of 1.51.0)."""
    own = _mark("tm_index", "router_down", T0 + 50)
    own.update(end=T0 + 1000, end_state="closed", severity="warning")

    def results() -> list[SourceResult]:
        ni = _mark("ni_events", "router_down", T0 + 100)
        ni["severity"] = "critical"
        return [
            SourceResult("ni_events", "ok", marks=[ni]),
            SourceResult("tm_index", "ok", marks=[dict(own)]),
        ]

    window = (T0, T0 + 3000)
    sources = ("ni_events", "tm_index")
    plain = tm_query.merge(
        results(), tm_query.Query(*window, sources=sources), admin=True, now=T0 + 3000
    )
    assert [m["source"] for m in plain["marks"]] == ["tm_index"]
    critical = tm_query.Query(*window, sources=sources, min_severity="critical")
    body = tm_query.merge(results(), critical, admin=True, now=T0 + 3000)
    assert [m["source"] for m in body["marks"]] == ["ni_events"]
    by_id = {s["id"]: s for s in body["sources"]}
    assert by_id["ni_events"]["duplicates"] == 0


async def test_the_double_rule_with_a_real_ni_event(disks, disk) -> None:
    """Leftover 2 of 1.51.0: the real NI writes ``router_unreachable`` from
    the same fleet tracker the Time Machine reads; the timeline shows the
    outage once (the own interval) and counts the NI events as doubles."""
    async with clients_world(disks, disk) as w:
        clock = SimpleNamespace(time=w.clock, monotonic=time.monotonic)
        w.stack.enter_context(patch.object(net_engine, "time", clock))
        w.stack.enter_context(
            patch.object(net_engine, "async_get_engine", lambda _h: w.ni)
        )
        for _ in range(3):
            step(w, [M1], [M2])
        w.down("r1")
        for _ in range(5):
            step(w, None, [M2])
        w.up("r1")
        for _ in range(3):
            step(w, [M1], [M2])
        kinds = [e.kind for e in w.ni.ring]
        assert (
            "system.router_unreachable" in kinds and "system.router_reachable" in kinds
        )
        sources = ("ni_events", "tm_index")
        query = tm_query.Query(T0 - 60, w.t + 60, sources=sources)
        body = await tm_query.async_timeline(w.hass, query, admin=True, now=w.t)
        by_id = {s["id"]: s for s in body["sources"]}
        assert by_id["ni_events"]["duplicates"] == 2
        outages = [
            m for m in body["marks"] if m["kind"] in ("router_down", "router_up")
        ]
        assert {m["source"] for m in outages} == {"tm_index"} and len(outages) == 2
        # an own mark filtered away by the kind: the NI event stays
        only_up = tm_query.Query(T0 - 60, w.t + 60, sources=sources, kind="router_up")
        body = await tm_query.async_timeline(w.hass, only_up, admin=True, now=w.t)
        assert [m["source"] for m in body["marks"]] == ["tm_index"]


# --- no router call ------------------------------------------------------------------


async def test_queries_between_two_polls_make_no_router_call(disks, disk) -> None:
    """Hard requirements 1 and 2: the call list of two polls with everything
    on (and state, compare and export read between them) equals the list
    with everything off."""
    off_calls: list[Any] = []
    off = kit.make_coordinator(MagicMock(), kit.make_api(off_calls))
    await kit.full_polls(off, on_poll=lambda d, n: None)
    async with clients_world(disks, disk) as w:
        on_calls: list[Any] = []
        coordinator = kit.make_coordinator(w.hass, kit.make_api(on_calls))
        w.engine.add_entry("r1", coordinator)
        reads: list[Any] = []

        def after_poll(result: Any, _n: int) -> None:
            coordinator.data = result
            coordinator.async_update_listeners()
            reads.append(asyncio.ensure_future(_read_everything(w)))

        await kit.full_polls(coordinator, on_poll=after_poll)
        bodies = await asyncio.gather(*reads)
        assert on_calls == off_calls
        assert all(b["status"] == "ok" for state, _c, _e in bodies for b in (state,))
        assert w.engine.store.seen.get(R1)  # it did follow the polls


async def _read_everything(w: Any) -> tuple[Any, Any, Any]:
    now = w.clock.t
    state = await tm_state.async_state(
        w.hass, tm_state.StateQuery(now), admin=True, now=now
    )
    compare = await tm_state.async_compare(
        w.hass, tm_state.CompareQuery(now - 60, now), admin=True, now=now
    )
    export = await async_export(
        w.hass, tm_query.Query(now - 3600, now + 1), now=now, user_id="u"
    )
    return state, compare, export


# --- cost on a full store ------------------------------------------------------------


class Blocks:
    """Longest stretch between two yields of the code under test."""

    def __init__(self) -> None:
        self.last = time.perf_counter()
        self.longest = 0.0
        self.real = asyncio.sleep

    async def sleep(self, delay: float = 0, *a: Any) -> None:
        now = time.perf_counter()
        self.longest = max(self.longest, now - self.last)
        await self.real(delay, *a)
        self.last = time.perf_counter()

    def end(self) -> None:
        self.longest = max(self.longest, time.perf_counter() - self.last)


def _fill(engine: Any) -> None:
    """15000 marks as in ``test_a_full_store_stays_under_the_limit``."""
    for i in range(3000):
        engine.index.add(
            ts=T0 + i,
            kind="channel_changed",
            router=R1,
            code="channel",
            params={
                "band": 5,
                "channel_from": 36 if i % 2 == 0 else 100,
                "channel_to": 100 if i % 2 == 0 else 36,
                "width_from": 80,
                "width_to": 80,
                "dfs": 0,
            },
        )
    for i in range(2000):
        engine.index.add(
            ts=T0 + i,
            kind="config_drift",
            router=R1,
            code="configuration.drift_detected",
            ref=("audit", f"evt_{i:032x}"),
        )
    for i in range(10_000):
        engine.index.add(
            ts=T0 + i,
            kind="client_session",
            router=R1,
            client=f"{i:016x}",
            end=T0 + i + 600,
            end_state="closed",
            params={"band": 5, "gaps": 1},
        )


async def test_cost_of_state_compare_and_export_on_a_full_store(disks) -> None:
    with world(disks) as w:
        w.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = True
        engine = await w.start(clients=False)
        engine.clients_wanted = True
        engine.recorder = SimpleNamespace(name_of=lambda _c: None, attached=True)
        engine.store.clients_cov = [[T0 - 10, None]]
        w.coords["r1"].poll()
        _fill(engine)
        assert len(engine.index) == 15_000
        w.clock.t = now = T0 + 10_000
        results = {}
        for name, call in (
            (
                "state",
                lambda: tm_state.async_state(
                    w.hass, tm_state.StateQuery(T0 + 5_000.5), admin=True, now=now
                ),
            ),
            (
                "compare",
                lambda: tm_state.async_compare(
                    w.hass,
                    tm_state.CompareQuery(T0 + 1_000.5, T0 + 9_000.5),
                    admin=True,
                    now=now,
                ),
            ),
            (
                "export",
                lambda: async_export(
                    w.hass, tm_query.Query(T0 - 60, now), now=now, user_id="u"
                ),
            ),
        ):
            blocks = Blocks()
            with (
                patch.object(tm_state.asyncio, "sleep", blocks.sleep),
                patch.object(tm_sources.asyncio, "sleep", blocks.sleep),
                patch.object(tm_query.asyncio, "sleep", blocks.sleep),
            ):
                started = time.perf_counter()
                body = await call()
                blocks.end()
            results[name] = (time.perf_counter() - started, blocks.longest)
            assert len(json.dumps(body)) < 4_000_000
        state = body_state = await tm_state.async_state(
            w.hass, tm_state.StateQuery(T0 + 5_000.5), admin=True, now=now
        )
        assert (
            state["clients"]["total"] == 600
            and len(body_state["clients"]["items"]) == 200
        )
        for name, (total, longest) in results.items():
            print(
                f"\n[time machine] {name} on 15000 marks: {total * 1000:.1f} ms, "
                f"longest block {longest * 1000:.1f} ms"
            )
            assert longest < 0.25, name  # generous for slow CI runners
