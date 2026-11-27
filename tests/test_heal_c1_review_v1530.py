"""Self-Healing, package C1: the points of the independent review of PR #78.

Each test failed before its fix (or pins a safety property no test held:
the reviewer's surviving mutations M06, M10, M15, M18, M20, M23, M27, M28).

* P2-1 a "ghost" entry (runtime data left after a failed setup, or an
  entry still setting up) is never added by the option and never acted on;
  the entry that is finishing its own setup still starts the engine.
* P2-2 the receiver, the tick, the deferred list, the bind task, the
  close rule (planning states, own action type only).
* P3: the switch re-checked inside the lock; no store without a real
  configuration directory (no stray ``MagicMock/`` directory); the options
  flow saves when ``heal_engine`` cannot be imported; spoofed and remote
  bus events (the event is a trigger, the truth is Network Intelligence's);
  malformed payloads; the masked ``last_activity``; a failed base unload;
  the option text; open announced incidents without a record are adopted
  at start and on the tick (bounded).
"""

from __future__ import annotations

import asyncio
import builtins
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core_testkit import USER_ID, FakeDisks, add_users, make_hass
from homeassistant.config_entries import ConfigEntryState
from homeassistant.core import Event, EventOrigin
from test_heal_engine_v1530 import (
    E1,
    E2,
    R1,
    R2,
    T0,
    Clock,
    FakeNI,
    Registry,
    World,
    heal_hass,
    incident,
    make_entries,
    patched,
    payload,
    world,
)
from test_heal_store_v1530 import disks, new_action
from test_heal_views_v1530 import URLS, Http, http
from test_net_p6 import SETTLE, clock, intel, open_of, step, timers, wan
from test_net_p6 import T0 as NI_T0
from test_tm_options import _save, fleet

from custom_components.openwrt_router import config_api
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router.const import (
    DATA_SELF_HEALING_ENGINE,
    EVENT_INCIDENT,
    OPTION_SELF_HEALING_ENABLED,
)
from custom_components.openwrt_router.net_events import IncidentStatus
from custom_components.openwrt_router.topology_panel import _PANEL_ACCESS_KEY

__all__ = ["clock", "disks", "http", "intel", "timers", "world"]  # fixtures

S = hm.ActionState
ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "custom_components" / "openwrt_router"


# --- P2-1: ghost entries ----------------------------------------------------------------


async def test_option_on_adds_only_loaded_entries(world: World) -> None:
    """An entry whose setup failed after its runtime data was set is no
    loaded router: the option never adds it, and the engine stops with the
    last router that really is loaded."""
    hass = world.hass
    hass.entries[1].state = ConfigEntryState.SETUP_ERROR  # runtime data kept
    await he.async_apply_self_healing_option(hass, on=True)
    engine = he.async_get_self_healing(hass)
    assert engine is not None and engine.entries == {E1}
    await he.async_release_self_healing(hass, E1)
    assert he.async_get_self_healing(hass) is None
    assert engine.closed and world.bus.listeners == []


@pytest.mark.parametrize(
    ("state", "runtime", "loaded"),
    [
        (ConfigEntryState.LOADED, True, True),
        (ConfigEntryState.LOADED, False, False),  # runtime data gone
        (ConfigEntryState.SETUP_IN_PROGRESS, True, False),
        (ConfigEntryState.SETUP_ERROR, True, False),
        (ConfigEntryState.SETUP_RETRY, True, False),
        (ConfigEntryState.FAILED_UNLOAD, True, False),
        (ConfigEntryState.NOT_LOADED, True, False),
    ],
)
def test_loaded_entries_need_runtime_data_and_the_loaded_state(
    state: ConfigEntryState, runtime: bool, loaded: bool
) -> None:
    """M28: both checks are needed."""
    (entry,) = make_entries(E1)
    entry.state = state
    if not runtime:
        del entry.runtime_data
    hass = heal_hass([entry])
    assert he._loaded_entry_ids(hass) == ([E1] if loaded else [])


@pytest.mark.parametrize(
    ("state", "starts"),
    [
        (ConfigEntryState.SETUP_IN_PROGRESS, True),  # its own setup finishing
        (ConfigEntryState.LOADED, True),
        (ConfigEntryState.SETUP_ERROR, False),
        (ConfigEntryState.NOT_LOADED, False),
        (None, False),
    ],
)
async def test_the_entry_finishing_its_setup_starts_the_engine(
    world: World, state: Any, starts: bool
) -> None:
    entry = world.hass.entries[0]
    entry.state = state
    await he.async_setup_self_healing(world.hass, entry)
    engine = he.async_get_self_healing(world.hass)
    assert (engine is not None) is starts
    if engine is not None:
        assert engine.entries == {E1}
        await engine.async_stop()


async def test_no_record_for_a_router_that_is_not_loaded(world: World) -> None:
    """An entry in the engine whose config entry is not LOADED (a failed
    unload, a setup still running) is not acted on."""
    engine = await world.start()
    world.hass.entries[0].state = ConfigEntryState.FAILED_UNLOAD
    world.open("inc-1", router=E1)
    world.hass.entries[1].state = ConfigEntryState.SETUP_IN_PROGRESS
    world.open("inc-2", router=E2)
    assert world.records() == []
    assert engine.counters["skipped_router_not_loaded"] == 2
    # loaded again: the tick adopts both announced incidents
    for entry in world.hass.entries:
        entry.state = ConfigEntryState.LOADED
    world.tick()
    assert {a.incident_id for a in world.records()} == {"inc-1", "inc-2"}


# --- P2-2: safety properties ------------------------------------------------------------


async def test_an_exception_in_the_receiver_does_not_escape(
    world: World, caplog: Any
) -> None:
    """M06: the bus receiver never raises into HA's bus."""
    engine = await world.start()
    with (
        patch.object(he.HealEngine, "handle_incident", side_effect=RuntimeError("x")),
        caplog.at_level(logging.WARNING),
    ):
        world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
        world.bus.fire(EVENT_INCIDENT, payload("inc-2"))
    assert engine.counters["errors"] == 2
    assert "RuntimeError" in caplog.text
    world.open("inc-3")  # and it goes on working
    assert world.of("inc-3").state is S.PROPOSED


async def test_a_raising_tick_does_not_stop_later_ticks(world: World) -> None:
    """M15: an error in one tick is counted; the next tick runs."""
    engine = await world.start()
    with patch.object(engine, "tick", side_effect=RuntimeError("x")):
        for _ in range(3):
            world.tick()
    assert engine.counters["ticks"] == 3 and engine.counters["errors"] == 3
    before = engine.store.loop.clock.safe
    world.tick()
    assert engine.counters["ticks"] == 4 and engine.counters["errors"] == 3
    assert engine.store.loop.clock.safe > before  # the clock is read again


async def test_the_deferred_list_is_capped(world: World) -> None:
    """M18: at most PENDING_MAX deferred incidents, the oldest drop first."""
    engine = await world.start()
    world.open("inc-0")
    for i in range(1, he.PENDING_MAX + 51):
        world.open(f"inc-{i}")
    assert engine.pending_count() == he.PENDING_MAX
    assert "inc-1" not in engine._pending and "inc-50" not in engine._pending
    assert f"inc-{he.PENDING_MAX + 50}" in engine._pending
    assert engine.counters["deferred"] == he.PENDING_MAX + 50


async def test_the_bind_task_is_cancelled_at_stop(world: World) -> None:
    """M27: a core bind still waiting when the engine stops is cancelled."""
    with patch.object(
        config_api,
        "async_get_configuration_api",
        AsyncMock(side_effect=RuntimeError("core down")),
    ):
        engine = await world.start()
    gate = asyncio.Event()

    async def wait_forever(*_a: Any, **_kw: Any) -> Any:
        await gate.wait()

    with patch.object(config_api, "async_get_configuration_api", wait_forever):
        world.tick()
        task = engine._bind_task
        assert task is not None
        await asyncio.sleep(0)
        assert not task.done()
        await engine.async_stop()
    assert task.cancelled()
    assert engine._bind_task is None


async def test_the_engine_closes_only_its_planning_records(world: World) -> None:
    """M10 / M20: a resolved incident closes observe records in DETECTED,
    ANALYZED or PROPOSED only; a record in a later state, and a record of
    another action type, stay as they are (also on the tick)."""
    engine = await world.start()
    store = engine.store
    world.open("inc-1", router=E1)
    observe = world.of("inc-1")
    store.apply(
        observe.action_id, S.PREFLIGHT, actor=hm.Actor.ENGINE, ts=T0 + 1, reason="t"
    )
    other = store.add(new_action(router_id=R2, incident_id="inc-7")).action
    world.ni.incidents["inc-7"] = incident("inc-7", [E2])
    world.resolve("inc-1")
    world.resolve("inc-7")
    world.tick()
    del world.ni.incidents["inc-1"], world.ni.incidents["inc-7"]
    world.tick()  # gone from NI: still untouched
    assert store.get(observe.action_id).state is S.PREFLIGHT
    assert store.get(other.action_id).state is S.DETECTED
    assert engine.counters["closed"] == 0


# --- P3-3: the switch inside the lock ---------------------------------------------------


async def test_the_switch_is_read_again_inside_the_lock(world: World) -> None:
    """An entry in setup retry waiting for the lock while the options flow
    switches the module off must not start a new engine."""
    hass = world.hass
    lock = he._lock(hass)
    await lock.acquire()
    task = asyncio.ensure_future(he.async_setup_self_healing(hass, hass.entries[0]))
    await asyncio.sleep(0)
    for entry in hass.entries:
        entry.options[OPTION_SELF_HEALING_ENABLED] = False
    lock.release()
    await task
    assert he.async_get_self_healing(hass) is None
    assert DATA_SELF_HEALING_ENGINE not in hass.data


# --- P3-4: no store without a real configuration directory ------------------------------


async def test_no_engine_without_a_configuration_directory(
    tmp_path: Path, monkeypatch: Any, caplog: Any
) -> None:
    """A mocked hass (no real config dir) never gets a store: HA's real
    Store would write into the working directory. Real store class here,
    run in an empty directory: nothing appears."""
    monkeypatch.chdir(tmp_path)
    (entry,) = make_entries(E1)
    entry.state = ConfigEntryState.SETUP_IN_PROGRESS
    hass = make_hass([entry])  # config.config_dir is a MagicMock
    with (
        patch.object(he, "async_track_time_interval", MagicMock()),
        caplog.at_level(logging.WARNING),
    ):
        await he.async_setup_self_healing(hass, entry)
        await he.async_setup_self_healing(hass, entry)
        await he.async_apply_self_healing_option(hass, on=True)
    assert he.async_get_self_healing(hass) is None
    assert list(tmp_path.iterdir()) == []
    assert caplog.text.count("no configuration directory") == 1  # once
    hass.http.register_view.assert_not_called()


def test_the_suite_checks_for_a_stray_directory() -> None:
    """The session hook in conftest fails the run when a test leaves a
    ``MagicMock`` directory behind (a store written on a mocked hass)."""
    import conftest

    assert conftest.STRAY_DIRS == ("MagicMock",)
    assert callable(conftest.pytest_sessionfinish)
    assert not (ROOT / "MagicMock").exists()


# --- P3-5: the options flow without heal_engine -----------------------------------------


async def test_the_options_flow_saves_when_heal_engine_cannot_import(
    caplog: Any,
) -> None:
    hass, (first, second) = fleet({}, {})
    real_import = builtins.__import__

    def failing(name: str, *args: Any, **kwargs: Any) -> Any:
        fromlist = args[2] if len(args) > 2 else kwargs.get("fromlist") or ()
        if name.endswith("heal_engine") or "heal_engine" in (fromlist or ()):
            raise ImportError("broken")
        return real_import(name, *args, **kwargs)

    with (
        patch.object(builtins, "__import__", failing),
        caplog.at_level(logging.WARNING),
    ):
        result = await _save(
            first,
            {OPTION_SELF_HEALING_ENABLED: False, "topology_port_debug": True},
            hass,
        )
    assert result["type"] == "create_entry"
    assert result["data"][OPTION_SELF_HEALING_ENABLED] is False
    assert result["data"]["topology_port_debug"] is True
    assert second.options == {OPTION_SELF_HEALING_ENABLED: False}
    assert "ImportError" in caplog.text


# --- P3-6 / P3-7: the event is a trigger only -------------------------------------------


async def test_a_spoofed_resolved_closes_nothing(world: World) -> None:
    engine = await world.start()
    world.open("inc-1")
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "resolved"))
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "resolved", reason="ignored"))
    assert world.of("inc-1").state is S.PROPOSED  # NI still says active
    assert engine.counters["closed"] == 0
    world.resolve("inc-1")  # NI really resolves it
    assert world.of("inc-1").state is S.CANCELLED


async def test_a_spoofed_opened_makes_nothing_and_blocks_nothing(world: World) -> None:
    engine = await world.start()
    world.bus.fire(EVENT_INCIDENT, payload("inc-fake", entry_ids=[E1]))
    assert world.records() == []
    assert engine.counters["skipped_unknown_incident"] == 1
    world.open("inc-real", router=E1)
    assert world.of("inc-real").state is S.PROPOSED  # not deferred
    # NI knows it but never announced it (below the severity, a child, in
    # maintenance, still settling): no record either
    world.ni.incidents["inc-quiet"] = incident("inc-quiet", [E2])
    world.bus.fire(EVENT_INCIDENT, payload("inc-quiet", entry_ids=[E2]))
    assert engine.counters["skipped_not_announced"] == 1
    assert {a.incident_id for a in world.records()} == {"inc-real"}


async def test_without_network_intelligence_an_event_does_nothing(
    world: World,
) -> None:
    engine = await world.start()
    world.open("inc-1")
    world.ni.loaded = False
    world.bus.fire(EVENT_INCIDENT, payload("inc-2"))
    world.ni.incidents["inc-1"].status = IncidentStatus.RESOLVED
    world.bus.fire(EVENT_INCIDENT, payload("inc-1", "resolved"))
    assert engine.counters["skipped_ni_unavailable"] == 2
    assert world.of("inc-1").state is S.PROPOSED and len(world.records()) == 1


async def test_a_remote_event_is_ignored(world: World) -> None:
    """Fired through the API (origin remote): not even a trigger."""
    engine = await world.start()
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    world.ni.announced["inc-1"] = 0
    [(_type, receiver)] = world.bus.listeners
    receiver(Event(EVENT_INCIDENT, payload("inc-1"), EventOrigin.remote))
    assert world.records() == []
    assert engine.counters["skipped_remote_event"] == 1
    receiver(Event(EVENT_INCIDENT, payload("inc-1"), EventOrigin.local))
    assert world.of("inc-1").state is S.PROPOSED


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        "opened",
        42,
        {"state": "opened"},
        {"state": ["opened"], "incident_id": "inc-1"},
        {"state": "opened", "incident_id": 5},
        {"state": "opened", "incident_id": ""},
        {"state": "opened", "incident_id": "x" * 200_000},
        {"state": "opened", "incident_id": "inc-1", "entry_ids": "e1"},
        {"state": "opened", "incident_id": "inc-1", "entry_ids": 7},
        {"state": "opened", "incident_id": "inc-1", "entry_ids": {"a": 1}},
        {"state": "opened", "incident_id": "inc-1", "entry_ids": [7]},
        {"state": "closed", "incident_id": "inc-1"},
    ],
)
async def test_malformed_payloads_are_bad_events_without_a_warning(
    world: World, caplog: Any, data: Any
) -> None:
    """P3-7: counted as ``skipped_bad_event``; no WARNING, no error, no
    record (even though NI knows inc-1)."""
    engine = await world.start()
    world.ni.incidents["inc-1"] = incident("inc-1", [E1])
    world.ni.announced["inc-1"] = 0
    with caplog.at_level(logging.WARNING):
        world.bus.fire(EVENT_INCIDENT, data)
    assert engine.counters["skipped_bad_event"] == 1
    assert engine.counters["errors"] == 0
    assert world.records() == []
    assert caplog.records == []


async def test_the_real_network_intelligence_says_what_it_announced(
    disks: FakeDisks, intel: Any
) -> None:
    """The read-only accessor the engine uses (NI's own record of its
    announcements: root, severity, settle, maintenance already applied)."""
    step(intel, NI_T0, wan())
    [inc] = open_of(intel, "wan_down")
    assert intel.announced_reopen_count(inc.id) is None  # still settling
    step(intel, NI_T0 + SETTLE, wan())
    assert intel.announced_reopen_count(inc.id) == inc.reopen_count == 0
    step(intel, NI_T0 + 400, wan(0.0))
    assert intel.announced_reopen_count(inc.id) is None  # resolved
    assert intel.announced_reopen_count("inc-unknown") is None


# --- P3-8: the masked overview ----------------------------------------------------------


async def test_last_activity_is_rounded_to_the_minute_for_non_admins(
    world: World, http: Http
) -> None:
    add_users(world.hass)
    await world.start()
    minute = (T0 // 60 + 1) * 60  # a full minute
    world.clock.now = minute + 59.7
    world.open("inc-1")
    world.hass.data[_PANEL_ACCESS_KEY] = {E1: True}
    status, body = await http.get(URLS["overview"], user=USER_ID)
    assert status == 200 and body["last_activity"] == minute
    status, body = await http.get(URLS["overview"])
    assert status == 200 and body["last_activity"] == minute + 59.7


async def test_the_overview_shows_a_router_that_is_not_loaded_as_not_loaded(
    world: World, http: Http
) -> None:
    """``loaded`` in the overview is the engine's own rule (in the engine,
    enabled and LOADED), not only membership."""
    add_users(world.hass)
    await world.start()
    world.hass.entries[0].state = ConfigEntryState.FAILED_UNLOAD
    status, body = await http.get(URLS["overview"])
    assert status == 200
    loaded = {r["router_id"]: r["loaded"] for r in body["routers"]}
    assert loaded == {R1: False, R2: True}


# --- P3-9: a failed base unload ---------------------------------------------------------


async def test_a_failed_base_unload_keeps_the_router_like_the_time_machine(
    world: World,
) -> None:
    """M23: HA keeps a router whose unload failed (FAILED_UNLOAD); the
    engine keeps it as well, like the Time Machine, but never acts on it."""
    import custom_components.openwrt_router as integration

    hass = world.hass
    for entry in hass.entries:
        await he.async_setup_self_healing(hass, entry)
    engine = he.async_get_self_healing(hass)
    with patch.object(
        integration, "_async_unload_entry_tm", AsyncMock(return_value=False)
    ):
        assert await integration.async_unload_entry(hass, hass.entries[0]) is False
    assert engine.entries == {E1, E2}
    hass.entries[0].state = ConfigEntryState.FAILED_UNLOAD
    world.engine = engine
    world.open("inc-1", router=E1)
    assert world.records() == []
    with patch.object(
        integration, "_async_unload_entry_tm", AsyncMock(return_value=True)
    ):
        assert await integration.async_unload_entry(hass, hass.entries[1]) is True
    assert engine.entries == {E1}


# --- P3-10 / P3-11: texts ---------------------------------------------------------------


def test_the_option_text_promises_no_repair() -> None:
    texts = []
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((COMPONENT / name).read_text(encoding="utf-8"))
        step_ = data["options"]["step"]["init"]
        texts.append(step_["data_description"][OPTION_SELF_HEALING_ENABLED])
    en, en2, de = texts
    assert en == en2
    for needle in ("repair proposal", "proposal"):
        assert needle not in en.lower()
    assert "reparaturvorschl" not in de.lower()
    assert "never changes a router" in en
    assert "ändert nie" in de


def test_the_diagnostics_wrapper_test_is_named_for_what_it_checks() -> None:
    source = (ROOT / "tests" / "test_tm_diagnostics.py").read_text(encoding="utf-8")
    assert "def test_the_block_is_the_last_wrapper_of_the_download" not in source


# --- P3-12: open incidents without a record ---------------------------------------------


async def test_restart_adopts_an_open_incident_that_had_no_record(
    world: World,
) -> None:
    """Deferred incidents are lost on a restart and NI does not announce an
    incident again: the start reconciles with NI's announced incidents."""
    engine = await world.start()
    world.open("inc-1", router=E1)
    world.open("inc-2", router=E1)  # deferred: inc-1 holds the router
    assert engine.pending_count() == 1
    await engine.async_stop()
    world.ni.incidents["inc-1"].status = IncidentStatus.RESOLVED  # while down
    world.ni.announced.pop("inc-1")
    world.clock.now += 60
    world.clock.real += 60
    again = await world.start()
    assert again.store.get(world.of("inc-1").action_id).state is S.CANCELLED
    second = world.of("inc-2")
    assert second.state is S.PROPOSED
    assert second.history[0].reason == "incident_reconciled"
    assert again.counters["reconciled"] == 1
    # the next tick adds nothing
    world.tick()
    assert len(world.records()) == 2


async def test_the_tick_adopts_only_announced_single_router_roots(
    world: World,
) -> None:
    engine = await world.start()
    world.ni.incidents["inc-a"] = incident("inc-a", [E1])
    world.ni.announced["inc-a"] = 0
    world.ni.incidents["inc-b"] = incident("inc-b", [E2])  # never announced
    world.ni.incidents["inc-c"] = incident("inc-c", [E1, E2])
    world.ni.announced["inc-c"] = 0
    world.ni.incidents["inc-d"] = incident("inc-d", [E2], reopen_count=1)
    world.ni.announced["inc-d"] = 0  # announced in an earlier open period
    world.tick()
    assert {a.incident_id for a in world.records()} == {"inc-a"}
    assert engine.counters["reconciled"] == 1
    # skips on the tick are not counted again and again
    counters = dict(engine.counters)
    world.tick()
    world.tick()
    for name in ("skipped_not_announced", "skipped_no_single_router"):
        assert engine.counters[name] == counters[name]


async def test_adopting_is_bounded_per_tick(disks: FakeDisks) -> None:
    n = he.RECONCILE_MAX + 5
    ids = [f"r{i}" for i in range(n)]
    hass = heal_hass(make_entries(*ids))
    w = World(
        hass,
        Clock(),
        FakeNI(),
        Registry({e: f"rtr_{i:032x}" for i, e in enumerate(ids, 1)}),
    )
    for i, entry_id in enumerate(ids):
        w.ni.incidents[f"inc-{i}"] = incident(f"inc-{i}", [entry_id])
        w.ni.announced[f"inc-{i}"] = 0
    with patched(w.ni, w.registry, w.ticks):
        engine = await w.start()  # adding the routers reconciles
        assert len(w.records()) == he.RECONCILE_MAX
        w.tick()
        assert len(w.records()) == n
        w.tick()
        assert len(w.records()) == n
        assert engine.counters["reconciled"] == n
        await engine.async_stop()


async def test_adopting_makes_no_second_record_for_a_closed_period(
    world: World,
) -> None:
    """A record closed while its incident is still open in the same period
    (it became a child, then a root again) is not made again."""
    engine = await world.start()
    world.open("inc-1")
    record = world.of("inc-1")
    engine._close(engine.store.get(record.action_id), "incident_now_child")
    world.tick()
    assert len(world.records()) == 1
    world.bus.fire(EVENT_INCIDENT, payload("inc-1"))
    assert len(world.records()) == 1


async def test_zero_router_calls_and_no_hass_writes_while_adopting(
    world: World,
) -> None:
    engine = await world.start()
    world.hass.async_add_executor_job.reset_mock()  # the store's load
    for i in range(5):
        world.ni.incidents[f"inc-{i}"] = incident(f"inc-{i}", [E1 if i % 2 else E2])
        world.ni.announced[f"inc-{i}"] = 0
    world.tick()
    assert len(world.records()) == 2
    assert world.hass.fired == []
    world.hass.services.async_call.assert_not_called()
    world.hass.async_add_executor_job.assert_not_called()
    assert engine.counters["errors"] == 0
