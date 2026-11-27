"""Self-Healing, package K2 (1.53.0): buttons and switches respect the lock.

Owner decision Q4 (b), "Sperre und Audit": every existing button and switch
that restarts, starts or stops a service, reloads or switches Wi-Fi or
reboots a router runs through ``heal_guard.async_manual_action``. Covered
here (docs/self-healing.md §10.3):

* the recorded calls: with nothing holding the lock every guarded button
  and switch sends exactly the router calls of main (1.52.3), in the same
  order, with the integration bare (no hass), with the Core alone and with
  the Core and a running engine (``EXPECTED_MAIN``, recorded by running the
  1.52.3 code against ``full_router_kit`` with write answers added);
* case 1: an engine action holds the router's lock (a stand-in: a real
  store whose action is in EXECUTING) -> HomeAssistantError
  ``repair_running``, no router call, no refresh, one audit entry
  ``refused_busy``, the engine lock untouched;
* case 2: a router on hold is not blocked, its audit entry says so;
* case 3: the press holds the router's lock while it runs (the engine's
  durable step is refused ``router_locked`` meanwhile), presses share one
  lock, and the lock is released after success, a refused call, an
  exception, a timeout and a cancelled task;
* case 4: exactly one audit entry per press with closed codes only (no
  address, hostname, SSID, UCI section, client name or secret), the user
  id of the service call's context, the Core's router id;
* case 5: module off (no engine, engine not loaded, settings switch off)
  -> no lock, no refusal; the audit still written with the Core running,
  skipped without it; a broken or slow audit never fails a press;
* a source scan: every router write of button.py and switch.py sits inside
  ``async_manual_action``.

In 1.53.0 the engine never executes, so case 1 cannot happen in
production; the stand-in holder is the only way to reach it.
"""

from __future__ import annotations

import ast
import asyncio
import inspect
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import full_router_kit as kit
import pytest
from core_testkit import (
    ADMIN_ID,
    SECRET,
    FakeEntry,
    add_user,
    make_hass,
    router_data,
    setup_router,
)
from homeassistant.core import Context
from homeassistant.exceptions import HomeAssistantError
from test_heal_store_v1530 import T0, Clock, disks, execute, new_action, to_approved
from test_wifi_switch_ids_v1492 import ENTRY

from custom_components.openwrt_router import OpenWrtRuntimeData
from custom_components.openwrt_router import button as button_platform
from custom_components.openwrt_router import heal_engine as he
from custom_components.openwrt_router import heal_guard as hg
from custom_components.openwrt_router import heal_model as hm
from custom_components.openwrt_router import heal_store as hs
from custom_components.openwrt_router import switch as switch_platform
from custom_components.openwrt_router.config_api import async_get_configuration_api
from custom_components.openwrt_router.const import DATA_SELF_HEALING_ENGINE, DOMAIN

__all__ = ["disks"]  # fixture used here

S = hm.ActionState
PKG = Path(__file__).resolve().parents[1] / "custom_components" / "openwrt_router"
REFRESH = ("<refresh>", "", {})

# Router writes the test router accepts (the kit answers every unknown call
# with "method not found"; these are the writes of the guarded entities).
WRITE_OK = {
    ("network", "reload"),
    ("system", "reboot"),
    ("rc", "init"),
    ("uci", "set"),
    ("uci", "commit"),
}
_KIT_ANSWER = kit.answer


def _answer(obj: str, method: str, args: dict[str, Any], **kw: Any) -> list[Any]:
    if (obj, method) in WRITE_OK:
        return [0]
    return _KIT_ANSWER(obj, method, args, **kw)


# --- the gateway and its entities -------------------------------------------------------


class Gateway:
    """The kit gateway after two polls, with its button and switch entities."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.api: Any = None
        self.coordinator: Any = None
        self.entities: dict[str, Any] = {}

    async def build(self, hass: Any) -> Gateway:
        self.api = kit.make_api(self.calls)
        self.coordinator = kit.make_coordinator(MagicMock(), self.api)
        await kit.full_polls(self.coordinator)
        self.coordinator.async_request_refresh = AsyncMock(
            side_effect=lambda: self.calls.append(REFRESH)
        )
        entry = MagicMock()
        entry.entry_id = ENTRY
        entry.title = "GW"
        entry.options = {}
        entry.data = {"host": "192.0.2.1", "port": 80}
        entry.runtime_data = OpenWrtRuntimeData(
            api=self.api, coordinator=self.coordinator
        )
        added: list[Any] = []
        setup_hass = hass if hass is not None else make_hass()
        for platform in (button_platform, switch_platform):
            await platform.async_setup_entry(
                setup_hass, entry, lambda ents, *a, **k: added.extend(ents)
            )
        for entity in added:
            key = entity.unique_id.replace(f"{ENTRY}_", "")
            entity.hass = hass
            self.entities[key] = entity
        self.calls.clear()
        return self


# (name, entity key, method, args)
ACTIONS: tuple[tuple[str, str, str], ...] = (
    ("button.reload_wifi", "reload_wifi", "async_press"),
    ("button.reboot", "reboot", "async_press"),
    ("button.restart.dnsmasq", "service_dnsmasq_restart", "async_press"),
    ("button.restart.dropbear", "service_dropbear_restart", "async_press"),
    ("button.restart.firewall", "service_firewall_restart", "async_press"),
    ("switch.wifi.lan_2g.off", "wifi_ssid_lan_2g", "async_turn_off"),
    ("switch.wifi.lan_2g.on", "wifi_ssid_lan_2g", "async_turn_on"),
    ("switch.wifi.lan_5g.off", "wifi_ssid_lan_5g", "async_turn_off"),
    ("switch.wifi.lan_5g.on", "wifi_ssid_lan_5g", "async_turn_on"),
    ("switch.wifi.iot_5g.on", "wifi_ssid_iot_5g", "async_turn_on"),
    ("switch.wifi.iot_5g.off", "wifi_ssid_iot_5g", "async_turn_off"),
    ("switch.wifi.uplink.off", "wifi_ssid_uplink", "async_turn_off"),
    ("switch.wifi.uplink.on", "wifi_ssid_uplink", "async_turn_on"),
    ("switch.service.dnsmasq.off", "service_dnsmasq", "async_turn_off"),
    ("switch.service.dnsmasq.on", "service_dnsmasq", "async_turn_on"),
    ("switch.service.dropbear.off", "service_dropbear", "async_turn_off"),
    ("switch.service.dropbear.on", "service_dropbear", "async_turn_on"),
    ("switch.service.firewall.off", "service_firewall", "async_turn_off"),
    ("switch.service.firewall.on", "service_firewall", "async_turn_on"),
)


def _no_ssh() -> Any:
    return patch(
        "custom_components.openwrt_router.api.asyncssh.connect",
        AsyncMock(side_effect=AssertionError("SSH must not be used")),
    )


async def record(gw: Gateway, actions: Any = ACTIONS) -> dict[str, list]:
    """Run each action once, in order; the router calls of each."""
    out: dict[str, list] = {}
    with _no_ssh():
        for name, key, method in actions:
            gw.calls.clear()
            await getattr(gw.entities[key], method)()
            out[name] = list(gw.calls)
    return out


def _wifi(section: str, disabled: str) -> list[tuple[str, str, dict]]:
    return [
        (
            "uci",
            "set",
            {
                "config": "wireless",
                "section": section,
                "values": {"disabled": disabled},
            },
        ),
        ("uci", "commit", {"config": "wireless"}),
        ("network", "reload", {}),
        REFRESH,
    ]


def _rc(name: str, action: str) -> list[tuple[str, str, dict]]:
    return [("rc", "init", {"name": name, "action": action}), REFRESH]


# Recorded by running the 1.52.3 code (main, git 06da693) with record():
# the same sequence of presses on one gateway, entity.hass None.
EXPECTED_MAIN: dict[str, list] = {
    "button.reload_wifi": [("network", "reload", {}), REFRESH],
    "button.reboot": [("system", "reboot", {})],
    "button.restart.dnsmasq": _rc("dnsmasq", "restart"),
    "button.restart.dropbear": _rc("dropbear", "restart"),
    "button.restart.firewall": _rc("firewall", "restart"),
    "switch.wifi.lan_2g.off": _wifi("lan_2g", "1"),
    "switch.wifi.lan_2g.on": _wifi("lan_2g", "0"),
    "switch.wifi.lan_5g.off": _wifi("lan_5g", "1"),
    "switch.wifi.lan_5g.on": _wifi("lan_5g", "0"),
    "switch.wifi.iot_5g.on": _wifi("iot_5g", "0"),
    "switch.wifi.iot_5g.off": _wifi("iot_5g", "1"),
    "switch.wifi.uplink.off": _wifi("uplink", "1"),
    "switch.wifi.uplink.on": _wifi("uplink", "0"),
    "switch.service.dnsmasq.off": _rc("dnsmasq", "stop"),
    "switch.service.dnsmasq.on": _rc("dnsmasq", "start"),
    "switch.service.dropbear.off": _rc("dropbear", "stop"),
    "switch.service.dropbear.on": _rc("dropbear", "start"),
    "switch.service.firewall.off": _rc("firewall", "stop"),
    "switch.service.firewall.on": _rc("firewall", "start"),
}


@pytest.fixture(autouse=True)
def write_answers() -> Any:
    with patch.object(kit, "answer", _answer):
        yield


async def test_recorded_calls_bare_are_the_main_ones() -> None:
    gw = await Gateway().build(None)
    assert await record(gw) == EXPECTED_MAIN


# --- Core and engine ----------------------------------------------------------------------


class World:
    """hass with the real Core (one router) and, optionally, an engine."""

    def __init__(self) -> None:
        self.hass: Any = None
        self.api: Any = None
        self.rid = ""
        self.engine: Any = None
        self.clock = Clock()

    @property
    def store(self) -> hs.SelfHealingStore:
        return self.engine.store

    async def start(self, *, core: bool = True, engine: bool = True) -> World:
        self.hass = make_hass()
        add_user(self.hass, ADMIN_ID, admin=True)
        if core:
            await setup_router(self.hass, FakeEntry(ENTRY), router_data())
            self.api = await async_get_configuration_api(self.hass, 1)
            self.rid = self.api.registry.get_by_entry(ENTRY).router_id
        if engine:
            store = hs.SelfHealingStore(
                self.hass, clock=self.clock, monotonic=self.clock.mono
            )
            await store.async_load()
            self.engine = he.HealEngine(
                self.hass, clock=self.clock, monotonic=self.clock.mono, store=store
            )
            self.engine.loaded = True
            self.engine._api = self.api
            self.hass.data[DATA_SELF_HEALING_ENGINE] = self.engine
        return self

    async def gateway(self) -> Gateway:
        return await Gateway().build(self.hass)

    def audits(self) -> list[Any]:
        if self.api is None:
            return []
        return list(self.api.events(types=[hg.EVENT_MANUAL_ACTION], limit=500))

    async def engine_holds(self, router_id: str | None = None) -> str:
        """A stand-in engine action in EXECUTING: it holds the router lock."""
        action_id = self.store.add(new_action(router_id=router_id or self.rid))
        action_id = action_id.action.action_id
        to_approved(self.store, action_id)
        assert (await execute(self.store, action_id)).ok
        assert self.store.loop.repair_active(router_id or self.rid)
        return action_id

    def hold(self) -> None:
        self.store.loop.place_hold(
            hm.RouterHold(
                router_id=self.rid,
                reason=hm.HoldReason.OUTCOME_UNKNOWN,
                since=self.store.now(),
            )
        )


async def until(cond: Callable[[], Any], what: str) -> None:
    """Let other tasks run until ``cond()`` holds (fails, never hangs)."""
    for _ in range(2000):
        if cond():
            return
        await asyncio.sleep(0)
    raise AssertionError(f"never happened: {what}")


def _data(event: Any) -> dict[str, Any]:
    return dict(event.data)


# action and target in the audit, per press of ACTIONS
AUDITED: dict[str, tuple[str, str]] = {
    "button.reload_wifi": ("wifi.reload", "wifi"),
    "button.reboot": ("router.reboot", "system"),
    "button.restart.dnsmasq": ("service.restart", "dnsmasq"),
    "button.restart.dropbear": ("service.restart", "dropbear"),
    "button.restart.firewall": ("service.restart", "firewall"),
    "switch.wifi.lan_2g.off": ("wifi.disable", "wifi"),
    "switch.wifi.lan_2g.on": ("wifi.enable", "wifi"),
    "switch.wifi.lan_5g.off": ("wifi.disable", "wifi"),
    "switch.wifi.lan_5g.on": ("wifi.enable", "wifi"),
    "switch.wifi.iot_5g.on": ("wifi.enable", "wifi"),
    "switch.wifi.iot_5g.off": ("wifi.disable", "wifi"),
    "switch.wifi.uplink.off": ("wifi.disable", "wifi"),
    "switch.wifi.uplink.on": ("wifi.enable", "wifi"),
    "switch.service.dnsmasq.off": ("service.stop", "dnsmasq"),
    "switch.service.dnsmasq.on": ("service.start", "dnsmasq"),
    "switch.service.dropbear.off": ("service.stop", "dropbear"),
    "switch.service.dropbear.on": ("service.start", "dropbear"),
    "switch.service.firewall.off": ("service.stop", "firewall"),
    "switch.service.firewall.on": ("service.start", "firewall"),
}
SOURCES = {
    "button.reload_wifi": "button.reload_wifi",
    "button.reboot": "button.reboot",
    "button.restart": "button.service_restart",
    "switch.wifi": "switch.wifi",
    "switch.service": "switch.service",
}


def _source_of(name: str) -> str:
    return next(v for k, v in SOURCES.items() if name.startswith(k))


async def test_recorded_calls_with_the_core_are_the_main_ones(disks: Any) -> None:
    world = await World().start(engine=False)
    gw = await world.gateway()
    assert await record(gw) == EXPECTED_MAIN
    audits = world.audits()
    assert [(_data(e)["action"], _data(e)["target"]) for e in audits] == list(
        AUDITED.values()
    )
    assert {_data(e)["lock"] for e in audits} == {"none"}
    assert {_data(e)["result"] for e in audits} == {"ok"}


async def test_recorded_calls_with_a_running_engine_are_the_main_ones(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    sources: list[str] = []
    real_try = world.store.try_external_lock

    def spy(router_id: str, source: str, ts: float) -> str | None:
        sources.append(source)
        return real_try(router_id, source, ts)

    world.store.try_external_lock = spy  # type: ignore[method-assign]
    assert await record(gw) == EXPECTED_MAIN
    assert sources == [_source_of(name) for name, _k, _m in ACTIONS]
    assert world.store.loop.lock_holder(world.rid) is None
    audits = world.audits()
    assert len(audits) == len(ACTIONS)
    assert [(_data(e)["action"], _data(e)["target"]) for e in audits] == list(
        AUDITED.values()
    )
    for event in audits:
        assert _data(event) == {
            **_data(event),
            "result": "ok",
            "lock": "taken",
            "on_hold": False,
            "hold_reason": None,
        }
        assert event.router_id == world.rid
        assert event.entry_id == ENTRY
        assert str(event.result) == "success"
    writes = world.store.loop.external_writes
    assert [(w.source, w.target) for w in writes] == [
        (_source_of(name), AUDITED[name][1]) for name, _k, _m in ACTIONS
    ]
    assert [w.audit_ref for w in writes] == [e.event_id for e in audits]
    assert {w.router_id for w in writes} == {world.rid}


# --- case 1: an engine action holds the lock ----------------------------------------------


@pytest.mark.parametrize(("name", "key", "method"), ACTIONS)
async def test_refused_while_an_engine_action_holds_the_lock(
    disks: Any, name: str, key: str, method: str
) -> None:
    world = await World().start()
    gw = await world.gateway()
    action_id = await world.engine_holds()
    with _no_ssh(), pytest.raises(HomeAssistantError) as err:
        await getattr(gw.entities[key], method)()
    assert err.value.translation_domain == DOMAIN
    assert err.value.translation_key == "repair_running"
    assert gw.calls == []  # no router call, no refresh
    held = world.store.loop.lock_holder(world.rid)
    assert held is not None and held.action_id == action_id
    assert world.store.loop.external_writes == []
    [event] = world.audits()
    assert _data(event) == {
        "action": AUDITED[name][0],
        "target": AUDITED[name][1],
        "result": "refused_busy",
        "on_hold": False,
        "hold_reason": None,
        "lock": "none",
    }
    assert str(event.result) == "denied"
    assert str(event.severity) == "warning"


async def test_an_engine_lock_on_another_router_does_not_refuse(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    await world.engine_holds("rtr_" + "9" * 32)
    assert await record(gw, ACTIONS[:1]) == {
        "button.reload_wifi": EXPECTED_MAIN["button.reload_wifi"]
    }


async def test_the_busy_text_is_translated() -> None:
    files = [PKG / "strings.json", *sorted((PKG / "translations").glob("*.json"))]
    texts = {}
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        texts[path.name] = data["exceptions"]["repair_running"]["message"]
    assert set(texts) == {"strings.json", "en.json", "de.json"}
    assert texts["strings.json"] == texts["en.json"]
    assert "repair" in texts["en.json"].lower()
    assert "reparatur" in texts["de.json"].lower()


# --- case 2: a router on hold is not blocked ----------------------------------------------


async def test_a_router_on_hold_is_not_blocked_and_the_audit_says_so(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    world.hold()
    assert await record(gw, ACTIONS[1:3]) == {
        name: EXPECTED_MAIN[name] for name, _k, _m in ACTIONS[1:3]
    }
    events = world.audits()
    assert [(_data(e)["on_hold"], _data(e)["hold_reason"]) for e in events] == [
        (True, "outcome_unknown"),
        (True, "outcome_unknown"),
    ]
    assert {_data(e)["result"] for e in events} == {"ok"}
    assert world.store.loop.lock_holder(world.rid) is None


# --- case 3: the press holds the lock, and always releases it ------------------------------


async def test_the_press_holds_the_lock_and_keeps_the_engine_out(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    action_id = world.store.add(new_action(router_id=world.rid)).action.action_id
    to_approved(world.store, action_id)
    seen: list[Any] = []
    real = gw.api.control_service

    async def during(name: str, action: str) -> bool:
        held = world.store.loop.lock_holder(world.rid)
        seen.append((held.holder, held.source))
        seen.append((await execute(world.store, action_id)).reason)
        return await real(name, action)

    gw.api.control_service = during
    assert await record(gw, ACTIONS[2:3]) == {
        "button.restart.dnsmasq": EXPECTED_MAIN["button.restart.dnsmasq"]
    }
    assert seen == [
        (hm.LockHolder.EXTERNAL, "button.service_restart"),
        "router_locked",
    ]
    assert world.store.loop.lock_holder(world.rid) is None
    assert (await execute(world.store, action_id, ts=T0 + 20)).ok


async def test_presses_at_the_same_time_share_one_lock(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    gate = asyncio.Event()
    started: list[str] = []
    real = gw.api.control_service

    async def slow(name: str, action: str) -> bool:
        started.append(name)
        await gate.wait()
        return await real(name, action)

    gw.api.control_service = slow
    first = asyncio.create_task(gw.entities["service_dnsmasq_restart"].async_press())
    second = asyncio.create_task(gw.entities["service_firewall"].async_turn_off())
    await until(lambda: len(started) == 2, "both calls started")
    held = world.store.loop.lock_holder(world.rid)
    assert held is not None and held.source == "button.service_restart"
    gate.set()
    await first
    # the second press still runs: the lock stays
    await asyncio.gather(second)
    assert world.store.loop.lock_holder(world.rid) is None
    assert [_data(e)["lock"] for e in world.audits()] == ["taken", "joined"]


async def test_the_last_press_releases_the_shared_lock(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    gates = {"dnsmasq": asyncio.Event(), "firewall": asyncio.Event()}
    started: list[str] = []
    real = gw.api.control_service

    async def slow(name: str, action: str) -> bool:
        started.append(name)
        await gates[name].wait()
        return await real(name, action)

    gw.api.control_service = slow
    first = asyncio.create_task(gw.entities["service_dnsmasq_restart"].async_press())
    second = asyncio.create_task(gw.entities["service_firewall"].async_turn_off())
    await until(lambda: len(started) == 2, "both calls started")
    held = world.store.loop.lock_holder(world.rid)
    gates["dnsmasq"].set()
    await first
    assert world.store.loop.lock_holder(world.rid) is held
    gates["firewall"].set()
    await second
    assert world.store.loop.lock_holder(world.rid) is None
    # a new press takes a new lock
    assert await record(gw, ACTIONS[:1])
    assert [_data(e)["lock"] for e in world.audits()] == ["taken", "joined", "taken"]


async def test_a_lock_an_admin_removed_is_not_released_by_the_old_press(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    gates = {"dnsmasq": asyncio.Event(), "firewall": asyncio.Event()}
    real = gw.api.control_service

    async def slow(name: str, action: str) -> bool:
        await gates[name].wait()
        return await real(name, action)

    gw.api.control_service = slow
    first = asyncio.create_task(gw.entities["service_dnsmasq_restart"].async_press())
    await until(lambda: world.store.loop.lock_holder(world.rid), "first lock")
    assert world.store.admin_force_release_lock(world.rid, actor="admin", ts=T0 + 1)
    second = asyncio.create_task(gw.entities["service_firewall"].async_turn_off())
    await until(lambda: world.store.loop.lock_holder(world.rid), "second lock")
    new = world.store.loop.lock_holder(world.rid)
    assert new is not None
    gates["dnsmasq"].set()
    await first
    # the first press's lock is gone; it must not free the second's
    assert world.store.loop.lock_holder(world.rid) is new
    gates["firewall"].set()
    await second
    assert world.store.loop.lock_holder(world.rid) is None
    assert [_data(e)["lock"] for e in world.audits()] == ["taken", "taken"]


def _failing(exc: BaseException) -> Callable[..., Any]:
    async def call(*_a: Any, **_k: Any) -> Any:
        raise exc

    return call


@pytest.mark.parametrize(
    ("key", "method", "api_method", "exc"),
    [
        ("service_dnsmasq", "async_turn_on", "control_service", TimeoutError()),
        ("service_dnsmasq", "async_turn_off", "control_service", RuntimeError("x")),
        ("wifi_ssid_lan_5g", "async_turn_off", "set_wifi_state", TimeoutError()),
        ("reload_wifi", "async_press", "reload_wifi", RuntimeError("x")),
        ("service_dnsmasq_restart", "async_press", "control_service", TimeoutError()),
    ],
)
async def test_the_lock_is_released_when_the_call_raises(
    disks: Any, key: str, method: str, api_method: str, exc: BaseException
) -> None:
    world = await World().start()
    gw = await world.gateway()
    setattr(gw.api, api_method, _failing(exc))
    with pytest.raises(type(exc)):
        await getattr(gw.entities[key], method)()
    assert world.store.loop.lock_holder(world.rid) is None
    [event] = world.audits()
    assert _data(event)["result"] == "failed"
    assert str(event.result) == "failure"
    assert len(world.store.loop.external_writes) == 1
    assert gw.calls == []  # no refresh after a raising call, as on main


async def test_the_reboot_button_swallows_errors_and_releases_the_lock(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    gw.api.reboot = _failing(RuntimeError("ssh"))
    await gw.entities["reboot"].async_press()  # never raises into HA, as on main
    assert world.store.loop.lock_holder(world.rid) is None
    [event] = world.audits()
    assert _data(event)["result"] == "failed"


@pytest.mark.parametrize(
    ("key", "method", "api_method"),
    [
        ("reboot", "async_press", "reboot"),
        ("reload_wifi", "async_press", "reload_wifi"),
        ("service_dnsmasq_restart", "async_press", "control_service"),
        ("service_dnsmasq", "async_turn_off", "control_service"),
        ("service_dnsmasq", "async_turn_on", "control_service"),
        ("wifi_ssid_lan_5g", "async_turn_off", "set_wifi_state"),
        ("wifi_ssid_lan_5g", "async_turn_on", "set_wifi_state"),
    ],
)
async def test_a_call_the_router_did_not_accept_is_audited_failed(
    disks: Any, key: str, method: str, api_method: str
) -> None:
    world = await World().start()
    gw = await world.gateway()
    setattr(gw.api, api_method, AsyncMock(return_value=False))
    await getattr(gw.entities[key], method)()
    assert world.store.loop.lock_holder(world.rid) is None
    [event] = world.audits()
    assert _data(event)["result"] == "failed"
    assert str(event.severity) == "warning"


async def test_the_lock_is_released_when_the_press_is_cancelled(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    entered = asyncio.Event()

    async def hang(*_a: Any, **_k: Any) -> bool:
        entered.set()
        await asyncio.Event().wait()
        return True

    gw.api.reboot = hang
    task = asyncio.create_task(gw.entities["reboot"].async_press())
    await until(entered.is_set, "reboot call entered")
    assert world.store.loop.lock_holder(world.rid) is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert world.store.loop.lock_holder(world.rid) is None
    [event] = world.audits()
    assert _data(event)["result"] == "failed"


async def test_a_wifi_switch_without_uci_section_is_not_a_router_write(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    await world.engine_holds()
    switch = gw.entities["wifi_ssid_lan_5g"]
    switch._uci_section = ""
    await switch.async_turn_off()  # a warning, as on main; nothing to refuse
    assert gw.calls == []
    assert world.audits() == []


# --- case 4: the audit entry ----------------------------------------------------------------


async def test_the_audit_names_the_user_and_the_router_and_nothing_else(
    disks: Any,
) -> None:
    world = await World().start()
    gw = await world.gateway()
    context = Context(user_id=ADMIN_ID)
    for key in ("wifi_ssid_lan_5g", "service_dnsmasq", "reboot"):
        gw.entities[key]._context = context
    with _no_ssh():
        await gw.entities["wifi_ssid_lan_5g"].async_turn_off()
        await gw.entities["service_dnsmasq"].async_turn_off()
        await gw.entities["reboot"].async_press()
    events = world.audits()
    assert len(events) == 3
    for event in events:
        assert event.type == hg.EVENT_MANUAL_ACTION
        assert event.source == "self_healing"
        assert event.actor.user_id == ADMIN_ID
        assert event.actor.context_id == context.id
        assert event.router_id == world.rid
        assert set(_data(event)) == {
            "action",
            "target",
            "result",
            "on_hold",
            "hold_reason",
            "lock",
        }
        text = json.dumps(event.to_dict())
        for secret in (
            "192.0.2.1",
            "GW",
            "Home",
            "IoT",
            "lan_5g",
            kit.CLIENT_MAC,
            SECRET,
            "gw-office",
        ):
            assert secret not in text
    write_text = json.dumps([w.to_dict() for w in world.store.loop.external_writes])
    assert "lan_5g" not in write_text


async def test_an_automation_press_has_no_user(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    gw.entities["reboot"]._context = Context(parent_id="01AUTOMATION")
    await record(gw, ACTIONS[1:2])
    [event] = world.audits()
    assert event.actor.user_id is None
    assert str(event.actor.kind) == "automation"


async def test_the_audit_works_when_the_self_healing_prefix_is_registered(
    disks: Any,
) -> None:
    world = await World().start()
    world.api.register_event_prefix("self_healing.", module="self_healing")
    gw = await world.gateway()
    await record(gw, ACTIONS[:1])
    assert len(world.audits()) == 1


def test_targets_are_a_closed_set() -> None:
    assert hg.audit_target("dnsmasq") == "dnsmasq"
    assert hg.audit_target("wifi") == "wifi"
    assert hg.audit_target("system") == "system"
    assert hg.audit_target("lan_5g") == "other"
    assert hg.audit_target("odhcpd") == "other"
    assert {str(a) for a in hg.ManualAction} == {
        "service.restart",
        "service.start",
        "service.stop",
        "wifi.reload",
        "wifi.enable",
        "wifi.disable",
        "router.reboot",
    }
    assert set(hg.LOCK_SOURCES) == set(hg.ManualAction)


# --- case 5: module off, no Core, a broken audit --------------------------------------------


async def test_without_core_and_engine_the_press_is_as_on_main(disks: Any) -> None:
    world = await World().start(core=False, engine=False)
    gw = await world.gateway()
    assert await record(gw) == EXPECTED_MAIN


async def test_an_engine_without_core_takes_no_lock(disks: Any) -> None:
    world = await World().start(core=False)
    gw = await world.gateway()
    taken = MagicMock(side_effect=AssertionError("no lock without a router id"))
    world.store.try_external_lock = taken  # type: ignore[method-assign]
    assert await record(gw) == EXPECTED_MAIN


@pytest.mark.parametrize("off", ["not_loaded", "settings_off", "closed", "no_engine"])
async def test_module_off_never_refuses_and_takes_no_lock(disks: Any, off: str) -> None:
    world = await World().start()
    gw = await world.gateway()
    action_id = await world.engine_holds()
    if off == "not_loaded":
        world.engine.loaded = False
    elif off == "settings_off":
        world.store.set_settings(hm.HealSettings(enabled=False))
    elif off == "closed":
        world.engine.closed = True
    else:
        world.hass.data.pop(DATA_SELF_HEALING_ENGINE)
    assert await record(gw) == EXPECTED_MAIN
    assert world.store.loop.lock_holder(world.rid).action_id == action_id
    events = world.audits()
    assert len(events) == len(ACTIONS)
    assert {(_data(e)["lock"], _data(e)["on_hold"]) for e in events} == {
        ("none", False)
    }
    assert world.store.loop.external_writes == []


async def test_a_failing_audit_never_fails_the_press(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    with patch.object(
        type(world.api), "emit", MagicMock(side_effect=RuntimeError("audit down"))
    ):
        assert await record(gw) == EXPECTED_MAIN
    assert world.store.loop.lock_holder(world.rid) is None
    writes = world.store.loop.external_writes
    assert len(writes) == len(ACTIONS)
    assert {w.audit_ref for w in writes} == {None}


async def test_a_refused_prefix_never_fails_the_press(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    with patch.object(
        type(world.api),
        "register_event_prefix",
        MagicMock(side_effect=ValueError("taken")),
    ):
        assert await record(gw) == EXPECTED_MAIN
    assert world.audits() == []


async def test_a_slow_core_never_holds_the_press_up(disks: Any) -> None:
    world = await World().start(engine=False)
    gw = await world.gateway()

    async def never(*_a: Any, **_k: Any) -> Any:
        await asyncio.Event().wait()

    with (
        patch.object(hg, "AUDIT_LOOKUP_TIMEOUT_S", 0.01),
        patch(
            "custom_components.openwrt_router.config_api.async_get_configuration_api",
            never,
        ),
    ):
        assert await record(gw, ACTIONS[:2]) == {
            name: EXPECTED_MAIN[name] for name, _k, _m in ACTIONS[:2]
        }
    assert world.audits() == []


async def test_a_slow_actor_lookup_never_holds_the_press_up(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    gw.entities["reboot"]._context = Context(user_id=ADMIN_ID)

    async def never(*_a: Any, **_k: Any) -> Any:
        await asyncio.Event().wait()

    world.hass.auth.async_get_user = never
    with patch.object(hg, "AUDIT_LOOKUP_TIMEOUT_S", 0.01):
        assert await record(gw, ACTIONS[1:2]) == {
            "button.reboot": EXPECTED_MAIN["button.reboot"]
        }
    [event] = world.audits()
    assert event.actor is None
    assert world.store.loop.lock_holder(world.rid) is None


async def test_a_guard_error_falls_back_to_the_main_behaviour(disks: Any) -> None:
    world = await World().start()
    gw = await world.gateway()
    world.store.try_external_lock = MagicMock(  # type: ignore[method-assign]
        side_effect=RuntimeError("bug")
    )
    assert await record(gw) == EXPECTED_MAIN
    assert {_data(e)["lock"] for e in world.audits()} == {"none"}


# --- source scan ----------------------------------------------------------------------------

WRITES = {"reboot", "reload_wifi", "control_service", "set_wifi_state"}


def _guarded_write_calls(path: Path) -> tuple[list[int], list[int]]:
    """(lines of guarded api writes, lines of unguarded ones)."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    guarded: list[int] = []
    loose: list[int] = []

    def visit(node: ast.AST, inside: bool) -> None:
        if isinstance(node, ast.AsyncWith):
            inside = inside or any(
                isinstance(item.context_expr, ast.Call)
                and getattr(item.context_expr.func, "id", "") == "async_manual_action"
                for item in node.items
            )
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in WRITES
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "_api"
        ):
            (guarded if inside else loose).append(node.lineno)
        for child in ast.iter_child_nodes(node):
            visit(child, inside)

    visit(tree, False)
    return guarded, loose


@pytest.mark.parametrize(("module", "count"), [("button.py", 3), ("switch.py", 4)])
def test_every_router_write_of_the_entities_is_guarded(module: str, count: int) -> None:
    guarded, loose = _guarded_write_calls(PKG / module)
    assert loose == []
    assert len(guarded) == count


def test_the_guard_calls_no_router() -> None:
    source = inspect.getsource(hg)
    assert "_api." not in source
    assert "from .api" not in source and "import api" not in source
