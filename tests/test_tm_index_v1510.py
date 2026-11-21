"""Network Time Machine, Phase B (1.51.0): the own index.

Marks reach the index only through the engine's listeners (fleet outage
tracker, coordinator listeners, audit subscription, tick, HA stop) and the
store through its real write path (``tm_store.payload`` on
``core_testkit.FakeDisks``; one test writes a real file with HA's Store).
Kit: ``tm_index_kit``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from core_testkit import FakeDisks
from tm_index_kit import KEY, RID, SECRETS, T0, iface, poll_data, world

from custom_components.openwrt_router import tm_marks, tm_store
from custom_components.openwrt_router.const import (
    DATA_TIME_MACHINE_ENGINE,
    OPTION_TIME_MACHINE_CLIENTS,
    OPTION_TIME_MACHINE_ENABLED,
    TIME_MACHINE_STORE_KEY,
)
from custom_components.openwrt_router.net_rules import Topology, Uplink
from custom_components.openwrt_router.tm_engine import (
    GAP_MIN_S,
    async_apply_time_machine_options,
    async_get_time_machine,
    async_release_time_machine,
    async_setup_time_machine,
)
from custom_components.openwrt_router.tm_marks import MarkIndex

R1, R2 = RID["r1"], RID["r2"]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def kinds(w: Any) -> list[str]:
    return [m.kind for m in w.marks()]


# --- off is off -------------------------------------------------------------------------


async def test_off_by_default_nothing_is_created(disks) -> None:
    """Hard requirement 1: no store, listener, task, router call or entity."""
    with world(disks) as w:
        coord = w.coords["r1"]
        tracker_listeners = list(w.tracker._listeners)
        for entry in w.entries:  # options of a 1.50.0 entry: nothing set
            entry.runtime_data = SimpleNamespace(coordinator=coord)
            await async_setup_time_machine(w.hass, entry)
        assert async_get_time_machine(w.hass) is None
        assert DATA_TIME_MACHINE_ENGINE not in w.hass.data
        assert TIME_MACHINE_STORE_KEY not in w.disks.disks
        assert coord._listeners == {}
        assert w.tracker._listeners == tracker_listeners
        assert w.api.listeners == [] and w.api.key_calls == 0
        w.hass.async_create_background_task.assert_not_called()
        # the client switch alone does nothing either (it needs the TM switch)
        w.entries[0].options[OPTION_TIME_MACHINE_CLIENTS] = True
        await async_setup_time_machine(w.hass, w.entries[0])
        assert async_get_time_machine(w.hass) is None
        assert TIME_MACHINE_STORE_KEY not in w.disks.disks


async def test_switch_on_and_off_through_the_options(disks) -> None:
    with world(disks) as w:
        coord = w.coords["r1"]
        w.entries[0].runtime_data = SimpleNamespace(coordinator=coord)
        await async_apply_time_machine_options(w.hass, on=True, clients=False)
        engine = async_get_time_machine(w.hass)
        assert engine is not None and engine.loaded and len(coord._listeners) == 1
        assert w.api.key_calls == 0  # no client key without the client switch
        assert kinds(SimpleNamespace(marks=lambda: list(engine.index))) == [
            "tm_started"
        ]
        await async_apply_time_machine_options(w.hass, on=False, clients=False)
        assert async_get_time_machine(w.hass) is None
        assert coord._listeners == {}
        stored = w.stored
        assert stored["stop"] == "disabled"
        assert [r.split("|")[2] for r in stored["marks"]] == [
            "tm_started",
            "tm_disabled",
        ]


# --- outages and gaps --------------------------------------------------------------------


async def test_router_outage_is_an_interval_with_its_end(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.clock.advance(60)
        w.coords["r1"].poll(ok=False)  # first failed poll: observation gap
        assert [m.kind for m in w.marks() if m.router == R1] == ["observation_gap"]
        w.clock.advance(120)
        w.down("r1")  # reported by the real tracker: the outage takes over
        w.coords["r1"].poll(ok=False)
        down = w.marks("router_down")
        assert len(down) == 1 and down[0].router == R1 and down[0].is_open
        assert down[0].code == "timeout" and not w.marks("observation_gap")
        w.clock.advance(600)
        w.up("r1")
        w.coords["r1"].poll()
        assert down[0].end_state == "closed" and down[0].end == pytest.approx(T0 + 780)
        [up] = w.marks("router_up")
        assert up.params["duration_s"] == 600 and up.router == R1
        assert not w.marks("observation_gap")  # no gap invented after the outage


async def test_observation_gaps_short_ones_are_dropped(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.coords["r1"].poll(ok=False)
        w.clock.advance(GAP_MIN_S - 1)
        w.coords["r1"].poll()
        assert not w.marks("observation_gap")
        assert w.engine.counters["gaps_dropped"] == 1
        w.coords["r1"].poll(ok=False)
        w.coords["r1"].poll(ok=False)  # repeated failures: one gap
        w.clock.advance(300)
        w.coords["r1"].poll()
        [gap] = w.marks("observation_gap")
        assert gap.end_state == "closed" and gap.params["gap_s"] == 300


async def test_fleet_outage_is_one_lan_interval(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.tracker.report_down("r1", "timeout", w.clock.utc())
        w.tracker.report_down("r2", "timeout", w.clock.utc())
        w.tracker._evaluate()
        [lan] = w.marks("lan_down")
        assert lan.router is None and lan.is_open and lan.severity == "critical"
        assert not w.marks("router_down")
        w.clock.advance(90)
        w.up("r1")
        assert lan.end_state == "closed"
        assert w.marks("lan_up")[0].params["duration_s"] == 90


# --- radios, fingerprint, topology ------------------------------------------------------


async def test_channel_change_dfs_radio_gone_and_back(disks) -> None:
    with world(disks) as w:
        await w.start()
        coord = w.coords["r1"]
        two = (iface("phy0", 6, "2.4g", "HT20"), iface("phy1", 36))
        coord.poll(poll_data(*two))
        assert not w.marks("channel_changed")  # the first poll only learns
        dfs = {
            "last_event": {
                "type": "channel_change",
                "radio": "phy1",
                "new_channel": 100,
                "dfs_related": True,
                "time": "t1",
            }
        }
        coord.poll(poll_data(two[0], iface("phy1", 100), dfs=dfs))
        [change] = w.marks("channel_changed")
        assert change.code == "dfs" and change.severity == "warning"
        assert change.params == {
            "band": 5,
            "channel_from": 36,
            "channel_to": 100,
            "width_from": 80,
            "width_to": 80,
            "dfs": 1,
        }
        # no htmode: the width is unknown and kept, no change invented
        coord.poll(poll_data(two[0], iface("phy1", 100, htmode=None)))
        assert len(w.marks("channel_changed")) == 1
        # an empty poll (iwinfo failed) keeps the radios
        coord.poll(poll_data())
        coord.poll(poll_data())
        assert not w.marks("radio_down")
        # 2.4 GHz gone for two polls: radio_down from the first missing poll
        w.clock.advance(60)
        first_missing = w.clock.t
        coord.poll(poll_data(iface("phy1", 100)))
        assert not w.marks("radio_down")
        w.clock.advance(60)
        coord.poll(poll_data(iface("phy1", 100)))
        [down] = w.marks("radio_down")
        assert down.ts == pytest.approx(first_missing) and down.is_open
        assert down.params == {"band": 2.4, "channel": 6}
        w.clock.advance(60)
        coord.poll(poll_data(*two))
        assert down.end_state == "closed"
        assert w.marks("radio_up")[0].params["duration_s"] == 120


async def test_fingerprint_needs_two_equal_polls(disks) -> None:
    with world(disks) as w:
        await w.start()
        coord = w.coords["r1"]
        coord.poll(poll_data(iface("phy1", 36), hostname="a"))
        coord.poll(poll_data(iface("phy1", 36), hostname="a"))
        assert not w.marks("config_fingerprint_changed")  # first value learned
        coord.poll(poll_data(iface("phy1", 36), hostname="b"))
        coord.poll(poll_data(iface("phy1", 36), hostname="a"))  # a blip
        assert not w.marks("config_fingerprint_changed")
        coord.poll(poll_data(iface("phy1", 36), hostname="b"))
        coord.poll(poll_data(iface("phy1", 36), hostname="b"))
        [fp] = w.marks("config_fingerprint_changed")
        assert fp.router == R1 and fp.params == {}


async def test_uplink_and_role_from_the_topology(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        w.topology = Topology(
            uplinks={"r2": Uplink("r1"), "r3": Uplink("r1")},
            gateways=frozenset({"r1"}),
        )
        for _ in range(2):
            for c in w.coords.values():
                c.poll()
        assert not w.marks("uplink_changed")
        w.topology = Topology(
            uplinks={"r2": Uplink("r1"), "r3": Uplink("r2")},
            gateways=frozenset({"r1"}),
        )
        w.coords["r3"].poll()
        assert not w.marks("uplink_changed")  # debounced
        w.coords["r3"].poll()
        [up] = w.marks("uplink_changed")
        assert up.router == RID["r3"] and up.peers == (R1, R2)
        # a remembered edge changes nothing
        w.topology = Topology(
            uplinks={"r2": Uplink("r1"), "r3": Uplink("r1", remembered=True)},
            gateways=frozenset({"r1"}),
        )
        for _ in range(3):
            w.coords["r3"].poll()
        assert len(w.marks("uplink_changed")) == 1
        assert not w.marks("router_role_changed")


# --- audit references ------------------------------------------------------------------


def audit_event(event_id: str, event_type: str, **kw: Any) -> Any:
    return SimpleNamespace(
        event_id=event_id,
        ts=kw.pop("ts"),
        type=event_type,
        severity=kw.pop("severity", "warning"),
        router_id=kw.pop("router_id", R1),
        data=kw.pop("data", {}),
        client_ref=kw.pop("client_ref", None),
    )


async def test_audit_entries_become_references_without_clients(disks) -> None:
    with world(disks) as w:
        await w.start()
        assert w.api.prefixes == [("time_machine.", "time_machine")]
        ts = w.clock.utc()
        w.api.publish(audit_event("evt_1", "configuration.drift_detected", ts=ts))
        w.api.publish(audit_event("evt_1", "configuration.drift_detected", ts=ts))
        w.api.publish(audit_event("evt_2", "router.capabilities_changed", ts=ts))
        w.api.publish(
            audit_event("evt_3", "wifi_rf.event", ts=ts, client_ref="cli_" + "a" * 16)
        )
        w.api.publish(audit_event("evt_4", "time_machine.store_recovered", ts=ts))
        refs = w.marks("config_drift")
        assert [m.ref for m in refs] == [("audit", "evt_1")]  # once, no admin noise
        assert len(w.marks()) == 2  # tm_started + the reference


# --- restarts, clock, retention --------------------------------------------------------


async def test_restart_closes_open_intervals_and_marks_the_ha_gap(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.down("r1")
        w.clock.advance(100)
        await w.ha_stop_and_write()
        assert w.stored["stop"] == "stop"
        stopped = w.clock.t
        w.clock.advance(3600)
        engine = await w.start()
        down, again = w.marks("router_down")
        assert (down.end_state, down.end) == ("unknown", pytest.approx(stopped))
        [gap] = w.marks("ha_gap")
        assert gap.ts == pytest.approx(stopped) and gap.end == pytest.approx(w.clock.t)
        assert gap.params == {"gap_s": 3600, "clean": 1} and gap.derived is False
        # the tracker still has the router down: a new outage interval opens
        # (a new process has a new tracker; here it is the same one): from the
        # start of this run on, derived, never over the closed interval
        assert again.is_open and again.derived is True
        assert again.ts == pytest.approx(w.clock.t)
        assert engine.store.coverage[-2][1] == pytest.approx(stopped)


async def test_crash_leaves_an_unclean_derived_gap(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.engine.tick()  # heartbeat
        w.flush()
        beat = w.stored["saved_at"]
        w.engine.closed = True  # the process died, no stop write
        w.clock.advance(7200)
        await w.start()
        [gap] = w.marks("ha_gap")
        assert gap.ts == pytest.approx(beat) and gap.derived is True
        assert (gap.code, gap.severity, gap.params["clean"]) == (
            "unclean",
            "warning",
            0,
        )


async def test_clock_backwards_and_jumps_are_marked_not_gaps(disks) -> None:
    with world(disks) as w:
        await w.start()
        await w.ha_stop_and_write()
        w.clock.t -= 3600  # the clock went back while HA was down
        await w.start()
        assert not w.marks("ha_gap")
        [shift] = w.marks("clock_shift")
        assert shift.code == "backwards" and shift.params["shift_s"] < -3000
        w.clock.t += 7200  # wall time jumps, monotonic does not
        w.engine.tick()
        assert [m.code for m in w.marks("clock_shift")] == ["backwards", "forwards"]


async def test_switched_off_and_on_again(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.down("r1")
        await w.engine.async_stop("disabled")
        [down] = w.marks("router_down")
        assert down.end_state == "unknown"
        assert w.stored["stop"] == "disabled"
        w.clock.advance(500)
        await w.start()
        assert [m.code for m in w.marks("tm_started")] == ["first_start", "switched_on"]
        assert not w.marks("ha_gap")


async def test_removed_router_ends_its_intervals_as_unknown(disks) -> None:
    with world(disks, routers=2) as w:
        w.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = True
        await w.start()
        w.down("r1")
        w.coords["r2"].poll(ok=False)
        await async_release_time_machine(w.hass, "r1")
        assert w.marks("router_down")[0].end_state == "unknown"
        assert w.engine.loaded and not w.engine.closed  # r2 still there
        assert w.coords["r1"]._listeners == {}
        await async_release_time_machine(w.hass, "r2")
        assert async_get_time_machine(w.hass) is None
        assert w.stored["stop"] == "unloaded"
        assert w.coords["r2"]._listeners == {}


async def test_retention_drops_closed_marks_after_14_days(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.down("r1")
        w.clock.advance(60)
        w.up("r1")
        w.clock.advance(14 * 86_400 + 120)
        w.engine.tick()
        assert not w.marks("router_up") and not w.marks("router_down")
        assert w.engine.index.counters["pruned"] >= 2


async def test_daily_checkpoint_carries_codes_only(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.coords["r1"].poll()
        w.coords["r1"].poll()
        w.engine.tick()
        w.clock.advance(86_400)
        w.engine.tick()
        w.flush()
        rows = w.stored["checkpoints"]
        assert [r.split("|")[1] for r in rows] == ["start", "day"]
        assert R1 in rows[1] and "u=1" in rows[1]


# --- store ---------------------------------------------------------------------------


async def test_broken_store_starts_empty_with_a_copy_and_a_mark(disks) -> None:
    with world(disks) as w:
        w.disk.data = {"version": 1, "minor_version": 1, "key": "x", "data": []}
        await w.start()
        assert kinds(w) == ["tm_store_recovered"]
        assert w.disk.backups == 1
        assert w.api.emitted[0][0] == "time_machine.store_recovered"
        assert w.engine.load_failed is True


async def test_newer_store_version_is_kept_as_bak(disks) -> None:
    with world(disks) as w:
        w.disk.data = {"version": 2, "minor_version": 1, "key": "x", "data": {}}
        await w.start()
        assert kinds(w) == ["tm_store_recovered"] and w.disk.backups == 1


async def test_bad_rows_are_skipped_not_the_file(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.down("r1")
        await w.ha_stop_and_write()
        data = w.stored
        data["marks"].append("not|a|mark")
        data["marks"].append("1|2|router_down|0|i|x|||02:00:5e:00:00:01||||0")
        w.disk.data["data"] = data
        await w.start()
        assert w.marks("router_down")
        assert w.engine.index.counters["bad_marks"] == 2


def test_quotas_never_evict_each_other_and_count() -> None:
    index = MarkIndex()
    for i in range(3001):
        index.add(ts=T0 + i, kind="channel_changed", router=R1)
    for i in range(12_000):
        index.add(
            ts=T0 + i,
            kind="client_roam",
            router=R1,
            client=f"{i % 100:016x}",
        )
    assert index.count("infrastructure") == 3000
    assert index.count("clients") == 10000
    assert index.counters["evicted_infrastructure"] == 1
    assert index.counters["evicted_clients"] == 1999 + 1
    assert len(index) == 13000 <= tm_marks.MAX_MARKS


def test_one_client_storm_is_folded_per_day() -> None:
    index = MarkIndex()
    for i in range(500):
        index.add(ts=T0 + i, kind="client_roam", router=R1, client="ab" * 8)
    [flap] = [m for m in index if m.kind == "client_flapping"]
    assert flap.params == {"suppressed": 300, "cap": 200}
    assert index.count("clients") == 201
    assert index.counters["client_day_capped"] == 300


async def test_size_limit_trims_clients_first_in_one_pass(disks) -> None:
    with world(disks) as w:
        engine = await w.start()
        for i in range(200):
            engine.index.add(ts=T0 + i, kind="router_up", router=R1, code="reachable")
        for i in range(2000):
            engine.index.add(
                ts=T0 + i, kind="client_roam", router=R1, client=f"{i:016x}"
            )
        full = tm_store.store_bytes(engine.store._build())
        engine.store.max_bytes = full - 20_000
        w.engine.store.schedule()
        w.flush()
        stored = w.stored
        assert tm_store.store_bytes(stored) <= engine.store.max_bytes
        assert len([r for r in stored["marks"] if "|router_up|" in r]) == 200
        assert engine.store.counters["trimmed_rows"] > 0
        # far over the limit even without clients: the last good file stays
        before = dict(stored)
        engine.store.max_bytes = 100
        engine.store.schedule()
        w.flush()
        assert w.stored == before and engine.store.counters["save_over_size"] == 1


async def test_real_file_has_no_identifiers_and_the_measured_size(tmp_path) -> None:
    """HA's own Store (indented JSON, atomic, private) on a real disk."""
    from homeassistant.core import HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    try:
        store = tm_store.TimeMachineStore(hass, clock=lambda: T0)
        await store.async_load()
        index = store.index
        index.add(
            ts=T0, kind="router_down", router=R1, code="timeout", end_state="open"
        )
        index.add(
            ts=T0,
            kind="client_session",
            router=R1,
            client="0123456789abcdef",
            end_state="open",
            params={"band": 5},
        )
        index.add(ts=T0, kind="uplink_changed", router=R1, peers=(R2, None))
        store.state[R1] = "0123456789abcdef|5g0=36/80|" + R2 + "|n"
        payload = store.payload()
        await store._store.async_save(payload)
        path = tmp_path / ".storage" / TIME_MACHINE_STORE_KEY
        raw = path.read_bytes()
        assert len(raw) == store.last_bytes == tm_store.store_bytes(payload)
        text = raw.decode()
        for needle in (*SECRETS, KEY.decode()):
            assert needle not in text, needle
        assert oct(path.stat().st_mode & 0o777) == "0o600"
        again = tm_store.TimeMachineStore(hass, clock=lambda: T0)
        await again.async_load()
        assert sorted(m.kind for m in again.index) == sorted(
            ["router_down", "client_session", "uplink_changed"]
        )
        assert json.loads(text)["data"]["routers"] == [R1, R2]
    finally:
        await hass.async_stop(force=True)


async def test_a_full_store_stays_under_the_limit(disks) -> None:
    """Estimate of the full store: 15000 marks with params under 2.5 MB."""
    with world(disks) as w:
        engine = await w.start()
        for i in range(3000):
            engine.index.add(
                ts=T0 + i,
                kind="channel_changed",
                router=R1,
                code="channel",
                params={
                    "band": 5,
                    "channel_from": 36,
                    "channel_to": 100,
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
        size = tm_store.store_bytes(engine.store._build())
        assert len(engine.index) == 15000
        assert size < tm_store.STORE_MAX_BYTES, size
        print(f"\n[time machine] full store: {size} bytes")


# --- background tasks only while on -------------------------------------------------


async def test_ha_stop_listener_and_tick_exist_only_while_on(disks) -> None:
    with world(disks) as w:
        w.hass.bus.async_listen_once = MagicMock(return_value=MagicMock())
        engine = await w.start()
        assert w.hass.bus.async_listen_once.call_count == 1
        unsub = w.hass.bus.async_listen_once.return_value
        await engine.async_stop("disabled")
        unsub.assert_called_once()
        assert w.api.listeners == []


async def test_writes_are_delayed_and_bundled(disks) -> None:
    """Hard requirement 5: no write in the event path, one delayed write armed."""
    with world(disks, routers=2) as w:
        await w.start()
        disk = w.disk
        saves = len(disk.saves)
        assert [delay for _f, delay in disk.delayed] == [tm_store.SAVE_DELAY_S]
        for _ in range(5):
            w.clock.advance(60)
            w.down("r1")
            w.coords["r1"].poll(ok=False)
            w.clock.advance(60)
            w.up("r1")
            w.coords["r1"].poll()
        assert len(w.marks("router_down")) == 5
        assert len(disk.saves) == saves  # nothing written yet
        assert len(disk.delayed) == 1  # one write armed for all of it
        w.flush()
        assert len(disk.saves) == saves + 1
        assert len(w.stored["marks"]) == len(w.engine.index)
        w.clock.advance(60)
        w.down("r2")
        w.coords["r2"].poll(ok=False)
        assert len(disk.delayed) == 1 and len(disk.saves) == saves + 1


async def test_heartbeat_write_every_15_minutes_without_changes(disks) -> None:
    """``saved_at`` stays recent without changes (the start of an unclean gap)."""
    with world(disks) as w:
        await w.start()
        w.engine.tick()
        w.flush()
        armed = []
        for _ in range(6):
            w.clock.advance(300)
            w.engine.tick()
            armed.append(len(w.disk.delayed))
            w.flush()
        assert armed == [0, 0, 1, 0, 0, 1]
