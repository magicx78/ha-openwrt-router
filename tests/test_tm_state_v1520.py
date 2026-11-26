"""Network Time Machine, Phase D (1.52.0): the state at a moment.

Everything reaches the index through the engine's real write paths
(``tm_index_kit``: fake coordinators, the real fleet outage tracker, the
NI topology the engine reads); the state is then reconstructed by
``tm_state`` and checked exactly on a mark, just before and after it, in a
gap, before the start and past the retention. The store migration is
checked with a real 1.51.0 file (``fixtures/tm_store_v1510.json``, written
by the unchanged 1.51.0 code).
"""

from __future__ import annotations

import json
import random
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from core_testkit import FakeDisks
from tm_index_kit import RID, T0, iface, poll_data, world

from custom_components.openwrt_router import tm_state, tm_store
from custom_components.openwrt_router.const import TIME_MACHINE_STORE_KEY
from custom_components.openwrt_router.net_rules import Topology, Uplink
from custom_components.openwrt_router.tm_engine import GAP_MIN_S, REBASE_S, RouterState
from custom_components.openwrt_router.tm_marks import QUOTA_INFRA, RETENTION_S
from custom_components.openwrt_router.tm_sources import RouterMap

R1, R2, R3 = RID["r1"], RID["r2"], RID["r3"]
ROUTERS = RouterMap(
    {"r1": R1, "r2": R2, "r3": R3}, {R1: "Router 1", R2: "Router 2", R3: "Router 3"}
)
FIXTURE = Path(__file__).parent / "fixtures" / "tm_store_v1510.json"
MS = 0.001


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def tree(*, r3_parent: str = "r1", r2_gateway: bool = False) -> Topology:
    gateways = {"r1", "r2"} if r2_gateway else {"r1"}
    uplinks = {"r3": Uplink(r3_parent)}
    if not r2_gateway:
        uplinks["r2"] = Uplink("r1")
    return Topology(uplinks=uplinks, gateways=frozenset(gateways))


class Run:
    """Polls every router once a minute with its current radios."""

    def __init__(self, w: Any) -> None:
        self.w = w
        self.radios: dict[str, list[dict[str, Any]]] = {
            e.entry_id: [iface("phy1", 36)] for e in w.entries
        }
        self.failing: set[str] = set()

    def poll(self, *, step: float = 60.0) -> None:
        for entry_id, coord in self.w.coords.items():
            if entry_id in self.failing:
                coord.poll(ok=False)
            else:
                coord.poll(poll_data(*self.radios[entry_id]))
        self.w.clock.advance(step)

    def polls(self, n: int) -> None:
        for _ in range(n):
            self.poll()


async def snap(w: Any, now: float | None = None) -> tm_state.Snapshot:
    return await tm_state.async_snapshot(w.engine, w.clock.t if now is None else now)


def at(s: tm_state.Snapshot, rid: str, ts: float) -> dict[str, Any]:
    item, _n = tm_state.router_state(s, rid, ts, ROUTERS)
    return item


def reach(s: tm_state.Snapshot, rid: str, ts: float) -> Any:
    got = at(s, rid, ts)["reachable"]
    return got["value"] if got["reason"] is None else got["reason"]


def chans(s: tm_state.Snapshot, rid: str, ts: float) -> Any:
    radios = at(s, rid, ts)["radios"]
    if radios["state"] == "unknown":
        return radios["reason"]
    return {i["key"]: (i["channel"], i["state"]) for i in radios["items"]}


def uplink(s: tm_state.Snapshot, rid: str, ts: float) -> Any:
    got = at(s, rid, ts)["uplink"]
    if got["reason"] is not None:
        return got["reason"]
    return None if got["value"] is None else got["value"]["router_id"]


def role(s: tm_state.Snapshot, rid: str, ts: float) -> Any:
    got = at(s, rid, ts)["role"]
    return got["value"] if got["reason"] is None else got["reason"]


def one(w: Any, kind: str) -> Any:
    [mark] = w.marks(kind)
    return mark


# --- reconstruction through the real write paths ---------------------------------------


async def test_channel_change_exactly_before_and_after(disks) -> None:
    with world(disks) as w:
        await w.start()
        run = Run(w)
        run.polls(3)
        run.radios["r1"] = [iface("phy1", 44)]
        run.polls(3)
        change = one(w, "channel_changed")
        s = await snap(w)
        assert chans(s, R1, change.ts - MS) == {"5g0": (36, "up")}
        assert chans(s, R1, change.ts) == {"5g0": (44, "up")}
        assert chans(s, R1, change.ts + MS) == {"5g0": (44, "up")}
        assert chans(s, R1, T0) == {"5g0": (36, "up")}  # the first poll itself
        # before the start: nothing recorded; reachability like the radios
        assert chans(s, R1, T0 - MS) == "not_recorded"
        assert reach(s, R1, T0 - MS) == "not_recorded"
        assert reach(s, R1, change.ts) is True
        state = at(s, R1, change.ts)
        assert state["reachable"]["derived"] is True
        assert state["radios"]["derived"] is True
        # no topology read (NI not loaded): uplink and role unknown
        assert uplink(s, R1, change.ts) == "not_observed"
        # past the retention: unknown, never the old value
        later = await snap(w, now=w.clock.t + RETENTION_S + 60)
        assert reach(later, R1, change.ts) == "beyond_retention"
        assert chans(later, R1, change.ts) == "beyond_retention"


async def test_radio_off_and_on_and_the_width_after_it(disks) -> None:
    with world(disks) as w:
        await w.start()
        run = Run(w)
        two = [iface("phy0", 6, "2.4g", "HT20"), iface("phy1", 36)]
        run.radios["r1"] = list(two)
        run.polls(2)
        run.radios["r1"] = [iface("phy1", 36)]
        run.polls(3)
        run.radios["r1"] = [iface("phy0", 11, "2.4g", "HT40"), iface("phy1", 36)]
        run.polls(2)
        down, up = one(w, "radio_down"), one(w, "radio_up")
        s = await snap(w)
        assert chans(s, R1, down.ts - MS) == {"2.4g0": (6, "up"), "5g0": (36, "up")}
        assert chans(s, R1, down.ts) == {"2.4g0": (6, "down"), "5g0": (36, "up")}
        assert chans(s, R1, up.ts - MS) == {"2.4g0": (6, "down"), "5g0": (36, "up")}
        assert chans(s, R1, up.ts) == {"2.4g0": (11, "up"), "5g0": (36, "up")}
        [radio] = [
            i for i in at(s, R1, up.ts)["radios"]["items"] if i["band"] == "2.4g"
        ]
        assert radio["width"] is None  # not in the mark: unknown, not guessed


async def test_outage_and_observation_gap(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        run = Run(w)
        run.polls(2)
        # r2: polls fail, the tracker reports the outage from the first one
        first_fail = w.clock.t
        run.failing.add("r2")
        run.polls(3)
        w.tracker.report_down("r2", "timeout", datetime.fromtimestamp(first_fail, UTC))
        w.tracker._evaluate()
        run.polls(3)
        run.failing.discard("r2")
        w.up("r2")
        run.polls(2)
        # r1: polls fail for 5 minutes without an outage: an observation gap
        run.failing.add("r1")
        run.polls(5)
        run.failing.discard("r1")
        run.polls(2)
        down, gap = one(w, "router_down"), one(w, "observation_gap")
        assert (
            down.ts == pytest.approx(first_fail) and not w.marks("observation_gap")[1:]
        )
        s = await snap(w)
        assert reach(s, R2, down.ts - MS) is True
        assert reach(s, R2, down.ts) is False
        assert reach(s, R2, down.end - MS) is False
        assert reach(s, R2, down.end) is True
        assert at(s, R2, down.ts)["reachable"]["derived"] is False  # seen, not inferred
        # while down: radios and topology are unknown, not the last value
        assert chans(s, R2, down.ts + 1) == "router_down"
        assert uplink(s, R2, down.ts + 1) == "router_down"
        assert reach(s, R1, gap.ts - MS) is True
        assert reach(s, R1, gap.ts) == "observation_gap"
        assert chans(s, R1, gap.ts + 1) == "observation_gap"
        assert reach(s, R1, gap.end) is True
        assert reach(s, R2, gap.ts + 1) is True  # the gap is r1's only


async def test_fleet_outage_is_unreachable_from_ha(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        run = Run(w)
        run.polls(2)
        utc = w.clock.utc()
        w.tracker.report_down("r1", "timeout", utc)
        w.tracker.report_down("r2", "timeout", utc)
        w.tracker._evaluate()
        run.polls(2)
        w.up("r1")
        w.up("r2")
        run.polls(2)
        lan = one(w, "lan_down")
        s = await snap(w)
        state = at(s, R1, lan.ts + 1)["reachable"]
        assert (state["value"], state["derived"], state["reason"]) == (
            False,
            True,
            None,
        )
        assert reach(s, R1, lan.end) is True


async def test_uplink_and_role_changes_and_the_settling_window(disks) -> None:
    with world(disks, routers=3) as w:
        await w.start()
        run = Run(w)
        w.topology = tree()
        run.polls(20)
        w.topology = tree(r3_parent="r2")
        run.polls(20)
        w.topology = tree(r3_parent="r2", r2_gateway=True)
        run.polls(20)
        [change] = [m for m in w.marks("uplink_changed") if m.router == R3]
        turn = one(w, "router_role_changed")
        settled = T0 + 60  # the second poll settles the first read
        s = await snap(w)
        assert uplink(s, R3, settled - MS) == "not_observed"
        assert uplink(s, R3, settled) == R1 and role(s, R3, settled) == "node"
        assert role(s, R1, settled) == "gateway" and uplink(s, R1, settled) is None
        # a change is settled two polls after it began: from 15 minutes
        # before the first poll that saw it (``since``, 1.52.0 review B) up
        # to the mark the state is unknown, not the old value
        first = change.params["since"]
        assert first == change.ts - 60
        assert uplink(s, R3, change.ts - MS) == "settling"
        assert uplink(s, R3, first - tm_state.TOPOLOGY_SETTLE_S) == "settling"
        assert uplink(s, R3, first - tm_state.TOPOLOGY_SETTLE_S - MS) == R1
        assert uplink(s, R3, change.ts) == R2
        assert uplink(s, R3, change.ts + MS) == R2
        assert role(s, R2, turn.ts) == "gateway"
        assert turn.params["since"] == turn.ts - 60
        assert role(s, R2, turn.ts - 60 - tm_state.TOPOLOGY_SETTLE_S) == "settling"
        assert role(s, R2, turn.ts - 60 - tm_state.TOPOLOGY_SETTLE_S - MS) == "node"
        # r2 lost its uplink when it became a gateway
        assert uplink(s, R2, turn.ts + 60) is None


async def test_restart_gap_and_the_new_stretch(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        run = Run(w)
        w.topology = tree()
        run.polls(20)
        await w.ha_stop_and_write()
        stopped = w.stored["saved_at"]
        w.clock.advance(600)
        await w.start()
        run.radios["r1"] = [iface("phy1", 100)]  # changed while HA was down
        run.polls(20)
        gap = one(w, "ha_gap")
        s = await snap(w)
        assert reach(s, R1, stopped - 1) is True
        assert reach(s, R1, gap.ts + 1) == "ha_gap"
        assert chans(s, R1, gap.ts + 1) == "ha_gap"
        restarted = gap.end
        assert chans(s, R1, restarted) == {"5g0": (100, "up")}
        # the last 15 minutes before the stop: the uplink may have been
        # changing (no seamless next stretch)
        assert uplink(s, R2, stopped - 1) == "settling"
        assert uplink(s, R2, stopped - tm_state.TOPOLOGY_SETTLE_S - 1) == R1
        # the new stretch knows its uplink again after two polls
        assert uplink(s, R2, restarted + 1) == "not_observed"
        assert uplink(s, R2, restarted + 120) == R1
        assert [len(v) for v in w.engine.store.seen.values()] == [2, 2]


async def test_a_new_radio_splits_the_stretch_and_old_bases_roll_forward(disks) -> None:
    with world(disks) as w:
        await w.start()
        run = Run(w)
        w.topology = tree()
        run.polls(3)
        run.radios["r1"] = [iface("phy1", 36), iface("phy2", 1, "2.4g", "HT20")]
        added = w.clock.t
        run.polls(3)
        segs = w.engine.store.seen[R1]
        assert len(segs) == 2 and segs[1].start == pytest.approx(added)
        assert segs[1].topo_at == segs[1].start and segs[1].parent == ""
        s = await snap(w)
        assert chans(s, R1, added - MS) == {"5g0": (36, "up")}
        assert chans(s, R1, added) == {"2.4g0": (1, "up"), "5g0": (36, "up")}
        assert role(s, R1, added - MS) == "gateway"  # seamless: no settling
        # a day later the base rolls forward (no mark is needed from before
        # the 14 days); the state before it stays as it was
        w.clock.advance(REBASE_S)
        run.polls(2)
        assert len(w.engine.store.seen[R1]) == 3
        s = await snap(w)
        assert chans(s, R1, added + 60) == {"2.4g0": (1, "up"), "5g0": (36, "up")}
        later = await snap(w, now=w.engine.store.seen[R1][2].start + RETENTION_S - 1)
        assert chans(later, R1, w.clock.t) == {"2.4g0": (1, "up"), "5g0": (36, "up")}


async def test_evicted_marks_make_the_time_before_unknown(disks) -> None:
    with world(disks) as w:
        await w.start()
        run = Run(w)
        w.engine.index.quotas[QUOTA_INFRA] = 3
        run.polls(2)
        for channel in (40, 44, 48, 52, 56):
            run.radios["r1"] = [iface("phy1", channel)]
            run.poll()
        lost = w.engine.index.lost[QUOTA_INFRA]
        kept = w.marks("channel_changed")
        assert len(kept) < 5 and lost >= T0
        s = await snap(w)
        assert reach(s, R1, lost) == "evicted"
        assert chans(s, R1, lost) == "evicted"
        assert chans(s, R1, w.clock.t) == {"5g0": (56, "up")}


async def test_clear_history_starts_from_nothing(disks) -> None:
    from custom_components.openwrt_router.tm_engine import async_clear_history

    with world(disks) as w:
        for entry in w.entries:
            entry.options["time_machine_enabled"] = True
        await w.start()
        run = Run(w)
        w.topology = tree()
        run.polls(3)
        before = w.clock.t - 30
        await async_clear_history(w.hass, False)
        run.polls(2)
        assert w.engine.index.lost[QUOTA_INFRA] == pytest.approx(w.clock.t - 120)
        s = await snap(w)
        assert reach(s, R1, before) == "not_recorded"  # the record starts anew
        # the settled uplink and role go on across the cleared history
        assert role(s, R1, w.clock.t - 1) == "gateway"


# --- the store 1.1 -> 1.2 ----------------------------------------------------------------


async def test_a_real_1510_file_loads_unchanged_and_saves_as_12(tmp_path) -> None:
    """The file written by 1.51.0 (version 1, minor 1)."""
    from homeassistant.core import HomeAssistant

    old = json.loads(FIXTURE.read_text())
    assert (old["version"], old["minor_version"]) == (1, 1)
    hass = HomeAssistant(str(tmp_path))
    try:
        (tmp_path / ".storage").mkdir()
        path = tmp_path / ".storage" / TIME_MACHINE_STORE_KEY
        shutil.copy(FIXTURE, path)
        now = old["data"]["saved_at"] + 600
        store = tm_store.TimeMachineStore(hass, clock=lambda: now)
        loaded = await store.async_load()
        assert not loaded.failed and loaded.stop == "stop"
        assert loaded.saved_at == old["data"]["saved_at"]
        assert store.payload()["marks"] == old["data"]["marks"]
        assert store.coverage == old["data"]["coverage"]
        assert store.state == old["data"]["state"]
        # the new keys are absent in 1.1: empty, so the time before is unknown
        assert (store.seen, store.clients_cov, store.index.lost) == ({}, [], {})
        await store._store.async_save(store.payload())
        new = json.loads(path.read_text())
        assert (new["version"], new["minor_version"]) == (1, 2)
        assert new["data"]["marks"] == old["data"]["marks"]
        for key in ("routers", "coverage", "checkpoints", "state", "next_seq"):
            assert new["data"][key] == old["data"][key], key
        added = set(new["data"]) - set(old["data"])
        assert added == {"seen", "clients_cov", "lost"}
        s = tm_state.Snapshot(
            store.index,
            coverage=store.coverage,
            seen=store.seen,
            lost=store.index.lost,
            clients_cov=store.clients_cov,
            now=now,
        )
        # recorded outage of r2: from its marks; everything else unknown
        assert reach(s, R2, 1_800_000_400.0) is False
        assert reach(s, R1, 1_800_000_400.0) == "not_observed"
        assert chans(s, R1, 1_800_000_400.0) == "not_observed"
        assert s.clients_reason(1_800_000_400.0) == ("unknown", "not_recorded")
    finally:
        await hass.async_stop(force=True)


async def test_the_engine_on_a_1510_file(disks) -> None:
    old = json.loads(FIXTURE.read_text())
    with world(disks, routers=2) as w:
        w.disk.data = json.loads(json.dumps(old))
        w.clock.t = old["data"]["saved_at"] + 600
        await w.start()
        run = Run(w)
        run.radios["r1"] = [iface("phy1", 44)]  # as stored by 1.51.0
        run.radios["r2"] = [iface("phy1", 100)]
        run.polls(3)
        w.flush()
        assert w.disk.data["minor_version"] == 2
        seen = w.stored["seen"]
        assert set(seen) == {R1, R2} and all(len(v) == 1 for v in seen.values())
        s = await snap(w)
        assert reach(s, R1, old["data"]["saved_at"] - 60) == "not_observed"
        assert reach(s, R1, w.clock.t - 60) is True
        # the stored state of 1.51.0 goes on: no channel change invented
        assert not [m for m in w.marks("channel_changed") if m.ts > T0 + 720]
        assert chans(s, R2, w.clock.t - 60) == {"5g0": (100, "up")}


# --- the oracle ------------------------------------------------------------------------


def _expected(w: Any) -> dict[str, Any]:
    """The engine's own view after a step (what the state must equal)."""
    engine = w.engine
    out = {}
    for entry_id, router in engine.routers.items():
        rid = RID[entry_id]
        state = RouterState.parse(engine.store.state.get(rid))
        radios = {k: (c, wd, "up") for k, (c, wd) in state.radios.items()}
        for key in router.radio_down:
            radios[key] = (None, None, "down")
        out[rid] = {
            "reach": entry_id not in engine._outage_seq,
            "radios": radios,
            "pending": set(router.missing),
            "uplink": state.parent or None,
            "role": {"g": "gateway", "n": "node"}.get(state.role),
        }
    return out


class Episodes:
    """Failed-poll stretches of the oracle run, judged in hindsight."""

    def __init__(self) -> None:
        self.items: list[dict[str, Any]] = []

    def begin(self, rid: str, ts: float) -> dict[str, Any]:
        item = {"rid": rid, "start": ts, "end": None, "reported": False}
        self.items.append(item)
        return item

    def reach(self, rid: str, ts: float) -> Any:
        """True / False, or None: the answer must be unknown."""
        for item in self.items:
            end = item["end"] if item["end"] is not None else float("inf")
            if item["rid"] != rid or not item["start"] <= ts < end:
                continue
            if item["reported"]:
                return False  # the outage begins at the first failed poll
            if end - item["start"] < GAP_MIN_S:
                return True  # a short gap is dropped (engine rule)
            return None
        return True


def _check(
    s: tm_state.Snapshot, ts: float, want: dict[str, Any], episodes: Episodes
) -> int:
    """The answer equals the tracked state or says unknown (never wrong)."""
    told = 0
    for rid, exp in want.items():
        item = at(s, rid, ts)
        got = item["reachable"]
        expected = episodes.reach(rid, ts)
        if got["reason"] is None:
            assert expected is not None, (rid, ts, "must be unknown")
            assert got["value"] is expected, (rid, ts)
            told += 1
        if expected is not True:
            continue  # radios and topology are not polled meanwhile
        radios = item["radios"]
        if radios["state"] != "unknown":
            for radio in radios["items"]:
                key = radio["key"]
                if radio["state"] == "unknown" or key in exp["pending"]:
                    continue
                assert key in exp["radios"], (rid, ts, key)
                chan, width, state = exp["radios"][key]
                assert radio["state"] == state, (rid, ts, key)
                if state == "up":
                    assert radio["channel"] == chan, (rid, ts, key)
                    assert radio["width"] in (None, width), (rid, ts, key)
                told += 1
            if radios["state"] == "ok":
                shown = {r["key"] for r in radios["items"]}
                assert set(exp["radios"]) - exp["pending"] <= shown, (rid, ts)
        for name in ("uplink", "role"):
            got = item[name]
            if got["reason"] is None:
                value = got["value"]
                if name == "uplink" and value is not None:
                    value = value["router_id"]
                assert value == exp[name], (rid, ts, name)
                told += 1
    return told


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5, 6])
async def test_randomised_oracle_never_tells_something_wrong(disks, seed) -> None:
    rnd = random.Random(seed)
    with world(disks, routers=3) as w:
        await w.start()
        run = Run(w)
        w.topology = tree()
        samples: list[tuple[float, float, dict[str, Any]]] = []
        episodes = Episodes()
        failing: dict[str, dict[str, Any]] = {}
        for step in range(160):
            for entry_id in ("r1", "r2", "r3"):
                radios = [iface("phy1", rnd.choice((36, 44, 100)))]
                if rnd.random() < 0.8:
                    radios.append(
                        iface(
                            "phy0",
                            rnd.choice((1, 6, 11)),
                            "2.4g",
                            rnd.choice(("HT20", None)),
                        )
                    )
                if rnd.random() < 0.15:
                    radios.append(iface("phy2", 149))
                if rnd.random() < 0.7:
                    run.radios[entry_id] = radios
            event = rnd.random()
            started = w.clock.t
            if event < 0.05:
                w.topology = tree(
                    r3_parent=rnd.choice(("r1", "r2")), r2_gateway=rnd.random() < 0.3
                )
            elif event < 0.09 and not failing:
                victim = rnd.choice(("r2", "r3"))
                failing[victim] = episodes.begin(RID[victim], started)
                run.failing.add(victim)
            elif (
                event < 0.12
                and failing
                and not next(iter(failing.values()))["reported"]
            ):
                victim, item = next(iter(failing.items()))
                since = datetime.fromtimestamp(item["start"], UTC)
                w.tracker.report_down(victim, "timeout", since)
                w.tracker._evaluate()
                item["reported"] = True
            elif event < 0.16 and failing:
                victim, item = failing.popitem()
                run.failing.discard(victim)
                w.up(victim)
                item["end"] = started  # this step's poll answers again
            elif event < 0.17 and step > 40 and not failing:
                await w.ha_stop_and_write()
                w.clock.advance(rnd.choice((30, 400)))
                await w.start()
                started = w.clock.t
            run.poll(step=rnd.choice((30.0, 60.0, 61.5, 300.0)))
            samples.append((started, w.clock.t, _expected(w)))
        s = await snap(w)
        told = 0
        for i, (started, ended, want) in enumerate(samples):
            # the value after a step holds until the next step's poll
            told += _check(s, started, want, episodes)
            inside = started + rnd.random() * (ended - started)
            told += _check(s, inside, want, episodes)
            if i:
                told += _check(s, started - MS, samples[i - 1][2], episodes)
        assert told > 1000  # most answers are known, not "unknown"
        print(f"\n[time machine] oracle seed {seed}: {told} values checked")
