"""1.52.0 review: a randomised oracle of the state at a moment.

Three routers live through 400 poll rounds of a seeded random world: channel,
width and radio changes, new radios, uplink and role changes, failing polls
with and without a reported outage, restarts (clean and unclean), flushes,
and per mode: ``base``; ``evict`` (an infrastructure quota of 25 marks);
``clear`` ("Verlauf löschen" at random moments); ``remove`` (a router removed
from HA and added again); ``jumpfwd`` (the wall clock jumps ahead).

The truth is what the polls saw (the inputs), never the engine's state. Every
answer of ``tm_state.router_state`` at each poll, just before and after it
and at a random moment between two polls must be that truth or say
"unknown" (a reason). Tolerated as documented: a radio missing at one poll
only (debounce), a topology the next poll did not confirm, a failed stretch
shorter than ``GAP_MIN_S`` without a report. Fixed seeds (among them 4 and
33 of the review, 32 of the clear mode) keep it repeatable.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from datetime import UTC, datetime

import pytest
from core_testkit import FakeDisks
from tm_index_kit import RID, T0, iface, poll_data, world

from custom_components.openwrt_router import tm_state
from custom_components.openwrt_router.channel_plan import radios_from_ap_interfaces
from custom_components.openwrt_router.net_rules import Topology, Uplink
from custom_components.openwrt_router.tm_engine import (
    GAP_MIN_S,
    async_clear_history,
    async_remove_router,
    radio_keys,
)
from custom_components.openwrt_router.tm_sources import RouterMap

E = ("r1", "r2", "r3")
ROUTERS = RouterMap({e: RID[e] for e in E}, {RID[e]: e for e in E})
INV = {RID[e]: e for e in E}
MS = 0.001


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def topo_of(r3_parent, r2_gw):
    gws = {"r1", "r2"} if r2_gw else {"r1"}
    up = {"r3": Uplink(r3_parent)}
    if not r2_gw:
        up["r2"] = Uplink("r1")
    return Topology(uplinks=up, gateways=frozenset(gws))


def truth_topo(e, r3_parent, r2_gw):
    gws = {"r1", "r2"} if r2_gw else {"r1"}
    role = "gateway" if e in gws else "node"
    if e == "r3":
        parent = r3_parent
    elif e == "r2" and not r2_gw:
        parent = "r1"
    else:
        parent = None
    return (RID[parent] if parent else None), role


def keys_of(ifaces):
    return {
        k: (c, w)
        for k, (c, w, _p) in radio_keys(
            radios_from_ap_interfaces("", "", ifaces, [])
        ).items()
    }


class Truth:
    """What the polls saw: per router ``(t, ok, radio keys, topology, run)``."""

    def __init__(self):
        self.cleared = None
        self.polls = defaultdict(list)  # e -> [(t, ok, keys, topo, run)]
        self.runs = []  # [start, end]
        self.reported = defaultdict(list)  # e -> [(since, end)]
        self.no_rebuild = []

    def last_poll(self, e, t):
        best = None
        for p in self.polls[e]:
            if p[0] <= t:
                best = p
            else:
                break
        return best

    def run_at(self, t):
        for i, (a, b) in enumerate(self.runs):
            if a <= t and (b is None or t < b):
                return i
        return None


def classify(s, truth, t, findings, stats, ctx):
    run = truth.run_at(t)
    for e in E:
        rid = RID[e]
        item, _ = tm_state.router_state(s, rid, t, ROUTERS)
        reach = item["reachable"]
        p = truth.last_poll(e, t)
        valid = p is not None and run is not None and p[4] == run
        if truth.cleared is not None and t <= truth.cleared:
            valid = False
        if run is None or not valid:
            # HA not running or not polled in this run
            for name in ("reachable", "role", "uplink"):
                if item[name]["reason"] is None:
                    findings[f"{name}_known_without_observation"].append(
                        (e, t - T0, item[name], ctx)
                    )
            if item["radios"]["state"] != "unknown":
                findings["radios_known_without_observation"].append((e, t - T0, ctx))
            continue
        pt, ok, keys, topo, _run = p
        # reachability
        rep = any(a <= t and (b is None or t < b) for a, b in truth.reported[e])
        if reach["reason"] is None:
            stats["reach_known"] += 1
            if reach["value"] is True and not ok:
                # documented: a failed stretch < GAP_MIN_S without report
                # leaves no gap
                fail_start = pt
                for q in reversed(truth.polls[e]):
                    if q[0] > pt:
                        continue
                    if q[1]:
                        break
                    fail_start = q[0]
                nxt = next((q for q in truth.polls[e] if q[0] > pt and q[1]), None)
                if nxt is not None and nxt[0] - fail_start < GAP_MIN_S and not rep:
                    stats["reach_true_short_gap_documented"] += 1
                else:
                    findings["reach_true_but_failed"].append((e, t - T0, ctx))
            if reach["value"] is False and ok and not rep:
                findings["reach_false_but_ok"].append((e, t - T0, ctx))
        if not ok:
            continue
        # radios: truth = keys at the last ok poll
        prev = None
        for q in truth.polls[e]:
            if q[0] >= pt:
                break
            if q[1]:
                prev = q
        rb = item["radios"]
        if rb["state"] != "unknown":
            for r in rb["items"]:
                if r["state"] == "unknown":
                    continue
                stats["radio_known"] += 1
                k = r["key"]
                if r["state"] == "up":
                    if k not in keys:
                        # pending: missing at this poll only (debounce)
                        if prev is None or prev[4] != p[4] or k in prev[2]:
                            stats["radio_pending_tolerated"] += 1
                            continue
                        findings["radio_up_but_absent"].append((e, t - T0, k, ctx))
                    elif keys[k][0] != r["channel"]:
                        findings["radio_wrong_channel"].append(
                            (e, t - T0, k, r["channel"], keys[k][0], ctx)
                        )
                    elif r["width"] is not None and r["width"] != keys[k][1]:
                        findings["radio_wrong_width"].append(
                            (e, t - T0, k, r["width"], keys[k][1], ctx)
                        )
                elif r["state"] == "down" and k in keys:
                    findings["radio_down_but_present"].append((e, t - T0, k, ctx))
            if rb["state"] == "ok":
                shown = {r["key"] for r in rb["items"]}
                miss = set(keys) - shown
                if miss:
                    findings["radio_ok_but_incomplete"].append(
                        (e, t - T0, sorted(miss), ctx)
                    )
        # topology
        want_parent, want_role = topo
        nxt_ok = next((q for q in truth.polls[e] if q[0] > pt and q[1]), None)
        if nxt_ok is None or nxt_ok[4] != p[4] or nxt_ok[3] != topo:
            stats["topo_unconfirmed_tolerated"] += 1
            return_topo = True
        else:
            return_topo = False
        if return_topo:
            continue
        up, role = item["uplink"], item["role"]
        if up["reason"] is None:
            stats["topo_known"] += 1
            got = None if up["value"] is None else up["value"]["router_id"]
            if got != want_parent:
                findings["uplink_wrong"].append(
                    (e, t - T0, got and INV[got], want_parent and INV[want_parent], ctx)
                )
        if role["reason"] is None and role["value"] != want_role:
            findings["role_wrong"].append((e, t - T0, role["value"], want_role, ctx))


STEPS = 400
SEEDS = (1, 2, 3, 4, 5, 8, 13, 21, 32, 33, 34, 40)
MODES = ("base", "evict", "clear", "remove", "jumpfwd")


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("seed", SEEDS)
async def test_state_oracle_is_the_truth_or_unknown(disks, mode, seed):
    MODE = mode
    rnd = random.Random(seed)
    findings = defaultdict(list)
    stats = Counter()
    truth = Truth()
    with world(disks, routers=3) as w:
        await w.start()
        if MODE == "evict":
            w.engine.index.quotas = {**w.engine.index.quotas, "infrastructure": 25}
        truth.runs.append([w.clock.t, None])
        run_no = 0
        removed = set()
        r3_parent, r2_gw = "r1", False
        w.topology = topo_of(r3_parent, r2_gw)
        phys = {e: {"phy1": (36, "HE80", "5g"), "phy0": (6, "HT20", "2.4g")} for e in E}
        failing = {}  # e -> first failed poll time
        reported = {}
        last_tick = w.clock.t
        sample_times = []
        for step in range(STEPS):
            ev = rnd.random()
            if MODE == "clear" and rnd.random() < 0.01:
                await async_clear_history(w.hass, clients_only=False)
                # truth: nothing before now is known any more
                truth.cleared = w.clock.t
            if MODE == "remove" and rnd.random() < 0.01 and "r3" not in failing:
                if "r3" not in removed:
                    w.engine.remove_entry("r3")
                    await async_remove_router(w.hass, RID["r3"])
                    removed.add("r3")
                    truth.polls["r3"] = []
                else:
                    w.engine.add_entry("r3", w.coords["r3"])
                    removed.discard("r3")
            if MODE == "jumpfwd" and rnd.random() < 0.01:
                w.clock.t += rnd.choice((400, 3000))
            # radio changes
            for e in E:
                if rnd.random() < 0.06:
                    phy = rnd.choice(list(phys[e]) or ["phy1"])
                    if phy in phys[e]:
                        _c, _ht, band = phys[e][phy]
                        if band == "5g":
                            phys[e][phy] = (
                                rnd.choice((36, 44, 100, 149)),
                                rnd.choice(("HE80", "HE40", "HE80")),
                                band,
                            )
                        else:
                            phys[e][phy] = (
                                rnd.choice((1, 6, 11)),
                                rnd.choice(("HT20", "HT40")),
                                band,
                            )
                if rnd.random() < 0.02 and "phy0" in phys[e]:
                    del phys[e]["phy0"]
                elif rnd.random() < 0.03 and "phy0" not in phys[e]:
                    phys[e]["phy0"] = (rnd.choice((1, 6, 11)), "HT20", "2.4g")
                if rnd.random() < 0.01 and "phy2" not in phys[e]:
                    phys[e]["phy2"] = (rnd.choice((52, 149)), "HE80", "5g")
                elif rnd.random() < 0.01 and "phy2" in phys[e]:
                    del phys[e]["phy2"]
            if ev < 0.04:
                r3_parent = rnd.choice(("r1", "r2"))
                r2_gw = rnd.random() < 0.3
                w.topology = topo_of(r3_parent, r2_gw)
            elif ev < 0.08 and len(failing) < 2:
                victim = rnd.choice([e for e in E if e not in failing])
                failing[victim] = None
            elif ev < 0.12 and failing:
                victim = rnd.choice(list(failing))
                if failing[victim] is not None and victim not in reported:
                    since = failing[victim]
                    w.tracker.report_down(
                        victim, "timeout", datetime.fromtimestamp(since, UTC)
                    )
                    w.tracker._evaluate()
                    reported[victim] = since
                    truth.reported[victim].append([since, None])
            elif ev < 0.17 and failing:
                victim = rnd.choice(list(failing))
                del failing[victim]
                if victim in reported:
                    w.up(victim)
                    truth.reported[victim][-1][1] = w.clock.t
                    del reported[victim]
            elif ev < 0.185 and step > 30 and not failing and not removed:
                clean = rnd.random() < 0.5
                if clean:
                    await w.ha_stop_and_write()
                else:
                    if w.disk.delayed and w.disk.delayed[-1][1] == 0:
                        w.flush()  # a delay-0 write happens at once
                    w.disk.delayed.clear()
                    w.engine.closed = True
                truth.runs[-1][1] = w.clock.t
                w.clock.advance(rnd.choice((30, 200, 400, 1500)))
                await w.start()
                if MODE == "evict":
                    w.engine.index.quotas = {
                        **w.engine.index.quotas,
                        "infrastructure": 25,
                    }
                truth.runs.append([w.clock.t, None])
                run_no += 1
                last_tick = w.clock.t
            elif ev < 0.20:
                w.flush()
            # one poll round
            now = w.clock.t
            for e in E:
                if e in removed:
                    continue
                ifaces = [
                    iface(p, c, b, ht) for p, (c, ht, b) in sorted(phys[e].items())
                ]
                ok = e not in failing
                if ok:
                    w.coords[e].poll(poll_data(*ifaces))
                else:
                    if failing[e] is None:
                        failing[e] = now
                    w.coords[e].poll(ok=False)
                truth.polls[e].append(
                    (
                        now,
                        ok,
                        keys_of(ifaces) if ifaces else {},
                        truth_topo(e, r3_parent, r2_gw),
                        run_no,
                    )
                )
            sample_times.append(now)
            step_s = rnd.choice((30.0, 60.0, 60.0, 61.5, 300.0))
            w.clock.advance(step_s)
            if w.clock.t - last_tick >= 300:
                w.engine.tick()
                last_tick = w.clock.t
        s = await tm_state.async_snapshot(w.engine, w.clock.t)
        for i, t in enumerate(sample_times):
            ctx = (seed, i)
            classify(s, truth, t, findings, stats, ctx)
            classify(s, truth, t + MS, findings, stats, ctx)
            classify(s, truth, t - MS, findings, stats, ctx)
            if i + 1 < len(sample_times):
                classify(
                    s,
                    truth,
                    t + rnd.random() * (sample_times[i + 1] - t),
                    findings,
                    stats,
                    ctx,
                )
        for a, b in truth.runs:
            if b is not None:
                classify(s, truth, b + 1, findings, stats, ("gap", seed))
        classify(s, truth, truth.runs[0][0] - 10, findings, stats, ("before", seed))
    summary = {k: len(v) for k, v in findings.items()}
    print(f"\nseed {seed} stats {dict(stats)} findings {summary}")
    for k, v in findings.items():
        print("  ", k, v[:3])
    assert not findings, summary
