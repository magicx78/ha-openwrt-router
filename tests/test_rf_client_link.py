"""WiFi RF Intelligence and Client Stability (Q5, release 1.48.0 part 2).

RF reads the client history (read only) for its client windows and the
roaming analysis; Client Stability gets a busy channel as a hint only. RF
on or off never changes a Client Stability rating. Mocks only: no router,
no Home Assistant, no network.
"""

from __future__ import annotations

import random
from types import SimpleNamespace
from typing import Any

import pytest
from rf_center_kit import (
    MAC_A,
    RID1,
    RID2,
    Clock,
    FakeCoordinator,
    ap,
    client,
    entry,
    load,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)
from test_client_engine import M1, M2, line
from test_client_engine import T0 as CT0
from test_client_engine import data as ni_data
from test_client_engine import setup as ni_setup
from test_diag_runtime import ni_disks  # noqa: F401 - fixture

from custom_components.openwrt_router import client_views, rf_client_link
from custom_components.openwrt_router.client_history import (
    Bucket,
    LastDisconnect,
    RingEntry,
)
from custom_components.openwrt_router.log_parser import (
    WIFI_DEAUTH,
    WIFI_DISCONNECTED,
)
from custom_components.openwrt_router.rf_client_link import (
    ClientHistoryFacts,
    client_facts,
    rf_hint,
    rf_hint_for_client,
    roaming_problems,
)
from custom_components.openwrt_router.rf_conflicts import RadioRef
from custom_components.openwrt_router.rf_models import (
    CapabilityState,
    Metric,
    metric_measured,
)

STATUS_A = load("hostapd_get_status_mt76_a.json")
SOURCE = "hostapd.get_status"


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


class FakeHistory:
    """The three public reads RF uses (``live``, ``ring``, ``recent_bucket``)."""

    def __init__(self, ring: dict[str, list[RingEntry]], bucket: Bucket) -> None:
        self._ring, self._bucket = ring, bucket
        self.reads: list[str] = []

    def live(self, mac: str) -> Any:
        self.reads.append("live")
        if mac not in self._ring:
            return None
        return SimpleNamespace(session_start=CT0 - 7200)

    def ring(self, mac: str) -> tuple[RingEntry, ...]:
        self.reads.append("ring")
        return tuple(self._ring.get(mac, ()))

    def recent_bucket(self, mac: str, start: float, end: float) -> Bucket:
        self.reads.append("recent_bucket")
        return self._bucket


def _samples(now: float, minutes: int, ap_: str = "gw", rate: int | None = 86_000):
    return [
        RingEntry(now - 60 * m, ap_, "5g", -60, "online", True, 1000, rate)
        for m in range(minutes, -1, -1)
    ]


BUCKET = Bucket(dc_error=1, dc_inactivity=1, dc_unknown=1, dc_leave=4, dc_infra=2)


# --- client window ----------------------------------------------------------------


def test_q5_history_facts_unknown_until_watched() -> None:
    now = CT0
    fresh = FakeHistory({M1: _samples(now, 20)}, BUCKET)  # 20 of 60 minutes
    facts = client_facts(fresh, M1, "gw", now, 3600)
    assert facts == ClientHistoryFacts(disconnects=None, rate_tx_mean=86_000)
    watched = FakeHistory({M1: _samples(now, 50)}, BUCKET)
    facts = client_facts(watched, M1, "gw", now, 3600)
    assert facts.disconnects == 3  # error + inactivity + unknown; no leave/infra
    other_router = client_facts(watched, M1, "ap2", now, 3600)
    assert other_router.rate_tx_mean is None  # no samples on that router
    no_rate = FakeHistory({M1: _samples(now, 50, rate=None)}, BUCKET)
    assert client_facts(no_rate, M1, "gw", now, 3600).rate_tx_mean is None
    assert client_facts(watched, M2, "gw", now, 3600) is None  # unknown client
    assert set(watched.reads) <= {"live", "ring", "recent_bucket"}  # read only


def _rf_run(history: Any, monkeypatch: Any, seed: int) -> Any:
    rng = random.Random(seed)
    signal = rng.randint(-85, -45)
    busy = rng.uniform(0.05, 0.95)

    async def run() -> Any:
        coord = FakeCoordinator(api="gw")
        center, clock, reader = await new_center(
            rf_hass(),
            (entry("gw", options("get_status")), coord),
            rids={"gw": RID1},
            clock=Clock(CT0 - 1200),
        )
        center.capability_of = lambda _rid, _name: (True, None)
        counters = {"time": 1_000_000, "busy": 100_000}

        def status() -> dict[str, Any]:
            counters["time"] += 300_000
            counters["busy"] += int(300_000 * busy)
            airtime = {"time": counters["time"], "time_busy": counters["busy"]}
            return {**STATUS_A, "airtime": airtime}

        reader.answers[("get_status", "phy1-ap0")] = status
        monkeypatch.setattr(rf_client_link, "history_of", lambda _h: history)
        clients = [client(MAC_A, signal=signal)]
        for i in range(5):
            await poll(center, coord, poll_data(uptime=1000 + 300 * i, clients=clients))
            clock.advance(300)
        (result,) = center.results.values()
        return result, center.fleet.health[result.ref], center.fleet.coverage

    return run()


@pytest.mark.parametrize("seed", range(8))
async def test_q5_history_feeds_the_rf_window_and_never_lowers_a_rating(
    disk, monkeypatch, seed: int
) -> None:
    """A confirming source (history with no RF problem) never lowers RF health."""
    without, base, base_cov = await _rf_run(None, monkeypatch, seed)
    calm = Bucket(dc_leave=1)
    history = FakeHistory({MAC_A: _samples(CT0, 55, rate=500_000)}, calm)
    fed, more, more_cov = await _rf_run(history, monkeypatch, seed)
    (before,) = without.assessments
    (after,) = fed.assessments
    assert {"disconnects", "rate_tx_mean"} <= set(before.missing)
    assert "disconnects" not in after.missing and "rate_tx_mean" not in after.missing
    assert more_cov >= base_cov
    if base.score is None:
        assert more.score is None or more.coverage > base.coverage
    else:
        assert more.score is not None and more.score >= base.score
    assert (more.score is None) == (more.grade == "unknown")


async def test_q5_broken_history_leaves_the_window_unknown(disk, monkeypatch) -> None:
    class Broken:
        def live(self, _mac: str) -> Any:
            raise RuntimeError("damaged")

    result, _health, _cov = await _rf_run(Broken(), monkeypatch, 0)
    (assessment,) = result.assessments
    assert "disconnects" in assessment.missing


# --- roaming ---------------------------------------------------------------------


def _roam_center(*band_radios: tuple[str, str, str]) -> Any:
    """Routers gw/ap2 with RF on; results (router_id, radio_id, band)."""
    on = SimpleNamespace(enabled=True)
    results = {
        RadioRef(rid, radio): SimpleNamespace(radio=SimpleNamespace(band=band))
        for rid, radio, band in band_radios
    }
    return SimpleNamespace(
        routers={
            "gw": SimpleNamespace(options=on, router_id=RID1),
            "ap2": SimpleNamespace(options=on, router_id=RID2),
        },
        results=results,
    )


def _pingpong(now: float, switches: int) -> list[RingEntry]:
    out = []
    for i in range(switches + 1):
        ap_ = "gw" if i % 2 == 0 else "ap2"
        out.append(RingEntry(now - 60 * (switches - i), ap_, "5g", -62, "online"))
    return out


def test_q5_roaming_problems_from_history_samples() -> None:
    center = _roam_center((RID1, "radio1", "5g"), (RID2, "radio1", "5g"))
    history = FakeHistory(
        {M1: _pingpong(CT0, 6), M2: _samples(CT0, 30)}, Bucket()
    )  # M1 flaps gw <-> ap2, M2 stays
    found = roaming_problems(center, history, [M1, M2], CT0)
    assert found.count == 1 and found.flapping == 1 and found.roams == 6
    attrs = found.as_dict()
    assert attrs["source"] == "client_history" and attrs["clients_checked"] == 2
    assert M1 not in repr(attrs)
    # no history: unknown, never 0
    assert roaming_problems(center, None, [M1], CT0).count is None


def test_q5_unknown_radios_are_not_guessed() -> None:
    # ap2 has two 5 GHz radios: the move cannot be mapped, so it is left out
    center = _roam_center(
        (RID1, "radio1", "5g"), (RID2, "radio1", "5g"), (RID2, "radio2", "5g")
    )
    history = FakeHistory({M1: _pingpong(CT0, 6)}, Bucket())
    found = roaming_problems(center, history, [M1], CT0)
    assert found.roams == 0 and found.count == 0


# --- the hint ---------------------------------------------------------------------


def _hint_center(util: Metric | None, *, sustained: bool = False, **kw: Any) -> Any:
    ref = RadioRef(RID1, "radio1")
    result = SimpleNamespace(
        ref=ref,
        radio=SimpleNamespace(band="5g"),
        metrics={"utilization": util},
        summary=SimpleNamespace(sustained_overload=sustained),
    )
    return SimpleNamespace(
        enabled=kw.get("enabled", True),
        status=kw.get("status", "ready"),
        routers={
            "gw": SimpleNamespace(options=SimpleNamespace(enabled=True), router_id=RID1)
        },
        results={ref: result},
    )


def test_q5_busy_channel_is_a_hint_with_source_and_time() -> None:
    busy = metric_measured(91.0, SOURCE, measured_at=CT0)
    hint = rf_hint(_hint_center(busy), "gw", "5g", CT0 - 120)
    assert hint == {
        "kind": "channel_busy",
        "hint_only": True,
        "radio_id": "radio1",
        "band": "5g",
        "utilization_pct": 91.0,
        "sustained": False,
        "source": SOURCE,
        "measured_at": CT0,
    }
    calm = metric_measured(30.0, SOURCE, measured_at=CT0)
    assert rf_hint(_hint_center(calm), "gw", "5g", CT0) is None
    assert rf_hint(_hint_center(calm, sustained=True), "gw", "5g", CT0) is not None
    stale = Metric(91.0, CapabilityState.STALE, SOURCE, CT0)
    assert rf_hint(_hint_center(stale), "gw", "5g", CT0) is None
    assert rf_hint(_hint_center(None), "gw", "5g", CT0) is None
    assert rf_hint(_hint_center(busy), "gw", "5g", CT0 - 3600) is None  # too old
    assert rf_hint(_hint_center(busy), "gw", "2.4g", CT0) is None  # other band
    assert rf_hint(_hint_center(busy, enabled=False), "gw", "5g", CT0) is None
    assert rf_hint(_hint_center(busy, status="not_ready"), "gw", "5g", CT0) is None
    assert rf_hint(None, "gw", "5g", CT0) is None


def test_q5_client_view_shows_the_hint_only(monkeypatch) -> None:
    live = SimpleNamespace(
        mac=M1,
        state="online",
        since=CT0,
        ap="gw",
        band="5g",
        rssi=-60,
        session_start=CT0,
        session_start_known=True,
        first_seen=CT0,
        last_seen=CT0,
        last_disconnect=LastDisconnect(CT0 - 60, "inactivity", "inactivity", True),
        hostname=None,
        ip=None,
        private_mac=False,
    )
    cs = SimpleNamespace(hass=SimpleNamespace(data={}), ssid=lambda _m: None)
    view = client_views._live(cs, live, lambda r: r)
    assert view["rf_hint"] is None  # no RF center: no hint, nothing else changes
    busy = metric_measured(91.0, SOURCE, measured_at=CT0)
    monkeypatch.setattr(
        "custom_components.openwrt_router.rf_center.async_get_rf_center",
        lambda _h: _hint_center(busy),
    )
    view = client_views._live(cs, live, lambda r: r)
    assert view["rf_hint"]["kind"] == "channel_busy"
    assert view["last_disconnect"]["class"] == "inactivity"  # not infrastructure
    assert rf_hint_for_client(cs.hass, SimpleNamespace(last_disconnect=None)) is None


# --- property: RF on or off never changes Client Stability ------------------------


async def _cs_run(rf_on: bool, seed: int) -> Any:
    rng = random.Random(seed)
    hass = rf_hass()
    engine, cs = await ni_setup(hass, "r1")
    coord = FakeCoordinator(api="r1")
    center, clock, reader = await new_center(
        hass,
        (entry("r1", options("get_status") if rf_on else {}), coord),
        rids={"r1": RID1},
        clock=Clock(CT0),
    )
    counters = {"time": 200_000_000, "time_busy": 60_000_000}
    busy = rng.uniform(0.05, 0.98)

    def status() -> dict[str, Any]:
        counters["time"] += 300_000
        counters["time_busy"] += int(300_000 * busy)
        return {**STATUS_A, "airtime": {**STATUS_A["airtime"], **counters}}

    reader.answers[("get_status", "phy1-ap0")] = status
    drops = set(rng.sample(range(3, 15), 3))
    for i in range(16):
        listed = [] if i in drops else [{"mac": M1, "radio": "phy1-ap0", "signal": -60}]
        rf_clients = [client(M1, signal=rng.randint(-80, -50))] if listed else []
        await poll(
            center,
            coord,
            poll_data(uptime=1000 + 300 * i, aps=[ap()], clients=rf_clients),
        )
        kind = rng.choice((WIFI_DISCONNECTED, WIFI_DEAUTH))
        lines = (line(kind, i),) if i in drops else ()
        engine.ingest("r1", ni_data(listed, lines), clock(), 300.0)
        clock.advance(300)
    now = clock()
    out = (
        cs.score(M1, now),
        cs.window(M1, now, 24),
        cs.history.transitions(M1),
        cs.infra_routers(now),
        [(i.type, i.scope_key, i.status) for i in engine.machine.incidents()],
    )
    center.close()
    return out


@pytest.mark.parametrize("seed", range(4))
async def test_q5_rf_on_or_off_never_changes_client_stability(
    disk,
    ni_disks,  # noqa: F811
    seed: int,
) -> None:
    on = await _cs_run(True, seed)
    off = await _cs_run(False, seed)
    assert on[0] is not None
    assert on == off
