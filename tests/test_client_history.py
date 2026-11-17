"""Tests for the client stability history (B1): client_history.py."""

from __future__ import annotations

import ast
import itertools
import json
from pathlib import Path

import pytest

from custom_components.openwrt_router import client_history as ch
from custom_components.openwrt_router.client_history import (
    BUCKET_FIELDS,
    DC_ERROR,
    DC_INACTIVITY,
    DC_INFRA,
    DC_LEAVE,
    DC_UNKNOWN,
    EV_ASSOC_FAIL,
    EV_AUTH_FAIL,
    EV_BAND_CHANGE,
    EV_CONNECT,
    EV_DHCP_FAIL,
    EV_DISCONNECT,
    EV_RECONNECT,
    EV_ROAM,
    STATE_GRACE,
    STATE_OFFLINE,
    STATE_ONLINE,
    STATE_UNKNOWN,
    TR_BLIP,
    TR_END,
    TR_GAP,
    TR_MOVE,
    TR_RESUME,
    TR_START,
    Bucket,
    ClientEvent,
    ClientHistory,
    ClientObs,
    PollInput,
    classify_disconnect,
    normalize_mac,
    pack_bucket,
    roam_grace,
    sum_buckets,
    unpack_bucket,
)

M1 = "AA:BB:CC:00:00:01"
M2 = "AA:BB:CC:00:00:02"
M3 = "AA:BB:CC:00:00:03"
PRIV = "02:BB:CC:00:00:09"
PUB = "00:BB:CC:00:00:05"  # globally unique (M1..M3 have the local bit)
R1 = "router_a"
R2 = "router_b"
R3 = "router_c"
I = 60.0  # poll interval
T0 = 1_800_000_000.0  # exact hour border (500000 * 3600)
H0 = int(T0 // 3600)
N = len(BUCKET_FIELDS)


def obs(mac: str = M1, rssi: int | None = -55, **kw) -> ClientObs:
    return ClientObs(mac=mac, rssi=rssi, **kw)


def poll(
    router: str,
    now: float,
    macs: list[str] | tuple[str, ...] = (),
    *,
    fresh: bool = True,
    events: tuple[ClientEvent, ...] = (),
    rssi: int | None = -55,
    **kw,
) -> PollInput:
    return PollInput(
        router=router,
        now=now,
        interval=I,
        fresh=fresh,
        clients=tuple(obs(m, rssi) for m in macs),
        events=events,
        **kw,
    )


def total(hist: ClientHistory, mac: str = M1) -> Bucket:
    return sum_buckets(b.bucket for b in hist.hours(mac))


def run(hist: ClientHistory, polls: list[PollInput]) -> None:
    for p in polls:
        hist.ingest(p)


# --- pure helpers -------------------------------------------------------------


def test_module_imports_no_home_assistant() -> None:
    tree = ast.parse(Path(ch.__file__).read_text(encoding="utf-8"))
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no package-relative imports"
            modules.append(node.module or "")
    assert not [m for m in modules if m.startswith("homeassistant")]
    assert set(modules) <= {
        "__future__",
        "itertools",
        "logging",
        "math",
        "re",
        "collections",
        "collections.abc",
        "dataclasses",
        "typing",
    }


def test_roam_grace() -> None:
    assert roam_grace(60) == 150
    assert roam_grace(120) == 240
    assert roam_grace(10) == 150


@pytest.mark.parametrize(
    ("reason", "infra", "expected"),
    [
        ("timeout", False, DC_ERROR),
        ("invalid_mic", False, DC_ERROR),
        ("psk", False, DC_ERROR),
        ("max_sta", False, DC_ERROR),
        ("blocked", False, DC_ERROR),
        ("other", False, DC_ERROR),
        ("failed", False, DC_ERROR),
        ("missing_acks", False, DC_ERROR),
        ("inactivity", False, DC_INACTIVITY),
        ("local_request", False, DC_LEAVE),
        (None, False, DC_UNKNOWN),
        ("something_new", False, DC_UNKNOWN),
        ("timeout", True, DC_INFRA),
        ("prune", False, None),
        ("prune", True, None),
    ],
)
def test_classify_disconnect(reason, infra, expected) -> None:
    assert classify_disconnect(reason, infra) == expected


def test_normalize_mac() -> None:
    assert normalize_mac("aa:bb:cc:00:00:01") == M1
    assert normalize_mac("aa-bb-cc-00-00-01") == M1
    assert normalize_mac("nope") is None
    assert normalize_mac(5) is None


def test_bucket_fields_order() -> None:
    assert BUCKET_FIELDS[:6] == (
        "observed_s",
        "online_s",
        "gap_s",
        "sessions",
        "associations",
        "longest_stable_s",
    )
    # the plan's 28 fields first, then the follow-up fields
    assert BUCKET_FIELDS[24:28] == (
        "ip_visible_n",
        "rate_rx_sum",
        "rate_tx_sum",
        "rate_n",
    )
    assert BUCKET_FIELDS[28:32] == (
        "online_2g_s",
        "online_5g_s",
        "online_6g_s",
        "session_s_sum",
    )
    assert BUCKET_FIELDS[32:] == tuple(
        f"sess_{n}"
        for n in (
            "lt5m",
            "lt15m",
            "lt30m",
            "lt1h",
            "lt2h",
            "lt4h",
            "lt6h",
            "lt12h",
            "lt24h",
            "ge24h",
        )
    )
    assert len(BUCKET_FIELDS) == 42 == len(Bucket._fields)
    assert tuple(Bucket._fields) == BUCKET_FIELDS


def test_pack_unpack_round_trip() -> None:
    values = [0] * N
    values[0] = 3600
    values[1] = 3600
    values[3] = 1
    values[19] = 60
    values[20] = -3300
    values[21] = -58
    values[22] = -52
    packed = pack_bucket(values)
    assert packed == "3600,3600,,1,,,,,,,,,,,,,,,,60,-3300,-58,-52"
    assert unpack_bucket(packed) == values
    assert pack_bucket([0] * N) == ""
    assert unpack_bucket("") == [0] * N
    # open buckets keep exact floats
    values[0] = 12.25
    assert unpack_bucket(pack_bucket(values)) == values


@pytest.mark.parametrize(
    "bad",
    [None, 5, "a,b", ",".join(["1"] * 43), "-5", "nan", "inf", "1" * 700],
)
def test_unpack_rejects_damaged(bad) -> None:
    assert unpack_bucket(bad) is None


def test_sum_buckets_min_max_longest() -> None:
    a = Bucket(
        observed_s=10, longest_stable_s=100, rssi_n=2, rssi_min=-70, rssi_max=-50
    )
    b = Bucket(observed_s=5, longest_stable_s=40, rssi_n=1, rssi_min=-80, rssi_max=-60)
    c = Bucket(observed_s=1)  # no RSSI: must not pull min/max to 0
    s = sum_buckets([a, b, c])
    assert s.observed_s == 16
    assert s.longest_stable_s == 100
    assert (s.rssi_n, s.rssi_min, s.rssi_max) == (3, -80, -50)
    assert sum_buckets([c, b]).rssi_max == -60


# --- state machine ------------------------------------------------------------


def test_stable_client() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(61)])
    live = hist.live(M1)
    assert live is not None
    assert live.state == STATE_ONLINE
    assert live.ap == R1
    assert live.session_start == T0
    assert live.session_start_known is False  # was already connected
    tot = total(hist)
    assert tot.online_s == tot.observed_s == 3600
    assert tot.gap_s == 0
    assert tot.sessions == 1
    assert tot.dc_error + tot.dc_unknown + tot.dc_leave + tot.dc_inactivity == 0
    assert tot.rssi_n == 61
    assert tot.rssi_min == tot.rssi_max == -55
    assert tot.weak_s == 0
    assert [t.kind for t in hist.transitions(M1)] == [TR_START]
    # the first hour is closed and folded into the day
    hours = hist.hours(M1)
    assert hours[0].hour == H0 and hours[0].closed
    assert hist.days(M1)[0].bucket.online_s == 3600
    meta = hist.day_meta(M1)[H0 // 24]
    assert meta.coverage_mask & (1 << (H0 % 24))


def test_unknown_mac_has_no_data_never_100_percent() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    assert hist.live(M2) is None
    assert hist.hours(M2) == []
    assert total(hist, M2).observed_s == 0  # availability must be "unknown"


def test_weak_signal_and_rates_and_ip() -> None:
    hist = ClientHistory()
    for k in range(4):
        hist.ingest(
            PollInput(
                router=R1,
                now=T0 + k * I,
                interval=I,
                fresh=True,
                clients=(
                    ClientObs(
                        M1,
                        rssi=-80,
                        rate_rx_kbit=52000,
                        rate_tx_kbit=12000,
                        ip_visible=k % 2 == 0,
                        hostname="test-device",
                        ip="192.0.2.10",
                    ),
                ),
            )
        )
    tot = total(hist)
    assert tot.weak_s == 180  # 3 intervals at <= -75 dBm
    assert tot.rate_n == 4 and tot.rate_rx_sum == 4 * 52000 and tot.rate_tx_sum == 48000
    assert tot.ip_visible_n == 2
    live = hist.live(M1)
    assert live.hostname == "test-device" and live.ip == "192.0.2.10"
    assert live.hostname_changed == T0


def test_reconnects_are_counted_only_from_events() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    # down and up within one poll: present in the list, two reconnect events
    ev = (
        ClientEvent(M1, EV_DISCONNECT, T0 + 20, R1, reason="timeout"),
        ClientEvent(M1, EV_CONNECT, T0 + 25, R1),
        ClientEvent(M1, EV_RECONNECT, T0 + 25, R1),
    )
    hist.ingest(poll(R1, T0 + I, [M1], events=ev))
    ev2 = (ClientEvent(M1, EV_RECONNECT, T0 + 90, R1),)
    hist.ingest(poll(R1, T0 + 2 * I, [M1], events=ev2))
    tot = total(hist)
    assert tot.reconnects == 2
    assert tot.associations == 1
    assert tot.dc_error == 0  # back before the poll: no disconnect
    assert tot.sessions == 1
    assert hist.live(M1).state == STATE_ONLINE


def test_disconnect_goes_offline_after_grace_backdated_with_reason() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])  # seen until T0+120
    down = (ClientEvent(M1, EV_DISCONNECT, T0 + 150, R1, reason="timeout"),)
    hist.ingest(poll(R1, T0 + 180, [], events=down))
    assert hist.live(M1).state == STATE_GRACE
    hist.ingest(poll(R1, T0 + 240, []))
    assert hist.live(M1).state == STATE_GRACE  # 90 s < 150 s
    hist.ingest(poll(R1, T0 + 300, []))  # 2+ polls and >= 150 s since the down
    live = hist.live(M1)
    assert live.state == STATE_OFFLINE
    assert live.last_disconnect.ts == T0 + 150
    assert live.last_disconnect.cls == DC_ERROR
    assert live.last_disconnect.reason == "timeout"
    tot = total(hist)
    assert tot.dc_error == 1
    assert tot.online_s == 150
    assert tot.observed_s == 300
    assert tot.longest_stable_s == 150
    kinds = [t.kind for t in hist.transitions(M1)]
    assert kinds == [TR_START, TR_END]
    end = hist.transitions(M1)[-1]
    assert end.ts == T0 + 150 and end.timed and end.cls == DC_ERROR
    # offline time keeps counting as observed (not as a gap)
    run(hist, [poll(R1, T0 + 300 + k * I, []) for k in range(1, 6)])
    tot = total(hist)
    assert tot.observed_s == 600 and tot.gap_s == 0


def test_offline_without_log_line_is_unknown_class() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(2)])  # last seen T0+60
    run(hist, [poll(R1, T0 + k * I, []) for k in range(2, 6)])
    live = hist.live(M1)
    assert live.state == STATE_OFFLINE
    assert live.last_disconnect.cls == DC_UNKNOWN
    assert live.last_disconnect.ts == T0 + 60  # grace from the previous poll
    assert total(hist).dc_unknown == 1


def test_blip_is_no_disconnect() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0, [M1]), poll(R1, T0 + 60, []), poll(R1, T0 + 120, [M1])])
    live = hist.live(M1)
    assert live.state == STATE_ONLINE and live.session_start == T0
    tot = total(hist)
    assert tot.online_s == 120 and tot.sessions == 1
    assert sum(getattr(tot, f) for f in BUCKET_FIELDS if f.startswith("dc_")) == 0
    assert TR_BLIP in [t.kind for t in hist.transitions(M1)]


def test_reconnect_after_offline_starts_new_session_at_connect_line() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1] if k < 2 else []) for k in range(6)])
    assert hist.live(M1).state == STATE_OFFLINE
    con = (ClientEvent(M1, EV_CONNECT, T0 + 330, R1),)
    hist.ingest(poll(R1, T0 + 360, [M1], events=con))
    live = hist.live(M1)
    assert live.state == STATE_ONLINE
    assert live.session_start == T0 + 330 and live.session_start_known
    tot = total(hist)
    assert tot.sessions == 2 and tot.associations == 1
    assert tot.online_s == 60 + 30
    assert tot.observed_s == 360


def test_normal_roaming_no_penalty_no_offline() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    hist.ingest(poll(R2, T0 + 10, []))
    hist.ingest(poll(R1, T0 + 60, [M1]))
    # roams to R2 at T0+90: prune line at R1 (= roaming), R2 lists it
    roam = (
        ClientEvent(M1, EV_DISCONNECT, T0 + 89, R1, reason="prune"),
        ClientEvent(M1, EV_ROAM, T0 + 90, R2, peer=R1),
    )
    hist.ingest(poll(R2, T0 + 100, [M1], events=roam))
    hist.ingest(poll(R1, T0 + 120, []))
    for k in range(2, 6):
        hist.ingest(poll(R2, T0 + 40 + k * I, [M1]))
        hist.ingest(poll(R1, T0 + 60 + k * I, []))
    live = hist.live(M1)
    assert live.state == STATE_ONLINE and live.ap == R2
    assert live.session_start == T0
    tot = total(hist)
    assert sum(getattr(tot, f) for f in BUCKET_FIELDS if f.startswith("dc_")) == 0
    assert tot.roams_in == 1 and tot.roams_out == 1 and tot.roam_flaps == 0
    assert tot.sessions == 1 and tot.gap_s == 0
    by_ap = {b.ap: b.bucket for b in hist.hours(M1)}
    assert by_ap[R1].online_s > 0 and by_ap[R2].online_s > 0
    assert by_ap[R2].roams_in == 1 and by_ap[R1].roams_out == 1
    assert TR_MOVE in [t.kind for t in hist.transitions(M1)]
    assert TR_END not in [t.kind for t in hist.transitions(M1)]


def test_roam_seen_first_at_old_ap_follows_other_fresh_list() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    hist.ingest(poll(R2, T0 + 30, [M1]))  # dual listing: stays at R1
    assert hist.live(M1).ap == R1
    hist.ingest(poll(R1, T0 + 60, []))  # gone at R1, R2 lists it -> move
    live = hist.live(M1)
    assert live.state == STATE_ONLINE and live.ap == R2
    assert total(hist).online_s == 60


def test_roaming_flapping_counted_but_no_disconnect() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    hist.ingest(poll(R2, T0 + 5, []))
    t = T0
    routers = [R1, R2]
    for k in range(1, 5):
        t = T0 + k * I
        new, old = routers[k % 2], routers[(k + 1) % 2]
        ev = (ClientEvent(M1, EV_ROAM, t - 5, new, peer=old),)
        hist.ingest(poll(new, t, [M1], events=ev))
        hist.ingest(poll(old, t + 5, []))
    tot = total(hist)
    assert tot.roams_in == 4 and tot.roams_out == 4
    assert tot.roam_flaps == 3  # every return within 600 s is a flap
    assert tot.dc_unknown == tot.dc_error == 0
    assert hist.live(M1).state == STATE_ONLINE
    # a return after more than 600 s is no flap
    ev = (ClientEvent(M1, EV_ROAM, t + 700, R1, peer=R2),)
    hist.ingest(poll(R1, t + 705, [M1], events=ev))
    assert total(hist).roam_flaps == 3


def test_band_change_and_failures_counted() -> None:
    hist = ClientHistory()
    ev = (
        ClientEvent(M1, EV_BAND_CHANGE, T0 + 1, R1),
        ClientEvent(M1, EV_AUTH_FAIL, T0 + 2, R1, count=3),
        ClientEvent(M1, EV_ASSOC_FAIL, T0 + 3, R1),
        ClientEvent(M1, EV_DHCP_FAIL, T0 + 4, R1),
        ClientEvent(M1, "nonsense", T0 + 4, R1),
        ClientEvent("bad", EV_AUTH_FAIL, T0 + 4, R1),
    )
    hist.ingest(poll(R1, T0 + 10, [M1], events=ev))
    tot = total(hist)
    assert (tot.band_changes, tot.auth_fail, tot.assoc_fail, tot.dhcp_fail) == (
        1,
        3,
        1,
        1,
    )


def test_auth_fail_of_never_connected_device_has_no_time() -> None:
    hist = ClientHistory()
    ev = (ClientEvent(M2, EV_AUTH_FAIL, T0, R1, count=2),)
    hist.ingest(poll(R1, T0, [M1], events=ev))
    hist.ingest(poll(R1, T0 + 60, [M1]))
    live = hist.live(M2)
    assert live.state == STATE_UNKNOWN
    tot = total(hist, M2)
    assert tot.auth_fail == 2 and tot.observed_s == 0 and tot.gap_s == 0


def test_ap_outage_is_gap_never_offline() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, M2]) for k in range(3)])  # until T0+120
    run(hist, [poll(R2, T0 + 125 + k * I, []) for k in range(10)])  # R1 silent
    for mac in (M1, M2):
        live = hist.live(mac)
        assert live.state == STATE_UNKNOWN
        assert live.last_disconnect is None
    # R1 back, M1 still there, M2 gone
    hist.ingest(poll(R1, T0 + 720, [M1]))
    live1 = hist.live(M1)
    assert live1.state == STATE_ONLINE and live1.session_start == T0
    tot1 = total(hist, M1)
    assert tot1.online_s == 120 and tot1.gap_s == 600 and tot1.observed_s == 120
    assert tot1.sessions == 1
    kinds = [t.kind for t in hist.transitions(M1)]
    assert kinds == [TR_START, TR_GAP, TR_RESUME]
    gap = hist.transitions(M1)[1]
    assert gap.ts == T0 + 120
    # M2: grace after the gap, then a disconnect with unknown time
    assert hist.live(M2).state == STATE_GRACE
    run(hist, [poll(R1, T0 + 720 + k * I, [M1]) for k in range(1, 4)])
    live2 = hist.live(M2)
    assert live2.state == STATE_OFFLINE
    assert live2.last_disconnect.timed is False
    assert live2.last_disconnect.ts == T0 + 120  # start of the gap
    assert live2.last_disconnect.cls == DC_UNKNOWN
    tot2 = total(hist, M2)
    assert tot2.gap_s == 600 and tot2.dc_unknown == 1


def test_ap_outage_with_ni_root_marks_infra() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(2)])
    hist.ingest(poll(R2, T0 + 200, [], down_routers=frozenset({R1})))
    assert hist.live(M1).state == STATE_UNKNOWN
    infra = {R1: "inc:router_a:1"}
    run(
        hist,
        [poll(R1, T0 + 300 + k * I, [], infra=infra) for k in range(4)],
    )
    live = hist.live(M1)
    assert live.state == STATE_OFFLINE
    assert live.last_disconnect.cls == DC_INFRA
    end = next(t for t in hist.transitions(M1) if t.kind == TR_END)
    assert end.incident_id == "inc:router_a:1"
    assert total(hist).dc_infra == 1 and total(hist).dc_unknown == 0


def test_poll_gap_is_measurement_gap() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])  # until T0+120
    # failed polls (no fresh client list)
    run(hist, [poll(R1, T0 + k * I, [], fresh=False) for k in range(3, 6)])
    assert hist.live(M1).state == STATE_UNKNOWN
    hist.ingest(poll(R1, T0 + 360, [M1]))
    tot = total(hist)
    assert tot.online_s == 120 and tot.gap_s == 240 and tot.dc_unknown == 0
    assert hist.live(M1).state == STATE_ONLINE


def test_long_silence_without_any_ingest_is_gap() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])
    hist.ingest(poll(R1, T0 + 120 + 1800, [M1]))  # next poll 30 min later
    tot = total(hist)
    assert tot.online_s == 120 and tot.gap_s == 1800
    assert hist.live(M1).state == STATE_ONLINE


def test_stale_table_is_gap_not_offline() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(2)])
    # R1 still answers but its table is reported as stale
    run(hist, [poll(R1, T0 + k * I, [M1], fresh=False) for k in range(2, 7)])
    live = hist.live(M1)
    assert live.state == STATE_UNKNOWN and live.last_disconnect is None
    assert total(hist).dc_unknown == 0


def test_two_tables_list_mac_time_counts_once() -> None:
    hist = ClientHistory()
    for k in range(6):
        hist.ingest(poll(R1, T0 + k * I, [M1]))
        hist.ingest(poll(R2, T0 + k * I + 30, [M1]))  # stale entry at R2
    tot = total(hist)
    assert tot.online_s == 300  # T0..T0+300, not doubled
    assert hist.live(M1).ap == R1
    by_ap = {b.ap for b in hist.hours(M1)}
    assert by_ap == {R1}


def test_loc_hint_decides_dual_listing() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, T0, [M1]))
    hist.ingest(poll(R2, T0 + 30, [M1], loc={M1: R2}))
    assert hist.live(M1).ap == R2


def test_offline_time_during_fleet_blind_window_is_gap() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1] if k < 2 else []) for k in range(6)])
    assert hist.live(M1).state == STATE_OFFLINE
    before = total(hist)
    hist.ingest(poll(R1, T0 + 300 + 3600, []))  # an hour without any data
    after = total(hist)
    assert after.observed_s - before.observed_s == 0
    assert after.gap_s - before.gap_s == 3600


def test_offline_time_during_failed_polls_of_whole_fleet_is_gap() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1] if k < 2 else []) for k in range(6)])
    assert hist.live(M1).state == STATE_OFFLINE
    before = total(hist)
    run(hist, [poll(R1, T0 + k * I, [], fresh=False) for k in range(6, 12)])
    hist.ingest(poll(R1, T0 + 12 * I, []))
    after = total(hist)
    # the last fresh list was at T0+300: 60 s still fresh, the rest a gap
    assert after.observed_s - before.observed_s == 60
    assert after.gap_s - before.gap_s == 360
    assert hist.live(M1).state == STATE_OFFLINE


# --- restart and clock ---------------------------------------------------------


def _scenario() -> list[PollInput]:
    out: list[PollInput] = []
    for k in range(150):
        t = T0 + k * I
        m1 = [M1] if not 40 <= k < 46 else []
        m2 = [M2] if k % 30 != 10 else []
        ev: tuple[ClientEvent, ...] = ()
        if k == 40:
            ev = (ClientEvent(M1, EV_DISCONNECT, t - 30, R1, reason="inactivity"),)
        if k == 46:
            ev = (ClientEvent(M1, EV_CONNECT, t - 20, R1),)
        if k == 80:
            ev = (ClientEvent(M2, EV_ROAM, t - 10, R2, peer=R1),)
        r1 = m1 + (m2 if k < 80 else [])
        out.append(poll(R1, t, r1, events=ev if k != 80 else ()))
        out.append(
            poll(R2, t + 20, m2 if k >= 80 else [], events=ev if k == 80 else ())
        )
    return out


@pytest.mark.parametrize("cut", [1, 81, 90, 93, 120, 161, 241])
def test_restart_continuation_matches_uninterrupted(cut: int) -> None:
    polls = _scenario()
    straight = ClientHistory()
    run(straight, polls)

    first = ClientHistory()
    run(first, polls[:cut])
    stored = json.loads(json.dumps(first.to_dict()))
    resumed = ClientHistory.from_dict(stored)
    run(resumed, polls[cut:])

    assert resumed.to_dict() == straight.to_dict()
    for mac in (M1, M2):
        assert resumed.live(mac) == straight.live(mac)


def test_scenario_sanity() -> None:
    hist = ClientHistory()
    run(hist, _scenario())
    t1 = total(hist, M1)
    assert t1.dc_inactivity == 1 and t1.sessions == 2 and t1.associations == 1
    t2 = total(hist, M2)
    assert t2.roams_in == 1 and t2.dc_unknown == 0  # one-poll misses are blips
    assert hist.live(M2).ap == R2


def test_ha_restart_with_downtime_continues_session_as_gap() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])
    resumed = ClientHistory.from_dict(json.loads(json.dumps(hist.to_dict())))
    assert resumed.ring(M1) == ()  # raw ring is memory only
    resumed.ingest(poll(R1, T0 + 120 + 900, [M1]))
    live = resumed.live(M1)
    assert live.state == STATE_ONLINE and live.session_start == T0
    tot = total(resumed)
    assert tot.online_s == 120 and tot.gap_s == 900 and tot.sessions == 1
    kinds = [t.kind for t in resumed.transitions(M1)]
    assert kinds == [TR_START, TR_GAP, TR_RESUME]


def test_ha_restart_client_gone_is_disconnect_with_unknown_time() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])
    resumed = ClientHistory.from_dict(json.loads(json.dumps(hist.to_dict())))
    run(resumed, [poll(R1, T0 + 1020 + k * I, []) for k in range(4)])
    live = resumed.live(M1)
    assert live.state == STATE_OFFLINE
    assert live.last_disconnect.timed is False
    assert total(resumed).gap_s == 900


def test_ha_restart_client_roamed_meanwhile_is_no_disconnect() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])
    resumed = ClientHistory.from_dict(json.loads(json.dumps(hist.to_dict())))
    resumed.ingest(poll(R1, T0 + 1020, []))  # R1 first: client missing
    assert resumed.live(M1).state == STATE_GRACE
    resumed.ingest(poll(R2, T0 + 1030, [M1]))  # found at R2
    live = resumed.live(M1)
    assert live.state == STATE_ONLINE and live.ap == R2
    assert live.last_disconnect is None and live.session_start == T0


def test_clock_shift_keeps_continuity() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(5)])  # until T0+240
    hist.shift_clock(500.0)
    live = hist.live(M1)
    assert live.session_start == T0 + 500
    run(hist, [poll(R1, T0 + 500 + k * I, [M1]) for k in range(5, 10)])
    tot = total(hist)
    assert tot.online_s == 540 and tot.gap_s == 0
    assert hist.live(M1).state == STATE_ONLINE
    assert all(t.ts >= T0 + 500 for t in hist.transitions(M1))


def test_clock_going_backwards_books_nothing_negative() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])
    hist.ingest(poll(R1, T0 + 30, [M1]))  # clock stepped back, no shift notice
    tot = total(hist)
    assert tot.online_s == 120
    assert all(
        v >= 0
        for i, v in enumerate(tot)
        if BUCKET_FIELDS[i]
        not in (
            "rssi_sum",
            "rssi_min",
            "rssi_max",
        )
    )


def test_invalid_poll_is_ignored() -> None:
    hist = ClientHistory()
    hist.ingest(poll(R1, float("nan"), [M1]))
    hist.ingest(PollInput(router=R1, now=T0, interval=0, fresh=True, clients=(obs(),)))
    hist.ingest(PollInput(router="", now=T0, interval=I, fresh=True, clients=(obs(),)))
    assert len(hist) == 0


# --- buckets, persistence, bounds ---------------------------------------------


def test_late_write_into_closed_hour_updates_hour_and_day() -> None:
    hist = ClientHistory()
    start = T0 + 3600 - 120  # last two minutes of hour H0
    run(hist, [poll(R1, start, [M1]), poll(R1, start + 60, [M1])])
    down = (ClientEvent(M1, EV_DISCONNECT, start + 90, R1, reason="psk"),)
    hist.ingest(poll(R1, start + 120, [], events=down))  # hour H0 closes here
    run(hist, [poll(R1, start + 120 + k * I, []) for k in range(1, 4)])
    assert hist.live(M1).state == STATE_OFFLINE
    h0 = next(b for b in hist.hours(M1) if b.hour == H0 and b.ap == R1)
    assert h0.closed
    assert h0.bucket.dc_error == 1 and h0.bucket.online_s == 90
    day = next(d for d in hist.days(M1) if d.ap == R1)
    assert day.bucket.dc_error == 1 and day.bucket.online_s == 90
    meta = hist.day_meta(M1)[H0 // 24]
    assert meta.disconnects == {H0 % 24: 1}


def test_hour_and_day_pack_load_round_trip() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, PRIV]) for k in range(200)])
    data = hist.to_dict()
    raw = data["clients"][M1]
    assert all(isinstance(row, str) for row in raw["h"])
    assert all(isinstance(row, str) for row in raw["d"])
    assert raw["aps"] == [R1]
    loaded = ClientHistory.from_dict(json.loads(json.dumps(data)))
    for mac in (M1, PRIV):
        assert loaded.hours(mac) == hist.hours(mac)
        assert loaded.days(mac) == hist.days(mac)
        assert loaded.day_meta(mac) == hist.day_meta(mac)
        assert loaded.transitions(mac) == hist.transitions(mac)
        assert loaded.live(mac) == hist.live(mac)
    assert loaded.live(PRIV).private_mac is True
    # 0xAA has the locally administered bit (0x02) set as well
    assert loaded.live(M1).private_mac is True
    assert ch.is_private_mac("00:BB:CC:00:00:01") is False
    assert loaded.to_dict() == data


@pytest.mark.parametrize(
    "damage",
    [
        lambda c: c.__setitem__("l", "x"),
        lambda c: c["l"].__setitem__("s", "bogus"),
        lambda c: c.__setitem__("aps", [1, 2]),
        lambda c: c.__setitem__("h", ["1:0:1"] * (ch.HOURS_KEEP * 16 + 1)),
        lambda c: c.__setitem__("tr", ["x"] * 65),
        lambda c: c["l"].pop("acc"),
    ],
)
def test_load_drops_damaged_client_only(damage) -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, M2]) for k in range(5)])
    data = json.loads(json.dumps(hist.to_dict()))
    damage(data["clients"][M1])
    loaded = ClientHistory.from_dict(data)
    assert M1 not in loaded
    assert loaded.live(M2) == hist.live(M2)


def test_load_skips_damaged_bucket_and_transition_rows() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(70)])
    data = json.loads(json.dumps(hist.to_dict()))
    raw = data["clients"][M1]
    good = len(raw["h"])
    raw["h"] += ["junk", "1:9:5", "1:0:a,b", "x:0:5", f"{H0 - 5}:0:-5"]
    raw["tr"] += ["1|start", "nan|start|0||||1", "1.0|bogus|0||||1"]
    raw["dm"] += ["junk", "1:99999999:", "2:1:x=1"]
    loaded = ClientHistory.from_dict(data)
    assert len(loaded.hours(M1)) == good + len(raw.get("ho", []))
    assert loaded.transitions(M1) == hist.transitions(M1)
    assert loaded.day_meta(M1) == hist.day_meta(M1)


@pytest.mark.parametrize("data", [None, [], "x", {"v": 99}, {"v": 1, "clients": 5}])
def test_load_garbage_gives_empty_history(data) -> None:
    hist = ClientHistory.from_dict(data)
    assert len(hist) == 0


def test_load_keeps_most_recent_when_over_max_clients() -> None:
    hist = ClientHistory()
    macs = [f"AA:BB:CC:00:01:{i:02X}" for i in range(5)]
    for i, mac in enumerate(macs):
        hist.ingest(poll(R1, T0 + i, [mac]))
    loaded = ClientHistory.from_dict(hist.to_dict(), max_clients=3)
    assert loaded.macs() == sorted(macs[2:])


def test_max_clients_evicts_oldest_idle_and_never_online() -> None:
    hist = ClientHistory(max_clients=2)
    run(hist, [poll(R1, T0 + k * I, [M1] if k < 2 else [M2]) for k in range(7)])
    assert hist.live(M1).state == STATE_OFFLINE
    hist.ingest(poll(R1, T0 + 7 * I, [M2, M3]))
    assert set(hist.macs()) == {M2, M3}  # offline M1 made room
    hist.ingest(poll(R1, T0 + 8 * I, [M2, M3, PRIV]))
    assert set(hist.macs()) == {M2, M3}  # nobody idle: new client not tracked
    assert len(hist) == 2


def test_raw_ring_and_transition_caps() -> None:
    hist = ClientHistory()
    t = T0
    for k in range(200):
        t = T0 + k * 20
        hist.ingest(
            PollInput(router=R1, now=t, interval=20, fresh=True, clients=(obs(),))
        )
    ring = hist.ring(M1)
    assert len(ring) == ch.RAW_RING_MAX
    # 100 blips: transitions are capped at 64
    for k in range(100):
        base = t + 1 + k * 40
        hist.ingest(PollInput(router=R1, now=base, interval=20, fresh=True))
        hist.ingest(
            PollInput(
                router=R1, now=base + 20, interval=20, fresh=True, clients=(obs(),)
            )
        )
    assert len(hist.transitions(M1)) == ch.TRANSITIONS_MAX
    data = hist.to_dict()
    assert len(data["clients"][M1]["tr"]) == ch.TRANSITIONS_MAX
    assert "ring" not in json.dumps(data)


def test_retention_hours_days_transitions_and_idle_clients() -> None:
    hist = ClientHistory(retention_days=3)
    run(hist, [poll(R1, T0 + k * I, [M1, M2] if k < 3 else [M1]) for k in range(70)])
    assert hist.live(M2).state == STATE_OFFLINE
    # keep M1 online every 10 minutes for 8 days (M2 offline tracking stops)
    t = T0 + 70 * I
    end = T0 + 8 * 86400
    while t < end:
        hist.ingest(
            PollInput(router=R1, now=t, interval=600, fresh=True, clients=(obs(),))
        )
        t += 600
    hist.prune(t)
    hours = hist.hours(M1)
    assert min(b.hour for b in hours) > int(t // 3600) - ch.HOURS_KEEP - 1
    days = hist.days(M1)
    assert min(d.day for d in days) > int(t // 86400) - 3
    assert all(tr.ts >= t - 86400 for tr in hist.transitions(M1))
    assert M2 not in hist  # idle longer than retention_days


def test_retention_days_is_clamped() -> None:
    assert ClientHistory(retention_days=500).retention_days == ch.RETENTION_DAYS_MAX
    assert ClientHistory(retention_days=0).retention_days == 1
    assert ClientHistory().retention_days == ch.RETENTION_DAYS_DEFAULT
    assert ClientHistory().max_clients == ch.MAX_CLIENTS_DEFAULT


def test_forget_and_remove_router() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, M2]) for k in range(2)])
    assert hist.forget("aa:bb:cc:00:00:01")
    assert M1 not in hist and not hist.forget(M1)
    hist.remove_router(R1)
    hist.ingest(poll(R2, T0 + 120, []))
    assert hist.live(M2).state == STATE_UNKNOWN  # no list: gap, not offline


def test_nothing_changes_on_identical_reserialization() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(90)])
    a = json.dumps(hist.to_dict(), sort_keys=True)
    b = json.dumps(ClientHistory.from_dict(json.loads(a)).to_dict(), sort_keys=True)
    assert a == b


def test_gap_booking_stops_after_a_day() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(2)])
    t = T0 + 60
    for _ in range(30):
        t += 3600
        hist.ingest(poll(R2, t, []))
    assert hist.live(M1).state == STATE_UNKNOWN
    assert total(hist).gap_s <= ch.GAP_TRACK_S
    assert total(hist).gap_s >= ch.GAP_TRACK_S - 3600


# --- follow-up: band share and session durations -------------------------------


def band_poll(now: float, band: str | None, router: str = R1) -> PollInput:
    return PollInput(
        router=router,
        now=now,
        interval=I,
        fresh=True,
        clients=(ClientObs(M1, band=band, rssi=-55),),
    )


def test_band_key_spellings() -> None:
    assert [ch.band_key(b) for b in ("2.4g", "2g", "2.4 GHz", "5G", "6ghz")] == [
        "2.4g",
        "2.4g",
        "2.4g",
        "5g",
        "6g",
    ]
    assert ch.band_key("60g") is None and ch.band_key(None) is None


def test_online_time_is_booked_per_band() -> None:
    hist = ClientHistory()
    run(hist, [band_poll(T0 + k * I, "5g") for k in range(4)])  # 180 s on 5 GHz
    run(hist, [band_poll(T0 + k * I, "2.4g") for k in range(4, 7)])
    tot = total(hist)
    # the interval before a sample is booked with the previous sample's band
    assert ch.band_online(tot) == {"2.4g": 120, "5g": 240, "6g": 0}
    assert tot.online_s == 360
    # no band reported: online time without a band share
    hist2 = ClientHistory()
    run(hist2, [band_poll(T0 + k * I, None) for k in range(3)])
    assert ch.band_online(total(hist2)) == {"2.4g": 0, "5g": 0, "6g": 0}
    assert total(hist2).online_s == 120


def test_new_session_uses_band_of_its_first_sample() -> None:
    hist = ClientHistory()
    run(hist, [band_poll(T0 + k * I, "2.4g") for k in range(2)])
    run(hist, [poll(R1, T0 + k * I, []) for k in range(2, 6)])  # offline
    hist.ingest(
        PollInput(
            router=R1,
            now=T0 + 360,
            interval=I,
            fresh=True,
            clients=(ClientObs(M1, band="6g"),),
            events=(ClientEvent(M1, EV_CONNECT, T0 + 330, R1),),
        )
    )
    assert ch.band_online(total(hist))["6g"] == 30


def test_session_bins() -> None:
    assert ch.session_bin(0) == 0
    assert ch.session_bin(299) == 0
    assert ch.session_bin(300) == 1
    assert ch.session_bin(3599) == 3
    assert ch.session_bin(3600) == 4
    assert ch.session_bin(86400) == 9
    assert ch.session_bin(10**7) == 9
    assert len(ch.SESSION_BIN_HOURS) == ch.SESSION_BINS == 10
    hours = ch.SESSION_BIN_HOURS
    assert all(a < b for a, b in itertools.pairwise(hours))
    assert hours[4] == pytest.approx(2**0.5)  # between 1 h and 2 h


def test_session_end_books_duration_histogram() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3)])  # until T0+120
    down = (ClientEvent(M1, EV_DISCONNECT, T0 + 150, R1, reason="timeout"),)
    hist.ingest(poll(R1, T0 + 180, [], events=down))
    run(hist, [poll(R1, T0 + 180 + k * I, []) for k in range(1, 3)])
    tot = total(hist)
    assert tot.session_s_sum == 150
    assert ch.session_histogram(tot) == (1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    assert tot.longest_stable_s == 150


def test_day_buckets_merge_new_fields() -> None:
    hist = ClientHistory()
    run(hist, [band_poll(T0 + k * I, "5g") for k in range(61)])  # closes hour H0
    for k in range(1, 5):
        hist.ingest(PollInput(router=R1, now=T0 + 3600 + k * I, interval=I, fresh=True))
    hist.ingest(PollInput(router=R1, now=T0 + 3 * 3600, interval=I, fresh=True))
    day = sum_buckets(d.bucket for d in hist.days(M1))
    assert day.online_5g_s == day.online_s == 3600
    assert day.session_s_sum == 3600
    assert ch.session_histogram(day)[4] == 1  # 1 h .. 2 h


def test_old_format_rows_load_with_new_fields_zero() -> None:
    hist = ClientHistory()
    run(hist, [band_poll(T0 + k * I, "5g") for k in range(70)])
    data = json.loads(json.dumps(hist.to_dict()))
    raw = data["clients"][M1]

    def old(row: str) -> str:
        index, ap, packed = row.split(":", 2)
        fields = packed.split(",")[:28]
        return f"{index}:{ap}:" + ",".join(fields).rstrip(",")

    for key in ("h", "ho", "d"):
        raw[key] = [old(r) for r in raw.get(key, [])]
    loaded = ClientHistory.from_dict(data)
    assert M1 in loaded
    tot = total(loaded)
    assert tot.online_s == total(hist).online_s
    assert tot.online_5g_s == 0 and tot.session_s_sum == 0
    # and it keeps working with the new fields from here on
    run(loaded, [band_poll(T0 + k * I, "5g") for k in range(70, 72)])
    assert total(loaded).online_5g_s == 120


# --- store size trimming (B8) ---------------------------------------------------


def _hours_of(hist: ClientHistory, mac: str) -> set[int]:
    return {b.hour for b in hist.hours(mac) if b.closed}


def _three_days(hist: ClientHistory, macs: list[str]) -> float:
    """Every client online for 72 h on R1, then M2 offline; returns the end."""
    end = T0 + 72 * 3600
    t = T0
    while t <= end:
        hist.ingest(poll(R1, t, macs))
        t += 600
    return end


def test_hours_filter_skips_unpacking_outside_the_range(monkeypatch) -> None:
    hist = ClientHistory()
    end = _three_days(hist, [M1])
    calls: list[str] = []
    real = ch.unpack_bucket

    def spy(packed):
        calls.append(packed)
        return real(packed)

    monkeypatch.setattr(ch, "unpack_bucket", spy)
    last = int(end // 3600)
    got = hist.hours(M1, last - 2, last)
    assert {b.hour for b in got} <= {last - 2, last - 1, last}
    assert len(calls) <= 3
    calls.clear()
    assert len(hist.hours(M1)) > 70  # unfiltered still returns everything


def test_trim_transitions_of_offline_clients_only() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, M2]) for k in range(3)])
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(3, 10)])
    assert hist.live(M2).state == STATE_OFFLINE
    assert hist.transitions(M2) and hist.transitions(M1)
    assert hist.trim_transitions() > 0
    assert hist.transitions(M2) == ()
    assert hist.transitions(M1)  # online client keeps its transitions


def test_trim_closed_hours_private_first_then_all() -> None:
    hist = ClientHistory()
    assert not ch.is_private_mac(PUB)
    end = _three_days(hist, [PUB, PRIV])
    cut = int(end // 3600) - 48
    days_before = sum_buckets(d.bucket for d in hist.days(PUB))
    assert min(_hours_of(hist, PRIV)) < cut
    assert hist.trim_closed_hours(cut, private_only=True) > 0
    assert min(_hours_of(hist, PRIV)) >= cut
    assert min(_hours_of(hist, PUB)) < cut  # public MAC untouched
    assert hist.trim_closed_hours(cut) > 0
    assert min(_hours_of(hist, PUB)) >= cut
    # the day buckets (already folded) are unchanged
    assert sum_buckets(d.bucket for d in hist.days(PUB)) == days_before
    assert hist.trim_closed_hours(cut) == 0


def test_drop_oldest_prefers_idle_clients() -> None:
    hist = ClientHistory()
    run(hist, [poll(R1, T0 + k * I, [M1, M2, M3]) for k in range(3)])
    run(hist, [poll(R1, T0 + k * I, [M1, M3]) for k in range(3, 6)])
    run(hist, [poll(R1, T0 + k * I, [M1]) for k in range(6, 12)])
    assert hist.live(M2).state == STATE_OFFLINE
    assert hist.live(M3).state == STATE_OFFLINE
    assert hist.drop_oldest(1) == 1
    assert M2 not in hist and M3 in hist  # M2 idle the longest
    assert hist.drop_oldest(5) == 2  # then M3, then the online M1
    assert len(hist) == 0
