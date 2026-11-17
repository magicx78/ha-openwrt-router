"""Tests for the engine input from the log with reason categories (RT5-D).

Path D of the realtime plan: the log is read on every poll; Wi-Fi lines
carry the category of their disconnect or failure reason (``wifi_reasons``).
Scenarios 1, 2, 3 and 9 of the plan (2.7) from log lines. The "excessive
missing ACKs" line was seen live on one router (plan 3.6); its exact prefix
follows hostapd's logger ("STA <mac> IEEE 802.11: ..."). MACs are locally
administered test values.
"""

from __future__ import annotations

import pytest
from test_net_wifi import (
    MAC1,
    MAC2,
    T0,
    Log,
    ap_line,
    client,
    conn,
    data,
    disc,
    engine,  # noqa: F401  (fixture)
    events_of,
    open_incidents,
    psk,
)

from custom_components.openwrt_router.log_parser import LogEvent, parse_entry
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import CauseStatus

MS0 = int(T0 * 1000)


def low_ack(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(
        iface,
        f"STA {mac.lower()} IEEE 802.11: disconnected due to excessive missing ACKs",
    )


def local_deauth(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(
        iface,
        f"STA {mac.lower()} IEEE 802.11: deauthenticated due to local deauth request",
    )


def idle(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(
        iface, f"STA {mac.lower()} IEEE 802.11: disassociated due to inactivity"
    )


def parse(msg: str) -> LogEvent:
    event = parse_entry({"msg": msg, "id": 1, "time": MS0, "source": 1})
    assert event is not None
    return event


# --- parser: reason and category ----------------------------------------------------


def test_missing_acks_line_is_a_disassoc_with_radio_category() -> None:
    event = parse(low_ack(MAC1))
    assert event.key == "wifi.disassoc"
    assert event.reason == "missing_acks"
    assert event.reason_category == "radio"
    assert event.reason_code == 34


@pytest.mark.parametrize(
    ("msg", "category"),
    [
        (idle(MAC1), "inactivity"),
        (local_deauth(MAC1), "ap"),
        (psk(MAC1), "security"),
        (ap_line("phy1-ap0", f"STA {MAC1.lower()} WPA: EAPOL-Key timeout"), "security"),
        (ap_line("phy0-ap0", f"Prune association for {MAC1.lower()}"), "unknown"),
        (disc(MAC1), None),  # no reason given: no category
        (conn(MAC1), None),
    ],
)
def test_wifi_lines_carry_their_reason_category(msg: str, category: str | None) -> None:
    assert parse(msg).reason_category == category


# --- engine: stored events ----------------------------------------------------------


@pytest.mark.asyncio
async def test_radio_disconnect_is_stored_with_its_category(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """A missing-ACKs disconnect is a stored event (radio category); a
    routine inactivity one stays count-only. No extra router call: the
    engine only reads the poll data."""
    log = Log()
    lines = log.lines((10, low_ack(MAC1)), (12, idle(MAC2)))
    engine.ingest("r1", data(lines, [client(MAC1, signal=-80)]), T0 + 40)
    [stored] = events_of(engine, "wifi.disassoc")
    assert stored.subject["mac"] == MAC1
    assert stored.params["reason"] == "missing_acks"
    assert stored.params["reason_category"] == "radio"
    assert stored.params["reason_code"] == 34
    # the signal measured right after the line confirms the weak link
    assert stored.cause == "weak_signal"
    assert stored.cause_status is CauseStatus.CONFIRMED


@pytest.mark.asyncio
async def test_auth_failure_event_carries_the_security_category(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    log = Log()
    engine.ingest("r1", data(log.lines((10, psk(MAC1)))), T0 + 30)
    [event] = events_of(engine, "wifi.psk_mismatch")
    assert event.params["reason_category"] == "security"


# --- scenarios 1, 2, 3, 9 from log lines --------------------------------------------


@pytest.mark.asyncio
async def test_scenario_1_reconnects_in_ten_minutes_with_reason_category(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """8 reconnects in 10 min, each after a missing-ACKs disconnect, read
    on every poll (60 s): one storm incident, the reasons and their
    category on the reconnect events."""
    log = Log()
    weak = [client(MAC1, signal=-79)]
    for n in range(8):
        base = n * 70
        lines = log.lines(
            (base + 10, low_ack(MAC1)),
            (base + 10.2, disc(MAC1)),
            (base + 15, conn(MAC1)),
        )
        engine.ingest("r1", data(lines, weak), T0 + base + 60)
    [incident] = open_incidents(engine, "wifi_reconnect_storm")
    assert incident.cause == "weak_signal"
    assert incident.cause_status is CauseStatus.CONFIRMED
    reconnects = events_of(engine, "wifi.reconnect")
    assert sum(e.count for e in reconnects) == 8
    assert reconnects[-1].params["reasons"] == ["missing_acks"]
    assert reconnects[-1].params["reason_categories"] == ["radio"]


@pytest.mark.asyncio
async def test_scenario_2_steering_roam_is_no_alarm(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """The AP sends a client away (local deauth request, category ap) and it
    connects to the other router: roaming, no reconnect, no stored event."""
    log = Log()
    for n in range(6):
        base = n * 120
        away = log.lines((base + 10, local_deauth(MAC1)), (base + 10.1, disc(MAC1)))
        there = log.lines((base + 12, conn(MAC1)))
        back = log.lines((base + 70, local_deauth(MAC1)), (base + 70.1, disc(MAC1)))
        home = log.lines((base + 72, conn(MAC1)))
        engine.ingest("r2", data(there), T0 + base + 30)
        engine.ingest("r1", data(away), T0 + base + 31)
        engine.ingest("r2", data(back), T0 + base + 90)
        engine.ingest("r1", data(home), T0 + base + 91)
    assert events_of(engine, "wifi.reconnect") == []
    assert events_of(engine, "wifi.deauth") == []
    assert open_incidents(engine, "wifi_reconnect_storm") == []


@pytest.mark.asyncio
async def test_scenario_3_roam_flapping_with_reason_lines(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """A client bounces between two APs every poll; the lines carry the AP
    category, the client lists show the moves: roam flapping, no storm."""
    log = Log()
    now = T0
    for n in range(6):
        on, off = ("r1", "r2") if n % 2 == 0 else ("r2", "r1")
        engine.ingest(
            off,
            data(log.lines((now - T0 - 20, local_deauth(MAC1))), clients=[]),
            now,
        )
        engine.ingest(
            on,
            data(log.lines((now - T0 - 18, conn(MAC1))), [client(MAC1, signal=-77)]),
            now + 1,
        )
        now += 60
    assert len(open_incidents(engine, "wifi_roam_flapping")) == 1
    assert open_incidents(engine, "wifi_reconnect_storm") == []


@pytest.mark.asyncio
async def test_scenario_9_lines_read_twice_count_once(
    engine: NetIntelligence,  # noqa: F811
) -> None:
    """The same lines in two overlapping reads (log on every poll) store and
    count once."""
    log = Log()
    lines = log.lines((10, low_ack(MAC1)), (10.2, disc(MAC1)), (13, conn(MAC1)))
    doubled = (
        *lines,
        *(LogEvent(**{**e.__dict__, "log_id": e.log_id + 100}) for e in lines),
    )
    engine.ingest("r1", data(doubled, [client(MAC1)]), T0 + 60)
    [reconnect] = events_of(engine, "wifi.reconnect")
    assert reconnect.count == 1
    assert len(events_of(engine, "wifi.disassoc")) == 1
