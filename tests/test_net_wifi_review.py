"""Regression tests for the P4 review of the WLAN detectors (M1-M6, K1-K4).

Each M test failed against ``4cc2935``. Decisions of the master: E1 (weak
signal confirmed only for handshake timeout and reconnect with a measurement
at most one poll old), E2 (usteer roam observed only with a matching usteer
log line), E3 (reconnect gap <= 30 s, ``exclusions.macs`` in every WLAN
detector), E4 (a DHCPNAK counts only without an ACK within 30 s).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_wifi import (
    IFACES,
    MAC1,
    MAC2,
    MAC3,
    MACS,
    T0,
    THRESHOLDS,
    Log,
    ap_line,
    client,
    conn,
    data,
    disc,
    events_of,
    mic,
    open_incidents,
    psk,
)

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.log_parser import (
    COUNT_ONLY_KINDS,
    parse_entry,
)
from custom_components.openwrt_router.net_engine import (
    NetIntelligence,
    async_get_net_intelligence,
)
from custom_components.openwrt_router.net_events import (
    CauseStatus,
    Origin,
    Severity,
    Source,
)
from custom_components.openwrt_router.net_rules import (
    INFERRED_CONFIDENCE_CAP,
    WifiSnapshot,
    WifiState,
    detect_wifi,
    merge_settings,
    wifi_context,
)


@pytest.fixture
async def engine() -> NetIntelligence:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = await async_get_net_intelligence(make_hass())
    intel.register("r1")
    intel.register("r2")
    return intel


ACK = "dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.0.2.60 {mac} host"
NAK = "dnsmasq-dhcp[1]: DHCPNAK(br-lan) 192.0.2.51 {mac} wrong network"


def inactivity(mac: str, iface: str = "phy0-ap0") -> str:
    return ap_line(
        iface,
        f"STA {mac.lower()} IEEE 802.11: deauthenticated due to inactivity "
        "(timer DEAUTH/REMOVE)",
    )


def steer(mac: str, node: str, connected: bool = True) -> str:
    direction = "connected to" if connected else "disconnected from"
    return f"usteer: station {mac.lower()} {direction} node {node}"


def causes(item: Any) -> dict[str, str]:
    return {c["cause"]: c["status"] for c in item.params["causes"]}


# --- M1 / E4: DHCPNAK followed by an ACK --------------------------------------------------


@pytest.mark.asyncio
async def test_m1_nak_followed_by_ack_is_no_dhcp_failure(
    engine: NetIntelligence,
) -> None:
    """INIT-REBOOT: the client asks for its old address, gets a NAK, then a
    lease. That is normal DHCP, not a failure after connect."""
    log = Log()
    lines = log.lines(
        (100, conn(MAC1)),
        (101, NAK.format(mac=MAC1.lower())),
        (103, ACK.format(mac=MAC1.lower())),
    )
    engine.ingest("r1", data(lines), T0 + 120)
    engine.ingest("r1", data(log.lines()), T0 + 180)
    assert open_incidents(engine, "wifi_dhcp_after_connect") == []
    assert events_of(engine, "wifi.dhcp_after_connect") == []


@pytest.mark.asyncio
async def test_m1_ack_in_a_later_read_still_cancels_the_nak(
    engine: NetIntelligence,
) -> None:
    log = Log()
    engine.ingest(
        "r1",
        data(log.lines((100, conn(MAC1)), (110, NAK.format(mac=MAC1.lower())))),
        T0 + 115,
    )
    engine.ingest("r1", data(log.lines((125, ACK.format(mac=MAC1.lower())))), T0 + 175)
    assert open_incidents(engine, "wifi_dhcp_after_connect") == []


@pytest.mark.asyncio
async def test_m1_nak_without_ack_counts_after_the_grace_and_stays_warning(
    engine: NetIntelligence,
) -> None:
    log = Log()
    lines = log.lines((100, conn(MAC1)), (101, NAK.format(mac=MAC1.lower())))
    engine.ingest("r1", data(lines), T0 + 110)
    assert open_incidents(engine, "wifi_dhcp_after_connect") == []  # undecided
    engine.ingest("r1", data(log.lines()), T0 + 170)
    [incident] = open_incidents(engine, "wifi_dhcp_after_connect")
    assert incident.severity is Severity.WARNING
    [event] = events_of(engine, "wifi.dhcp_after_connect")
    assert event.params["dhcp"] == "nak" and event.severity is Severity.WARNING


# --- M2 / E1: weak signal confirmed only with a fitting measurement --------------------


@pytest.mark.asyncio
async def test_m2_psk_mismatch_never_confirms_weak_signal(
    engine: NetIntelligence,
) -> None:
    log = Log()
    lines = log.lines((10, psk(MAC1)), (40, psk(MAC1)), (70, psk(MAC1)))
    engine.ingest("r1", data(lines, [client(MAC1, signal=-80)]), T0 + 90)
    [incident] = open_incidents(engine, "wifi_auth_failures")
    assert incident.cause_status is not CauseStatus.CONFIRMED
    assert incident.cause == "psk_wrong"
    for event in events_of(engine, "wifi.psk_mismatch"):
        assert causes(event)["weak_signal"] == "hypothesis"


@pytest.mark.asyncio
async def test_m2_invalid_mic_and_reasonless_reject_keep_weak_signal_a_hypothesis(
    engine: NetIntelligence,
) -> None:
    log = Log()
    reject = ap_line(
        "phy1-ap0", f"STA {MAC2.lower()} IEEE 802.11: association rejected"
    )
    lines = log.lines((10, mic(MAC1)), (20, reject))
    engine.ingest(
        "r1",
        data(lines, [client(MAC1, signal=-82), client(MAC2, signal=-85)]),
        T0 + 30,
    )
    [mic_event] = events_of(engine, "wifi.handshake_failed")
    assert causes(mic_event)["weak_signal"] == "hypothesis"
    [reject_event] = events_of(engine, "wifi.assoc_rejected")
    assert reject_event.cause_status is CauseStatus.HYPOTHESIS
    assert causes(reject_event)["weak_signal"] == "hypothesis"


@pytest.mark.asyncio
async def test_m2_roam_and_band_change_never_confirm_weak_signal(
    engine: NetIntelligence,
) -> None:
    engine.ingest("r1", data(clients=[client(MAC1, signal=-80)]), T0)
    engine.ingest("r1", data(clients=[]), T0 + 60)
    engine.ingest("r2", data(clients=[client(MAC1, signal=-80)]), T0 + 61)
    engine.ingest("r2", data(clients=[client(MAC1, "phy0-ap0", -80)]), T0 + 121)
    [roam] = events_of(engine, "wifi.roam")
    [band] = events_of(engine, "wifi.band_change")
    for event in (roam, band):
        assert event.cause_status is CauseStatus.HYPOTHESIS
        assert causes(event)["weak_signal"] == "hypothesis"


@pytest.mark.asyncio
async def test_m2_reconnect_needs_a_measurement_at_most_one_poll_old(
    engine: NetIntelligence,
) -> None:
    """The reconnect happened 200 s before the poll (60 s interval): the
    signal of this poll says nothing about that moment."""
    log = Log()
    lines = log.lines((0, disc(MAC1)), (10, conn(MAC1)))
    engine.ingest("r1", data(lines, [client(MAC1, signal=-80)]), T0 + 210, interval=60)
    [event] = events_of(engine, "wifi.reconnect")
    assert event.signal == -80
    assert causes(event)["weak_signal"] == "hypothesis"
    assert event.cause_status is CauseStatus.HYPOTHESIS


@pytest.mark.asyncio
async def test_m2_handshake_timeout_with_an_old_line_is_a_hypothesis(
    engine: NetIntelligence,
) -> None:
    log = Log()
    timeout = ap_line("phy1-ap0", f"STA {MAC1.lower()} WPA: EAPOL-Key timeout")
    engine.ingest(
        "r1",
        data(log.lines((10, timeout)), [client(MAC1, signal=-80)]),
        T0 + 300,
        interval=60,
    )
    [event] = events_of(engine, "wifi.handshake_failed")
    assert event.cause_status is CauseStatus.HYPOTHESIS


# --- E2: usteer roam observed only with a usteer log line -------------------------------


@pytest.mark.asyncio
async def test_e2_usteer_snapshot_change_without_log_line_is_inferred(
    engine: NetIntelligence,
) -> None:
    engine.ingest("r2", data(), T0, host="192.0.2.2")
    local = {MAC1.lower(): ("hostapd.phy1-ap0",)}
    remote = {MAC1.lower(): ("192.0.2.2#hostapd.phy1-ap0",)}
    engine.ingest("r1", data(usteer=local, usteer_status="ok"), T0 + 10)
    engine.ingest("r1", data(usteer=remote, usteer_status="ok"), T0 + 70)
    [roam] = events_of(engine, "wifi.roam")
    assert roam.source is Source.USTEER
    assert roam.origin is Origin.INFERRED
    assert roam.confidence == INFERRED_CONFIDENCE_CAP


@pytest.mark.asyncio
async def test_e2_usteer_roam_with_matching_line_is_observed(
    engine: NetIntelligence,
) -> None:
    log = Log()
    engine.ingest("r2", data(), T0, host="192.0.2.2")
    local = {MAC1.lower(): ("hostapd.phy1-ap0",)}
    remote = {MAC1.lower(): ("192.0.2.2#hostapd.phy1-ap0",)}
    engine.ingest("r1", data(log.lines(), usteer=local, usteer_status="ok"), T0 + 10)
    lines = log.lines((40, steer(MAC1, "hostapd.phy1-ap0", connected=False)))
    engine.ingest("r1", data(lines, usteer=remote, usteer_status="ok"), T0 + 70)
    [roam] = events_of(engine, "wifi.roam")
    assert roam.origin is Origin.OBSERVED and roam.confidence == 1.0


# --- M3 / E3: sleeping clients, exclusions ----------------------------------------------


@pytest.mark.asyncio
async def test_m3_deep_sleep_client_is_no_reconnect_storm(
    engine: NetIntelligence,
) -> None:
    """An ESP32 wakes every 60 s: connect at wake, disconnect at sleep."""
    log = Log()
    t = 0.0
    for _poll in range(11):
        items = [(t + 5, conn(MACS[0], "phy0-ap0")), (t + 8, disc(MACS[0], "phy0-ap0"))]
        t += 60
        engine.ingest("r1", data(log.lines(*items), [client(MAC2, "phy0-ap0")]), T0 + t)
    assert open_incidents(engine, "wifi_reconnect_storm") == []
    assert events_of(engine, "wifi.reconnect") == []


@pytest.mark.asyncio
async def test_e3_excluded_mac_feeds_no_wifi_detector(engine: NetIntelligence) -> None:
    engine.settings = merge_settings({"exclusions": {"macs": [MAC1.lower()]}})
    engine.machine.set_settings(engine.settings)
    log = Log()
    storm = [
        item
        for k in range(6)
        for item in ((k * 20, disc(MAC1)), (k * 20 + 5, conn(MAC1)))
    ]
    attempts = [(200 + k * 30, psk(MAC1)) for k in range(4)]
    weak = [client(MAC1, signal=-85)]
    engine.ingest("r1", data(log.lines(*storm, *attempts), weak), T0 + 330)
    for n in range(1, 12):
        engine.ingest("r1", data(log.lines(), weak), T0 + 330 + n * 60)
    for type_ in (
        "wifi_reconnect_storm",
        "wifi_auth_failures",
        "wifi_auth_wave",
        "wifi_weak_clients",
    ):
        assert open_incidents(engine, type_) == [], type_
    assert events_of(engine, "wifi.reconnect") == []
    # the plain log lines are still stored (only the detectors skip them)
    assert events_of(engine, "wifi.psk_mismatch")


# --- M4: ping-pong roaming is no reconnect ------------------------------------------------


@pytest.mark.asyncio
async def test_m4_ping_pong_roaming_counts_no_reconnect(
    engine: NetIntelligence,
) -> None:
    """A -> B -> A within 30 s: the client was on B between down and up."""
    log = Log()
    for n in range(6):
        base = n * 100
        on_b = log.lines((base + 2, conn(MAC1)), (base + 15, disc(MAC1)))
        on_a = log.lines((base + 1, disc(MAC1)), (base + 20, conn(MAC1)))
        engine.ingest("r2", data(on_b), T0 + base + 40)
        engine.ingest("r1", data(on_a), T0 + base + 41)
    assert events_of(engine, "wifi.reconnect") == []
    assert open_incidents(engine, "wifi_reconnect_storm") == []


# --- M5: mass disconnect ------------------------------------------------------------------


def _four_then(engine: NetIntelligence, lines: Any, **kw: Any) -> None:
    four = [client(m, "phy0-ap0") for m in MACS[:4]]
    engine.ingest("r1", data((), four), T0)
    engine.ingest("r1", data(lines, [client(MACS[3], "phy0-ap0")], **kw), T0 + 160)


@pytest.mark.asyncio
async def test_m5_idle_timeouts_are_no_mass_disconnect(engine: NetIntelligence) -> None:
    log = Log()
    items = []
    for i, mac in enumerate(MACS[:3]):
        items.append((100 + i, inactivity(mac)))
        items.append((100 + i + 0.1, disc(mac, "phy0-ap0")))
    _four_then(engine, log.lines(*items))
    assert events_of(engine, "wifi.mass_disconnect") == []
    assert open_incidents(engine, "wifi_mass_disconnect") == []


@pytest.mark.asyncio
async def test_m5_spread_disconnects_are_no_mass_disconnect(
    engine: NetIntelligence,
) -> None:
    """Six clients leaving 4 s apart (20 s) are no cluster of one event."""
    log = Log()
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(*((100 + i * 4, disc(MACS[i])) for i in range(6)))
    engine.ingest("r1", data(lines, clients[6:]), T0 + 130)
    assert events_of(engine, "wifi.mass_disconnect") == []


@pytest.mark.asyncio
async def test_m5_own_wifi_action_suppresses_the_mass_disconnect(
    engine: NetIntelligence,
) -> None:
    log = Log()
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(*((100 + i * 0.5, disc(MACS[i])) for i in range(6)))
    batch = data(lines, clients[6:])
    batch.wifi_actions = {"reload_wifi": T0 + 98}
    engine.ingest("r1", batch, T0 + 130)
    assert events_of(engine, "wifi.mass_disconnect") == []


@pytest.mark.asyncio
async def test_m5_hostapd_shutdown_suppresses_the_mass_disconnect(
    engine: NetIntelligence,
) -> None:
    log = Log()
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(
        (99, ap_line("phy1-ap0", "AP-DISABLED")),
        *((100 + i * 0.5, disc(MACS[i])) for i in range(6)),
    )
    engine.ingest("r1", data(lines, clients[6:]), T0 + 130)
    assert events_of(engine, "wifi.mass_disconnect") == []


def test_m5_hostapd_shutdown_lines_are_parsed_count_only() -> None:
    for text in ("AP-DISABLED", "INTERFACE-DISABLED"):
        event = parse_entry(
            {"msg": ap_line("phy1-ap0", text), "id": 1, "time": 1, "source": 1}
        )
        assert event is not None and event.key == "wifi.ap_disabled"
        assert event.interface == "phy1-ap0"
    assert ("wifi", "ap_disabled") in COUNT_ONLY_KINDS


def test_m5_reboot_suppresses_the_log_path() -> None:
    state = WifiState()
    log = Log()
    context = wifi_context(IFACES, [client(m) for m in MACS[:8]])
    detect_wifi(
        state, WifiSnapshot(context=context, has_aps=True), T0, "r1", THRESHOLDS
    )
    lines = log.lines(*((100 + i * 0.5, disc(MACS[i])) for i in range(6)))
    snap = WifiSnapshot(
        context=wifi_context(IFACES, []),
        has_aps=True,
        log_events=lines,
        log_status="ok",
        log_lines=len(lines),
        rebooted=True,
    )
    findings = detect_wifi(state, snap, T0 + 130, "r1", THRESHOLDS)
    assert [f for f in findings if f.kind == "wifi.mass_disconnect"] == []


@pytest.mark.asyncio
async def test_m5_tight_cluster_still_is_a_mass_disconnect(
    engine: NetIntelligence,
) -> None:
    log = Log()
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(*((100 + i * 0.5, disc(MACS[i])) for i in range(6)))
    engine.ingest("r1", data(lines, clients[6:]), T0 + 130)
    [event] = events_of(engine, "wifi.mass_disconnect")
    assert event.params["window_s"] == 5 and event.count == 6


# --- M6: the auth wave counts clients ---------------------------------------------------


@pytest.mark.asyncio
async def test_m6_one_bad_client_is_no_wave(engine: NetIntelligence) -> None:
    """One device with an old PSK plus two single failures elsewhere."""
    log = Log()
    items = [(10 + i * 30, psk(MAC1)) for i in range(8)]
    items += [(50, psk(MAC2)), (130, psk(MAC3))]
    engine.ingest("r1", data(log.lines(*sorted(items))), T0 + 300)
    assert open_incidents(engine, "wifi_auth_wave") == []


@pytest.mark.asyncio
async def test_m6_handshake_timeouts_are_no_wave(engine: NetIntelligence) -> None:
    log = Log()
    items = [
        (
            10 + i * 10,
            ap_line("phy1-ap0", f"STA {MACS[i % 6].lower()} WPA: EAPOL-Key timeout"),
        )
        for i in range(12)
    ]
    engine.ingest("r1", data(log.lines(*items)), T0 + 200)
    assert open_incidents(engine, "wifi_auth_wave") == []


@pytest.mark.asyncio
async def test_m6_wave_counts_distinct_clients(engine: NetIntelligence) -> None:
    log = Log()
    first = log.lines(*((10 + i * 10, psk(MACS[i])) for i in range(3)))
    engine.ingest("r1", data(first), T0 + 60)
    again = log.lines(*((70 + i * 10, psk(MACS[i % 3])) for i in range(6)))
    engine.ingest("r1", data(again), T0 + 140)
    assert open_incidents(engine, "wifi_auth_wave") == []  # still 3 clients
    more = log.lines((150, psk(MACS[3])), (160, sae_line(MACS[4])))
    engine.ingest("r2", data(more), T0 + 180)
    [wave] = open_incidents(engine, "wifi_auth_wave")
    assert wave.occurrences == 5 and wave.affected == 5
    assert sorted(wave.routers) == ["r1", "r2"]


def sae_line(mac: str) -> str:
    return ap_line(
        "phy1-ap0", f"STA {mac.lower()} IEEE 802.11: SAE authentication failed"
    )


# --- K3 / K4 ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_k3_hold_ends_when_the_client_left_or_after_the_limit(
    engine: NetIntelligence,
) -> None:
    log = Log()
    storm = [
        item
        for k in range(5)
        for item in ((k * 20, disc(MAC1)), (k * 20 + 5, conn(MAC1)))
    ]
    engine.ingest("r1", data(log.lines(*storm), [client(MAC1)]), T0 + 120)
    assert open_incidents(engine, "wifi_reconnect_storm")
    # log unreadable and the client gone: nothing holds the incident
    for n in range(1, 40):
        engine.ingest("r1", data(log_status="error", fetched=False), T0 + 120 + n * 60)
    assert open_incidents(engine, "wifi_reconnect_storm") == []


@pytest.mark.asyncio
async def test_k3_hold_is_limited_in_time(engine: NetIntelligence) -> None:
    log = Log()
    storm = [
        item
        for k in range(5)
        for item in ((k * 20, disc(MAC1)), (k * 20 + 5, conn(MAC1)))
    ]
    engine.ingest("r1", data(log.lines(*storm), [client(MAC1)]), T0 + 120)
    for n in range(1, 61):
        engine.ingest(
            "r1",
            data(clients=[client(MAC1)], log_status="error", fetched=False),
            T0 + 120 + n * 60,
        )
    assert open_incidents(engine, "wifi_reconnect_storm")  # within the hold limit
    for n in range(61, 120):
        engine.ingest(
            "r1",
            data(clients=[client(MAC1)], log_status="error", fetched=False),
            T0 + 120 + n * 60,
        )
    assert open_incidents(engine, "wifi_reconnect_storm") == []


@pytest.mark.asyncio
async def test_k4_poll_fallback_needs_the_drop_on_two_polls(
    engine: NetIntelligence,
) -> None:
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, log_status="not_permitted"), T0)
    engine.ingest("r1", data(clients=clients[:2], log_status="not_permitted"), T0 + 60)
    assert events_of(engine, "wifi.mass_disconnect") == []
    # the clients came back: a short gap in the client list, no mass
    engine.ingest("r1", data(clients=clients, log_status="not_permitted"), T0 + 120)
    assert events_of(engine, "wifi.mass_disconnect") == []
    engine.ingest("r1", data(clients=clients[:2], log_status="not_permitted"), T0 + 180)
    engine.ingest("r1", data(clients=clients[:2], log_status="not_permitted"), T0 + 240)
    [event] = events_of(engine, "wifi.mass_disconnect")
    assert event.origin is Origin.INFERRED and event.count == 6
