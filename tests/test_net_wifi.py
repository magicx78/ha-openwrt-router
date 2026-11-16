"""Tests for the WLAN detectors (network intelligence P4).

Log fixtures are the anonymised line shapes of the read-only live check of
2026-11-16 (OpenWrt 25.12.1, hostapd at its default log level, usteer on
some routers). SAE, invalid MIC, PSK, WPA timeout, assoc reject and
``reason=`` lines were never seen live: those tests are synthetic. MACs are
locally administered test values, IPs from TEST-NET.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import test_poll_no_ssh as model
from test_net_engine import FakeDisk, FakeStore, make_hass

from custom_components.openwrt_router import net_engine
from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.coordinator import LogBatch
from custom_components.openwrt_router.log_parser import (
    COUNT_ONLY_KINDS,
    ENGINE_ONLY_KINDS,
    EventLimiter,
    LogEvent,
    parse_entry,
)
from custom_components.openwrt_router.net_engine import (
    NetIntelligence,
    async_get_net_intelligence,
)
from custom_components.openwrt_router.net_events import (
    CauseStatus,
    IncidentStatus,
    Origin,
    Scope,
    Severity,
    Source,
)
from custom_components.openwrt_router.net_rules import (
    INFERRED_CONFIDENCE_CAP,
    WifiContext,
    WifiSnapshot,
    WifiState,
    cause_list,
    detect_wifi,
    merge_settings,
    wifi_context,
)

T0 = 1_763_280_000.0
MS0 = int(T0 * 1000)
MAC1 = "02:00:5E:10:00:01"
MAC2 = "02:00:5E:10:00:02"
MAC3 = "02:00:5E:10:00:03"
MAC4 = "02:00:5E:10:00:04"
MACS = [f"02:00:5E:10:01:{i:02X}" for i in range(12)]
SSID = "Test-Net-xyz"
IFACES = [
    {"ifname": "phy0-ap0", "ssid": SSID, "frequency": 2437, "phy": "phy0"},
    {"ifname": "phy1-ap0", "ssid": SSID, "frequency": 5180, "phy": "phy1"},
]
THRESHOLDS = merge_settings(None)["thresholds"]


# --- helpers ---------------------------------------------------------------------------


def ap_line(iface: str, text: str) -> str:
    return f"hostapd: {iface}: {text}"


def conn(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(iface, f"AP-STA-CONNECTED {mac.lower()} auth_alg=open")


def disc(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(iface, f"AP-STA-DISCONNECTED {mac.lower()}")


def psk(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(iface, f"AP-STA-POSSIBLE-PSK-MISMATCH {mac.lower()}")


def mic(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(
        iface, f"STA {mac.lower()} WPA: invalid MIC in msg 2/4 of 4-Way Handshake"
    )


def sae(mac: str, iface: str = "phy1-ap0") -> str:
    return ap_line(
        iface, f"STA {mac.lower()} IEEE 802.11: SAE authentication failed (status 15)"
    )


class Log:
    """Builds parsed log lines with growing ids at given router seconds."""

    def __init__(self) -> None:
        self.next_id = 1

    def lines(self, *items: tuple[float, str]) -> tuple[LogEvent, ...]:
        out = []
        for seconds, msg in items:
            entry = {
                "msg": msg,
                "id": self.next_id,
                "time": MS0 + int(seconds * 1000),
                "priority": 30,
                "source": 1,
            }
            self.next_id += 1
            event = parse_entry(entry)
            if event is not None:
                out.append(event)
        return tuple(out)


def client(
    mac: str,
    iface: str = "phy1-ap0",
    signal: int = -60,
    since: float | None = None,
) -> dict[str, Any]:
    item = {"mac": mac, "radio": iface, "signal": signal, "ssid": SSID}
    if since is not None:
        item["connected_since"] = datetime.fromtimestamp(since, UTC).isoformat()
    return item


def data(
    events: tuple[LogEvent, ...] = (),
    clients: list[dict[str, Any]] | None = None,
    *,
    log_status: str = "ok",
    fetched: bool = True,
    missed: int = 0,
    usteer: dict[str, tuple[str, ...]] | None = None,
    usteer_status: str | None = None,
) -> SimpleNamespace:
    """A fresh coordinator data object (one poll)."""
    batch = None
    if fetched:
        ids = [e.log_id for e in events]
        batch = LogBatch(
            baseline=False,
            missed=missed,
            first_time_ms=None,
            last_id=max(ids) if ids else None,
            last_time_ms=None,
            new_lines=len(events),
        )
    return SimpleNamespace(
        new_log_events=events,
        new_log_batch=batch,
        ap_interfaces=IFACES,
        clients=list(clients or []),
        log_status=log_status,
        usteer_connected=usteer,
        client_stability={"usteer": usteer_status} if usteer_status else {},
    )


@pytest.fixture
async def engine() -> NetIntelligence:
    disk = FakeDisk()
    with patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)):
        intel = await async_get_net_intelligence(make_hass())
    intel.register("r1")
    intel.register("r2")
    return intel


def open_incidents(intel: NetIntelligence, type_: str) -> list[Any]:
    return [
        inc
        for inc in intel.machine.incidents()
        if inc.type == type_
        and inc.status in (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)
    ]


def events_of(intel: NetIntelligence, kind: str) -> list[Any]:
    return [e for e in intel.ring if e.kind == kind]


# --- log parser: live shapes and synthetic patterns --------------------------------------

LIVE = [
    # (message, key, reason) -- anonymised live lines of the report (F2/F3)
    (conn(MAC1, "phy1-ap1"), "wifi.connected", None),
    (disc(MAC1, "phy1-ap1"), "wifi.disconnected", None),
    (
        ap_line(
            "phy1-ap1",
            f"STA {MAC1.lower()} IEEE 802.11: disassociated due to inactivity",
        ),
        "wifi.disassoc",
        "inactivity",
    ),
    (
        ap_line(
            "phy1-ap1",
            f"STA {MAC1.lower()} IEEE 802.11: deauthenticated due to inactivity "
            "(timer DEAUTH/REMOVE)",
        ),
        "wifi.inactivity_timeout",
        "inactivity",
    ),
    (
        ap_line(
            "phy1-ap0",
            f"STA {MAC2.lower()} IEEE 802.11: deauthenticated due to local deauth request",
        ),
        "wifi.deauth",
        "local_request",
    ),
    (
        ap_line("phy1-ap1", f"STA {MAC3.lower()} IEEE 802.11: disassociated"),
        "wifi.disassoc",
        None,
    ),
    (
        ap_line("phy0-ap0", f"Prune association for {MAC4.lower()}"),
        "wifi.disassoc",
        "prune",
    ),
    (
        ap_line("phy1-ap1", f"EAPOL-4WAY-HS-COMPLETED {MAC1.lower()}"),
        "wifi.handshake_completed",
        None,
    ),
    (
        f"usteer: station {MAC1.lower()} disconnected from node hostapd.phy1-ap1",
        "wifi.usteer_disconnected",
        None,
    ),
]

NOISE = [
    ap_line("phy1-ap1", f"STA {MAC1.lower()} IEEE 802.11: authenticated"),
    ap_line("phy1-ap1", f"STA {MAC1.lower()} IEEE 802.11: associated (aid 1)"),
    ap_line(
        "phy1-ap1", f"STA {MAC1.lower()} WPA: pairwise key handshake completed (RSN)"
    ),
    ap_line("phy0-ap4", f"BEACON-REQ-TX-STATUS {MAC1.lower()} 1 ack=1"),
    "hostapd: Unexpected Link measurement report, token 7",
    ap_line("phy1-ap0", f"STA {MAC1.lower()} RADIUS: starting accounting session 5F3A"),
    "hostapd: VLAN: vlan_event_receive: recvfrom failed: No buffer space available",
    "dropbear[2565]: Pubkey auth succeeded for 'root' with key from 192.0.2.5:64008",
    "crond[1803]: USER root pid 9000 cmd /usr/bin/ha-collect",
]

# Never seen live (plan P4: "nicht live gesehen")
BACKHAUL_PSK = (
    "wpa_supplicant[812]: phy1-sta0: WPA: 4-Way Handshake failed - "
    "pre-shared key may be incorrect"
)
SYNTHETIC = [
    (psk(MAC1), "wifi.psk_mismatch", None),
    (mic(MAC1), "wifi.handshake_failed", "invalid_mic"),
    (
        ap_line("phy1-ap0", f"STA {MAC1.lower()} WPA: EAPOL-Key timeout"),
        "wifi.handshake_failed",
        "timeout",
    ),
    (sae(MAC1), "wifi.sae_failed", None),
    (
        ap_line("phy1-ap0", f"SAE-UNKNOWN-PASSWORD-IDENTIFIER {MAC1.lower()}"),
        "wifi.sae_failed",
        None,
    ),
    (
        ap_line("phy1-ap0", f"AP-REJECTED-MAX-STA {MAC1.lower()}"),
        "wifi.assoc_rejected",
        "max_sta",
    ),
    (
        ap_line("phy1-ap0", f"AP-REJECTED-BLOCKED-STA {MAC1.lower()}"),
        "wifi.assoc_rejected",
        "blocked",
    ),
    (
        BACKHAUL_PSK,
        "wifi.backhaul_auth_failed",
        "psk",
    ),
    (
        ap_line(
            "phy1-ap0",
            f"STA {MAC1.lower()} IEEE 802.11: deauthenticated due to some other text",
        ),
        "wifi.deauth",
        "other",
    ),
]


@pytest.mark.parametrize(("msg", "key", "reason"), LIVE + SYNTHETIC)
def test_wifi_lines_are_parsed_with_plain_text_reason(
    msg: str, key: str, reason: str | None
) -> None:
    event = parse_entry({"msg": msg, "id": 1, "time": MS0, "source": 1})
    assert event is not None
    assert event.key == key
    assert event.reason == reason


@pytest.mark.parametrize("msg", NOISE)
def test_noise_and_login_lines_are_ignored(msg: str) -> None:
    assert parse_entry({"msg": msg, "id": 1, "time": MS0, "source": 1}) is None


def test_bus_keeps_its_kinds() -> None:
    """New P4 kinds never become HA bus events; the old ones still do."""
    log = Log()
    events = log.lines(
        *((i, msg) for i, (msg, _k, _r) in enumerate(LIVE + SYNTHETIC)),
    )
    fired, _suppressed = EventLimiter(per_fetch=100, window_ms=1).select(events, MS0)
    assert sorted({e.key for e in fired}) == [
        "wifi.handshake_failed",
        "wifi.inactivity_timeout",
        "wifi.psk_mismatch",
    ]
    new = {
        ("wifi", k)
        for k in ("deauth", "disassoc", "handshake_completed", "usteer_disconnected")
    }
    assert new <= COUNT_ONLY_KINDS
    assert ("wifi", "sae_failed") in ENGINE_ONLY_KINDS


# --- API: rate kept, no new call -----------------------------------------------------------


@pytest.mark.asyncio
async def test_api_keeps_rate_of_hostapd_clients() -> None:
    session = model._ubus_session()
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=session,
        protocol="http",
    )
    answer = {
        "freq": 5180,
        "clients": {
            MAC1.lower(): {
                "auth": True,
                "bytes": {"rx": 1, "tx": 2},
                "rate": {"rx": 433300, "tx": 866700},
                "signal": -61,
            }
        },
    }
    with patch.dict(model.RESPONSES, {("hostapd.phy1-ap0", "get_clients"): answer}):
        await api.login()
        found = await api.get_connected_clients(leases={})
    [item] = [c for c in found if c["mac"] == MAC1]
    assert item["rx_rate"] == 433300 and item["tx_rate"] == 866700
    assert item["signal"] == -61


# --- reconnect storm --------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reconnect_storm_with_weak_signal_confirms_the_cause(
    engine: NetIntelligence,
) -> None:
    """8 reconnects in 10 min at -78 dBm: storm incident, weak signal confirmed."""
    log = Log()
    weak = [client(MAC1, signal=-78)]
    for poll_no in range(4):
        base = poll_no * 140
        events = log.lines(
            (base + 10, disc(MAC1)),
            (base + 15, conn(MAC1)),
            (base + 80, disc(MAC1)),
            (base + 85, conn(MAC1)),
        )
        engine.ingest("r1", data(events, weak), T0 + base + 120)
    [incident] = open_incidents(engine, "wifi_reconnect_storm")
    assert incident.scope is Scope.CLIENT and incident.scope_key == MAC1
    assert incident.cause == "weak_signal"
    assert incident.cause_status is CauseStatus.CONFIRMED
    assert incident.severity is Severity.WARNING
    reconnects = events_of(engine, "wifi.reconnect")
    assert sum(e.count for e in reconnects) == 8
    last = reconnects[-1]
    # every field of plan 2.14
    assert last.router == "r1" and last.ts == T0 + 3 * 140 + 120
    assert last.subject == {
        "mac": MAC1,
        "iface": "phy1-ap0",
        "ssid": SSID,
        "band": "5g",
    }
    assert last.signal == -78 and last.count == 2
    assert last.params["window_count"] == 8
    assert last.severity is Severity.INFO
    assert last.origin is Origin.OBSERVED and last.source is Source.HOSTAPD
    assert last.confidence == 1.0
    assert last.params["causes"][0] == {"cause": "weak_signal", "status": "confirmed"}


@pytest.mark.asyncio
async def test_reconnects_with_good_signal_list_hypotheses_only(
    engine: NetIntelligence,
) -> None:
    log = Log()
    events = log.lines(
        (
            1,
            ap_line(
                "phy1-ap0",
                f"STA {MAC1.lower()} IEEE 802.11: deauthenticated due to local "
                "deauth request",
            ),
        ),
        (1.2, disc(MAC1)),
        (4, conn(MAC1)),
    )
    engine.ingest("r1", data(events, [client(MAC1, signal=-58)]), T0 + 10)
    [event] = events_of(engine, "wifi.reconnect")
    assert event.cause_status is CauseStatus.HYPOTHESIS
    causes = [c["cause"] for c in event.params["causes"]]
    assert causes[0] == "weak_signal"
    assert {"steering", "interference", "power_supply", "roaming", "auth"} <= set(
        causes
    )
    assert all(c["status"] == "hypothesis" for c in event.params["causes"])
    assert event.params["reasons"] == ["local_request"]


@pytest.mark.asyncio
async def test_single_short_disconnect_is_nothing_critical(
    engine: NetIntelligence,
) -> None:
    log = Log()
    events = log.lines((10, disc(MAC1)), (13, conn(MAC1)))
    engine.ingest("r1", data(events, [client(MAC1)]), T0 + 60)
    assert engine.machine.incidents() == []
    assert [e.kind for e in engine.ring] == ["wifi.reconnect"]
    assert all(e.severity is Severity.INFO for e in engine.ring)


@pytest.mark.asyncio
async def test_band_steering_and_roaming_are_no_reconnect(
    engine: NetIntelligence,
) -> None:
    """Another radio of the router or a prune line is no reconnect."""
    log = Log()
    events = log.lines(
        (10, disc(MAC1, "phy1-ap0")),
        (12, conn(MAC1, "phy0-ap0")),
        (20, ap_line("phy0-ap0", f"Prune association for {MAC2.lower()}")),
        (22, conn(MAC2, "phy0-ap0")),
    )
    engine.ingest("r1", data(events, [client(MAC1, "phy0-ap0")]), T0 + 60)
    assert events_of(engine, "wifi.reconnect") == []


@pytest.mark.asyncio
async def test_duplicate_log_lines_count_once(engine: NetIntelligence) -> None:
    log = Log()
    events = log.lines((10, disc(MAC1)), (13, conn(MAC1)))
    doubled = (
        *events,
        *(LogEvent(**{**e.__dict__, "log_id": e.log_id + 100}) for e in events),
    )
    engine.ingest("r1", data(doubled, [client(MAC1)]), T0 + 60)
    [event] = events_of(engine, "wifi.reconnect")
    assert event.count == 1


# --- authentication failures ------------------------------------------------------------------


@pytest.mark.asyncio
async def test_psk_series_opens_auth_failures_after_three_attempts(
    engine: NetIntelligence,
) -> None:
    """One wrong-password attempt writes two lines (invalid MIC + PSK
    mismatch); they count as one attempt."""
    log = Log()
    for attempt in range(3):
        seconds = 10 + attempt * 30
        events = log.lines((seconds, mic(MAC1)), (seconds + 0.2, psk(MAC1)))
        engine.ingest("r1", data(events, [client(MAC1)]), T0 + seconds + 20)
        if attempt < 2:
            assert open_incidents(engine, "wifi_auth_failures") == []
    [incident] = open_incidents(engine, "wifi_auth_failures")
    assert incident.scope_key == MAC1
    assert incident.occurrences == 3
    assert incident.cause == "psk_wrong"
    assert incident.cause_status is CauseStatus.HYPOTHESIS
    psk_events = events_of(engine, "wifi.psk_mismatch")
    assert psk_events[-1].params["window_count"] == 3
    assert psk_events[-1].subject["ssid"] == SSID
    assert psk_events[-1].subject["band"] == "5g"


@pytest.mark.asyncio
async def test_duplicate_psk_line_is_one_attempt(engine: NetIntelligence) -> None:
    log = Log()
    events = log.lines((10, psk(MAC1)), (10, psk(MAC1)), (10, psk(MAC1)))
    engine.ingest("r1", data(events), T0 + 30)
    assert open_incidents(engine, "wifi_auth_failures") == []
    assert events_of(engine, "wifi.psk_mismatch")[-1].params["window_count"] == 1


@pytest.mark.asyncio
async def test_sae_failures_open_auth_failures_without_bus_events(
    engine: NetIntelligence,
) -> None:
    log = Log()
    lines = log.lines((10, sae(MAC1)), (40, sae(MAC1)), (70, sae(MAC1)))
    engine.ingest("r1", data(lines), T0 + 90)
    [incident] = open_incidents(engine, "wifi_auth_failures")
    assert incident.occurrences == 3
    sae_events = events_of(engine, "wifi.sae_failed")
    assert [c["cause"] for c in sae_events[0].params["causes"]][:2] == [
        "psk_wrong",
        "sae_mismatch",
    ]
    fired, _ = EventLimiter(per_fetch=10, window_ms=1).select(lines, MS0)
    assert fired == []


@pytest.mark.asyncio
async def test_handshake_timeout_with_weak_signal_confirms_weak_signal(
    engine: NetIntelligence,
) -> None:
    log = Log()
    timeout = ap_line("phy1-ap0", f"STA {MAC1.lower()} WPA: EAPOL-Key timeout")
    engine.ingest(
        "r1", data(log.lines((10, timeout)), [client(MAC1, signal=-80)]), T0 + 30
    )
    [event] = events_of(engine, "wifi.handshake_failed")
    assert event.params["reason"] == "timeout"
    assert event.cause == "weak_signal"
    assert event.cause_status is CauseStatus.CONFIRMED
    assert event.signal == -80


@pytest.mark.asyncio
async def test_backhaul_psk_failure_is_tracked_per_uplink(
    engine: NetIntelligence,
) -> None:
    log = Log()
    line = BACKHAUL_PSK
    engine.ingest("r1", data(log.lines((10, line), (30, line), (50, line))), T0 + 60)
    [incident] = open_incidents(engine, "wifi_auth_failures")
    assert incident.scope is Scope.ROUTER
    assert incident.scope_key == "r1:backhaul:phy1-sta0"
    assert open_incidents(engine, "wifi_auth_wave") == []


@pytest.mark.asyncio
async def test_auth_wave_needs_several_clients(engine: NetIntelligence) -> None:
    log = Log()
    # one client, 12 failed attempts: per-client incident, no wave
    single = log.lines(*((10 + i * 10, psk(MAC1)) for i in range(12)))
    engine.ingest("r1", data(single), T0 + 150)
    assert open_incidents(engine, "wifi_auth_wave") == []
    assert len(open_incidents(engine, "wifi_auth_failures")) == 1


@pytest.mark.asyncio
async def test_auth_wave_across_routers_and_clients(engine: NetIntelligence) -> None:
    """The wave counts distinct clients (P4 review M6): 3 on r1 (with
    repeats), 2 more on r2."""
    log = Log()
    macs = [MAC1, MAC2, MAC3]
    first = log.lines(*((10 + i * 10, psk(macs[i % 3])) for i in range(6)))
    engine.ingest("r1", data(first), T0 + 80)
    assert open_incidents(engine, "wifi_auth_wave") == []
    second = log.lines((90, sae(MAC4)), (100, sae(MACS[0])), (110, sae(MAC4)))
    engine.ingest("r2", data(second), T0 + 140)
    [wave] = open_incidents(engine, "wifi_auth_wave")
    assert wave.scope is Scope.FLEET
    assert wave.occurrences == 5 and wave.affected == 5
    assert sorted(wave.routers) == ["r1", "r2"]
    assert wave.cause == "psk_changed"
    assert wave.cause_status is CauseStatus.HYPOTHESIS


# --- band / AP changes ------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_band_flapping_from_client_lists_is_inferred(
    engine: NetIntelligence,
) -> None:
    for n in range(6):
        iface = "phy1-ap0" if n % 2 == 0 else "phy0-ap0"
        engine.ingest("r1", data(clients=[client(MAC1, iface)]), T0 + n * 60)
    changes = events_of(engine, "wifi.band_change")
    assert len(changes) == 5
    assert changes[0].params["from_band"] == "5g"
    assert changes[0].params["to_band"] == "2.4g"
    assert changes[0].origin is Origin.INFERRED
    assert changes[0].confidence <= INFERRED_CONFIDENCE_CAP
    [incident] = open_incidents(engine, "wifi_band_flapping")
    assert incident.origin is Origin.INFERRED
    assert incident.confidence <= INFERRED_CONFIDENCE_CAP
    assert incident.cause_status is not CauseStatus.CONFIRMED


@pytest.mark.asyncio
async def test_roam_flapping_without_usteer_from_poll_differences(
    engine: NetIntelligence,
) -> None:
    now = T0
    for n in range(5):
        on, off = ("r1", "r2") if n % 2 == 0 else ("r2", "r1")
        engine.ingest(off, data(clients=[]), now)
        engine.ingest(on, data(clients=[client(MAC1, signal=-77)]), now + 1)
        now += 60
    roams = events_of(engine, "wifi.roam")
    assert len(roams) == 4
    assert roams[0].params["from_router"] == "r1"
    assert roams[0].params["to_router"] == "r2"
    assert roams[0].source is Source.POLL and roams[0].origin is Origin.INFERRED
    # a poll-measured signal never confirms the cause of a roam (E1)
    assert roams[0].cause == "weak_signal"
    assert roams[0].cause_status is CauseStatus.HYPOTHESIS
    [incident] = open_incidents(engine, "wifi_roam_flapping")
    assert incident.confidence <= INFERRED_CONFIDENCE_CAP


@pytest.mark.asyncio
async def test_client_on_two_routers_counts_once_when_the_old_one_drops_it(
    engine: NetIntelligence,
) -> None:
    """The old AP keeps a station until its inactivity timeout."""
    engine.ingest("r1", data(clients=[client(MAC1)]), T0)
    engine.ingest("r2", data(clients=[client(MAC1)]), T0 + 30)  # stale on r1
    engine.ingest("r1", data(clients=[client(MAC1)]), T0 + 60)
    engine.ingest("r2", data(clients=[client(MAC1)]), T0 + 90)
    assert events_of(engine, "wifi.roam") == []
    engine.ingest("r1", data(clients=[]), T0 + 120)
    engine.ingest("r2", data(clients=[client(MAC1)]), T0 + 150)
    assert len(events_of(engine, "wifi.roam")) == 1


@pytest.mark.asyncio
async def test_roam_flapping_with_usteer_is_observed(engine: NetIntelligence) -> None:
    """usteer's view plus its log line of the move: observed (E2)."""
    engine.ingest("r2", data(), T0, host="192.0.2.2")
    local = {MAC1.lower(): ("hostapd.phy1-ap0",)}
    remote = {MAC1.lower(): ("192.0.2.2#hostapd.phy1-ap0",)}
    unknown = {MAC1.lower(): ("192.0.2.99#hostapd.phy1-ap0",)}
    log = Log()
    now = T0 + 10
    for n in range(5):
        view = local if n % 2 == 0 else remote
        direction = "connected to" if n % 2 == 0 else "disconnected from"
        line = f"usteer: station {MAC1.lower()} {direction} node hostapd.phy1-ap0"
        lines = log.lines((now - T0 - 30, line)) if n else log.lines()
        engine.ingest(
            "r1",
            data(lines, usteer=view, usteer_status="ok"),
            now,
            host="192.0.2.1",
        )
        now += 120
    engine.ingest("r1", data(usteer=unknown, usteer_status="ok"), now)
    roams = events_of(engine, "wifi.roam")
    assert len(roams) == 4
    assert all(r.source is Source.USTEER for r in roams)
    assert all(r.origin is Origin.OBSERVED for r in roams)
    [incident] = open_incidents(engine, "wifi_roam_flapping")
    assert incident.origin is Origin.OBSERVED
    # the client lists do not add inferred roams while usteer covers MAC1
    engine.ingest("r1", data(clients=[client(MAC1)]), now + 5)
    engine.ingest("r1", data(clients=[]), now + 10)
    engine.ingest("r2", data(clients=[client(MAC1)]), now + 15)
    assert len(events_of(engine, "wifi.roam")) == 4


# --- weak clients, no IP, DHCP after connect -------------------------------------------------


@pytest.mark.asyncio
async def test_weak_clients_need_the_hold_and_clear_with_hysteresis(
    engine: NetIntelligence,
) -> None:
    def poll(signals: list[int]) -> SimpleNamespace:
        clients = [client(MACS[i], signal=s) for i, s in enumerate(signals)]
        return data(clients=[*clients, client(MAC4, signal=-50)], fetched=False)

    for n in range(10):
        engine.ingest("r1", poll([-78, -80, -76]), T0 + n * 60)
    assert open_incidents(engine, "wifi_weak_clients") == []  # 540 s < hold
    engine.ingest("r1", poll([-78, -80, -76]), T0 + 600)
    [incident] = open_incidents(engine, "wifi_weak_clients")
    assert incident.scope is Scope.RADIO and incident.scope_key == "r1:radio:phy1"
    assert incident.origin is Origin.INFERRED
    # -72 dBm is between clear (-70) and weak (-75): still weak
    engine.ingest("r1", poll([-78, -80, -72]), T0 + 660)
    assert open_incidents(engine, "wifi_weak_clients")
    engine.ingest("r1", poll([-78, -80, -65]), T0 + 720)
    assert open_incidents(engine, "wifi_weak_clients") == []


@pytest.mark.asyncio
async def test_no_ip_after_debounce_and_warning_with_three_clients(
    engine: NetIntelligence,
) -> None:
    context = (frozenset({MAC4}), frozenset(), frozenset())
    clients = [client(m, since=T0 - 600) for m in (MAC1, MAC2, MAC3)]
    clients.append(client(MAC4, since=T0 - 600))  # has a lease
    clients.append(client(MACS[0], since=T0 - 30))  # just connected: pending
    with patch.object(net_engine, "dhcp_context", return_value=context):
        engine.ingest("r1", data(clients=clients, fetched=False), T0)
        assert open_incidents(engine, "wifi_no_ip") == []
        engine.ingest("r1", data(clients=clients, fetched=False), T0 + 60)
    incidents = open_incidents(engine, "wifi_no_ip")
    assert sorted(i.scope_key for i in incidents) == [MAC1, MAC2, MAC3]
    assert all(i.severity is Severity.WARNING for i in incidents)
    assert all(i.origin is Origin.INFERRED for i in incidents)
    stored = events_of(engine, "wifi.no_ip")
    assert len(stored) == 3  # one per client, on the first missing poll
    assert stored[0].params["clients_without_ip"] == 3
    assert stored[0].cause_status is CauseStatus.HYPOTHESIS


@pytest.mark.asyncio
async def test_single_client_without_ip_stays_info(engine: NetIntelligence) -> None:
    context = (frozenset(), frozenset({MAC2}), frozenset())  # MAC2: in ARP
    clients = [client(MAC1, since=T0 - 600), client(MAC2, since=T0 - 600)]
    with patch.object(net_engine, "dhcp_context", return_value=context):
        engine.ingest("r1", data(clients=clients, fetched=False), T0)
        engine.ingest("r1", data(clients=clients, fetched=False), T0 + 60)
    [incident] = open_incidents(engine, "wifi_no_ip")
    assert incident.scope_key == MAC1 and incident.severity is Severity.INFO


@pytest.mark.asyncio
async def test_no_ip_is_unknown_without_a_dhcp_view(engine: NetIntelligence) -> None:
    clients = [client(MAC1, since=T0 - 600)]
    with patch.object(net_engine, "dhcp_context", return_value=None):
        for n in range(3):
            engine.ingest("r1", data(clients=clients, fetched=False), T0 + n * 60)
    assert open_incidents(engine, "wifi_no_ip") == []
    assert events_of(engine, "wifi.no_ip") == []


NAK = "dnsmasq-dhcp[1]: DHCPNAK(br-lan) 192.0.2.51 {mac} wrong network"
NO_ADDRESS = "dnsmasq-dhcp[1]: DHCPDISCOVER(br-lan) {mac} no address available"


@pytest.mark.asyncio
@pytest.mark.parametrize("gateway_first", [False, True])
async def test_dhcp_failure_after_connect_across_routers(
    engine: NetIntelligence, gateway_first: bool
) -> None:
    log = Log()
    ap_lines = log.lines((100, conn(MAC1)))
    gw_lines = log.lines((110, NAK.format(mac=MAC1.lower())))
    order = [("r1", gw_lines), ("r2", ap_lines)]
    if not gateway_first:
        order.reverse()
    for n, (router, lines) in enumerate(order):
        engine.ingest(router, data(lines), T0 + 120 + n)
    # a NAK counts once the gateway's log showed no ACK for 30 s (E4)
    assert open_incidents(engine, "wifi_dhcp_after_connect") == []
    engine.ingest("r1", data(log.lines()), T0 + 160)
    [incident] = open_incidents(engine, "wifi_dhcp_after_connect")
    assert incident.scope_key == MAC1
    assert incident.origin is Origin.OBSERVED
    [event] = events_of(engine, "wifi.dhcp_after_connect")
    assert event.params["dhcp"] == "nak" and event.params["delay_s"] == 10
    assert event.params["ap_router"] == "r2" and event.params["dhcp_router"] == "r1"
    assert event.cause == "wrong_network"


@pytest.mark.asyncio
async def test_dhcp_failure_long_after_connect_is_not_paired(
    engine: NetIntelligence,
) -> None:
    log = Log()
    lines = log.lines((100, conn(MAC1)), (220, NO_ADDRESS.format(mac=MAC1.lower())))
    engine.ingest("r1", data(lines), T0 + 240)
    assert open_incidents(engine, "wifi_dhcp_after_connect") == []


# --- mass disconnect ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mass_disconnect_from_log_lines(engine: NetIntelligence) -> None:
    log = Log()
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(*((100 + i * 0.5, disc(MACS[i])) for i in range(6)))
    engine.ingest("r1", data(lines, clients[6:]), T0 + 120)
    [event] = events_of(engine, "wifi.mass_disconnect")
    assert event.count == 6 and event.severity is Severity.WARNING
    assert event.origin is Origin.OBSERVED
    assert event.params["window_s"] == 5
    [incident] = open_incidents(engine, "wifi_mass_disconnect")
    assert incident.affected == 6 and incident.scope_key == "r1"
    # the same lines never count twice
    engine.ingest("r1", data(log.lines((140, disc(MACS[6]))), []), T0 + 180)
    assert len(events_of(engine, "wifi.mass_disconnect")) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(("before", "leaving", "expected"), [(4, 3, 1), (2, 1, 0)])
async def test_mass_disconnect_by_ratio_needs_three_clients(
    engine: NetIntelligence, before: int, leaving: int, expected: int
) -> None:
    log = Log()
    clients = [client(m) for m in MACS[:before]]
    engine.ingest("r1", data(clients=clients, fetched=False), T0)
    lines = log.lines(*((100 + i, disc(MACS[i])) for i in range(leaving)))
    engine.ingest("r1", data(lines, clients[leaving:]), T0 + 120)
    assert len(events_of(engine, "wifi.mass_disconnect")) == expected


@pytest.mark.asyncio
async def test_mass_disconnect_without_log_is_inferred(engine: NetIntelligence) -> None:
    clients = [client(m) for m in MACS[:8]]
    engine.ingest("r1", data(clients=clients, log_status="not_permitted"), T0)
    engine.ingest("r1", data(clients=clients[:2], log_status="not_permitted"), T0 + 60)
    # the drop must persist on the next poll (K4)
    engine.ingest("r1", data(clients=clients[:2], log_status="not_permitted"), T0 + 120)
    [event] = events_of(engine, "wifi.mass_disconnect")
    assert event.origin is Origin.INFERRED and event.source is Source.POLL
    assert event.confidence <= INFERRED_CONFIDENCE_CAP and event.count == 6


# --- missing log data -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_missing_log_lowers_coverage_and_never_reads_healthy(
    engine: NetIntelligence,
) -> None:
    log = Log()
    engine.ingest("r1", data(log.lines((1, conn(MAC1))), [client(MAC1)]), T0)
    full = engine.diagnostics("r1", T0)["wifi_coverage"]
    assert full == {
        "applicable": True,
        "clients": True,
        "log": 1.0,
        "log_missed_lines": 0,
        "usteer": None,
        "value": 1.0,
    }
    engine.ingest(
        "r1", data(log.lines((2, conn(MAC2))), [client(MAC1)], missed=3), T0 + 60
    )
    partial = engine.diagnostics("r1", T0 + 60)["wifi_coverage"]
    assert partial["log"] == 0.4 and partial["log_missed_lines"] == 3
    assert partial["value"] < 1.0
    engine.ingest(
        "r1", data(clients=[client(MAC1)], log_status="not_permitted"), T0 + 120
    )
    missing = engine.diagnostics("r1", T0 + 120)["wifi_coverage"]
    assert missing["log"] == 0.0 and missing["value"] == 0.5


@pytest.mark.asyncio
async def test_open_storm_stays_open_while_the_log_is_unreadable(
    engine: NetIntelligence,
) -> None:
    log = Log()
    events = log.lines(
        *(
            item
            for k in range(5)
            for item in ((k * 20, disc(MAC1)), (k * 20 + 5, conn(MAC1)))
        )
    )
    engine.ingest("r1", data(events, [client(MAC1)]), T0 + 120)
    assert open_incidents(engine, "wifi_reconnect_storm")
    # no log for an hour: no lines is no proof of a stable client
    for n in range(1, 61):
        engine.ingest(
            "r1",
            data(clients=[client(MAC1)], log_status="error", fetched=False),
            T0 + 120 + n * 60,
        )
    assert open_incidents(engine, "wifi_reconnect_storm")
    # readable again and quiet: resolves after the clear time
    for n in range(61, 95):
        engine.ingest("r1", data(clients=[client(MAC1)]), T0 + 120 + n * 60)
    assert open_incidents(engine, "wifi_reconnect_storm") == []


# --- pure helpers ----------------------------------------------------------------------------


def test_cause_list_puts_confirmed_first_without_repeats() -> None:
    top, status, listed = cause_list(
        [
            ("roaming", CauseStatus.HYPOTHESIS),
            ("weak_signal", CauseStatus.HYPOTHESIS),
            ("weak_signal", CauseStatus.CONFIRMED),
        ]
    )
    assert top == "weak_signal" and status is CauseStatus.CONFIRMED
    assert listed == [
        {"cause": "weak_signal", "status": "confirmed"},
        {"cause": "roaming", "status": "hypothesis"},
    ]
    assert cause_list([]) == (None, None, [])


def test_wifi_context_skips_broken_entries() -> None:
    context = wifi_context(
        [*IFACES, {"ifname": 5}, "x", {"ifname": "wlan1", "band": "6g"}],
        [client(MAC1), {"mac": None}, "y"],
    )
    assert context.ifaces["phy1-ap0"] == ("5g", SSID, "phy1")
    assert context.ifaces["wlan1"] == ("6g", None, "wlan1")
    assert set(context.clients or {}) == {MAC1}
    assert wifi_context(None, None).clients is None


def test_detect_wifi_without_clients_or_log_finds_nothing() -> None:
    state = WifiState()
    snap = WifiSnapshot(context=WifiContext(), log_status=None)
    assert detect_wifi(state, snap, T0, "r1", THRESHOLDS) == []
    assert state.coverage("r1") == {"applicable": False}


def test_wifi_state_stays_bounded() -> None:
    state = WifiState()
    log = Log()
    lines = log.lines(
        *((i, conn(f"02:00:5E:20:{i // 256:02X}:{i % 256:02X}")) for i in range(5000))
    )
    snap = WifiSnapshot(
        context=wifi_context(IFACES, []),
        has_aps=True,
        log_events=lines,
        log_status="ok",
        log_lines=len(lines),
    )
    detect_wifi(state, snap, T0, "r1", THRESHOLDS)
    detect_wifi(
        state, WifiSnapshot(context=wifi_context(IFACES, [])), T0 + 1, "r1", THRESHOLDS
    )
    assert len(state.connects) <= 4096
    detect_wifi(
        state,
        WifiSnapshot(context=wifi_context(IFACES, [])),
        T0 + 7200,
        "r1",
        THRESHOLDS,
    )
    assert len(state.history) == 0


def test_track_entries_keep_their_router_and_load_old_entries() -> None:
    from custom_components.openwrt_router.net_rules import _Track

    track = _Track.from_dict(
        {
            "type": "wifi_auth_wave",
            "scope_key": "fleet:wifi_auth_wave",
            "entries": [[T0, 2, "r1:1", "wifi.auth_wave"], [T0 + 1, 3, None, "", "r2"]],
        }
    )
    assert track is not None
    assert track.entries == [
        [T0, 2, "r1:1", "wifi.auth_wave", ""],
        [T0 + 1, 3, None, "", "r2"],
    ]
    assert _Track.from_dict(track.to_dict()).entries == track.entries
