"""Tests for the router log ingest (F6): log_parser.py, coordinator glue, API, logbook.

Example lines follow the exact format seen on OpenWrt 25.12.1 routers
(hostapd, dnsmasq-dhcp, usteer, dropbear); MACs and IPs are placeholders.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.const import (
    EVENT_DHCP,
    EVENT_WIFI,
    LOG_READ_LINES,
    LOG_STATUS_ERROR,
    LOG_STATUS_OK,
    LOG_STATUS_PENDING,
    LOG_STATUS_NOT_PERMITTED,
)
from custom_components.openwrt_router.log_parser import (
    CATEGORY_DHCP,
    CATEGORY_WIFI,
    DHCP_ACK,
    DHCP_DECLINE,
    DHCP_NAK,
    DHCP_NO_ADDRESS,
    MESSAGE_MAX_LEN,
    WIFI_CONNECTED,
    WIFI_DISCONNECTED,
    WIFI_HANDSHAKE_FAILED,
    WIFI_INACTIVITY,
    WIFI_PSK_MISMATCH,
    EventLimiter,
    LogCursor,
    LogEvent,
    RollingCounter,
    parse_entry,
)

MAC = "02:00:00:00:00:01"
MAC2 = "02:00:00:00:00:02"
T = 1_793_094_113_364  # epoch ms


def _e(msg, log_id=1, time_ms=T):
    return {"msg": msg, "id": log_id, "priority": 30, "source": 1, "time": time_ms}


# =====================================================================
# parse_entry
# =====================================================================


class TestParseEntry:
    @pytest.mark.parametrize(
        ("msg", "category", "kind", "iface", "ip"),
        [
            (f"hostapd: phy0-ap1: AP-STA-CONNECTED {MAC} auth_alg=open", CATEGORY_WIFI, WIFI_CONNECTED, "phy0-ap1", None),
            (f"hostapd: phy0-ap1: AP-STA-DISCONNECTED {MAC}", CATEGORY_WIFI, WIFI_DISCONNECTED, "phy0-ap1", None),
            (f"hostapd: phy0-ap2: AP-STA-POSSIBLE-PSK-MISMATCH {MAC}", CATEGORY_WIFI, WIFI_PSK_MISMATCH, "phy0-ap2", None),
            (
                f"hostapd: phy0-ap1: STA {MAC} IEEE 802.11: deauthenticated due to inactivity (timer DEAUTH/REMOVE)",
                CATEGORY_WIFI,
                WIFI_INACTIVITY,
                "phy0-ap1",
                None,
            ),
            (f"hostapd: phy1-ap0: STA {MAC} WPA: EAPOL-Key timeout", CATEGORY_WIFI, WIFI_HANDSHAKE_FAILED, "phy1-ap0", None),
            (f"hostapd: phy1-ap0: STA {MAC} WPA: 4-Way Handshake failed", CATEGORY_WIFI, WIFI_HANDSHAKE_FAILED, "phy1-ap0", None),
            (f"dnsmasq-dhcp[1]: DHCPACK(br-lan) 192.0.2.10 {MAC} laptop", CATEGORY_DHCP, DHCP_ACK, "br-lan", "192.0.2.10"),
            (f"dnsmasq-dhcp[1]: DHCPNAK(br-lan.10) 192.0.2.10 {MAC} wrong address", CATEGORY_DHCP, DHCP_NAK, "br-lan.10", "192.0.2.10"),
            (f"dnsmasq-dhcp[1]: DHCPDECLINE(br-lan) 192.0.2.10 {MAC}", CATEGORY_DHCP, DHCP_DECLINE, "br-lan", "192.0.2.10"),
            (f"dnsmasq-dhcp[1]: DHCPDISCOVER(br-lan) {MAC} no address available", CATEGORY_DHCP, DHCP_NO_ADDRESS, "br-lan", None),
            (f"dnsmasq-dhcp[1]: DHCPACK(br-lan) 2001:db8::10 {MAC} phone", CATEGORY_DHCP, DHCP_ACK, "br-lan", "2001:db8::10"),
        ],
    )
    def test_recognised_lines(self, msg, category, kind, iface, ip):
        event = parse_entry(_e(msg, log_id=7))
        assert event is not None
        assert (event.category, event.kind) == (category, kind)
        assert event.mac == MAC.upper()
        assert event.interface == iface
        assert event.ip == ip
        assert event.log_id == 7
        assert event.time_ms == T
        assert event.key == f"{category}.{kind}"

    def test_mac_is_upper_cased(self):
        event = parse_entry(_e("hostapd: phy0-ap1: AP-STA-CONNECTED 0a:bc:de:f0:12:34"))
        assert event.mac == "0A:BC:DE:F0:12:34"

    @pytest.mark.parametrize(
        "msg",
        [
            f"hostapd: phy0-ap1: EAPOL-4WAY-HS-COMPLETED {MAC}",
            f"hostapd: phy0-ap1: STA {MAC} WPA: pairwise key handshake completed (RSN)",
            f"hostapd: phy0-ap1: STA {MAC} IEEE 802.11: associated (aid 17)",
            f"hostapd: phy1-ap0: BEACON-RESP-RX {MAC} 3 04",
            "hostapd: Unexpected Link measurement report, token 1",
            f"dnsmasq-dhcp[1]: DHCPDISCOVER(br-lan.10) {MAC}",
            f"dnsmasq-dhcp[1]: DHCPOFFER(br-lan.10) 192.0.2.10 {MAC}",
            f"dnsmasq-dhcp[1]: DHCPREQUEST(br-lan) 192.0.2.10 {MAC}",
            f"usteer: station {MAC} disconnected from node hostapd.phy0-ap2",
            "dropbear[2565]: Password auth succeeded for 'root' from 192.0.2.5:64008",
            "kernel: [12345.678] some driver line",
            "no process prefix at all",
            "",
        ],
    )
    def test_other_lines_are_ignored(self, msg):
        assert parse_entry(_e(msg)) is None

    @pytest.mark.parametrize(
        "entry",
        [
            None,
            "string",
            [],
            {},
            {"msg": None, "id": 1},
            {"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {MAC}"},
            {"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {MAC}", "id": "1"},
            {"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {MAC}", "id": True},
            {"msg": 5, "id": 1},
        ],
    )
    def test_broken_entries(self, entry):
        assert parse_entry(entry) is None

    def test_missing_time_becomes_zero(self):
        event = parse_entry({"msg": f"hostapd: x: AP-STA-CONNECTED {MAC}", "id": 1, "time": "?"})
        assert event.time_ms == 0

    def test_message_is_truncated(self):
        msg = f"hostapd: phy0-ap1: AP-STA-POSSIBLE-PSK-MISMATCH {MAC} " + "x" * 500
        assert len(parse_entry(_e(msg)).message) == MESSAGE_MAX_LEN


# =====================================================================
# LogCursor
# =====================================================================


def _batch(first, last, msg=f"hostapd: phy0-ap1: AP-STA-POSSIBLE-PSK-MISMATCH {MAC}"):
    return [_e(msg, log_id=i) for i in range(first, last + 1)]


class TestLogCursor:
    def test_first_fetch_is_baseline(self):
        cursor = LogCursor()
        result = cursor.ingest(_batch(100, 104))
        assert result.baseline is True
        assert result.new_lines == 5
        assert len(result.events) == 5
        assert cursor.last_id == 104

    def test_only_new_ids_after_baseline(self):
        cursor = LogCursor()
        cursor.ingest(_batch(100, 104))
        result = cursor.ingest(_batch(102, 107))
        assert result.baseline is False
        assert [e.log_id for e in result.events] == [105, 106, 107]
        assert result.missed == 0

    def test_nothing_new(self):
        cursor = LogCursor()
        cursor.ingest(_batch(100, 104))
        result = cursor.ingest(_batch(100, 104))
        assert (result.new_lines, result.events, result.baseline) == (0, [], False)

    def test_gap_counts_missed_lines(self):
        cursor = LogCursor()
        cursor.ingest(_batch(100, 104))
        result = cursor.ingest(_batch(200, 210))
        assert result.missed == 95
        assert result.new_lines == 11

    def test_logd_restart_is_a_new_baseline(self):
        cursor = LogCursor()
        cursor.ingest(_batch(5000, 5010))
        result = cursor.ingest(_batch(1, 20))
        assert result.baseline is True
        assert result.new_lines == 20
        assert cursor.last_id == 20

    def test_unsorted_and_invalid_entries(self):
        cursor = LogCursor()
        entries = [_e("x", 3), "junk", {"id": "4"}, _e("y", 1), {"msg": "z"}, _e("w", 2)]
        result = cursor.ingest(entries)
        assert result.new_lines == 3
        assert cursor.last_id == 3

    def test_empty_fetch_keeps_position(self):
        cursor = LogCursor()
        cursor.ingest(_batch(100, 104))
        assert cursor.ingest([]).new_lines == 0
        assert cursor.last_id == 104
        assert LogCursor().ingest([]).baseline is False


# =====================================================================
# EventLimiter / RollingCounter
# =====================================================================


def _ev(kind=WIFI_PSK_MISMATCH, mac=MAC, category=CATEGORY_WIFI, log_id=1):
    return LogEvent(category=category, kind=kind, log_id=log_id, time_ms=T, mac=mac)


class TestEventLimiter:
    def test_count_only_kinds_never_fire(self):
        limiter = EventLimiter(10, 300_000)
        fire, suppressed = limiter.select(
            [_ev(WIFI_CONNECTED), _ev(WIFI_DISCONNECTED), _ev(DHCP_ACK, category=CATEGORY_DHCP)],
            T,
        )
        assert (fire, suppressed) == ([], 0)

    def test_cooldown_per_kind_and_mac(self):
        limiter = EventLimiter(10, 300_000)
        fire, suppressed = limiter.select(
            [_ev(), _ev(), _ev(mac=MAC2), _ev(WIFI_INACTIVITY)], T
        )
        assert len(fire) == 3
        assert suppressed == 1
        fire, suppressed = limiter.select([_ev()], T + 299_000)
        assert (fire, suppressed) == ([], 1)
        fire, _ = limiter.select([_ev()], T + 300_000)
        assert len(fire) == 1

    def test_max_per_fetch(self):
        limiter = EventLimiter(10, 300_000)
        events = [_ev(mac=f"02:00:00:00:00:{i:02X}") for i in range(15)]
        fire, suppressed = limiter.select(events, T)
        assert len(fire) == 10
        assert suppressed == 5


class TestRollingCounter:
    def test_window(self):
        counter = RollingCounter(window_ms=1000)
        counter.add(0, "wifi.connected")
        counter.add(500, "wifi.connected")
        counter.add(900, "dhcp.nak")
        assert counter.counts(1000) == {"dhcp.nak": 1, "wifi.connected": 2}
        assert counter.counts(1600) == {"dhcp.nak": 1}
        assert counter.counts(5000) == {}

    def test_bounded(self):
        counter = RollingCounter(window_ms=10**9, max_items=3)
        for i in range(5):
            counter.add(i, "k")
        assert counter.counts(10) == {"k": 3}


# =====================================================================
# Coordinator glue
# =====================================================================


def _coordinator():
    from custom_components.openwrt_router.coordinator import (
        OpenWrtCoordinator,
        OpenWrtCoordinatorData,
    )

    hass = MagicMock()
    api = AsyncMock()
    with patch("homeassistant.helpers.frame.report_usage"):
        coord = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    coord._entry = MagicMock(entry_id="e1", title="Router A")
    data = OpenWrtCoordinatorData()
    data.dhcp_leases = {MAC: {"ip": "192.0.2.10", "hostname": "laptop"}}
    data.clients = [{"mac": MAC2, "hostname": "phone"}]
    return coord, api, data


def _fired(coord, event_type):
    return [
        c.args[1]
        for c in coord.hass.bus.async_fire.call_args_list
        if c.args[0] == event_type
    ]


class TestCoordinatorIngest:
    @pytest.mark.asyncio
    async def test_baseline_counts_without_events(self):
        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(return_value=_batch(100, 104))
        await coord._ingest_log(data)
        api.get_log_entries.assert_awaited_once_with(LOG_READ_LINES)
        assert coord._log_status == LOG_STATUS_OK
        assert _fired(coord, EVENT_WIFI) == []
        assert coord._log_totals["baseline_lines"] == 5
        assert coord._log_counter.counts(T) == {"wifi.psk_mismatch": 5}

    @pytest.mark.asyncio
    async def test_new_lines_fire_events_with_hostname(self):
        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(return_value=_batch(100, 101))
        await coord._ingest_log(data)
        api.get_log_entries = AsyncMock(
            return_value=_batch(100, 101)
            + [
                _e(f"hostapd: phy0-ap1: AP-STA-POSSIBLE-PSK-MISMATCH {MAC}", 102),
                _e(f"hostapd: phy0-ap1: AP-STA-POSSIBLE-PSK-MISMATCH {MAC}", 103),
                _e(f"hostapd: phy0-ap1: STA {MAC2} IEEE 802.11: deauthenticated due to inactivity", 104),
                _e(f"hostapd: phy0-ap1: AP-STA-CONNECTED {MAC2} auth_alg=open", 105),
                _e(f"dnsmasq-dhcp[1]: DHCPNAK(br-lan) 192.0.2.10 {MAC} wrong address", 106),
            ]
        )
        with patch(
            "custom_components.openwrt_router.coordinator.time.time",
            return_value=T / 1000,
        ):
            await coord._ingest_log(data)

        wifi = _fired(coord, EVENT_WIFI)
        assert [(p["type"], p["hostname"]) for p in wifi] == [
            ("psk_mismatch", "laptop"),
            ("inactivity_timeout", "phone"),
        ]
        assert wifi[0]["entry_id"] == "e1"
        assert wifi[0]["router"] == "Router A"
        assert wifi[0]["mac"] == MAC
        assert wifi[0]["interface"] == "phy0-ap1"
        assert wifi[0]["time"].startswith("2026-")
        (dhcp,) = _fired(coord, EVENT_DHCP)
        assert (dhcp["type"], dhcp["ip"], dhcp["hostname"]) == ("nak", "192.0.2.10", "laptop")
        assert coord._log_totals["events_fired"] == 3
        assert coord._log_totals["events_suppressed"] == 1  # 2nd PSK mismatch

    @pytest.mark.asyncio
    async def test_acl_blocked_sets_unavailable(self):
        from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(side_effect=OpenWrtMethodNotFoundError("acl"))
        await coord._ingest_log(data)
        await coord._ingest_log(data)
        assert coord._log_status == LOG_STATUS_NOT_PERMITTED

    @pytest.mark.asyncio
    async def test_other_errors_set_error(self):
        from custom_components.openwrt_router.api import OpenWrtTimeoutError

        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))
        await coord._ingest_log(data)
        assert coord._log_status == LOG_STATUS_ERROR

    @pytest.mark.asyncio
    async def test_poll_fetches_every_second_cycle_and_never_fails(self):
        from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

        coord, api, _ = _coordinator()
        api.reset_ssh_fallback_flag = MagicMock()
        api.uses_ssh_fallback = False
        api.detect_features = AsyncMock(return_value={})
        api.get_router_info = AsyncMock(return_value={})
        api.get_wan_status = AsyncMock(return_value={"connected": True})
        api.get_wifi_status = AsyncMock(return_value=[])
        api.get_dhcp_leases = AsyncMock(return_value={})
        api.get_connected_clients = AsyncMock(return_value=[])
        api.get_router_status = AsyncMock(return_value={"memory": {}})
        api.get_services = AsyncMock(return_value=[])
        api.get_log_entries = AsyncMock(side_effect=OpenWrtMethodNotFoundError("acl"))

        statuses = []
        for _ in range(5):
            coord.data = await coord._async_update_data()
            statuses.append(coord.data.log_status)
        # polls 2 and 4 fetch; poll 1 (setup) is skipped
        assert api.get_log_entries.await_count == 2
        assert statuses == [
            LOG_STATUS_PENDING,
            LOG_STATUS_NOT_PERMITTED,
            LOG_STATUS_NOT_PERMITTED,
            LOG_STATUS_NOT_PERMITTED,
            LOG_STATUS_NOT_PERMITTED,
        ]
        assert set(coord.data.log_stats) >= {
            "counts_24h",
            "lines_processed",
            "baseline_lines",
            "missed_lines",
            "events_fired",
            "events_suppressed",
        }
        assert coord.data.as_dict()["log_status"] == LOG_STATUS_NOT_PERMITTED


# =====================================================================
# API
# =====================================================================


def _api():
    from custom_components.openwrt_router.api import OpenWrtAPI

    return OpenWrtAPI(
        host="router.test",
        port=80,
        username="root",
        password="test",
        session=MagicMock(),
        protocol="http",
    )


class TestApiGetLogEntries:
    @pytest.mark.asyncio
    async def test_calls_log_read_without_stream(self):
        api = _api()
        api._call = AsyncMock(return_value={"log": [_e("x")]})
        assert await api.get_log_entries(250) == [_e("x")]
        api._call.assert_awaited_once_with("log", "read", {"lines": 250, "stream": False})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("answer", [{}, {"log": "x"}, [], None])
    async def test_bad_shape_raises_response_error(self, answer):
        from custom_components.openwrt_router.api import OpenWrtResponseError

        api = _api()
        api._call = AsyncMock(return_value=answer)
        with pytest.raises(OpenWrtResponseError):
            await api.get_log_entries(250)


# =====================================================================
# ACL + logbook
# =====================================================================


class TestAclV6:
    def test_log_and_usteer_are_granted_read_only(self):
        from custom_components.openwrt_router.acl_provisioning import (
            ACL_VERSION,
            RPCD_ACL_CONTENT,
        )

        assert ACL_VERSION == 6
        read = RPCD_ACL_CONTENT["root"]["read"]["ubus"]
        write = RPCD_ACL_CONTENT["root"]["write"]["ubus"]
        assert read["log"] == ["read"]
        assert read["usteer"] == ["get_clients"]
        assert "log" not in write
        assert "usteer" not in write


class TestLogbook:
    def test_descriptions(self):
        from custom_components.openwrt_router.logbook import async_describe_events

        registered = {}
        async_describe_events(
            MagicMock(), lambda domain, event, fn: registered.setdefault(event, fn)
        )
        wifi = registered[EVENT_WIFI](
            MagicMock(
                data={
                    "router": "Router A",
                    "type": "psk_mismatch",
                    "hostname": "laptop",
                    "interface": "phy0-ap1",
                }
            )
        )
        assert wifi == {
            "name": "Router A",
            "message": "Wi-Fi psk mismatch: laptop on phy0-ap1",
        }
        dhcp = registered[EVENT_DHCP](
            MagicMock(data={"type": "no_address", "mac": MAC})
        )
        assert dhcp == {
            "name": "OpenWrt Router",
            "message": f"DHCP no address: {MAC}",
        }


# =====================================================================
# Review follow-ups (P3)
# =====================================================================


class TestReviewFollowUps:
    def test_log_dhcp_transaction_id_prefix(self):
        event = parse_entry(_e(f"dnsmasq-dhcp[1]: 1234567 DHCPNAK(br-lan) 192.0.2.10 {MAC} wrong"))
        assert (event.kind, event.ip, event.mac) == (DHCP_NAK, "192.0.2.10", MAC)

    def test_dhcpv6_duid_is_not_a_mac(self):
        msg = "dnsmasq-dhcp[1]: DHCPSOLICIT(br-lan) 00:01:00:01:2a:3b:4c:5d:6e:7f no address available"
        assert parse_entry(_e(msg)) is None

    @pytest.mark.parametrize("bad_time", [-1, 5, 10**15, 253_402_300_800_000])
    def test_implausible_time_becomes_zero(self, bad_time):
        event = parse_entry(_e(f"hostapd: x: AP-STA-CONNECTED {MAC}", time_ms=bad_time))
        assert event.time_ms == 0

    def test_restart_detected_when_anchor_line_changed(self):
        cursor = LogCursor()
        cursor.ingest([_e("a", i, T + i) for i in range(100, 105)])
        # logd restarted and has since written more lines than before: id 104
        # exists again, but it is a different line (other time)
        result = cursor.ingest([_e("b", i, T + 10_000 + i) for i in range(50, 120)])
        assert result.baseline is True
        assert result.new_lines == 70

    def test_restart_detected_when_anchor_vanished(self):
        cursor = LogCursor()
        cursor.ingest([_e("a", i, T + i) for i in range(100, 105)])
        entries = [_e("b", i, T + i) for i in range(90, 120) if i != 104]
        assert cursor.ingest(entries).baseline is True

    def test_same_anchor_is_no_restart(self):
        cursor = LogCursor()
        cursor.ingest([_e("a", i, T + i) for i in range(100, 105)])
        result = cursor.ingest([_e("a", i, T + i) for i in range(100, 110)])
        assert result.baseline is False
        assert result.new_lines == 5

    def test_priority_keeps_psk_mismatch_in_budget(self):
        limiter = EventLimiter(10, 300_000)
        events = [
            LogEvent(CATEGORY_WIFI, WIFI_INACTIVITY, i, T, mac=f"02:00:00:00:01:{i:02X}")
            for i in range(12)
        ] + [LogEvent(CATEGORY_WIFI, WIFI_PSK_MISMATCH, 99, T, mac=MAC)]
        fire, suppressed = limiter.select(events, T)
        assert len(fire) == 10
        assert suppressed == 3
        assert fire[-1].kind == WIFI_PSK_MISMATCH  # fired in log order
        assert [e.log_id for e in fire] == sorted(e.log_id for e in fire)


class TestCoordinatorReviewFollowUps:
    @pytest.mark.asyncio
    async def test_line_count_adapts(self):
        from custom_components.openwrt_router.const import (
            LOG_READ_LINES_MAX,
            LOG_READ_LINES_MIN,
        )

        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(return_value=_batch(1, 600))
        await coord._ingest_log(data)  # baseline: keep the default
        assert coord._log_lines == LOG_READ_LINES
        api.get_log_entries = AsyncMock(return_value=_batch(401, 640))
        await coord._ingest_log(data)  # 40 new lines
        assert coord._log_lines == LOG_READ_LINES_MIN
        api.get_log_entries = AsyncMock(return_value=_batch(641, 940))
        await coord._ingest_log(data)  # 300 new lines, no gap
        assert coord._log_lines == 470
        api.get_log_entries.assert_awaited_once_with(LOG_READ_LINES_MIN)
        api.get_log_entries = AsyncMock(return_value=_batch(1500, 1600))
        await coord._ingest_log(data)  # gap → whole buffer next time
        assert coord._log_lines == LOG_READ_LINES_MAX
        assert coord._log_totals["missed_lines"] == 559

    @pytest.mark.asyncio
    async def test_processing_error_never_fails(self):
        coord, api, data = _coordinator()
        api.get_log_entries = AsyncMock(return_value=_batch(1, 3))
        with patch.object(coord, "_process_log", side_effect=ValueError("boom")):
            await coord._ingest_log(data)
        assert coord._log_status == LOG_STATUS_ERROR

    @pytest.mark.asyncio
    async def test_implausible_router_time_counts_now(self):
        coord, api, data = _coordinator()
        old = _e(f"hostapd: phy0-ap1: AP-STA-POSSIBLE-PSK-MISMATCH {MAC}", 1, 1_000)
        api.get_log_entries = AsyncMock(return_value=[old])
        await coord._ingest_log(data)
        now_ms = int(__import__("time").time() * 1000)
        assert coord._log_counter.counts(now_ms) == {"wifi.psk_mismatch": 1}

    @pytest.mark.asyncio
    async def test_payload_carries_device_id(self):
        coord, api, data = _coordinator()
        device = MagicMock(id="dev-1")
        with patch(
            "custom_components.openwrt_router.coordinator.dr.async_get"
        ) as get_reg:
            get_reg.return_value.async_get_device.return_value = device
            api.get_log_entries = AsyncMock(return_value=_batch(1, 1))
            await coord._ingest_log(data)
            api.get_log_entries = AsyncMock(return_value=_batch(1, 2))
            await coord._ingest_log(data)
            api.get_log_entries = AsyncMock(return_value=_batch(1, 3))
            await coord._ingest_log(data)
        (first,) = _fired(coord, EVENT_WIFI)  # 2nd is in the 5 min cooldown
        assert first["device_id"] == "dev-1"
        get_reg.return_value.async_get_device.assert_called_once_with(
            identifiers={("openwrt_router", "e1")}
        )

    def test_not_permitted_is_not_ha_reserved(self):
        assert LOG_STATUS_NOT_PERMITTED == "not_permitted"
