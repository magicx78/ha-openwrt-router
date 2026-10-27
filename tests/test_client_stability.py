"""Tests for Wi-Fi client stability (F4): client_stability.py and glue."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.client_stability import (
    STICKY_HOLD_SECONDS,
    AssociationTracker,
    HoldTimer,
    NodeSignal,
    parse_usteer_clients,
    sticky_candidates,
    unstable_top,
)
from custom_components.openwrt_router.const import (
    USTEER_STATUS_OK,
    USTEER_STATUS_PENDING,
    USTEER_STATUS_UNAVAILABLE,
)

A = "02:00:00:00:00:0a"
B = "02:00:00:00:00:0b"
T = 1_793_094_113_364

# Shape of `ubus call usteer get_clients` (OpenWrt 25.12, usteer on 3 nodes)
USTEER = {
    A: {
        "hostapd.phy0-ap1": {"connected": True, "signal": -78},
        "hostapd.phy1-ap1": {"connected": False, "signal": -60},  # same AP, 5 GHz
        "192.0.2.2#hostapd.phy0-ap1": {"connected": False, "signal": -66},
        "192.0.2.4#hostapd.phy0-ap1": {"connected": False, "signal": -72},
    },
    B: {
        "hostapd.phy0-ap1": {"connected": True, "signal": -60},
        "192.0.2.2#hostapd.phy0-ap1": {"connected": False, "signal": -55},
    },
    "02:00:00:00:00:0c": {  # connected elsewhere
        "hostapd.phy0-ap1": {"connected": False, "signal": -80},
        "192.0.2.2#hostapd.phy0-ap1": {"connected": True, "signal": -50},
    },
}


class TestParseUsteer:
    def test_parse(self):
        parsed = parse_usteer_clients(USTEER)
        assert set(parsed) == {A.upper(), B.upper(), "02:00:00:00:00:0C"}
        local = [n for n in parsed[A.upper()] if n.local]
        assert [n.node for n in local] == ["hostapd.phy0-ap1", "hostapd.phy1-ap1"]
        assert parsed[A.upper()][0] == NodeSignal("hostapd.phy0-ap1", True, True, -78)

    @pytest.mark.parametrize(
        "raw",
        [None, [], "x", {"not-a-mac": {}}, {A: "x"}, {A: {}}, {A: {"n": "x"}}],
    )
    def test_broken(self, raw):
        assert parse_usteer_clients(raw) == {}

    def test_bad_signal_values(self):
        parsed = parse_usteer_clients(
            {A: {"n1": {"connected": True, "signal": True}, "n2": {"signal": 5}, "n3": {"signal": "x"}}}
        )
        assert [n.signal for n in parsed[A.upper()]] == [None, None, None]


class TestStickyCandidates:
    def test_remote_node_8_db_stronger(self):
        cands = sticky_candidates(parse_usteer_clients(USTEER))
        assert set(cands) == {A.upper()}
        assert cands[A.upper()] == {
            "signal": -78,
            "interface": "phy0-ap1",
            "better_node": "192.0.2.2#hostapd.phy0-ap1",
            "better_signal": -66,
            "delta_db": 12,
        }

    def test_own_other_radio_is_no_alternative(self):
        raw = {A: {"hostapd.phy0-ap1": {"connected": True, "signal": -80}, "hostapd.phy1-ap1": {"signal": -50}}}
        assert sticky_candidates(parse_usteer_clients(raw)) == {}

    def test_delta_threshold(self):
        raw = {
            A: {"hostapd.x": {"connected": True, "signal": -70}, "192.0.2.2#hostapd.x": {"signal": -63}},
            B: {"hostapd.x": {"connected": True, "signal": -70}, "192.0.2.2#hostapd.x": {"signal": -62}},
        }
        assert set(sticky_candidates(parse_usteer_clients(raw))) == {B.upper()}

    def test_without_signal_values(self):
        raw = {A: {"hostapd.x": {"connected": True}, "192.0.2.2#hostapd.x": {"signal": -40}}}
        assert sticky_candidates(parse_usteer_clients(raw)) == {}


class TestHoldTimer:
    def test_hold(self):
        timer = HoldTimer()
        timer.update({A}, 0)
        timer.update({A, B}, 300_000)
        assert timer.held(600_000, 600) == {A: 0}
        timer.update({B}, 700_000)
        assert timer.held(900_000, 600) == {B: 300_000}
        timer.update(set(), 950_000)
        assert timer.held(10**9, 600) == {}


class TestAssociationTracker:
    def test_reconnect_within_window(self):
        tr = AssociationTracker(reconnect_ms=300_000)
        tr.connected(A, T)
        tr.disconnected(A, T + 1_000)
        tr.connected(A, T + 61_000)  # reconnect
        tr.disconnected(A, T + 100_000)
        tr.connected(A, T + 500_000)  # 400 s later: no reconnect
        tr.connected(B, T)
        assert tr.counts(T + 600_000) == {
            A: {"associations_24h": 3, "reconnects_24h": 1},
            B: {"associations_24h": 1, "reconnects_24h": 0},
        }

    def test_window_expires(self):
        tr = AssociationTracker(window_ms=1_000_000)
        tr.connected(A, T)
        tr.disconnected(B, T)
        assert tr.counts(T + 2_000_000) == {}
        assert tr._last_disconnect == {}

    def test_unstable_top(self):
        counts = {
            A: {"associations_24h": 9, "reconnects_24h": 4},
            B: {"associations_24h": 2, "reconnects_24h": 0},
            "02:00:00:00:00:0c": {"associations_24h": 12, "reconnects_24h": 4},
        }
        top = unstable_top(counts, limit=10)
        assert [c["mac"] for c in top] == ["02:00:00:00:00:0c", A]


# =====================================================================
# Coordinator
# =====================================================================


def _coordinator():
    from custom_components.openwrt_router.coordinator import OpenWrtCoordinator

    hass = MagicMock()
    api = AsyncMock()
    with patch("homeassistant.helpers.frame.report_usage"):
        coord = OpenWrtCoordinator(hass=hass, api=api, entry_title="test")
    api.reset_ssh_fallback_flag = MagicMock()
    api.uses_ssh_fallback = False
    api.detect_features = AsyncMock(return_value={})
    api.get_router_info = AsyncMock(return_value={})
    api.get_wan_status = AsyncMock(return_value={"connected": True})
    api.get_wifi_status = AsyncMock(return_value=[])
    api.get_dhcp_leases = AsyncMock(return_value={A.upper(): {"ip": "192.0.2.10", "hostname": "laptop"}})
    api.get_connected_clients = AsyncMock(
        return_value=[
            {"mac": A.upper(), "signal": -78, "radio": "phy0-ap1"},
            {"mac": B.upper(), "signal": -60, "radio": "phy0-ap1"},
        ]
    )
    api.get_router_status = AsyncMock(return_value={"memory": {}})
    api.get_services = AsyncMock(return_value=[])
    api.get_ap_interface_details = AsyncMock(
        return_value=[{"ifname": "phy0-ap1", "band": "2.4g", "channel": 6, "frequency": 2437}]
    )
    api.get_log_entries = AsyncMock(return_value=[])
    api.get_dhcp_config = AsyncMock(return_value={})
    api.get_usteer_clients = AsyncMock(return_value=USTEER)
    return coord, api


async def _poll(coord, now_s):
    with patch("custom_components.openwrt_router.coordinator.time.time", return_value=now_s):
        coord.data = await coord._async_update_data()
    return coord.data


class TestCoordinatorStability:
    @pytest.mark.asyncio
    async def test_usteer_schedule_and_sticky_after_hold(self):
        coord, api = _coordinator()
        t0 = T / 1000
        data = await _poll(coord, t0)  # poll 1: setup
        assert data.client_stability["usteer"] == USTEER_STATUS_PENDING
        await _poll(coord, t0 + 60)  # poll 2: log
        api.get_usteer_clients.assert_not_awaited()
        data = await _poll(coord, t0 + 120)  # poll 3: usteer
        assert api.get_usteer_clients.await_count == 1
        assert data.client_stability["usteer"] == USTEER_STATUS_OK
        assert data.client_stability["sticky"] == []  # not held long enough
        for i in range(4, 14):
            data = await _poll(coord, t0 + 60 * i)
        assert api.get_usteer_clients.await_count == 6  # polls 3,5,7,9,11,13
        (sticky,) = data.client_stability["sticky"]
        assert sticky["mac"] == A.upper()
        assert sticky["hostname"] == "laptop"
        assert sticky["delta_db"] == 12

    @pytest.mark.asyncio
    async def test_without_usteer_weak_clients_and_retry(self):
        from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

        coord, api = _coordinator()
        api.get_usteer_clients = AsyncMock(side_effect=OpenWrtMethodNotFoundError("no usteer"))
        t0 = T / 1000
        for i in range(0, 14):
            data = await _poll(coord, t0 + 60 * i)
        assert data.client_stability["usteer"] == USTEER_STATUS_UNAVAILABLE
        assert api.get_usteer_clients.await_count == 1  # retried only every 30 polls
        (weak,) = data.client_stability["weak"]
        assert (weak["mac"], weak["signal"], weak["band"]) == (A.upper(), -78, "2.4g")
        for i in range(14, 34):
            await _poll(coord, t0 + 60 * i)
        assert api.get_usteer_clients.await_count == 2  # poll 33 (3 + 30)

    @pytest.mark.asyncio
    async def test_counts_from_log_lines(self):
        coord, api = _coordinator()
        now = T
        lines = [
            {"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {A} auth_alg=open", "id": 1, "time": now - 600_000},
            {"msg": f"hostapd: phy0-ap1: AP-STA-DISCONNECTED {A}", "id": 2, "time": now - 500_000},
            {"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {A} auth_alg=open", "id": 3, "time": now - 480_000},
        ]
        api.get_log_entries = AsyncMock(return_value=lines)
        await _poll(coord, now / 1000)
        data = await _poll(coord, now / 1000)  # poll 2 fetches the log (baseline counts)
        assert data.client_stability["clients"][A.upper()] == {
            "associations_24h": 2,
            "reconnects_24h": 1,
        }
        assert data.client_stability["unstable"][0]["hostname"] == "laptop"
        assert data.client_stability["unstable_count"] == 0


# =====================================================================
# Entities + fleet
# =====================================================================


def _entry(entry_id, stability, ap=None):
    entry = MagicMock()
    entry.entry_id = entry_id
    entry.title = entry_id
    coordinator = entry.runtime_data.coordinator
    coordinator.last_update_success = True
    coordinator.data.client_stability = stability
    coordinator.data.ap_interfaces = ap or []
    coordinator.data.sta_interfaces = []
    return entry


class TestStickyBinarySensor:
    def _sensor(self, entry, entries):
        from custom_components.openwrt_router.binary_sensor import (
            OpenWrtStickyClientsBinarySensor,
        )

        sensor = OpenWrtStickyClientsBinarySensor(entry.runtime_data.coordinator, entry)
        sensor.hass = MagicMock()
        sensor.hass.config_entries.async_loaded_entries.return_value = entries
        return sensor

    def test_usteer_mode(self):
        own = _entry("gw", {"usteer": USTEER_STATUS_OK, "sticky": [{"mac": A}], "weak": []})
        sensor = self._sensor(own, [own])
        assert sensor.is_on is True
        assert sensor.extra_state_attributes == {"method": "usteer", "clients": [{"mac": A}]}
        assert sensor.unique_id == "gw_sticky_clients"

    def test_signal_mode_needs_alternative_in_same_band(self):
        weak = [{"mac": A, "band": "5g"}, {"mac": B, "band": "2.4g"}]
        own = _entry("gw", {"usteer": USTEER_STATUS_UNAVAILABLE, "weak": weak})
        other = _entry(
            "ap2",
            {},
            ap=[{"ifname": "phy1-ap0", "channel": 36, "frequency": 5180, "mode": "Master"}],
        )
        sensor = self._sensor(own, [own, other])
        assert sensor.is_on is True
        assert sensor.extra_state_attributes == {"method": "signal", "clients": [{"mac": A, "band": "5g"}]}
        alone = self._sensor(own, [own])
        assert alone.is_on is False

    def test_no_data(self):
        own = _entry("gw", {})
        own.runtime_data.coordinator.data = None
        sensor = self._sensor(own, [own])
        assert sensor.is_on is False


class TestTrackerCounts:
    def test_sum_over_routers(self):
        from custom_components.openwrt_router.fleet import client_counts

        hass = MagicMock()
        hass.config_entries.async_loaded_entries.return_value = [
            _entry("gw", {"clients": {A.upper(): {"associations_24h": 3, "reconnects_24h": 1}}}),
            _entry("ap2", {"clients": {A.upper(): {"associations_24h": 2, "reconnects_24h": 2}}}),
            _entry("ap4", {}),
        ]
        assert client_counts(hass, A) == {"associations_24h": 5, "reconnects_24h": 3}
        assert client_counts(hass, B) is None

    def test_tracker_attributes(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.device_tracker import (
            OpenWrtClientTrackerEntity,
        )

        tracker = OpenWrtClientTrackerEntity(mock_coordinator, mock_config_entry, A.upper())
        tracker.hass = MagicMock()
        tracker._find_client = MagicMock(return_value=(None, None))
        with patch(
            "custom_components.openwrt_router.device_tracker.client_counts",
            return_value={"associations_24h": 4, "reconnects_24h": 1},
        ):
            attrs = tracker.extra_state_attributes
        assert attrs["associations_24h"] == 4
        assert attrs["reconnects_24h"] == 1
        assert attrs["connected"] is False


class TestUnstableSensor:
    def test_description(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.sensor import (
            SENSOR_DESCRIPTIONS,
            OpenWrtSensorEntity,
        )

        desc = next(d for d in SENSOR_DESCRIPTIONS if d.key == "unstable_clients")
        mock_coordinator.data.client_stability = {"unstable_count": 2, "unstable": [{"mac": A}]}
        mock_coordinator.data.log_status = "ok"
        sensor = OpenWrtSensorEntity(coordinator=mock_coordinator, entry=mock_config_entry, description=desc)
        assert sensor.native_value == 2
        mock_coordinator.data.log_status = "not_permitted"
        assert sensor.native_value is None
        assert sensor.extra_state_attributes == {"top": [{"mac": A}]}
        for legacy in ("_rate", "_ap_", "_port_", "_radio_", "_iface_"):
            assert legacy not in sensor.unique_id

    def test_hold_constant(self):
        assert STICKY_HOLD_SECONDS == 600


# =====================================================================
# Review follow-ups (P6)
# =====================================================================


class TestReviewFollowUps:
    @pytest.mark.asyncio
    async def test_object_not_found_switches_to_fallback(self):
        from custom_components.openwrt_router.api import OpenWrtResponseError

        coord, api = _coordinator()
        t0 = T / 1000
        for i in range(0, 14):
            data = await _poll(coord, t0 + 60 * i)
        assert data.client_stability["sticky"]
        api.get_usteer_clients = AsyncMock(side_effect=OpenWrtResponseError("Object not found"))
        for i in range(14, 17):
            data = await _poll(coord, t0 + 60 * i)
        assert data.client_stability["usteer"] == USTEER_STATUS_UNAVAILABLE
        assert data.client_stability["sticky"] == []

    @pytest.mark.asyncio
    async def test_transient_error_drops_stale_candidates(self):
        from custom_components.openwrt_router.api import OpenWrtTimeoutError

        coord, api = _coordinator()
        t0 = T / 1000
        for i in range(0, 14):
            await _poll(coord, t0 + 60 * i)
        api.get_usteer_clients = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))
        for i in range(14, 17):
            data = await _poll(coord, t0 + 60 * i)
        assert data.client_stability["usteer"] == USTEER_STATUS_OK
        assert data.client_stability["sticky"] == []

    @pytest.mark.asyncio
    async def test_old_baseline_lines_are_not_reconnects(self):
        coord, api = _coordinator()
        old = T - 30 * 3600 * 1000
        lines = []
        for k in range(3):
            base = old + k * 3_600_000
            lines.append({"msg": f"hostapd: phy0-ap1: AP-STA-DISCONNECTED {A}", "id": 2 * k + 1, "time": base})
            lines.append({"msg": f"hostapd: phy0-ap1: AP-STA-CONNECTED {A} auth_alg=open", "id": 2 * k + 2, "time": base + 60_000})
        api.get_log_entries = AsyncMock(return_value=lines)
        await _poll(coord, T / 1000)
        data = await _poll(coord, T / 1000)
        assert A.upper() not in data.client_stability["clients"]
        assert data.client_stability["unstable_count"] == 0

    def test_band_steering_is_no_reconnect(self):
        tr = AssociationTracker()
        tr.disconnected(A, T, "phy0-ap1")
        tr.connected(A, T + 5_000, "phy1-ap1")
        tr.disconnected(A, T + 10_000, "phy1-ap1")
        tr.connected(A, T + 20_000, "phy1-ap1")
        assert tr.counts(T + 30_000)[A] == {"associations_24h": 2, "reconnects_24h": 1}

    def test_only_same_band_and_ssid_count(self):
        raw = {
            A: {
                "hostapd.phy0-ap1": {"connected": True, "signal": -78},
                "192.0.2.2#hostapd.phy1-ap1": {"signal": -55},  # 5 GHz elsewhere
                "192.0.2.2#hostapd.phy0-ap0": {"signal": -60},  # other SSID
                "192.0.2.4#hostapd.phy0-ap1": {"signal": -69},  # same band + SSID
            }
        }
        info = {
            "hostapd.phy0-ap1": ("2.4g", "iot"),
            "192.0.2.2#hostapd.phy1-ap1": ("5g", "iot"),
            "192.0.2.2#hostapd.phy0-ap0": ("2.4g", "home"),
            "192.0.2.4#hostapd.phy0-ap1": ("2.4g", "iot"),
        }
        (cand,) = sticky_candidates(parse_usteer_clients(raw), info).values()
        assert cand["better_node"] == "192.0.2.4#hostapd.phy0-ap1"
        assert cand["delta_db"] == 9
        info["192.0.2.4#hostapd.phy0-ap1"] = ("2.4g", "home")
        assert sticky_candidates(parse_usteer_clients(raw), info) == {}

    def test_fleet_node_info(self):
        from custom_components.openwrt_router.fleet import usteer_node_info

        entry = _entry("ap2", {}, ap=[{"ifname": "phy0-ap1", "frequency": 2437, "ssid": "iot"}])
        entry.data = {"host": "192.0.2.2"}
        hass = MagicMock()
        hass.config_entries.async_loaded_entries.return_value = [entry]
        assert usteer_node_info(hass) == {"192.0.2.2#hostapd.phy0-ap1": ("2.4g", "iot")}

    @pytest.mark.asyncio
    async def test_diagnostics_without_client_macs(self):
        coord, api = _coordinator()
        data = await _poll(coord, T / 1000)
        assert "clients" in data.client_stability
        assert "clients" not in data.as_dict()["client_stability"]
