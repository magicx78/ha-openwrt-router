"""Tests for DHCP health (F5): dhcp_health.py, coordinator, fleet, tracker, sensor."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from custom_components.openwrt_router.dhcp_health import (
    DHCP_MISSING,
    DHCP_MISSING_AFTER_SECONDS,
    DHCP_OK,
    DHCP_PENDING,
    DHCP_STATIC_NO_LEASE,
    Pool,
    client_dhcp_status,
    parse_dhcp_config,
    pool_usage,
)

MAC = "02:00:00:00:00:01"
NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)

# Shape of `ubus call uci get {"config":"dhcp"}` on OpenWrt 25.12 (placeholders)
UCI_DHCP = {
    "lan": {".type": "dhcp", ".name": "lan", "interface": "lan", "start": "100", "limit": "150"},
    "guest": {".type": "dhcp", ".name": "guest", "interface": "guest", "start": "10", "limit": "20"},
    "wan": {".type": "dhcp", ".name": "wan", "interface": "wan", "ignore": "1"},
    "v6only": {".type": "dhcp", ".name": "v6only", "interface": "x", "dhcpv4": "disabled"},
    "cfg01": {".type": "host", "name": "printer", "mac": "02:00:00:00:00:aa", "ip": "192.0.2.5"},
    "cfg02": {".type": "host", "name": "nas", "mac": ["02:00:00:00:00:bb", "02:00:00:00:00:cc"]},
    "cfg03": {".type": "host", "name": "tv", "mac": "02:00:00:00:00:dd 02:00:00:00:00:ee"},
    "cfg04": {".type": "dnsmasq", "domain": "lan"},
}

IFACES = [
    {"logical_name": "lan", "ipv4_addr": "192.0.2.1", "prefix_len": 24, "status": "up"},
    {"logical_name": "guest", "ipv4_addr": "198.51.100.1", "prefix_len": 24, "status": "up"},
]


class TestParseDhcpConfig:
    def test_pools_and_static_hosts(self):
        pools, static = parse_dhcp_config(UCI_DHCP)
        assert pools == [Pool("lan", "lan", 100, 150), Pool("guest", "guest", 10, 20)]
        assert static == {
            "02:00:00:00:00:AA",
            "02:00:00:00:00:BB",
            "02:00:00:00:00:CC",
            "02:00:00:00:00:DD",
            "02:00:00:00:00:EE",
        }

    def test_defaults_when_start_limit_missing(self):
        pools, _ = parse_dhcp_config({"lan": {".type": "dhcp", "interface": "lan"}})
        assert pools == [Pool("lan", "lan", 100, 150)]

    @pytest.mark.parametrize(
        "values",
        [
            None,
            [],
            "x",
            {"a": "x"},
            {"a": {".type": "dhcp"}},  # no interface
            {"a": {".type": "dhcp", "interface": "lan", "limit": "0"}},
            {"a": {".type": "dhcp", "interface": "lan", "start": "-5"}},
            {"a": {".type": "host", "mac": 5}},
        ],
    )
    def test_broken_input(self, values):
        pools, static = parse_dhcp_config(values)
        assert pools == []
        assert static == frozenset()

    def test_garbage_numbers_fall_back_to_defaults(self):
        pools, _ = parse_dhcp_config(
            {"lan": {".type": "dhcp", "interface": "lan", "start": "x", "limit": ""}}
        )
        assert pools == [Pool("lan", "lan", 100, 150)]


class TestPoolUsage:
    def test_usage_per_pool(self):
        pools, _ = parse_dhcp_config(UCI_DHCP)
        leases = {
            "A": {"ip": "192.0.2.100"},
            "B": {"ip": "192.0.2.249"},
            "C": {"ip": "192.0.2.250"},  # outside the pool (static range)
            "D": {"ip": "192.0.2.5"},  # static below start
            "E": {"ip": "198.51.100.15"},
            "F": {"ip": "not-an-ip"},
            "G": {},
            "H": "x",
        }
        usage = pool_usage(pools, IFACES, leases)
        assert usage == [
            {"name": "lan", "interface": "lan", "size": 150, "leases": 2, "usage_pct": 1.3},
            {"name": "guest", "interface": "guest", "size": 20, "leases": 1, "usage_pct": 5.0},
        ]

    def test_pool_clamped_to_subnet(self):
        usage = pool_usage(
            [Pool("small", "small", 100, 150)],
            [{"logical_name": "small", "ipv4_addr": "192.0.2.1", "prefix_len": 26}],
            {},
        )
        assert usage == []  # start 100 lies beyond a /26 (.1-.62 usable)
        usage = pool_usage(
            [Pool("small", "small", 10, 500)],
            [{"logical_name": "small", "ipv4_addr": "192.0.2.1", "prefix_len": 25}],
            {},
        )
        assert usage[0]["size"] == 117  # .10 … .126

    def test_interface_without_ipv4_is_skipped(self):
        usage = pool_usage(
            [Pool("lan", "lan", 100, 150)],
            [{"logical_name": "lan", "ipv4_addr": None}, {"logical_name": "x", "ipv4_addr": "1.2.3.4", "prefix_len": "y"}, "junk"],
            {},
        )
        assert usage == []


class TestClientDhcpStatus:
    def _status(self, connected_s=600, leases=(), arp=(), static=()):
        since = (NOW - timedelta(seconds=connected_s)).isoformat()
        return client_dhcp_status(MAC.lower(), since, NOW, set(leases), set(arp), set(static))

    def test_lease_anywhere_is_ok(self):
        assert self._status(leases={MAC}) == DHCP_OK
        assert self._status(connected_s=5, leases={MAC}) == DHCP_OK

    def test_missing_only_after_180s(self):
        assert DHCP_MISSING_AFTER_SECONDS == 180
        assert self._status(connected_s=179) == DHCP_PENDING
        assert self._status(connected_s=180) == DHCP_MISSING

    def test_arp_entry_is_ok(self):
        assert self._status(arp={MAC}) == DHCP_OK

    def test_static_host_without_lease(self):
        assert self._status(static={MAC}) == DHCP_STATIC_NO_LEASE
        assert self._status(static={MAC}, arp={MAC}) == DHCP_STATIC_NO_LEASE
        assert self._status(connected_s=10, static={MAC}) == DHCP_PENDING

    @pytest.mark.parametrize("since", [None, "garbage", "2026-10-27T11:00:00"])
    def test_unknown_association_time_is_pending(self, since):
        assert client_dhcp_status(MAC, since, NOW, set(), set(), set()) == DHCP_PENDING


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
    api.get_dhcp_leases = AsyncMock(return_value={MAC: {"ip": "192.0.2.120"}})
    api.get_connected_clients = AsyncMock(return_value=[])
    api.get_router_status = AsyncMock(return_value={"memory": {}})
    api.get_services = AsyncMock(return_value=[])
    api.get_network_interfaces = AsyncMock(return_value=IFACES)
    api.get_ap_interface_details = AsyncMock(return_value=[])
    api.get_log_entries = AsyncMock(return_value=[])
    api.get_dhcp_config = AsyncMock(return_value=UCI_DHCP)
    return coord, api


async def _polls(coord, n):
    for _ in range(n):
        coord.data = await coord._async_update_data()
    return coord.data


class TestCoordinatorDhcp:
    @pytest.mark.asyncio
    async def test_fetch_schedule_on_gateway(self):
        coord, api = _coordinator()
        data = await _polls(coord, 1)
        api.get_dhcp_config.assert_not_awaited()  # setup poll
        assert data.dhcp_pools == []
        data = await _polls(coord, 1)
        assert api.get_dhcp_config.await_count == 1
        assert [p["name"] for p in data.dhcp_pools] == ["lan", "guest"]
        assert data.dhcp_pools[0]["leases"] == 1
        assert "02:00:00:00:00:AA" in data.dhcp_static_macs
        assert "dhcp_static_macs" not in data.as_dict()
        assert data.as_dict()["dhcp_pools"] == data.dhcp_pools
        await _polls(coord, 8)  # polls 3–10: refresh on poll 10
        assert api.get_dhcp_config.await_count == 2

    @pytest.mark.asyncio
    async def test_dumb_ap_is_asked_once(self):
        coord, api = _coordinator()
        api.get_dhcp_config = AsyncMock(return_value={"lan": {".type": "dhcp", "interface": "lan", "ignore": "1"}})
        data = await _polls(coord, 25)
        assert api.get_dhcp_config.await_count == 1
        assert data.dhcp_pools == []

    @pytest.mark.asyncio
    async def test_acl_blocked_is_asked_once(self):
        from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

        coord, api = _coordinator()
        api.get_dhcp_config = AsyncMock(side_effect=OpenWrtMethodNotFoundError("acl"))
        data = await _polls(coord, 12)
        assert api.get_dhcp_config.await_count == 1
        assert data.dhcp_pools == []

    @pytest.mark.asyncio
    async def test_transient_error_retries_and_keeps_old_pools(self):
        from custom_components.openwrt_router.api import OpenWrtTimeoutError

        coord, api = _coordinator()
        api.get_dhcp_config = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))
        await _polls(coord, 3)
        assert api.get_dhcp_config.await_count == 2  # polls 2 and 3
        api.get_dhcp_config = AsyncMock(return_value=UCI_DHCP)
        data = await _polls(coord, 1)
        assert len(data.dhcp_pools) == 2
        api.get_dhcp_config = AsyncMock(side_effect=OpenWrtTimeoutError("slow"))
        data = await _polls(coord, 6)  # poll 10 refresh fails
        assert api.get_dhcp_config.await_count == 1
        assert len(data.dhcp_pools) == 2


# =====================================================================
# Fleet + device tracker + sensor
# =====================================================================


def _entry_with(leases=None, arp=None, static=frozenset(), data=True):
    entry = MagicMock()
    if not data:
        entry.runtime_data.coordinator.data = None
        return entry
    entry.runtime_data.coordinator.last_update_success = True
    d = entry.runtime_data.coordinator.data
    d.dhcp_pools = []
    d.dhcp_leases = leases or {}
    d.arp_table = arp or {}
    d.dhcp_static_macs = static
    return entry


class TestDhcpContext:
    def test_union_over_routers(self):
        from custom_components.openwrt_router.fleet import dhcp_context

        hass = MagicMock()
        hass.config_entries.async_loaded_entries.return_value = [
            _entry_with(leases={"02:00:00:00:00:0a": {}}, static=frozenset({"02:00:00:00:00:0C"})),
            _entry_with(arp={"02:00:00:00:00:0b": "192.0.2.7"}),
            _entry_with(data=False),
        ]
        leases, arp, static = dhcp_context(hass)
        assert leases == {"02:00:00:00:00:0A"}
        assert arp == {"02:00:00:00:00:0B"}
        assert static == {"02:00:00:00:00:0C"}

    def test_none_without_any_lease(self):
        from custom_components.openwrt_router.fleet import dhcp_context

        hass = MagicMock()
        hass.config_entries.async_loaded_entries.return_value = [
            _entry_with(arp={"02:00:00:00:00:0b": "192.0.2.7"})
        ]
        assert dhcp_context(hass) is None


class TestTrackerAttribute:
    def _tracker(self, mock_coordinator, mock_config_entry, client):
        from custom_components.openwrt_router.device_tracker import (
            OpenWrtClientTrackerEntity,
        )

        tracker = OpenWrtClientTrackerEntity(mock_coordinator, mock_config_entry, MAC)
        tracker.hass = MagicMock()
        mock_coordinator.get_client_by_mac = MagicMock(return_value=client)
        return tracker

    def test_dhcp_missing_attribute(self, mock_coordinator, mock_config_entry):
        since = (datetime.now(UTC) - timedelta(minutes=10)).isoformat()
        tracker = self._tracker(
            mock_coordinator, mock_config_entry, {"mac": MAC, "connected_since": since}
        )
        with patch(
            "custom_components.openwrt_router.device_tracker.dhcp_context",
            return_value=(frozenset({"02:00:00:00:00:99"}), frozenset(), frozenset()),
        ):
            attrs = tracker.extra_state_attributes
        assert attrs["dhcp_status"] == DHCP_MISSING

    def test_unknown_without_dhcp_server(self, mock_coordinator, mock_config_entry):
        tracker = self._tracker(mock_coordinator, mock_config_entry, {"mac": MAC})
        with patch(
            "custom_components.openwrt_router.device_tracker.dhcp_context",
            return_value=None,
        ):
            assert tracker.extra_state_attributes["dhcp_status"] is None

    def test_no_attribute_when_away(self, mock_coordinator, mock_config_entry):
        tracker = self._tracker(mock_coordinator, mock_config_entry, None)
        tracker._find_client = MagicMock(return_value=(None, None))
        assert "dhcp_status" not in tracker.extra_state_attributes


class TestPoolSensor:
    def test_value_attributes_and_unique_id(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.sensor import OpenWrtDhcpPoolSensor

        mock_coordinator.data.dhcp_pools = [
            {"name": "my_rate_ap_pool", "interface": "lan", "size": 150, "leases": 30, "usage_pct": 20.0}
        ]
        mock_coordinator.last_update_success = True
        sensor = OpenWrtDhcpPoolSensor(mock_coordinator, mock_config_entry, "my_rate_ap_pool")
        assert sensor.native_value == 20.0
        assert sensor.available is True
        assert sensor.extra_state_attributes == {"interface": "lan", "leases": 30, "size": 150}
        assert sensor.unique_id == "test_entry_id_dhcp_pool-my-rate-ap-pool"
        for legacy in ("_rate", "_ap_", "_port_", "_radio_", "_iface_"):
            assert legacy not in sensor.unique_id
        assert sensor.translation_placeholders == {"pool": "my_rate_ap_pool"}

    def test_unavailable_when_pool_gone(self, mock_coordinator, mock_config_entry):
        from custom_components.openwrt_router.sensor import OpenWrtDhcpPoolSensor

        mock_coordinator.data.dhcp_pools = []
        mock_coordinator.last_update_success = True
        sensor = OpenWrtDhcpPoolSensor(mock_coordinator, mock_config_entry, "lan")
        assert sensor.available is False
        assert sensor.native_value is None


# =====================================================================
# Review follow-ups (P5)
# =====================================================================


class TestReviewFollowUps:
    def test_anonymous_pool_named_after_interface(self):
        pools, _ = parse_dhcp_config(
            {"cfg01411c": {".type": "dhcp", ".anonymous": True, ".name": "cfg01411c", "interface": "lan"}}
        )
        assert pools == [Pool("lan", "lan", 100, 150)]

    def test_unknown_while_dhcp_server_is_stale(self):
        from custom_components.openwrt_router.fleet import dhcp_context

        server = _entry_with(leases={"02:00:00:00:00:0a": {}})
        server.runtime_data.coordinator.data.dhcp_pools = [{"name": "lan"}]
        hass = MagicMock()
        hass.config_entries.async_loaded_entries.return_value = [server]
        assert dhcp_context(hass) is not None
        server.runtime_data.coordinator.last_update_success = False
        assert dhcp_context(hass) is None
        server.runtime_data.coordinator.last_update_success = True
        server.runtime_data.coordinator.data.dhcp_leases = {}
        assert dhcp_context(hass) is None

    def test_static_host_with_arp_is_pending_first(self):
        since = (NOW - timedelta(seconds=30)).isoformat()
        assert client_dhcp_status(MAC, since, NOW, set(), {MAC}, {MAC}) == DHCP_PENDING

    @pytest.mark.asyncio
    async def test_dnsmasq_stopped_hides_pools(self):
        coord, api = _coordinator()
        api.get_services = AsyncMock(return_value=[{"name": "dnsmasq", "running": False}])
        data = await _polls(coord, 3)
        assert api.get_dhcp_config.await_count >= 1
        assert data.dhcp_pools == []

    @pytest.mark.asyncio
    async def test_rare_retry_without_pool(self):
        coord, api = _coordinator()
        api.get_dhcp_config = AsyncMock(return_value={})
        await _polls(coord, 60)
        assert api.get_dhcp_config.await_count == 2  # poll 2 and poll 60
