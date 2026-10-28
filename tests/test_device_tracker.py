"""Tests for the OpenWrt Device Tracker platform (device_tracker.py)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from custom_components.openwrt_router.const import (
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    DOMAIN,
)
from custom_components.openwrt_router.device_tracker import (
    OpenWrtClientTrackerEntity,
    async_setup_entry,
)
from homeassistant.components.device_tracker import SourceType


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tracker(
    mock_coordinator,
    mock_config_entry,
    mac: str = "B8:27:EB:AA:BB:01",
) -> OpenWrtClientTrackerEntity:
    """Create a tracker entity with mock dependencies."""
    return OpenWrtClientTrackerEntity(
        coordinator=mock_coordinator,
        entry=mock_config_entry,
        mac=mac,
    )


def _make_hass() -> MagicMock:
    """Mock hass with a real data dict (needed for the MAC claim registry)."""
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_loaded_entries.return_value = []
    return hass


# Entity registry entries seen by async_setup_entry (registry restore).
_REGISTRY: list = []


@pytest.fixture(autouse=True)
def _fake_entity_registry(monkeypatch):
    """Serve registry entries from _REGISTRY instead of a real registry."""
    from custom_components.openwrt_router import device_tracker as dt_module

    _REGISTRY.clear()
    monkeypatch.setattr(dt_module.er, "async_get", lambda hass: MagicMock())
    monkeypatch.setattr(
        dt_module.er,
        "async_entries_for_config_entry",
        lambda registry, entry_id: [
            e for e in _REGISTRY if e.config_entry_id == entry_id
        ],
    )
    yield
    _REGISTRY.clear()


def _reg_entry(
    entry_id: str,
    unique_id: str,
    original_name: str | None = None,
    name: str | None = None,
    domain: str = "device_tracker",
    disabled_by: str | None = None,
):
    """A minimal stand-in for an entity registry entry."""
    return SimpleNamespace(
        config_entry_id=entry_id,
        domain=domain,
        platform=DOMAIN,
        unique_id=unique_id,
        original_name=original_name,
        name=name,
        disabled_by=disabled_by,
    )


# =====================================================================
# async_setup_entry
# =====================================================================

class TestAsyncSetupEntry:
    @pytest.mark.asyncio
    async def test_adds_entities_for_existing_clients(
        self, mock_coordinator, mock_config_entry
    ):
        """Should create tracker entities for clients already present."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        added: list = []
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=lambda entities: added.extend(entities),
        )
        # 2 clients in mock_coordinator_data
        assert len(added) == 2
        macs = {e.mac_address for e in added}
        assert "B8:27:EB:AA:BB:01" in macs
        assert "AC:DE:48:11:22:01" in macs

    @pytest.mark.asyncio
    async def test_no_entities_when_no_data(self, mock_coordinator, mock_config_entry):
        """Should not crash when coordinator.data is None."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_coordinator.data = None
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        added: list = []
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=lambda entities: added.extend(entities),
        )
        assert len(added) == 0

    @pytest.mark.asyncio
    async def test_registers_listener(self, mock_coordinator, mock_config_entry):
        """Should register a coordinator listener for new clients."""
        from custom_components.openwrt_router import OpenWrtRuntimeData
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        mock_config_entry.async_on_unload = MagicMock()

        await async_setup_entry(
            hass=_make_hass(),
            entry=mock_config_entry,
            async_add_entities=MagicMock(),
        )
        mock_coordinator.async_add_listener.assert_called_once()
        # one unload hook for the listener, one for the MAC claim release
        assert mock_config_entry.async_on_unload.call_count == 2


# =====================================================================
# Entity Creation
# =====================================================================

class TestTrackerCreation:
    def test_unique_id(self, mock_coordinator, mock_config_entry):
        """Newer HA cores force unique_id = mac_address; older ones use ours."""
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker._attr_unique_id == "test_entry_id_tracker_b827ebaabb01"
        assert tracker.unique_id in {
            "B8:27:EB:AA:BB:01",  # ScannerEntity.unique_id override (new cores)
            "test_entry_id_tracker_b827ebaabb01",  # _attr_unique_id (old cores)
        }

    def test_mac_address(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.mac_address == "B8:27:EB:AA:BB:01"

    def test_source_type(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.source_type == SourceType.ROUTER


# =====================================================================
# Name
# =====================================================================

class TestTrackerName:
    def test_name_uses_hostname(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.name == "raspberrypi"

    def test_name_falls_back_to_mac(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.name == "00:00:00:00:00:00"

    def test_name_when_hostname_empty(self, mock_coordinator, mock_config_entry):
        """If client found but hostname is empty, use MAC."""
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={"hostname": "", CLIENT_KEY_MAC: "B8:27:EB:AA:BB:01"}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.name == "B8:27:EB:AA:BB:01"


# =====================================================================
# Connection State
# =====================================================================

class TestTrackerState:
    def test_is_connected_true(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.is_connected is True

    def test_is_connected_false(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.is_connected is False


# =====================================================================
# IP Address
# =====================================================================

class TestTrackerIP:
    def test_ip_address_known(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.ip_address == "192.168.1.101"

    def test_ip_address_unknown_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.ip_address is None

    def test_ip_address_empty_string(self, mock_coordinator, mock_config_entry):
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={CLIENT_KEY_IP: ""}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.ip_address is None


# =====================================================================
# Hostname
# =====================================================================

class TestTrackerHostname:
    def test_hostname_present(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.hostname == "raspberrypi"

    def test_hostname_none_when_client_missing(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        assert tracker.hostname is None

    def test_hostname_none_when_empty(self, mock_coordinator, mock_config_entry):
        mock_coordinator.get_client_by_mac = MagicMock(
            return_value={"hostname": ""}
        )
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        assert tracker.hostname is None


# =====================================================================
# Extra State Attributes
# =====================================================================

class TestTrackerAttributes:
    def test_attrs_connected_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is True
        assert attrs["mac"] == "B8:27:EB:AA:BB:01"
        assert attrs["ssid"] == "OpenWrt-Home"
        assert attrs["signal"] == -55
        assert attrs["ip_address"] == "192.168.1.101"
        assert "radio" in attrs

    def test_attrs_disconnected_client(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is False
        assert attrs["mac"] == "00:00:00:00:00:00"
        assert "ssid" not in attrs


# =====================================================================
# Device Info
# =====================================================================

class TestTrackerDeviceInfo:
    def test_device_info(self, mock_coordinator, mock_config_entry):
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        info = tracker.device_info
        assert (DOMAIN, "test_entry_id") in info["identifiers"]
        assert info["manufacturer"] == "OpenWrt"
        assert info["model"] == "GL.iNet GL-MT3000"
        assert info["sw_version"] == "24.10.0"

    def test_device_info_fallback_name(self, mock_coordinator, mock_config_entry):
        """When hostname missing from router_info, use entry title."""
        mock_coordinator.router_info = {"release": {}}
        tracker = _make_tracker(mock_coordinator, mock_config_entry)
        info = tracker.device_info
        assert info["name"] == "OpenWrt-Dev"  # entry.title


# =====================================================================
# T-DT1 through T-DT3: connected_since in extra_state_attributes
# =====================================================================

from custom_components.openwrt_router.const import CLIENT_KEY_CONNECTED_SINCE


class TestTrackerConnectedSince:
    """Tests that connected_since is surfaced in extra_state_attributes."""

    def _tracker_with_connected_since(self, mock_coordinator, mock_config_entry):
        """Return a tracker whose client has a connected_since timestamp."""
        mock_coordinator.get_client_by_mac = MagicMock(return_value={
            CLIENT_KEY_MAC: "B8:27:EB:AA:BB:01",
            CLIENT_KEY_IP: "192.168.1.101",
            CLIENT_KEY_SIGNAL: -55,
            CLIENT_KEY_SSID: "OpenWrt-Home",
            CLIENT_KEY_RADIO: "phy0-ap0",
            "hostname": "raspberrypi",
            CLIENT_KEY_CONNECTED_SINCE: "2026-04-06T10:00:00+00:00",
        })
        mock_coordinator.is_client_connected = MagicMock(return_value=True)
        return _make_tracker(mock_coordinator, mock_config_entry)

    def test_t_dt1_connected_since_present_when_online(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT1: connected_since appears in extra_state_attributes for connected client."""
        tracker = self._tracker_with_connected_since(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        assert "connected_since" in attrs
        assert attrs["connected_since"] == "2026-04-06T10:00:00+00:00"

    def test_t_dt2_no_connected_since_when_offline(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT2: Offline client has connected: False and no connected_since."""
        mock_coordinator.get_client_by_mac = MagicMock(return_value=None)
        mock_coordinator.is_client_connected = MagicMock(return_value=False)
        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac="00:00:00:00:00:00"
        )
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is False
        assert "connected_since" not in attrs

    def test_t_dt3_connected_since_is_iso_format(
        self, mock_coordinator, mock_config_entry
    ):
        """T-DT3: connected_since value is a valid ISO-8601 datetime string."""
        from datetime import datetime
        tracker = self._tracker_with_connected_since(mock_coordinator, mock_config_entry)
        attrs = tracker.extra_state_attributes
        ts = attrs.get("connected_since", "")
        # Must parse without error
        try:
            datetime.fromisoformat(ts)
        except ValueError:
            pytest.fail(f"connected_since '{ts}' is not a valid ISO datetime")


# =====================================================================
# Cross-entry dedup + mesh-wide roaming (v1.26.4)
# =====================================================================

class TestCrossEntryDedup:
    """Same client MAC visible on several routers → only ONE entity."""

    def _entry(self, entry_id: str, mock_coordinator):
        from custom_components.openwrt_router import OpenWrtRuntimeData
        entry = MagicMock()
        entry.entry_id = entry_id
        entry.title = entry_id
        entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )
        entry.async_on_unload = MagicMock()
        return entry

    @pytest.mark.asyncio
    async def test_second_entry_skips_claimed_macs(self, mock_coordinator):
        """Entry B must not create entities for MACs already claimed by A."""
        hass = _make_hass()
        entry_a = self._entry("entry_a", mock_coordinator)
        entry_b = self._entry("entry_b", mock_coordinator)

        added_a: list = []
        added_b: list = []
        await async_setup_entry(hass, entry_a, lambda e: added_a.extend(e))
        await async_setup_entry(hass, entry_b, lambda e: added_b.extend(e))

        assert len(added_a) == 2
        assert len(added_b) == 0

    @pytest.mark.asyncio
    async def test_claims_released_on_unload(self, mock_coordinator):
        """After entry A unloads, entry B can claim the same MACs."""
        hass = _make_hass()
        entry_a = self._entry("entry_a", mock_coordinator)
        entry_b = self._entry("entry_b", mock_coordinator)

        added_a: list = []
        await async_setup_entry(hass, entry_a, lambda e: added_a.extend(e))
        assert len(added_a) == 2

        # Simulate unload of A: run all registered unload callbacks
        for call_args in entry_a.async_on_unload.call_args_list:
            call_args.args[0]()

        added_b: list = []
        await async_setup_entry(hass, entry_b, lambda e: added_b.extend(e))
        assert len(added_b) == 2


class TestMeshRoaming:
    """Tracker reports 'home' when ANY loaded router sees the client."""

    def _roaming_setup(self, mock_coordinator, mock_config_entry, client: dict):
        """Tracker owned by A; the client is only visible on router B."""
        from custom_components.openwrt_router import OpenWrtRuntimeData

        # Real runtime_data for the owning entry so the mesh lookup skips it
        # via coordinator identity (a bare MagicMock would auto-create a
        # truthy fake coordinator instead).
        mock_config_entry.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=mock_coordinator
        )

        coordinator_b = MagicMock()
        coordinator_b.get_client_by_mac = MagicMock(
            side_effect=lambda mac: client
            if mac.upper() == client[CLIENT_KEY_MAC].upper()
            else None
        )
        coordinator_b.router_info = {"hostname": "OpenWrt-AP4"}

        entry_b = MagicMock()
        entry_b.entry_id = "entry_b"
        entry_b.runtime_data = OpenWrtRuntimeData(
            api=AsyncMock(), coordinator=coordinator_b
        )

        hass = _make_hass()
        hass.config_entries.async_loaded_entries.return_value = [
            mock_config_entry, entry_b
        ]

        tracker = _make_tracker(
            mock_coordinator, mock_config_entry, mac=client[CLIENT_KEY_MAC]
        )
        tracker.hass = hass
        return tracker

    def test_roaming_client_is_home(self, mock_coordinator, mock_config_entry):
        client = {
            CLIENT_KEY_MAC: "0A:0B:0C:0D:0E:0F",
            CLIENT_KEY_IP: "192.168.1.199",
            CLIENT_KEY_SSID: "OpenWrt-Home",
            CLIENT_KEY_RADIO: "phy1-ap0",
            CLIENT_KEY_SIGNAL: -61,
            "hostname": "wanderer",
        }
        tracker = self._roaming_setup(mock_coordinator, mock_config_entry, client)

        assert tracker.is_connected is True
        assert tracker.ip_address == "192.168.1.199"
        assert tracker.hostname == "wanderer"
        attrs = tracker.extra_state_attributes
        assert attrs["connected"] is True
        assert attrs["connected_ap"] == "OpenWrt-AP4"

    def test_client_gone_everywhere_is_not_home(
        self, mock_coordinator, mock_config_entry
    ):
        client = {CLIENT_KEY_MAC: "0A:0B:0C:0D:0E:0F"}
        tracker = self._roaming_setup(mock_coordinator, mock_config_entry, client)
        tracker._mac = "FF:FF:FF:FF:FF:FF"  # a MAC no coordinator knows

        assert tracker.is_connected is False
        assert tracker.extra_state_attributes["connected"] is False


# =====================================================================
# A3: availability across routers, registry restore, last known name
# =====================================================================

_MAC_X = "02:00:00:00:0A:01"
_MAC_Y = "02:00:00:00:0A:02"


def _coordinator(
    clients: list, ok: bool = True, ap: str = "OpenWrt-AP", stale: bool = False
):
    """Coordinator stub whose client list can be mutated by the test."""
    coordinator = MagicMock()
    coordinator.data = SimpleNamespace(clients=clients)
    coordinator.last_update_success = ok
    coordinator.stale_for_presence = stale
    coordinator.router_info = {"hostname": ap, "release": {}}
    coordinator.get_client_by_mac = MagicMock(
        side_effect=lambda mac: next(
            (c for c in clients if c[CLIENT_KEY_MAC].upper() == mac.upper()),
            None,
        )
    )
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)
    return coordinator


def _entry(entry_id: str, coordinator):
    from custom_components.openwrt_router import OpenWrtRuntimeData

    entry = MagicMock()
    entry.entry_id = entry_id
    entry.title = entry_id
    entry.data = {"host": "192.0.2.1", "port": 80}
    entry.runtime_data = OpenWrtRuntimeData(api=AsyncMock(), coordinator=coordinator)
    entry.async_on_unload = MagicMock()
    return entry


def _owned_tracker(owner_entry, other_entries: list, mac: str):
    """Tracker owned by owner_entry; hass sees owner + other entries loaded."""
    hass = _make_hass()
    hass.config_entries.async_loaded_entries.return_value = [
        owner_entry, *other_entries
    ]
    tracker = OpenWrtClientTrackerEntity(
        coordinator=owner_entry.runtime_data.coordinator,
        entry=owner_entry,
        mac=mac,
    )
    tracker.hass = hass
    return tracker


async def _setup(hass, entry) -> list:
    added: list = []
    await async_setup_entry(hass, entry, lambda entities: added.extend(entities))
    return added


class TestAvailabilityAcrossRouters:
    """N4: availability follows ANY answering router, not just the owner."""

    def test_owner_failed_client_on_other_router_is_available_home(self):
        entry_a = _entry("entry_a", _coordinator([], ok=False))
        entry_b = _entry(
            "entry_b",
            _coordinator([{CLIENT_KEY_MAC: _MAC_X, "hostname": "laptop-test"}]),
        )
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is True
        assert tracker.state == "home"

    def test_owner_failed_client_nowhere_is_available_not_home(self):
        entry_a = _entry("entry_a", _coordinator([], ok=False))
        entry_b = _entry("entry_b", _coordinator([]))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is True
        assert tracker.state == "not_home"

    def test_all_routers_failed_is_unavailable(self):
        entry_a = _entry("entry_a", _coordinator([], ok=False))
        entry_b = _entry("entry_b", _coordinator([], ok=False))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is False

    def test_owner_ok_is_available(self):
        entry_a = _entry("entry_a", _coordinator([]))
        tracker = _owned_tracker(entry_a, [], _MAC_X)

        assert tracker.available is True

    def test_other_router_poll_writes_state_only_while_owner_failed(self):
        coordinator_a = _coordinator([], ok=False)
        entry_a = _entry("entry_a", coordinator_a)
        entry_b = _entry("entry_b", _coordinator([]))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)
        tracker.async_write_ha_state = MagicMock()

        # The owner's own poll is already handled by CoordinatorEntity.
        tracker._async_router_polled("entry_a")
        tracker.async_write_ha_state.assert_not_called()

        tracker._async_router_polled("entry_b")
        tracker.async_write_ha_state.assert_called_once()

        coordinator_a.last_update_success = True
        tracker._async_router_polled("entry_b")
        tracker.async_write_ha_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_coordinator_listener_signals_poll(self):
        from custom_components.openwrt_router import device_tracker as dt_module

        coordinator = _coordinator([])
        entry = _entry("entry_a", coordinator)
        hass = _make_hass()
        await _setup(hass, entry)

        listener = coordinator.async_add_listener.call_args.args[0]
        with patch.object(dt_module, "async_dispatcher_send") as send:
            listener()
        send.assert_called_once_with(hass, dt_module._SIGNAL_ROUTER_POLLED, "entry_a")


class TestRegistryRestore:
    """N5: absent clients known to the registry get an entity at setup."""

    @pytest.mark.asyncio
    async def test_absent_registry_client_restored_as_not_home(self):
        entry_a = _entry("entry_a", _coordinator([]))
        _REGISTRY.append(_reg_entry("entry_a", _MAC_X, original_name="phone-test"))
        hass = _make_hass()
        hass.config_entries.async_loaded_entries.return_value = [entry_a]

        added = await _setup(hass, entry_a)

        assert [e.mac_address for e in added] == [_MAC_X]
        tracker = added[0]
        tracker.hass = hass
        assert tracker.state == "not_home"
        assert tracker.available is True
        assert tracker.name == "phone-test"

    @pytest.mark.asyncio
    async def test_legacy_unique_id_restored(self):
        entry_a = _entry("entry_a", _coordinator([]))
        _REGISTRY.append(_reg_entry("entry_a", "entry_a_tracker_020000000a02"))

        added = await _setup(_make_hass(), entry_a)

        assert [e.mac_address for e in added] == [_MAC_Y]

    @pytest.mark.asyncio
    async def test_unrelated_registry_entries_ignored(self):
        entry_a = _entry("entry_a", _coordinator([]))
        _REGISTRY.extend(
            [
                _reg_entry("entry_a", "entry_a_uptime", domain="sensor"),
                _reg_entry("entry_a", "not-a-mac"),
                _reg_entry("entry_other", _MAC_X),
            ]
        )

        assert await _setup(_make_hass(), entry_a) == []

    @pytest.mark.asyncio
    async def test_live_and_registry_same_mac_gives_one_entity(self):
        entry_a = _entry(
            "entry_a",
            _coordinator([{CLIENT_KEY_MAC: _MAC_X, "hostname": "laptop-test"}]),
        )
        _REGISTRY.append(_reg_entry("entry_a", _MAC_X))

        added = await _setup(_make_hass(), entry_a)

        assert [e.mac_address for e in added] == [_MAC_X]

    @pytest.mark.parametrize("order", [("a", "b"), ("b", "a")])
    @pytest.mark.asyncio
    async def test_same_mac_in_two_entries_gives_one_entity(self, order):
        """A knows X from the registry, B from the registry (legacy) AND live."""
        entries = {
            "a": _entry("entry_a", _coordinator([])),
            "b": _entry(
                "entry_b", _coordinator([{CLIENT_KEY_MAC: _MAC_X, "hostname": ""}])
            ),
        }
        _REGISTRY.extend(
            [
                _reg_entry("entry_a", _MAC_X),
                _reg_entry("entry_b", "entry_b_tracker_020000000a01"),
            ]
        )
        hass = _make_hass()

        added: list = []
        for key in order:
            added.extend(await _setup(hass, entries[key]))

        assert [e.mac_address for e in added] == [_MAC_X]
        # The first entry to set up keeps the claim; nothing is stolen.
        assert added[0]._entry is entries[order[0]]

    @pytest.mark.asyncio
    async def test_restored_claims_released_on_unload(self):
        entry_a = _entry("entry_a", _coordinator([]))
        entry_b = _entry("entry_b", _coordinator([]))
        _REGISTRY.extend(
            [_reg_entry("entry_a", _MAC_X), _reg_entry("entry_b", _MAC_X)]
        )
        hass = _make_hass()

        assert len(await _setup(hass, entry_a)) == 1
        for call_args in entry_a.async_on_unload.call_args_list:
            call_args.args[0]()

        assert [e.mac_address for e in await _setup(hass, entry_b)] == [_MAC_X]


class TestLastKnownName:
    """NEU-A5: an absent client keeps its last hostname as name."""

    def test_absent_client_keeps_last_hostname(self):
        clients = [{CLIENT_KEY_MAC: _MAC_X, "hostname": "laptop-test"}]
        entry_a = _entry("entry_a", _coordinator(clients))
        tracker = _owned_tracker(entry_a, [], _MAC_X)
        assert tracker.name == "laptop-test"

        clients.clear()

        assert tracker.is_connected is False
        assert tracker.name == "laptop-test"

    def test_seeded_last_name_used_while_absent(self):
        entry_a = _entry("entry_a", _coordinator([]))
        tracker = OpenWrtClientTrackerEntity(
            coordinator=entry_a.runtime_data.coordinator,
            entry=entry_a,
            mac=_MAC_X,
            last_name="phone-test",
        )
        assert tracker.name == "phone-test"

    @pytest.mark.asyncio
    async def test_mac_like_registry_name_is_not_seeded(self):
        entry_a = _entry("entry_a", _coordinator([]))
        _REGISTRY.append(
            _reg_entry("entry_a", _MAC_X, original_name="02-00-00-00-0a-01", name="")
        )

        added = await _setup(_make_hass(), entry_a)

        assert added[0].name == _MAC_X

    @pytest.mark.asyncio
    async def test_registry_name_falls_back_to_user_name(self):
        entry_a = _entry("entry_a", _coordinator([]))
        _REGISTRY.append(_reg_entry("entry_a", _MAC_X, name="phone-test"))

        added = await _setup(_make_hass(), entry_a)

        assert added[0].name == "phone-test"


class TestStaleRouterPresence:
    """A3 review P1: a router failing beyond the grace period is ignored."""

    _CLIENT = {CLIENT_KEY_MAC: _MAC_X, "hostname": "laptop-test"}

    def test_owner_brief_failure_keeps_client_home(self):
        entry_a = _entry("entry_a", _coordinator([dict(self._CLIENT)], ok=False))
        entry_b = _entry("entry_b", _coordinator([]))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is True
        assert tracker.state == "home"

    def test_owner_stale_client_only_there_is_not_home(self):
        entry_a = _entry(
            "entry_a", _coordinator([dict(self._CLIENT)], ok=False, stale=True)
        )
        entry_b = _entry("entry_b", _coordinator([]))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is True
        assert tracker.state == "not_home"
        assert tracker.extra_state_attributes["connected"] is False

    def test_owner_stale_client_on_other_router_is_home(self):
        entry_a = _entry(
            "entry_a", _coordinator([dict(self._CLIENT)], ok=False, stale=True)
        )
        entry_b = _entry("entry_b", _coordinator([dict(self._CLIENT)], ap="AP-B"))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.state == "home"
        assert tracker.extra_state_attributes["connected_ap"] == "AP-B"

    def test_other_router_stale_is_ignored(self):
        entry_a = _entry("entry_a", _coordinator([]))
        entry_b = _entry(
            "entry_b", _coordinator([dict(self._CLIENT)], ok=False, stale=True)
        )
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is True
        assert tracker.state == "not_home"

    def test_all_routers_stale_is_unavailable(self):
        entry_a = _entry("entry_a", _coordinator([], ok=False, stale=True))
        entry_b = _entry("entry_b", _coordinator([], ok=False, stale=True))
        tracker = _owned_tracker(entry_a, [entry_b], _MAC_X)

        assert tracker.available is False


class TestDisabledRegistryEntries:
    """A3 review P2: disabled registry trackers must not take a claim."""

    @pytest.mark.asyncio
    async def test_disabled_entry_not_restored_and_claims_nothing(self):
        entry_a = _entry("entry_a", _coordinator([]))
        entry_b = _entry(
            "entry_b", _coordinator([{CLIENT_KEY_MAC: _MAC_X, "hostname": ""}])
        )
        _REGISTRY.append(_reg_entry("entry_a", _MAC_X, disabled_by="user"))
        hass = _make_hass()

        assert await _setup(hass, entry_a) == []
        assert [e.mac_address for e in await _setup(hass, entry_b)] == [_MAC_X]
