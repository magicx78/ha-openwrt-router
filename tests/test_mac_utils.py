"""Tests for randomised (locally administered) MAC detection (F8 stage 1)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from custom_components.openwrt_router.mac_utils import is_locally_administered


class TestIsLocallyAdministered:
    @pytest.mark.parametrize(
        "mac",
        [
            "02:00:00:00:00:01",
            "da:a1:19:00:00:01",
            "DA:A1:19:00:00:01",
            "2a-00-00-00-00-01",
            "fe0000000001",
            "0200.0000.0001",
        ],
    )
    def test_locally_administered(self, mac):
        assert is_locally_administered(mac) is True

    @pytest.mark.parametrize(
        "mac",
        [
            "00:1a:2b:00:00:01",  # globally unique (IEEE OUI)
            "ac:de:48:00:00:01",
            "34:29:8f:00:00:01",
            "03:00:00:00:00:01",  # multicast + local
            "01:00:5e:00:00:01",  # IPv4 multicast
            "ff:ff:ff:ff:ff:ff",  # broadcast
        ],
    )
    def test_not_locally_administered(self, mac):
        assert is_locally_administered(mac) is False

    @pytest.mark.parametrize(
        "mac",
        [None, "", "zz", "02:00:00:00:00", "02:00:00:00:00:01:02", 42, "02:00:00:00:00:0g"],
    )
    def test_malformed(self, mac):
        assert is_locally_administered(mac) is False


class TestClientEnrichment:
    def _api(self):
        from custom_components.openwrt_router.api import OpenWrtAPI

        return OpenWrtAPI(
            host="router.test",
            port=80,
            username="root",
            password="test",
            session=MagicMock(),
            protocol="http",
        )

    def test_random_mac_gets_flag_and_no_vendor(self):
        api = self._api()
        clients = [
            {"mac": "DA:A1:19:00:00:01"},
            {"mac": "34:29:8F:00:00:01"},  # Cudy OUI in the table
            {"mac": "02:00:00:00:00:02", "vendor": "Preset"},
        ]
        with patch(
            "custom_components.openwrt_router.api.oui.lookup_vendor",
            side_effect=lambda mac: "Cudy" if mac.startswith("34") else "Wrong",
        ):
            api._enrich_client_metadata(clients)
        assert [(c["random_mac"], c["vendor"]) for c in clients] == [
            (True, None),
            (False, "Cudy"),
            (True, None),  # an earlier vendor guess is dropped as well
        ]


class TestTrackerAttribute:
    @pytest.mark.parametrize(
        ("mac", "expected"), [("02:00:00:00:00:01", True), ("00:1A:2B:00:00:01", False)]
    )
    def test_random_mac_attribute(self, mock_coordinator, mock_config_entry, mac, expected):
        from custom_components.openwrt_router.device_tracker import (
            OpenWrtClientTrackerEntity,
        )

        tracker = OpenWrtClientTrackerEntity(mock_coordinator, mock_config_entry, mac)
        tracker.hass = None
        tracker._find_client = MagicMock(return_value=(None, None))
        assert tracker.extra_state_attributes["random_mac"] is expected
        tracker._find_client = MagicMock(return_value=({"mac": mac}, mock_coordinator))
        assert tracker.extra_state_attributes["random_mac"] is expected
