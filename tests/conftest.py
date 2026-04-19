"""Shared fixtures for the OpenWrt Router integration tests."""
from __future__ import annotations

import os
import sys
import types
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Make custom_components importable as a namespace package.
# The project root contains custom_components/openwrt_router/ but no
# custom_components/__init__.py (HA convention).
# ---------------------------------------------------------------------------
_PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# Register custom_components as a namespace package pointing to the real dir
import importlib
_cc_path = os.path.join(_PROJECT_ROOT, "custom_components")
if "custom_components" not in sys.modules:
    _cc = types.ModuleType("custom_components")
    _cc.__path__ = [_cc_path]  # type: ignore[attr-defined]
    _cc.__package__ = "custom_components"
    sys.modules["custom_components"] = _cc
else:
    _cc = sys.modules["custom_components"]
    if _cc_path not in getattr(_cc, "__path__", []):
        _cc.__path__.insert(0, _cc_path)  # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Now safe to import the integration
# ---------------------------------------------------------------------------
from custom_components.openwrt_router.api import (  # noqa: E402
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.const import (  # noqa: E402
    CLIENT_KEY_CONNECTED_SINCE,
    CLIENT_KEY_DHCP_EXPIRES,
    CLIENT_KEY_HOSTNAME,
    CLIENT_KEY_IP,
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    CLIENT_KEY_SSID,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
    DOMAIN,
    FEATURE_AVAILABLE_RADIOS,
    FEATURE_DHCP_LEASES,
    FEATURE_HAS_5GHZ,
    FEATURE_HAS_6GHZ,
    FEATURE_HAS_GUEST_WIFI,
    FEATURE_HAS_IWINFO,
    FEATURE_UCI_AVAILABLE,
    PROTOCOL_HTTP,
    RADIO_KEY_BAND,
    RADIO_KEY_BITRATE,
    RADIO_KEY_BSSID,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_ENABLED,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_HTMODE,
    RADIO_KEY_HWMODE,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IS_GUEST,
    RADIO_KEY_MODE,
    RADIO_KEY_NAME,
    RADIO_KEY_SSID,
    RADIO_KEY_TXPOWER,
    RADIO_KEY_UCI_SECTION,
)
from custom_components.openwrt_router.coordinator import (  # noqa: E402
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
)

# ---------------------------------------------------------------------------
# Mock ubus response data  (mirrors scripts/mock_router.py)
# ---------------------------------------------------------------------------

MOCK_SESSION_TOKEN = "deadbeefdeadbeefdeadbeefdeadbeef"

MOCK_BOARD_INFO = {
    "kernel": "6.6.73",
    "hostname": "OpenWrt-Dev",
    "model": "GL.iNet GL-MT3000",
    "board_name": "glinet,gl-mt3000",
    "release": {
        "distribution": "OpenWrt",
        "version": "24.10.0",
        "revision": "r28427",
        "codename": "Snapdragon",
        "target": "mediatek/filogic",
        "description": "OpenWrt 24.10.0 r28427",
    },
    "mac": "aa:bb:cc:dd:ee:ff",
}

MOCK_SYSTEM_INFO = {
    "uptime": 86400,
    "load": [65536, 131072, 98304],  # 1.0, 2.0, 1.5 × 65536
    "memory": {
        "total": 268435456,   # 256 MB
        "free": 134217728,    # 128 MB
        "shared": 4194304,
        "buffered": 8388608,
        "available": 142606336,
    },
}

MOCK_NETWORK_DUMP = {
    "interface": [
        {
            "interface": "wan",
            "up": True,
            "uptime": 3600,
            "proto": "dhcp",
            "ipv4-address": [{"address": "203.0.113.42", "mask": 24}],
            "statistics": {"rx_bytes": 1048576, "tx_bytes": 524288},
        },
        {
            "interface": "lan",
            "up": True,
            "uptime": 86000,
            "proto": "static",
            "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
            "statistics": {"rx_bytes": 5242880, "tx_bytes": 2097152},
        },
    ]
}

MOCK_WIRELESS_STATUS = {
    "radio0": {
        "up": True,
        "pending": False,
        "interfaces": [
            {
                "ifname": "phy0-ap0",
                "config": {
                    "ssid": "OpenWrt-Home",
                    "mode": "ap",
                    "encryption": "psk2",
                    "disabled": False,
                    "section": "default_radio0",
                },
            }
        ],
    },
    "radio1": {
        "up": True,
        "pending": False,
        "interfaces": [
            {
                "ifname": "phy1-ap0",
                "config": {
                    "ssid": "OpenWrt-Home-5G",
                    "mode": "ap",
                    "encryption": "psk2",
                    "disabled": False,
                    "section": "default_radio1",
                },
            },
            {
                "ifname": "phy1-ap1",
                "config": {
                    "ssid": "Guest-WiFi",
                    "mode": "ap",
                    "encryption": "psk2",
                    "disabled": False,
                    "section": "guest_radio1",
                },
            },
        ],
    },
}

MOCK_IWINFO_INFO = {
    "phy0-ap0": {
        "ssid": "OpenWrt-Home",
        "bssid": "AA:BB:CC:DD:EE:01",
        "frequency": 2412,
        "phy": "radio0",
    },
    "phy1-ap0": {
        "ssid": "OpenWrt-Home-5G",
        "bssid": "AA:BB:CC:DD:EE:02",
        "frequency": 5200,
        "phy": "radio1",
    },
}

MOCK_UCI_WIRELESS = {
    "values": {
        "default_radio0": {
            ".type": "wifi-iface",
            "ssid": "OpenWrt-Home",
            "disabled": "0",
            "device": "radio0",
        },
        "default_radio1": {
            ".type": "wifi-iface",
            "ssid": "OpenWrt-Home-5G",
            "disabled": "0",
            "device": "radio1",
        },
        "guest_radio1": {
            ".type": "wifi-iface",
            "ssid": "Guest-WiFi",
            "disabled": "0",
            "device": "radio1",
        },
    }
}

MOCK_DHCP_LEASES_RAW = (
    "1741600000 b8:27:eb:aa:bb:01 192.168.1.101 raspberrypi 01:b8:27:eb:aa:bb:01\n"
    "1741600001 ac:de:48:11:22:01 192.168.1.102 myphone *\n"
)

MOCK_ASSOCLIST = {
    "results": [
        {"mac": "b8:27:eb:aa:bb:01", "signal": -55, "noise": -95},
        {"mac": "ac:de:48:11:22:01", "signal": -70, "noise": -95},
    ]
}

# All ubus responses keyed by (object, method)
MOCK_UBUS_RESPONSES: dict[tuple[str, str], Any] = {
    ("session", "login"): {
        "ubus_rpc_session": MOCK_SESSION_TOKEN,
        "timeout": 300,
        "expires": 300,
        "acls": {},
        "data": {"username": "root"},
    },
    ("system", "board"): MOCK_BOARD_INFO,
    ("system", "info"): MOCK_SYSTEM_INFO,
    ("network.interface", "dump"): MOCK_NETWORK_DUMP,
    ("network.wireless", "status"): MOCK_WIRELESS_STATUS,
    ("iwinfo", "info"): MOCK_IWINFO_INFO,
    ("iwinfo", "assoclist"): MOCK_ASSOCLIST,
    ("uci", "get"): MOCK_UCI_WIRELESS,
    ("uci", "set"): {},
    ("uci", "commit"): {},
    ("network", "reload"): {},
    ("file", "read"): {"data": MOCK_DHCP_LEASES_RAW},
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_mock_response(status: int = 200, json_data: Any = None):
    """Create a mock aiohttp response."""
    resp = AsyncMock()
    resp.status = status
    resp.json = AsyncMock(return_value=json_data or {})
    return resp


def _make_ubus_envelope(rpc_id: int, ubus_status: int, data: Any) -> dict:
    """Build a ubus JSON-RPC envelope."""
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": [ubus_status, data],
    }


@pytest.fixture
def mock_aiohttp_session():
    """Create a mock aiohttp.ClientSession that routes ubus calls."""
    session = MagicMock()

    def _post(url, json=None, **kwargs):
        """Simulate POST to /ubus (returns an async context manager)."""
        params = (json or {}).get("params", [None, "", "", {}])
        rpc_id = (json or {}).get("id", 1)
        obj = params[1] if len(params) > 1 else ""
        method = params[2] if len(params) > 2 else ""

        key = (obj, method)
        if key in MOCK_UBUS_RESPONSES:
            envelope = _make_ubus_envelope(rpc_id, 0, MOCK_UBUS_RESPONSES[key])
        else:
            envelope = _make_ubus_envelope(rpc_id, 3, None)  # METHOD_NOT_FOUND

        resp = _make_mock_response(200, envelope)

        # Async context manager support (NOT a coroutine - aiohttp session.post
        # returns an async CM directly, not a coroutine)
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    session.post = MagicMock(side_effect=_post)
    return session


@pytest.fixture
def mock_api(mock_aiohttp_session):
    """Create an OpenWrtAPI instance with mock session."""
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="test",
        session=mock_aiohttp_session,
        protocol="http",
    )
    import time
    # Pre-authenticate so tests don't need to call login() first
    api._token = MOCK_SESSION_TOKEN
    api._token_expires_at = time.monotonic() + 3600  # valid for 1h in tests
    return api


@pytest.fixture
def mock_coordinator_data():
    """Return a pre-populated OpenWrtCoordinatorData."""
    data = OpenWrtCoordinatorData()
    data.router_info = {
        "model": "GL.iNet GL-MT3000",
        "hostname": "OpenWrt-Dev",
        "release": {
            "distribution": "OpenWrt",
            "version": "24.10.0",
            "target": "mediatek/filogic",
        },
        "mac": "aa:bb:cc:dd:ee:ff",
        "board_name": "glinet,gl-mt3000",
        "kernel": "6.6.73",
        "platform_architecture": "mediatek/filogic",
    }
    data.uptime = 86400
    data.cpu_load = 100.0
    data.cpu_load_5min = 200.0
    data.cpu_load_15min = 150.0
    data.memory = {
        "total": 268435456,
        "free": 134217728,
        "shared": 4194304,
        "buffered": 8388608,
        "available": 142606336,
    }
    data.wan_status = {
        "connected": True,
        "interface": "wan",
        "ipv4": "203.0.113.42",
        "uptime": 3600,
        "proto": "dhcp",
        "rx_bytes": 1048576,
        "tx_bytes": 524288,
    }
    data.wan_connected = True
    data.wifi_radios = [
        {
            RADIO_KEY_NAME: "radio0",
            RADIO_KEY_IFNAME: "phy0-ap0",
            RADIO_KEY_SSID: "OpenWrt-Home",
            RADIO_KEY_BAND: "2.4g",
            RADIO_KEY_ENABLED: True,
            RADIO_KEY_IS_GUEST: False,
            RADIO_KEY_UCI_SECTION: "default_radio0",
            RADIO_KEY_MODE: "Master",
            RADIO_KEY_CHANNEL: 6,
            RADIO_KEY_FREQUENCY: 2437,
            RADIO_KEY_TXPOWER: 20,
            RADIO_KEY_BITRATE: 72.2,
            RADIO_KEY_HWMODE: "11n",
            RADIO_KEY_HTMODE: "HT20",
            RADIO_KEY_BSSID: "AA:BB:CC:DD:EE:01",
            "signal": -55,
            "noise": -92,
            "quality": 65,
            "quality_max": 100,
        },
        {
            RADIO_KEY_NAME: "radio1",
            RADIO_KEY_IFNAME: "phy1-ap0",
            RADIO_KEY_SSID: "OpenWrt-Home-5G",
            RADIO_KEY_BAND: "5g",
            RADIO_KEY_ENABLED: True,
            RADIO_KEY_IS_GUEST: False,
            RADIO_KEY_UCI_SECTION: "default_radio1",
            RADIO_KEY_MODE: "Master",
            RADIO_KEY_CHANNEL: 36,
            RADIO_KEY_FREQUENCY: 5180,
            RADIO_KEY_TXPOWER: 23,
            RADIO_KEY_BITRATE: 433.3,
            RADIO_KEY_HWMODE: "11ac",
            RADIO_KEY_HTMODE: "VHT80",
            RADIO_KEY_BSSID: "AA:BB:CC:DD:EE:02",
            "signal": -48,
            "noise": -95,
            "quality": 78,
            "quality_max": 100,
        },
        {
            RADIO_KEY_NAME: "radio1",
            RADIO_KEY_IFNAME: "phy1-ap1",
            RADIO_KEY_SSID: "Guest-WiFi",
            RADIO_KEY_BAND: "5g",
            RADIO_KEY_ENABLED: True,
            RADIO_KEY_IS_GUEST: True,
            RADIO_KEY_UCI_SECTION: "guest_radio1",
            RADIO_KEY_MODE: "Master",
            RADIO_KEY_CHANNEL: 36,
            RADIO_KEY_FREQUENCY: 5180,
            RADIO_KEY_TXPOWER: None,
            RADIO_KEY_BITRATE: None,
            RADIO_KEY_HWMODE: None,
            RADIO_KEY_HTMODE: None,
            RADIO_KEY_BSSID: None,
            "signal": None,
            "noise": None,
            "quality": None,
            "quality_max": None,
        },
    ]
    data.clients = [
        {
            CLIENT_KEY_MAC: "B8:27:EB:AA:BB:01",
            CLIENT_KEY_IP: "192.168.1.101",
            CLIENT_KEY_HOSTNAME: "raspberrypi",
            CLIENT_KEY_SIGNAL: -55,
            CLIENT_KEY_SSID: "OpenWrt-Home",
            CLIENT_KEY_RADIO: "phy0-ap0",
            CLIENT_KEY_CONNECTED_SINCE: "2026-04-07T10:00:00+00:00",
            CLIENT_KEY_DHCP_EXPIRES: 9999999999,
        },
        {
            CLIENT_KEY_MAC: "AC:DE:48:11:22:01",
            CLIENT_KEY_IP: "192.168.1.102",
            CLIENT_KEY_HOSTNAME: "myphone",
            CLIENT_KEY_SIGNAL: -70,
            CLIENT_KEY_SSID: "OpenWrt-Home-5G",
            CLIENT_KEY_RADIO: "phy1-ap0",
            CLIENT_KEY_CONNECTED_SINCE: "2026-04-07T10:05:00+00:00",
            CLIENT_KEY_DHCP_EXPIRES: 9999999999,
        },
    ]
    data.client_count = 2
    data.dhcp_leases = {
        "B8:27:EB:AA:BB:01": {"ip": "192.168.1.101", "hostname": "raspberrypi", "expires": 9999999999},
        "AC:DE:48:11:22:01": {"ip": "192.168.1.102", "hostname": "myphone", "expires": 9999999999},
    }
    data.disk_space = {
        "primary": {
            "mount": "/",
            "total_mb": 100,
            "used_mb": 30,
            "free_mb": 70,
            "usage_percent": 30.0,
        }
    }
    data.tmpfs = {
        "total_mb": 128.0,
        "used_mb": 10.0,
        "free_mb": 118.0,
        "usage_percent": 7.8,
    }
    data.active_connections = 42
    data.features = {
        FEATURE_HAS_IWINFO: True,
        FEATURE_HAS_5GHZ: True,
        FEATURE_HAS_6GHZ: False,
        FEATURE_HAS_GUEST_WIFI: True,
        FEATURE_AVAILABLE_RADIOS: ["phy0-ap0", "phy1-ap0", "phy1-ap1"],
        FEATURE_UCI_AVAILABLE: True,
        FEATURE_DHCP_LEASES: True,
    }
    return data


@pytest.fixture
def mock_coordinator(mock_coordinator_data):
    """Create a mock OpenWrtCoordinator with pre-populated data."""
    coordinator = MagicMock(spec=OpenWrtCoordinator)
    coordinator.data = mock_coordinator_data
    coordinator.last_update_success = True
    coordinator.update_interval = MagicMock()
    coordinator.update_interval.total_seconds.return_value = 30.0

    # Properties
    coordinator.router_info = mock_coordinator_data.router_info
    coordinator.features = mock_coordinator_data.features

    # Methods
    coordinator.get_client_by_mac = MagicMock(
        side_effect=lambda mac: next(
            (c for c in mock_coordinator_data.clients if c[CLIENT_KEY_MAC].upper() == mac.upper()),
            None,
        )
    )
    coordinator.is_client_connected = MagicMock(
        side_effect=lambda mac: any(
            c[CLIENT_KEY_MAC].upper() == mac.upper() for c in mock_coordinator_data.clients
        )
    )
    coordinator.async_request_refresh = AsyncMock()
    coordinator.async_add_listener = MagicMock(return_value=lambda: None)

    return coordinator


@pytest.fixture
def mock_config_entry():
    """Create a mock ConfigEntry."""
    entry = MagicMock()
    entry.entry_id = "test_entry_id"
    entry.title = "OpenWrt-Dev"
    entry.data = {
        CONF_HOST: "192.168.1.1",
        CONF_PORT: 80,
        CONF_USERNAME: "root",
        CONF_PASSWORD: "test",
        CONF_PROTOCOL: PROTOCOL_HTTP,
    }
    entry.unique_id = "aabbccddeeff"
    return entry


@pytest.fixture
def mock_config_entry_with_runtime(mock_config_entry, mock_api, mock_coordinator):
    """ConfigEntry with runtime_data set."""
    from custom_components.openwrt_router import OpenWrtRuntimeData
    mock_config_entry.runtime_data = OpenWrtRuntimeData(
        api=mock_api, coordinator=mock_coordinator
    )
    return mock_config_entry
