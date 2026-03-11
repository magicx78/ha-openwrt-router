"""Unit tests for DHCP lease parsing (standalone, no HA required)."""
import sys
import types
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).parent.parent

# ---------------------------------------------------------------------------
# Stub every module that api.py or const.py would try to import from HA/aiohttp
# ---------------------------------------------------------------------------
_STUB_MODS = [
    "aiohttp",
    "homeassistant",
    "homeassistant.config_entries",
    "homeassistant.core",
    "homeassistant.exceptions",
    "homeassistant.helpers",
    "homeassistant.helpers.update_coordinator",
    "homeassistant.helpers.device_registry",
    "homeassistant.helpers.entity_platform",
    "homeassistant.components",
    "homeassistant.components.sensor",
    "homeassistant.components.switch",
    "homeassistant.components.device_tracker",
    "homeassistant.components.button",
    "homeassistant.const",
]
for _m in _STUB_MODS:
    if _m not in sys.modules:
        sys.modules[_m] = types.ModuleType(_m)

# aiohttp needs a few class attributes
_aio = sys.modules["aiohttp"]
_aio.ClientSession = object        # type: ignore[attr-defined]
_aio.ClientTimeout = lambda **kw: None  # type: ignore[attr-defined]
_aio.ClientConnectorError = Exception  # type: ignore[attr-defined]
_aio.ClientError = Exception       # type: ignore[attr-defined]

# ---------------------------------------------------------------------------
# Load const.py then api.py directly (bypasses __init__.py)
# ---------------------------------------------------------------------------
def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

_const = _load(
    "custom_components.openwrt_router.const",
    "custom_components/openwrt_router/const.py",
)
_api = _load(
    "custom_components.openwrt_router.api",
    "custom_components/openwrt_router/api.py",
)

OpenWrtAPI = _api.OpenWrtAPI

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------
SAMPLE_LEASES = """\
1741600000 b8:27:eb:aa:bb:cc 192.168.1.100 raspberrypi 01:b8:27:eb:aa:bb:cc
1741600001 ac:de:48:11:22:33 192.168.1.101 myphone *
1741600002 00:11:22:33:44:55 192.168.1.102 * *
"""


def test_parse_normal():
    leases = OpenWrtAPI._parse_dhcp_leases(SAMPLE_LEASES)
    # hostname present → stored as-is
    assert leases["B8:27:EB:AA:BB:CC"] == {"ip": "192.168.1.100", "hostname": "raspberrypi"}
    # hostname present (not '*') → stored
    assert leases["AC:DE:48:11:22:33"] == {"ip": "192.168.1.101", "hostname": "myphone"}
    # hostname is '*' → stored as empty string
    assert leases["00:11:22:33:44:55"] == {"ip": "192.168.1.102", "hostname": ""}
    print("✓ normal lease file parsed correctly")


def test_parse_empty():
    assert OpenWrtAPI._parse_dhcp_leases("") == {}
    assert OpenWrtAPI._parse_dhcp_leases("\n\n") == {}
    print("✓ empty / whitespace-only input → empty dict")


def test_parse_malformed_lines_ignored():
    leases = OpenWrtAPI._parse_dhcp_leases("bad\nonly two fields\n")
    assert leases == {}
    print("✓ malformed lines silently skipped")


def test_parse_uppercase_mac():
    raw = "1741600000 AA:BB:CC:DD:EE:FF 10.0.0.1 laptop *\n"
    leases = OpenWrtAPI._parse_dhcp_leases(raw)
    assert "AA:BB:CC:DD:EE:FF" in leases
    assert leases["AA:BB:CC:DD:EE:FF"]["ip"] == "10.0.0.1"
    print("✓ uppercase MAC stored correctly")


if __name__ == "__main__":
    test_parse_normal()
    test_parse_empty()
    test_parse_malformed_lines_ignored()
    test_parse_uppercase_mac()
    print("\nAll tests passed!")
