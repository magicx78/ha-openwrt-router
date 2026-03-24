"""Unit tests for DHCP lease parsing.

These tests verify the _parse_dhcp_leases static method of OpenWrtAPI.
Now uses the standard import path (HA is installed in venv).
"""
from custom_components.openwrt_router.api import OpenWrtAPI

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


def test_parse_empty():
    assert OpenWrtAPI._parse_dhcp_leases("") == {}
    assert OpenWrtAPI._parse_dhcp_leases("\n\n") == {}


def test_parse_malformed_lines_ignored():
    leases = OpenWrtAPI._parse_dhcp_leases("bad\nonly two fields\n")
    assert leases == {}


def test_parse_uppercase_mac():
    raw = "1741600000 AA:BB:CC:DD:EE:FF 10.0.0.1 laptop *\n"
    leases = OpenWrtAPI._parse_dhcp_leases(raw)
    assert "AA:BB:CC:DD:EE:FF" in leases
    assert leases["AA:BB:CC:DD:EE:FF"]["ip"] == "10.0.0.1"


if __name__ == "__main__":
    test_parse_normal()
    test_parse_empty()
    test_parse_malformed_lines_ignored()
    test_parse_uppercase_mac()
    print("\nAll tests passed!")
