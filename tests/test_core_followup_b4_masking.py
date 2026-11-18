"""Follow-up B4: identifier names with ``key``, counters, identifier pseudonyms.

1. Field names that name an identifier (``router_key``, ``radio_key``, …,
   ``IDENTIFIER_KEY_NAMES``) are no longer blackened by the broad ``key``
   rule; their VALUE is still masked when it looks like key material (PEM
   block, long base64 / base64url, long hex). UCI options keep the precise
   snapshot rule (``is_snapshot_secret`` unchanged).
2. Counter names keep NUMBERS readable; any other value under them is
   masked as before. Since review L1 the rule never lifts a name with a
   word of SECRET_WORDS, so ``auth_failures`` is masked again.
3. ``pseudonymise_identifier(kind, value, key)`` for mac / ip / hostname /
   ssid / bssid / client and ``pseudonymise_fields(data, key, fields)``:
   deterministic, normalised per kind, prefix per kind, 16 hex. Core
   masking itself never masks MAC/IP/hostname/SSID/BSSID.
"""

from __future__ import annotations

import base64

import pytest

from custom_components.openwrt_router import core_masking as cm
from custom_components.openwrt_router.core_masking import (
    IDENTIFIER_INVALID,
    IDENTIFIER_KEY_NAMES,
    IDENTIFIER_PSEUDONYM_HEX_LENGTH,
    IDENTIFIER_PSEUDONYM_PREFIXES,
    MASK,
    is_secret_key,
    is_snapshot_secret,
    mask_for_output,
    mask_secrets,
    pseudonymise_fields,
    pseudonymise_identifier,
    redact_text,
)

KEY = b"\x07" * 32
PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
B64 = base64.b64encode(bytes(range(32))).decode()  # 44 chars, WireGuard shape
B64URL = base64.urlsafe_b64encode(bytes(range(100, 148))).decode().rstrip("=")
HEX64 = "ab" * 32
RTR = "rtr_" + "0123456789abcdef" * 2


@pytest.mark.parametrize("name", ["rule_key", "scope_key", "ruleKey", "SCOPE-KEY"])
def test_identifier_names_readable(name):
    # review M1: still a secret NAME; only a strict identifier value shows
    assert is_secret_key(name)
    assert mask_secrets({name: "radio0"}) == {name: "radio0"}
    assert mask_for_output({name: RTR}) == {name: RTR}
    assert redact_text(f"{name}=radio0") == f"{name}=radio0"


@pytest.mark.parametrize("value", [PEM, B64, B64URL, HEX64, "  " + B64 + "  "])
@pytest.mark.parametrize("name", ["rule_key", "scope_key", "router_key", "radio_key"])
def test_identifier_value_key_material(name, value):
    assert mask_secrets({name: value}) == {name: MASK}
    assert mask_for_output({name: value}) == {name: MASK}
    assert mask_for_output({"key": name, "value": value})["value"] == MASK
    out = redact_text(f"{name}={value}")
    assert value.strip() not in out and "MIIEvQ" not in out


def test_identifier_names_listed():
    assert {"rule_key", "scope_key"} <= IDENTIFIER_KEY_NAMES
    # review M1: router_key / radio_key are off the list (masked like on main)
    assert not {"router_key", "radio_key"} & IDENTIFIER_KEY_NAMES
    # real secrets stay secret
    for name in ("key", "key1", "wpa_key", "private_key", "auth_key", "api_key"):
        assert is_secret_key(name), name
    assert mask_secrets({"private_key": "radio0"}) == {"private_key": MASK}


def test_snapshot_rule_unchanged():
    """UCI options keep config-manager's precise rule (``_key$``)."""
    for option in ("router_key", "radio_key", "rule_key"):
        assert is_snapshot_secret("wireless", "wifi-iface", option)
        assert cm.is_secret_option("wireless", "wifi-iface", option)
    change = {"config": "x", "option": "radio_key", "old": "a", "new": "b"}
    masked = mask_for_output(change)
    assert masked["old"] == MASK and masked["new"] == MASK


@pytest.mark.parametrize("name", ["auth_failures", "auth_errors", "wifi_auth_failures"])
def test_counter_names(name):
    # review L1: the word "auth" is in SECRET_WORDS, so the counter rule no
    # longer lifts these names; numbers are masked again (as on main)
    assert mask_secrets({name: 3}) == {name: MASK}
    assert mask_for_output({name: 0, "nested": {name: 12}}) == {
        name: MASK,
        "nested": {name: MASK},
    }
    assert "=3" not in redact_text(f"{name}=3 ok")
    assert ": 7" not in redact_text(f'"{name}": 7,')
    assert mask_secrets({name: "hunter2"}) == {name: MASK}
    assert "hunter2" not in redact_text(f"{name}=hunter2")
    assert mask_secrets({name: True}) == {name: True}  # bool carries nothing


def test_counter_rule_keeps_real_secrets():
    for name in ("password_failures", "auth", "auth_key", "pin"):
        assert mask_secrets({name: 1234}) == {name: MASK}, name
    assert "1234" not in redact_text("pin=1234")


def test_redact_keeps_other_secrets_on_line():
    out = redact_text("wan_failures=3 password=hunter2")
    assert out.startswith("wan_failures=3 ") and "hunter2" not in out


def test_core_never_masks_network_identifiers():
    data = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "ip": "192.168.1.10",
        "hostname": "laptop",
        "ssid": "Home",
        "bssid": "aa:bb:cc:00:11:22",
    }
    assert mask_for_output(data) == data


# -- pseudonymise_identifier ---------------------------------------------------------


def _shape(value: str, kind: str) -> bool:
    prefix = IDENTIFIER_PSEUDONYM_PREFIXES[kind]
    tail = value[len(prefix) :]
    return (
        value.startswith(prefix)
        and len(tail) == IDENTIFIER_PSEUDONYM_HEX_LENGTH
        and all(c in "0123456789abcdef" for c in tail)
    )


def test_prefixes_and_length():
    assert IDENTIFIER_PSEUDONYM_PREFIXES == {
        "mac": "mac_",
        "ip": "ipa_",
        "hostname": "hst_",
        "ssid": "ssd_",
        "bssid": "bss_",
        "client": "cli_",
    }
    assert IDENTIFIER_PSEUDONYM_HEX_LENGTH == 16
    for kind, value in (
        ("mac", "aa:bb:cc:dd:ee:ff"),
        ("ip", "10.0.0.1"),
        ("hostname", "nas"),
        ("ssid", "Home"),
        ("bssid", "aa:bb:cc:dd:ee:ff"),
        ("client", "aa:bb:cc:dd:ee:ff"),
    ):
        assert _shape(pseudonymise_identifier(kind, value, KEY), kind)


@pytest.mark.parametrize(
    ("kind", "spellings"),
    [
        (
            "mac",
            [
                "AA:BB:CC:DD:EE:FF",
                "aa-bb-cc-dd-ee-ff",
                "aabb.ccdd.eeff",
                "aabbccddeeff",
            ],
        ),
        ("bssid", ["AA:BB:CC:00:11:22", "aa-bb-cc-00-11-22"]),
        ("client", ["AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:01 "]),
        ("ip", ["192.168.1.10", " 192.168.1.10 "]),
        ("ip", ["2001:DB8:0:0:0:0:0:1", "2001:db8::1", "2001:0db8::0001"]),
        ("hostname", ["Laptop", "laptop.", " LAPTOP "]),
    ],
)
def test_normalisation(kind, spellings):
    results = {pseudonymise_identifier(kind, s, KEY) for s in spellings}
    assert len(results) == 1, results


def test_deterministic_and_separated():
    a = pseudonymise_identifier("mac", "aa:bb:cc:dd:ee:ff", KEY)
    assert a == pseudonymise_identifier("mac", "aa:bb:cc:dd:ee:ff", KEY)
    assert a != pseudonymise_identifier("mac", "aa:bb:cc:dd:ee:ff", b"\x08" * 32)
    # the kind is part of the input: the same MAC as client or BSSID differs
    tails = {
        pseudonymise_identifier(k, "aa:bb:cc:dd:ee:ff", KEY)[4:]
        for k in ("mac", "bssid", "client")
    }
    assert len(tails) == 3
    # SSIDs are case sensitive (two networks)
    assert pseudonymise_identifier("ssid", "Home", KEY) != pseudonymise_identifier(
        "ssid", "home", KEY
    )
    assert "aabbccddeeff" not in a


@pytest.mark.parametrize(
    ("kind", "value"),
    [
        ("mac", "not-a-mac"),
        ("ip", "999.1.1.1"),
        ("hostname", "   "),
        ("ssid", ""),
        ("bssid", 12),
        ("color", "red"),
    ],
)
def test_invalid(kind, value):
    with pytest.raises((ValueError, TypeError)):
        pseudonymise_identifier(kind, value, KEY)


def test_short_key_refused():
    with pytest.raises(ValueError):
        pseudonymise_identifier("mac", "aa:bb:cc:dd:ee:ff", b"short")


def test_fields_helper():
    data = {
        "mac": "AA:BB:CC:DD:EE:FF",
        "count": 3,
        "clients": [{"mac": "aa:bb:cc:dd:ee:01", "ip": "10.0.0.2", "name": "tv"}],
        "macs": ["aa:bb:cc:dd:ee:02", None],
        "ip": "garbage",
        "hostname": None,
    }
    fields = {"mac": "mac", "macs": "mac", "ip": "ip", "hostname": "hostname"}
    out = pseudonymise_fields(data, KEY, fields)
    assert out["mac"] == pseudonymise_identifier("mac", "aa:bb:cc:dd:ee:ff", KEY)
    assert out["count"] == 3
    assert out["clients"][0]["name"] == "tv"
    assert _shape(out["clients"][0]["mac"], "mac")
    assert _shape(out["clients"][0]["ip"], "ip")
    assert _shape(out["macs"][0], "mac") and out["macs"][1] is None
    assert out["ip"] == IDENTIFIER_INVALID  # visible, never the raw value
    assert out["hostname"] is None
    assert data["mac"] == "AA:BB:CC:DD:EE:FF"  # input unchanged
    with pytest.raises(ValueError):
        pseudonymise_fields(data, KEY, {"mac": "colour"})
