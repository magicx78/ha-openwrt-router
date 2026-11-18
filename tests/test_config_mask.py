"""Tests for the configuration manager constants and secret masking (G1).

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.1, 11.5, 14, 16 (case 10).
"""

from __future__ import annotations

import copy
import json
import logging
from dataclasses import dataclass, field
from typing import Any

import pytest

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router.config_mask import (
    is_secret_name,
    is_secret_option,
    is_secret_path,
    mask_for_output,
    redact_text,
    secret_digest_factory,
)

SECRET = "Sup3rS3cretValue"
KEY = b"k" * 32

# Every exact and context-dependent option name from plan section 14.1.
_CONTEXT_NAMES = sorted(
    {name for rule in cc.SECRET_CONTEXT_OPTIONS for name in rule.options}
)
ALL_SECRET_NAMES = sorted(set(cc.SECRET_OPTIONS) | set(_CONTEXT_NAMES))

# Section 14.1 literally, so a shrinking constant is caught by the test.
PLAN_14_1_EXACT = (
    "key",
    "key1",
    "key2",
    "key3",
    "key4",
    "password",
    "passwd",
    "psk",
    "sae_password",
    "auth_secret",
    "acct_secret",
    "dae_secret",
    "priv_key_pwd",
    "private_key",
    "preshared_key",
    "secret",
    "token",
    "api_key",
    "apikey",
    "auth_key",
    "shared_secret",
    "pre_shared_key",
    "pin",
    "pincode",
    "wps_pin",
    "r0kh",
    "r1kh",
    "mesh_psk",
    "nas_secret",
)
PLAN_14_1_CONTEXT = {
    ("ddns", "service"): {"password", "param_enc", "param_opt", "update_url"},
    ("rpcd", "login"): {"password"},
    ("network", "interface"): {"password", "pincode"},
    ("network", "wireguard_wg0"): {"private_key", "preshared_key"},
    ("openvpn", "client"): {"auth_user_pass", "askpass", "secret", "key"},
}

# One concrete example per pattern of plan section 14.2.
SECRET_PATH_EXAMPLES = (
    "etc/shadow",
    "etc/passwd",
    "etc/dropbear/dropbear_rsa_host_key",
    "etc/dropbear/dropbear_ed25519_host_key",
    "etc/dropbear/dropbear_ecdsa_host_key",
    "etc/dropbear/authorized_keys",
    "root/.ssh/id_ed25519",
    "etc/uhttpd.key",
    "etc/config/rpcd",
    "etc/config/wireless",
    "etc/config/network",
    "etc/config/ddns",
    "etc/wireguard/wg0.conf",
    "etc/openvpn/client.key",
    "etc/openvpn/ca.pem",
    "etc/openvpn/client.p12",
    "etc/openvpn/client.auth",
    "etc/acme/example/example.key",
    "etc/ssl/private/server.key",
    "etc/luci-uploads/cbid.openvpn.x.secret",
    "etc/ipsec.secrets",
    "etc/swanctl/conf.d/site.conf",
    "etc/ppp/chap-secrets",
    "etc/ppp/pap-secrets",
    "etc/crontabs/root",
    "etc/hostapd.psk",
    "etc/hostapd/wlan0.psk",
)
PUBLIC_PATH_EXAMPLES = (
    "etc/config/system",
    "etc/config/firewall",
    "etc/config/dhcp",
    "etc/hosts",
    "etc/sysupgrade.conf",
    "etc/rc.local",
    "",
)


@dataclass(frozen=True)
class _Change:
    """Shape of config_diff.Change (G4), local so G1 has no dependency on it."""

    kind: str
    config: str
    section: str
    option: str | None
    old: Any
    new: Any


@dataclass
class _Member:
    name: str
    size: int
    content: bytes | str = field(repr=False)


def _dump(obj: Any) -> str:
    return json.dumps(obj, default=str)


# ---------------------------------------------------------------------------
# Constants (plan 11.1)
# ---------------------------------------------------------------------------


def test_secret_options_cover_plan_section_14_1() -> None:
    assert set(PLAN_14_1_EXACT) <= cc.SECRET_OPTIONS
    for (config, section_type), names in PLAN_14_1_CONTEXT.items():
        for name in names:
            assert is_secret_option(config, section_type, name), (config, name)


def test_archive_limits_defaults() -> None:
    limits = cc.ArchiveLimits()
    mib = 1024 * 1024
    assert limits.max_compressed == 16 * mib
    assert limits.max_uncompressed_total == 64 * mib
    assert limits.max_member_size == 16 * mib
    assert limits.max_members == 5000
    assert limits.max_ratio == 200
    assert limits.max_name_length == 255
    assert cc.DEFAULT_ARCHIVE_LIMITS == limits
    with pytest.raises(AttributeError):
        limits.max_members = 1  # type: ignore[misc]


def test_uci_configs_match_acl_scope() -> None:
    assert cc.UCI_CONFIGS == (
        "network",
        "wireless",
        "firewall",
        "dhcp",
        "system",
        "dropbear",
        "uhttpd",
        "rpcd",
        "ddns",
        "sqm",
        "usteer",
        "mwan3",
        "upnpd",
        "openvpn",
    )


def test_timing_and_error_constants() -> None:
    assert cc.DRIFT_DEBOUNCE_S == 300
    assert cc.DRIFT_MIN_INTERVAL_S == 3600
    assert cc.FAILURE_EVENT_COOLDOWN_S == 86400
    assert cc.FETCH_TIMEOUTS[cc.FETCH_METHOD_CGI] == 60.0
    assert cc.FETCH_TIMEOUTS[cc.FETCH_METHOD_SSH] == 120.0
    assert cc.FETCH_TIMEOUTS[cc.FETCH_JOB] == 180.0
    with pytest.raises(TypeError):
        cc.FETCH_TIMEOUTS["cgi"] = 1.0  # type: ignore[index]
    assert set(cc.ERROR_CLASSES) == {
        "unreachable",
        "timeout",
        "auth",
        "permission",
        "not_available",
        "too_large",
        "incomplete",
        "invalid",
        "checksum_mismatch",
        "storage_full",
        "storage_error",
    }
    assert len(cc.ERROR_CLASSES) == len(set(cc.ERROR_CLASSES))


def test_risk_rules_are_well_formed() -> None:
    assert cc.RISK_RULES
    for rule in cc.RISK_RULES:
        assert rule.area in cc.AREAS
        assert rule.risk in cc.RISKS
    for config in cc.UCI_CONFIGS:
        assert config in cc.AREA_RULES
    for area in cc.AREAS:
        assert cc.AREA_DEFAULT_RISK[area] in cc.RISKS


@pytest.mark.parametrize(
    ("config", "section_type", "option", "section_name", "expected"),
    [
        ("network", "bridge-vlan", "ports", "", (cc.AREA_VLAN, cc.RISK_CRITICAL)),
        ("network", "switch_vlan", "vlan", "", (cc.AREA_VLAN, cc.RISK_CRITICAL)),
        ("network", "device", "ports", "", (cc.AREA_VLAN, cc.RISK_CRITICAL)),
        ("network", "device", "type", "", (cc.AREA_VLAN, cc.RISK_CRITICAL)),
        ("network", "device", "mtu", "", (cc.AREA_INTERFACE, cc.RISK_HIGH)),
        ("network", "interface", "dns", "wan", (cc.AREA_INTERFACE, cc.RISK_CRITICAL)),
        (
            "network",
            "interface",
            "proto",
            "wan6",
            (cc.AREA_INTERFACE, cc.RISK_CRITICAL),
        ),
        ("network", "interface", "dns", "lan", (cc.AREA_DNS, cc.RISK_MEDIUM)),
        ("network", "interface", "ipaddr", "lan", (cc.AREA_INTERFACE, cc.RISK_HIGH)),
        ("network", "route", "target", "", (cc.AREA_ROUTING, cc.RISK_HIGH)),
        ("network", "rule", None, "", (cc.AREA_ROUTING, cc.RISK_HIGH)),
        ("firewall", "defaults", "input", "", (cc.AREA_FIREWALL, cc.RISK_CRITICAL)),
        ("firewall", "zone", "input", "", (cc.AREA_FIREWALL, cc.RISK_CRITICAL)),
        ("firewall", "zone", "log", "", (cc.AREA_FIREWALL, cc.RISK_HIGH)),
        ("firewall", "rule", "src_port", "", (cc.AREA_FIREWALL, cc.RISK_HIGH)),
        ("firewall", "forwarding", None, "", (cc.AREA_FIREWALL, cc.RISK_HIGH)),
        ("dropbear", "dropbear", "Port", "", (cc.AREA_SSH, cc.RISK_CRITICAL)),
        ("uhttpd", "uhttpd", "listen_http", "", (cc.AREA_SSH, cc.RISK_CRITICAL)),
        ("rpcd", "login", "username", "", (cc.AREA_SSH, cc.RISK_CRITICAL)),
        ("wireless", "wifi-iface", "ssid", "", (cc.AREA_WLAN, cc.RISK_HIGH)),
        ("wireless", "wifi-iface", "key", "", (cc.AREA_WLAN, cc.RISK_HIGH)),
        ("wireless", "wifi-device", "channel", "", (cc.AREA_WLAN, cc.RISK_MEDIUM)),
        ("wireless", "wifi-device", "disabled", "", (cc.AREA_WLAN, cc.RISK_HIGH)),
        ("dhcp", "host", "ip", "", (cc.AREA_DHCP, cc.RISK_MEDIUM)),
        ("dhcp", "dhcp", "limit", "", (cc.AREA_DHCP, cc.RISK_MEDIUM)),
        ("dhcp", "dnsmasq", "server", "", (cc.AREA_DNS, cc.RISK_MEDIUM)),
        ("sqm", "queue", "download", "", (cc.AREA_SERVICES, cc.RISK_LOW)),
        ("mwan3", "member", "metric", "", (cc.AREA_SERVICES, cc.RISK_MEDIUM)),
        ("system", "system", "hostname", "", (cc.AREA_SYSTEM, cc.RISK_LOW)),
        ("unknownpkg", "thing", "x", "", (cc.AREA_OTHER, cc.RISK_MEDIUM)),
    ],
)
def test_lookup_risk_rule(
    config: str,
    section_type: str,
    option: str | None,
    section_name: str,
    expected: tuple[str, str],
) -> None:
    assert (
        cc.lookup_risk_rule(config, section_type, option, section_name=section_name)
        == expected
    )


# ---------------------------------------------------------------------------
# Case 10: masking
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_SECRET_NAMES)
def test_all_secret_options_masked(name: str) -> None:
    # Detection, case-insensitive.
    assert is_secret_option("wireless", "wifi-iface", name)
    assert is_secret_option("", "", name.upper())
    assert is_secret_name(name)

    # Structured output (ubus form of a UCI section and a nested snapshot).
    section = {".type": "wifi-iface", "ssid": "HomeNet", name: SECRET}
    out = mask_for_output({"wireless": {"default_radio0": section}})
    assert SECRET not in _dump(out)
    assert out["wireless"]["default_radio0"][name] == cc.MASK_PLACEHOLDER
    assert out["wireless"]["default_radio0"]["ssid"] == "HomeNet"

    # List values (UCI `list` options) and digest markers.
    out = mask_for_output({name: [SECRET, SECRET + "2"]})
    assert out == {name: cc.MASK_PLACEHOLDER}
    out = mask_for_output({name: {"secret": "0123456789abcdef"}})
    assert out == {name: cc.MASK_PLACEHOLDER}

    # Free text: UCI file, `uci show`, assignment and JSON forms.
    for text in (
        f"option {name} '{SECRET}'",
        f'\tlist {name} "{SECRET}"',
        f"wireless.@wifi-iface[0].{name}='{SECRET}'",
        f"{name}={SECRET}",
        f'{{"{name}": "{SECRET}", "ssid": "HomeNet"}}',
        f"--{name} {SECRET}",
    ):
        red = redact_text(text)
        assert SECRET not in red, text


def test_secret_paths_never_expose_content() -> None:
    for path in SECRET_PATH_EXAMPLES:
        assert is_secret_path(path), path
        assert is_secret_path("/" + path), path
        assert is_secret_path("./" + path.upper()), path
        content = f"root:{SECRET}:19000:0:99999:7:::"
        out = mask_for_output(
            {
                "by_path": {path: content},
                "member": {"name": path, "size": 42, "content": content},
                "member_dc": _Member(name=path, size=42, content=content.encode()),
                "present": {path: True},
            }
        )
        dumped = _dump(out)
        assert SECRET not in dumped, path
        # Path, presence and size stay visible.
        assert out["member"]["name"] == path
        assert out["member"]["size"] == 42
        assert out["present"][path] is True

    for path in PUBLIC_PATH_EXAMPLES:
        assert not is_secret_path(path), path
    out = mask_for_output({"etc/config/system": "option hostname 'ap1'"})
    assert out == {"etc/config/system": "option hostname 'ap1'"}


def test_secret_path_traversal_is_normalised() -> None:
    assert is_secret_path("etc/../etc/shadow")
    assert is_secret_path("etc//shadow")
    assert is_secret_path("etc\\shadow")
    assert is_secret_path("etc/shadow-")


def test_mask_for_output_json_contains_no_plaintext() -> None:
    digest = secret_digest_factory(KEY)
    wg_private = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    payload = {
        "router_id": "r1",
        "snapshot": {
            "wireless": {
                "@wifi-iface[0]": {
                    "type": "wifi-iface",
                    "ssid": "HomeNet",
                    "encryption": "psk2",
                    "key": {"secret": digest(f"wireless/x/key/{SECRET}")},
                    "sae_password": SECRET,
                }
            },
            "network": {
                "wg0": {"type": "interface", "private_key": wg_private},
                "wan": {"type": "interface", "proto": "pppoe", "password": SECRET},
            },
            "ddns": {
                "myddns": {
                    "type": "service",
                    "update_url": f"https://user:{SECRET}@dyn.example/upd",
                }
            },
        },
        "changes": (
            _Change("changed", "wireless", "@wifi-iface[0]", "key", SECRET, "x"),
            _Change("changed", "wireless", "@wifi-iface[0]", "ssid", "Old", "New"),
            {"config": "ddns", "option": "param_enc", "old": SECRET, "new": None},
        ),
        "errors": [
            f"uci: option key '{SECRET}' invalid",
            f"psk={SECRET}",
            f"Authorization: Bearer {SECRET}",
            f"stderr: {pem}",
        ],
        "raw": SECRET.encode(),
        "peers": [("b", f"token={SECRET}")],
        "tags": frozenset({"wan", f"psk={SECRET}"}),
        "counts": {"critical": 1, "secret_changed": True},
    }
    original = copy.deepcopy(payload)

    out = mask_for_output(payload)
    dumped = _dump(out)

    assert SECRET not in dumped
    assert wg_private not in dumped
    assert "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ" not in dumped
    assert payload == original, "input must not be mutated"
    # Readable parts survive.
    assert out["router_id"] == "r1"
    iface = out["snapshot"]["wireless"]["@wifi-iface[0]"]
    assert iface["ssid"] == "HomeNet"
    assert iface["encryption"] == "psk2"
    assert iface["key"] == cc.MASK_PLACEHOLDER
    assert out["changes"][1] == {
        "kind": "changed",
        "config": "wireless",
        "section": "@wifi-iface[0]",
        "option": "ssid",
        "old": "Old",
        "new": "New",
    }
    assert out["changes"][0]["old"] == cc.MASK_PLACEHOLDER
    assert out["changes"][2]["new"] is None
    assert isinstance(out["changes"], tuple)
    assert out["raw"] == cc.MASK_PLACEHOLDER
    assert out["counts"]["critical"] == 1
    assert out["counts"]["secret_changed"] is True


def test_logs_contain_no_secret(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    log = logging.getLogger("custom_components.openwrt_router.config_test")
    stderr = (
        f"Saving config files...\nuci: Parse error: option key '{SECRET}'\n"
        f"wpa_passphrase={SECRET}\nsessionid={'a' * 32}\n"
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    )
    log.warning("backup failed: %s", redact_text(stderr))
    log.info("result: %s", mask_for_output({"password": SECRET, "nested": [stderr]}))
    # The mask module itself must not log plaintext either, even at DEBUG.
    cyclic: dict[str, Any] = {"psk": SECRET}
    cyclic["self"] = cyclic
    mask_for_output(cyclic)
    secret_digest_factory(KEY)(SECRET)

    text = caplog.text
    assert "backup failed" in text
    assert SECRET not in text
    assert "a" * 32 not in text
    assert "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" not in text


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "ssid",
        "encryption",
        "channel",
        "htmode",
        "ipaddr",
        "proto",
        "username",
        "hostname",
        "ft_psk_generate_local",
        "keepalive",
        "key_mgmt",
        "network",
        "mode",
    ],
)
def test_non_secret_options_stay_readable(name: str) -> None:
    assert not is_secret_option("wireless", "wifi-iface", name)
    assert mask_for_output({name: "visible"}) == {name: "visible"}
    assert redact_text(f"option {name} 'visible'") == f"option {name} 'visible'"


@pytest.mark.parametrize(
    "name",
    ["wpa_passphrase", "auth_user_pass", "my_credential", "ddns_token", "API-KEY"],
)
def test_pattern_catches_unknown_secret_names(name: str) -> None:
    assert is_secret_option("whatever", "whatever", name)
    assert SECRET not in _dump(mask_for_output({name: SECRET}))


def test_case_insensitive_keys_and_marker() -> None:
    out = mask_for_output({"PSK": SECRET, "Password": SECRET, "Key2": SECRET})
    assert set(out.values()) == {cc.MASK_PLACEHOLDER}
    # Digest marker is masked wherever it appears, also under neutral keys.
    assert mask_for_output({"value": {"secret": "abcdef0123456789"}}) == {
        "value": cc.MASK_PLACEHOLDER
    }


def test_empty_and_none_values() -> None:
    out = mask_for_output({"key": "", "psk": None, "pin": 0, "password": []})
    assert out["key"] == cc.MASK_PLACEHOLDER
    assert out["psk"] is None
    assert out["pin"] == cc.MASK_PLACEHOLDER
    assert out["password"] == cc.MASK_PLACEHOLDER
    assert mask_for_output({}) == {}
    assert mask_for_output([]) == []
    assert mask_for_output(None) is None
    assert redact_text("") == ""


def test_deeply_nested_lists_and_tuples() -> None:
    obj = {"a": [{"b": ({"c": [{"secret_key": SECRET}]},)}]}
    out = mask_for_output(obj)
    assert SECRET not in _dump(out)
    assert isinstance(out["a"][0]["b"], tuple)


def test_cycle_does_not_recurse_forever() -> None:
    a: list[Any] = ["x"]
    a.append(a)
    out = mask_for_output(a)
    assert out[0] == "x"
    assert out[1] == cc.MASK_PLACEHOLDER


def test_digest_is_stable_and_key_dependent() -> None:
    d1 = secret_digest_factory(KEY)
    d1b = secret_digest_factory(bytearray(KEY))
    d2 = secret_digest_factory(b"z" * 32)
    value = "wireless/default_radio0/key/" + SECRET
    assert d1(value) == d1(value) == d1b(value)
    assert len(d1(value)) == cc.SECRET_DIGEST_LENGTH
    assert all(ch in "0123456789abcdef" for ch in d1(value))
    assert d1(value) != d2(value)
    assert d1(value) != d1(value + "x")
    assert SECRET not in d1(value)


def test_digest_rejects_weak_keys() -> None:
    with pytest.raises(ValueError):
        secret_digest_factory(b"")
    with pytest.raises(ValueError):
        secret_digest_factory(b"short")
    with pytest.raises(TypeError):
        secret_digest_factory("k" * 32)  # type: ignore[arg-type]


def test_redact_text_free_text_forms() -> None:
    text = (
        f"https://admin:{SECRET}@10.0.0.1/cgi-bin\n"
        f"root:$6$salt${SECRET}:19000:0:99999:7:::\n"
        f"option key '{SECRET}'\\''tail'\n"
        f"PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\n"
        "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
        "option ssid 'HomeNet'\n"
    )
    red = redact_text(text)
    assert SECRET not in red
    assert "tail" not in red
    assert "yAnz5TF" not in red
    assert "AAAA" not in red
    assert "option ssid 'HomeNet'" in red
    assert "10.0.0.1" in red


def test_redact_text_secret_after_readable_pair_on_same_line() -> None:
    assert redact_text(f"ssid=Home psk={SECRET}") == "ssid=Home psk=***"
    assert redact_text(f"GET /x?user=a&token={SECRET}&y=1") == "GET /x?user=a&token=***"
    red = redact_text(f"r0kh=02:00:00:00:03:00 nas1 0001020304{SECRET}")
    assert SECRET not in red


@pytest.mark.parametrize(
    "line",
    [
        # `uci show` prints a list on one line (review L1).
        "wireless.wifinet0.sae_password='pw-one' 'pw-two-{s}'",
        "wireless.@wifi-iface[0].key='pw-one' 'pw-two' '{s}'",
        "openvpn.x.auth_user_pass='it'\\''s' '{s}'",
        'password="pw-one" "{s}"',
        "psk: 'pw-one'{s}",
        "psk='pw-one' trailing {s}",
        "--password 'pw-one' '{s}'",
    ],
)
def test_redact_text_masks_every_value_after_a_secret_head(line: str) -> None:
    text = line.format(s=SECRET)
    red = redact_text(text)
    assert SECRET not in red
    assert "pw-one" not in red and "pw-two" not in red
    # The head stays readable.
    head = text.split("'", 1)[0].split('"', 1)[0]
    assert red.startswith(head)


def test_redact_text_secret_list_does_not_mask_the_next_line() -> None:
    text = f"wireless.w.sae_password='a' '{SECRET}'\nwireless.w.ssid='HomeNet'"
    red = redact_text(text)
    assert SECRET not in red
    assert red.endswith("\nwireless.w.ssid='HomeNet'")


def test_redact_text_keeps_ordinary_messages() -> None:
    msg = "Connection refused: host unreachable after 60 s (error: timeout)"
    assert redact_text(msg) == msg


def test_mask_for_output_keeps_scalar_types() -> None:
    out = mask_for_output(
        {"n": 3, "f": 1.5, "b": False, "s": "ok", "risk": cc.RISK_LOW}
    )
    assert out == {"n": 3, "f": 1.5, "b": False, "s": "ok", "risk": "low"}


@pytest.mark.parametrize(
    "name",
    ["PasswordAuth", "RootPasswordAuth", "passwordauth", "ROOTPASSWORDAUTH"],
)
def test_dropbear_password_auth_switches_stay_readable(name: str) -> None:
    """on/off switches, no secret; the diff must show "on -> off" (any case)."""
    assert not is_secret_option("dropbear", "dropbear", name)
    assert mask_for_output({name: "off"}) == {name: "off"}
    change = {
        "config": "dropbear",
        "section_type": "dropbear",
        "option": name,
        "old": "on",
        "new": "off",
    }
    assert mask_for_output(change) == change
    assert redact_text(f"option {name} 'off'") == f"option {name} 'off'"
    # The whitelist only lifts the pattern: real secrets stay secret.
    assert is_secret_option("dropbear", "dropbear", "Password")
    assert is_secret_option("dropbear", "dropbear", "RootPassword")
