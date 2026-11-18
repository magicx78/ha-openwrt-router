"""Tests for core_masking: the one secret masking of the integration.

core_masking absorbs config_mask / config_const of the config-manager branch
(name lists, context names, archive paths, HMAC digest, free-text redaction,
dataclasses) and adds CamelCase splitting, ``privkey``, ``auth``,
``session`` and the review's word list.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import json
import time
from collections import namedtuple
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from uuid import UUID

import pytest

from custom_components.openwrt_router import core_masking
from custom_components.openwrt_router.core_masking import (
    MASK,
    SECRET_ARCHIVE_PATHS,
    SECRET_CONTEXT_OPTIONS,
    SECRET_OPTION_WHITELIST,
    SECRET_OPTIONS,
    is_secret_key,
    is_secret_name,
    is_secret_option,
    is_secret_path,
    is_snapshot_secret,
    mask_for_output,
    mask_secrets,
    redact_text,
    scrub_text,
    secret_digest_factory,
)

# The 14 names config-manager reported as not masked by contract 5c9d248.
# Measured before the fix: 13 leaked at 5c9d248 (all but auth_user_pass,
# caught by the word "auth"); 7 still leaked after the review's word list
# (r0kh, r1kh, pincode, param_enc, param_opt, update_url, askpass).
REPORTED_LEAKS = [
    "r0kh",
    "r1kh",
    "pincode",
    "param_enc",
    "param_opt",
    "update_url",
    "askpass",
    "sessionid",
    "session_id",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "auth_user_pass",
]

# What config_mask lacked (CamelCase, privkey, auth, session) plus the
# review's words.
CORE_ADDITIONS = [
    "accessKey",
    "authKey",
    "sharedKey",
    "WEPKey",
    "privkey",
    "auth",
    "session",
    "privatekey",
    "presharedkey",
    "Authorization",
    "bearer",
    "cookie",
    "sysauth",
    "community",
]


class TestReportedLeaks:
    @pytest.mark.parametrize("name", REPORTED_LEAKS)
    def test_mask_secrets_masks_reported_name(self, name):
        assert mask_secrets({name: "value"}) == {name: MASK}

    @pytest.mark.parametrize("name", REPORTED_LEAKS)
    def test_mask_for_output_masks_reported_name(self, name):
        assert mask_for_output({name: "value"}) == {name: MASK}

    @pytest.mark.parametrize("name", ["smtp_pass", "ppp_pass", "rootpass"])
    def test_names_with_pass(self, name):
        assert is_secret_key(name)


class TestNames:
    @pytest.mark.parametrize("name", sorted(SECRET_OPTIONS))
    def test_every_exact_option(self, name):
        assert is_secret_name(name)

    @pytest.mark.parametrize(
        "name", sorted({n for rule in SECRET_CONTEXT_OPTIONS for n in rule.options})
    )
    def test_context_names_are_secret_everywhere(self, name):
        assert is_secret_name(name)

    @pytest.mark.parametrize("name", CORE_ADDITIONS)
    def test_core_additions(self, name):
        assert is_secret_key(name)

    @pytest.mark.parametrize(
        "name",
        [
            "wireless.@wifi-iface[0].key",
            "wireless.default_radio0.r0kh",
            "'sae_password'",
            "--password",
            "ddns.myddns.update_url",
        ],
    )
    def test_dotted_quoted_and_flag_forms(self, name):
        assert is_secret_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "ssid",
            "monkey",
            "author",
            "keyboard",
            "hostname",
            "encryption",
            "key_mgmt",
            "keepalive",
            "persistent_keepalive",
            "ft_psk_generate_local",
            "auth_server",
            "auth_port",
            "dedup_key",
            "backup_id",
            "version_ids",
            "content_hash",
            "uci_hash",
            "sha256",
            "contains_secrets",
            "repeat_count",
        ],
    )
    def test_readable_names(self, name):
        assert not is_secret_key(name)

    def test_is_secret_name_is_is_secret_key(self):
        assert is_secret_name is is_secret_key

    def test_context_option(self):
        assert is_secret_option("network", "wireguard_wg0", "private_key")
        assert is_secret_option("ddns", "service", "param_enc")
        assert not is_secret_option("network", "interface", "ipaddr")


class TestArchivePaths:
    @pytest.mark.parametrize(
        "path",
        [
            "etc/shadow",
            "/etc/shadow",
            "./etc/config/wireless",
            "etc/dropbear/dropbear_ed25519_host_key",
            "root/.ssh/authorized_keys",
            "etc/wireguard/wg0/private",
            "ETC/Config/Network",
            "../../etc/shadow",
            "etc\\uhttpd.key",
            "foo/bar.p12",
        ],
    )
    def test_secret_paths(self, path):
        assert is_secret_path(path)

    @pytest.mark.parametrize(
        "path", ["etc/config/system", "etc/banner", "", None, "etc/hosts"]
    )
    def test_plain_paths(self, path):
        assert not is_secret_path(path)

    def test_list_absorbed(self):
        assert "etc/ppp/chap-secrets" in SECRET_ARCHIVE_PATHS


class TestDigest:
    def test_digest_is_hmac16_and_key_bound(self):
        a = secret_digest_factory(b"k" * 32)
        b = secret_digest_factory(b"j" * 32)
        assert a("wireless/r0/key/x") == a("wireless/r0/key/x")
        assert len(a("x")) == 16
        assert a("x") != b("x")
        int(a("x"), 16)

    @pytest.mark.parametrize("key", ["k" * 32, 5, None])
    def test_digest_key_must_be_bytes(self, key):
        with pytest.raises(TypeError):
            secret_digest_factory(key)  # type: ignore[arg-type]

    def test_digest_key_min_length(self):
        with pytest.raises(ValueError):
            secret_digest_factory(b"short")


class TestRedactText:
    @pytest.mark.parametrize(
        ("text", "secret"),
        [
            ("option key 'hunter2'", "hunter2"),
            ("list r0kh '02:00:00:00:00:01,id,0011'", "0011"),
            ("wireless.@wifi-iface[0].key='hunter2'", "hunter2"),
            ('{"password": "hunter2"}', "hunter2"),
            ("password=hunter2 user=root", "hunter2"),
            ("Authorization: Bearer abc.def.ghi", "abc.def.ghi"),
            ("Authorization: Digest username=x", "username"),
            ("curl https://user:hunter2@example.org/x", "hunter2"),
            ("sshpass --password hunter2 ssh", "hunter2"),
            ("root:$6$salt$hashhashhash:19000:0", "$6$salt$hashhashhash"),
            ("PrivateKey = " + "A" * 43 + "=", "A" * 43),
            ("session " + "0123456789abcdef" * 2 + " expired", "0123456789abcdef"),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
                "MIIB",
            ),
            ("Cookie: sysauth=0123", "0123"),
        ],
    )
    def test_secret_removed(self, text, secret):
        assert secret not in redact_text(text)

    @pytest.mark.parametrize(
        "text",
        [
            "router offline",
            "backup bkp_" + "1" * 32 + " failed",
            "router rtr_" + "a" * 32,
            "sha256 " + "b" * 64,
            "option ssid 'Home'",
            "key_mgmt=psk2",
        ],
    )
    def test_plain_text_kept(self, text):
        assert redact_text(text) == text

    def test_scrub_text_keeps_none(self):
        assert scrub_text(None) is None
        assert scrub_text("option key 'x'") == redact_text("option key 'x'")

    def test_secret_after_harmless_pair_on_same_line(self):
        out = redact_text("ssid=Home key=hunter2")
        assert "Home" in out
        assert "hunter2" not in out


@dataclass
class _Radio:
    ssid: str
    key: str


@dataclass(frozen=True, slots=True)
class _Frozen:
    note: str
    psk: str


class TestMaskForOutput:
    def test_dataclasses_become_masked_dicts(self):
        out = mask_for_output({"radio": _Radio(ssid="Home", key="hunter2")})
        assert out == {"radio": {"ssid": "Home", "key": MASK}}
        out = mask_for_output(_Frozen(note="password=x", psk="y"))
        assert out["psk"] == MASK
        assert "x" not in out["note"].replace(MASK, "")

    def test_strings_bytes_and_exceptions(self):
        out = mask_for_output(
            {
                "msg": "option key 'hunter2'",
                "raw": b"\x00secret",
                "err": ValueError("password=hunter2"),
            }
        )
        assert "hunter2" not in json.dumps(out)
        assert out["raw"] == MASK

    def test_digest_marker_masked(self):
        out = mask_for_output({"options": {"ssid": "x", "k": {"secret": "abcd"}}})
        assert out["options"]["k"] == MASK

    def test_option_record_masks_values(self):
        change = {
            "config": "wireless",
            "section_type": "wifi-iface",
            "option": "key",
            "before": "a",
            "after": "b",
        }
        out = mask_for_output(change)
        assert out["before"] == MASK
        assert out["after"] == MASK
        assert out["option"] == "key"

    def test_path_record_masks_content(self):
        out = mask_for_output({"path": "etc/shadow", "content": "root:x", "size": 9})
        assert out["content"] == MASK
        assert out["size"] == 9
        out = mask_for_output({"etc/shadow": "root:x", "etc/banner": "hi"})
        assert out == {"etc/shadow": MASK, "etc/banner": "hi"}

    def test_ids_and_hashes_survive(self):
        data = {
            "backup_id": "bkp_" + "1" * 32,
            "version_ids": ["bkp_" + "2" * 32],
            "content_hash": "c" * 64,
            "device_id": "0123456789abcdef" * 2,
        }
        assert mask_for_output(data) == data

    def test_containers_and_cycles(self):
        point = namedtuple("point", "x y")
        cyclic: dict = {"a": 1}
        cyclic["self"] = cyclic
        out = mask_for_output(
            {
                "t": ("a", {"psk": "x"}),
                "s": frozenset({"plain"}),
                "n": point(1, "password=x"),
                "c": cyclic,
                "m": MappingProxyType({"token": "t"}),
            }
        )
        assert out["t"] == ("a", {"psk": MASK})
        assert out["s"] == frozenset({"plain"})
        assert out["n"].x == 1
        assert out["c"]["self"] == MASK
        assert out["m"] == {"token": MASK}

    def test_none_and_bool_under_secret_key_stay(self):
        assert mask_for_output({"password": None, "psk": True}) == {
            "password": None,
            "psk": True,
        }

    def test_input_not_mutated(self):
        data = {"wifi": [{"key": "x"}]}
        mask_for_output(data)
        assert data == {"wifi": [{"key": "x"}]}

    def test_mask_secrets_keeps_plain_strings(self):
        # mask_secrets is the key-only mode used by core to_dict(): strings
        # under plain keys stay (ids, timestamps), secret keys are masked.
        assert mask_secrets({"msg": "option key 'x'", "psk": "y"}) == {
            "msg": "option key 'x'",
            "psk": MASK,
        }
        assert mask_secrets({"radio": _Radio(ssid="s", key="k")}) == {
            "radio": {"ssid": "s", "key": MASK}
        }
        assert mask_secrets({"raw": b"x"}) == {"raw": MASK}


SECRET = "Sup3rS3cretValue"

# Real OpenWrt options whose values are not secret: the snapshot keeps them
# as plain text so a diff shows "old -> new" (config-manager's view).
READABLE_UCI_OPTIONS = [
    ("wireless", "wifi-iface", "sae_pwe"),
    ("wireless", "wifi-iface", "sae_require_mfp"),
    ("wireless", "wifi-iface", "wpa_group_rekey"),
    ("wireless", "wifi-iface", "wpa_disable_eapol_key_retries"),
    ("wireless", "wifi-iface", "auth_cache"),
    ("wireless", "wifi-iface", "r0_key_lifetime"),
    ("wireless", "wifi-iface", "wpa_strict_rekey"),
    ("wireless", "wifi-iface", "auth_type"),
    ("dropbear", "dropbear", "PasswordAuth"),
    ("dropbear", "dropbear", "RootPasswordAuth"),
    ("dropbear", "dropbear", "MaxAuthTries"),
    ("network", "interface", "auth"),
    ("openvpn", "openvpn", "auth"),
    ("openvpn", "openvpn", "tls_auth"),
    ("openvpn", "openvpn", "auth_nocache"),
    ("openvpn", "openvpn", "key_direction"),
    ("usteer", "usteer", "key_value"),
]


class TestRedactTextValueEnd:
    """An unquoted secret value runs to the end of the line."""

    def test_unquoted_value_with_spaces_removed_to_end_of_line(self):
        out = redact_text("wpa_passphrase=correct horse battery staple")
        for word in ("correct", "horse", "battery", "staple"):
            assert word not in out

    def test_r0kh_key_after_space_removed(self):
        out = redact_text(f"r0kh=02:00:00:00:03:00 nas1 0001020304{SECRET}")
        assert SECRET not in out
        assert "0001020304" not in out

    def test_value_with_comma_and_semicolon_removed(self):
        out = redact_text("key=abc,def;ghi")
        assert "def" not in out
        assert "ghi" not in out

    @pytest.mark.parametrize("name", ["r0kh", "r1kh"])
    def test_r0kh_r1kh_with_64_hex_key_removed(self, name):
        hex_key = "a1b2c3d4" * 8
        out = redact_text(f"{name}=02:00:00:00:03:00,nas1.example,{hex_key}")
        assert hex_key not in out

    def test_quoted_value_ends_at_closing_quote(self):
        out = redact_text('psk="a b c" ssid=Home')
        assert "a b c" not in out
        assert out.endswith(" ssid=Home")

    def test_value_ends_at_line_break(self):
        assert redact_text("psk=x y\nssid=Home").endswith("\nssid=Home")

    def test_flag_value_quoted_ends_at_quote(self):
        out = redact_text("sshpass --password 'a b' ssh root@ap1")
        assert "a b" not in out
        assert out.endswith(" ssh root@ap1")


class TestSnapshotSecretPrecise:
    """is_snapshot_secret: config-manager's digest decision, exactly."""

    @pytest.mark.parametrize(("config", "section_type", "option"), READABLE_UCI_OPTIONS)
    def test_readable_uci_options_are_not_snapshot_secrets(
        self, config, section_type, option
    ):
        assert not is_snapshot_secret(config, section_type, option)

    @pytest.mark.parametrize("name", sorted(SECRET_OPTIONS))
    def test_exact_options_are_snapshot_secrets(self, name):
        assert is_snapshot_secret("wireless", "wifi-iface", name)
        assert is_snapshot_secret("", "", name.upper())

    @pytest.mark.parametrize(
        ("config", "section_type", "option"),
        [
            ("ddns", "service", "param_enc"),
            ("ddns", "service", "param_opt"),
            ("ddns", "service", "update_url"),
            ("rpcd", "login", "password"),
            ("network", "interface", "pincode"),
            ("network", "wireguard_wg0", "private_key"),
            ("openvpn", "client", "auth_user_pass"),
            ("openvpn", "client", "askpass"),
            ("openvpn", "client", "secret"),
            ("openvpn", "client", "key"),
        ],
    )
    def test_context_options_are_snapshot_secrets(self, config, section_type, option):
        assert is_snapshot_secret(config, section_type, option)

    @pytest.mark.parametrize(
        "name", ["wpa_passphrase", "my_credential", "ddns_token", "API-KEY", "Password"]
    )
    def test_pattern_names_are_snapshot_secrets(self, name):
        assert is_snapshot_secret("whatever", "whatever", name)

    def test_openvpn_auth_is_algorithm_tls_auth_is_file_path(self):
        # config-manager: "auth" names a digest algorithm (SHA256) and
        # "tls_auth" a key FILE path; the file content is protected by the
        # archive path rules, the option value itself is not secret.
        assert not is_snapshot_secret("openvpn", "openvpn", "auth")
        assert not is_snapshot_secret("openvpn", "openvpn", "tls_auth")
        assert is_secret_path("etc/openvpn/ta.key")

    def test_lists_identical_to_config_manager(self):
        assert len(SECRET_OPTIONS) == 29
        rules = {
            (rule.config, rule.section_type): set(rule.options)
            for rule in SECRET_CONTEXT_OPTIONS
        }
        assert rules == {
            ("ddns", "service"): {"password", "param_enc", "param_opt", "update_url"},
            ("rpcd", "login"): {"password"},
            ("network", "interface"): {"password", "pincode"},
            ("network", "wireguard_*"): {"private_key", "preshared_key"},
            ("openvpn", "*"): {"auth_user_pass", "askpass", "secret", "key"},
        }
        assert len({n for names in rules.values() for n in names}) == 11
        assert len(SECRET_ARCHIVE_PATHS) == 28
        assert SECRET_OPTION_WHITELIST == frozenset(
            {
                "ft_psk_generate_local",
                "keepalive",
                "persistent_keepalive",
                "key_mgmt",
                "passwordauth",
                "rootpasswordauth",
            }
        )

    def test_digest_value_is_plain_hmac_sha256_16(self):
        key = b"k" * 32
        value = '["wireless","wifi-iface","key","x"]'
        expected = hmac.new(key, value.encode(), hashlib.sha256).hexdigest()[:16]
        assert secret_digest_factory(key)(value) == expected
        assert MASK == "**REDACTED**"


class TestPasswordAuthSwitches:
    @pytest.mark.parametrize(
        "name", ["PasswordAuth", "RootPasswordAuth", "passwordauth", "ROOTPASSWORDAUTH"]
    )
    def test_switch_readable_in_every_mode(self, name):
        change = {
            "config": "dropbear",
            "section_type": "dropbear",
            "option": name,
            "old": "on",
            "new": "off",
        }
        assert not is_snapshot_secret("dropbear", "dropbear", name)
        assert not is_secret_key(name)
        assert not is_secret_option("dropbear", "dropbear", name)
        assert mask_for_output(change) == change
        assert mask_secrets(change) == change
        assert mask_for_output({name: "off"}) == {name: "off"}
        assert redact_text(f"option {name} 'off'") == f"option {name} 'off'"

    def test_real_passwords_stay_secret(self):
        for name in ("Password", "RootPassword"):
            assert is_snapshot_secret("dropbear", "dropbear", name)
            assert is_secret_key(name)


class TestBroadOutput:
    @pytest.mark.parametrize(("config", "section_type", "option"), READABLE_UCI_OPTIONS)
    def test_change_record_of_readable_option_stays_readable(
        self, config, section_type, option
    ):
        change = {
            "config": config,
            "section_type": section_type,
            "option": option,
            "old": "SHA1",
            "new": "SHA256",
        }
        assert not is_secret_option(config, section_type, option)
        assert mask_for_output(change) == change
        assert mask_secrets(change) == change

    @pytest.mark.parametrize("option", ["sae_pwe", "auth", "tls_auth", "community"])
    def test_change_record_without_known_context_is_masked(self, option):
        # No config -> no readable lift: when in doubt, mask.
        out = mask_for_output({"option": option, "old": "a", "new": "b"})
        assert out["old"] == MASK
        assert out["new"] == MASK
        out = mask_for_output(
            {"config": "snmpd", "option": "community", "old": "a", "new": "b"}
        )
        assert out["old"] == MASK

    def test_plain_auth_key_still_masked(self):
        assert mask_for_output({"auth": "x"}) == {"auth": MASK}
        assert mask_secrets({"auth": "x"}) == {"auth": MASK}

    @pytest.mark.parametrize(
        "name",
        sorted(SECRET_OPTIONS)
        + ["param_enc", "update_url", "askpass", "wpa_passphrase", "API-KEY"]
        + [option for _, _, option in READABLE_UCI_OPTIONS],
    )
    def test_broad_is_superset_of_precise(self, name):
        for config, section_type in (
            ("wireless", "wifi-iface"),
            ("openvpn", "client"),
            ("ddns", "service"),
            ("", ""),
        ):
            if is_snapshot_secret(config, section_type, name):
                assert is_secret_option(config, section_type, name)
                assert is_secret_key(name)

    @pytest.mark.parametrize("name", ["password_hash", "secret_id", "token_count"])
    def test_secret_word_beats_safe_suffix(self, name):
        assert is_secret_key(name)

    def test_metadata_survives_output(self):
        data = {
            "sha256": "b" * 64,
            "dedup_key": "audit:r1:backup",
            "content_hash": "c" * 64,
            "backup_id": "bkp_" + "1" * 32,
            "repeat_count": 3,
            "contains_secrets": True,
        }
        assert mask_for_output(data) == data
        assert mask_secrets(data) == data


ARCHIVE_MEMBERS = (
    "etc/dropbear/dropbear_rsa_host_key",
    "etc/dropbear/dropbear_ed25519_host_key",
    "etc/dropbear/dropbear_ecdsa_host_key",
    "etc/config/wireless",
    "etc/openvpn/client.key",
    "etc/luci-uploads/cbid.openvpn.x.secret",
)


class TestNamesAreNotTokens:
    def test_archive_member_list_displayable(self):
        members = list(ARCHIVE_MEMBERS)
        assert mask_for_output({"members": members}) == {"members": members}
        for member in ARCHIVE_MEMBERS:
            assert redact_text(member) == member

    @pytest.mark.parametrize(
        "hostname",
        [
            "openwrt-ap-wohnzimmer-erdgeschoss-1",
            "OpenWrt-AP-Wohnzimmer-Erdgeschoss-2",
            "router_keller_technikraum_hauptverteiler",
        ],
    )
    def test_hostname_with_dashes_kept(self, hostname):
        text = f"router {hostname} offline"
        assert redact_text(text) == text
        assert mask_for_output({"router": hostname}) == {"router": hostname}

    @pytest.mark.parametrize(
        "token",
        [
            "dGhpcyBpcyBhIHNlY3JldCB0b2tlbiB2YWx1ZQ",
            "aB3dE9fG2hJ7kL4mN8pQ1rS6tU0vW5xY_zA-bC",
            "Zm9v/YmFy+YmF6L3F1eC9xdXV4L2NvcmdlL2dyYXVsdA",
            "sk-proj-Ab3x9Kq2Lm7Np4Rt8Vw1Yz6Bc0Df5Gh",
            "eyJhbGciOiJIUzI1NiJ9-eyJzdWIiOiJyb290In0_c2lnbmF0dXJl",
            "ghp_" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2",
            "x" * 40,
        ],
    )
    def test_real_tokens_still_masked(self, token):
        assert token not in redact_text(f"value {token} end")

    def test_token_shapes_still_masked(self):
        assert "0123456789abcdef" * 2 not in redact_text(
            "session " + "0123456789abcdef" * 2
        )
        assert "Bearer abc" not in redact_text("Authorization: Bearer abc")
        assert "MIIB" not in redact_text(
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
        )
        wg_key = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        assert wg_key not in redact_text(f"PrivateKey = {wg_key}")
        assert wg_key not in redact_text(f"peer {wg_key}")


class TestReviewPoint1UpdatekeyPppdOptions:
    """6in4 ``updatekey`` and ppp ``pppd_options`` (may carry a password)."""

    @pytest.mark.parametrize("name", ["updatekey", "pppd_options"])
    def test_masked_in_every_mode(self, name):
        assert is_secret_key(name)
        assert is_snapshot_secret("network", "interface", name)
        assert is_secret_option("network", "interface", name)
        assert mask_secrets({name: SECRET}) == {name: MASK}
        assert mask_for_output({name: SECRET}) == {name: MASK}
        assert SECRET not in redact_text(f"{name}={SECRET}")
        assert SECRET not in redact_text(f"network.wan6.{name}='{SECRET}'")

    def test_pppd_options_password_in_uci_line(self):
        out = redact_text(f"option pppd_options 'password {SECRET} debug'")
        assert SECRET not in out


class TestReviewPoint2MoreNames:
    @pytest.mark.parametrize(
        "name",
        ["authkey", "sharedkey", "otp", "tls_crypt", "tls_crypt_v2", "pkcs12"]
        + ["sauth", "sysauth_https", "tls_auth", "accesskey"],
    )
    def test_broad_mode_masks_without_context(self, name):
        assert is_secret_key(name)
        assert mask_secrets({name: SECRET}) == {name: MASK}
        assert SECRET not in redact_text(f"{name}={SECRET}")
        out = mask_for_output({"option": name, "old": "a", "new": SECRET})
        assert out["new"] == MASK

    @pytest.mark.parametrize("option", ["tls_auth", "tls_crypt", "pkcs12"])
    def test_openvpn_key_file_path_readable_in_context(self, option):
        change = {
            "config": "openvpn",
            "section_type": "openvpn",
            "option": option,
            "old": "/etc/openvpn/a.key",
            "new": "/etc/openvpn/b.key",
        }
        assert not is_snapshot_secret("openvpn", "openvpn", option)
        assert mask_secrets(change) == change
        assert mask_for_output(change) == change

    @pytest.mark.parametrize("option", ["tls_auth", "tls_crypt", "pkcs12"])
    def test_inline_key_block_masked_even_in_context(self, option):
        block = (
            "-----BEGIN OpenVPN Static key V1-----\n"
            f"{SECRET}\n-----END OpenVPN Static key V1-----"
        )
        change = {
            "config": "openvpn",
            "section_type": "openvpn",
            "option": option,
            "old": "/etc/openvpn/a.key",
            "new": block,
        }
        for fn in (mask_secrets, mask_for_output):
            assert SECRET not in json.dumps(fn(change))
        listed = dict(change, new=[block])
        assert SECRET not in json.dumps(mask_secrets(listed))


HOSTILE = 100 * 1024
HOSTILE_INPUTS = {
    "a": "a" * HOSTILE,
    "a-": "a-" * (HOSTILE // 2),
    "a@": "a@" * (HOSTILE // 2),
    "[a]": "[a]" * (HOSTILE // 3),
    "a.": "a." * (HOSTILE // 2),
    "a=": "a=" * (HOSTILE // 2),
    "a b ": "a b " * (HOSTILE // 4),
    "slashes": "/".join(["a"] * (HOSTILE // 2)),
    "quotes": "key='a' " * (HOSTILE // 8),
    "uci_escapes": "psk='" + "'\\''" * (HOSTILE // 4),
    "token32000": "aB3dE9fG2h" * 3200,
    "board_name32000": "openwrt-" * 4000,
}


class TestReviewPoint3Runtime:
    @pytest.mark.parametrize("name", sorted(HOSTILE_INPUTS))
    def test_hostile_input_is_fast(self, name):
        start = time.perf_counter()
        redact_text(HOSTILE_INPUTS[name])
        assert time.perf_counter() - start < 2.0

    def test_long_text_truncated_visibly(self):
        text = "x " * core_masking.MAX_TEXT_LENGTH + f"password={SECRET}"
        out = redact_text(text)
        assert out.endswith(core_masking.TRUNCATED)
        assert SECRET not in out
        assert len(out) <= core_masking.MAX_TEXT_LENGTH + len(core_masking.TRUNCATED)

    def test_cut_never_leaves_a_token_fragment(self):
        filler = "x " * (core_masking.MAX_TEXT_LENGTH // 2 - 5)
        text = filler + SECRET * 10
        out = redact_text(text)
        assert SECRET[:5] not in out
        assert out.endswith(core_masking.TRUNCATED)

    def test_short_text_unchanged(self):
        assert redact_text("router offline") == "router offline"

    def test_url_credentials_any_scheme_shape(self):
        for text in (
            "curl https://user:hunter2@example.org/x",
            "+https://u:hunter2@h",
            "x" * 40 + "https://u:hunter2@h",
        ):
            assert "hunter2" not in redact_text(text)


class TestReviewPoint4MultiValue:
    def test_uci_show_second_value_masked(self):
        out = redact_text("wireless.default_radio0.sae_password='pw-one' 'pw-two'")
        assert "pw-one" not in out
        assert "pw-two" not in out

    def test_unterminated_second_value_masked(self):
        assert "pw-two" not in redact_text("sae_password='pw-one' 'pw-two")

    def test_json_pair_after_secret_kept(self):
        out = redact_text('{"password": "x1", "user": "root"}')
        assert "x1" not in out
        assert '"user": "root"' in out

    def test_list_under_secret_key_fully_masked(self):
        data = {"sae_password": ["pw-one", "pw-two"]}
        for fn in (mask_secrets, mask_for_output):
            assert "pw-" not in json.dumps(fn(data))
            assert "pw-" not in json.dumps(fn({"options": data}))
        change = {"config": "wireless", "option": "r0kh", "values": ["a1", "a2"]}
        assert mask_secrets(change)["values"] == MASK

    def test_list_of_digest_markers(self):
        out = mask_secrets({"r0kh": [{"secret": "ab"}], "x": [{"secret": "cd"}]})
        assert out == {"r0kh": MASK, "x": [MASK]}


class _PlainSecret:
    def __init__(self) -> None:
        self.password = SECRET


class _SlotSecret:
    __slots__ = ("password",)

    def __init__(self) -> None:
        self.password = SECRET


_NTSecret = namedtuple("_NTSecret", "user password")


class TestReviewPoint5OddKeysAndObjects:
    @pytest.mark.parametrize(
        "key", [b"password", ("wifi", "key"), frozenset({"token"}), (1, (b"psk",))]
    )
    def test_non_str_secret_keys_masked(self, key):
        for fn in (mask_secrets, mask_for_output):
            assert fn({key: SECRET}) == {key: MASK}
        assert is_secret_key(key)

    def test_unhashable_byte_names(self):
        assert is_secret_key(bytearray(b"psk"))
        assert is_secret_key(memoryview(b"password"))
        assert not is_secret_key(b"ssid")

    def test_int_key_is_not_a_name(self):
        assert mask_secrets({1: "plain"}) == {1: "plain"}

    @pytest.mark.parametrize("obj", [_PlainSecret(), _SlotSecret()])
    def test_unknown_objects_become_type_marker(self, obj):
        for fn in (mask_secrets, mask_for_output):
            out = fn({"x": obj})
            assert out == {"x": f"**OBJECT:{type(obj).__name__}**"}

    def test_namedtuple_secret_field_masked(self):
        for fn in (mask_secrets, mask_for_output):
            out = fn({"x": _NTSecret("root", SECRET)})["x"]
            assert out == _NTSecret("root", MASK)

    def test_known_value_types_kept(self):
        when = datetime(2026, 11, 18, tzinfo=UTC)
        data = {"at": when, "id": UUID(int=1), "path": PurePosixPath("/etc/x")}
        assert mask_secrets(data) == data


class TestHostileNesting:
    def test_deep_dict_and_list(self):
        deep: object = SECRET
        for _ in range(10_000):
            deep = {"a": [deep]}
        for fn in (mask_secrets, mask_for_output):
            start = time.perf_counter()
            assert SECRET not in repr(fn(deep))
            assert time.perf_counter() - start < 2.0

    def test_deep_tuple_key(self):
        key: object = "password"
        for _ in range(10_000):
            key = (key,)
        assert mask_secrets({key: SECRET}) == {key: MASK}

    def test_wide_dict(self):
        # 100 000 keys measured ~0.95 s per walk (2026-11-18); 50 000 here
        # keeps CI runners well inside the bound.
        wide = {f"k{i}": "v" for i in range(50_000)}
        for fn in (mask_secrets, mask_for_output):
            start = time.perf_counter()
            assert fn(wide) == wide
            assert time.perf_counter() - start < 2.0


def test_core_masking_imports_no_config_module():
    source = Path(core_masking.__file__).read_text(encoding="utf-8")
    imported = [
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    ]
    assert not [m for m in imported if m.lstrip(".").startswith("config_")]
