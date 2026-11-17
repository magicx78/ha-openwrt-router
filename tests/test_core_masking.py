"""Tests for core_masking: the one secret masking of the integration.

core_masking absorbs config_mask / config_const of the config-manager branch
(name lists, context names, archive paths, HMAC digest, free-text redaction,
dataclasses) and adds CamelCase splitting, ``privkey``, ``auth``,
``session`` and the review's word list.
"""

from __future__ import annotations

import ast
import json
from collections import namedtuple
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType

import pytest

from custom_components.openwrt_router import core_masking
from custom_components.openwrt_router.core_masking import (
    MASK,
    SECRET_ARCHIVE_PATHS,
    SECRET_CONTEXT_OPTIONS,
    SECRET_OPTIONS,
    is_secret_key,
    is_secret_name,
    is_secret_option,
    is_secret_path,
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


def test_core_masking_imports_no_config_module():
    source = Path(core_masking.__file__).read_text(encoding="utf-8")
    imported = [
        node.module or ""
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ImportFrom)
    ]
    assert not [m for m in imported if m.lstrip(".").startswith("config_")]
