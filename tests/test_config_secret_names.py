"""Secret option names found missing in the security review (C2).

Each name is checked end to end: detection, the snapshot (digest marker,
never the plaintext), the diff (no plaintext in old/new) and the output
masking. A fixed whitelist of look-alike names must stay readable.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router.config_diff import diff_snapshots
from custom_components.openwrt_router.config_mask import (
    is_secret_option,
    mask_for_output,
    redact_text,
    secret_digest_factory,
)
from custom_components.openwrt_router.config_snapshot import build_snapshot

SECRET = "Hx7kP2mQ9wLzSecret"
DIGEST = secret_digest_factory(b"k" * 32)

# (config, section type, option) as OpenWrt uses them.
NEW_SECRETS = [
    ("network", "interface", "updatekey"),  # 6in4 tunnelbroker update key
    ("network", "interface", "pppd_options"),  # may hold "password …"
    ("network", "interface", "authkey"),
    ("network", "interface", "sharedkey"),
    ("network", "interface", "otp"),
    ("network", "interface", "ikey"),  # GRE tunnel keys
    ("network", "interface", "okey"),
    ("network", "interface", "token_secret"),  # openconnect
    ("network", "interface", "form_entry"),  # openconnect form fields
    ("openvpn", "client", "tls_auth"),
    ("openvpn", "client", "tls_crypt"),
    ("openvpn", "client", "tls_crypt_v2"),
    ("openvpn", "client", "pkcs12"),
    ("luci", "internal", "sauth"),
    ("acme", "cert", "accessKey"),
    ("acme", "cert", "SecretAccessKey"),
    ("network", "interface", "privkey"),
    ("usteer", "usteer", "key_value"),
    ("network", "interface", "peer_cookie"),  # l2tpv3
]

# Must stay readable (review C2, exact list) plus the openvpn digest
# algorithm "auth" and the PPP auth type "auth".
WHITELIST = [
    "key_mgmt",
    "keepalive",
    "persistent_keepalive",
    "ft_psk_generate_local",
    "passwordauth",
    "rootpasswordauth",
    "maxauthtries",
    "sae_pwe",
    "sae_require_mfp",
    "wpa_group_rekey",
    "wpa_disable_eapol_key_retries",
    "wpa_strict_rekey",
    "auth_cache",
    "r0_key_lifetime",
    "auth_type",
    "auth_nocache",
    "key_direction",
    "auth_server",
    "auth_port",
    "acct_server",
    "acct_port",
    "macfilter",
    "maclist",
]
READABLE = [
    *(("wireless", "wifi-iface", name) for name in WHITELIST),
    ("openvpn", "client", "auth"),
    ("network", "interface", "auth"),
    ("dropbear", "dropbear", "PasswordAuth"),
]


def _snapshot(config: str, stype: str, option: str, value: str) -> Any:
    raw = {config: {"s": {".type": stype, option: value}}}
    return build_snapshot(raw, DIGEST, configs=[config])


def _ids(case: tuple[str, str, str]) -> str:
    return ".".join(case)


@pytest.mark.parametrize("case", NEW_SECRETS, ids=_ids)
def test_new_secret_name_is_detected_and_masked(case: tuple[str, str, str]) -> None:
    config, stype, option = case
    assert is_secret_option(config, stype, option)
    assert SECRET not in json.dumps(mask_for_output({option: SECRET}))
    assert SECRET not in redact_text(f"option {option} '{SECRET}'")
    assert SECRET not in redact_text(f"{config}.s.{option}='{SECRET}'")


@pytest.mark.parametrize("case", NEW_SECRETS, ids=_ids)
def test_new_secret_name_is_a_digest_in_the_snapshot(
    case: tuple[str, str, str],
) -> None:
    config, stype, option = case
    snap = _snapshot(config, stype, option, SECRET)
    value = snap.configs[config]["sections"]["s"]["options"][option]
    assert set(value) == {cc.SECRET_MARKER_KEY}
    assert SECRET not in json.dumps(snap.configs)


@pytest.mark.parametrize("case", NEW_SECRETS, ids=_ids)
def test_new_secret_name_has_no_plaintext_in_the_diff(
    case: tuple[str, str, str],
) -> None:
    config, stype, option = case
    old = _snapshot(config, stype, option, SECRET)
    new = _snapshot(config, stype, option, SECRET + "-new")
    changes = diff_snapshots(old, new, mgmt_host=None)
    assert [change.option for change in changes] == [option]
    for change in changes:
        assert SECRET not in json.dumps([change.old, change.new])
        assert SECRET not in json.dumps(mask_for_output(change))


@pytest.mark.parametrize("case", READABLE, ids=_ids)
def test_whitelisted_names_stay_readable(case: tuple[str, str, str]) -> None:
    config, stype, option = case
    assert not is_secret_option(config, stype, option)
    snap = _snapshot(config, stype, option, "visible")
    assert snap.configs[config]["sections"]["s"]["options"][option] == "visible"
    assert mask_for_output({option: "visible"}) == {option: "visible"}
    assert redact_text(f"option {option} 'visible'") == f"option {option} 'visible'"
