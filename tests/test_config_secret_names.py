"""Secret option names found missing in the security review (C2).

Each name is checked end to end: detection, the snapshot (digest marker,
never the plaintext), the diff (no plaintext in old/new) and the output
masking. A fixed whitelist of look-alike names must stay readable.

Since 2026-11-18 these run as acceptance tests against core_masking plus
the configuration manager's bridge (config_const). Readable names are
judged in their real config: the core keeps them readable in the snapshot,
the diff and a change record that names its config; a bare key or a text
line without a config is masked by the core's broad rule for some of them
(accepted over-masking, display only, M6).
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from custom_components.openwrt_router import core_masking as cm
from custom_components.openwrt_router.config_const import (
    config_mask_for_output as mask_for_output,
)
from custom_components.openwrt_router.config_const import (
    config_redact_text as redact_text,
)
from custom_components.openwrt_router.config_const import (
    is_config_secret_option as is_secret_option,
)
from custom_components.openwrt_router.config_diff import diff_snapshots
from custom_components.openwrt_router.config_snapshot import build_snapshot
from custom_components.openwrt_router.core_masking import (
    SECRET_MARKER_KEY,
    secret_digest_factory,
)

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
# algorithm "auth" and the PPP auth type "auth", each in its real config.
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
_REAL_CONFIG = {
    "keepalive": ("openvpn", "client"),
    "persistent_keepalive": ("network", "wireguard_wg0"),
    "passwordauth": ("dropbear", "dropbear"),
    "rootpasswordauth": ("dropbear", "dropbear"),
    "maxauthtries": ("dropbear", "dropbear"),
    "auth_nocache": ("openvpn", "client"),
    "key_direction": ("openvpn", "client"),
}
READABLE = [
    (*_REAL_CONFIG.get(name, ("wireless", "wifi-iface")), name) for name in WHITELIST
] + [
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
    assert set(value) == {SECRET_MARKER_KEY}
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
    # The diff record names its config: the value stays readable.
    old = _snapshot(config, stype, option, "visible")
    new = _snapshot(config, stype, option, "other")
    (change,) = diff_snapshots(old, new, mgmt_host=None)
    masked = mask_for_output(change)
    assert (masked["old"], masked["new"]) == ("visible", "other")
    if not cm.is_secret_key(option):
        # Without a config only names the core's broad rule lets through
        # stay readable; the others are masked (accepted over-masking, M6).
        assert mask_for_output({option: "visible"}) == {option: "visible"}
        line = f"option {option} 'visible'"
        assert redact_text(line) == line
