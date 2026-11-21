"""Review M1 of PR #56: identifier names must never open a leak.

On main every name below was masked (``_key$`` / the word ``key``); B4 made
``IDENTIFIER_KEY_NAMES`` readable and walked into their values. Now:

a) ``client_key`` / ``device_key`` (and every other name that is a real key
   somewhere: MQTT/TLS, IoT, Signal/MTProto, Tor, keystores …) are off the
   list; a client is referenced by ``client_ref``.
b) Under a name that stays on the list only a STRICT identifier value is
   readable: a core id (``rtr_<32 hex>``, ``cli_<16 hex>`` …) or a short
   lower-case slug that is not key material. Anything else (dict, list,
   number, mixed case, blanks, symbols, PEM, long base64/hex) is masked.
c) ``is_secret_key`` says True for identifier names again (a caller that
   only asks the predicate over-masks); the walkers and ``redact_text``
   apply the strict value rule.
"""

from __future__ import annotations

import base64

import pytest

from custom_components.openwrt_router import core_masking as cm
from custom_components.openwrt_router.core_masking import (
    IDENTIFIER_KEY_NAMES,
    MASK,
    is_identifier_name,
    is_identifier_value,
    is_secret_key,
    is_snapshot_secret,
    mask_for_output,
    mask_secrets,
    redact_text,
)

PEM = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
B64 = base64.b64encode(bytes(range(32))).decode()
HEX64 = "ab" * 32
RTR = "rtr_" + "0123456789abcdef" * 2
CLI = "cli_" + "0123456789abcdef"

SECRET_WORDS_IN_VALUES = ("hunter2", "s3cr3t", "a1b2c3d4e5f6g7h8", "Tr0ub4dor", "horse")

# The reviewer's table: every case must come out masked.
STRUCTURED_CASES = [
    {"client_key": "hunter2"},
    {"device_key": "a1b2c3d4e5f6g7h8"},
    {"client_key": "correct-horse-battery-staple"},
    {"device_key": {"value": "s3cr3t"}},
    {"client_key": [{"v": "s3cr3t"}]},
    {"Client-Key": "hunter2"},
    {"clientKey": "hunter2"},
    {"client_key2": "hunter2"},
]
TEXT_CASES = [
    "client_key=hunter2",
    "wireless.radio0.client_key='hunter2'",
    "option device_key 'Tr0ub4dor&3'",
]


def _leaks(out: object) -> list[str]:
    text = repr(out)
    return [word for word in SECRET_WORDS_IN_VALUES if word in text]


@pytest.mark.parametrize("case", STRUCTURED_CASES, ids=lambda c: next(iter(c)))
@pytest.mark.parametrize("walker", [mask_secrets, mask_for_output])
def test_reviewer_table_structured(walker, case):
    out = walker(case)
    assert out == {next(iter(case)): MASK}
    assert _leaks(out) == []
    # also nested, and inside a list
    nested = walker({"module": {"findings": [case]}})
    assert _leaks(nested) == []


@pytest.mark.parametrize("text", TEXT_CASES)
def test_reviewer_table_text(text):
    out = redact_text(text)
    assert _leaks(out) == [], out
    assert MASK in out
    # the same text as a value of a neutral key in an event payload
    assert _leaks(mask_for_output({"message": text})) == []


def test_client_and_device_key_off_the_list():
    for name in ("client_key", "device_key", "Client-Key", "clientKey", "client_key2"):
        assert not is_identifier_name(name), name
        assert is_secret_key(name), name


FINAL_LIST = frozenset(
    {
        "finding_key",
        "incident_key",
        "recommendation_key",
        "rule_key",
        "scope_key",
        "sort_key",
        "translation_key",
    }
)
REMOVED = (
    "cache_key",
    "client_key",
    "device_key",
    "entry_key",
    "event_key",
    "lookup_key",
    "message_key",
    "msg_key",
    "radio_key",
    "router_key",
)


def test_final_identifier_list():
    assert IDENTIFIER_KEY_NAMES == FINAL_LIST
    for name in REMOVED:
        assert not is_identifier_name(name), name
        assert mask_for_output({name: "radio0"}) == {name: MASK}, name
        assert "radio0" not in redact_text(f"{name}=radio0"), name


@pytest.mark.parametrize("name", sorted(FINAL_LIST))
@pytest.mark.parametrize(
    "value",
    [
        {"value": "s3cr3t"},
        [{"v": "s3cr3t"}],
        ["s3cr3t"],
        ("s3cr3t",),
        {"nested": {"deeper": "s3cr3t"}},
    ],
    ids=["dict", "list_of_dicts", "list", "tuple", "deep_dict"],
)
@pytest.mark.parametrize("walker", [mask_secrets, mask_for_output])
def test_non_scalar_under_identifier_is_masked(walker, name, value):
    assert walker({name: value}) == {name: MASK}


@pytest.mark.parametrize("name", sorted(FINAL_LIST))
def test_identifier_name_is_still_a_secret_name(name):
    # a caller that only asks the predicate over-masks instead of leaking
    assert is_secret_key(name)
    assert is_identifier_name(name)


READABLE_VALUES = [
    RTR,
    CLI,
    "bkp_" + "f" * 32,
    "radio0",
    "wan_down",
    "port_scan",
    "rogue_ap.suspected",
    "fw:wan-in",
    "aa:bb:cc:dd:ee:ff",
    "rule-12",
    "x",
]
MASKED_VALUES = [
    PEM,
    B64,
    HEX64,
    "a" * 65,  # too long for a slug
    "Tr0ub4dor&3",  # symbols / mixed case
    "Hunter2",  # mixed case
    "correct horse battery staple",  # blanks
    "s3cr3t!",
    "abcdefghijklmnopqrstuvwx",  # 24 lower-case letters without a separator
    "0123456789abcdef0123456789abcdef",  # 32 hex
    "",
    " radio0",
    "radio0\n",
    1234,
    12.5,
]


@pytest.mark.parametrize("value", READABLE_VALUES)
@pytest.mark.parametrize("name", ["rule_key", "translation_key", "ruleKey", "RULE-KEY"])
def test_strict_identifier_values_readable(name, value):
    assert is_identifier_value(value)
    assert mask_secrets({name: value}) == {name: value}
    assert mask_for_output({name: value}) == {name: value}
    assert mask_for_output({"key": name, "value": value})["value"] == value
    # (an unquoted "name=<id>" run of 32+ characters is one opaque token for
    # the long-token rule and stays masked as before; ": " and quotes keep it)
    # 1.49.4: free text masks a MAC (structured output above keeps it)
    shown = MASK if value == "aa:bb:cc:dd:ee:ff" else value
    assert redact_text(f"{name}: {value}") == f"{name}: {shown}"
    assert redact_text(f"{name}='{value}'") == f"{name}='{shown}'"


@pytest.mark.parametrize("value", MASKED_VALUES, ids=repr)
@pytest.mark.parametrize("name", ["rule_key", "scope_key"])
def test_other_values_masked(name, value):
    assert not is_identifier_value(value)
    assert mask_secrets({name: value}) == {name: MASK}
    assert mask_for_output({name: value}) == {name: MASK}
    assert mask_for_output({"key": name, "value": value})["value"] == MASK
    if isinstance(value, str) and value and value == value.strip():
        out = redact_text(f"{name}={value}")
        assert value.strip() not in out and "MIIEvQ" not in out, out


def test_none_and_bool_stay():
    assert mask_for_output({"rule_key": None, "sort_key": True}) == {
        "rule_key": None,
        "sort_key": True,
    }


def test_free_text_keeps_following_pairs_readable():
    assert redact_text("rule_key=wan_in, count=3") == "rule_key=wan_in, count=3"
    assert redact_text("rule_key=wan_in band=5g") == "rule_key=wan_in band=5g"
    # a passphrase after the identifier: the whole rest of the line is masked
    out = redact_text("rule_key=wan correct horse battery")
    assert "horse" not in out and "battery" not in out
    # escaped JSON keeps the old rule (masked)
    out = redact_text('{\\"rule_key\\": \\"wan_in\\"}')
    assert "wan_in" not in out


def test_identifier_with_trailing_digits_is_not_an_identifier():
    for name in ("rule_key2", "rule2_key", "sort_key1"):
        assert not is_identifier_name(name), name
        assert mask_for_output({name: "radio0"}) == {name: MASK}, name


def test_precise_mode_unchanged():
    for option in (*REMOVED, *FINAL_LIST):
        assert is_snapshot_secret("wireless", "wifi-iface", option), option
    change = {"config": "x", "option": "rule_key", "old": "a", "new": "b"}
    masked = mask_for_output(change)
    assert masked["old"] == MASK and masked["new"] == MASK


def test_byte_and_namedtuple_keys_mask():
    from collections import namedtuple

    pair = namedtuple("pair", ["rule_key", "other"])
    assert mask_for_output(pair({"value": "s3cr3t"}, "x")).rule_key == MASK
    assert mask_secrets({b"rule_key": {"value": "s3cr3t"}}) == {b"rule_key": MASK}


def test_module_level_helpers_exist():
    assert cm.IDENTIFIER_VALUE_MAX_LENGTH == 64
