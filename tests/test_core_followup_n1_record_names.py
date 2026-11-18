"""Review N1 of PR #56: every name field of a record is checked.

A record may name its field in several keys at once (``key``, ``name``,
``field``, ``param``, ``parameter``, ``setting``). The M1 fix stopped at the
first name field holding an allowed identifier name (``sort_key``,
``rule_key`` …) and never looked at the others, so a secret name in a second
field leaked its value. On main all of these were masked.

Rule now: if ANY name field holds a secret name, the values are masked; the
identifier value rule applies only when none does.
"""

from __future__ import annotations

from itertools import permutations

import pytest

from custom_components.openwrt_router.core_masking import (
    MASK,
    mask_for_output,
    mask_secrets,
)

MASKERS = [mask_secrets, mask_for_output]

# (record, value key that must be masked, secret that must not appear)
REVIEW_CASES = [
    ({"key": "sort_key", "field": "password", "value": "hunter2"}, "value", "hunter2"),
    ({"key": "sort_key", "name": "psk", "new": "hunter2"}, "new", "hunter2"),
    (
        {"name": "rule_key", "param": "wpa_passphrase", "after": "hunter2"},
        "after",
        "hunter2",
    ),
    ({"setting": "pin", "key": "rule_key", "value": "12345670"}, "value", "12345670"),
]
REVIEW_IDS = ["key_then_field", "key_then_name", "name_then_param", "setting_then_key"]


@pytest.mark.parametrize("masker", MASKERS, ids=["mask_secrets", "mask_for_output"])
@pytest.mark.parametrize(
    ("record", "value_key", "secret"), REVIEW_CASES, ids=REVIEW_IDS
)
def test_n1_secret_name_in_any_field_masks_the_value(masker, record, value_key, secret):
    out = masker(record)
    assert out[value_key] == MASK
    assert secret not in repr(out)


@pytest.mark.parametrize("masker", MASKERS, ids=["mask_secrets", "mask_for_output"])
@pytest.mark.parametrize(
    "order",
    list(
        permutations([("key", "sort_key"), ("field", "password"), ("value", "hunter2")])
    ),
    ids=lambda order: "-".join(k for k, _ in order),
)
def test_n1_dict_order_does_not_matter(masker, order):
    out = masker(dict(order))
    assert out["value"] == MASK


@pytest.mark.parametrize("masker", MASKERS, ids=["mask_secrets", "mask_for_output"])
@pytest.mark.parametrize(
    ("ident_field", "secret_field"),
    [
        (a, b)
        for a in ("key", "name", "field", "param", "parameter", "setting")
        for b in ("key", "name", "field", "param", "parameter", "setting")
        if a != b
    ],
    ids=lambda v: v,
)
def test_n1_every_pair_of_name_fields(masker, ident_field, secret_field):
    """Secret name before or after the allowed identifier name: masked."""
    record = {ident_field: "rule_key", secret_field: "password", "value": "hunter2"}
    assert masker(record)["value"] == MASK


@pytest.mark.parametrize("masker", MASKERS, ids=["mask_secrets", "mask_for_output"])
def test_n1_identifier_record_without_secret_name_stays_readable(masker):
    """Guard: the M1 behaviour for a pure identifier record is unchanged."""
    out = masker({"key": "sort_key", "value": "newest_first"})
    assert out["value"] == "newest_first"


@pytest.mark.parametrize("masker", MASKERS, ids=["mask_secrets", "mask_for_output"])
def test_n1_identifier_record_with_non_identifier_value_is_masked(masker):
    """Guard: the strict value rule still applies when no name is secret."""
    out = masker({"key": "sort_key", "name": "label", "value": "Hunter 2!"})
    assert out["value"] == MASK
