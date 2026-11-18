"""Review L1 of PR #56: the counter rule never lifts a secret word.

B4 kept a NUMBER readable under a counter name (``*_failures``,
``*_attempts``, ``*_total`` …) even when a broad secret word hit the name.
A PIN or a one-time password is a number, so ``pin_total = 12345670``
must stay masked. Now the counter rule does not apply when any word of the
name is in ``SECRET_WORDS`` (``pin``, ``pincode``, ``otp``, ``psk``,
``auth``, ``key``, ``session`` …). Consequence: ``auth_failures`` (word
``auth``) is masked again, as on main. A counter without a secret word
(``wan_failures``) was never secret and stays readable.
"""

from __future__ import annotations

import pytest

from custom_components.openwrt_router.core_masking import (
    MASK,
    SECRET_WORDS,
    is_counter_name,
    mask_for_output,
    mask_secrets,
    redact_text,
)

SECRET_COUNTERS = [
    "pin_total",
    "wps_pin_attempts",
    "otp_total",
    "pincode_failures",
    "psk_retries",
    "key_errors",
    "session_total",
    "sae_failed",
    "auth_failures",
    "auth_errors",
    "wifi_auth_failures",
    "authFailures",
    "pin2_total",
]


@pytest.mark.parametrize("name", SECRET_COUNTERS)
def test_secret_word_counters_are_masked(name):
    assert not is_counter_name(name)
    for value in (12345670, 0, 3.5):
        assert mask_secrets({name: value}) == {name: MASK}
        assert mask_for_output({"nested": {name: value}}) == {"nested": {name: MASK}}
    out = redact_text(f"{name}=12345670 ok")
    assert "12345670" not in out
    assert "12345670" not in redact_text(f'"{name}": 12345670,')


@pytest.mark.parametrize("name", ["wan_failures", "probe_attempts", "poll_errors"])
def test_plain_counters_stay_readable(name):
    # never secret in the first place; the counter rule is not needed
    assert mask_for_output({name: 3}) == {name: 3}
    assert redact_text(f"{name}=3") == f"{name}=3"


def test_every_secret_word_blocks_the_counter_rule():
    for word in sorted(SECRET_WORDS):
        assert not is_counter_name(f"{word}_total"), word
        assert not is_counter_name(f"x_{word}_failures"), word
