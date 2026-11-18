"""Cost bounds against hostile router data (security review H4).

Masking runs on router-supplied text (error messages, stderr, board names,
config values). Each regex must stay linear, the text length is capped and
router fields are bounded where they enter the inventory.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import pytest

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router.config_collector import collect_inventory
from custom_components.openwrt_router.config_mask import (
    is_secret_name,
    mask_for_output,
    redact_text,
)
from custom_components.openwrt_router.config_provider import _finding_message
from custom_components.openwrt_router.config_restore import Finding

K = 100 * 1024
BUDGET_S = 2.0

HOSTILE = {
    "a": "a" * K,
    "a-": "a-" * (K // 2),
    "a@": "a@" * (K // 2),
    "[a]": "[a]" * (K // 3),
    "a.": "a." * (K // 2),
    "-a": "-a" * (K // 2),
    "a:": "a:" * (K // 2),
    "auth": "auth" * (K // 4),
    "a://": "a://" * (K // 4),
    "option_a": "option a " * (K // 9),
}


def _timed(func: Callable[[], Any]) -> float:
    started = time.perf_counter()
    func()
    return time.perf_counter() - started


@pytest.mark.parametrize("text", list(HOSTILE.values()), ids=list(HOSTILE))
def test_redact_text_is_fast_on_hostile_input(text: str) -> None:
    assert _timed(lambda: redact_text(text)) < BUDGET_S


@pytest.mark.parametrize("text", list(HOSTILE.values()), ids=list(HOSTILE))
def test_secret_name_check_is_fast_on_hostile_names(text: str) -> None:
    assert _timed(lambda: is_secret_name(text)) < BUDGET_S
    assert _timed(lambda: mask_for_output({text: "x"})) < BUDGET_S


def test_redact_text_caps_the_length() -> None:
    text = "word " * (cc.REDACT_MAX_CHARS // 2)
    out = redact_text(text)
    assert len(out) <= cc.REDACT_MAX_CHARS + 32
    assert out.endswith(cc.REDACT_TRUNCATED)
    # Masking still applies to the kept part.
    assert "Secret9" not in redact_text("psk=Secret9 " + text)


def test_long_secret_names_are_still_found() -> None:
    assert redact_text("x" * 120 + ".password=Hunter2") == "x" * 120 + ".password=***"


def test_finding_message_with_a_huge_board_name_is_fast() -> None:
    finding = Finding(
        code="board_mismatch",
        level="block",
        params={"source": "a" * 32000, "target": "a-" * 16000},
    )
    assert _timed(lambda: _finding_message(finding)) < BUDGET_S


class _Api:
    def __init__(self, packages: dict[str, Any]) -> None:
        self.packages = packages

    async def config_packagelist(self) -> dict[str, Any]:
        return self.packages


async def test_collect_inventory_bounds_router_fields() -> None:
    huge = "a" * 32000
    packages = {
        "dnsmasq": "2.90-r4",
        huge: "1.0",
        "evil": huge,
    }
    info = {
        "board_name": huge,
        "model": huge,
        "kernel": "6.6.104",
        "release": {"version": huge, "revision": huge, "target": "mediatek/filogic"},
    }
    inventory = await collect_inventory(_Api(packages), info)  # type: ignore[arg-type]
    assert inventory.board_name is None
    assert inventory.model is None
    assert inventory.release_version is None
    assert inventory.release_revision is None
    assert inventory.kernel == "6.6.104"
    assert inventory.target == "mediatek/filogic"
    assert inventory.packages == {"dnsmasq": "2.90-r4", "evil": None}


async def test_collect_inventory_bounds_the_package_count() -> None:
    packages = {f"pkg{i}": "1" for i in range(cc.INVENTORY_MAX_PACKAGES + 10)}
    info = {"board_name": "cudy,wr3000-v1"}
    inventory = await collect_inventory(_Api(packages), info)  # type: ignore[arg-type]
    assert inventory.packages is not None
    assert len(inventory.packages) == cc.INVENTORY_MAX_PACKAGES
