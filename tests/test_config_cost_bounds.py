"""Cost bounds against hostile router data (security review H4).

Masking runs on router-supplied text (error messages, stderr, board names,
config values). Each regex must stay linear, the text length is capped and
router fields are bounded where they enter the inventory.
"""

from __future__ import annotations

import gzip
import io
import itertools
import random
import shlex
import tarfile
import time
from collections.abc import Callable
from typing import Any

import pytest

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router.config_archive import extract_uci_texts
from custom_components.openwrt_router.config_collector import collect_inventory
from custom_components.openwrt_router.config_const import (
    config_mask_for_output as mask_for_output,
)
from custom_components.openwrt_router.config_const import (
    config_redact_text as redact_text,
)
from custom_components.openwrt_router.config_const import (
    is_config_secret_name as is_secret_name,
)
from custom_components.openwrt_router.config_provider import _finding_message
from custom_components.openwrt_router.config_restore import Finding
from custom_components.openwrt_router.config_snapshot import (
    _Q_OUT,
    UciTextTooLargeError,
    _quote_state,
    _show_words,
    parse_uci_file,
    parse_uci_show,
)
from custom_components.openwrt_router.core_masking import (
    MASK,
    MAX_TEXT_LENGTH,
    TRUNCATED,
)

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
    text = "word " * (MAX_TEXT_LENGTH // 2)
    out = redact_text(text)
    assert len(out) <= MAX_TEXT_LENGTH + 32
    assert out.endswith(TRUNCATED)
    # Masking still applies to the kept part.
    assert "Secret9" not in redact_text("psk=Secret9 " + text)


def test_long_secret_names_are_still_found() -> None:
    # The core also masks the 120-character run in front (an opaque run of
    # 32+ characters, accepted over-masking M7); the head stays.
    out = redact_text("x" * 120 + ".password=Hunter2")
    assert "Hunter2" not in out
    assert out.endswith(f".password={MASK}")


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


# ---------------------------------------------------------------------------
# Review M6: a UCI text above UCI_TEXT_MAX_BYTES is never parsed
# ---------------------------------------------------------------------------


def _huge_uci() -> str:
    # Hex of random bytes: compresses about 2:1, so the archive ratio
    # check does not reject the test archive first.
    noise = random.Random(6).randbytes(cc.UCI_TEXT_MAX_BYTES // 2 + 1).hex()
    return "config x\n\toption a '" + noise + "'\n"


@pytest.mark.parametrize("parse", ["file", "show"])
def test_parsers_refuse_text_over_the_cap(parse: str) -> None:
    text = _huge_uci()
    if parse == "file":
        call: Callable[[], Any] = lambda: parse_uci_file(text)
    else:
        show = "network.x.a='" + "b" * len(text) + "'"
        call = lambda: parse_uci_show(show, "network")
    started = time.perf_counter()
    with pytest.raises(UciTextTooLargeError):
        call()
    assert time.perf_counter() - started < BUDGET_S
    assert not issubclass(UciTextTooLargeError, ValueError)


def test_extract_uci_texts_leaves_out_oversized_configs() -> None:
    entries = {
        "etc/config/network": b"config interface 'lan'\n",
        "etc/config/system": b"config system\n",
        "etc/config/firewall": _huge_uci().encode(),
    }
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in entries.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    texts = extract_uci_texts(gzip.compress(buf.getvalue()))
    assert sorted(texts) == ["network", "system"]
    assert texts.oversized == ("firewall",)
    assert "firewall" in repr(texts)


UNCLOSED = {
    # One quote that never closes, then many plain lines.
    "single": "network.x.a='\n" + "b\n" * 400_000,
    "double": 'network.x.a="\n' + "b\n" * 400_000,
    # Every line ends in a backslash: each one continues the record.
    "escape": "network.x.a=b\\\n" * 60_000,
    # The first line opens a quote no later line closes, the others pair up.
    "mixed": "network.x.a='\"\n" + 'network.x.b="\n' * 60_000,
}


@pytest.mark.parametrize("text", list(UNCLOSED.values()), ids=list(UNCLOSED))
def test_parse_uci_show_with_open_quotes_is_linear(text: str) -> None:
    assert len(text) <= cc.UCI_TEXT_MAX_BYTES
    assert _timed(lambda: parse_uci_show(text, "network")) < BUDGET_S


def test_parse_uci_show_keeps_multi_line_values() -> None:
    text = (
        "network.lan=interface\n"
        "network.lan.descr='line one\n"
        "line two'\n"
        'network.lan.note="a \\"b\\"\n'
        'c"\n'
        "network.lan.cont=x\\\n"
        "y\n"
        "network.lan.broken='never closed\n"
        "network.lan.proto='static'\n"
    )
    lan = parse_uci_show(text, "network")["lan"]
    assert lan["descr"] == "line one\nline two"
    assert lan["note"] == 'a "b"\nc'
    assert lan["cont"] == "x\ny"
    assert lan["proto"] == "static"
    assert "broken" not in lan


def test_show_unquoting_matches_shlex() -> None:
    """The linear unquoter gives the same words as shlex.split (POSIX)."""
    alphabet = "a'\"\\ \n\t#"
    for length in range(5):
        for chars in itertools.product(alphabet, repeat=length):
            raw = "".join(chars)
            try:
                expected: list[str] | None = shlex.split(raw)
            except ValueError:
                expected = None
            assert _show_words(raw) == expected, raw
            if "\n" not in raw:
                closed = _quote_state(_Q_OUT, raw) is None
                assert closed == (expected is not None), raw


def test_parse_uci_show_near_the_cap_is_fast() -> None:
    value = random.Random(7).randbytes(cc.UCI_TEXT_MAX_BYTES // 2 - 64).hex()
    text = f"network.lan=interface\nnetwork.lan.descr='{value}'\n"
    assert len(text) <= cc.UCI_TEXT_MAX_BYTES
    assert _timed(lambda: parse_uci_show(text, "network")) < BUDGET_S
    assert parse_uci_show(text, "network")["lan"]["descr"] == value


def test_parse_uci_file_near_the_cap_is_fast() -> None:
    value = random.Random(8).randbytes(cc.UCI_TEXT_MAX_BYTES // 2 - 64).hex()
    text = f"config interface 'lan'\n\toption descr {value}\n"
    assert len(text) <= cc.UCI_TEXT_MAX_BYTES
    assert _timed(lambda: parse_uci_file(text)) < BUDGET_S
