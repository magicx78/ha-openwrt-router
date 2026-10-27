"""Tests for the shared Wi-Fi band helpers (wifi_band.py)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from custom_components.openwrt_router import wifi_band
from custom_components.openwrt_router.wifi_band import (
    UCI_BAND_MAP,
    band_from_channel,
    band_from_frequency,
    band_from_hwmode,
)


@pytest.mark.parametrize(
    ("value", "band"),
    [
        (2412, "2.4g"),
        ("5180", "5g"),
        (5925, "6g"),
        (7125, "6g"),
        (58320, "unknown"),
        (0, None),
        (None, None),
        (True, None),
        ("n/a", None),
    ],
)
def test_band_from_frequency(value, band):
    assert band_from_frequency(value) == band


@pytest.mark.parametrize(
    ("hwmode", "band"),
    [("11a", "5g"), ("11g", "2.4g"), ("bgn", "2.4g"), ("11ad", "unknown"), ("11ax", None)],
)
def test_band_from_hwmode(hwmode, band):
    assert band_from_hwmode(hwmode) == band


@pytest.mark.parametrize(
    ("channel", "band"),
    [(6, "2.4g"), ("36", "5g"), (149, "5g"), (181, "6g"), (0, None), (35, None)],
)
def test_band_from_channel(channel, band):
    assert band_from_channel(channel) == band


def test_uci_band_map_uses_normalised_codes():
    assert UCI_BAND_MAP == {"2g": "2.4g", "5g": "5g", "6g": "6g", "60g": "unknown"}


def test_module_imports_neither_home_assistant_nor_api():
    """channel_plan/client_stability import it: no HA, no api.py (cycles)."""
    tree = ast.parse(Path(wifi_band.__file__).read_text(encoding="utf-8"))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            modules.add("." * node.level + (node.module or ""))
    assert modules <= {"__future__", "typing"}
