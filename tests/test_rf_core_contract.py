"""Source rules of the RF modules against the Core contract (rf_*.py)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
RF_FILES = sorted(PKG.glob("rf_*.py"))
# Core modules that import Home Assistant themselves (core_guard: hass.core).
_HA_CORE_MODULES = {"core_guard", "core_audit", "core_store", "core_security"}


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(a.name for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append("." * node.level + (node.module or ""))
    return names


def _names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    found |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            found |= {a.name for a in node.names}
    return found


def test_there_are_rf_modules():
    assert len(RF_FILES) >= 15


@pytest.mark.parametrize("path", RF_FILES, ids=lambda p: p.name)
def test_no_direct_home_assistant_or_io_imports(path):
    for name in _imports(path):
        assert not name.startswith("homeassistant"), name
        assert name not in (".api", ".coordinator", ".__init__"), name
        assert name.lstrip(".") not in _HA_CORE_MODULES, name
        assert name not in ("aiohttp", "asyncio", "socket", "subprocess"), name


@pytest.mark.parametrize("path", RF_FILES, ids=lambda p: p.name)
def test_no_async_code_no_probe_in_the_poll(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Await)]


@pytest.mark.parametrize("path", RF_FILES, ids=lambda p: p.name)
def test_rf_never_derives_router_ids_or_makes_keys(path):
    names = _names(path)
    forbidden = {
        "default_router_id",
        "router_id_for_entry",
        "uuid5",
        "uuid4",
        "urandom",
        "token_bytes",
        "token_hex",
        "sha256",
    }
    assert not names & forbidden, sorted(names & forbidden)
    assert "hashlib" not in _imports(path)
    assert "secrets" not in _imports(path)
