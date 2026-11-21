"""Source rules of the RF modules against the Core contract (rf_*.py)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
RF_FILES = sorted(PKG.glob("rf_*.py"))
# The Home Assistant wiring of the RF layer (1.48.0 part 1): it runs the reads
# of api.py, the history store and the HTTP routes, so it is async and
# imports Home Assistant. It is pinned here (a new rf_* module is pure unless
# it is added on purpose) and has its own rules below; every other rf_*
# module keeps the pure rules.
RF_WIRING = {"rf_center.py", "rf_collector.py", "rf_store.py", "rf_views.py"}
RF_PURE = [p for p in RF_FILES if p.name not in RF_WIRING]
# Only these may import api.py: the center hands ``async_rf_read`` to the
# collector, the collector names the read kinds and their errors.
_API_USERS = {"rf_center.py", "rf_collector.py"}
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


@pytest.mark.parametrize("path", RF_PURE, ids=lambda p: p.name)
def test_no_direct_home_assistant_or_io_imports(path):
    for name in _imports(path):
        assert not name.startswith("homeassistant"), name
        assert name not in (".api", ".coordinator", ".__init__"), name
        assert name.lstrip(".") not in _HA_CORE_MODULES, name
        assert name not in ("aiohttp", "asyncio", "socket", "subprocess"), name


@pytest.mark.parametrize("path", RF_PURE, ids=lambda p: p.name)
def test_no_async_code_no_probe_in_the_poll(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)]
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.Await)]


def test_the_wiring_is_pinned():
    assert RF_WIRING <= {p.name for p in RF_FILES}
    assert len(RF_PURE) >= 15


@pytest.mark.parametrize("path", sorted(PKG / n for n in RF_WIRING), ids=str)
def test_the_wiring_reaches_routers_only_through_api(path):
    for name in _imports(path):
        assert name not in ("socket", "subprocess", "asyncssh", "paramiko"), name
        assert name not in (".coordinator", ".__init__"), name
        if name == ".api" or name == ".":
            assert path.name in _API_USERS, (path.name, name)
    names = _names(path)
    for forbidden in ("ClientSession", "async_get_clientsession", "_call", "_ubus"):
        assert forbidden not in names, (path.name, forbidden)


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
