"""Enterprise core import: never on the event loop, never fatal.

HA imports the integration package in the executor. The core modules must be
loaded by that import, not first imported inside ``async_setup_entry`` (which
runs on the event loop: "Detected blocking call to import_module"). A core
that fails to import degrades to "core unavailable" with one warning; the
routers keep working.

The import checks run in a fresh interpreter: in the test session the modules
are long since imported by other tests.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from core_testkit import FakeDisks
from test_enterprise_core_lifecycle import _core_listeners, _lifecycle_snapshot

import custom_components.openwrt_router as integration
from custom_components.openwrt_router.core_models import ROUTER_REGISTRY_STORE_KEY

ROOT = Path(__file__).resolve().parent.parent
PKG = "custom_components.openwrt_router"
CORE_MODULES = (
    "enterprise_core",
    "config_api",
    "core_audit",
    "core_errors",
    "core_guard",
    "core_masking",
    "core_models",
    "core_security",
    "core_store",
    "router_registry",
    "version_store",
    "acl_provisioning",
)

# Fresh interpreter: register custom_components like tests/conftest.py, then
# import the package exactly once (what HA does in the executor).
_PRELUDE = r"""
import importlib.abc, json, logging, os, sys, types
root = sys.argv[1]
sys.path.insert(0, root)
cc = types.ModuleType("custom_components")
cc.__path__ = [os.path.join(root, "custom_components")]
sys.modules["custom_components"] = cc
"""

_LOADED = (
    _PRELUDE
    + r"""
import custom_components.openwrt_router  # noqa
mods = sorted(m for m in sys.modules if m.startswith("custom_components.openwrt_router."))
print(json.dumps(mods))
"""
)

_BROKEN = (
    _PRELUDE
    + r"""
class _Broken(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "custom_components.openwrt_router.enterprise_core":
            raise RuntimeError("core is broken")
        return None

sys.meta_path.insert(0, _Broken())
records = []

class _Keep(logging.Handler):
    def emit(self, record):
        records.append([record.levelname, record.getMessage()])

logging.getLogger("custom_components.openwrt_router").addHandler(_Keep())
logging.getLogger("custom_components.openwrt_router").setLevel(logging.DEBUG)
import custom_components.openwrt_router as pkg
print(json.dumps({"core": pkg._enterprise_core is None, "records": records}))
"""
)


def _run(code: str) -> Any:
    done = subprocess.run(
        [sys.executable, "-c", code, str(ROOT)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stderr[-2000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_core_modules_are_loaded_by_the_package_import() -> None:
    """After `import custom_components.openwrt_router` every core module is in
    sys.modules, so async_setup_entry never first-imports one on the loop."""
    loaded = set(_run(_LOADED))
    missing = [m for m in CORE_MODULES if f"{PKG}.{m}" not in loaded]
    assert missing == []


def test_init_has_no_function_level_core_import() -> None:
    """No `from .enterprise_core import` inside a function of __init__.py."""
    source = (ROOT / "custom_components/openwrt_router/__init__.py").read_text(
        encoding="utf-8"
    )
    nested = [
        line
        for line in source.splitlines()
        if line.startswith((" ", "\t")) and "from .enterprise_core import" in line
    ]
    assert nested == []


def test_broken_core_import_degrades_with_one_warning() -> None:
    result = _run(_BROKEN)
    assert result["core"] is True  # the package imported, core marked unavailable
    warnings = [
        msg
        for level, msg in result["records"]
        if level == "WARNING" and "Enterprise core unavailable" in msg
    ]
    assert len(warnings) == 1
    assert "RuntimeError" in warnings[0]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def test_unavailable_core_setup_unload_remove_still_work(
    disks: FakeDisks,
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Core unavailable: the real lifecycle succeeds, no hook runs, no noise."""
    hooks = {
        name: AsyncMock()
        for name in (
            "async_setup_entry_core",
            "async_unload_entry_core",
            "async_remove_entry_core",
        )
    }
    monkeypatch.setattr(integration, "_enterprise_core", None)
    with patch.multiple(f"{PKG}.enterprise_core", **hooks):
        before, after, (_hass, listeners) = await _lifecycle_snapshot(disks, tmp_path)
    assert after == before
    assert all(not hook.called for hook in hooks.values())
    assert _core_listeners(listeners) == []
    assert disks[ROUTER_REGISTRY_STORE_KEY].data is None
    assert "Enterprise core" not in caplog.text  # degraded quietly per entry
