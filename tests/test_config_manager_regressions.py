"""Regressions of the configuration manager integration (plan 2026-11-18, #20).

What must stay as it was: no router contact with the option off, the
existing unique_ids, no network intelligence coupling, no HTTP in entities,
no raw user id on the bus, no restore execution anywhere, other modules'
incident versions, and the topology routes.
"""

from __future__ import annotations

import ast
import json
import pathlib
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from config_manager_kit import ON, cm_env, drain, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import (
    ADMIN_ID,
    OTHER_ADMIN_ID,
    USER_ID,
    FakeDisks,
    bus_events,
    user_actor,
)

from custom_components.openwrt_router import binary_sensor as binary_sensor_platform
from custom_components.openwrt_router import config_entities as ce
from custom_components.openwrt_router import config_views as cv
from custom_components.openwrt_router import sensor as sensor_platform
from custom_components.openwrt_router import topology_panel
from custom_components.openwrt_router.const import (
    OPTION_CONFIG_DRIFT_CHECK,
)
from custom_components.openwrt_router.core_models import (
    Actor,
    BackupLinks,
    BackupReason,
)

PACKAGE = pathlib.Path(ce.__file__).parent
NEW_MODULES = ("config_manager.py", "config_entities.py", "config_views.py")
RID = "rtr_" + "1" * 32
ADMIN = user_actor(ADMIN_ID)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _tree(name: str) -> ast.Module:
    return ast.parse((PACKAGE / name).read_text(encoding="utf-8"))


def _imports(tree: ast.Module) -> set[str]:
    """Every imported module name (``from .x import y`` -> ``.x``, ``.x.y``)."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = "." * node.level + (node.module or "")
            names.add(base)
            names.update(f"{base}.{alias.name}" for alias in node.names)
    return names


def _attribute_names(tree: ast.Module) -> set[str]:
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    return names


# ---------------------------------------------------------------------------
# static checks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("module", NEW_MODULES)
def test_no_net_imports(module):
    imports = _imports(_tree(module))
    for forbidden in ("net_engine", "net_rules", "net_events"):
        assert not any(forbidden in name for name in imports), (module, forbidden)


@pytest.mark.parametrize("module", NEW_MODULES)
def test_entities_import_no_http(module):
    """No HTTP client, socket or SSH in the new modules: the core and its
    provider make every router call (``api.py`` stays the only network code
    of the integration's own polling)."""
    imports = _imports(_tree(module))
    names = _attribute_names(_tree(module))
    for forbidden in (".api", "aiohttp.ClientSession", "socket", "asyncssh"):
        assert forbidden not in imports, (module, forbidden)
    assert not any(n.startswith(("http.client", "urllib", "requests")) for n in imports)
    for forbidden in ("ClientSession", "async_get_clientsession", "create_connection"):
        assert forbidden not in names, (module, forbidden)
    if module == "config_entities.py":
        assert not any("aiohttp" in n for n in imports)
    if module == "config_views.py":
        # the server side only (web.Response), never a client
        assert {n for n in imports if "aiohttp" in n} <= {"aiohttp", "aiohttp.web"}


def test_coordinator_knows_no_config_manager():
    imports = _imports(_tree("coordinator.py"))
    names = _attribute_names(_tree("coordinator.py"))
    ours = (".config_manager", ".config_entities", ".config_views")
    assert not any(n.startswith(ours) for n in imports)
    assert "SIGNAL_CONFIG_MANAGER" not in names


@pytest.mark.parametrize("module", NEW_MODULES)
def test_no_restore_execution_call(module):
    names = _attribute_names(_tree(module))
    for forbidden in (
        "async_request_restore",
        "async_execute_restore",
        "async_delete_backups",
        "async_request_deletion",
    ):
        assert forbidden not in names, (module, forbidden)


def test_topology_routes_unchanged():
    views = {view.name: view.url for view in topology_panel._api_views()}
    assert views["api:openwrt_topology:snapshot"] == "/api/openwrt_topology/snapshot"
    for name, url in views.items():
        assert not url.startswith(cv.BASE_URL), name
        assert not name.startswith(cv.VIEW_NAME_PREFIX), name
    ours = {view.url for view in cv.CONFIG_VIEWS}
    assert ours.isdisjoint(views.values())
    assert {view.name for view in cv.CONFIG_VIEWS}.isdisjoint(views)


# ---------------------------------------------------------------------------
# entity ids
# ---------------------------------------------------------------------------


async def _unique_ids(entry: Any, router_id: str | None) -> list[str]:
    added: list[Any] = []

    def add(entities: Any, *_: Any, **__: Any) -> None:
        added.extend(entities)

    with patch.object(ce, "config_router_id", return_value=router_id):
        await sensor_platform.async_setup_entry(MagicMock(), entry, add)
        await binary_sensor_platform.async_setup_entry(MagicMock(), entry, add)
    return [e.unique_id for e in added]


async def test_existing_unique_ids_unchanged(mock_config_entry_with_runtime):
    entry = mock_config_entry_with_runtime
    entry.async_on_unload = MagicMock()
    without = await _unique_ids(entry, None)
    with_config = await _unique_ids(entry, RID)
    # the configuration manager only adds; every other id stays as it was
    added = set(with_config) - set(without)
    assert [uid for uid in with_config if uid not in added] == without
    assert added == {f"{RID}_{suffix}" for suffix in ce.CONFIG_ENTITY_SUFFIXES}
    assert len(with_config) == len(set(with_config))
    for description in sensor_platform.SENSOR_DESCRIPTIONS:
        assert f"{entry.entry_id}_{description.key}" in without
    for description in binary_sensor_platform.BINARY_SENSOR_DESCRIPTIONS:
        assert f"{entry.entry_id}_{description.key}" in without
    assert not any(uid.startswith("rtr_") for uid in without)


# ---------------------------------------------------------------------------
# runtime behaviour
# ---------------------------------------------------------------------------


async def test_option_off_zero_router_calls(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=3, options={})
    runtime = env.runtime
    for _ in range(2 * 24 * 12):  # two days of 5-minute ticks
        env.clock.advance(minutes=5)
        await env.tick()
    for rid in env.rids:
        await runtime.async_refresh(rid)
    await drain(env.hass)
    assert env.provider.calls == []
    assert env.router_calls() == []
    assert env.timers.active == []  # no schedule while the option is off
    assert {runtime.status(rid) for rid in env.rids} == {"disabled"}
    await stop(env)


async def test_bus_payloads_have_no_raw_user_id(disks, tmp_path):
    env = await cm_env(
        disks, tmp_path, routers=2, options={**ON, OPTION_CONFIG_DRIFT_CHECK: True}
    )
    runtime = env.runtime
    await runtime.async_backup_now(env.rid, actor=ADMIN, note="by admin")
    await runtime.async_backup_now(
        env.rids[1], actor=user_actor(OTHER_ADMIN_ID), wait=True
    )
    live = env.provider.live(env.rid)
    live["system"] = {**live["system"], "changed": {"x": "1"}}
    report = await runtime.async_check_drift(env.rid, actor=ADMIN)
    assert report.drift_id
    from custom_components.openwrt_router.core_models import DriftAckState

    await env.api.async_acknowledge_drift(
        env.rid, report.drift_id, state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )
    await env.tick()
    await drain(env.hass)
    assert env.hass.fired, "no bus events at all"
    dump = json.dumps([data for _type, data in env.hass.fired], default=str)
    for user_id in (ADMIN_ID, OTHER_ADMIN_ID, USER_ID):
        assert user_id not in dump
    await stop(env)


async def test_foreign_incident_version_fires_despite_drift(disks, tmp_path):
    """A version another module takes for an incident is stored and
    announced although our drift is open and our drift cap is used up; it
    does not count as one of our drift versions."""
    env = await cm_env(disks, tmp_path, options={**ON, OPTION_CONFIG_DRIFT_CHECK: True})
    runtime = env.runtime
    await runtime.async_backup_now(env.rid, actor=ADMIN)
    live = env.provider.live(env.rid)
    live["firewall"] = {**live["firewall"], "changed": {"x": "1"}}
    await runtime.async_check_drift(env.rid, actor=ADMIN)
    state = runtime.routers[env.rid]
    assert state.drift is not None and state.drift["state"] == "open"
    drift_versions = runtime.stats["drift_versions"]
    before = len(bus_events(env.hass, "configuration.backup_created"))

    result = await env.api.async_create_backup(
        env.rid,
        reason=BackupReason.INCIDENT,
        actor=Actor.system("net_engine"),
        links=BackupLinks(incident_id="inc_1"),
    )
    await drain(env.hass)

    assert result.created is True
    assert result.record.reason is BackupReason.INCIDENT
    created = bus_events(env.hass, "configuration.backup_created")[before:]
    assert [e["data"].get("reason") for e in created] == ["incident"]
    assert all(ADMIN_ID not in json.dumps(e, default=str) for e in created)
    assert runtime.stats["drift_versions"] == drift_versions
    assert state.version_count == 2
    await stop(env)


async def test_diagnostics_block_keeps_every_field_readable(disks, tmp_path):
    """Contract #108/#110: no field of our diagnostics block is masked.

    The block now goes through the configuration manager's masker (core
    plus bridge names). Counters, states and timestamps stay readable; the
    salt counter of the module key is a plain number.
    """
    from custom_components.openwrt_router.core_masking import MASK
    from custom_components.openwrt_router.diagnostics import _config_manager_summary

    env = await cm_env(disks, tmp_path)
    runtime = env.runtime
    await runtime.async_backup_now(env.rid, actor=ADMIN, note="weekly check")
    live = env.provider.live(env.rid)
    live["firewall"] = {**live["firewall"], "changed": {"x": "1"}}
    await runtime.async_check_drift(env.rid, actor=ADMIN)
    await runtime.async_route_salt()
    block = _config_manager_summary(env.hass, env.entries[0].entry_id)
    assert MASK not in json.dumps(block, default=str), block
    assert block["stats"]["route_salt_ephemeral"] in (0, 1)
    assert set(block["backup"]) >= {
        "enabled",
        "status",
        "error_class",
        "running",
        "version_count",
        "last_backup_at",
        "last_attempt_at",
        "next_run_at",
        "drift",
    }
    assert block["backup"]["drift"]["critical_count"] == 1
    await stop(env)
