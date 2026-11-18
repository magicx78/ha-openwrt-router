"""Configuration manager entities (plan 2026-11-18, section 6).

Mocks only: core on FakeDisks, FakeConfigProvider, FakeCoordinators whose
api objects must never be called. No Home Assistant instance, no router.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from config_manager_kit import ON, cm_env, drain, macs, restart, stop
from core_test_provider import short_tmp_path  # noqa: F401 - Windows path limit
from core_testkit import ADMIN_ID, FakeDisks, make_hass, router_data, user_actor
from homeassistant.components.sensor import SensorDeviceClass

from custom_components.openwrt_router import config_entities as ce
from custom_components.openwrt_router.const import (
    CONFIG_BACKUP_SCHEDULE_OFF,
    CONFIG_BACKUP_STATUSES,
    DOMAIN,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    SIGNAL_CONFIG_MANAGER,
)
from custom_components.openwrt_router.core_errors import RouterUnavailableError
from custom_components.openwrt_router.core_models import DriftAckState

ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
ADMIN = user_actor(ADMIN_ID)
NO_SCHEDULE = {**ON, OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_OFF}


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _entities(env, index=0):
    """The four entities of one router, bound to the test hass."""
    added: list = []
    entry = env.entries[index]
    ce.async_setup_config_sensors(env.hass, entry, added.extend)
    ce.async_setup_config_binary_sensors(env.hass, entry, added.extend)
    for entity in added:
        entity.hass = env.hass
    by_key = {entity.translation_key: entity for entity in added}
    return (
        by_key["config_last_backup"],
        by_key["config_backup_status"],
        by_key["config_versions"],
        by_key["config_drift"],
    )


async def test_unique_id_schema_and_device(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    for index, entry in enumerate(env.entries):
        entities = _entities(env, index)
        rid = env.rids[index]
        assert [e.unique_id for e in entities] == [
            f"{rid}_config_last_backup",
            f"{rid}_config_backup_status",
            f"{rid}_config_versions",
            f"{rid}_config_drift",
        ]
        for entity in entities:
            assert entity.has_entity_name is True
            assert entity.should_poll is False
            assert entity.device_info["identifiers"] == {(DOMAIN, entry.entry_id)}
    last, status, versions, drift = _entities(env)
    assert last.device_class == SensorDeviceClass.TIMESTAMP
    assert status.device_class == SensorDeviceClass.ENUM
    assert status.options == list(CONFIG_BACKUP_STATUSES)
    assert versions.entity_category == "diagnostic"
    assert drift.device_class == "problem"
    await stop(env)


async def test_entities_created_with_option_off_show_disabled(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options={})
    last, status, versions, drift = _entities(env)
    assert status.native_value == "disabled"
    assert status.extra_state_attributes["next_run_at"] is None
    assert last.native_value is None and versions.native_value == 0
    assert drift.is_on is None
    assert env.provider.calls == [] and env.router_calls() == []
    await stop(env)


async def test_states_never_then_ok(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    last, status, versions, _drift = _entities(env)
    assert status.native_value == "never"
    made = await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    assert status.native_value == "ok"
    assert last.native_value == made.record.created_at
    assert versions.native_value == 1
    attrs = status.extra_state_attributes
    assert attrs["error_class"] is None
    assert attrs["last_attempt_at"] is not None
    assert attrs["next_run_at"] is None  # schedule off
    await stop(env)


async def test_status_running_and_failed(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    _last, status, _versions, _drift = _entities(env)
    assert status.extra_state_attributes["next_run_at"] is not None
    gate = env.provider.gates["collect"] = asyncio.Event()
    env.runtime.async_tick()
    entered = env.provider.entered.setdefault("collect", asyncio.Event())
    await asyncio.wait_for(entered.wait(), 5)
    assert status.native_value == "running"
    env.provider.fail["collect"] = RouterUnavailableError("offline")
    gate.set()
    await drain(env.hass)
    assert status.native_value == "failed"
    assert status.extra_state_attributes["error_class"] == "unreachable"
    await stop(env)


async def test_dispatcher_updates_only_the_own_router(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2)
    _last, status, _versions, _drift = _entities(env)
    connected = {}

    def fake_connect(hass, signal, target):
        connected[signal] = target
        return lambda: None

    status.async_write_ha_state = MagicMock()
    status.async_on_remove = MagicMock()
    with patch.object(ce, "async_dispatcher_connect", fake_connect):
        await status.async_added_to_hass()
    assert connected[SIGNAL_CONFIG_MANAGER] == status._handle_update
    status._handle_update(env.rids[1])
    status.async_write_ha_state.assert_not_called()
    status._handle_update(env.rids[0])
    status.async_write_ha_state.assert_called_once()
    await stop(env)


async def test_drift_state_from_events_after_restart(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    env.provider.live(env.rid)["network"]["lan"]["ipaddr"] = "10.9.9.1"
    report = await env.runtime.async_check_drift(env.rid, actor=ADMIN)
    assert report.drifted
    env = await restart(env)
    *_rest, drift = _entities(env)
    assert drift.is_on is True  # rebuilt from api.events (plan L7)
    attrs = drift.extra_state_attributes
    assert attrs["drift_id"] == report.drift_id
    assert attrs["checked_at"] is not None
    await env.api.async_acknowledge_drift(
        env.rid, report.drift_id, state=DriftAckState.ACKNOWLEDGED, actor=ADMIN
    )
    await drain(env.hass)
    assert drift.is_on is False
    env = await restart(env)
    *_rest, drift = _entities(env)
    assert drift.is_on is False  # the acknowledgement survives a restart
    await stop(env)


async def test_unavailable_without_runtime(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    last, status, versions, drift = _entities(env)
    await stop(env)
    assert not last.available and not versions.available and not drift.available
    assert not status.available
    assert status.native_value == "disabled"
    assert status.extra_state_attributes["error_class"] is None


def test_no_entities_without_a_router_id():
    hass = make_hass()
    added: list = []
    entry = MagicMock(entry_id="e1")
    ce.async_setup_config_sensors(hass, entry, added.extend)
    ce.async_setup_config_binary_sensors(hass, entry, added.extend)
    assert added == []


async def test_drift_clear_after_a_clean_check(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    *_rest, drift = _entities(env)
    assert drift.is_on is None
    await env.runtime.async_check_drift(env.rid, actor=ADMIN)
    assert drift.is_on is False
    env.coords[env.rid].poll(data=router_data(hostname="r1", macs=macs(0)))
    assert drift.is_on is False  # a poll alone never changes the state
    await stop(env)


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_entity_translations(name):
    data = json.loads((ROOT / name).read_text(encoding="utf-8"))
    sensors = data["entity"]["sensor"]
    for key in ("config_last_backup", "config_backup_status", "config_versions"):
        assert sensors[key]["name"], key
    states = sensors["config_backup_status"]["state"]
    assert set(states) == set(CONFIG_BACKUP_STATUSES)
    assert data["entity"]["binary_sensor"]["config_drift"]["name"]


def test_entities_import_no_http():
    source = (ROOT / "config_entities.py").read_text(encoding="utf-8")
    for forbidden in ("aiohttp", "async_get_clientsession", "import requests"):
        assert forbidden not in source
    assert ce.CONFIG_ENTITY_SUFFIXES == (
        "config_last_backup",
        "config_backup_status",
        "config_versions",
        "config_drift",
    )


NEW_RID = "rtr_" + "a" * 32


async def test_adoption_moves_unique_ids_and_keeps_entity_ids():
    from test_net_entities import loaded_registry

    hass = MagicMock()
    hass.data = {}
    registry = await loaded_registry(hass)
    old_rid = "rtr_" + "b" * 32
    before = {
        suffix: registry.async_get_or_create(
            platform, DOMAIN, f"{old_rid}_{suffix}"
        ).entity_id
        for suffix, platform in ce._SUFFIX_PLATFORMS.items()
    }
    taken = registry.async_get_or_create("sensor", DOMAIN, f"{NEW_RID}_config_versions")
    with patch.object(ce.er, "async_get", return_value=registry):
        assert ce.async_migrate_config_unique_ids(hass, old_rid, NEW_RID) == 3
        assert ce.async_migrate_config_unique_ids(hass, old_rid, NEW_RID) == 0
        assert ce.async_migrate_config_unique_ids(hass, NEW_RID, NEW_RID) == 0
    for suffix, entity_id in before.items():
        entry = registry.async_get(entity_id)
        if suffix == "config_versions":  # new id taken: both left alone
            assert entry.unique_id == f"{old_rid}_{suffix}"
        else:
            assert entry.unique_id == f"{NEW_RID}_{suffix}"
    assert registry.async_get(taken.entity_id).unique_id == taken.unique_id


async def test_entities_follow_the_entry_after_an_adoption(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    last, status, versions, drift = _entities(env)
    await env.runtime.async_backup_now(env.rid, actor=ADMIN)
    assert versions.native_value == 1
    migrate = MagicMock(return_value=4)
    with (
        patch.object(env.runtime, "_router_id_of", return_value=NEW_RID),
        patch.object(ce, "async_migrate_config_unique_ids", migrate),
    ):
        env.runtime._rebind(env.entries[0].entry_id)
        await drain(env.hass)
    migrate.assert_called_once_with(env.hass, env.rid, NEW_RID)
    assert env.rid not in env.runtime.routers
    assert status._rid == NEW_RID and status.available
    assert versions.native_value == 0  # the adopted router has no versions here
    assert last.native_value is None and drift.is_on is None
    status.async_write_ha_state = MagicMock()
    status._handle_update(NEW_RID)
    status.async_write_ha_state.assert_called_once()
    assert env.router_calls() == []
    await stop(env)
