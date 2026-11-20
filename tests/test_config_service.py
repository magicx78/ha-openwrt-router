"""Action openwrt_router.create_config_backup (plan 2026-11-18, section 4).

Mocks only: the enterprise core runs on FakeDisks, the provider is the
in-memory FakeConfigProvider, devices come from a small fake device
registry. No Home Assistant instance, no router.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import voluptuous as vol
import yaml
from config_manager_kit import ON, cm_env, stop
from core_test_provider import short_tmp_path  # noqa: F401 - Windows path limit
from core_testkit import ADMIN_ID, USER_ID, FakeDisks
from homeassistant.core import Context, ServiceCall, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import device_registry as dr

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import config_manager as cm
from custom_components.openwrt_router.const import (
    CONFIG_BACKUP_SCHEDULE_OFF,
    DOMAIN,
    OPTION_CONFIG_BACKUP_SCHEDULE,
    SERVICE_CREATE_CONFIG_BACKUP,
)
from custom_components.openwrt_router.core_errors import RouterUnavailableError
from custom_components.openwrt_router.core_models import BackupReason

ROOT = Path(__file__).resolve().parent.parent / "custom_components" / "openwrt_router"
NO_SCHEDULE = {**ON, OPTION_CONFIG_BACKUP_SCHEDULE: CONFIG_BACKUP_SCHEDULE_OFF}
EXCEPTION_KEYS = (
    "config_backup_unknown_device",
    "config_backup_disabled",
    "config_backup_not_ready",
    "config_backup_denied",
    "config_backup_failed",
    "config_backup_invalid_note",
)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _devices(env) -> dict[str, str]:
    """One router device per entry (identifier (DOMAIN, entry_id)), plus a
    device of another integration."""
    devices = {
        f"dev-{entry.entry_id}": SimpleNamespace(
            id=f"dev-{entry.entry_id}",
            identifiers={(DOMAIN, entry.entry_id)},
            name=f"Router {entry.entry_id}",
            name_by_user=None,
        )
        for entry in env.entries
    }
    devices["dev-foreign"] = SimpleNamespace(
        id="dev-foreign",
        identifiers={("hue", "bridge-1")},
        name="Hue",
        name_by_user=None,
    )
    env.hass.data[dr.DATA_REGISTRY].async_get = devices.get
    return {entry.entry_id: f"dev-{entry.entry_id}" for entry in env.entries}


async def _call(env, data, *, context=None, return_response=True):
    call = ServiceCall(
        env.hass,
        DOMAIN,
        SERVICE_CREATE_CONFIG_BACKUP,
        cm.SERVICE_CREATE_CONFIG_BACKUP_SCHEMA(data),
        context or Context(user_id=ADMIN_ID),
        return_response,
    )
    return await cm.async_handle_create_config_backup(env.hass, call)


def _collected(env):
    return [rid for _op, rid in env.provider.ops("collect")]


async def test_admin_creates_one_version_per_router(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2, options=NO_SCHEDULE)
    dev = _devices(env)
    response = await _call(
        env, {"device_id": [dev["e2"], dev["e1"]], "note": "before VLAN"}
    )
    results = response["results"]
    assert [r["router_id"] for r in results] == [env.rids[1], env.rids[0]]
    assert all(r["created"] is True and r["status"] == "ok" for r in results)
    assert all(r["error_class"] is None for r in results)
    assert all(r["backup_id"].startswith("bkp_") for r in results)
    assert _collected(env) == [env.rids[1], env.rids[0]]  # one after another
    assert env.provider.max_active == 1
    record = await env.api.async_get_backup(results[0]["backup_id"])
    assert record.reason is BackupReason.MANUAL and record.note == "before VLAN"
    assert env.router_calls() == []
    await stop(env)


async def test_single_device_id_string_is_accepted(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    response = await _call(env, {"device_id": dev["e1"]})
    assert len(response["results"]) == 1
    await stop(env)


async def test_no_response_unless_requested(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    assert await _call(env, {"device_id": [dev["e1"]]}, return_response=False) is None
    assert len(_collected(env)) == 1
    await stop(env)


async def test_non_admin_is_denied(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    with pytest.raises(ServiceValidationError) as err:
        await _call(env, {"device_id": [dev["e1"]]}, context=Context(user_id=USER_ID))
    assert err.value.translation_key == "config_backup_denied"
    assert _collected(env) == []
    await stop(env)


async def test_automation_is_allowed(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    response = await _call(
        env, {"device_id": [dev["e1"]]}, context=Context(parent_id="01AUTOMATION")
    )
    assert response["results"][0]["created"] is True
    await stop(env)


async def test_option_off_rejected_before_any_run(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2, options=NO_SCHEDULE)
    env.entries[1].options = {}
    dev = _devices(env)
    with pytest.raises(ServiceValidationError) as err:
        await _call(env, {"device_id": [dev["e1"], dev["e2"]]})
    assert err.value.translation_key == "config_backup_disabled"
    assert err.value.translation_placeholders == {"router": "Router e2"}
    assert _collected(env) == []  # validated first, nothing ran
    await stop(env)


@pytest.mark.parametrize("device_id", ["dev-unknown", "dev-foreign"])
async def test_unknown_device(disks, tmp_path, device_id):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    with pytest.raises(ServiceValidationError) as err:
        await _call(env, {"device_id": [dev["e1"], device_id]})
    assert err.value.translation_key == "config_backup_unknown_device"
    assert err.value.translation_placeholders == {"device_id": device_id}
    assert _collected(env) == []
    await stop(env)


@pytest.mark.parametrize("note", ["x" * 201, "line\nbreak", "nul\x00"])
async def test_invalid_note_rejected(disks, tmp_path, note):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    dev = _devices(env)
    with pytest.raises(ServiceValidationError) as err:
        await _call(env, {"device_id": [dev["e1"]], "note": note})
    assert err.value.translation_key == "config_backup_invalid_note"
    assert _collected(env) == []
    await stop(env)


async def test_not_ready_without_runtime(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE, attach=False)
    dev = _devices(env)
    with pytest.raises(ServiceValidationError) as err:
        await _call(env, {"device_id": [dev["e1"]]})
    assert err.value.translation_key == "config_backup_not_ready"
    await stop(env)


async def test_partial_failure_reported_per_router(disks, tmp_path):
    env = await cm_env(disks, tmp_path, routers=2, options=NO_SCHEDULE)
    env.provider.declined.add(env.rids[1])
    env.core.registry.invalidate_capabilities()
    dev = _devices(env)
    response = await _call(env, {"device_id": [dev["e1"], dev["e2"]]})
    ok, failed = response["results"]
    assert ok["created"] is True
    assert failed == {
        "router_id": env.rids[1],
        "backup_id": None,
        "created": False,
        "status": "failed",
        "error_class": "not_available",
    }
    await stop(env)


async def test_failure_of_every_router_raises(disks, tmp_path):
    env = await cm_env(disks, tmp_path, options=NO_SCHEDULE)
    env.provider.fail["collect"] = RouterUnavailableError("offline")
    dev = _devices(env)
    with pytest.raises(HomeAssistantError) as err:
        await _call(env, {"device_id": [dev["e1"]]})
    assert not isinstance(err.value, ServiceValidationError)
    assert err.value.translation_key == "config_backup_failed"
    assert err.value.translation_placeholders == {"error_class": "unreachable"}
    await stop(env)


def test_schema_rejects_unknown_keys_and_missing_device():
    with pytest.raises(vol.Invalid):
        cm.SERVICE_CREATE_CONFIG_BACKUP_SCHEMA({"note": "x"})
    with pytest.raises(vol.Invalid):
        cm.SERVICE_CREATE_CONFIG_BACKUP_SCHEMA({"device_id": ["d"], "force": True})


def test_registered_once_with_optional_response():
    hass = MagicMock()
    hass.services.has_service = MagicMock(return_value=False)
    cm.async_register_services(hass)
    args, kwargs = hass.services.async_register.call_args
    assert args[:2] == (DOMAIN, SERVICE_CREATE_CONFIG_BACKUP)
    assert kwargs["supports_response"] is SupportsResponse.OPTIONAL
    assert kwargs["schema"] is cm.SERVICE_CREATE_CONFIG_BACKUP_SCHEMA
    hass.services.has_service = MagicMock(return_value=True)
    cm.async_register_services(hass)
    assert hass.services.async_register.call_count == 1


async def test_async_setup_registers_the_action():
    hass = MagicMock()
    hass.services.has_service = MagicMock(return_value=False)
    assert await integration.async_setup(hass, {}) is True
    assert hass.services.async_register.call_count == 1
    assert integration.CONFIG_SCHEMA is not None


def test_services_yaml_matches_the_schema():
    services = yaml.safe_load((ROOT / "services.yaml").read_text(encoding="utf-8"))
    fields = services[SERVICE_CREATE_CONFIG_BACKUP]["fields"]
    assert set(fields) == {"device_id", "note"}
    assert fields["device_id"]["required"] is True
    device = fields["device_id"]["selector"]["device"]
    assert device == {"integration": DOMAIN, "multiple": True}
    assert fields["note"]["required"] is False


@pytest.mark.parametrize(
    "name", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_action_and_errors_translated(name):
    data = json.loads((ROOT / name).read_text(encoding="utf-8"))
    action = data["services"][SERVICE_CREATE_CONFIG_BACKUP]
    assert action["name"] and action["description"]
    assert set(action["fields"]) == {"device_id", "note"}
    for key in EXCEPTION_KEYS:
        assert data["exceptions"][key]["message"], key
    assert (
        "{device_id}" in data["exceptions"]["config_backup_unknown_device"]["message"]
    )
    assert "{router}" in data["exceptions"]["config_backup_disabled"]["message"]
    assert "{error_class}" in data["exceptions"]["config_backup_failed"]["message"]
