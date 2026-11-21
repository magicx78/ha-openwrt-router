"""Archive backups of a plain HTTP entry, runtime -> core -> real provider.

Only the router API is a fake (``FakeApi`` of test_config_provider); the
configuration manager runtime, the enterprise core and the real
``ConfigManagerProvider`` run unchanged. Documented behaviour
(docs/configuration-manager.md, section 9): HTTP plus root SSH (pinned)
gives the archive over SSH; HTTP without root SSH rejects the archive
backup (status ``failed``, reason ``insecure_transport``), never a silent
UCI-only "ok". HTTPS keeps choosing as before.
"""

from __future__ import annotations

from typing import Any

import pytest
from config_manager_kit import attach_entry, cm_env, drain, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_config_provider import FakeApi, methods, router_info

from custom_components.openwrt_router.api import OpenWrtConfigFetchPermissionError
from custom_components.openwrt_router.config_provider import ConfigManagerProvider
from custom_components.openwrt_router.const import (
    CONFIG_STATUS_FAILED,
    CONFIG_STATUS_OK,
)
from custom_components.openwrt_router.core_models import BackupType, VersionStatus


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _env(disks: Any, tmp_path: Any, api: FakeApi) -> Any:
    """One router whose api is ``api``, with the real provider attached."""
    env = await cm_env(disks, tmp_path, provider=ConfigManagerProvider(), attach=False)
    coord = env.coords[env.rid]
    coord.api = api
    coord.router_info = router_info()
    await attach_entry(env, env.entries[0])
    await drain(env.hass)
    return env


async def _records(env: Any) -> list[Any]:
    return list(await env.api.async_list_backups(env.rid, limit=50))


async def test_http_entry_with_root_ssh_takes_the_archive_over_ssh(disks, tmp_path):
    api = FakeApi(secure=False)
    env = await _env(disks, tmp_path, api)
    await env.tick()  # the daily run
    records = await _records(env)
    assert len(records) == 1
    record = records[0]
    assert record.backup_type is BackupType.FULL_ARCHIVE
    assert record.status is VersionStatus.OK
    assert record.fetch_method == "ssh"
    assert "cgi" not in methods(api)
    assert env.runtime.status(env.rid) == CONFIG_STATUS_OK
    await stop(env)


async def test_http_entry_without_root_ssh_fails_with_insecure_transport(
    disks, tmp_path
):
    api = FakeApi(
        secure=False,
        root=False,
        ssh=OpenWrtConfigFetchPermissionError("not root"),
    )
    env = await _env(disks, tmp_path, api)
    await env.tick()  # the daily run
    assert await _records(env) == []  # no silent UCI-only version
    assert env.runtime.status(env.rid) == CONFIG_STATUS_FAILED
    assert env.runtime.error_class(env.rid) == "not_available"
    assert env.runtime.error_reason(env.rid) == "insecure_transport"
    assert "cgi" not in methods(api)
    await stop(env)


async def test_https_entry_with_cgi_backup_keeps_the_cgi_archive(disks, tmp_path):
    api = FakeApi(secure=True)
    env = await _env(disks, tmp_path, api)
    await env.tick()
    [record] = await _records(env)
    assert record.backup_type is BackupType.FULL_ARCHIVE
    assert record.fetch_method == "cgi"
    assert "ssh" not in methods(api)
    await stop(env)


async def test_https_entry_without_cgi_right_takes_the_ssh_archive(disks, tmp_path):
    # PR 59 review R3: SSH as root is not proven by the probe, so the first
    # backup asks for the archive and finds out.
    no_right = OpenWrtConfigFetchPermissionError("no cgi right")
    api = FakeApi(secure=True, access=False, cgi=no_right)
    env = await _env(disks, tmp_path, api)
    await env.tick()
    [record] = await _records(env)
    assert record.backup_type is BackupType.FULL_ARCHIVE
    assert record.status is VersionStatus.OK
    assert record.fetch_method == "ssh"
    await stop(env)


async def test_https_entry_without_any_archive_path_keeps_the_uci_snapshot(
    disks, tmp_path
):
    # Without the cgi right and without root SSH the core's choice is a UCI
    # snapshot; no archive is asked for.
    api = FakeApi(secure=True, access=False, root=False)
    env = await _env(disks, tmp_path, api)
    await env.tick()
    [record] = await _records(env)
    assert record.backup_type is BackupType.UCI_SNAPSHOT
    assert record.status is VersionStatus.OK
    assert "cgi" not in methods(api) and "ssh" not in methods(api)
    await stop(env)
