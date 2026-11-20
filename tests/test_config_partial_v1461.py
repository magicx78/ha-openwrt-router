"""Regressions of 1.46.1: routers shown "incomplete" although they can do better.

End to end where it matters: runtime -> core -> real ``ConfigManagerProvider``,
only the router API is a fake (``FakeApi`` of test_config_provider, template
test_config_http_archive). All names, hosts and keys are invented.
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

from custom_components.openwrt_router.config_provider import ConfigManagerProvider
from custom_components.openwrt_router.const import CONFIG_STATUS_OK
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


# -- point 1: the archive path does not hang on the package list -------------


async def test_https_root_without_package_list_takes_the_cgi_archive(disks, tmp_path):
    # HTTPS, root, rpc-sys package list unreadable, cgi-io backup right held:
    # the run must ask for the archive and get it over cgi.
    api = FakeApi(secure=True, root=True, packages=None, access=True)
    env = await _env(disks, tmp_path, api)
    await env.tick()  # the daily run
    [record] = await _records(env)
    assert record.backup_type is BackupType.FULL_ARCHIVE
    assert record.status is VersionStatus.OK
    assert record.fetch_method == "cgi"
    assert "cgi" in methods(api)
    assert env.runtime.status(env.rid) == CONFIG_STATUS_OK
    await stop(env)
