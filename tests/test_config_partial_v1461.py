"""Regressions of 1.46.1: routers shown "incomplete" although they can do better.

End to end where it matters: runtime -> core -> real ``ConfigManagerProvider``,
only the router API is a fake (``FakeApi`` of test_config_provider, template
test_config_http_archive). All names, hosts and keys are invented.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest
from config_manager_kit import attach_entry, cm_env, drain, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks
from test_config_fetch_api import make_api
from test_config_provider import (
    FakeApi,
    collect,
    every_config,
    methods,
    router_info,
    ubus_values,
)

from custom_components.openwrt_router.api import (
    OpenWrtConfigFetchHostKeyError,
    OpenWrtConfigFetchIncompleteError,
    OpenWrtConfigFetchNotAvailableError,
    OpenWrtConfigFetchPermissionError,
    OpenWrtHostKeyError,
    OpenWrtMethodNotFoundError,
)
from custom_components.openwrt_router.config_collector import (
    PinnedApi,
    PinnedSsh,
    collect_uci,
)
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


# -- point 3: a config that does not exist is not a read error ---------------

OPTIONAL = ("sqm", "mwan3", "upnpd", "openvpn", "usteer")


def _ubus(api: Any, *, existing: dict[str, Any], acl_denied: set[str]) -> None:
    """``_call`` like rpcd behind api.py: values, ACL block or not found.

    An ACL denial lands in ``_acl_blocked`` exactly like ``OpenWrtAPI._call``
    does after its re-login; a config the router does not have answers
    UBUS_STATUS_NOT_FOUND, which ``_raw_call`` turns into the same exception
    class without touching ``_acl_blocked``.
    """

    async def call(obj: str, method: str, params: dict[str, Any]) -> Any:
        name = params["config"]
        if name in acl_denied:
            api._acl_blocked.add(api._acl_cache_key(obj, method, params))
            raise OpenWrtMethodNotFoundError(f"rpcd ACL blocks {obj}/{method}/{name}")
        if name in existing:
            return {"values": existing[name]}
        raise OpenWrtMethodNotFoundError(f"ubus object or method not found: {obj}")

    api._call = AsyncMock(side_effect=call)  # type: ignore[method-assign]


async def _pin_pending(*_args: Any) -> Any:
    raise OpenWrtHostKeyError("pin_pending", "first-seen key awaits confirmation")


async def test_missing_config_with_pending_pin_is_not_available() -> None:
    api, _ = make_api()
    _ubus(api, existing={}, acl_denied=set())
    with pytest.raises(OpenWrtConfigFetchNotAvailableError):
        await api.config_uci_get("sqm", ssh=_pin_pending)


async def test_acl_denied_config_with_pending_pin_stays_denied() -> None:
    # A missing right is a real read error: never softened to "absent".
    api, _ = make_api()
    _ubus(api, existing={}, acl_denied={"rpcd"})
    with pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
        await api.config_uci_get("rpcd", ssh=_pin_pending)
    assert exc.value.error_class == "denied"


async def test_missing_config_without_any_runner_is_not_available() -> None:
    api, _ = make_api()
    _ubus(api, existing={}, acl_denied=set())
    with pytest.raises(OpenWrtConfigFetchNotAvailableError):
        await api.config_uci_get("mwan3")


class _PendingCtx:
    """The core's pinned path while the host key awaits confirmation."""

    async def async_ssh_run_pinned(self, *_args: Any, **_kwargs: Any) -> Any:
        raise OpenWrtHostKeyError("pin_pending", "first-seen key awaits confirmation")


async def test_collector_reads_absent_configs_as_not_available() -> None:
    # The observed router: core configs readable, optional packages absent,
    # rpcd denied by the ACL, SSH pin pending.
    api, _ = make_api()
    present = ubus_values()
    _ubus(api, existing=present, acl_denied={"rpcd"})
    pinned = PinnedApi(api, PinnedSsh(_PendingCtx(), "rtr_" + "c" * 32))
    fetch = await collect_uci(pinned, (*present, "rpcd", *OPTIONAL))
    failed = dict(fetch.failed)
    assert {name: failed[name] for name in OPTIONAL} == dict.fromkeys(
        OPTIONAL, "not_available"
    )
    assert failed["rpcd"] == "denied"
    assert pinned.ssh.refused == "pin_pending"


async def test_absent_optional_configs_do_not_make_a_version_partial() -> None:
    uci = {**ubus_values(), "rpcd": {}}
    for name in OPTIONAL:
        uci[name] = OpenWrtConfigFetchNotAvailableError(f"uci get {name}: absent")
    api = FakeApi(uci=uci, cgi=OpenWrtConfigFetchPermissionError("no right"))
    api.ssh = OpenWrtConfigFetchPermissionError("no ssh")
    version = await collect(api)
    meta = version.meta
    assert meta.backup_type is BackupType.UCI_SNAPSHOT
    assert meta.status is VersionStatus.OK
    assert not [w for w in meta.warnings if w.startswith("uci_failed:")]


@pytest.mark.parametrize(
    "error",
    [
        OpenWrtConfigFetchIncompleteError("cut off"),
        OpenWrtConfigFetchPermissionError("denied"),
        OpenWrtConfigFetchHostKeyError("pin_pending", "refused"),
    ],
)
async def test_unknown_read_outcome_stays_a_failure(error: Exception) -> None:
    # Only "config does not exist" is softened; anything unclear stays partial.
    uci = {**ubus_values(), **every_config(OpenWrtConfigFetchNotAvailableError("x"))}
    uci.update(ubus_values())
    uci["sqm"] = error
    api = FakeApi(uci=uci, cgi=OpenWrtConfigFetchPermissionError("no right"))
    api.ssh = OpenWrtConfigFetchPermissionError("no ssh")
    version = await collect(api)
    assert version.meta.status is VersionStatus.PARTIAL
    assert "uci_failed:sqm" in version.meta.warnings
