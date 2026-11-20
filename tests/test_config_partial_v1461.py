"""Regressions of 1.46.1: routers shown "incomplete" although they can do better.

End to end where it matters: runtime -> core -> real ``ConfigManagerProvider``,
only the router API is a fake (``FakeApi`` of test_config_provider, template
test_config_http_archive). All names, hosts and keys are invented.
"""

from __future__ import annotations

from dataclasses import replace
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
    make_conn,
    make_ctx,
    methods,
    router_info,
    router_record,
    ubus_values,
)
from test_config_views import backup, http

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConfigFetchHostKeyError,
    OpenWrtConfigFetchIncompleteError,
    OpenWrtConfigFetchNotAvailableError,
    OpenWrtConfigFetchPermissionError,
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtMethodNotFoundError,
    OpenWrtTimeoutError,
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


# -- point 2: a run without an archive path says why -------------------------


async def test_uci_only_run_names_the_cause_per_archive_path() -> None:
    provider = ConfigManagerProvider()
    api = FakeApi(access=False, root=False)
    await provider.async_probe(make_conn(api), make_ctx())
    record = router_record()
    assert provider.default_backup_type(record) is BackupType.UCI_SNAPSHOT
    version = await collect(api, provider=provider, backup_type=BackupType.UCI_SNAPSHOT)
    warnings = version.meta.warnings
    assert "archive_not_attempted:cgi.permission" in warnings
    assert "archive_not_attempted:ssh.permission" in warnings


async def test_unprobed_router_says_not_probed_per_path() -> None:
    version = await collect(FakeApi(), backup_type=BackupType.UCI_SNAPSHOT)
    warnings = version.meta.warnings
    assert "archive_not_attempted:cgi.not_probed" in warnings
    assert "archive_not_attempted:ssh.not_probed" in warnings


async def test_requested_snapshot_with_an_archive_path_says_requested() -> None:
    provider = ConfigManagerProvider()
    api = FakeApi()
    await provider.async_probe(make_conn(api), make_ctx())
    version = await collect(api, provider=provider, backup_type=BackupType.UCI_SNAPSHOT)
    assert "archive_not_attempted:requested" in version.meta.warnings


async def test_partial_run_without_archive_path_end_to_end(disks, tmp_path):
    # The field case after point 1 and 3: rpcd gives no clear answer on the
    # cgi right, the rpcd config is denied, the SSH pin is pending.
    uci = {**ubus_values(), "rpcd": OpenWrtConfigFetchHostKeyError("pin_pending", "x")}
    api = FakeApi(secure=True, root=True, packages=None, access=None, uci=uci)
    env = await _env(disks, tmp_path, api)
    await env.tick()
    [record] = await _records(env)
    assert record.status is VersionStatus.PARTIAL
    assert record.fetch_method == "uci"
    assert "archive_not_attempted:cgi.not_probed" in record.warnings
    assert "archive_not_attempted:ssh.not_probed" in record.warnings
    await stop(env)


# -- point 4: the host-key reason is a fixed code, not a secret ---------------


def _with_warnings(*codes: str) -> Any:
    def hook(collected: Any) -> Any:
        meta = replace(collected.meta, warnings=(*collected.meta.warnings, *codes))
        return replace(collected, meta=meta)

    return hook


async def test_host_key_reason_reaches_the_panel_unmasked(disks, tmp_path):
    env = await cm_env(disks, tmp_path)
    env.provider.collect_hook = _with_warnings(
        "ssh_host_key:pin_pending", "ssh_host_key:a1b2c3d4e5f6"
    )
    async with http(env.hass) as h:
        made = await backup(h, env.rid)
        assert "ssh_host_key:pin_pending" in made["version"]["warnings"]
        one = (await h.get(f"/versions/{made['backup_id']}")).data
        listed = (await h.get(f"/routers/{env.rid}/versions")).data["versions"][0]
        for warnings in (one["warnings"], listed["warnings"]):
            assert "ssh_host_key:pin_pending" in warnings
            # Anything outside the fixed reason codes stays masked.
            assert "ssh_host_key:a1b2c3d4e5f6" not in warnings
            assert "ssh_host_key:**REDACTED**" in warnings
    await stop(env)


# -- point 8: the SSH host-key pin store is strictly per router ID -----------


async def _ssh_run(env: Any, rid: str, router: Any) -> Any:
    from test_ssh_hostkey_pinning import _patched

    ctx = env.manager._context()
    with _patched(router):
        return await ctx.async_ssh_run_pinned(rid, "uci show", timeout=5)


async def test_ssh_pin_store_keeps_each_router_apart(disks, tmp_path):
    # Two routers on the SAME (invented) host string with different keys:
    # the pin follows the router ID, never the host or another router.
    from core_test_provider import approve_as, restart, start_env, stop_env
    from core_testkit import ADMIN_ID, OTHER_ADMIN_ID, user_actor
    from test_ssh_hostkey_pinning import KEY_A, KEY_B, FakeRouter
    from test_ssh_hostkey_pinning import _api as ssh_api

    from custom_components.openwrt_router.api import OpenWrtHostKeyMismatchError

    env = await start_env(disks, tmp_path, routers=2)
    rid_a, rid_b = env.rids
    for rid in env.rids:
        env.coords[rid].api = ssh_api()
    fp_a, fp_b = (k.get_fingerprint("sha256") for k in (KEY_A, KEY_B))

    for rid, key in ((rid_a, KEY_A), (rid_b, KEY_B)):
        with pytest.raises(OpenWrtHostKeyError) as err:
            await _ssh_run(env, rid, FakeRouter(key))
        assert err.value.reason == "pin_pending"
    assert env.api.ssh_pin_status(rid_a)["pending_fingerprint"] == fp_a
    assert env.api.ssh_pin_status(rid_b)["pending_fingerprint"] == fp_b

    # Confirming A pins A only; B stays pending with its own key.
    approval = await env.api.async_request_ssh_pin_confirm(
        rid_a, actor=user_actor(ADMIN_ID)
    )
    await approve_as(env, approval.approval_id, OTHER_ADMIN_ID)
    await env.api.async_confirm_ssh_pin(
        approval.approval_id, actor=user_actor(ADMIN_ID)
    )
    assert env.api.ssh_pin_status(rid_a)["state"] == "pinned"
    assert env.api.ssh_pin_status(rid_a)["fingerprint"] == fp_a
    assert env.api.ssh_pin_status(rid_b)["state"] == "pending"
    assert env.api.ssh_pin_status(rid_b)["fingerprint"] is None

    # A runs with its key; A's pin is no pass for B, B's key no pass for A.
    assert (await _ssh_run(env, rid_a, FakeRouter(KEY_A))).pinned_now is False
    with pytest.raises(OpenWrtHostKeyError) as err:
        await _ssh_run(env, rid_b, FakeRouter(KEY_A))
    assert err.value.reason in ("pin_pending", "mismatch")
    with pytest.raises(OpenWrtHostKeyMismatchError):
        await _ssh_run(env, rid_a, FakeRouter(KEY_B))
    assert env.api.ssh_pin_status(rid_b)["pending_fingerprint"] == fp_b

    # Still apart after a restart (one store, one entry per router ID).
    env = await restart(env)
    assert env.api.ssh_pin_status(rid_a)["fingerprint"] == fp_a
    assert env.api.ssh_pin_status(rid_b)["state"] == "pending"
    assert env.api.ssh_pin_status(rid_b)["pending_fingerprint"] == fp_b
    await stop_env(env)


# == Review follow-up (PR 59) ===============================================

# -- R4: rpcd's "not found" stands; no SSH attempt can overwrite it -----------


def _runner(error: Exception) -> Any:
    """Pinned SSH runner that records its calls and fails with ``error``."""
    calls: list[str] = []

    async def run(cmd: str, *_args: Any) -> Any:
        calls.append(cmd)
        raise error

    run.calls = calls  # type: ignore[attr-defined]
    return run


_SSH_FAILURES = [
    OpenWrtAuthError("login refused"),
    OpenWrtConnectionError("port closed"),
    OpenWrtTimeoutError("no answer"),
    OpenWrtHostKeyError("pin_pending", "first-seen key"),
]


@pytest.mark.parametrize("error", _SSH_FAILURES, ids=type)
async def test_not_found_config_never_tries_ssh(error: Exception) -> None:
    api, _ = make_api()
    _ubus(api, existing={}, acl_denied=set())
    ssh = _runner(error)
    with pytest.raises(OpenWrtConfigFetchNotAvailableError):
        await api.config_uci_get("sqm", ssh=ssh)
    assert ssh.calls == []


async def test_acl_denied_config_with_refused_ssh_login_stays_an_error() -> None:
    api, _ = make_api()
    _ubus(api, existing={}, acl_denied={"rpcd"})
    ssh = _runner(OpenWrtAuthError("login refused"))
    with pytest.raises(OpenWrtConfigFetchPermissionError):
        await api.config_uci_get("rpcd", ssh=ssh)
    assert ssh.calls == ["uci show rpcd"]


# -- R1: network and system must exist; other absent configs are fine ---------


def _snapshot_run(**absent: Exception) -> Any:
    uci = {**ubus_values(), "rpcd": {}, **absent}
    api = FakeApi(uci=uci, cgi=OpenWrtConfigFetchPermissionError("no right"))
    api.ssh = OpenWrtConfigFetchPermissionError("no ssh")
    return collect(api)


@pytest.mark.parametrize("name", ["network", "system"])
async def test_absent_required_config_makes_the_run_incomplete(name: str) -> None:
    gone = OpenWrtConfigFetchNotAvailableError(f"uci get {name}: absent")
    meta = (await _snapshot_run(**{name: gone})).meta
    assert meta.status is VersionStatus.PARTIAL
    assert meta.error_class is not None and meta.error_class.value == "incomplete"
    assert f"uci_missing:{name}" in meta.warnings


async def test_access_point_without_firewall_dhcp_wireless_stays_ok() -> None:
    # A wired-only access point may lack all three packages' configs.
    absent = {
        name: OpenWrtConfigFetchNotAvailableError(f"uci get {name}: absent")
        for name in ("firewall", "dhcp", "wireless")
    }
    meta = (await _snapshot_run(**absent)).meta
    assert meta.backup_type is BackupType.UCI_SNAPSHOT
    assert meta.status is VersionStatus.OK
