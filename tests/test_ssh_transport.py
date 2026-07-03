"""test_ssh_transport.py — asyncssh SSH-fallback transport (v1.22.0).

Replaces test_sshpass_security_v1179.py: the transport moved from
sshpass/subprocess to in-process asyncssh. These tests pin the contracts the
rest of api.py / acl_provisioning.py rely on:

  * the password is only ever an asyncssh connect() kwarg (never in a command)
  * connect() parity: known_hosts=None, connect_timeout, no ssh-port confusion
  * PermissionDenied → key-auth retry (password=None) → rc 255 when still denied
  * _run_ssh returns None on empty stdout even at exit 0 (ACL-deploy marker)
  * partial stdout survives a non-zero exit
  * binary passthrough keeps NUL bytes
  * timeout → sentinel; connection errors → spawn sentinel
  * _run_ssh_detached still wraps with nohup + </dev/null, single-quote safe
"""

from __future__ import annotations

import asyncio
import shlex
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest

from custom_components.openwrt_router.api import (
    SSH_CONNECT_TIMEOUT,
    SUBPROCESS_RC_FAILED_TO_SPAWN,
    SUBPROCESS_RC_TIMEOUT,
    OpenWrtAPI,
)

_PW = "s3cret-router-pw"


def _make_api():
    return OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password=_PW,
        session=MagicMock(),
        protocol="http",
    )


def _fake_conn(exit_status=0, stdout=b"", stderr=b""):
    """Stand-in for an asyncssh SSHClientConnection."""
    conn = MagicMock()
    conn.run = AsyncMock(
        return_value=SimpleNamespace(
            exit_status=exit_status, stdout=stdout, stderr=stderr
        )
    )
    conn.close = MagicMock()
    conn.wait_closed = AsyncMock()
    return conn


def _patch_connect(conn=None, side_effect=None):
    """Patch api.asyncssh.connect (the transport uses await connect(), not async-with)."""
    mock = (
        AsyncMock(return_value=conn)
        if side_effect is None
        else AsyncMock(side_effect=side_effect)
    )
    return patch("custom_components.openwrt_router.api.asyncssh.connect", mock), mock


@pytest.mark.asyncio
async def test_password_only_in_connect_kwarg_never_in_command():
    api = _make_api()
    conn = _fake_conn(exit_status=0, stdout=b"ok")
    ctx, mock = _patch_connect(conn)
    with ctx:
        await api._run_ssh("uci show wireless")
    # password is the connect() kwarg...
    assert mock.await_args.kwargs["password"] == _PW
    # ...and appears nowhere in the executed remote command or its repr
    remote_cmd = conn.run.await_args.args[0]
    assert _PW not in remote_cmd
    assert _PW not in repr(conn.run.await_args)


@pytest.mark.asyncio
async def test_connect_kwargs_parity():
    api = _make_api()
    conn = _fake_conn(stdout=b"x")
    ctx, mock = _patch_connect(conn)
    with ctx:
        await api._run_ssh("true")
    kw = mock.await_args.kwargs
    assert kw["known_hosts"] is None
    assert kw["connect_timeout"] == SSH_CONNECT_TIMEOUT
    assert kw["username"] == "root"
    # host is the positional arg; SSH port must NOT be the ubus HTTP port
    assert mock.await_args.args[0] == "192.168.1.1"
    assert "port" not in kw


@pytest.mark.asyncio
async def test_key_retry_on_permission_denied():
    api = _make_api()
    good = _fake_conn(exit_status=0, stdout=b"done")
    calls = {"n": 0}

    async def _connect(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise asyncssh.PermissionDenied("password rejected")
        return good

    ctx, mock = _patch_connect(side_effect=_connect)
    with ctx:
        out = await api._run_ssh("uptime")
    assert calls["n"] == 2
    assert mock.await_args_list[0].kwargs["password"] == _PW  # attempt 1: password
    assert mock.await_args_list[1].kwargs["password"] is None  # attempt 2: key-auth
    assert api._ssh_use_key is True
    assert out == "done"


@pytest.mark.asyncio
async def test_permission_denied_final_returns_none_and_rc255():
    api = _make_api()
    ctx, _ = _patch_connect(side_effect=asyncssh.PermissionDenied("nope"))
    with ctx:
        assert await api._run_ssh("uptime") is None
    # direct-call-site contract: rc 255 + stderr marker
    ctx2, _ = _patch_connect(side_effect=asyncssh.PermissionDenied("nope"))
    api2 = _make_api()
    with ctx2:
        rc, out, err = await api2._asyncssh_run("uptime", timeout=5.0)
    assert rc == 255
    assert b"Permission denied" in err


@pytest.mark.asyncio
async def test_run_ssh_none_on_empty_stdout_rc0():
    """ACL-deploy marker contract: empty stdout at exit 0 must be None."""
    api = _make_api()
    ctx, _ = _patch_connect(_fake_conn(exit_status=0, stdout=b""))
    with ctx:
        assert await api._run_ssh("true") is None


@pytest.mark.asyncio
async def test_run_ssh_returns_partial_stdout_on_nonzero_exit():
    api = _make_api()
    ctx, _ = _patch_connect(_fake_conn(exit_status=1, stdout=b"partial"))
    with ctx:
        assert await api._run_ssh("flaky") == "partial"


@pytest.mark.asyncio
async def test_run_ssh_binary_preserves_nul_bytes():
    api = _make_api()
    payload = b"\x00\x01\xffMAC\x00port"
    ctx, _ = _patch_connect(_fake_conn(exit_status=0, stdout=payload))
    with ctx:
        assert (
            await api._run_ssh_binary("cat /sys/class/net/br-lan/brforward") == payload
        )


@pytest.mark.asyncio
async def test_timeout_returns_none_and_detached_sentinel():
    api = _make_api()

    async def _hang(*a, **k):
        await asyncio.sleep(30)

    ctx, _ = _patch_connect(side_effect=_hang)
    with ctx:
        assert await api._run_ssh("sleep 999", timeout=0.01) is None
    ctx2, _ = _patch_connect(side_effect=_hang)
    with ctx2:
        rc, _out, _err = await api._run_ssh_detached("sleep 999", timeout=0.01)
    assert rc == SUBPROCESS_RC_TIMEOUT


@pytest.mark.asyncio
async def test_detached_wraps_nohup_devnull_singlequote_safe():
    """The detached wrapper must survive single quotes in remote_cmd (opkg filter)."""
    api = _make_api()
    conn = _fake_conn(exit_status=0, stdout=b"")
    nasty = (
        "opkg update && opkg upgrade $(opkg list-upgradable | "
        "grep -v -E '^addon-|^luci-' | cut -d' ' -f1) > /tmp/opkg_update.log 2>&1"
    )
    ctx, _ = _patch_connect(conn)
    with ctx:
        await api._run_ssh_detached(nasty, timeout=10.0)
    wrapped = conn.run.await_args.args[0]
    assert wrapped.startswith("nohup sh -c ")
    assert "</dev/null" in wrapped
    assert wrapped.endswith(" &")
    tokens = shlex.split(wrapped, posix=True)
    assert tokens[:3] == ["nohup", "sh", "-c"]
    assert tokens[3] == nasty  # verbatim round-trip, quoting intact


@pytest.mark.asyncio
async def test_connection_refused_maps_to_spawn_sentinel():
    api = _make_api()
    ctx, _ = _patch_connect(side_effect=ConnectionRefusedError("refused"))
    with ctx:
        rc, _out, _err = await api._asyncssh_run("uptime", timeout=5.0)
    assert rc == SUBPROCESS_RC_FAILED_TO_SPAWN
    # wrapper surfaces it as None (not a timeout)
    ctx2, _ = _patch_connect(side_effect=ConnectionRefusedError("refused"))
    with ctx2:
        assert await api._run_ssh("uptime") is None


def test_no_sshpass_left_in_source():
    """The sshpass/subprocess SSH code path is fully gone from api.py.

    (Docstrings may still say "no sshpass required" — that documents the fix;
    what matters is the executable path, i.e. the old helpers and the sshpass
    argv construction are gone.)
    """
    from pathlib import Path

    import custom_components.openwrt_router.api as api_mod

    src = Path(api_mod.__file__).read_text(encoding="utf-8")
    assert "_build_ssh_cmd" not in src
    assert "_ssh_env" not in src
    assert '"sshpass"' not in src  # no argv literal like ["sshpass", "-e", ...]
