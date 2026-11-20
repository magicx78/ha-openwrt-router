"""Tests for the Configuration Manager fetch methods in api.py (config_*).

No network: a fake aiohttp session replays the answers of uhttpd/cgi-io
(``cgi-backup``) and a fake asyncssh connection replays remote processes
(``sysupgrade --create-backup -``, ``uci show``, apk/opkg). The ubus side of
``config_uci_get``/``config_packagelist`` is a patched ``_call``.

SSH runs only over the core's PINNED path (``ssh=``): the tests build that
runner from the real ``api.async_ssh_run_pinned`` with an in-memory pin
store (:func:`pinned`). The SSH tests of the 1.45.0 manager that fixed the
old shared, unverified transport (known_hosts=None, shared connection,
kill on overflow) were changed deliberately; see the test names in
TestSshBackup. Handshake behaviour (pending / mismatch before any login)
uses the fake router of test_ssh_hostkey_pinning.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import asyncssh
import pytest
from test_ssh_hostkey_pinning import KEY_A, KEY_B, KEY_ECDSA, FakeRouter, _patched

from custom_components.openwrt_router.api import (
    PINNED_SSH_STDERR_MAX_BYTES,
    ConfigSshRunner,
    HostKeyPin,
    HostKeyPinStore,
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConfigFetchError,
    OpenWrtConfigFetchHostKeyError,
    OpenWrtConfigFetchIncompleteError,
    OpenWrtConfigFetchNotAvailableError,
    OpenWrtConfigFetchPermissionError,
    OpenWrtConfigFetchTooLargeError,
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
    async_ssh_run_pinned,
)

TOKEN_A = "a1" * 16
TOKEN_B = "b2" * 16
PASSWORD = "router-pw-never-logged"
# Looks like an archive (gzip magic) and carries a secret-looking marker, so a
# log line or error text that includes the bytes would be caught.
ARCHIVE = b"\x1f\x8b\x08\x00" + b"ARCHIVE-SECRET-root:$6$shadowhash" * 20
STDERR_SECRET = b"tar: /etc/shadow: STDERR-SECRET-psk=hunter2"

API_MOD = "custom_components.openwrt_router.api"


# =====================================================================
# HTTP fakes (cgi-backup)
# =====================================================================


class FakeContent:
    """Stands in for ``resp.content``; counts the chunks handed out."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        end_exc: BaseException | None = None,
        block: bool = False,
    ) -> None:
        self._chunks = list(chunks)
        self.total = len(chunks)
        self.yielded = 0
        self._end_exc = end_exc
        self._block = block
        self.chunk_sizes: list[int] = []

    async def iter_chunked(self, n: int) -> AsyncIterator[bytes]:
        self.chunk_sizes.append(n)
        for chunk in self._chunks:
            await asyncio.sleep(0)
            self.yielded += 1
            yield chunk
        if self._end_exc is not None:
            raise self._end_exc
        if self._block:
            await asyncio.Event().wait()


class FakeResponse:
    def __init__(
        self,
        *,
        status: int = 200,
        content_type: str = "application/x-targz",
        chunks: list[bytes] | None = None,
        end_exc: BaseException | None = None,
        block: bool = False,
    ) -> None:
        self.status = status
        self.content_type = content_type
        self.content = FakeContent(chunks or [], end_exc=end_exc, block=block)
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeCM:
    def __init__(self, item: FakeResponse | BaseException) -> None:
        self._item = item

    async def __aenter__(self) -> FakeResponse:
        if isinstance(self._item, BaseException):
            raise self._item
        return self._item

    async def __aexit__(self, *exc: object) -> bool:
        return False


class FakeSession:
    """Records POST calls and hands out scripted responses."""

    def __init__(self, items: list[FakeResponse | BaseException]) -> None:
        self.items = list(items)
        self.calls: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> FakeCM:
        self.calls.append({"url": url, **kwargs})
        if not self.items:
            raise AssertionError("unexpected POST")
        return FakeCM(self.items.pop(0))

    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no GET expected")


def make_api(
    items: list[FakeResponse | BaseException] | None = None,
    *,
    username: str = "root",
    protocol: str = "http",
) -> tuple[OpenWrtAPI, FakeSession]:
    session = FakeSession(items or [])
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username=username,
        password=PASSWORD,
        session=session,  # type: ignore[arg-type]
        protocol=protocol,
    )
    api._token = TOKEN_A
    api._token_expires_at = time.monotonic() + 3600
    return api, session


def fake_login(api: OpenWrtAPI, tokens: list[str]) -> AsyncMock:
    async def _login() -> bool:
        await asyncio.sleep(0)
        api._token = tokens.pop(0)
        api._token_expires_at = time.monotonic() + 3600
        return True

    mock = AsyncMock(side_effect=_login)
    api.login = mock  # type: ignore[method-assign]
    return mock


def gz_response(*chunks: bytes) -> FakeResponse:
    return FakeResponse(chunks=list(chunks))


async def fetch_cgi(api: OpenWrtAPI, **kw: Any) -> bytes:
    kw.setdefault("max_bytes", 1_000_000)
    kw.setdefault("timeout", 5.0)
    return await api.config_fetch_backup_cgi(**kw)


# =====================================================================
# SSH fakes
# =====================================================================


class FakeReader:
    def __init__(self, chunks: list[bytes], *, block: bool = False) -> None:
        self._chunks = list(chunks)
        self.total = len(chunks)
        self.reads = 0
        self.sizes: list[int] = []
        self._block = block

    async def read(self, n: int = -1) -> bytes:
        self.sizes.append(n)
        await asyncio.sleep(0)
        if self._chunks:
            self.reads += 1
            return self._chunks.pop(0)
        if self._block:
            await asyncio.Event().wait()
        return b""


class FakeProc:
    def __init__(
        self,
        stdout: list[bytes] | None = None,
        stderr: list[bytes] | None = None,
        *,
        exit_status: int | None = 0,
        block: bool = False,
    ) -> None:
        self.stdout = FakeReader(stdout or [], block=block)
        self.stderr = FakeReader(stderr or [])
        self.exit_status = exit_status
        self.killed = False
        self.closed = False

    def kill(self) -> None:
        self.killed = True

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        await asyncio.sleep(0)


def fake_conn(proc: FakeProc | None = None, *, open_exc: BaseException | None = None):
    """An authenticated connection to the router with host key KEY_A."""
    conn = MagicMock()
    conn.is_closed = MagicMock(return_value=False)
    conn.get_server_host_key = MagicMock(return_value=KEY_A)
    if open_exc is not None:
        conn.create_process = AsyncMock(side_effect=open_exc)
    else:
        conn.create_process = AsyncMock(return_value=proc)
    conn.run = AsyncMock(side_effect=AssertionError("conn.run must not be used"))
    conn.close = MagicMock()
    conn.wait_closed = AsyncMock()
    return conn


def patch_connect(conn: Any = None, side_effect: Any = None):
    mock = (
        AsyncMock(return_value=conn)
        if side_effect is None
        else AsyncMock(side_effect=side_effect)
    )
    return patch(f"{API_MOD}.asyncssh.connect", mock), mock


def remote_cmd(conn: Any) -> str:
    return conn.create_process.await_args.args[0]


class PinStore(HostKeyPinStore):
    """The core's pin rules in small (core_security.RouterPinStore).

    ``confirm`` (the core's policy): a first-seen key is recorded as pending
    and refused; while it is pending every call refuses before connecting.
    ``tofu``: the first-seen key is pinned at once.
    """

    def __init__(self, pin: HostKeyPin | None = None, *, policy: str = "confirm"):
        self.pin = pin
        self.pending: HostKeyPin | None = None
        self.policy = policy
        self.loads = 0

    async def async_load_pin(self) -> HostKeyPin | None:
        self.loads += 1
        if self.pin is None and self.pending is not None:
            raise OpenWrtHostKeyError("pin_pending", "first-seen key awaits confirm")
        return self.pin

    async def async_save_pin(self, pin: HostKeyPin) -> None:
        if self.policy == "tofu":
            self.pin = pin
            return
        self.pending = pin
        raise OpenWrtHostKeyError("pin_pending", "first-seen key awaits confirm")


def confirmed(key: asyncssh.SSHKey = KEY_A) -> PinStore:
    return PinStore(HostKeyPin.from_key(key, "192.0.2.1"))


def pinned(api: OpenWrtAPI, store: HostKeyPinStore | None = None) -> ConfigSshRunner:
    """The provider's runner, built on the real pinned path of the core."""
    pin_store = confirmed() if store is None else store

    async def run(command: str, timeout: float, max_bytes: int) -> Any:
        return await async_ssh_run_pinned(
            api,
            command,
            pin_store=pin_store,
            timeout=timeout,
            binary=True,
            max_output_bytes=max_bytes,
        )

    return run


def guard_shared_transport(api: OpenWrtAPI) -> None:
    """Fail loudly if anything touches the shared, unverified transport."""
    api._asyncssh_run = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("unpinned transport")
    )
    api._asyncssh_get_connection = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("shared connection")
    )


async def fetch_ssh(api: OpenWrtAPI, **kw: Any) -> bytes:
    kw.setdefault("max_bytes", 1_000_000)
    kw.setdefault("timeout", 5.0)
    kw.setdefault("ssh", pinned(api))
    guard_shared_transport(api)
    return await api.config_fetch_backup_ssh(**kw)


# =====================================================================
# Exceptions
# =====================================================================


class TestExceptions:
    def test_hierarchy_and_error_classes(self) -> None:
        assert issubclass(OpenWrtConfigFetchError, OpenWrtResponseError)
        expected = {
            OpenWrtConfigFetchPermissionError: "permission",
            OpenWrtConfigFetchNotAvailableError: "not_available",
            OpenWrtConfigFetchTooLargeError: "too_large",
            OpenWrtConfigFetchIncompleteError: "incomplete",
            OpenWrtConfigFetchHostKeyError: "denied",
        }
        for cls, error_class in expected.items():
            assert issubclass(cls, OpenWrtConfigFetchError)
            assert not issubclass(cls, OpenWrtAuthError)
            assert cls.error_class == error_class


# =====================================================================
# cgi-backup
# =====================================================================


class TestCgiBackup:
    async def test_success_returns_gzip_bytes(self) -> None:
        api, session = make_api([gz_response(ARCHIVE[:1], ARCHIVE[1:50], ARCHIVE[50:])])
        assert await fetch_cgi(api) == ARCHIVE
        (call,) = session.calls
        assert call["url"] == "http://192.0.2.1:80/cgi-bin/cgi-backup"
        # token only in the form body, never in the URL
        assert call["data"] == {"sessionid": TOKEN_A}
        assert TOKEN_A not in call["url"]
        assert "params" not in call and "headers" not in call
        assert call["ssl"] is api._ssl_context

    async def test_streams_in_64k_chunks_and_closes_response(self) -> None:
        resp = gz_response(ARCHIVE)
        api, _ = make_api([resp])
        await fetch_cgi(api)
        assert resp.content.chunk_sizes == [65536]
        assert resp.closed

    async def test_https_uses_ssl_context_and_https_url(self) -> None:
        api, session = make_api([gz_response(ARCHIVE)], protocol="https-insecure")
        await fetch_cgi(api)
        assert session.calls[0]["url"] == "https://192.0.2.1:80/cgi-bin/cgi-backup"
        assert session.calls[0]["ssl"] is api._ssl_context
        assert api._ssl_context is not None

    async def test_403_twice_is_permission_after_one_relogin(self) -> None:
        api, session = make_api([FakeResponse(status=403), FakeResponse(status=403)])
        login = fake_login(api, [TOKEN_B])
        with pytest.raises(OpenWrtConfigFetchPermissionError) as exc:
            await fetch_cgi(api)
        assert login.await_count == 1
        assert [c["data"]["sessionid"] for c in session.calls] == [TOKEN_A, TOKEN_B]
        assert "403" in str(exc.value)

    async def test_expired_session_relogs_in_once_then_succeeds(self) -> None:
        api, session = make_api([FakeResponse(status=403), gz_response(ARCHIVE)])
        login = fake_login(api, [TOKEN_B])
        assert await fetch_cgi(api) == ARCHIVE
        assert login.await_count == 1
        assert session.calls[1]["data"] == {"sessionid": TOKEN_B}

    async def test_stale_token_refreshed_before_request(self) -> None:
        api, session = make_api([gz_response(ARCHIVE)])
        api._token_expires_at = 0.0
        login = fake_login(api, [TOKEN_B])
        assert await fetch_cgi(api) == ARCHIVE
        assert login.await_count == 1
        assert session.calls[0]["data"] == {"sessionid": TOKEN_B}

    async def test_404_is_not_available_without_relogin(self) -> None:
        api, session = make_api([FakeResponse(status=404, content_type="text/plain")])
        login = fake_login(api, [TOKEN_B])
        with pytest.raises(OpenWrtConfigFetchNotAvailableError):
            await fetch_cgi(api)
        assert login.await_count == 0
        assert len(session.calls) == 1

    @pytest.mark.parametrize("status", [400, 500, 502])
    async def test_other_http_status_is_incomplete(self, status: int) -> None:
        api, _ = make_api([FakeResponse(status=status, content_type="text/plain")])
        with pytest.raises(OpenWrtConfigFetchIncompleteError):
            await fetch_cgi(api)

    async def test_401_is_permission(self) -> None:
        api, _ = make_api([FakeResponse(status=401)])
        fake_login(api, [TOKEN_B])
        with pytest.raises(OpenWrtConfigFetchPermissionError):
            await fetch_cgi(api)

    @pytest.mark.parametrize(
        ("content_type", "body", "expected"),
        [
            (
                "text/html",
                b"<!DOCTYPE html><html><body>LuCI</body></html>",
                OpenWrtConfigFetchNotAvailableError,
            ),
            (
                "text/html",
                b"<html><h1>403 Forbidden</h1></html>",
                OpenWrtConfigFetchPermissionError,
            ),
            (
                "text/plain",
                b"Backup permission denied\n",
                OpenWrtConfigFetchPermissionError,
            ),
            (
                "application/json",
                b'{"error": {"code": -32002, "message": "Access denied"}}',
                OpenWrtConfigFetchPermissionError,
            ),
            (
                "application/json",
                b'{"code": 4, "message": "x"}',
                OpenWrtConfigFetchNotAvailableError,
            ),
            ("application/json", b'{"code": 9}', OpenWrtConfigFetchIncompleteError),
            ("text/plain", b"something else", OpenWrtConfigFetchIncompleteError),
            ("application/x-targz", b"", OpenWrtConfigFetchIncompleteError),
            ("application/x-targz", b"\x1f", OpenWrtConfigFetchIncompleteError),
        ],
    )
    async def test_non_gzip_body_is_classified(
        self, content_type: str, body: bytes, expected: type[Exception]
    ) -> None:
        resp = FakeResponse(content_type=content_type, chunks=[body] if body else [])
        api, _ = make_api([resp])
        with pytest.raises(expected) as exc:
            await fetch_cgi(api)
        assert type(exc.value) is expected
        assert resp.closed

    async def test_non_gzip_body_read_is_bounded(self) -> None:
        resp = FakeResponse(
            content_type="text/html", chunks=[b"<html>" + b"x" * 65530] * 50
        )
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtConfigFetchNotAvailableError):
            await fetch_cgi(api)
        assert resp.content.yielded == 1
        assert resp.closed

    async def test_size_cap_aborts_stream_without_reading_everything(self) -> None:
        chunks = [ARCHIVE[:4]] + [b"\x00" * 1000] * 100
        resp = gz_response(*chunks)
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtConfigFetchTooLargeError) as exc:
            await fetch_cgi(api, max_bytes=5000)
        assert resp.content.yielded < resp.content.total
        assert resp.closed
        assert "5000" in str(exc.value)

    async def test_exact_limit_is_accepted(self) -> None:
        api, _ = make_api([gz_response(ARCHIVE)])
        assert await fetch_cgi(api, max_bytes=len(ARCHIVE)) == ARCHIVE

    async def test_timeout_covers_whole_operation(self) -> None:
        resp = FakeResponse(chunks=[ARCHIVE[:10]], block=True)
        api, _ = make_api([resp])
        started = time.monotonic()
        with pytest.raises(OpenWrtTimeoutError):
            await fetch_cgi(api, timeout=0.05)
        assert time.monotonic() - started < 2
        assert resp.closed

    async def test_aiohttp_timeout_maps_to_timeout_error(self) -> None:
        api, _ = make_api([aiohttp.ServerTimeoutError("read timeout")])
        with pytest.raises(OpenWrtTimeoutError):
            await fetch_cgi(api)

    async def test_connection_lost_maps_to_connection_error(self) -> None:
        api, _ = make_api([aiohttp.ClientConnectionError("refused")])
        with pytest.raises(OpenWrtConnectionError):
            await fetch_cgi(api)

    async def test_transfer_cut_mid_stream_is_incomplete(self) -> None:
        resp = FakeResponse(
            chunks=[ARCHIVE[:10]],
            end_exc=aiohttp.ClientPayloadError("payload not completed"),
        )
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtConfigFetchIncompleteError):
            await fetch_cgi(api)
        assert resp.closed

    async def test_cancel_closes_response_and_propagates(self) -> None:
        resp = FakeResponse(chunks=[ARCHIVE[:10]], block=True)
        api, _ = make_api([resp])
        task = asyncio.create_task(fetch_cgi(api, timeout=30))
        for _ in range(20):
            await asyncio.sleep(0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert resp.closed

    async def test_closing_api_rejects_without_request(self) -> None:
        api, session = make_api([])
        api._closing = True
        with pytest.raises(OpenWrtConnectionError):
            await fetch_cgi(api)
        assert session.calls == []

    @pytest.mark.parametrize(
        ("max_bytes", "timeout"),
        [(0, 5.0), (-1, 5.0), (100, 0), (100, -1.0), (True, 5.0)],
    )
    async def test_invalid_limits_raise_value_error(
        self, max_bytes: Any, timeout: Any
    ) -> None:
        api, session = make_api([])
        with pytest.raises(ValueError):
            await api.config_fetch_backup_cgi(max_bytes=max_bytes, timeout=timeout)
        assert session.calls == []

    async def test_auth_backoff_blocks_without_request(self) -> None:
        api, session = make_api([])
        api._auth_failure_count = 3
        api._auth_backoff_until = time.monotonic() + 60
        with pytest.raises(OpenWrtAuthError):
            await fetch_cgi(api)
        assert session.calls == []


# =====================================================================
# SSH sysupgrade -b
# =====================================================================


class TestSshBackup:
    async def test_success_returns_archive_with_fixed_command(self) -> None:
        """Changed deliberately (pinning): the pinned connection trusts KEY_A
        only (was: known_hosts=None on the shared transport)."""
        proc = FakeProc([ARCHIVE[:20], ARCHIVE[20:]], [b"Saving config files...\n"])
        conn = fake_conn(proc)
        ctx, connect = patch_connect(conn)
        api, _ = make_api()
        with ctx:
            assert await fetch_ssh(api) == ARCHIVE
        assert remote_cmd(conn) == "/sbin/sysupgrade --create-backup -"
        assert conn.create_process.await_args.kwargs["encoding"] is None
        kwargs = connect.await_args.kwargs
        assert kwargs["password"] == PASSWORD
        assert PASSWORD not in remote_cmd(conn)
        trusted, ca, revoked = kwargs["known_hosts"]
        assert [k.public_data for k in trusted] == [KEY_A.public_data]
        assert (ca, revoked) == ([], [])
        # own connection, closed afterwards; the shared one is never opened
        conn.close.assert_called_once()
        assert api._ssh_conn is None and api._ssh_inflight == 0

    async def test_non_root_refused_without_connecting(self) -> None:
        ctx, connect = patch_connect(fake_conn(FakeProc([ARCHIVE])))
        api, _ = make_api(username="homeassistant")
        with ctx, pytest.raises(OpenWrtConfigFetchPermissionError):
            await fetch_ssh(api)
        connect.assert_not_awaited()

    async def test_without_pinned_runner_refuses_without_connecting(self) -> None:
        """No pin store / no runner: the SSH path does not exist (no fallback)."""
        ctx, connect = patch_connect(fake_conn(FakeProc([ARCHIVE])))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
            await fetch_ssh(api, ssh=None)
        assert exc.value.reason == "pin_unavailable"
        assert exc.value.error_class == "denied"
        connect.assert_not_awaited()

    async def test_first_contact_reads_key_without_login_and_stays_pending(
        self,
    ) -> None:
        """Core rule (policy confirm): key recorded as pending, no credential,
        no command; the next call refuses before connecting."""
        store = PinStore()
        router = FakeRouter(KEY_A, stdout=ARCHIVE)
        api, _ = make_api()
        with _patched(router), pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
            await fetch_ssh(api, ssh=pinned(api, store))
        assert exc.value.reason == "pin_pending"
        assert router.auth_attempts == [] and router.conns == []
        assert router.connect_kwargs[0]["password"] is None
        assert store.pending is not None
        assert store.pending.fingerprint == KEY_A.get_fingerprint("sha256")
        with _patched(router), pytest.raises(OpenWrtConfigFetchHostKeyError) as again:
            await fetch_ssh(api, ssh=pinned(api, store))
        assert again.value.reason == "pin_pending"
        assert len(router.connect_kwargs) == 1  # refused before connecting

    async def test_first_contact_under_tofu_pins_then_logs_in(self) -> None:
        """Core rule (policy tofu): pinned at once, a second, pinned
        connection logs in and runs the command."""
        store = PinStore(policy="tofu")
        router = FakeRouter(KEY_A, stdout=ARCHIVE)
        api, _ = make_api()
        with _patched(router):
            assert await fetch_ssh(api, ssh=pinned(api, store)) == ARCHIVE
        assert store.pin is not None
        assert router.auth_attempts == [PASSWORD]  # only the pinned connection
        assert router.connect_kwargs[0]["password"] is None

    async def test_confirmed_pin_runs_the_command(self) -> None:
        router = FakeRouter(KEY_A, stdout=ARCHIVE)
        api, _ = make_api()
        with _patched(router):
            assert await fetch_ssh(api, ssh=pinned(api, confirmed())) == ARCHIVE
        assert router.auth_attempts == [PASSWORD]
        assert len(router.processes) == 1

    @pytest.mark.parametrize(
        ("presented", "reason"),
        [(KEY_B, "mismatch"), (KEY_ECDSA, "algorithm_unavailable")],
    )
    async def test_other_host_key_sends_no_credential_and_fetches_nothing(
        self, presented: asyncssh.SSHKey, reason: str
    ) -> None:
        router = FakeRouter(presented, stdout=ARCHIVE)
        api, _ = make_api()
        with _patched(router), pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
            await fetch_ssh(api, ssh=pinned(api, confirmed(KEY_A)))
        assert exc.value.reason == reason
        assert exc.value.error_class == "denied"
        assert router.auth_attempts == []  # refused in the handshake
        assert router.processes == []  # nothing ran, nothing fetched
        assert len(router.connect_kwargs) == 1  # no retry, no unpinned path
        assert api._ssh_conn is None

    @pytest.mark.parametrize("exit_status", [1, 127, 255, None])
    async def test_nonzero_or_missing_exit_is_incomplete(
        self, exit_status: Any
    ) -> None:
        proc = FakeProc([ARCHIVE], [STDERR_SECRET], exit_status=exit_status)
        ctx, _ = patch_connect(fake_conn(proc))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchIncompleteError) as exc:
            await fetch_ssh(api)
        assert "STDERR-SECRET" not in str(exc.value)
        assert "hunter2" not in str(exc.value)

    async def test_non_gzip_stdout_is_incomplete(self) -> None:
        proc = FakeProc([b"Usage: sysupgrade ...\n"])
        ctx, _ = patch_connect(fake_conn(proc))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchIncompleteError):
            await fetch_ssh(api)

    async def test_empty_stdout_is_incomplete(self) -> None:
        ctx, _ = patch_connect(fake_conn(FakeProc([])))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchIncompleteError):
            await fetch_ssh(api)

    async def test_size_cap_closes_process_without_reading_everything(self) -> None:
        """Changed deliberately: the core's capped read closes the channel
        (was: kill() on the shared transport); the cap is still ours."""
        chunks = [ARCHIVE[:4]] + [b"\x00" * 1000] * 100
        proc = FakeProc(chunks)
        conn = fake_conn(proc)
        ctx, _ = patch_connect(conn)
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchTooLargeError):
            await fetch_ssh(api, max_bytes=5000)
        assert proc.stdout.reads < proc.stdout.total
        assert proc.closed
        conn.close.assert_called_once()

    async def test_runner_gets_our_cap_and_timeout(self) -> None:
        seen: list[tuple[str, float, int]] = []

        async def runner(command: str, timeout: float, max_bytes: int) -> Any:
            seen.append((command, timeout, max_bytes))
            return MagicMock(exit_status=0, stdout=ARCHIVE, stderr=b"")

        api, _ = make_api()
        assert await fetch_ssh(api, ssh=runner, max_bytes=16 * 1024 * 1024) == ARCHIVE
        assert seen == [("/sbin/sysupgrade --create-backup -", 5.0, 16 * 1024 * 1024)]

    async def test_runner_output_over_cap_is_too_large(self) -> None:
        """Defence in depth: a runner that ignored the cap is still refused."""

        async def runner(command: str, timeout: float, max_bytes: int) -> Any:
            return MagicMock(exit_status=0, stdout=ARCHIVE * 10, stderr=b"")

        api, _ = make_api()
        with pytest.raises(OpenWrtConfigFetchTooLargeError):
            await fetch_ssh(api, ssh=runner, max_bytes=len(ARCHIVE))

    async def test_stderr_capped_at_4k_and_drained(self) -> None:
        """Changed deliberately (was test_stderr_read_in_bounded_pieces): the
        core reads stderr to EOF and keeps 4 KiB."""
        proc = FakeProc([ARCHIVE], [b"e" * 4096, b"e" * 4096, b"e" * 10])
        ctx, _ = patch_connect(fake_conn(proc))
        api, _ = make_api()
        guard_shared_transport(api)
        with ctx:
            rc, out, err = await api._config_ssh_read(
                "/sbin/sysupgrade --create-backup -",
                pinned(api),
                max_bytes=1_000_000,
                timeout=5.0,
            )
        assert (rc, out) == (0, ARCHIVE)
        assert len(err) <= PINNED_SSH_STDERR_MAX_BYTES
        assert proc.stderr.reads == 3  # drained, the channel never stalls

    async def test_timeout_closes_process(self) -> None:
        """Renamed (was test_timeout_kills_process): closed, not killed."""
        proc = FakeProc([ARCHIVE[:10]], block=True)
        ctx, _ = patch_connect(fake_conn(proc))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtTimeoutError):
            await fetch_ssh(api, timeout=0.05)
        assert proc.closed
        assert api._ssh_inflight == 0

    async def test_hanging_connect_hits_the_deadline(self) -> None:
        router = FakeRouter(KEY_A, stdout=ARCHIVE, connect_delay=5.0)
        api, _ = make_api()
        started = time.monotonic()
        with _patched(router), pytest.raises(OpenWrtTimeoutError):
            await fetch_ssh(api, timeout=0.05)
        assert time.monotonic() - started < 2.0
        assert router.auth_attempts == []

    async def test_cancel_closes_process_and_propagates(self) -> None:
        """Renamed (was test_cancel_kills_process_and_propagates)."""
        proc = FakeProc([ARCHIVE[:10]], block=True)
        conn = fake_conn(proc)
        ctx, _ = patch_connect(conn)
        api, _ = make_api()
        with ctx:
            task = asyncio.create_task(fetch_ssh(api, timeout=30))
            for _ in range(20):
                await asyncio.sleep(0)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert proc.closed
        conn.close.assert_called_once()
        assert api._ssh_inflight == 0

    async def test_connect_failure_is_connection_error(self) -> None:
        ctx, _ = patch_connect(side_effect=OSError("No route to host"))
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConnectionError):
            await fetch_ssh(api)
        assert api._ssh_inflight == 0

    async def test_channel_open_failure_is_connection_error(self) -> None:
        conn = fake_conn(open_exc=asyncssh.ChannelOpenError(2, "refused"))
        ctx, _ = patch_connect(conn)
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConnectionError):
            await fetch_ssh(api)

    async def test_password_then_key_denied_is_permission(self) -> None:
        denied = asyncssh.PermissionDenied("denied")
        ctx, connect = patch_connect(side_effect=[denied, denied])
        api, _ = make_api()
        with ctx, pytest.raises(OpenWrtConfigFetchPermissionError):
            await fetch_ssh(api)
        assert connect.await_count == 2
        assert connect.await_args_list[1].kwargs["password"] is None
        # the pinned path never changes the shared transport's state
        assert api._ssh_use_key is False

    async def test_key_auth_after_password_denied(self) -> None:
        proc = FakeProc([ARCHIVE])
        ctx, connect = patch_connect(
            side_effect=[asyncssh.PermissionDenied("denied"), fake_conn(proc)]
        )
        api, _ = make_api()
        with ctx:
            assert await fetch_ssh(api) == ARCHIVE
        assert connect.await_args_list[1].kwargs["password"] is None

    async def test_never_uses_the_shared_connection(self) -> None:
        """Changed deliberately (was test_reuses_open_connection): an open
        shared connection is ignored; the pinned path opens its own."""
        shared = MagicMock()
        shared.create_process = AsyncMock(side_effect=AssertionError("shared conn"))
        proc = FakeProc([ARCHIVE])
        own = fake_conn(proc)
        ctx, connect = patch_connect(own)
        api, _ = make_api()
        api._ssh_conn = shared
        with ctx:
            assert await fetch_ssh(api) == ARCHIVE
        connect.assert_awaited_once()
        shared.create_process.assert_not_awaited()
        assert api._ssh_conn is shared  # untouched


# =====================================================================
# config_uci_get
# =====================================================================

UCI_VALUES = {
    "lan": {
        ".type": "interface",
        ".name": "lan",
        ".anonymous": False,
        "proto": "static",
    }
}
UCI_SHOW = (
    "network.lan=interface\n"
    "network.lan.proto='static'\n"
    "network.@device[0]=device\n"
    "network.@device[0].ports='lan1' 'lan2'\n"
)


class TestUciGet:
    async def test_ubus_success(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(return_value={"values": UCI_VALUES})  # type: ignore[method-assign]
        assert await api.config_uci_get("network") == UCI_VALUES
        api._call.assert_awaited_once_with("uci", "get", {"config": "network"})

    async def test_reply_without_values_is_incomplete(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(return_value={})  # type: ignore[method-assign]
        with pytest.raises(OpenWrtConfigFetchIncompleteError):
            await api.config_uci_get("network")

    async def test_acl_block_falls_back_to_ssh_uci_show(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("rpcd ACL blocks uci/get/network")
        )
        conn = fake_conn(FakeProc([UCI_SHOW.encode()]))
        ctx, _ = patch_connect(conn)
        guard_shared_transport(api)
        with ctx:
            result = await api.config_uci_get("network", ssh=pinned(api))
        assert remote_cmd(conn) == "uci show network"
        assert result["lan"][".type"] == "interface"
        assert result["lan"]["proto"] == "static"
        assert result["@device[0]"]["ports"] == ["lan1", "lan2"]

    async def test_ssh_uci_show_over_text_cap_is_too_large(self) -> None:
        """Review M6: the parser never sees more than UCI_TEXT_MAX_BYTES."""
        from custom_components.openwrt_router.config_const import UCI_TEXT_MAX_BYTES

        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("rpcd ACL blocks uci/get/network")
        )
        line = b"network.x.y='" + b"a" * 1000 + b"'\n"
        chunks = [line * 64] * (UCI_TEXT_MAX_BYTES // (len(line) * 64) + 2)
        proc = FakeProc(chunks)
        ctx, _ = patch_connect(fake_conn(proc))
        with ctx, pytest.raises(OpenWrtConfigFetchTooLargeError):
            await api.config_uci_get("network", ssh=pinned(api))
        assert proc.stdout.reads < proc.stdout.total  # stopped at the cap

    def test_uci_show_cap_equals_the_parser_cap(self) -> None:
        from custom_components.openwrt_router import api as api_module
        from custom_components.openwrt_router.config_const import UCI_TEXT_MAX_BYTES

        assert api_module._CONFIG_UCI_SHOW_MAX_BYTES == UCI_TEXT_MAX_BYTES

    async def test_cached_acl_block_goes_straight_to_ssh(self) -> None:
        api, session = make_api()
        api._acl_blocked.add(("uci", "get", "network"))
        conn = fake_conn(FakeProc([UCI_SHOW.encode()]))
        ctx, _ = patch_connect(conn)
        with ctx:
            result = await api.config_uci_get("network", ssh=pinned(api))
        assert session.calls == []  # no ubus request at all
        assert "lan" in result

    async def test_acl_block_without_usable_ssh_is_permission(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        ctx, _ = patch_connect(side_effect=OSError("Connection refused"))
        with ctx, pytest.raises(OpenWrtConfigFetchPermissionError):
            await api.config_uci_get("network", ssh=pinned(api))

    async def test_missing_config_via_ssh_is_not_available(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("not found")
        )
        proc = FakeProc([], [b"uci: Entry not found\n"], exit_status=1)
        ctx, _ = patch_connect(fake_conn(proc))
        with ctx, pytest.raises(OpenWrtConfigFetchNotAvailableError):
            await api.config_uci_get("sqm", ssh=pinned(api))

    async def test_ssh_other_failure_is_incomplete(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        proc = FakeProc([], [b"uci: I/O error\n"], exit_status=1)
        ctx, _ = patch_connect(fake_conn(proc))
        with ctx, pytest.raises(OpenWrtConfigFetchIncompleteError):
            await api.config_uci_get("network", ssh=pinned(api))

    async def test_acl_block_without_runner_is_denied_not_unpinned(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        guard_shared_transport(api)
        ctx, connect = patch_connect(fake_conn(FakeProc([UCI_SHOW.encode()])))
        with ctx, pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
            await api.config_uci_get("network")
        assert exc.value.reason == "pin_unavailable"
        connect.assert_not_awaited()

    @pytest.mark.parametrize(
        ("pending", "presented", "reason"),
        [(False, KEY_B, "mismatch"), (True, KEY_A, "pin_pending")],
    )
    async def test_acl_block_with_refused_pin_sends_no_credential(
        self, pending: bool, presented: asyncssh.SSHKey, reason: str
    ) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        router = FakeRouter(presented, stdout=UCI_SHOW.encode())
        runner = pinned(api, PinStore() if pending else confirmed(KEY_A))
        with _patched(router), pytest.raises(OpenWrtConfigFetchHostKeyError) as exc:
            await api.config_uci_get("network", ssh=runner)
        assert exc.value.reason == reason and exc.value.error_class == "denied"
        assert router.auth_attempts == [] and router.processes == []

    async def test_ubus_connection_error_propagates_without_ssh(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtConnectionError("down")
        )
        ctx, connect = patch_connect(fake_conn(FakeProc([UCI_SHOW.encode()])))
        with ctx, pytest.raises(OpenWrtConnectionError):
            await api.config_uci_get("network")
        connect.assert_not_awaited()

    @pytest.mark.parametrize(
        "name",
        [
            "; rm -rf /",
            "network; reboot",
            "$(reboot)",
            "`id`",
            "-c",
            "--help",
            "-",
            "",
            "a" * 65,
            "net work",
            "network\n",
            "wire\nless",
            "../etc/shadow",
            "network.lan",
            "netw'ork",
            "nétwork",
            None,
            5,
        ],
    )
    async def test_invalid_name_raises_before_any_call(self, name: Any) -> None:
        api, session = make_api()
        api._call = AsyncMock()  # type: ignore[method-assign]
        ctx, connect = patch_connect(fake_conn(FakeProc([])))
        with ctx, pytest.raises(ValueError):
            await api.config_uci_get(name)
        api._call.assert_not_awaited()
        connect.assert_not_awaited()
        assert session.calls == []

    @pytest.mark.parametrize(
        "name", ["network", "a", "luci_statistics", "a-b_c9", "x" * 64]
    )
    async def test_valid_names_accepted(self, name: str) -> None:
        api, _ = make_api()
        api._call = AsyncMock(return_value={"values": {}})  # type: ignore[method-assign]
        assert await api.config_uci_get(name) == {}


# =====================================================================
# config_packagelist
# =====================================================================

APK_LIST = (
    "@@pm=apk\n"
    "busybox-1.37.0-r2 aarch64_cortex-a53 {busybox} (GPL-2.0) [installed]\n"
    "libpcre2-8-10.42-r1 aarch64_cortex-a53 {pcre2} (BSD-3-Clause) [installed]\n"
    "WARNING: opening /etc/apk/repositories.d: No such file\n"
)
OPKG_LIST = (
    "@@pm=opkg\nbusybox - 1.36.1-1\nkmod-nft-core - 6.6.73-1\nCollected errors:\n"
)


class TestPackageList:
    async def test_rpc_sys_packagelist(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            return_value={"packages": {"busybox": "1.37.0-r2", "dnsmasq": "2.90-r4"}}
        )
        ctx, connect = patch_connect(fake_conn(FakeProc([])))
        with ctx:
            assert await api.config_packagelist() == {
                "busybox": "1.37.0-r2",
                "dnsmasq": "2.90-r4",
            }
        api._call.assert_awaited_once_with("rpc-sys", "packagelist", {"all": True})
        connect.assert_not_awaited()

    async def test_apk_over_ssh(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("no rpc-sys")
        )
        conn = fake_conn(FakeProc([APK_LIST.encode()]))
        ctx, _ = patch_connect(conn)
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) == {
                "busybox": "1.37.0-r2",
                "libpcre2-8": "10.42-r1",
            }
        assert "apk list -I" in remote_cmd(conn)
        assert "opkg list-installed" in remote_cmd(conn)

    async def test_opkg_over_ssh(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("no rpc-sys")
        )
        ctx, _ = patch_connect(fake_conn(FakeProc([OPKG_LIST.encode()])))
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) == {
                "busybox": "1.36.1-1",
                "kmod-nft-core": "6.6.73-1",
            }

    async def test_empty_rpc_reply_falls_back_to_ssh(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(return_value={"packages": {}})  # type: ignore[method-assign]
        ctx, _ = patch_connect(fake_conn(FakeProc([OPKG_LIST.encode()])))
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) == {
                "busybox": "1.36.1-1",
                "kmod-nft-core": "6.6.73-1",
            }

    @pytest.mark.parametrize(
        "proc",
        [
            FakeProc([b"@@pm=none\n"]),
            FakeProc([b"@@pm=apk\n"]),
            FakeProc([], exit_status=1),
        ],
    )
    async def test_nothing_available_returns_none(self, proc: FakeProc) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtResponseError("ubus error 9")
        )
        ctx, _ = patch_connect(fake_conn(proc))
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) is None

    async def test_ssh_unusable_returns_none(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        ctx, _ = patch_connect(side_effect=OSError("refused"))
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) is None

    async def test_ssh_package_list_is_capped(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("no rpc-sys")
        )
        proc = FakeProc([b"@@pm=apk\n" + b"x" * 65536] * 40)  # > 2 MiB
        ctx, _ = patch_connect(fake_conn(proc))
        with ctx:
            assert await api.config_packagelist(ssh=pinned(api)) is None
        assert proc.stdout.reads < proc.stdout.total and proc.closed

    @pytest.mark.parametrize("runner_given", [False, True])
    async def test_refused_pin_returns_none_without_credentials(
        self, runner_given: bool
    ) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("no rpc-sys")
        )
        guard_shared_transport(api)
        router = FakeRouter(KEY_B, stdout=APK_LIST.encode())
        runner = pinned(api, confirmed(KEY_A)) if runner_given else None
        with _patched(router):
            assert await api.config_packagelist(ssh=runner) is None
        assert router.auth_attempts == [] and router.processes == []

    async def test_ubus_connection_error_propagates(self) -> None:
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtTimeoutError("timeout")
        )
        ctx, connect = patch_connect(fake_conn(FakeProc([])))
        with ctx, pytest.raises(OpenWrtTimeoutError):
            await api.config_packagelist()
        connect.assert_not_awaited()


# =====================================================================
# config_backup_access / config_ssh_user_is_root (review M1: no sysupgrade)
# =====================================================================


class TestBackupAccess:
    @pytest.mark.parametrize("allowed", [True, False])
    async def test_asks_rpcd_for_the_cgi_io_backup_right(self, allowed: bool) -> None:
        api, session = make_api()
        api._call = AsyncMock(return_value={"access": allowed})  # type: ignore[method-assign]
        ctx, connect = patch_connect(fake_conn(FakeProc([])))
        with ctx:
            assert await api.config_backup_access() is allowed
        # The same check cgi-io makes before it starts sysupgrade.
        api._call.assert_awaited_once_with(
            "session",
            "access",
            {"scope": "cgi-io", "object": "backup", "function": "read"},
        )
        assert session.calls == []  # no cgi-backup POST
        connect.assert_not_awaited()  # no SSH, so no sysupgrade

    @pytest.mark.parametrize(
        "outcome",
        [
            OpenWrtMethodNotFoundError("ACL blocks session/access"),
            OpenWrtResponseError("ubus error 2"),
            {"access": "yes"},
            {},
            ["access"],
        ],
    )
    async def test_no_clear_answer_is_none(self, outcome: Any) -> None:
        api, _ = make_api()
        mock = (
            AsyncMock(side_effect=outcome)
            if isinstance(outcome, BaseException)
            else AsyncMock(return_value=outcome)
        )
        api._call = mock  # type: ignore[method-assign]
        assert await api.config_backup_access() is None

    @pytest.mark.parametrize(
        "exc", [OpenWrtConnectionError("down"), OpenWrtTimeoutError("slow")]
    )
    async def test_dead_router_propagates(self, exc: BaseException) -> None:
        api, _ = make_api()
        api._call = AsyncMock(side_effect=exc)  # type: ignore[method-assign]
        with pytest.raises(type(exc)):
            await api.config_backup_access()

    @pytest.mark.parametrize(("username", "root"), [("root", True), ("admin", False)])
    def test_ssh_user_is_root_without_a_call(self, username: str, root: bool) -> None:
        api, session = make_api(username=username)
        ctx, connect = patch_connect(fake_conn(FakeProc([])))
        with ctx:
            assert api.config_ssh_user_is_root() is root
        assert session.calls == []
        connect.assert_not_awaited()


# =====================================================================
# Secrets never reach the log
# =====================================================================


class TestNoSecretsInLog:
    async def test_token_archive_and_stderr_never_logged(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        messages: list[str] = []

        # cgi: expired session, re-login, success
        api, _ = make_api([FakeResponse(status=403), gz_response(ARCHIVE)])
        fake_login(api, [TOKEN_B])
        await fetch_cgi(api)

        # cgi: HTML body, too large
        api, _ = make_api([FakeResponse(content_type="text/html", chunks=[b"<html>x"])])
        with pytest.raises(OpenWrtConfigFetchError) as exc:
            await fetch_cgi(api)
        messages.append(str(exc.value))
        api, _ = make_api([gz_response(ARCHIVE, ARCHIVE)])
        with pytest.raises(OpenWrtConfigFetchTooLargeError) as exc:
            await fetch_cgi(api, max_bytes=len(ARCHIVE) + 1)
        messages.append(str(exc.value))

        # ssh: success, failing exit with secret stderr, uci fallback failure
        for proc in (
            FakeProc([ARCHIVE], [STDERR_SECRET]),
            FakeProc([ARCHIVE], [STDERR_SECRET], exit_status=1),
        ):
            ctx, _ = patch_connect(fake_conn(proc))
            api, _ = make_api()
            with ctx, contextlib.suppress(OpenWrtConfigFetchError):
                await fetch_ssh(api)
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        ctx, _ = patch_connect(fake_conn(FakeProc([], [STDERR_SECRET], exit_status=1)))
        with ctx, pytest.raises(OpenWrtConfigFetchError) as exc:
            await api.config_uci_get("network", ssh=pinned(api))
        messages.append(str(exc.value))

        # ssh: pending first contact and other key (no login, nothing ran)
        for store, presented in ((PinStore(), KEY_A), (confirmed(KEY_A), KEY_B)):
            api, _ = make_api()
            router = FakeRouter(presented, stdout=ARCHIVE, stderr=STDERR_SECRET)
            with _patched(router), pytest.raises(OpenWrtConfigFetchError) as exc:
                await fetch_ssh(api, ssh=pinned(api, store))
            messages.append(str(exc.value))
            assert router.auth_attempts == []

        text = caplog.text + "\n".join(messages)
        for secret in (
            TOKEN_A,
            TOKEN_B,
            PASSWORD,
            "ARCHIVE-SECRET",
            "shadowhash",
            "STDERR-SECRET",
            "hunter2",
            "x1f",
        ):
            assert secret not in text, secret


# =====================================================================
# No unpinned path (source check of our two api.py blocks)
# =====================================================================

_BLOCK_START = "# --- Configuration Manager (config_*) ---"
_BLOCK_END = "# --- end Configuration Manager ---"
# What the shared, unverified transport is made of; none of it may appear.
_UNPINNED = frozenset(
    {
        "_asyncssh_get_connection",
        "_asyncssh_run",
        "_run_ssh",
        "_ssh_conn",
        "_ssh_inflight",
        "create_process",
        "connect",
    }
)


def _config_blocks() -> list[str]:
    from pathlib import Path

    from custom_components.openwrt_router import api as api_module

    text = Path(api_module.__file__).read_text(encoding="utf-8")
    blocks: list[str] = []
    pos = 0
    while (found := text.find(_BLOCK_START, pos)) != -1:
        start = text.rfind("\n", 0, found) + 1  # whole line: dedent works
        end = text.index(_BLOCK_END, found)
        blocks.append(text[start:end])
        pos = end + len(_BLOCK_END)
    return blocks


class TestNoUnpinnedPath:
    def test_two_blocks_found(self) -> None:
        assert len(_config_blocks()) == 2

    def test_blocks_never_reach_the_shared_transport(self) -> None:
        import ast
        import textwrap

        for block in _config_blocks():
            tree = ast.parse(textwrap.dedent(block))
            names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            keywords = {
                k.arg
                for n in ast.walk(tree)
                if isinstance(n, ast.Call)
                for k in n.keywords
            }
            assert not names & _UNPINNED, names & _UNPINNED
            assert "known_hosts" not in keywords
            # SSH only through the runner handed in (``ssh(...)``)
            assert "asyncssh.connect" not in block

    async def test_every_ssh_read_needs_the_runner(self) -> None:
        """Without ``ssh=`` none of the three SSH reads connects."""
        api, _ = make_api()
        api._call = AsyncMock(  # type: ignore[method-assign]
            side_effect=OpenWrtMethodNotFoundError("blocked")
        )
        guard_shared_transport(api)
        ctx, connect = patch_connect(fake_conn(FakeProc([ARCHIVE])))
        with ctx:
            with pytest.raises(OpenWrtConfigFetchHostKeyError):
                await api.config_fetch_backup_ssh(max_bytes=1000, timeout=1.0)
            with pytest.raises(OpenWrtConfigFetchHostKeyError):
                await api.config_uci_get("network")
            assert await api.config_packagelist() is None
        connect.assert_not_awaited()
