"""Tests for async_ssh_run_pinned (host-key pinning, config/backup path).

Since the security review of 2026-11-18 (finding 2) the first contact reads
the host key WITHOUT credentials and stops before authentication; only a
connection pinned to a CONFIRMED key logs in. The first-use tests below were
changed deliberately for that (they asserted the old "log in with the
password, then pin" order). The fake process models asyncssh's
``create_process`` streams for the output caps (finding 3).

asyncssh.connect is replaced by a fake router that behaves like asyncssh in
the parts that matter: the host key is checked during the handshake (trusted
list first, then SSHClient.validate_host_public_key), BEFORE authentication;
a pinned key restricts the host-key algorithms. Keys are real asyncssh keys
generated in memory. No network.
"""

from __future__ import annotations

import asyncio
import re
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import asyncssh
import pytest
from asyncssh.known_hosts import match_known_hosts

from custom_components.openwrt_router.api import (
    SSH_CONNECT_TIMEOUT,
    SUBPROCESS_RC_FAILED_TO_SPAWN,
    HostKeyPin,
    HostKeyPinStore,
    OpenWrtAPI,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtHostKeyMismatchError,
    OpenWrtTimeoutError,
    PinnedSshResult,
    _PinningSSHClient,
    async_ssh_run_pinned,
)

_PW = "s3cret-router-pw"
_HOST = "192.168.1.1"


def _key(alg: str = "ssh-ed25519") -> asyncssh.SSHKey:
    return asyncssh.generate_private_key(alg).convert_to_public()


KEY_A = _key()
KEY_B = _key()
KEY_ECDSA = _key("ecdsa-sha2-nistp256")


def _api() -> OpenWrtAPI:
    return OpenWrtAPI(
        host=_HOST,
        port=80,
        username="root",
        password=_PW,
        session=MagicMock(),
        protocol="http",
    )


class MemoryPinStore(HostKeyPinStore):
    def __init__(self, pin: HostKeyPin | None = None, *, fail_save: bool = False):
        self.pin = pin
        self.fail_save = fail_save
        self.saved: list[HostKeyPin] = []

    async def async_load_pin(self) -> HostKeyPin | None:
        return self.pin

    async def async_save_pin(self, pin: HostKeyPin) -> None:
        if self.fail_save:
            raise OSError("disk full")
        self.saved.append(pin)
        self.pin = pin


class FakeStream:
    """asyncssh process stream: read(n) returns chunks, b"" at EOF."""

    def __init__(self, data: bytes, chunk: int = 7000):
        self.data = data
        self.pos = 0
        self.chunk = chunk
        self.reads = 0

    async def read(self, n: int = -1) -> bytes:
        self.reads += 1
        size = min(n if n > 0 else len(self.data), self.chunk)
        out = self.data[self.pos : self.pos + size]
        self.pos += len(out)
        return out


class FakeProcess:
    def __init__(self, stdout: bytes, stderr: bytes, exit_status):
        self.stdout = FakeStream(stdout)
        self.stderr = FakeStream(stderr)
        self.exit_status = exit_status
        self.closed = False

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class FakeRouter:
    """Stand-in for asyncssh.connect against one router."""

    def __init__(
        self,
        host_keys,
        *,
        deny_password: bool = False,
        deny_all: bool = False,
        exit_status: int | None = 0,
        stdout: bytes = b"ok\n",
        stderr: bytes = b"",
        connect_error: Exception | None = None,
        connect_delay: float = 0.0,
    ):
        # one key per connection attempt (last one repeats)
        self.host_keys = list(host_keys) if isinstance(host_keys, list) else [host_keys]
        self.deny_password = deny_password
        self.deny_all = deny_all
        self.exit_status = exit_status
        self.stdout = stdout
        self.stderr = stderr
        self.processes: list[FakeProcess] = []
        self.connect_error = connect_error
        self.connect_delay = connect_delay
        self.connect_kwargs: list[dict] = []
        self.auth_attempts: list[str | None] = []  # passwords the server saw
        self.conns: list[MagicMock] = []
        self.on_run = None

    async def connect(self, host, **kw):
        self.connect_kwargs.append({"host": host, **kw})
        if self.connect_delay:
            await asyncio.sleep(self.connect_delay)
        if self.connect_error is not None:
            raise self.connect_error
        key = self.host_keys[min(len(self.connect_kwargs) - 1, len(self.host_keys) - 1)]
        trusted, _ca, _revoked = kw["known_hosts"]
        client = kw["client_factory"]()
        # Handshake: pinned key restricts host-key algorithms ...
        if trusted and key.get_algorithm() not in {k.get_algorithm() for k in trusted}:
            raise asyncssh.KeyExchangeFailed("No matching host key format found")
        # ... trusted list, then the client's own decision ...
        is_trusted = any(k.public_data == key.public_data for k in trusted)
        if not is_trusted and not client.validate_host_public_key(host, host, 22, key):
            raise asyncssh.HostKeyNotVerifiable("Host key is not trusted")
        # ... and only then authentication.
        self.auth_attempts.append(kw["password"])
        if self.deny_all or (self.deny_password and kw["password"] is not None):
            raise asyncssh.PermissionDenied("denied")
        conn = MagicMock()
        conn.get_server_host_key = MagicMock(return_value=key)

        async def _create_process(cmd, **run_kw):
            assert run_kw.get("encoding", "x") is None
            if self.on_run:
                self.on_run()
            proc = FakeProcess(self.stdout, self.stderr, self.exit_status)
            self.processes.append(proc)
            return proc

        conn.create_process = AsyncMock(side_effect=_create_process)
        conn.run = AsyncMock(side_effect=AssertionError("unbounded conn.run"))
        conn.close = MagicMock()
        conn.wait_closed = AsyncMock()
        self.conns.append(conn)
        return conn


def _patched(router: FakeRouter):
    return patch(
        "custom_components.openwrt_router.api.asyncssh.connect",
        AsyncMock(side_effect=router.connect),
    )


def _guard_shared_transport(api: OpenWrtAPI):
    """Fail loudly if the pinned path touched the unpinned transport."""
    api._asyncssh_run = AsyncMock(side_effect=AssertionError("unpinned transport"))
    api._asyncssh_get_connection = AsyncMock(
        side_effect=AssertionError("shared connection")
    )


# ---------------------------------------------------------------------------
# First use / later use
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_first_use_pins_before_running_the_command():
    """Changed deliberately (finding 2): the first connection carries NO
    credentials and stops in the handshake; a store that confirms at once
    (MemoryPinStore = tofu) gets a SECOND, pinned connection that logs in."""
    api, store, router = _api(), MemoryPinStore(), FakeRouter(KEY_A)
    _guard_shared_transport(api)
    seen_at_run: list[int] = []
    router.on_run = lambda: seen_at_run.append(len(store.saved))
    with _patched(router):
        result = await async_ssh_run_pinned(api, "sysupgrade -b -", pin_store=store)
    assert isinstance(result, PinnedSshResult)
    assert result.pinned_now is True
    assert seen_at_run == [1]  # saved before the command ran
    assert store.saved[0].fingerprint == KEY_A.get_fingerprint("sha256")
    assert store.saved[0].algorithm == "ssh-ed25519"
    assert store.saved[0].host == _HOST
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", store.saved[0].pinned_at)
    assert result.pin == store.saved[0]
    assert result.stdout == "ok\n"
    assert result.exit_status == 0
    probe, login = router.connect_kwargs
    assert probe["known_hosts"] == ([], [], [])  # checked, not None, not empty
    assert probe["password"] is None and probe["client_keys"] is None
    assert probe["agent_path"] is None and probe["gss_host"] is None
    assert [k.public_data for k in login["known_hosts"][0]] == [KEY_A.public_data]
    assert login["password"] == _PW
    assert router.auth_attempts == [_PW]  # only the pinned connection logged in
    assert login["connect_timeout"] == SSH_CONNECT_TIMEOUT
    assert "port" not in login
    router.conns[0].close.assert_called_once()
    assert api._ssh_conn is None


@pytest.mark.asyncio
async def test_later_use_trusts_only_the_pinned_key():
    pin = HostKeyPin.from_key(KEY_A, _HOST)
    api, store, router = _api(), MemoryPinStore(pin), FakeRouter(KEY_A)
    _guard_shared_transport(api)
    with _patched(router):
        result = await async_ssh_run_pinned(api, "uci export", pin_store=store)
    assert result.pinned_now is False
    assert result.pin == pin
    assert store.saved == []
    trusted = router.connect_kwargs[0]["known_hosts"][0]
    assert [k.public_data for k in trusted] == [KEY_A.public_data]


@pytest.mark.asyncio
async def test_pin_survives_an_address_change():
    pin = HostKeyPin.from_key(KEY_A, "10.0.0.9")
    api, router = _api(), FakeRouter(KEY_A)
    with _patched(router):
        result = await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore(pin))
    assert result.pin.host == "10.0.0.9"


# ---------------------------------------------------------------------------
# Mismatch: refuse, never fall back
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_mismatch_refuses_before_authentication():
    pin = HostKeyPin.from_key(KEY_A, _HOST)
    api, store, router = _api(), MemoryPinStore(pin), FakeRouter(KEY_B)
    _guard_shared_transport(api)
    with _patched(router), pytest.raises(OpenWrtHostKeyMismatchError) as exc:
        await async_ssh_run_pinned(api, "sysupgrade -b -", pin_store=store)
    assert exc.value.reason == "mismatch"
    assert exc.value.expected_fingerprint == pin.fingerprint
    assert exc.value.host == _HOST
    assert router.auth_attempts == []  # password never reached the server
    assert len(router.connect_kwargs) == 1  # no second, unpinned attempt
    assert router.conns == []
    assert store.saved == [] and store.pin == pin  # pin not replaced
    api._asyncssh_run.assert_not_awaited()
    api._asyncssh_get_connection.assert_not_awaited()


@pytest.mark.asyncio
async def test_key_type_change_is_refused_as_mismatch():
    pin = HostKeyPin.from_key(KEY_A, _HOST)  # ed25519
    api, router = _api(), FakeRouter(KEY_ECDSA)
    _guard_shared_transport(api)
    with _patched(router), pytest.raises(OpenWrtHostKeyMismatchError) as exc:
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore(pin))
    assert exc.value.reason == "algorithm_unavailable"
    assert len(router.connect_kwargs) == 1
    assert router.auth_attempts == []


@pytest.mark.asyncio
async def test_mismatch_after_handshake_is_still_refused():
    """Defence in depth if asyncssh ever let a different key through."""
    pin = HostKeyPin.from_key(KEY_A, _HOST)
    api, router = _api(), FakeRouter(KEY_A)

    async def _lying_connect(host, **kw):
        conn = await router.connect(host, **kw)
        conn.get_server_host_key.return_value = KEY_B
        return conn

    with (
        patch(
            "custom_components.openwrt_router.api.asyncssh.connect",
            AsyncMock(side_effect=_lying_connect),
        ),
        pytest.raises(OpenWrtHostKeyMismatchError) as exc,
    ):
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore(pin))
    assert exc.value.presented_fingerprint == KEY_B.get_fingerprint("sha256")
    router.conns[0].create_process.assert_not_awaited()
    router.conns[0].close.assert_called_once()


def test_mismatch_error_is_not_a_connection_error():
    """Generic 'router unreachable, retry' handlers must not swallow it."""
    err = OpenWrtHostKeyMismatchError("mismatch", "x")
    assert isinstance(err, OpenWrtHostKeyError)
    assert not isinstance(err, OpenWrtConnectionError | OpenWrtTimeoutError)


# ---------------------------------------------------------------------------
# Pin store problems
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_failed_pin_save_refuses_the_command():
    api, router = _api(), FakeRouter(KEY_A)
    store = MemoryPinStore(fail_save=True)
    with _patched(router), pytest.raises(OpenWrtHostKeyError) as exc:
        await async_ssh_run_pinned(api, "sysupgrade -b -", pin_store=store)
    assert exc.value.reason == "pin_save_failed"
    # changed deliberately (finding 2): no login, no session, no command
    assert router.conns == [] and router.auth_attempts == []


@pytest.mark.asyncio
async def test_corrupt_pin_refuses_without_connecting():
    good = HostKeyPin.from_key(KEY_A, _HOST)
    bad = HostKeyPin.from_dict({**good.to_dict(), "fingerprint": "SHA256:forged"})
    api, router = _api(), FakeRouter(KEY_A)
    with _patched(router), pytest.raises(OpenWrtHostKeyError) as exc:
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore(bad))
    assert exc.value.reason == "pin_invalid"
    assert router.connect_kwargs == []


@pytest.mark.asyncio
async def test_unparsable_pin_refuses_without_connecting():
    good = HostKeyPin.from_key(KEY_A, _HOST)
    bad = HostKeyPin.from_dict({**good.to_dict(), "public_key": "not a key"})
    api, router = _api(), FakeRouter(KEY_A)
    with _patched(router), pytest.raises(OpenWrtHostKeyError) as exc:
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore(bad))
    assert exc.value.reason == "pin_invalid"
    assert router.connect_kwargs == []


# ---------------------------------------------------------------------------
# Authentication mirrors the shared transport, without changing its state
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_denied_retries_with_key_on_the_same_host_key():
    api, store = _api(), MemoryPinStore()
    router = FakeRouter(KEY_A, deny_password=True)
    with _patched(router):
        result = await async_ssh_run_pinned(api, "true", pin_store=store)
    # changed deliberately (finding 2): probe without credentials first
    assert [kw["password"] for kw in router.connect_kwargs] == [None, _PW, None]
    assert router.connect_kwargs[0]["client_keys"] is None
    # both logins trust only the key the probe captured
    for kw in router.connect_kwargs[1:]:
        assert [k.public_data for k in kw["known_hosts"][0]] == [KEY_A.public_data]
    assert result.pinned_now is True
    assert api._ssh_use_key is False  # shared transport state untouched


@pytest.mark.asyncio
async def test_first_use_retry_with_a_different_key_is_refused():
    api, store = _api(), MemoryPinStore()
    router = FakeRouter([KEY_A, KEY_B], deny_password=True)
    with _patched(router), pytest.raises(OpenWrtHostKeyMismatchError) as exc:
        await async_ssh_run_pinned(api, "true", pin_store=store)
    # changed deliberately (finding 2): the probe saw KEY_A (stored), the
    # login connection presented KEY_B and was refused before any password
    assert [p.fingerprint for p in store.saved] == [KEY_A.get_fingerprint("sha256")]
    assert exc.value.presented_fingerprint == KEY_B.get_fingerprint("sha256")
    assert router.auth_attempts == []


@pytest.mark.asyncio
async def test_key_auth_first_when_instance_already_uses_keys():
    api, router = _api(), FakeRouter(KEY_A)
    api._ssh_use_key = True
    with _patched(router):
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore())
    # changed deliberately (finding 2): probe (no credentials at all), then
    # key auth on the pinned connection
    assert [kw["password"] for kw in router.connect_kwargs] == [None, None]
    assert router.connect_kwargs[0]["client_keys"] is None
    assert "client_keys" not in router.connect_kwargs[1]


@pytest.mark.asyncio
async def test_both_auth_methods_denied():
    api, router = _api(), FakeRouter(KEY_A, deny_all=True)
    store = MemoryPinStore()
    with _patched(router), pytest.raises(OpenWrtAuthError):
        await async_ssh_run_pinned(api, "true", pin_store=store)
    # changed deliberately (finding 2): probe + two pinned logins; the key
    # was stored (tofu store) from the credential-less probe, before any login
    assert len(router.connect_kwargs) == 3
    assert len(store.saved) == 1


@pytest.mark.asyncio
async def test_password_never_in_the_command():
    api, router = _api(), FakeRouter(KEY_A)
    with _patched(router):
        await async_ssh_run_pinned(api, "sysupgrade -b -", pin_store=MemoryPinStore())
    cmd = router.conns[0].create_process.await_args.args[0]
    assert cmd == "sysupgrade -b -"
    assert _PW not in repr(router.conns[0].create_process.await_args)


# ---------------------------------------------------------------------------
# Transport errors, output handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connection_error_no_fallback():
    api = _api()
    _guard_shared_transport(api)
    router = FakeRouter(KEY_A, connect_error=OSError("no route"))
    with _patched(router), pytest.raises(OpenWrtConnectionError):
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore())
    assert len(router.connect_kwargs) == 1
    api._asyncssh_run.assert_not_awaited()


@pytest.mark.asyncio
async def test_timeout():
    api, router = _api(), FakeRouter(KEY_A, connect_delay=5)
    with _patched(router), pytest.raises(OpenWrtTimeoutError):
        await async_ssh_run_pinned(
            api, "true", pin_store=MemoryPinStore(), timeout=0.05
        )


@pytest.mark.asyncio
async def test_closing_api_refuses_early():
    api, router = _api(), FakeRouter(KEY_A)
    api._closing = True
    with _patched(router), pytest.raises(OpenWrtConnectionError):
        await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore())
    assert router.connect_kwargs == []


@pytest.mark.asyncio
async def test_binary_output_kept():
    blob = b"\x1f\x8b\x08\x00\x00binary\x00tar"
    api, router = _api(), FakeRouter(KEY_A, stdout=blob)
    with _patched(router):
        result = await async_ssh_run_pinned(
            api, "sysupgrade -b -", pin_store=MemoryPinStore(), binary=True
        )
    assert result.stdout == blob


@pytest.mark.asyncio
async def test_missing_exit_status_is_not_success():
    api, router = _api(), FakeRouter(KEY_A, exit_status=None)
    with _patched(router):
        result = await async_ssh_run_pinned(api, "true", pin_store=MemoryPinStore())
    assert result.exit_status == SUBPROCESS_RC_FAILED_TO_SPAWN


# ---------------------------------------------------------------------------
# Existing transport unchanged
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shared_transport_still_unpinned():
    """The appended block must not change the existing SSH path."""
    api = _api()
    conn = MagicMock()
    conn.run = AsyncMock(
        return_value=SimpleNamespace(exit_status=0, stdout=b"x", stderr=b"")
    )
    conn.is_closed = MagicMock(return_value=False)
    mock = AsyncMock(return_value=conn)
    with patch("custom_components.openwrt_router.api.asyncssh.connect", mock):
        await api._run_ssh("true")
    kw = mock.await_args.kwargs
    assert kw["known_hosts"] is None
    assert "client_factory" not in kw


# ---------------------------------------------------------------------------
# Pieces: pin model, client decision, asyncssh known_hosts semantics
# ---------------------------------------------------------------------------


def test_pin_round_trip_and_immutability():
    pin = HostKeyPin.from_key(KEY_A, _HOST)
    assert HostKeyPin.from_dict(pin.to_dict()) == pin
    assert hash(HostKeyPin.from_dict(pin.to_dict())) == hash(pin)
    assert pin.to_key().public_data == KEY_A.public_data
    assert pin.public_key.startswith("ssh-ed25519 ")
    with pytest.raises(AttributeError):
        pin.fingerprint = "SHA256:other"  # type: ignore[misc]
    assert pin.public_key not in repr(pin)
    with pytest.raises(TypeError):
        HostKeyPin.from_dict(["not", "a", "dict"])
    with pytest.raises(ValueError):
        HostKeyPin.from_dict({**pin.to_dict(), "host": ""})


def test_client_decision():
    # changed deliberately (finding 2): first contact captures and REFUSES
    first_use = _PinningSSHClient(None)
    assert first_use.validate_host_public_key(_HOST, _HOST, 22, KEY_B) is False
    assert first_use.presented_key is KEY_B
    pinned = _PinningSSHClient(KEY_A)
    assert pinned.validate_host_public_key(_HOST, _HOST, 22, KEY_B) is False
    assert pinned.validate_host_public_key(_HOST, _HOST, 22, KEY_A) is True


def test_asyncssh_known_hosts_tuple_semantics():
    """What _pinned_connect relies on in asyncssh itself (no network).

    A 3-tuple is used as (trusted, CA, revoked) without host matching; it is
    truthy even when empty, so asyncssh does not fall back to
    ~/.ssh/known_hosts; None would disable checking altogether.
    """
    trusted, ca, revoked, *_ = match_known_hosts(
        ([KEY_A], [], []), "h", "1.2.3.4", None
    )
    assert [k.public_data for k in trusted] == [KEY_A.public_data]
    assert list(ca) == [] and list(revoked) == []
    empty = ([], [], [])
    assert bool(empty) is True
    assert list(match_known_hosts(empty, "h", "1.2.3.4", None)[0]) == []


@pytest.mark.asyncio
async def test_store_base_is_abstract():
    store = HostKeyPinStore()
    with pytest.raises(NotImplementedError):
        await store.async_load_pin()
    with pytest.raises(NotImplementedError):
        await store.async_save_pin(HostKeyPin.from_key(KEY_A, _HOST))
