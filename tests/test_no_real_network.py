"""The test suite never opens a real network connection (see conftest.py)."""
from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest
from conftest import RealNetworkBlockedError


async def test_default_probe_result_is_a_fixed_failure():
    with pytest.raises(OSError, match="blocked by the test suite"):
        await asyncio.open_connection("8.8.8.8", 53)
    with pytest.raises(OSError):
        await asyncio.wait_for(asyncio.open_connection("8.8.8.8", 53), timeout=3.0)


async def test_override_succeed_and_fail_again(network_stub):
    network_stub.succeed()
    _, writer = await asyncio.open_connection("8.8.8.8", 53)
    writer.close()
    await writer.wait_closed()
    assert network_stub.calls == [("8.8.8.8", 53)]

    network_stub.fail(TimeoutError("slow"))
    with pytest.raises(TimeoutError, match="slow"):
        await asyncio.open_connection("8.8.8.8", 53)
    network_stub.fail()
    with pytest.raises(OSError, match="blocked by the test suite"):
        await asyncio.open_connection("8.8.8.8", 53)


async def test_local_patch_still_wins():
    with patch("asyncio.open_connection", side_effect=OSError("mine")):
        with pytest.raises(OSError, match="mine"):
            await asyncio.open_connection("8.8.8.8", 53)


async def test_coordinator_probe_sees_the_default_and_the_override(network_stub):
    from test_coordinator import _make_coordinator

    coord, _api = _make_coordinator()
    await coord._async_update_data()
    data = await coord._async_update_data()
    assert data.ping_checked is True and data.ping_ms is None

    network_stub.succeed()
    data = await coord._async_update_data()
    assert isinstance(data.ping_ms, float)


def test_raw_socket_create_connection_is_refused(network_stub):
    with pytest.raises(RealNetworkBlockedError) as err:
        socket.create_connection(("8.8.8.8", 53), timeout=1)
    assert "test_raw_socket_create_connection_is_refused" in str(err.value)
    assert network_stub.violations
    network_stub.violations.clear()  # provoked on purpose


async def test_asyncio_loop_level_connect_is_refused(network_stub):
    loop = asyncio.get_running_loop()
    with pytest.raises(RealNetworkBlockedError):
        await asyncio.streams.open_connection("8.8.8.8", 53)  # not the stubbed name
    with pytest.raises(RealNetworkBlockedError):
        await loop.create_connection(asyncio.Protocol, "8.8.8.8", 53)
    with socket.socket() as sock, pytest.raises(RealNetworkBlockedError):
        sock.setblocking(False)
        await loop.sock_connect(sock, ("8.8.8.8", 53))
    assert len(network_stub.violations) == 3
    network_stub.violations.clear()


def test_loopback_and_unix_stay_allowed():
    a, b = socket.socketpair()
    a.close()
    b.close()
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen()
    cli = socket.create_connection(srv.getsockname(), timeout=2)
    cli.close()
    srv.close()
