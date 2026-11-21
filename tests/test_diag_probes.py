"""Network diagnostics, HA side of api.py (release 1.47.0, part 1).

Probes run against loopback servers only: a vetted global address
(``9.9.9.9``; loopback and documentation addresses are refused by the target
registry) is redirected to ``127.0.0.1`` by a test ``DiagTransport``. The
conftest network guard stays in force. No router, no Home Assistant.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import struct
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from custom_components.openwrt_router import api as api_module
from custom_components.openwrt_router.api import (
    DIAG_REASON_ICMP_NOT_ON_HA,
    DIAG_REASON_NO_QUERY_NAME,
    DIAG_REASON_QUERY_NOT_ALLOWED,
    DIAG_REASON_REDIRECT,
    DiagTransport,
    async_diag_dns_probe,
    async_diag_http_probe,
    async_diag_probe,
    async_diag_resolve,
    async_diag_tcp_probe,
    diag_interface_facts,
)
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    Stage,
)
from custom_components.openwrt_router.diag_targets import (
    PinnedTarget,
    Refusal,
    ScopePolicy,
    TargetRegistry,
    TargetScope,
    make_target,
)
from custom_components.openwrt_router.diagnostics import _redact

GLOBAL_IP = "9.9.9.9"


def registry(*targets: Any) -> TargetRegistry:
    reg, refused = TargetRegistry.build(ScopePolicy(), list(targets))
    assert refused == []
    return reg


def pinned(target_id: str, kind: str, port: int | None = None) -> PinnedTarget:
    target = make_target(
        target_id, kind, "external", GLOBAL_IP, port=port, confirmed=True
    )
    resolved = registry(target).resolve(target_id)
    assert isinstance(resolved, PinnedTarget)
    return resolved


@contextlib.asynccontextmanager
async def tcp_server(reply: bytes | None = None) -> AsyncIterator[tuple[int, list]]:
    """Loopback TCP server; with ``reply``: read the request, answer, close."""
    requests: list[bytes] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if reply is not None:
            with contextlib.suppress(Exception):
                requests.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(reply)
                await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], requests
    finally:
        server.close()
        await server.wait_closed()


class DnsServer(asyncio.DatagramProtocol):
    """Loopback resolver: answers every query with ``rcode`` (and ``bad_id``)."""

    def __init__(self, rcode: int = 0, *, bad_id: bool = False) -> None:
        self.rcode = rcode
        self.bad_id = bad_id
        self.queries: list[bytes] = []
        self.transport: Any = None

    def connection_made(self, transport: Any) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Any) -> None:
        self.queries.append(data)
        ident = struct.unpack("!H", data[:2])[0] ^ (1 if self.bad_id else 0)
        head = struct.pack("!HHHHHH", ident, 0x8180 | self.rcode, 1, 0, 0, 0)
        self.transport.sendto(head + data[12:], addr)


@contextlib.asynccontextmanager
async def dns_server(**kw: Any) -> AsyncIterator[tuple[int, DnsServer]]:
    server = DnsServer(**kw)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: server, local_addr=("127.0.0.1", 0)
    )
    try:
        yield transport.get_extra_info("sockname")[1], server
    finally:
        transport.close()


def loopback(
    tcp: dict[int, int] | None = None, udp: int | None = None, seen: list | None = None
) -> DiagTransport:
    """Redirect the vetted address to loopback ports (target port -> local)."""
    seen = seen if seen is not None else []

    async def open_connection(host: str, port: int, **kw: Any) -> Any:
        seen.append(("tcp", host, port))
        return await asyncio.open_connection("127.0.0.1", (tcp or {})[port])

    async def exchange(host: str, port: int, payload: bytes, timeout: float) -> bytes:
        seen.append(("udp", host, port))
        assert udp is not None
        return await api_module._diag_exchange_datagram(
            "127.0.0.1", udp, payload, timeout
        )

    async def getaddrinfo(host: str, port: int) -> list[Any]:
        raise AssertionError("no resolver in this test")

    return DiagTransport(
        open_connection=open_connection,
        exchange_datagram=exchange,
        getaddrinfo=getaddrinfo,
    )


def allow(name: Any, scope: TargetScope) -> bool:
    return True


# --- probes against loopback ---------------------------------------------------------


async def test_tcp_probe_connects_and_measures() -> None:
    target = pinned("t1", "tcp", 443)
    seen: list = []
    async with tcp_server() as (port, _):
        result = await async_diag_tcp_probe(
            target, stage=Stage.INTERNET, transport=loopback({443: port}, seen=seen)
        )
    assert result.outcome is ProbeOutcome.OK
    assert result.kind is ProbeKind.TCP and result.family is AddressFamily.IPV4
    assert result.point == MeasurementPoint.ha() and result.subject is None
    assert result.rtt_ms is not None and result.rtt_ms >= 0
    assert seen == [("tcp", GLOBAL_IP, 443)]  # the pinned address, nothing else


async def test_tcp_probe_failures_are_results_not_exceptions() -> None:
    target = pinned("t1", "tcp", 443)

    async def refused(host: str, port: int, **kw: Any) -> Any:
        raise ConnectionRefusedError

    async def hang(host: str, port: int, **kw: Any) -> Any:
        await asyncio.Event().wait()

    async def boom(host: str, port: int, **kw: Any) -> Any:
        raise RuntimeError(GLOBAL_IP)

    out = await async_diag_tcp_probe(
        target, stage=Stage.INTERNET, transport=DiagTransport(open_connection=refused)
    )
    assert out.outcome is ProbeOutcome.REFUSED and out.received == 1
    out = await async_diag_tcp_probe(
        target,
        stage=Stage.INTERNET,
        timeout=0.05,
        transport=DiagTransport(open_connection=hang),
    )
    assert out.outcome is ProbeOutcome.TIMEOUT
    out = await async_diag_tcp_probe(
        target, stage=Stage.INTERNET, transport=DiagTransport(open_connection=boom)
    )
    assert out.outcome is ProbeOutcome.ERROR
    assert GLOBAL_IP not in json.dumps(dict(out.evidence))


async def test_dns_probe_against_a_loopback_resolver() -> None:
    target = pinned("d1", "dns")
    async with dns_server() as (port, server):
        ok = await async_diag_dns_probe(
            target,
            query_name="example.org",
            may_query=allow,
            transport=loopback(udp=port),
        )
    assert ok.outcome is ProbeOutcome.OK and ok.evidence["rcode"] == 0
    assert len(server.queries) == 1
    async with dns_server(rcode=3) as (port, _):
        nx = await async_diag_dns_probe(
            target,
            query_name="example.org",
            may_query=allow,
            transport=loopback(udp=port),
        )
    assert nx.outcome is ProbeOutcome.NXDOMAIN
    async with dns_server(bad_id=True) as (port, _):
        bad = await async_diag_dns_probe(
            target,
            query_name="example.org",
            may_query=allow,
            transport=loopback(udp=port),
        )
    assert bad.outcome is ProbeOutcome.ERROR


async def test_dns_probe_sends_nothing_without_a_permitted_name() -> None:
    target = pinned("d1", "dns")
    exchange = AsyncMock()
    transport = DiagTransport(exchange_datagram=exchange)
    none = await async_diag_dns_probe(
        target, query_name=None, may_query=allow, transport=transport
    )
    assert none.outcome is ProbeOutcome.SKIPPED
    assert none.evidence["reason"] == DIAG_REASON_NO_QUERY_NAME
    denied = await async_diag_dns_probe(
        target,
        query_name="nas.lan",
        may_query=lambda name, scope: False,
        transport=transport,
    )
    assert denied.evidence["reason"] == DIAG_REASON_QUERY_NOT_ALLOWED
    exchange.assert_not_called()


async def test_http_probe_reads_the_status_line_only() -> None:
    target = pinned("h1", "http", 80)
    async with tcp_server(b"HTTP/1.1 204 No Content\r\n\r\n") as (port, requests):
        ok = await async_diag_http_probe(
            target, stage=Stage.INTERNET, transport=loopback({80: port})
        )
    assert ok.outcome is ProbeOutcome.OK and ok.evidence["status"] == 204
    request = requests[0].decode("ascii")
    assert request.startswith("GET /generate_204 HTTP/1.1\r\n")
    for banned in ("Authorization", "Cookie", "Content-Length"):
        assert banned not in request
    async with tcp_server(b"HTTP/1.1 301 Moved\r\nLocation: x\r\n\r\n") as (
        port,
        _,
    ):
        moved = await async_diag_http_probe(
            target, stage=Stage.INTERNET, transport=loopback({80: port})
        )
    assert moved.outcome is ProbeOutcome.FAILED
    assert moved.evidence["reason"] == DIAG_REASON_REDIRECT


async def test_icmp_is_skipped_on_the_ha_side_without_a_packet() -> None:
    target = pinned("i1", "icmp")
    transport = DiagTransport(
        open_connection=AsyncMock(), exchange_datagram=AsyncMock()
    )
    out = await async_diag_probe(
        target, stage=Stage.INTERNET, may_query=allow, transport=transport
    )
    assert out.outcome is ProbeOutcome.SKIPPED
    assert out.evidence["reason"] == DIAG_REASON_ICMP_NOT_ON_HA
    transport.open_connection.assert_not_called()
    transport.exchange_datagram.assert_not_called()


async def test_probes_take_a_pinned_target_only() -> None:
    raw = make_target("t1", "tcp", "external", GLOBAL_IP, port=1, confirmed=True)
    with pytest.raises(TypeError):
        await async_diag_probe(raw, stage=Stage.INTERNET, may_query=allow)


# --- resolution ------------------------------------------------------------------------


def _infos(*addresses: str) -> list[Any]:
    return [(2, 1, 6, "", (a, 0)) for a in addresses]


async def test_resolution_vets_every_address_before_pinning() -> None:
    target = make_target(
        "n1", "tcp", "external", "example.org", port=443, confirmed=True
    )
    reg = registry(target)

    async def answer(*addresses: str) -> Any:
        return await async_diag_resolve(
            reg,
            "n1",
            transport=DiagTransport(
                getaddrinfo=AsyncMock(return_value=_infos(*addresses))
            ),
        )

    good = await answer(GLOBAL_IP)
    assert isinstance(good, PinnedTarget) and good.host == GLOBAL_IP
    rebound = await answer(GLOBAL_IP, "192.168.1.1")  # DNS rebinding attempt
    assert isinstance(rebound, Refusal)
    failing = await async_diag_resolve(
        reg, "n1", transport=DiagTransport(getaddrinfo=AsyncMock(side_effect=OSError))
    )
    assert failing is Refusal.RESOLVED_EMPTY


async def test_unconfirmed_external_target_is_refused_without_a_lookup() -> None:
    target = make_target("n1", "tcp", "external", "example.org", port=443)
    lookup = AsyncMock()
    out = await async_diag_resolve(
        registry(target), "n1", transport=DiagTransport(getaddrinfo=lookup)
    )
    assert out is Refusal.NOT_CONFIRMED
    lookup.assert_not_called()


async def test_internal_name_is_never_sent_to_an_external_resolver() -> None:
    policy = ScopePolicy.from_config(["192.168.0.0/16"], ["lan"])
    target = make_target("n1", "tcp", "internal", "nas.lan", port=445)
    reg, _ = TargetRegistry.build(policy, [target])
    lookup = AsyncMock()
    out = await async_diag_resolve(
        reg,
        "n1",
        resolver_scope=TargetScope.EXTERNAL,
        transport=DiagTransport(getaddrinfo=lookup),
    )
    assert out is Refusal.INTERNAL_NAME
    lookup.assert_not_called()


# --- interface dump facts -------------------------------------------------------------


def _dump(*, wan_up: bool = True, gw: str = "192.0.2.1") -> list[dict[str, Any]]:
    return [
        {"interface": "loopback", "up": True, "l3_device": "lo"},
        {
            "interface": "lan",
            "up": True,
            "proto": "static",
            "dns-server": ["192.0.2.54"],
            "ipv6-address": [{"address": "fd00::1", "mask": 64}],
        },
        {
            "interface": "wan",
            "up": wan_up,
            "proto": "dhcp",
            "uptime": 3600,
            "l3_device": "wan",
            "ipv4-address": [{"address": "203.0.113.42", "mask": 24}],
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": gw}]
            if wan_up
            else [],
            "dns-server": ["192.0.2.53", "192.0.2.53"],
        },
        {
            "interface": "wan6",
            "up": wan_up,
            "proto": "dhcpv6",
            "route": [{"target": "::", "mask": 0, "nexthop": "fe80::1"}],
            "ipv6-address": [{"address": "2001:db8::5", "mask": 64}],
        },
    ]


def test_interface_facts_from_the_dump() -> None:
    dump = _dump()
    facts = diag_interface_facts(dump, dump[2])
    assert facts == {
        "version": 1,
        "interfaces": 3,  # loopback left out
        "interfaces_up": 3,
        "ipv4_default_route": True,
        "ipv6_default_route": True,
        "ipv4_gateway": {"address": "192.0.2.1"},
        "ipv6_gateway": {"address": "fe80::1"},
        "dns_servers": [{"address": "192.0.2.53"}, {"address": "192.0.2.54"}],
        "ipv6_global_address": False,  # 2001:db8::/32 is documentation
    }
    down = diag_interface_facts(_dump(wan_up=False), None)
    assert down["interfaces_up"] == 1 and down["ipv4_default_route"] is False


@pytest.mark.parametrize("garbage", [None, "x", [1, None, "a"], [{"route": "x"}]])
def test_interface_facts_never_raise(garbage: Any) -> None:
    facts = diag_interface_facts(garbage)
    assert facts["interfaces_up"] == 0 and facts["dns_servers"] == []


def test_diagnostics_redaction_removes_the_fact_addresses() -> None:
    dump = _dump()
    text = json.dumps(
        _redact({"wan_status": {"diag_facts": diag_interface_facts(dump, dump[2])}})
    )
    for secret in ("192.0.2.1", "192.0.2.53", "fe80::1"):
        assert secret not in text


# --- WAN status: additive only --------------------------------------------------------


def _ubus(dump: list[dict[str, Any]]) -> Any:
    async def _call(obj: str, method: str, params: Any = None, **kw: Any) -> Any:
        if (obj, method) == ("network.interface", "dump"):
            return {"interface": dump}
        if (obj, method) == ("network.device", "status"):
            return {"statistics": {"rx_bytes": 10, "tx_bytes": 20}}
        raise api_module.OpenWrtMethodNotFoundError(f"{obj}/{method}")

    return _call


@pytest.mark.parametrize(
    "dump",
    [
        _dump(),
        _dump(wan_up=False),
        [{"interface": "lan", "up": True, "proto": "static"}],  # no WAN at all
    ],
)
async def test_wan_fields_unchanged_byte_for_byte(mock_api, dump) -> None:
    mock_api._call = AsyncMock(side_effect=_ubus(dump))
    mock_api._asyncssh_run = AsyncMock()
    with patch.object(api_module, "_diag_add_facts", lambda *a, **kw: None):
        before = await mock_api.get_wan_status()
    after = await mock_api.get_wan_status()
    assert "diag_facts" not in before and "diag_facts" in after
    assert list(after)[-1] == "diag_facts"  # appended, existing order kept
    rest = {k: v for k, v in after.items() if k != "diag_facts"}
    assert json.dumps(rest) == json.dumps(before)  # byte for byte, same order
    mock_api._asyncssh_run.assert_not_awaited()


async def test_broken_fact_reader_leaves_the_wan_status_alone(mock_api) -> None:
    mock_api._call = AsyncMock(side_effect=_ubus(_dump()))
    mock_api._asyncssh_run = AsyncMock()
    with patch.object(api_module, "_diag_add_facts", lambda *a, **kw: None):
        before = await mock_api.get_wan_status()
    with patch.object(
        api_module, "diag_interface_facts", side_effect=RuntimeError("x")
    ):
        after = await mock_api.get_wan_status()
    assert json.dumps(after) == json.dumps(before)
