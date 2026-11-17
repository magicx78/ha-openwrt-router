"""Tests for the ubus SSE stream client in api.py (RT2).

No network: a fake aiohttp session/response replays chunked SSE bodies and the
JSON error bodies uhttpd sends (-13, not found) or a 404.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator
from typing import Any
from unittest.mock import AsyncMock

import aiohttp
import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAPI,
    OpenWrtAuthBackoffError,
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtResponseError,
    OpenWrtStreamError,
    OpenWrtStreamNotFoundError,
    OpenWrtStreamPermissionError,
    OpenWrtTimeoutError,
    SseParser,
    SseStats,
    parse_sse,
    stream_error_from_payload,
    validate_stream_object,
)
from custom_components.openwrt_router.const import (
    STREAM_CONNECT_TIMEOUT,
    STREAM_IDLE_TIMEOUT,
)

TOKEN_A = "a" * 32
TOKEN_B = "b" * 32

PROBE = b'event: probe\ndata: {"address":"aa:bb:cc:dd:ee:ff","signal":-71}\n\n'
LINK = b'event: link-measurement-report\ndata: {"address":"11:22:33:44:55:66","rcpi":74}\n\n'


# =====================================================================
# Fakes
# =====================================================================


class FakeContent:
    """Stands in for ``resp.content`` (only ``iter_any`` is used)."""

    def __init__(
        self,
        chunks: list[bytes],
        *,
        end_exc: BaseException | None = None,
        block: bool = False,
    ) -> None:
        self._chunks = chunks
        self._end_exc = end_exc
        self._block = block

    async def iter_any(self) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            await asyncio.sleep(0)
            yield chunk
        if self._end_exc is not None:
            raise self._end_exc
        if self._block:
            await asyncio.Event().wait()


class FakeResponse:
    """Minimal aiohttp.ClientResponse replacement."""

    def __init__(
        self,
        *,
        status: int = 200,
        content_type: str = "text/event-stream",
        chunks: list[bytes] | None = None,
        end_exc: BaseException | None = None,
        block: bool = False,
    ) -> None:
        self.status = status
        self.content_type = content_type
        self.content = FakeContent(chunks or [], end_exc=end_exc, block=block)
        self.closed = False
        self.released = False

    def close(self) -> None:
        self.closed = True


def sse(*chunks: bytes, block: bool = False, **kw: Any) -> FakeResponse:
    """An SSE response with the given chunks."""
    return FakeResponse(chunks=list(chunks), block=block, **kw)


def json_body(body: bytes, status: int = 200) -> FakeResponse:
    """A JSON (error) response."""
    return FakeResponse(status=status, content_type="application/json", chunks=[body])


class FakeCM:
    def __init__(self, item: FakeResponse | BaseException) -> None:
        self._item = item

    async def __aenter__(self) -> FakeResponse:
        if isinstance(self._item, BaseException):
            raise self._item
        return self._item

    async def __aexit__(self, *exc: object) -> bool:
        if isinstance(self._item, FakeResponse):
            self._item.released = True
        return False


class FakeSession:
    """Records GET calls and hands out scripted responses."""

    def __init__(self, items: list[FakeResponse | BaseException]) -> None:
        self.items = list(items)
        self.calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> FakeCM:
        self.calls.append({"url": url, **kwargs})
        if not self.items:
            raise AssertionError("unexpected GET")
        return FakeCM(self.items.pop(0))

    def post(self, *args: Any, **kwargs: Any) -> Any:
        raise AssertionError("no JSON-RPC expected in stream tests")


def make_api(
    items: list[FakeResponse | BaseException], *, token: str = TOKEN_A
) -> tuple[OpenWrtAPI, FakeSession]:
    session = FakeSession(items)
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="test",
        session=session,  # type: ignore[arg-type]
        protocol="http",
    )
    api._token = token
    api._token_expires_at = time.monotonic() + 3600
    return api, session


def fake_login(api: OpenWrtAPI, tokens: list[str]) -> AsyncMock:
    """Replace api.login with a mock that hands out the next token."""

    async def _login() -> bool:
        await asyncio.sleep(0)
        api._token = tokens.pop(0)
        api._token_expires_at = time.monotonic() + 3600
        return True

    mock = AsyncMock(side_effect=_login)
    api.login = mock  # type: ignore[method-assign]
    return mock


async def collect(api: OpenWrtAPI, obj: str = "hostapd.phy0-ap0", **kw: Any) -> list:
    return [item async for item in api.async_subscribe(obj, **kw)]


# =====================================================================
# Parser
# =====================================================================


class TestSseParser:
    def test_single_event(self) -> None:
        assert parse_sse([PROBE]) == [
            ("probe", {"address": "aa:bb:cc:dd:ee:ff", "signal": -71})
        ]

    def test_every_split_point_gives_same_result(self) -> None:
        body = PROBE + LINK
        expected = parse_sse([body])
        assert len(expected) == 2
        for i in range(len(body) + 1):
            assert parse_sse([body[:i], body[i:]]) == expected, i

    def test_byte_by_byte(self) -> None:
        body = PROBE + LINK
        assert parse_sse([body[i : i + 1] for i in range(len(body))]) == parse_sse(
            [body]
        )

    def test_crlf_and_split_between_cr_and_lf(self) -> None:
        body = (PROBE + LINK).replace(b"\n", b"\r\n")
        expected = parse_sse([PROBE + LINK])
        assert parse_sse([body]) == expected
        cut = body.index(b"\r\n") + 1  # chunk ends with \r
        assert parse_sse([body[:cut], body[cut:]]) == expected
        for i in range(len(body) + 1):
            assert parse_sse([body[:i], body[i:]]) == expected, i

    def test_multiple_data_lines_joined_with_newline(self) -> None:
        body = b'event: assoc\ndata: {"address":\ndata: "x",\ndata:"n": 1}\n\n'
        assert parse_sse([body]) == [("assoc", {"address": "x", "n": 1})]

    def test_comments_id_retry_and_default_event_name(self) -> None:
        stats = SseStats()
        body = b": keepalive\nretry: 3000\nid: 7\ndata: {}\n\n"
        assert parse_sse([body], stats=stats) == [("message", {})]
        assert stats.retry_ms == 3000
        assert stats.events == 1

    def test_bad_retry_value_ignored(self) -> None:
        stats = SseStats()
        parse_sse([b"retry: soon\n\n"], stats=stats)
        assert stats.retry_ms is None

    def test_several_events_in_one_chunk_and_name_reset(self) -> None:
        body = PROBE + b'data: {"a":1}\n\n' + LINK
        events = parse_sse([body])
        assert [e for e, _ in events] == ["probe", "message", "link-measurement-report"]

    def test_event_without_data_is_not_dispatched(self) -> None:
        assert parse_sse([b"event: auth\n\n"]) == []
        # ...and its name does not leak into the next event
        assert parse_sse([b"event: auth\n\ndata: {}\n\n"]) == [("message", {})]

    def test_incomplete_trailing_event_is_not_dispatched(self) -> None:
        assert parse_sse([b'event: probe\ndata: {"a":1}\n']) == []

    def test_str_chunks_and_split_utf8(self) -> None:
        body = 'data: {"ssid":"Grüße"}\n\n'.encode()
        cut = body.index("ü".encode()) + 1  # inside the 2-byte sequence
        assert parse_sse([body[:cut], body[cut:]]) == [("message", {"ssid": "Grüße"})]
        assert parse_sse(['data: {"ok":true}\n\n']) == [("message", {"ok": True})]

    def test_oversize_event_dropped_and_counted(self) -> None:
        stats = SseStats()
        big = b'data: {"x":"' + b"y" * 200 + b'"}\n\n'
        out = parse_sse([big, PROBE], max_event_bytes=100, stats=stats)
        assert [e for e, _ in out] == ["probe"]
        assert stats.oversize == 1
        assert stats.events == 1

    def test_oversize_by_many_data_lines(self) -> None:
        stats = SseStats()
        body = b"event: x\n" + b"data: 1234567890\n" * 20 + b"\n"
        out = parse_sse([body, PROBE], max_event_bytes=100, stats=stats)
        assert [e for e, _ in out] == ["probe"]
        assert stats.oversize == 1

    def test_overlong_line_across_chunks_keeps_memory_bounded(self) -> None:
        stats = SseStats()
        parser = SseParser(max_event_bytes=100, stats=stats)
        assert parser.feed(b"data: " + b"z" * 80) == []
        for _ in range(50):
            assert parser.feed(b"z" * 80) == []
            assert len(parser._buf) <= 100
        out = parser.feed(b"zzz\n\n" + PROBE)
        assert [e for e, _ in out] == ["probe"]
        assert stats.oversize == 1

    @pytest.mark.parametrize(
        "data",
        [
            b"data: {not json}\n\n",
            b"data: [1, 2]\n\n",
            b"data: 42\n\n",
            b"data: \xff\xfe\n\n",
        ],
    )
    def test_bad_json_dropped_and_counted(self, data: bytes) -> None:
        stats = SseStats()
        out = parse_sse([data, PROBE], stats=stats)
        assert [e for e, _ in out] == ["probe"]
        assert stats.bad_json == 1


# =====================================================================
# Object validation and error mapping
# =====================================================================


class TestValidateStreamObject:
    @pytest.mark.parametrize(
        "obj", ["hostapd", "hostapd.phy0-ap0", "hostapd.phy1-ap1_guest", "log"]
    )
    def test_valid(self, obj: str) -> None:
        assert validate_stream_object(obj) == obj

    @pytest.mark.parametrize(
        "obj",
        [
            "",
            "hostapd-auth",
            "a/b",
            "../system",
            "..",
            ".",
            "hostapd phy0",
            "hostapd?x=1",
            "hostapd%2F",
            "x" * 129,
            None,
        ],
    )
    def test_invalid(self, obj: Any) -> None:
        with pytest.raises(ValueError):
            validate_stream_object(obj)

    async def test_subscribe_rejects_hostapd_auth_without_http(self) -> None:
        api, session = make_api([])
        with pytest.raises(ValueError, match="hostapd-auth"):
            await collect(api, "hostapd-auth")
        assert session.calls == []


class TestStreamErrorFromPayload:
    @pytest.mark.parametrize(
        ("payload", "exc_type"),
        [
            (
                {"code": -13, "message": "Permission denied"},
                OpenWrtStreamPermissionError,
            ),
            (
                {"error": {"code": -32002, "message": "Access denied"}},
                OpenWrtStreamPermissionError,
            ),
            (
                {"code": -2, "message": "No such file or directory"},
                OpenWrtStreamNotFoundError,
            ),
            ({"code": 4, "message": "Not found"}, OpenWrtStreamNotFoundError),
            ({"code": 99, "message": "Object not found"}, OpenWrtStreamNotFoundError),
        ],
    )
    def test_mapping(self, payload: Any, exc_type: type) -> None:
        assert type(stream_error_from_payload(payload, "hostapd")) is exc_type

    @pytest.mark.parametrize("payload", [{"code": -5, "message": "I/O error"}, [], "x"])
    def test_other_errors_generic(self, payload: Any) -> None:
        err = stream_error_from_payload(payload, "hostapd")
        assert type(err) is OpenWrtStreamError

    def test_hierarchy_never_auth_error(self) -> None:
        for exc in (OpenWrtStreamPermissionError, OpenWrtStreamNotFoundError):
            assert issubclass(exc, OpenWrtStreamError)
            assert issubclass(exc, OpenWrtResponseError)
            assert not issubclass(exc, OpenWrtAuthError)


# =====================================================================
# async_subscribe
# =====================================================================


class TestAsyncSubscribe:
    async def test_happy_path_yields_events_and_closes(self) -> None:
        body = PROBE + LINK
        resp = sse(body[:17], body[17:90], body[90:])
        api, session = make_api([resp])
        opened: list[int] = []
        stats = SseStats()

        events = await collect(
            api, on_open=lambda: opened.append(len(opened)), stats=stats
        )

        assert [e for e, _ in events] == ["probe", "link-measurement-report"]
        assert events[1][1] == {"address": "11:22:33:44:55:66", "rcpi": 74}
        assert opened == [0]
        assert stats.events == 2
        assert resp.closed and resp.released
        (call,) = session.calls
        assert call["url"] == "http://192.168.1.1:80/ubus/subscribe/hostapd.phy0-ap0"
        assert call["headers"]["Authorization"] == f"Bearer {TOKEN_A}"
        assert call["ssl"] is api._ssl_context
        timeout = call["timeout"]
        assert isinstance(timeout, aiohttp.ClientTimeout)
        assert timeout.total is None
        assert timeout.sock_connect == STREAM_CONNECT_TIMEOUT
        assert timeout.sock_read == STREAM_IDLE_TIMEOUT

    async def test_bearer_uses_current_token(self) -> None:
        api, session = make_api([sse(PROBE), sse(PROBE)])
        await collect(api)
        api._token = TOKEN_B
        await collect(api)
        assert [c["headers"]["Authorization"] for c in session.calls] == [
            f"Bearer {TOKEN_A}",
            f"Bearer {TOKEN_B}",
        ]

    async def test_expired_token_logs_in_first(self) -> None:
        api, session = make_api([sse(PROBE)])
        api._token_expires_at = 0.0
        login = fake_login(api, [TOKEN_B])
        await collect(api)
        login.assert_awaited_once()
        assert session.calls[0]["headers"]["Authorization"] == f"Bearer {TOKEN_B}"

    async def test_concurrent_subscribes_log_in_once(self) -> None:
        api, session = make_api([sse(PROBE), sse(PROBE), sse(PROBE)])
        api._token_expires_at = 0.0
        login = fake_login(api, [TOKEN_B, "c" * 32, "d" * 32])
        await asyncio.gather(*(collect(api, f"hostapd.phy{i}-ap0") for i in range(3)))
        assert login.await_count == 1
        assert {c["headers"]["Authorization"] for c in session.calls} == {
            f"Bearer {TOKEN_B}"
        }

    async def test_permission_denied_minus_13_after_relogin(self) -> None:
        body = b'{"code":-13,"message":"Permission denied"}'
        first, second = json_body(body), json_body(body)
        api, session = make_api([first, second])
        login = fake_login(api, [TOKEN_B])

        with pytest.raises(OpenWrtStreamPermissionError):
            await collect(api)

        login.assert_awaited_once()
        assert [c["headers"]["Authorization"] for c in session.calls] == [
            f"Bearer {TOKEN_A}",
            f"Bearer {TOKEN_B}",
        ]
        assert first.closed and second.closed

    async def test_minus_13_with_stale_session_recovers_after_relogin(self) -> None:
        stale = json_body(b'{"code":-13,"message":"Permission denied"}')
        api, session = make_api([stale, sse(PROBE)])
        fake_login(api, [TOKEN_B])
        events = await collect(api)
        assert [e for e, _ in events] == ["probe"]
        assert len(session.calls) == 2

    async def test_minus_13_no_relogin_when_token_already_replaced(self) -> None:
        """Another stream re-logged in meanwhile: just retry with its token."""
        api, session = make_api([])
        login = fake_login(api, ["x" * 32])

        def _get(url: str, **kw: Any) -> FakeCM:
            session.calls.append({"url": url, **kw})
            if len(session.calls) == 1:
                api._token = TOKEN_B  # concurrent re-login by someone else
                return FakeCM(json_body(b'{"code":-13}'))
            return FakeCM(sse(PROBE))

        session.get = _get  # type: ignore[method-assign]
        await collect(api)
        login.assert_not_awaited()
        assert session.calls[1]["headers"]["Authorization"] == f"Bearer {TOKEN_B}"

    async def test_http_404_not_found(self) -> None:
        resp = FakeResponse(status=404, content_type="text/html")
        api, session = make_api([resp])
        login = fake_login(api, [TOKEN_B])
        with pytest.raises(OpenWrtStreamNotFoundError):
            await collect(api)
        login.assert_not_awaited()
        assert len(session.calls) == 1
        assert resp.closed

    async def test_ubus_not_found_json(self) -> None:
        resp = json_body(b'{"code":-2,"message":"No such file or directory"}')
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtStreamNotFoundError):
            await collect(api)
        assert resp.closed

    async def test_http_403_is_permission(self) -> None:
        api, _ = make_api([FakeResponse(status=403), FakeResponse(status=403)])
        fake_login(api, [TOKEN_B])
        with pytest.raises(OpenWrtStreamPermissionError):
            await collect(api)

    async def test_http_500_generic_error(self) -> None:
        api, _ = make_api([FakeResponse(status=500, content_type="text/plain")])
        with pytest.raises(OpenWrtStreamError) as info:
            await collect(api)
        assert type(info.value) is OpenWrtStreamError

    async def test_wrong_content_type(self) -> None:
        resp = FakeResponse(content_type="text/html", chunks=[b"<html>hi</html>"])
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtStreamError, match="content type") as info:
            await collect(api)
        assert type(info.value) is OpenWrtStreamError
        assert resp.closed

    async def test_auth_backoff_blocks_without_http(self) -> None:
        api, session = make_api([sse(PROBE)])
        api._auth_failure_count = 3
        api._auth_backoff_until = time.monotonic() + 60
        with pytest.raises(OpenWrtAuthBackoffError):
            await collect(api)
        assert session.calls == []

    async def test_login_failure_counts(self) -> None:
        api, session = make_api([])
        api._token_expires_at = 0.0
        api.login = AsyncMock(side_effect=OpenWrtAuthError("bad"))  # type: ignore[method-assign]
        with pytest.raises(OpenWrtAuthError):
            await collect(api)
        assert api._auth_failure_count == 1
        assert session.calls == []

    async def test_closing_api_rejects(self) -> None:
        api, session = make_api([sse(PROBE)])
        api._closing = True
        with pytest.raises(OpenWrtConnectionError):
            await collect(api)
        assert session.calls == []

    async def test_connect_error_mapped(self) -> None:
        api, _ = make_api([aiohttp.ClientConnectionError("refused")])
        with pytest.raises(OpenWrtConnectionError):
            await collect(api)

    async def test_connect_timeout_mapped(self) -> None:
        api, _ = make_api([TimeoutError()])
        with pytest.raises(OpenWrtTimeoutError):
            await collect(api)

    async def test_stream_abort_mid_event_maps_and_closes(self) -> None:
        resp = sse(
            PROBE, b"event: assoc\ndata: {", end_exc=aiohttp.ClientPayloadError("cut")
        )
        api, _ = make_api([resp])
        got: list[str] = []
        with pytest.raises(OpenWrtConnectionError):
            async for event, _data in api.async_subscribe("hostapd.phy0-ap0"):
                got.append(event)
        assert got == ["probe"]  # the cut event is never dispatched
        assert resp.closed

    async def test_idle_timeout_maps_to_timeout_and_closes(self) -> None:
        resp = sse(PROBE, end_exc=aiohttp.ServerTimeoutError("idle"))
        api, _ = make_api([resp])
        with pytest.raises(OpenWrtTimeoutError):
            await collect(api)
        assert resp.closed

    async def test_response_closed_on_cancellation(self) -> None:
        resp = sse(PROBE, block=True)
        api, _ = make_api([resp])
        first = asyncio.Event()

        async def _consume() -> None:
            async for _item in api.async_subscribe("hostapd.phy0-ap0"):
                first.set()

        task = asyncio.create_task(_consume())
        await asyncio.wait_for(first.wait(), 1)
        assert not resp.closed
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert resp.closed and resp.released

    async def test_response_closed_when_consumer_stops_early(self) -> None:
        resp = sse(PROBE, LINK, block=True)
        api, _ = make_api([resp])
        async with contextlib.aclosing(api.async_subscribe("hostapd")) as stream:
            async for _item in stream:
                break
        assert resp.closed
