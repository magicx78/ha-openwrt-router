"""Tests for the auth backoff order and ARP truncation handling (package A10).

- NEU-A2: while the auth backoff is active no login is attempted — not by
  the proactive token refresh either, and not after a poll boundary.
- rpcd's ``file read`` truncates /proc/net/arp at 4 KiB; a truncated read is
  supplemented by ``luci-rpc getHostHints`` (ACL v7+), ARP rows win.
"""
from __future__ import annotations

import time
from unittest.mock import AsyncMock

import pytest

from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtMethodNotFoundError,
)

ARP_HEADER = (
    "IP address       HW type     Flags       HW address            Mask     Device\n"
)


def _arp_row(i: int) -> str:
    return (
        f"192.168.1.{i:<3}    0x1         0x2         aa:bb:cc:dd:ee:{i:02x}"
        "     *        br-lan\n"
    )


# ---------------------------------------------------------------------------
# NEU-A2 — backoff before any login
# ---------------------------------------------------------------------------


def _in_backoff(api, *, token_expired: bool) -> None:
    api._auth_failure_count = 3
    api._auth_backoff_until = time.monotonic() + 120
    if token_expired:
        api._token_expires_at = 0.0
    api.login = AsyncMock(side_effect=OpenWrtAuthError("denied"))
    api._raw_call = AsyncMock(return_value={})


class TestAuthBackoff:
    @pytest.mark.asyncio
    async def test_no_login_during_backoff_with_expired_token(self, mock_api):
        _in_backoff(mock_api, token_expired=True)
        with pytest.raises(OpenWrtAuthError, match="backoff"):
            await mock_api._call("system", "info", {})
        mock_api.login.assert_not_awaited()
        mock_api._raw_call.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_backoff_survives_the_poll_boundary(self, mock_api):
        _in_backoff(mock_api, token_expired=True)
        mock_api.reset_ssh_fallback_flag()  # start of the next poll
        with pytest.raises(OpenWrtAuthError):
            await mock_api._call("system", "info", {})
        mock_api.login.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_failed_proactive_refresh_counts_towards_backoff(self, mock_api):
        mock_api._token_expires_at = 0.0
        mock_api.login = AsyncMock(side_effect=OpenWrtAuthError("denied"))
        mock_api._raw_call = AsyncMock(return_value={})
        for _ in range(3):
            with pytest.raises(OpenWrtAuthError):
                await mock_api._call("system", "info", {})
        assert mock_api.login.await_count == 3
        with pytest.raises(OpenWrtAuthError, match="backoff"):
            await mock_api._call("system", "info", {})
        assert mock_api.login.await_count == 3

    @pytest.mark.asyncio
    async def test_login_retried_after_backoff_expired(self, mock_api):
        _in_backoff(mock_api, token_expired=True)
        mock_api._auth_backoff_until = time.monotonic() - 1
        mock_api.login = AsyncMock(return_value=True)
        await mock_api._call("system", "info", {})
        mock_api.login.assert_awaited_once()
        assert mock_api._auth_failure_count == 0


# ---------------------------------------------------------------------------
# ARP 4-KiB truncation → getHostHints
# ---------------------------------------------------------------------------


def _routed_call(arp_text: str, hints=None):
    seen: list[tuple[str, str]] = []

    async def _call(obj, method, params, *args, **kwargs):
        seen.append((obj, method))
        if (obj, method) == ("file", "read"):
            return {"data": arp_text}
        if (obj, method) == ("luci-rpc", "getHostHints"):
            if isinstance(hints, Exception):
                raise hints
            return hints or {}
        raise AssertionError(f"unexpected {obj}/{method}")

    return _call, seen


class TestArpTruncation:
    @pytest.mark.asyncio
    async def test_short_read_makes_no_hint_call(self, mock_api):
        call, seen = _routed_call(ARP_HEADER + _arp_row(2) + _arp_row(3))
        mock_api._call = AsyncMock(side_effect=call)
        arp = await mock_api.get_arp_table()
        assert seen == [("file", "read")]
        assert arp == {"aa:bb:cc:dd:ee:02": "192.168.1.2", "aa:bb:cc:dd:ee:03": "192.168.1.3"}

    @pytest.mark.asyncio
    async def test_truncated_read_is_supplemented_by_host_hints(self, mock_api):
        text = ARP_HEADER + "".join(_arp_row(i) for i in range(2, 60))
        text = text[:4096]  # rpcd cut-off, last line incomplete
        hints = {
            # in ARP already — ARP wins
            "AA:BB:CC:DD:EE:02": {"ipaddrs": ["192.168.1.250"], "name": "a"},
            # lost by the truncation
            "AA:BB:CC:DD:EE:3B": {"ipaddrs": ["192.168.1.59"], "name": "b"},
            # older LuCI shape
            "aa:bb:cc:dd:ee:f0": {"ipv4": "192.168.1.240"},
            # no IPv4 → ignored
            "aa:bb:cc:dd:ee:f1": {"ip6addrs": ["fd00::1"]},
        }
        call, seen = _routed_call(text, hints)
        mock_api._call = AsyncMock(side_effect=call)
        mock_api._run_ssh = AsyncMock()
        arp = await mock_api.get_arp_table()
        assert seen == [("file", "read"), ("luci-rpc", "getHostHints")]
        assert arp["aa:bb:cc:dd:ee:02"] == "192.168.1.2"
        assert arp["aa:bb:cc:dd:ee:3b"] == "192.168.1.59"
        assert arp["aa:bb:cc:dd:ee:f0"] == "192.168.1.240"
        assert "aa:bb:cc:dd:ee:f1" not in arp
        assert len(arp) == len(set(arp))
        mock_api._run_ssh.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_incomplete_last_line_counts_as_truncated(self, mock_api):
        text = ARP_HEADER + _arp_row(2) + "192.168.1.3      0x1"
        call, seen = _routed_call(text, {})
        mock_api._call = AsyncMock(side_effect=call)
        await mock_api.get_arp_table()
        assert ("luci-rpc", "getHostHints") in seen

    @pytest.mark.asyncio
    async def test_hints_blocked_keeps_arp_without_ssh(self, mock_api):
        text = (ARP_HEADER + "".join(_arp_row(i) for i in range(2, 60)))[:4096]
        call, _ = _routed_call(text, OpenWrtMethodNotFoundError("acl"))
        mock_api._call = AsyncMock(side_effect=call)
        mock_api._run_ssh = AsyncMock()
        arp = await mock_api.get_arp_table()
        assert arp["aa:bb:cc:dd:ee:02"] == "192.168.1.2"
        mock_api._run_ssh.assert_not_awaited()


# ---------------------------------------------------------------------------
# Backoff-blocked calls do not count towards reauth
# ---------------------------------------------------------------------------


class TestBackoffIsNotACredentialFailure:
    @pytest.mark.asyncio
    async def test_blocked_call_raises_backoff_error(self, mock_api):
        from custom_components.openwrt_router.api import OpenWrtAuthBackoffError

        _in_backoff(mock_api, token_expired=False)
        with pytest.raises(OpenWrtAuthBackoffError):
            await mock_api._call("system", "info", {})

    @pytest.mark.asyncio
    async def test_coordinator_never_opens_reauth_for_backoff(self):
        from homeassistant.helpers.update_coordinator import UpdateFailed

        from custom_components.openwrt_router.api import OpenWrtAuthBackoffError
        from test_coordinator import _make_coordinator

        coord, api = _make_coordinator()
        api.get_wan_status = AsyncMock(side_effect=OpenWrtAuthBackoffError("wait"))
        for _ in range(5):
            with pytest.raises(UpdateFailed):
                await coord._async_update_data()
        assert coord._consecutive_auth_failures == 0
        assert coord._failure_count == 5
