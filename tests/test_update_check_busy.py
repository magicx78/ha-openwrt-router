"""A second update check while one runs is refused, and the timeout says why.

- A press while a check holds the lock raises a translated
  HomeAssistantError ("already running") instead of waiting up to 180 s and
  running the package manager a second time.
- The timeout message mentions that the router may still be refreshing
  its package lists.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from homeassistant.exceptions import HomeAssistantError

from custom_components.openwrt_router.api import (
    OpenWrtUpdateCheckError,
    OpenWrtUpdateCheckRunningError,
)
from custom_components.openwrt_router.const import SUFFIX_CHECK_UPDATES

from test_package_updates import (
    SUBPROCESS_RC_TIMEOUT,
    _api,
    _button,
    _coordinator,
    _poll_api,
)

_COMPONENT = Path(__file__).parent.parent / "custom_components" / "openwrt_router"


class TestCheckAlreadyRunning:
    @pytest.mark.asyncio
    async def test_second_check_is_refused_without_running_again(self):
        api = _poll_api()
        release = asyncio.Event()
        result = await api.check_package_updates()

        async def _slow_check():
            await release.wait()
            return result

        api.check_package_updates = AsyncMock(side_effect=_slow_check)
        coord = _coordinator(api)
        first = asyncio.create_task(coord.async_check_package_updates())
        await asyncio.sleep(0)
        try:
            with pytest.raises(OpenWrtUpdateCheckRunningError):
                # Before: waited for the lock (up to 180 s), then ran again.
                await asyncio.wait_for(coord.async_check_package_updates(), 1)
        finally:
            release.set()
        await first
        api.check_package_updates.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_button_shows_translated_already_running(
        self, mock_coordinator, mock_config_entry
    ):
        mock_coordinator.async_check_package_updates = AsyncMock(
            side_effect=OpenWrtUpdateCheckRunningError("busy")
        )
        btn = _button(mock_coordinator, mock_config_entry, SUFFIX_CHECK_UPDATES)
        with pytest.raises(HomeAssistantError) as exc:
            await btn.async_press()
        assert exc.value.translation_key == "update_check_running"

    @pytest.mark.parametrize("name", ["strings.json", "translations/en.json", "translations/de.json"])
    def test_running_message_is_translated(self, name):
        data = json.loads((_COMPONENT / name).read_text(encoding="utf-8"))
        assert data["exceptions"]["update_check_running"]["message"]


class TestTimeoutMessage:
    @pytest.mark.asyncio
    async def test_timeout_mentions_package_list_refresh(self):
        api = _api()
        api._asyncssh_run = AsyncMock(
            return_value=(SUBPROCESS_RC_TIMEOUT, "", b"timeout")
        )
        with pytest.raises(OpenWrtUpdateCheckError, match="package lists"):
            await api.check_package_updates()
