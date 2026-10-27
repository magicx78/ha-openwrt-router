"""Describe OpenWrt Router events for the logbook."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from homeassistant.core import Event, HomeAssistant, callback

from .const import DOMAIN, EVENT_DFS, EVENT_DHCP, EVENT_WIFI


def _client(data: dict[str, Any]) -> str:
    return str(data.get("hostname") or data.get("mac") or "unknown client")


def _name(data: dict[str, Any]) -> str:
    return str(data.get("router") or "OpenWrt Router")


def _kind(data: dict[str, Any]) -> str:
    return str(data.get("type") or "event").replace("_", " ")


@callback
def async_describe_events(
    hass: HomeAssistant,
    async_describe_event: Callable[[str, str, Callable[[Event], dict[str, str]]], None],
) -> None:
    """Register logbook descriptions for the integration's events."""

    @callback
    def describe_wifi(event: Event) -> dict[str, str]:
        data = event.data
        where = f" on {data['interface']}" if data.get("interface") else ""
        return {
            "name": _name(data),
            "message": f"Wi-Fi {_kind(data)}: {_client(data)}{where}",
        }

    @callback
    def describe_dhcp(event: Event) -> dict[str, str]:
        data = event.data
        ip = f" ({data['ip']})" if data.get("ip") else ""
        return {
            "name": _name(data),
            "message": f"DHCP {_kind(data)}: {_client(data)}{ip}",
        }

    @callback
    def describe_dfs(event: Event) -> dict[str, str]:
        data = event.data
        radio = data.get("radio") or data.get("interface") or "radio"
        if data.get("type") == "channel_change":
            dfs = " (DFS)" if data.get("dfs_related") else ""
            message = (
                f"channel change on {radio}: {data.get('old_channel')} → "
                f"{data.get('new_channel')}{dfs}"
            )
        else:
            channel = f" (channel {data['channel']})" if data.get("channel") else ""
            message = f"DFS {_kind(data)} on {radio}{channel}"
        return {"name": _name(data), "message": message}

    async_describe_event(DOMAIN, EVENT_WIFI, describe_wifi)
    async_describe_event(DOMAIN, EVENT_DFS, describe_dfs)
    async_describe_event(DOMAIN, EVENT_DHCP, describe_dhcp)
