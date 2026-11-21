"""A full gateway with rpcd-faithful Wi-Fi, for entity-level tests (1.49.4).

Built from the two router models already in the suite, nothing new:

* the ubus model of ``test_poll_no_ssh`` (system, board, disks, conntrack,
  ``network.device status`` of a DSA gateway, file reads for ARP/FDB/leases)
  with the ``network.interface dump`` of the static-WAN gateway of
  ``test_traffic_wan_device`` (``lan``, ``loopback``, ``wan`` up, ``wan6``
  pending);
* the Wi-Fi of ``test_wifi_switch_ids_v1492``, which answers like real rpcd:
  no ``network.wireless``, ``iwinfo info {}`` -> status 2 (Invalid
  argument), per-device ``iwinfo info`` and ``uci get wireless`` readable,
  so radios come from the UCI path (``wifi_ssid_<uci section>``). The
  per-device answers here also carry the radio fields rpcd sends (channel,
  frequency, txpower, bitrate, htmode, quality, signal), so the optional AP
  sensors exist; the model sends no ``hwmode``.

``iwinfo_flat=True`` is the one deliberate deviation from rpcd: ``iwinfo
info {}`` then answers with all interfaces keyed by ifname, which selects
the iwinfo path. Real rpcd does not do that (see the 1.49.2 notes in
``api.get_wifi_status``); the path is kept for routers that had ifname-keyed
Wi-Fi switches before 1.48.0, and it is the only path that creates the
radio noise/signal sensors without WiFi RF.

Added on top: one associated Wi-Fi client, the procd service and init
lists, and the stock ``uci get dhcp`` (a ``lan`` pool, ``wan`` ignored) so
device trackers, service switches and DHCP pool sensors exist. Every call
is answered over ubus; SSH raises, so a poll that falls back fails the test.
"""

from __future__ import annotations

import time as time_module
from collections.abc import Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import test_poll_no_ssh as poll_model
import test_wifi_switch_ids_v1492 as wifi_model
from test_traffic_wan_device import CUDY_DUMP, _wan_device

from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.coordinator import (
    OpenWrtCoordinator,
    OpenWrtCoordinatorData,
)

CLIENT_MAC = "02:00:00:00:0a:0a"
SERVICE_LIST = {
    "cron": {},
    "dnsmasq": {"instances": {"cfg01411c": {"running": True, "pid": 3820}}},
    "dropbear": {"instances": {"instance1": {"running": True, "pid": 1}}},
    "firewall": {},
}
RC_LIST = {
    "dnsmasq": {"start": 19, "enabled": True},
    "dropbear": {"start": 19, "stop": 50, "enabled": True},
    "firewall": {"start": 19, "enabled": True},
}
# /etc/config/dhcp as shipped (named sections, wan pool ignored).
DHCP_UCI = {
    "lan": {
        ".type": "dhcp",
        ".name": "lan",
        ".anonymous": False,
        "interface": "lan",
        "start": "100",
        "limit": "150",
        "leasetime": "12h",
    },
    "wan": {
        ".type": "dhcp",
        ".name": "wan",
        ".anonymous": False,
        "interface": "wan",
        "ignore": "1",
    },
}

# What rpcd's per-device ``iwinfo info`` adds to the reduced answers of
# test_wifi_switch_ids_v1492 (fields the AP detail sensors read).
IWINFO_EXTRA: dict[str, dict[str, Any]] = {
    "phy0-ap0": {
        "channel": 6,
        "frequency": 2437,
        "txpower": 20,
        "bitrate": 286800,
        "htmode": "HE20",
        "quality": 60,
        "quality_max": 70,
        "signal": -50,
    },
    "phy1-ap0": {
        "channel": 36,
        "frequency": 5180,
        "txpower": 23,
        "bitrate": 1201000,
        "htmode": "HE80",
        "quality": 55,
        "quality_max": 70,
        "signal": -55,
    },
    "phy1-ap1": {
        "channel": 36,
        "frequency": 5180,
        "txpower": 23,
        "bitrate": 1201000,
        "htmode": "HE80",
        "quality": 55,
        "quality_max": 70,
        "signal": -55,
    },
    "phy1-sta0": {
        "channel": 36,
        "frequency": 5180,
        "txpower": 23,
        "bitrate": 866700,
        "htmode": "HE80",
        "quality": 50,
        "quality_max": 70,
        "signal": -60,
        "noise": -95,
    },
}


def _iwinfo(device: str) -> dict[str, Any]:
    return {**wifi_model._INFO[device], **IWINFO_EXTRA[device]}


# WAN port byte counters per poll (1 250 000 B down, 125 000 B up between
# poll 1 and 2), as in test_traffic_wan_device.
WAN_COUNTERS = ((1_000, 500), (1_251_000, 125_500))


def answer(
    obj: str, method: str, args: dict[str, Any], *, iwinfo_flat: bool = False
) -> list[Any]:
    """The ubus result envelope of one call."""
    if (obj, method) == ("iwinfo", "info"):
        device = args.get("device")
        if device is None and iwinfo_flat:
            return [0, {n: _iwinfo(n) for n in wifi_model._INFO}]
        if device in IWINFO_EXTRA:
            return [0, _iwinfo(device)]
    if obj == "iwinfo" or obj.startswith("hostapd.") or obj == "network.wireless":
        if (obj, method) == ("hostapd.phy1-ap0", "get_clients"):
            return [0, {"clients": {CLIENT_MAC: {"signal": -55, "authorized": True}}}]
        return wifi_model._answer(obj, method, args)
    if (obj, method) == ("uci", "get"):
        if args.get("config") == "wireless":
            return wifi_model._answer(obj, method, args)
        if args.get("config") == "dhcp":
            return [0, {"values": DHCP_UCI}]
    if (obj, method) == ("service", "list"):
        return [0, SERVICE_LIST]
    if (obj, method) == ("rc", "list"):
        return [0, RC_LIST]
    if (obj, method) == ("network.interface", "dump"):
        return [0, CUDY_DUMP]
    handler = poll_model.RESPONSES.get((obj, method))
    if handler is None:
        return [poll_model.UBUS_METHOD_NOT_FOUND]
    data = handler(args) if callable(handler) else handler
    return [0, data] if data is not None else [poll_model.UBUS_NOT_FOUND]


def session(
    calls: list[tuple[str, str, dict]] | None = None, *, iwinfo_flat: bool = False
) -> MagicMock:
    """aiohttp session mock answering every ubus call with :func:`answer`."""

    def post(url: str, json: Any = None, **kwargs: Any) -> Any:
        params = (json or {}).get("params", [None, "", "", {}])
        obj, method = params[1], params[2]
        args = params[3] if len(params) > 3 and isinstance(params[3], dict) else {}
        if calls is not None:
            calls.append((obj, method, dict(args)))
        resp = AsyncMock()
        resp.status = 200
        resp.json = AsyncMock(
            return_value={
                "jsonrpc": "2.0",
                "id": (json or {}).get("id", 1),
                "result": answer(obj, method, args, iwinfo_flat=iwinfo_flat),
            }
        )
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    mock = MagicMock()
    mock.post = MagicMock(side_effect=post)
    return mock


def make_api(
    calls: list[tuple[str, str, dict]] | None = None, *, iwinfo_flat: bool = False
) -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=session(calls, iwinfo_flat=iwinfo_flat),
        protocol="http",
    )
    # LLDP is the one SSH reader (600 s cadence): primed as unavailable.
    api._lldp_checked = True
    api._lldp_available = False
    api._lldp_last_fetch = time_module.monotonic()
    return api


def make_coordinator(hass: Any, api: OpenWrtAPI) -> OpenWrtCoordinator:
    with patch("homeassistant.helpers.frame.report_usage"):
        return OpenWrtCoordinator(hass=hass, api=api, entry_title="GW")


async def full_polls(
    coordinator: OpenWrtCoordinator,
    *,
    on_poll: Callable[[OpenWrtCoordinatorData, int], None] | None = None,
) -> list[OpenWrtCoordinatorData]:
    """Two polls of the real api and coordinator, entirely over ubus.

    Poll 2 is the first with DHCP pools (the coordinator reads ``uci get
    dhcp`` from its second poll on). ``on_poll`` may adjust each result
    (sample time) before it becomes ``coordinator.data``.
    """
    out: list[OpenWrtCoordinatorData] = []
    with (
        patch.dict(poll_model._MODE, {"empty_tables": False}),
        patch(
            "custom_components.openwrt_router.api.asyncssh.connect",
            AsyncMock(side_effect=AssertionError("SSH must not be used")),
        ),
        patch("asyncio.open_connection", side_effect=OSError("no net")),
    ):
        for n, (rx, tx) in enumerate(WAN_COUNTERS):
            with patch.dict(poll_model._DEVICES, {"wan": _wan_device(rx, tx)}):
                data = await coordinator._async_update_data()
            assert coordinator.api.uses_ssh_fallback is False
            if on_poll is not None:
                on_poll(data, n)
            coordinator.data = data
            out.append(data)
    return out
