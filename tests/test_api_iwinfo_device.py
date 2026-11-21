"""``iwinfo info`` always needs a ``device`` (fix in 1.48.0, sub-step B).

rpcd's iwinfo plugin answers ``iwinfo info {}`` with UBUS_STATUS_INVALID_ARGUMENT
(status 2, "Invalid argument" in the ubus CLI); it never returned the flat
dict keyed by interface name that the old fallback paths expected and the
conftest mock still pretends. The fallback paths of ``get_wifi_status`` and
the STA detection now enumerate ``iwinfo devices`` and ask per device; the
STA detection reuses what ``get_ap_interface_details`` read in the same poll
so no extra call is made on an AP-only router.

The emulator below answers like rpcd: status 2 for a missing ``device``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.const import RADIO_KEY_IFNAME

UBUS_OK = 0
UBUS_INVALID_ARGUMENT = 2
UBUS_METHOD_NOT_FOUND = 3

_INFO = {
    "phy0-ap0": {"phy": "phy0", "ssid": "net", "mode": "Master", "channel": 6},
    "phy1-ap0": {"phy": "phy1", "ssid": "net", "mode": "Master", "channel": 36},
    "phy1-sta0": {
        "phy": "phy1",
        "ssid": "uplink",
        "mode": "Client",
        "bssid": "02:00:00:00:09:09",
        "signal": -60,
        "channel": 36,
    },
}


def _session(calls: list[tuple[str, str, dict]], *, wireless: bool) -> MagicMock:
    session = MagicMock()

    def answer(obj: str, method: str, args: dict) -> list[Any]:
        if (obj, method) == ("session", "login"):
            return [UBUS_OK, {"ubus_rpc_session": "a" * 32, "timeout": 300}]
        if (obj, method) == ("iwinfo", "devices"):
            return [UBUS_OK, {"devices": list(_INFO)}]
        if (obj, method) == ("iwinfo", "info"):
            if "device" not in args:
                return [UBUS_INVALID_ARGUMENT]  # what rpcd really answers
            info = _INFO.get(args["device"])
            return [UBUS_OK, info] if info else [UBUS_INVALID_ARGUMENT]
        if (obj, method) == ("network.device", "status"):
            return [UBUS_OK, {"macaddr": "02:00:00:00:08:08"}]
        if (obj, method) == ("network.wireless", "status") and not wireless:
            return [UBUS_METHOD_NOT_FOUND]
        return [UBUS_METHOD_NOT_FOUND]

    def post(url, json=None, **kwargs):
        params = (json or {}).get("params", [None, "", "", {}])
        obj, method = params[1], params[2]
        args = params[3] if len(params) > 3 and isinstance(params[3], dict) else {}
        calls.append((obj, method, dict(args)))
        resp = AsyncMock()
        resp.status = 200
        resp.json = AsyncMock(
            return_value={
                "jsonrpc": "2.0",
                "id": 1,
                "result": answer(obj, method, args),
            }
        )
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    session.post = MagicMock(side_effect=post)
    return session


def _api(calls: list, *, wireless: bool = False) -> OpenWrtAPI:
    return OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=_session(calls, wireless=wireless),
        protocol="http",
    )


def _info_calls(calls: list) -> list[dict]:
    return [args for obj, method, args in calls if (obj, method) == ("iwinfo", "info")]


@pytest.mark.asyncio
async def test_wifi_status_iwinfo_fallback_asks_per_device():
    calls: list = []
    api = _api(calls)
    api.get_uci_wireless = AsyncMock(return_value={})
    radios = await api.get_wifi_status()
    assert {r[RADIO_KEY_IFNAME] for r in radios} == set(_INFO)
    assert api._wifi_method == "iwinfo"
    assert all("device" in args for args in _info_calls(calls))
    # The cached fast path uses the same per-device form.
    calls.clear()
    again = await api.get_wifi_status()
    assert {r[RADIO_KEY_IFNAME] for r in again} == set(_INFO)
    assert _info_calls(calls) and all("device" in a for a in _info_calls(calls))


@pytest.mark.asyncio
async def test_sta_detection_finds_the_uplink_via_iwinfo():
    calls: list = []
    api = _api(calls)
    api.get_uci_wireless = AsyncMock(return_value={})
    sta = await api.get_sta_interface_details()
    assert [s["ifname"] for s in sta] == ["phy1-sta0"]
    assert sta[0]["bssid"] == "02:00:00:00:09:09"
    assert sta[0]["mac"] == "02:00:00:00:08:08"
    assert all("device" in args for args in _info_calls(calls))


@pytest.mark.asyncio
async def test_sta_detection_reuses_the_ap_details_of_the_same_poll():
    calls: list = []
    api = _api(calls)
    api._hostapd_ifaces = list(_INFO)  # from iwinfo devices, STA included
    await api.get_ap_interface_details()
    before = len(_info_calls(calls))
    sta = await api.get_sta_interface_details()
    assert [s["ifname"] for s in sta] == ["phy1-sta0"]
    # No second info round and no devices call: the poll costs what it did.
    assert len(_info_calls(calls)) == before
    assert ("iwinfo", "devices", {}) not in calls
    # The reuse is one-shot: a later call without fresh AP details asks again.
    calls.clear()
    await api.get_sta_interface_details()
    assert ("iwinfo", "devices", {}) in calls


@pytest.mark.asyncio
async def test_no_iwinfo_falls_back_to_uci_as_before():
    calls: list = []
    api = _api(calls)

    async def no_iwinfo(obj, method, params=None):
        from custom_components.openwrt_router.api import OpenWrtMethodNotFoundError

        if obj == "iwinfo":
            raise OpenWrtMethodNotFoundError("no iwinfo")
        raise OpenWrtMethodNotFoundError(obj)

    api._call = no_iwinfo
    api.get_uci_wireless = AsyncMock(
        return_value={"sta1": {".type": "wifi-iface", "mode": "sta", "ssid": "up"}}
    )
    sta = await api.get_sta_interface_details()
    assert sta == [
        {
            "ifname": "sta1",
            "mode": "sta",
            "ssid": "up",
            "bssid": "",
            "mac": "",
            "signal": None,
        }
    ]
