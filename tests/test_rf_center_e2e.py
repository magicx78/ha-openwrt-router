"""WiFi RF Intelligence end to end over the real API and coordinator (1.48.0).

The real :class:`OpenWrtAPI` and :class:`OpenWrtCoordinator` poll the
path-aware ubus mock of ``test_poll_no_ssh`` (patched with the synthetic RF
fixtures); after each poll the RF center's listener runs as HA would call
it. Every ubus call is counted from the mocked session. No router, no Home
Assistant instance, no network (``conftest`` blocks sockets).
"""

from __future__ import annotations

import copy
import json
import re
import time
from collections import Counter
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from rf_center_kit import (
    KEY,
    RID1,
    Clock,
    entry,
    load,
    options,
    rf_disk,
    rf_hass,
)
from test_poll_no_ssh import RESPONSES, _make_coordinator, _ubus_session

from custom_components.openwrt_router import channel_plan
from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.rf_center import ROUTER_OK, RfCenter
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_models import CapabilityState

INFO_5G = load("iwinfo_info_mt76.json")
INFO_2G = {**load("iwinfo_info_ath9k.json"), "phy": "phy0"}
CLIENTS_5G = load("hostapd_get_clients_mt76.json")
STATUS = [
    load("hostapd_get_status_mt76_a.json"),
    load("hostapd_get_status_mt76_b.json"),
]
ASSOC = load("iwinfo_assoclist_mt76.json")
R5 = RadioRef(RID1, "radio1")
SYSTEM_INFO = dict(RESPONSES[("system", "info")])
STAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(\+00:00)?")


class Router:
    """The answers of one fake router across polls (uptime, counters)."""

    def __init__(self) -> None:
        self.uptime = 86_400
        self.status_reads = 0
        self.status_2g_reads = 0
        self.assoc_reads = 0

    def system_info(self, _params: dict[str, Any]) -> dict[str, Any]:
        return {**SYSTEM_INFO, "uptime": self.uptime}

    @staticmethod
    def iwinfo_info(params: dict[str, Any]) -> Any:
        return {"phy0-ap0": INFO_2G, "phy1-ap0": INFO_5G}.get(params.get("device"))

    def get_status(self, _params: dict[str, Any]) -> dict[str, Any]:
        answer = STATUS[min(self.status_reads, 1)]
        self.status_reads += 1
        return copy.deepcopy(answer)

    def get_status_2g(self, _params: dict[str, Any]) -> dict[str, Any]:
        self.status_2g_reads += 1
        airtime = {"time": 1_000_000 * self.status_2g_reads, "time_busy": 0}
        return {
            **copy.deepcopy(STATUS[0]),
            "channel": 6,
            "freq": 2437,
            "airtime": airtime,
        }

    def assoclist(self, params: dict[str, Any]) -> dict[str, Any]:
        if params.get("device") != "phy1-ap0":
            return {"results": []}
        later = copy.deepcopy(ASSOC)
        for station in later["results"]:
            station["tx"]["packets"] += 2000 * self.assoc_reads
            station["tx"]["retries"] += 300 * self.assoc_reads
        self.assoc_reads += 1
        return later

    def responses(self) -> dict[tuple[str, str], Any]:
        return {
            ("system", "info"): self.system_info,
            ("iwinfo", "info"): self.iwinfo_info,
            ("hostapd.phy1-ap0", "get_clients"): copy.deepcopy(CLIENTS_5G),
            ("hostapd.phy1-ap0", "get_status"): self.get_status,
            ("hostapd.phy0-ap0", "get_status"): self.get_status_2g,
            ("iwinfo", "assoclist"): self.assoclist,
        }


def _api(session: Any) -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.168.1.1",
        port=80,
        username="root",
        password="pw",
        session=session,
        protocol="http",
    )
    # LLDP is the one SSH reader (600 s cadence): primed as unavailable
    api._lldp_checked = True
    api._lldp_available = False
    api._lldp_last_fetch = time.monotonic()
    return api


def _calls(session: Any) -> Counter[tuple[str, str]]:
    out: Counter[tuple[str, str]] = Counter()
    for call in session.post.call_args_list:
        params = call.kwargs["json"]["params"]
        out[(params[1], params[2])] += 1
    return out


async def _run(opts: dict[str, Any], polls: int = 3) -> tuple[Any, ...]:
    """``polls`` real polls 300 s apart, each followed by the RF listener."""
    router = Router()
    session = _ubus_session()
    api = _api(session)
    coordinator = _make_coordinator(api)
    listeners: list[Any] = []
    coordinator.async_add_listener = lambda cb: listeners.append(cb) or (lambda: None)
    clock = Clock()
    with rf_disk():  # before the center: it builds its HA Store at once
        center = RfCenter(rf_hass())
        center.clock = center.monotonic = clock
        center.auto_bind = False
        center.module_key = KEY
        center.router_id_of = {"e1": RID1}.get
        center.capability_of = lambda _rid, _name: (False, "not_detected")
        await center.async_load()
        center.add_entry(entry("e1", opts), coordinator)
        connect = AsyncMock(side_effect=AssertionError("SSH must not be used"))
        with (
            patch.dict(RESPONSES, router.responses()),
            patch("custom_components.openwrt_router.api.asyncssh.connect", connect),
            patch("asyncio.open_connection", side_effect=OSError("no net")),
        ):
            for _ in range(polls):
                coordinator.data = await coordinator._async_update_data()
                for callback in listeners:
                    callback()  # what HA does after a successful poll
                await center.async_wait_rounds()
                clock.advance(300)
                router.uptime += 300
    assert connect.await_count == 0
    return center, coordinator, _calls(session), router


def _rf_only(calls: Counter[tuple[str, str]]) -> Counter[tuple[str, str]]:
    return Counter(
        {
            k: n
            for k, n in calls.items()
            if k[1] == "get_status" and k[0].startswith("hostapd.")
        }
    )


# --- test case 01 ------------------------------------------------------------------


async def test_case_01_successful_rf_collection_end_to_end() -> None:
    """RF on with get_status and assoclist: two polls give utilization from
    the airtime counter delta and the retry rate from the assoclist delta;
    the existing poll data gives noise, power and width."""
    center, _coordinator, calls, router = await _run(
        options("get_status", "assoclist"), polls=2
    )
    assert center.routers["e1"].status == ROUTER_OK
    result = center.results[R5]
    assert result.radio.radio_id_source == "uci"
    assert (result.radio.band, result.radio.channel, result.radio.width) == (
        "5g",
        36,
        80,
    )
    metrics = result.metrics
    assert metrics["utilization"].value == pytest.approx(38.0)
    assert metrics["utilization"].source == "hostapd.get_status"
    assert metrics["noise"].value == -92 and metrics["txpower"].value == 20
    retry = metrics["retry_rate"]
    assert retry.is_measured and retry.value == pytest.approx(0.15)
    assert result.caps.state("busy_time") is CapabilityState.MEASURED
    assert result.caps.state("retries") is CapabilityState.MEASURED
    assert result.caps.state("scan") is CapabilityState.UNSUPPORTED
    # the extra reads, exactly: one get_status per radio and poll, one
    # assoclist per AP interface and poll (the poll's own assoclist aside)
    assert router.status_reads == 2 and router.status_2g_reads == 2
    assert calls[("hostapd.phy1-ap0", "get_status")] == 2


# --- test case 30 ------------------------------------------------------------------


async def test_case_30_regressions_existing_features_poll_call_count() -> None:
    """With RF off, and with RF on but no extra read, a poll makes exactly
    the same router calls (number and kind) as before 1.48.0."""
    _c, _co, off, _r = await _run({})
    _c, _co, on_plain, _r = await _run(options())
    assert on_plain == off
    _c, _co, on_status, _r = await _run(options("get_status"))
    extra = on_status - off
    assert extra == _rf_only(on_status)  # only hostapd get_status was added
    assert sum(extra.values()) == 2 * 3  # 2 radios x 3 polls (every poll here)
    assert not off - on_status  # nothing of the poll went missing


async def test_case_30_regressions_existing_features_poll_data_unchanged() -> None:
    """The RF listener changes nothing in the coordinator's data: client
    list and stability fields, AP interfaces and the channel plan input."""
    _c, off_coord, _calls_off, _r = await _run({}, polls=2)
    _c, on_coord, _calls_on, _r = await _run(
        options("get_status", "assoclist"), polls=2
    )

    def view(data: Any) -> str:
        plain = {
            "clients": data.clients,
            "ap": data.ap_interfaces,
            "radios": data.wifi_radios,
        }
        # wall-clock stamps of the two runs differ; everything else must not
        return STAMP.sub("<t>", json.dumps(plain, sort_keys=True, default=str))

    assert view(on_coord.data) == view(off_coord.data)


async def test_case_30_regressions_existing_features_channel_plan_message() -> None:
    """The channel plan finding (and its message) is the same with RF on:
    the RF center only reads the poll data the plan reads too."""

    def messages(coordinator: Any) -> list[str]:
        data = coordinator.data
        radios = channel_plan.radios_from_ap_interfaces(
            "e1", "A", data.ap_interfaces
        ) + channel_plan.radios_from_ap_interfaces("e2", "B", data.ap_interfaces)
        return [channel_plan.format_finding(f) for f in channel_plan.analyze(radios)]

    _c, off_coord, _calls_off, _r = await _run({}, polls=1)
    _c, on_coord, _calls_on, _r = await _run(
        options("get_status", "assoclist"), polls=1
    )
    assert messages(off_coord)  # the same radios twice: co-channel findings
    assert messages(on_coord) == messages(off_coord)
