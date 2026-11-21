"""WAN device of Traffic Analytics on real poll data (fix after 1.49.3).

Found on a real gateway (Cudy WR3000, OpenWrt 25.12, static WAN behind a
second router): traffic analytics ran, but the gateway got none of its
router sensors (no ``<entry_id>_traffic_wan_down`` ...). The traffic copy
takes the WAN netdev from ``wan_status["l3_device"]``; ``get_wan_status``
had netifd's ``l3_device`` in hand (it reads the WAN byte counters of that
netdev) but never put it into ``wan_status``. Without it there is no WAN
point, so neither WAN nor uplink sensors were wanted. The traffic tests
were green because their poll fixtures add ``l3_device`` to ``wan_status``
themselves (``poll_data`` in ``test_traffic_engine`` and five more).

Here the poll data come from the real ``OpenWrtAPI`` and
``OpenWrtCoordinator`` on the ubus session mock of ``test_poll_no_ssh``, so
``wan_status`` has exactly the shape a router produces, and they run the
whole way: poll data -> snapshot -> ``wan_point`` -> ``_wanted`` ->
entities. No router, no network (conftest blocks it).
"""

from __future__ import annotations

import time as time_module
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import test_poll_no_ssh as model
from core_testkit import FakeCoordinator, FakeDisks, drain
from test_diag_entities import Host
from test_traffic_engine import (
    RID,
    _reset_pending,  # noqa: F401 - autouse fixture
    enabled,
    make_hass,
    poll_data,
    start,
)

from custom_components.openwrt_router import traffic_entities as te
from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.coordinator import (
    TRAFFIC_MAX_DEVICES,
    traffic_device_counters,
    traffic_first_devices,
)
from custom_components.openwrt_router.traffic_collect import (
    snapshot_from_data,
    sysfs_candidates,
)
from custom_components.openwrt_router.traffic_model import Scope

KEY = bytes(range(32))

# What the gateway's poll put into ``coordinator.data.wan_status`` on the
# real instance (1.49.3): no ``l3_device``, no ``device``.
REPORTED_WAN_KEYS = {
    "connected",
    "interface",
    "ipv4",
    "uptime",
    "proto",
    "wan_found",
    "rx_bytes",
    "tx_bytes",
    "default_route",
    "diag_facts",
}

# ``network.interface dump`` of a DSA gateway with a static WAN behind
# another router, as netifd sends it (alphabetical; ``l3_device`` only on
# interfaces that are up). Documentation addresses only.
CUDY_DUMP = {
    "interface": [
        {
            "interface": "lan",
            "up": True,
            "pending": False,
            "available": True,
            "autostart": True,
            "uptime": 1434950,
            "proto": "static",
            "device": "br-lan",
            "l3_device": "br-lan",
            "ipv4-address": [{"address": "192.168.1.1", "mask": 24}],
            "route": [],
            "dns-server": [],
        },
        {
            "interface": "loopback",
            "up": True,
            "uptime": 1434960,
            "proto": "static",
            "device": "lo",
            "l3_device": "lo",
            "ipv4-address": [{"address": "127.0.0.1", "mask": 8}],
        },
        {
            "interface": "wan",
            "up": True,
            "pending": False,
            "available": True,
            "autostart": True,
            "uptime": 1434918,
            "proto": "static",
            "device": "wan",
            "l3_device": "wan",
            "ipv4-address": [{"address": "192.0.2.10", "mask": 24}],
            "route": [
                {
                    "target": "0.0.0.0",
                    "mask": 0,
                    "nexthop": "192.0.2.1",
                    "source": "0.0.0.0/0",
                }
            ],
            "dns-server": ["192.0.2.1"],
        },
        {
            "interface": "wan6",
            "up": False,
            "pending": True,
            "available": True,
            "autostart": True,
            "proto": "dhcpv6",
            "device": "wan",
        },
    ]
}


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


@pytest.fixture
def host() -> Any:
    found = Host(make_hass())
    with patch.object(te, "platforms_of", found):
        yield found


def _api() -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=model._ubus_session(),
        protocol="http",
    )
    # LLDP is the one SSH reader (600 s cadence): primed as unavailable
    api._lldp_checked = True
    api._lldp_available = False
    api._lldp_last_fetch = time_module.monotonic()
    return api


def _wan_device(rx: int, tx: int) -> dict[str, Any]:
    return {
        "up": True,
        "carrier": True,
        "devtype": "ethernet",
        "speed": "1000F",
        "statistics": {
            "rx_bytes": rx,
            "tx_bytes": tx,
            "rx_packets": rx // 1000,
            "tx_packets": tx // 1000,
            "rx_errors": 0,
            "tx_errors": 0,
            "rx_dropped": 0,
            "tx_dropped": 0,
        },
    }


async def real_polls(dump: dict[str, Any] = CUDY_DUMP) -> list[Any]:
    """Two full polls of the real api + coordinator, 10 s apart (sample time).

    The WAN port counts 1 250 000 B down and 125 000 B up between them.
    """
    out: list[Any] = []
    coordinator = model._make_coordinator(_api())
    model._MODE["empty_tables"] = False
    with (
        patch.dict(model.RESPONSES, {("network.interface", "dump"): dump}),
        patch(
            "custom_components.openwrt_router.api.asyncssh.connect",
            AsyncMock(side_effect=AssertionError("SSH must not be used")),
        ),
        patch("asyncio.open_connection", side_effect=OSError("no net")),
    ):
        for n, (rx, tx) in enumerate(((1_000, 500), (1_251_000, 125_500))):
            with patch.dict(model._DEVICES, {"wan": _wan_device(rx, tx)}):
                data = await coordinator._async_update_data()
            coordinator.data = data
            # the sample time the poll measured, made deterministic
            data.counters_sampled_mono = 100.0 + 10 * n
            data.uptime = 5_000 + 10 * n
            out.append(data)
    return out


# --- the poll data -------------------------------------------------------------------


async def test_real_wan_status_has_the_reported_shape_plus_l3_device() -> None:
    first, second = await real_polls()
    for data in (first, second):
        wan = data.wan_status
        # exactly what the real gateway showed, plus netifd's l3_device
        assert set(wan) - {"l3_device"} == REPORTED_WAN_KEYS
        assert "device" not in wan
        assert wan["interface"] == "wan" and wan["proto"] == "static"
        assert wan["l3_device"] == "wan"
        assert list(wan)[-1] == "diag_facts"  # still appended last
    assert second.wan_status["rx_bytes"] == 1_251_000


async def test_real_poll_fills_the_traffic_snapshot() -> None:
    """Every field the traffic copy reads exists in real poll data."""
    _first, data = await real_polls()
    snap = snapshot_from_data(data, router_id=RID, module_key=KEY, wall_s=1.0)
    assert snap.wan_device == "wan"
    assert snap.devices is not None
    assert {d.name for d in snap.devices} == {"wan", "lan1", "br-lan"}
    assert snap.port_names == frozenset({"wan", "lan1"})
    assert snap.mono_s == 110.0 and snap.uptime_s == 5_010
    assert snap.stale is False
    assert snap.ap_interfaces  # AP netdevs of this poll
    assert "br-lan" in snap.interface_devices
    assert snap.uplink_ports is not None  # the topology field exists
    assert snap.port_vlans is not None
    assert snap.wired is not None  # bridge FDB with the module key
    assert snap.stations == ()  # hostapd answered, no station associated
    assert snap.conntrack_count == 12  # count file


async def test_sysfs_fallback_never_reads_a_logical_interface_name() -> None:
    """``wan6`` is pending (no ``l3_device``): the interface list carries the
    logical name, which is no netdev; ``lo`` is up and has no Q1 counters."""
    _first, data = await real_polls()
    rows = {r["logical_name"]: r for r in data.network_interfaces}
    assert rows["wan6"]["interface"] == "wan6" and rows["wan6"]["status"] == "down"
    snap = snapshot_from_data(data, router_id=RID, module_key=KEY, wall_s=1.0)
    assert "wan6" not in snap.interface_devices
    assert sysfs_candidates(snap) == ("lo",)


# --- the whole way to the entities ---------------------------------------------------


async def test_gateway_gets_its_wan_sensors_from_real_poll_data(host, disks) -> None:
    first, second = await real_polls()
    hass = host.hass
    host.load("e1")
    hass.devices["e1"] = "dev-e1"
    enabled(disks)
    engine, coord = await start(hass, coord=FakeCoordinator(first))
    await te.async_sync_traffic_entities(hass)
    coord.poll(data=first)
    await drain(hass)
    engine.clock.t += 10
    coord.poll(data=second)
    await drain(hass)

    point = engine.wan_point(RID)
    assert point is not None
    assert point.scope is Scope.WAN and point.device == "wan"
    assert engine.uplink_point(RID) == (point, "wan")
    assert set(te.router_keys(engine, RID)) == set(te.ROUTER_KEYS)
    uids = set(host.by_uid())
    for key in te.ROUTER_KEYS:
        assert te.router_unique_id("e1", key) in uids
    assert "e1_traffic_wan_down" in uids  # the unique id missing on the instance
    sensor = host.by_uid()["e1_traffic_wan_down"]
    sensor._refresh()
    assert sensor.native_value == 1_000_000  # 1 250 000 B in 10 s
    assert te._wanted(hass, engine) == {}  # nothing left to create


# --- api: the new key only where netifd sends it --------------------------------------


def _wan(**changes: Any) -> dict[str, Any]:
    wan = dict(CUDY_DUMP["interface"][2])
    wan.update(changes)
    return wan


def _dump_with(wan: dict[str, Any]) -> dict[str, Any]:
    items = list(CUDY_DUMP["interface"])
    items[2] = wan
    return {"interface": items}


async def _wan_status(dump: dict[str, Any]) -> dict[str, Any]:
    api = _api()
    with patch.dict(model.RESPONSES, {("network.interface", "dump"): dump}):
        return await api.get_wan_status()


async def test_l3_device_is_netifds_while_the_wan_is_up() -> None:
    pppoe = _wan(proto="pppoe", l3_device="pppoe-wan", device="wan")
    status = await _wan_status(_dump_with(pppoe))
    assert status["l3_device"] == "pppoe-wan"  # the L3 netdev, not the port


async def test_no_l3_device_while_the_wan_is_down() -> None:
    down = {k: v for k, v in _wan(up=False).items() if k != "l3_device"}
    status = await _wan_status(_dump_with(down))
    assert status["wan_found"] is True and status["connected"] is False
    assert "l3_device" not in status  # unknown, never the port as a guess


@pytest.mark.parametrize("bad", ["", None, 7, "../wan", "x" * 40])
async def test_an_unusable_l3_device_is_not_copied(bad: Any) -> None:
    status = await _wan_status(_dump_with(_wan(l3_device=bad)))
    assert "l3_device" not in status
    assert status["wan_found"] is True


async def test_no_wan_no_l3_device() -> None:
    lan_only = {"interface": [CUDY_DUMP["interface"][0]]}
    status = await _wan_status(lan_only)
    assert status["wan_found"] is False and "l3_device" not in status


# --- coordinator: the WAN netdev keeps its place in the capped copy ------------------


async def test_capped_counter_copy_keeps_a_non_wan_named_wan_device() -> None:
    lte = _wan(interface="wwan", proto="qmi", l3_device="eth9", device="eth9")
    status = await _wan_status(_dump_with(lte))
    devices = {f"aa{i:03d}": {"statistics": {"rx_bytes": i}} for i in range(80)}
    devices["eth9"] = {"statistics": {"rx_bytes": 1, "tx_bytes": 2}}
    first = traffic_first_devices(status, {})
    assert first == ["eth9"]
    copy = traffic_device_counters(devices, first=first)
    assert copy is not None and len(copy) == TRAFFIC_MAX_DEVICES
    assert "eth9" in copy  # "eth9" sorts after "aa..." and was cut before


# --- "routers: 6" with one router on ---------------------------------------------------


async def test_routers_counts_loaded_entries_only_the_one_on_is_read(disks) -> None:
    """Six loaded entries, traffic on at one: ``routers`` is 6, but only the
    gateway's polls are copied; the five others get no listener at all."""
    hass = make_hass()
    rids = {f"e{i}": "rtr_" + str(i) * 32 for i in range(1, 7)}
    coords: dict[str, FakeCoordinator] = {}
    for i in range(2, 7):  # five routers with the switch off
        _engine, coords[f"e{i}"] = await start(hass, entry_id=f"e{i}", rids=rids)
    enabled(disks)
    engine, coords["e1"] = await start(hass, entry_id="e1")
    for n in range(2):
        for coord in coords.values():
            coord.poll(data=poll_data(100.0 + 10 * n, uptime=5_000 + 10 * n))
        await drain(hass)
        engine.clock.t += 10
    summary = engine.summary()
    assert summary["routers"] == 6 and summary["entries_enabled"] == 1
    assert summary["counters"]["queued_snapshots"] == 2
    assert summary["counters"]["processed_snapshots"] == 2
    assert {f"e{i}" for i in range(2, 7) if coords[f"e{i}"].listener_count} == set()
    assert coords["e1"].listener_count == 1
    assert set(engine.status) == {rids["e1"]}
    assert {r.point.router_id for r in engine.latest.values()} == {rids["e1"]}
