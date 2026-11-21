"""Wi-Fi switch unique_ids are the 1.47.1 ones again (hotfix 1.49.2).

1.48.0 (commit fddb6cf) made get_wifi_status ask ``iwinfo info`` per device.
On a real router (rpcd answers ``iwinfo info {}`` with "Invalid argument")
that turned the probe from the UCI fallback to the iwinfo path: radios
without UCI section, so every Wi-Fi switch got ``<entry>_wifi_ssid_<ifname>``
instead of ``<entry>_wifi_ssid_<uci_section>``, always ``enabled``, STA
interfaces as switches and 1+N iwinfo calls per poll.

The emulator below answers like rpcd on such a router (no network.wireless,
iwinfo needs a device, UCI readable). ``EXPECTED_1_47_1`` is the call list
the 1.47.1 code (git 11ae349) makes against it, recorded by running that
code; the current code must make exactly the same calls with WiFi RF off.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import attr
import pytest
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from custom_components.openwrt_router.api import OpenWrtAPI
from custom_components.openwrt_router.const import (
    DOMAIN,
    RADIO_KEY_ENABLED,
    RADIO_KEY_IFNAME,
    RADIO_KEY_UCI_SECTION,
)
from custom_components.openwrt_router.switch import OpenWrtWifiSwitchEntity
from custom_components.openwrt_router.wifi_id_repair import (
    async_remove_duplicate_wifi_entities,
    duplicate_entity_ids,
    looks_like_netdev,
)

ENTRY = "entry_ap3"

_INFO = {
    "phy0-ap0": {"phy": "phy0", "ssid": "Home", "mode": "Master", "noise": -90},
    "phy1-ap0": {"phy": "phy1", "ssid": "Home", "mode": "Master", "noise": -95},
    "phy1-ap1": {"phy": "phy1", "ssid": "IoT", "mode": "Master", "noise": -95},
    "phy1-sta0": {
        "phy": "phy1",
        "ssid": "up",
        "mode": "Client",
        "bssid": "02:00:00:00:09:09",
    },
}
_UCI = {
    "radio0": {".type": "wifi-device", ".index": 0, "band": "2g", "channel": "6"},
    "radio1": {".type": "wifi-device", ".index": 1, "band": "5g", "channel": "36"},
    "lan_2g": {
        ".type": "wifi-iface",
        ".index": 2,
        "device": "radio0",
        "mode": "ap",
        "ssid": "Home",
    },
    "lan_5g": {
        ".type": "wifi-iface",
        ".index": 3,
        "device": "radio1",
        "mode": "ap",
        "ssid": "Home",
    },
    "iot_5g": {
        ".type": "wifi-iface",
        ".index": 4,
        "device": "radio1",
        "mode": "ap",
        "ssid": "IoT",
        "disabled": "1",
    },
    "uplink": {
        ".type": "wifi-iface",
        ".index": 5,
        "device": "radio1",
        "mode": "sta",
        "ssid": "up",
    },
}

_LOGIN = ("session", "login", {"username": "root", "password": "pw", "timeout": 600})
_UCI_GET = ("uci", "get", {"config": "wireless"})
_INFO_NO_DEVICE = ("iwinfo", "info", {})


def _per_device(*names: str) -> list[tuple[str, str, dict]]:
    return [("iwinfo", "info", {"device": n}) for n in names]


_DISCOVERY = [("iwinfo", "devices", {})]
for _n in _INFO:
    _DISCOVERY += [(f"hostapd.{_n}", "get_status", {}), *_per_device(_n)]
_CLIENTS = [(f"hostapd.{n}", "get_clients", {}) for n in _INFO]
_AP_DETAILS = _per_device(*_INFO)

# Recorded from git 11ae349 (1.47.1) against this emulator, poll by poll:
# get_wifi_status, get_connected_clients, get_ap_interface_details,
# get_sta_interface_details.
EXPECTED_1_47_1 = [
    [
        _LOGIN,
        ("network.wireless", "status", {}),
        _INFO_NO_DEVICE,
        _UCI_GET,
        *_DISCOVERY,
        *_CLIENTS,
        *_AP_DETAILS,
        _INFO_NO_DEVICE,
        _UCI_GET,
    ],
    [
        _UCI_GET,
        *_DISCOVERY[1:],
        *_CLIENTS,
        *_AP_DETAILS,
        _INFO_NO_DEVICE,
        _UCI_GET,
    ],
]


def _answer(obj: str, method: str, args: dict) -> list[Any]:
    if (obj, method) == ("session", "login"):
        return [0, {"ubus_rpc_session": "a" * 32, "timeout": 300}]
    if (obj, method) == ("iwinfo", "devices"):
        return [0, {"devices": list(_INFO)}]
    if (obj, method) == ("iwinfo", "info"):
        if "device" not in args:
            return [2]  # rpcd: Invalid argument
        info = _INFO.get(args["device"])
        return [0, info] if info else [2]
    if (obj, method) == ("uci", "get") and args.get("config") == "wireless":
        return [0, {"values": _UCI}]
    if obj.startswith("hostapd.") and method == "get_clients":
        return [0, {"clients": {}}]
    if (obj, method) == ("network.device", "status"):
        return [0, {"macaddr": "02:00:00:00:08:08"}]
    return [3]  # method not found (network.wireless, hostapd get_status, ...)


def _api(calls: list) -> OpenWrtAPI:
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
                "result": _answer(obj, method, args),
            }
        )
        cm = AsyncMock()
        cm.__aenter__ = AsyncMock(return_value=resp)
        cm.__aexit__ = AsyncMock(return_value=False)
        return cm

    session = MagicMock()
    session.post = MagicMock(side_effect=post)
    return OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username="root",
        password="pw",
        session=session,
        protocol="http",
    )


async def _poll(api: OpenWrtAPI) -> tuple[list, list, list]:
    radios = await api.get_wifi_status()
    await api.get_connected_clients(leases={}, radios=radios)
    ap = await api.get_ap_interface_details()
    sta = await api.get_sta_interface_details()
    return radios, ap, sta


# --- router calls -----------------------------------------------------------


@pytest.mark.asyncio
async def test_rf_off_poll_makes_exactly_the_1_47_1_calls():
    calls: list = []
    api = _api(calls)
    for expected in EXPECTED_1_47_1:
        calls.clear()
        await _poll(api)
        assert calls == expected
    assert api._wifi_method == "uci"


@pytest.mark.asyncio
async def test_radios_are_the_1_47_1_uci_radios():
    api = _api([])
    radios, _, sta = await _poll(api)
    # Same keys, order and state as 1.47.1: UCI sections, disabled one off,
    # no kernel ifname (so no radio noise/signal sensors either).
    assert [(r[RADIO_KEY_UCI_SECTION], r[RADIO_KEY_ENABLED]) for r in radios] == [
        ("lan_2g", True),
        ("lan_5g", True),
        ("iot_5g", False),
        ("uplink", True),
    ]
    assert all(r[RADIO_KEY_IFNAME] == "" for r in radios)
    assert all("noise" not in r for r in radios)
    # STA detection: 1.47.1 UCI fallback (section name, no MAC).
    assert [(s["ifname"], s["mac"]) for s in sta] == [("uplink", "")]


@pytest.mark.asyncio
async def test_rf_on_keeps_the_switch_identity_and_gets_sta_detail():
    calls: list = []
    api = _api(calls)
    api.wifi_rf_sta_detail = True
    radios, _, sta = await _poll(api)
    assert [r[RADIO_KEY_UCI_SECTION] for r in radios] == [
        "lan_2g",
        "lan_5g",
        "iot_5g",
        "uplink",
    ]
    # RF extra (1.48.0): the STA uplink with its MAC from the per-device reads
    # of the same poll, no second iwinfo round.
    assert [(s["ifname"], s["mac"]) for s in sta] == [
        ("phy1-sta0", "02:00:00:00:08:08")
    ]
    assert _INFO_NO_DEVICE not in calls[calls.index(_AP_DETAILS[-1]) :]


# --- switches -----------------------------------------------------------------


def _switches(radios: list) -> list[OpenWrtWifiSwitchEntity]:
    coordinator = MagicMock()
    coordinator.data.wifi_radios = radios
    entry = MagicMock()
    entry.entry_id = ENTRY
    return [OpenWrtWifiSwitchEntity(coordinator, AsyncMock(), entry, r) for r in radios]


@pytest.mark.asyncio
async def test_switch_unique_ids_and_actions_are_the_1_47_1_ones():
    radios, _, _ = await _poll(_api([]))
    switches = _switches(radios)
    assert [s.unique_id for s in switches] == [
        f"{ENTRY}_wifi_ssid_lan_2g",
        f"{ENTRY}_wifi_ssid_lan_5g",
        f"{ENTRY}_wifi_ssid_iot_5g",
        f"{ENTRY}_wifi_ssid_uplink",
    ]
    assert [s.is_on for s in switches] == [True, True, False, True]
    lan_5g = switches[1]
    lan_5g.coordinator.async_request_refresh = AsyncMock()
    await lan_5g.async_turn_off()
    lan_5g._api.set_wifi_state.assert_awaited_once_with("lan_5g", enabled=False)


# --- cleanup of the duplicates ------------------------------------------------

OLD = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)
NEW = datetime(2026, 11, 21, 8, 0, tzinfo=UTC)
PREVIOUS_RELEASE = datetime(2026, 6, 1, tzinfo=UTC)


async def _registry() -> tuple[MagicMock, er.EntityRegistry, str]:
    hass = MagicMock()
    hass.data = {}
    hass.config_entries.async_wait_initialized = AsyncMock(return_value=None)
    devices = dr.DeviceRegistry(hass)
    hass.data[dr.DATA_REGISTRY] = devices
    registry = er.EntityRegistry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    for item in (devices, registry):
        with patch.object(item._store, "async_load", AsyncMock(return_value=None)):
            await item.async_load()
        item.async_schedule_save = lambda: None
    config_entry = MagicMock()
    config_entry.entry_id = ENTRY
    config_entry.domain = DOMAIN
    config_entry.disabled_by = None
    config_entry.pref_disable_new_entities = False
    other = MagicMock()
    other.entry_id = "other_entry"
    other.domain = DOMAIN
    other.disabled_by = None
    other.pref_disable_new_entities = False
    hass.config_entries.async_get_entry.side_effect = {
        ENTRY: config_entry,
        "other_entry": other,
    }.get
    return hass, registry, "router-device"


def _add(
    registry: er.EntityRegistry,
    domain: str,
    unique_id: str,
    created: datetime,
    *,
    entry_id: str = ENTRY,
    platform: str = DOMAIN,
    suggested: str | None = None,
    device_id: str | None = "router-device",
) -> str:
    with patch("homeassistant.helpers.entity_registry.utcnow", return_value=created):
        ent = registry.async_get_or_create(
            domain,
            platform,
            unique_id,
            config_entry=MagicMock(
                entry_id=entry_id,
                domain=DOMAIN,
                disabled_by=None,
                pref_disable_new_entities=False,
            ),
            suggested_object_id=suggested,
        )
    # device_id needs a real device; set the attribute directly (test only).
    registry.entities[ent.entity_id] = attr.evolve(ent, device_id=device_id)
    return ent.entity_id


async def _uci_radios() -> list[dict]:
    radios, _, _ = await _poll(_api([]))
    return radios


@pytest.mark.asyncio
async def test_cleanup_removes_the_duplicates_and_keeps_the_originals():
    hass, registry, _ = await _registry()
    old_5 = _add(
        registry,
        "switch",
        f"{ENTRY}_wifi_ssid_lan_5g",
        OLD,
        suggested="secureap_ap3_5_ghz",
    )
    old_2 = _add(
        registry,
        "switch",
        f"{ENTRY}_wifi_ssid_lan_2g",
        OLD,
        suggested="secureap_ap3_2_4_ghz",
    )
    old_iot = _add(registry, "switch", f"{ENTRY}_wifi_ssid_iot_5g", OLD)
    registry.async_update_entity(old_5, area_id="buero", name="Büro-WLAN")
    registry.async_update_entity(old_iot, disabled_by=er.RegistryEntryDisabler.USER)
    before = {e: registry.async_get(e) for e in (old_5, old_2, old_iot)}

    dupes = [
        _add(registry, "switch", f"{ENTRY}_wifi_ssid_{n}", NEW, suggested=f"dup_{i}")
        for i, n in enumerate(("phy1-ap0", "phy0-ap0", "phy1-ap1", "phy1-sta0"))
    ]
    dupes += [
        _add(registry, "sensor", f"{ENTRY}_radio_phy1-ap0_{m}", NEW)
        for m in ("noise", "signal")
    ]
    # Never touched: other entry, other integration, non-Wi-Fi unique_id.
    other_entry = _add(
        registry,
        "switch",
        "other_entry_wifi_ssid_phy0-ap0",
        NEW,
        entry_id="other_entry",
    )
    other_platform = _add(
        registry, "switch", f"{ENTRY}_wifi_ssid_phy0-ap1", NEW, platform="other"
    )
    ap_sensor = _add(registry, "sensor", f"{ENTRY}_ap_phy1-ap0_channel", NEW)

    removed = async_remove_duplicate_wifi_entities(hass, ENTRY, await _uci_radios())

    assert removed == len(dupes)
    for entity_id in dupes:
        assert registry.async_get(entity_id) is None
    for entity_id in (other_entry, other_platform, ap_sensor):
        assert registry.async_get(entity_id) is not None
    for entity_id, entry in before.items():
        assert registry.async_get(entity_id) == entry
    assert registry.async_get(old_5).area_id == "buero"
    assert registry.async_get(old_iot).disabled_by is er.RegistryEntryDisabler.USER

    # The switch platform then gets the original entries back.
    found = [
        registry.async_get_entity_id("switch", DOMAIN, s.unique_id)
        for s in _switches(await _uci_radios())[:3]
    ]
    assert found == [old_2, old_5, old_iot]
    assert old_5 == "switch.secureap_ap3_5_ghz"

    # Idempotent.
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, await _uci_radios()) == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("radios", [[], None, [{"ssid": "x"}]])
async def test_cleanup_removes_nothing_without_a_good_wifi_read(radios):
    hass, registry, _ = await _registry()
    _add(registry, "switch", f"{ENTRY}_wifi_ssid_lan_5g", OLD)
    dupe = _add(registry, "switch", f"{ENTRY}_wifi_ssid_phy1-ap0", NEW)
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, radios) == 0
    assert registry.async_get(dupe) is not None


@pytest.mark.asyncio
async def test_cleanup_keeps_ifname_switches_of_ifname_keyed_routers():
    """Routers that had ifname keys before 1.48.0 keep them.

    In 1.47.1 that was the case on the network.wireless path when netifd's
    interface config carried no ``section`` (_parse_wireless_status reads
    ``config.section``) and on the iwinfo path (only where ``iwinfo info {}``
    answered; real rpcd does not). Both paths are unchanged in 1.49.2.
    """
    hass, registry, _ = await _registry()
    old = _add(registry, "switch", f"{ENTRY}_wifi_ssid_phy1-ap0", PREVIOUS_RELEASE)
    new = _add(registry, "switch", f"{ENTRY}_wifi_ssid_phy0-ap0", NEW)
    radios = [
        {RADIO_KEY_IFNAME: "phy1-ap0", RADIO_KEY_UCI_SECTION: ""},
        {RADIO_KEY_IFNAME: "phy0-ap0", RADIO_KEY_UCI_SECTION: ""},
    ]
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, radios) == 0
    assert registry.async_get(old) is not None
    assert registry.async_get(new) is not None


@pytest.mark.asyncio
async def test_cleanup_keeps_old_ifname_entries_even_on_uci_routers():
    """Created before 1.48.0 existed: never a duplicate of this bug."""
    hass, registry, _ = await _registry()
    _add(registry, "switch", f"{ENTRY}_wifi_ssid_lan_5g", OLD)
    older = _add(registry, "switch", f"{ENTRY}_wifi_ssid_phy1-ap0", PREVIOUS_RELEASE)
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, await _uci_radios()) == 0
    assert registry.async_get(older) is not None


@pytest.mark.asyncio
async def test_cleanup_keeps_a_duplicate_whose_original_is_gone():
    hass, registry, _ = await _registry()
    dupe = _add(registry, "switch", f"{ENTRY}_wifi_ssid_phy1-ap0", NEW)
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, await _uci_radios()) == 0
    assert registry.async_get(dupe) is not None


@pytest.mark.asyncio
async def test_cleanup_keeps_a_uci_section_named_like_an_ifname():
    hass, registry, _ = await _registry()
    _add(registry, "switch", f"{ENTRY}_wifi_ssid_lan_5g", OLD)
    section = _add(registry, "switch", f"{ENTRY}_wifi_ssid_wlan0", NEW)
    dupe = _add(registry, "switch", f"{ENTRY}_wifi_ssid_wlan1", NEW)
    radios = [
        {RADIO_KEY_UCI_SECTION: "lan_5g", RADIO_KEY_IFNAME: ""},
        {RADIO_KEY_UCI_SECTION: "wlan0", RADIO_KEY_IFNAME: ""},
    ]
    assert async_remove_duplicate_wifi_entities(hass, ENTRY, radios) == 1
    assert registry.async_get(section) is not None
    assert registry.async_get(dupe) is None


def test_netdev_names():
    for name in (
        "phy0-ap0",
        "phy1-ap12",
        "phy0-sta0",
        "phy2-mesh0",
        "wlan0",
        "wlan1-1",
    ):
        assert looks_like_netdev(name), name
    for name in ("lan_5g", "default_radio0", "@wifi-iface[0]", "wifinet2", "radio0"):
        assert not looks_like_netdev(name), name


def test_duplicate_ids_ignore_entries_without_created_at():
    entry = MagicMock(
        platform=DOMAIN,
        config_entry_id=ENTRY,
        unique_id=f"{ENTRY}_wifi_ssid_phy1-ap0",
        domain="switch",
        device_id="d",
        created_at=None,
    )
    radios = [{RADIO_KEY_UCI_SECTION: "lan_5g"}]
    assert duplicate_entity_ids(ENTRY, radios, [entry]) == []


@pytest.mark.asyncio
async def test_setup_runs_the_cleanup_before_the_platforms():
    from custom_components.openwrt_router import async_setup_entry

    order: list[str] = []
    hass = MagicMock()
    hass.config_entries.async_forward_entry_setups = AsyncMock(
        side_effect=lambda *a: order.append("platforms")
    )
    entry = MagicMock()
    entry.entry_id = ENTRY
    entry.title = "AP3"
    entry.data = {"host": "192.0.2.1", "port": 80, "username": "u", "password": "p"}
    coordinator = MagicMock()
    coordinator.async_config_entry_first_refresh = AsyncMock()
    coordinator.data.wifi_radios = [{RADIO_KEY_UCI_SECTION: "lan_5g"}]
    with (
        patch(
            "custom_components.openwrt_router.async_get_clientsession",
            return_value=MagicMock(),
        ),
        patch("custom_components.openwrt_router.OpenWrtAPI", return_value=AsyncMock()),
        patch(
            "custom_components.openwrt_router.OpenWrtCoordinator",
            return_value=coordinator,
        ),
        patch(
            "custom_components.openwrt_router.acl_provisioning.ensure_acl_respecting_offer",
            AsyncMock(return_value=False),
        ),
        patch(
            "custom_components.openwrt_router.async_remove_duplicate_wifi_entities",
            side_effect=lambda h, e, r: order.append(("cleanup", e, r)),
        ),
    ):
        await async_setup_entry(hass, entry)
    assert order[0] == ("cleanup", ENTRY, [{RADIO_KEY_UCI_SECTION: "lan_5g"}])
    assert "platforms" in order[1:]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("options", "expected"),
    [
        ({}, False),
        ({"wifi_rf_enabled": False}, False),
        ({"wifi_rf_enabled": True}, True),
    ],
)
async def test_coordinator_sets_sta_detail_from_the_rf_option(options, expected):
    from test_coordinator import _make_coordinator

    coordinator, api = _make_coordinator()
    coordinator._entry = MagicMock(options=options)
    seen: list[bool] = []

    async def sta() -> list:
        seen.append(api.wifi_rf_sta_detail)
        return []

    api.get_sta_interface_details = sta
    await coordinator._async_update_data()
    assert seen == [expected]
