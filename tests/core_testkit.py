"""Shared fakes for the enterprise core tests (no router, no HA instance).

* :class:`FakeDisks` replaces ``core_store.create_store``: one in-memory
  "file" per store key that survives a new core (restart / reload).
* :class:`FakeEntry` records ``async_on_unload`` callbacks and runs them
  like HA does (a returned coroutine is awaited).
* :class:`FakeCoordinator` behaves like a DataUpdateCoordinator for
  listeners: removers raise KeyError on a second call, like HA's.
* ``router_data`` / ``repeater_data`` / ``ssh_router_data`` build real
  ``OpenWrtCoordinatorData`` objects.
"""

from __future__ import annotations

import asyncio
import copy
import json
from collections.abc import Callable
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.helpers import device_registry as dr

from custom_components.openwrt_router import core_store
from custom_components.openwrt_router.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_PROTOCOL,
    CONF_USERNAME,
    DOMAIN,
)
from custom_components.openwrt_router.coordinator import OpenWrtCoordinatorData

# Universally administered MACs (first octet 0x94 / 0x00: bit 0x02 clear).
MAC_A = ["94:83:c4:00:00:01", "94:83:c4:00:00:02", "94:83:c4:00:00:03"]
MAC_B = ["94:83:c4:00:01:01", "94:83:c4:00:01:02", "94:83:c4:00:01:03"]
MAC_C = ["00:1a:2b:00:02:01", "00:1a:2b:00:02:02"]
LOCAL_MAC = "96:83:c4:00:00:99"  # 0x96: locally administered (randomised)
SECRET = "S3cr3t-pa55"


class FakeDisk:
    """One store 'file'."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.data: Any = None
        self.load_error: BaseException | None = None
        self.saves: list[Any] = []
        self.delayed: list[tuple[Any, float]] = []
        self.path = f"/nonexistent/.storage/{key}"
        self.backups = 0


class FakeStore:
    def __init__(self, disk: FakeDisk, version: int, minor: int, migrate: Any) -> None:
        self.disk = disk
        self.path = disk.path
        self.version = version
        self.minor = minor
        self.migrate = migrate

    async def async_load(self) -> Any:
        if self.disk.load_error is not None:
            raise self.disk.load_error
        raw = copy.deepcopy(self.disk.data)
        if raw is None:
            return None
        if not isinstance(raw, dict) or "data" not in raw:
            raise ValueError("not a store file")
        if (raw.get("version"), raw.get("minor_version")) != (self.version, self.minor):
            return self.migrate(
                raw.get("version"), raw.get("minor_version"), raw["data"]
            )
        return raw["data"]

    def async_delay_save(self, data_func: Callable[[], Any], delay: float = 0) -> None:
        self.disk.delayed.append((data_func, delay))

    async def async_save(self, data: Any) -> None:
        self.disk.data = {
            "version": self.version,
            "minor_version": self.minor,
            "key": self.disk.key,
            "data": json.loads(json.dumps(data)),
        }
        self.disk.saves.append(self.disk.data["data"])

    def run_delayed(self) -> None:
        """Run the pending delayed save (what HA does after the delay)."""
        if self.disk.delayed:
            func, _ = self.disk.delayed[-1]
            self.disk.delayed.clear()
            data = func()
            self.disk.data = {
                "version": self.version,
                "minor_version": self.minor,
                "key": self.disk.key,
                "data": json.loads(json.dumps(data)),
            }
            self.disk.saves.append(self.disk.data["data"])


class FakeDisks:
    """All core store files; patch ``core_store.create_store`` with :meth:`patch`."""

    def __init__(self) -> None:
        self.disks: dict[str, FakeDisk] = {}
        self.stores: list[FakeStore] = []
        self.options: dict[str, dict[str, bool]] = {}

    def __getitem__(self, key: str) -> FakeDisk:
        return self.disks.setdefault(key, FakeDisk(key))

    def create(
        self,
        hass: Any,
        version: int,
        key: str,
        *,
        minor_version: int,
        migrate: Any,
        private: bool = False,
        atomic_writes: bool = False,
    ) -> FakeStore:
        store = FakeStore(self[key], version, minor_version, migrate)
        self.stores.append(store)
        self.options[key] = {"private": private, "atomic_writes": atomic_writes}
        return store

    def flush_delayed(self) -> None:
        for disk in self.disks.values():
            for store in self.stores:
                if store.disk is disk and disk.delayed:
                    store.run_delayed()
                    break

    @contextmanager
    def patch(self) -> Any:
        def backup(path: Any) -> bool:
            for disk in self.disks.values():
                if disk.path == path and disk.data is not None:
                    disk.backups += 1
                    return True
            return False

        with (
            patch.object(core_store, "create_store", self.create),
            patch.object(core_store, "_backup_file", backup),
        ):
            yield self


async def _run_in_executor(func: Any, *args: Any) -> Any:
    return func(*args)


def make_hass(entries: list[Any] | None = None) -> MagicMock:
    """A MagicMock hass with a real ``data`` dict, bus recorder and tasks."""
    hass = MagicMock()
    hass.data = {}
    hass.async_add_executor_job = AsyncMock(side_effect=_run_in_executor)
    fired: list[tuple[str, dict[str, Any]]] = []
    hass.bus.async_fire = MagicMock(
        side_effect=lambda t, d=None, **kw: fired.append((t, d))
    )
    hass.fired = fired
    tasks: list[asyncio.Task[Any]] = []

    def create_task(coro: Any, *args: Any, **kwargs: Any) -> asyncio.Task[Any]:
        task = asyncio.get_running_loop().create_task(coro)
        tasks.append(task)
        return task

    hass.async_create_task = MagicMock(side_effect=create_task)
    hass.tasks = tasks
    hass.devices = {}
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    hass.entries = entries if entries is not None else []
    hass.config_entries.async_entries = MagicMock(
        side_effect=lambda domain=None: list(hass.entries)
    )
    hass.config_entries.async_get_entry = MagicMock(
        side_effect=lambda eid: next(
            (e for e in hass.entries if e.entry_id == eid), None
        )
    )
    # hass.auth with known users (see add_user); unknown ids return None.
    hass.users = {}
    hass.auth.async_get_user = AsyncMock(side_effect=lambda uid: hass.users.get(uid))
    return hass


ADMIN_ID = "user-admin"
USER_ID = "user-plain"
OTHER_ADMIN_ID = "user-admin-2"


def add_user(
    hass: Any,
    user_id: str,
    *,
    admin: bool,
    active: bool = True,
    system_generated: bool = False,
) -> Any:
    """Register a user in the fake ``hass.auth``."""
    user = SimpleNamespace(
        id=user_id,
        is_admin=admin,
        is_active=active,
        system_generated=system_generated,
    )
    hass.users[user_id] = user
    return user


def add_users(hass: Any) -> None:
    """Two admins and one plain user."""
    add_user(hass, ADMIN_ID, admin=True)
    add_user(hass, OTHER_ADMIN_ID, admin=True)
    add_user(hass, USER_ID, admin=False)


def user_actor(user_id: str = ADMIN_ID, *, claims_admin: bool = False) -> Any:
    """A user actor; ``claims_admin`` is a self-declaration the core ignores."""
    from custom_components.openwrt_router.core_models import Actor, ActorKind

    return Actor(kind=ActorKind.USER, user_id=user_id, is_admin=claims_admin)


async def guard_adopt_auth(hass: Any, entry_id: str, orphan_id: str) -> Any:
    """An adopt authorization issued by the running core's guard (admin)."""
    if ADMIN_ID not in hass.users:
        add_user(hass, ADMIN_ID, admin=True)
    return await core_of(hass).manager.async_authorize_adopt(
        entry_id, orphan_id, user_actor(ADMIN_ID)
    )


async def drain(hass: Any) -> None:
    """Wait for every task the core scheduled."""
    while hass.tasks:
        task = hass.tasks.pop(0)
        await task


class FakeEntry:
    """Config entry with the fields the core reads."""

    def __init__(
        self,
        entry_id: str,
        *,
        host: str = "192.168.1.1",
        title: str | None = None,
        unique_id: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> None:
        self.entry_id = entry_id
        self.domain = DOMAIN
        self.title = title or f"Router {entry_id}"
        self.unique_id = unique_id or f"uid-{entry_id}"
        self.version = 1
        self.minor_version = 1
        self.data: dict[str, Any] = {
            CONF_HOST: host,
            CONF_PORT: 443,
            CONF_USERNAME: "root",
            CONF_PASSWORD: SECRET,
            CONF_PROTOCOL: "https",
        }
        self.options: dict[str, Any] = dict(options or {})
        self.disabled_by = None
        self.source = "user"
        self.pref_disable_new_entities = False
        self.on_unload: list[Callable[[], Any]] = []

    def async_on_unload(self, func: Callable[[], Any]) -> None:
        self.on_unload.append(func)

    async def run_on_unload(self) -> None:
        """What HA does after unload or a failed setup."""
        while self.on_unload:
            result = self.on_unload.pop()()
            if asyncio.iscoroutine(result):
                await result


class FakeCoordinator:
    """Listener behaviour of DataUpdateCoordinator, plus a fake api."""

    def __init__(self, data: Any, *, ssh: bool = False) -> None:
        self.data = data
        self.last_update_success = True
        self.api = MagicMock()
        self.api.uses_ssh_fallback = ssh
        self._listeners: dict[Callable[[], None], Callable[[], None]] = {}

    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        def remove_listener() -> None:
            self._listeners.pop(remove_listener)  # KeyError on a 2nd call, like HA

        self._listeners[remove_listener] = update_callback
        return remove_listener

    @property
    def listener_count(self) -> int:
        return len(self._listeners)

    def poll(self, *, success: bool = True, data: Any = None) -> None:
        """Finish one poll: like ``async_update_listeners``."""
        self.last_update_success = success
        if data is not None:
            self.data = data
        for update_callback in list(self._listeners.values()):
            update_callback()

    def router_calls(self) -> list[Any]:
        """Every call made on the api object (must stay empty)."""
        return list(self.api.mock_calls)


def router_data(
    *,
    hostname: str = "gw-office",
    model: str = "GL.iNet GL-MT3000",
    board: str = "glinet,gl-mt3000",
    macs: list[str] | None = None,
    version: str = "24.10.2",
    wan: dict[str, Any] | None = None,
    features: dict[str, Any] | None = None,
    lldp: str = "ok",
    log: str = "ok",
    package_manager: str | None = "apk",
    extra_macs: list[str] | None = None,
) -> OpenWrtCoordinatorData:
    """A GL-MT3000-like gateway poll."""
    macs = list(MAC_A if macs is None else macs)
    data = OpenWrtCoordinatorData()
    data.router_info = {
        "model": model,
        "hostname": hostname,
        "release": {
            "distribution": "OpenWrt",
            "version": version,
            "revision": "r28000",
            "target": "mediatek/filogic",
        },
        "mac": macs[0] if macs else "",
        "board_name": board,
        "kernel": "6.6.86",
        "platform_architecture": "aarch64_cortex-a53",
    }
    data.ap_interfaces = [
        {"ifname": f"phy{i}-ap0", "ssid": "Home", "bssid": mac, "band": "5g"}
        for i, mac in enumerate(macs[1:] + list(extra_macs or []))
    ]
    data.wifi_radios = [{"bssid": mac} for mac in macs[1:]]
    data.sta_interfaces = []
    data.network_interfaces = [
        {
            "interface": "br-lan",
            "logical_name": "lan",
            "status": "up",
            "ipv4_addr": "192.168.1.1",
        }
    ]
    data.wan_status = (
        wan
        if wan is not None
        else {
            "wan_found": True,
            "interface": "wan",
            "proto": "dhcp",
            "connected": True,
            "ipv4": "203.0.113.7",
        }
    )
    data.features = (
        features
        if features is not None
        else {
            "has_iwinfo": True,
            "dhcp_leases": True,
            "has_services": True,
            "uci_available": True,
        }
    )
    data.lldp_status = lldp
    data.log_status = log
    data.updates_available = {
        **data.updates_available,
        "package_manager": package_manager,
    }
    return data


def repeater_data(host: str = "192.168.1.40") -> OpenWrtCoordinatorData:
    """FRITZ!Repeater 3000-like: no system/board, no LLDP, no log ACL, no uci."""
    data = OpenWrtCoordinatorData()
    data.router_info = {
        "model": "OpenWrt Router",  # api.py fallback
        "hostname": host,  # api.py fallback
        "release": {"distribution": "OpenWrt", "version": "25.12.0"},
        "mac": "",
        "board_name": "",
        "kernel": "",
        "platform_architecture": "",
    }
    data.ap_interfaces = [
        {"ifname": "phy0-ap0", "ssid": "Home", "bssid": MAC_C[0], "band": "2g"},
        {"ifname": "phy1-ap0", "ssid": "Home", "bssid": MAC_C[1], "band": "5g"},
    ]
    data.wifi_radios = [{"bssid": MAC_C[0]}]
    data.sta_interfaces = [{"ifname": "phy1-sta0", "mac": LOCAL_MAC, "bssid": MAC_A[1]}]
    data.wan_status = {"wan_found": False}
    data.features = {
        "has_iwinfo": False,
        "dhcp_leases": False,
        "has_services": False,
        "uci_available": False,
    }
    data.lldp_status = "unavailable"
    data.log_status = "not_permitted"
    data.updates_available = {**data.updates_available, "package_manager": None}
    return data


def ssh_router_data() -> OpenWrtCoordinatorData:
    """A router whose ubus is restricted: data via the SSH fallback scripts."""
    data = router_data(
        macs=MAC_B,
        hostname="ap-garage",
        wan={"connected": True},  # SSH fallback shape
        features={"has_iwinfo": True, "uci_available": False},
        lldp="unavailable",
        log="pending",
        package_manager="opkg",
    )
    return data


async def setup_router(
    hass: Any, entry: FakeEntry, data: Any, *, ssh: bool = False
) -> FakeCoordinator:
    """Both setup hooks, like ``__init__.async_setup_entry`` calls them."""
    from custom_components.openwrt_router.enterprise_core import (
        async_setup_entry_core,
    )

    if entry not in hass.entries:
        hass.entries.append(entry)
    await async_setup_entry_core(hass, entry)
    coordinator = FakeCoordinator(data, ssh=ssh)
    await async_setup_entry_core(hass, entry, coordinator)
    return coordinator


def core_of(hass: Any) -> Any:
    from custom_components.openwrt_router.enterprise_core import async_get_core

    core = async_get_core(hass)
    assert core is not None
    return core


def bus_events(hass: Any, event_type: str | None = None) -> list[dict[str, Any]]:
    """Payloads of ``openwrt_router_core_event`` fired so far (optionally by type)."""
    from custom_components.openwrt_router.core_models import EVENT_CORE

    return [
        payload
        for name, payload in hass.fired
        if name == EVENT_CORE and (event_type is None or payload["type"] == event_type)
    ]


def fake_device_registry(mapping: dict[str, str]) -> Any:
    """``dr.async_get`` replacement: (DOMAIN, entry_id) -> device id."""

    def get_device(*, identifiers: set[tuple[str, str]]) -> Any:
        for domain, entry_id in identifiers:
            if domain == DOMAIN and entry_id in mapping:
                return SimpleNamespace(id=mapping[entry_id])
        return None

    def get_by_identifier(identifier: tuple[str, str], config_entry_id: str) -> Any:
        domain, entry_id = identifier
        if domain == DOMAIN and entry_id == config_entry_id and entry_id in mapping:
            return SimpleNamespace(id=mapping[entry_id])
        return None

    # both: HA 2026.8+ (by identifier) and the 2026.2 floor (async_get_device)
    return SimpleNamespace(
        async_get_device=get_device, async_get_device_by_identifier=get_by_identifier
    )
