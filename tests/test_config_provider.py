"""Tests for the config-manager backup provider (Configuration API v1).

The provider is driven with a fake api (the four ``config_*`` read methods
only), a fake coordinator holding ``router_info``, a fake registry and a
scoped artifact reader that checks sha256 like the core does. No network,
no Home Assistant instance, no router.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import gzip
import hashlib
import inspect
import io
import json
import logging
import random
import tarfile
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router import config_provider as cp
from custom_components.openwrt_router.api import (
    OpenWrtAuthError,
    OpenWrtConfigFetchHostKeyError,
    OpenWrtConfigFetchIncompleteError,
    OpenWrtConfigFetchNotAvailableError,
    OpenWrtConfigFetchPermissionError,
    OpenWrtConfigFetchTooLargeError,
    OpenWrtConnectionError,
    OpenWrtHostKeyError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.config_archive import validate_archive
from custom_components.openwrt_router.config_collector import PinnedSsh
from custom_components.openwrt_router.config_const import (
    FETCH_TIMEOUTS,
    UCI_CONFIGS,
    UCI_TEXT_MAX_BYTES,
)
from custom_components.openwrt_router.config_provider import (
    PROVIDER_ID,
    ConfigManagerProvider,
    error_for_class,
)
from custom_components.openwrt_router.config_snapshot import parse_uci_file
from custom_components.openwrt_router.core_errors import (
    ArtifactTooLargeError,
    AuthorizationError,
    BackupIncompleteError,
    BackupIntegrityError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ErrorClass,
    InstallationKeyLostError,
    OperationTimeoutError,
    ProviderError,
    RouterAuthError,
    RouterNotFoundError,
    RouterPermissionError,
    RouterUnavailableError,
)
from custom_components.openwrt_router.core_models import (
    BACKUP_ID_PREFIX,
    CONFIG_CAPABILITIES,
    PROVIDER_API_VERSION,
    SNAPSHOT_FORMAT_UCI_NORMALIZED,
    WARNING_CODE_PATTERN,
    Actor,
    ArtifactRef,
    BackupReason,
    BackupRecord,
    BackupType,
    Capability,
    CapabilityReason,
    CapabilityState,
    CaptureRequest,
    ChangeKind,
    CollectedVersion,
    CollectRequest,
    ConfigBackupProvider,
    ConfigRef,
    ConfigSnapshot,
    ConnectionInfo,
    DriftAck,
    DriftAckState,
    FirmwareInfo,
    InstallationKeyState,
    ProviderContext,
    RecordState,
    RouterConnection,
    RouterIdentity,
    RouterRecord,
    StorageRef,
    Transport,
    ValidationStatus,
    VersionStatus,
    installation_key_id,
    new_id,
    utcnow,
)

KEY = bytes(range(32))
OTHER_KEY = bytes(range(100, 132))
HOST_A = "192.168.1.1"
ROUTER_A = "rtr_" + "a" * 32
ROUTER_B = "rtr_" + "b" * 32
BOARD = "cudy,wr3000-v1"
OTHER_BOARD = "glinet,gl-mt6000"

WLAN_KEY = "ProvSecret#WlanKey1"
GUEST_KEY = "ProvSecret#Guest2"
PPP_PASSWORD = "ProvSecret#Ppp3"
SHADOW_HASH = "$6$ARCHIVESECRET$abcdefghijklmnop"
PLAINTEXT = (WLAN_KEY, GUEST_KEY, PPP_PASSWORD, "ARCHIVESECRET")

# ---------------------------------------------------------------------------
# Router fixture: UCI files, ubus form, archive
# ---------------------------------------------------------------------------

NETWORK = f"""\
config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'lan1'
\tlist ports 'lan2'

config bridge-vlan
\toption device 'br-lan'
\toption vlan '1'
\tlist ports 'lan1:u*'
\tlist ports 'lan2:u*'

config interface 'lan'
\toption device 'br-lan.1'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'wan'
\toption proto 'pppoe'
\toption username 'isp-user@example'
\toption password '{PPP_PASSWORD}'
"""

WIRELESS = f"""\
config wifi-device 'radio0'
\toption type 'mac80211'
\toption band '2g'
\toption channel '6'
\toption country 'DE'

config wifi-iface 'default_radio0'
\toption device 'radio0'
\toption network 'lan'
\toption mode 'ap'
\toption ssid 'PlainHomeSsid'
\toption encryption 'sae-mixed'
\toption key '{WLAN_KEY}'

config wifi-iface
\toption device 'radio0'
\toption network 'lan'
\toption mode 'ap'
\toption ssid 'Gast Netz'
\toption encryption 'psk2'
\toption key '{GUEST_KEY}'
"""

FIREWALL = """\
config defaults
\toption input 'REJECT'
\toption output 'ACCEPT'
\toption forward 'REJECT'

config zone
\toption name 'lan'
\tlist network 'lan'
\toption input 'ACCEPT'
"""

SYSTEM = """\
config system
\toption hostname 'OpenWrt-GW'
\toption timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
"""

FILES: dict[str, str] = {
    "network": NETWORK,
    "wireless": WIRELESS,
    "firewall": FIREWALL,
    "system": SYSTEM,
}

PACKAGES = {
    "base-files": "1641",
    "cgi-io": "2024.09.13",
    "dnsmasq": "2.90-r4",
    "dropbear": "2024.86-r1",
    "firewall4": "2024.12.18",
    "luci-base": "25.001",
    "rpcd": "2024.09.17",
    "uhttpd": "2023.06.25",
}


def changed(
    files: Mapping[str, str] = FILES,
    *,
    channel: bool = False,
    vlan: bool = False,
    firewall: bool = False,
    netmask: bool = False,
    wlan_key: bool = False,
) -> dict[str, str]:
    """A copy of ``files`` with the named edits made on the router."""
    out = dict(files)

    def edit(config: str, old: str, new: str) -> None:
        assert out[config].count(old) == 1, (config, old)
        out[config] = out[config].replace(old, new)

    if channel:
        edit("wireless", "option channel '6'", "option channel '11'")
    if vlan:
        edit("network", "list ports 'lan2:u*'", "list ports 'lan2:t'")
    if firewall:
        edit("firewall", "option input 'ACCEPT'", "option input 'REJECT'")
    if netmask:
        edit(
            "network", "option netmask '255.255.255.0'", "option netmask '255.255.0.0'"
        )
    if wlan_key:
        edit("wireless", f"option key '{WLAN_KEY}'", "option key 'ProvSecret#NewKey9'")
    return out


def to_ubus(parsed: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """parse_uci_file output in the shape rpcd ``uci get`` returns."""
    out: dict[str, dict[str, Any]] = {}
    for pos, (key, body) in enumerate(parsed.items()):
        anonymous = bool(body.get(".anonymous"))
        name = f"cfg{0x0A1B2C + pos * 0x111:06x}" if anonymous else key
        section = {
            k: copy.deepcopy(v) for k, v in body.items() if not k.startswith(".")
        }
        out[name] = {
            ".anonymous": anonymous,
            ".type": body[".type"],
            ".name": name,
            ".index": pos,
            **section,
        }
    return out


def ubus_values(files: Mapping[str, str] = FILES) -> dict[str, Any]:
    return {name: to_ubus(parse_uci_file(text)) for name, text in files.items()}


def make_archive(
    files: Mapping[str, str] = FILES,
    *,
    mtime: int = 1_700_000_000,
    gzip_mtime: int = 0,
) -> bytes:
    """A sysupgrade-shaped backup: etc/config/*, shadow, host key."""
    members: dict[str, bytes] = {
        f"etc/config/{name}": text.encode() for name, text in files.items()
    }
    members["etc/shadow"] = f"root:{SHADOW_HASH}:19000:0:99999:7:::\n".encode()
    members["etc/dropbear/dropbear_ed25519_host_key"] = bytes(range(83))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600 if "shadow" in name or "dropbear" in name else 0o644
            info.mtime = mtime
            info.uname = info.gname = "root"
            tf.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=gzip_mtime)


ARCHIVE = make_archive()


def router_info(board: str = BOARD, version: str = "24.10.4") -> dict[str, Any]:
    return {
        "model": "Cudy WR3000 v1" if board == BOARD else "GL.iNet GL-MT6000",
        "hostname": "OpenWrt-GW",
        "board_name": board,
        "kernel": "6.6.104",
        "release": {
            "version": version,
            "revision": "r28959-29397011cc",
            "target": "mediatek/filogic",
        },
    }


# ---------------------------------------------------------------------------
# Fakes: api, coordinator, registry, version store, context
# ---------------------------------------------------------------------------

Outcome = Any  # a value, an exception instance, or a callable (maybe async)


def hang() -> Any:
    """Outcome of a call that never answers."""
    return asyncio.Event().wait()


class FakeApi:
    """The ``config_*`` read methods of OpenWrtAPI, nothing else."""

    def __init__(
        self,
        *,
        files: Mapping[str, str] = FILES,
        cgi: Outcome = None,
        ssh: Outcome = None,
        uci: Mapping[str, Outcome] | None = None,
        packages: Outcome = PACKAGES,
        access: Outcome = True,
        root: bool = True,
    ) -> None:
        self.cgi = make_archive(files) if cgi is None else cgi
        self.ssh = make_archive(files) if ssh is None else ssh
        self.uci = dict(ubus_values(files) if uci is None else uci)
        self.packages = packages
        self.access = access
        self.root = root
        self.calls: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, Any]] = []
        # The pinned runner handed in by each SSH-capable call (None = none).
        self.runners: list[Any] = []

    async def _play(self, outcome: Outcome) -> Any:
        await asyncio.sleep(0)
        if callable(outcome):
            outcome = outcome()
            if asyncio.iscoroutine(outcome):
                outcome = await outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return copy.deepcopy(outcome)

    async def config_fetch_backup_cgi(self, *, max_bytes: int, timeout: float) -> bytes:
        self.calls.append(("cgi",))
        self.kwargs.append({"max_bytes": max_bytes, "timeout": timeout})
        return await self._play(self.cgi)

    async def config_fetch_backup_ssh(
        self, *, max_bytes: int, timeout: float, ssh: Any = None
    ) -> bytes:
        self.calls.append(("ssh",))
        self.runners.append(ssh)
        self.kwargs.append({"max_bytes": max_bytes, "timeout": timeout})
        return await self._play(self.ssh)

    async def config_uci_get(self, config: str, *, ssh: Any = None) -> dict[str, Any]:
        self.calls.append(("uci", config))
        self.runners.append(ssh)
        outcome = self.uci.get(
            config, OpenWrtConfigFetchNotAvailableError(f"uci get {config}: no such")
        )
        return await self._play(outcome)

    async def config_packagelist(self, *, ssh: Any = None) -> dict[str, str] | None:
        self.calls.append(("packagelist",))
        self.runners.append(ssh)
        return await self._play(self.packages)

    async def config_backup_access(self) -> bool | None:
        self.calls.append(("backup_access",))
        return await self._play(self.access)

    def config_ssh_user_is_root(self) -> bool:
        self.calls.append(("ssh_user_is_root",))
        return self.root


def methods(api: FakeApi) -> list[str]:
    return [call[0] for call in api.calls]


def every_config(outcome: Outcome) -> dict[str, Outcome]:
    return dict.fromkeys(UCI_CONFIGS, outcome)


class FakeCoordinator:
    """Holds ``router_info`` like OpenWrtCoordinator.router_info."""

    def __init__(self, info: Mapping[str, Any]) -> None:
        self.router_info = info


def router_record(
    router_id: str = ROUTER_A,
    *,
    host: str = HOST_A,
    board: str = BOARD,
    state: RecordState = RecordState.ACTIVE,
) -> RouterRecord:
    return RouterRecord(
        identity=RouterIdentity(
            router_id=router_id,
            entry_id="entry-" + router_id[-4:],
            management_host=host,
            model="Cudy WR3000 v1",
            board_name=board,
            architecture="aarch64_cortex-a53",
            openwrt_version="24.10.4",
        ),
        state=state,
        connection=ConnectionInfo(
            host=host, port=80, protocol="http", transport=Transport.UBUS
        ),
        firmware=FirmwareInfo(
            version="24.10.4", board_name=board, target="mediatek/filogic"
        ),
    )


class FakeRegistry:
    """Read side of the router registry (only what the provider may use)."""

    def __init__(self, *records: RouterRecord) -> None:
        self.records = {r.router_id: r for r in records}

    def get(self, router_id: str) -> RouterRecord:
        if router_id not in self.records:
            raise RouterNotFoundError(router_id=router_id)
        return self.records[router_id]

    def find(self, router_id: str) -> RouterRecord | None:
        return self.records.get(router_id)

    def list(self, *, include_orphaned: bool = False) -> tuple[RouterRecord, ...]:
        return tuple(self.records.values())


class Store:
    """Stands in for the core's version store: bytes plus index records."""

    def __init__(self) -> None:
        self.records: dict[str, BackupRecord] = {}
        self.blobs: dict[tuple[str, str], bytes] = {}
        self.reads: list[tuple[str, str]] = []

    def _record(
        self, router_id: str, blobs: Mapping[str, tuple[bytes, str]], **fields: Any
    ) -> BackupRecord:
        backup_id = fields.pop("backup_id", None) or new_id(BACKUP_ID_PREFIX)
        artifacts = {}
        for kind, (data, content_type) in blobs.items():
            artifacts[kind] = ArtifactRef(
                storage=StorageRef(locator=f"{backup_id}.{kind}"),
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
                content_type=content_type,
            )
            self.blobs[(backup_id, kind)] = data
        record = BackupRecord(
            backup_id=backup_id,
            router_id=router_id,
            created_at=utcnow(),
            created_by=Actor.system(),
            artifacts=artifacts,
            **fields,
        )
        self.records[backup_id] = record
        return record

    def put(self, router_id: str, version: CollectedVersion) -> BackupRecord:
        meta = version.meta
        for payload in version.artifacts.values():
            assert hashlib.sha256(payload.data).hexdigest() == payload.sha256
        return self._record(
            router_id,
            {k: (p.data, p.content_type) for k, p in version.artifacts.items()},
            backup_type=meta.backup_type,
            reason=meta.reason,
            status=meta.status,
            error_class=meta.error_class,
            fetch_method=meta.fetch_method,
            content_hash=meta.content_hash,
            uci_hash=meta.uci_hash,
            openwrt_version=meta.openwrt_version,
            hardware_model=meta.hardware_model,
            board_name=meta.board_name,
            compatibility=meta.compatibility,
            contains_secrets=meta.contains_secrets,
            warnings=meta.warnings,
            installation_key_id=meta.installation_key_id,
        )

    def put_raw(
        self,
        router_id: str,
        blobs: Mapping[str, bytes],
        *,
        backup_type: BackupType = BackupType.FULL_ARCHIVE,
        **fields: Any,
    ) -> BackupRecord:
        types = {"archive": "application/gzip"}
        return self._record(
            router_id,
            {k: (v, types.get(k, "application/json")) for k, v in blobs.items()},
            backup_type=backup_type,
            reason=BackupReason.IMPORT,
            **fields,
        )


_NO_SSH: Any = object()


async def _unexpected_ssh(*_args: Any) -> Any:
    raise AssertionError("no pinned SSH call expected")


def make_ctx(
    store: Store | None = None,
    *,
    key: bytes = KEY,
    lost: bool = False,
    verify: bool = True,
    registry: FakeRegistry | None = None,
    ssh: Any = _NO_SSH,
) -> ProviderContext:
    """``ssh``: the core's pinned runner (default: one that must not run,
    FakeApi never calls it; None = the core has no pin store)."""
    store = store if store is not None else Store()

    async def read(version_id: str, kind: str) -> bytes:
        await asyncio.sleep(0)
        store.reads.append((version_id, kind))
        data = store.blobs.get((version_id, kind))
        if data is None:
            raise BackupNotFoundError(f"no {kind} for this version")
        expected = store.records[version_id].artifacts[kind].sha256
        if verify and hashlib.sha256(data).hexdigest() != expected:
            raise BackupIntegrityError("stored bytes do not match the index")
        return data

    async def installation_key() -> bytes:
        await asyncio.sleep(0)
        if lost:
            raise InstallationKeyLostError("installation key store is unreadable")
        return key

    return ProviderContext(
        registry=registry if registry is not None else FakeRegistry(router_record()),
        read=read,
        installation_key=installation_key,
        installation_key_state=(
            InstallationKeyState.LOST if lost else InstallationKeyState.OK
        ),
        ssh=_unexpected_ssh if ssh is _NO_SSH else ssh,
    )


def make_conn(
    api: FakeApi,
    router_id: str = ROUTER_A,
    info: Mapping[str, Any] | None = None,
) -> RouterConnection:
    return RouterConnection(
        router_id=router_id,
        entry_id="entry-" + router_id[-4:],
        api=api,  # type: ignore[arg-type]
        coordinator=FakeCoordinator(info or router_info()),  # type: ignore[arg-type]
        transport=Transport.UBUS,
    )


def collect_request(router_id: str = ROUTER_A, **kwargs: Any) -> CollectRequest:
    return CollectRequest(
        router_id=router_id,
        backup_type=kwargs.pop("backup_type", BackupType.FULL_ARCHIVE),
        reason=kwargs.pop("reason", BackupReason.MANUAL),
        actor=Actor.system(),
        **kwargs,
    )


async def collect(
    api: FakeApi | None = None,
    *,
    provider: ConfigManagerProvider | None = None,
    ctx: ProviderContext | None = None,
    key: bytes = KEY,
    router_id: str = ROUTER_A,
    info: Mapping[str, Any] | None = None,
    **request: Any,
) -> CollectedVersion:
    api = api if api is not None else FakeApi()
    provider = provider or ConfigManagerProvider()
    return await provider.async_collect(
        make_conn(api, router_id, info),
        collect_request(router_id, **request),
        ctx if ctx is not None else make_ctx(key=key),
    )


def uci_doc(version: CollectedVersion) -> dict[str, Any]:
    return json.loads(version.artifacts["uci"].data)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Protocol
# ---------------------------------------------------------------------------

_PROTOCOL_METHODS = (
    "supported",
    "async_probe",
    "async_capture",
    "async_collect",
    "async_validate",
    "async_compare",
    "async_detect_drift",
    "async_prepare_restore",
    "async_execute_restore",
)


def test_provider_satisfies_the_protocol() -> None:
    provider = ConfigManagerProvider()
    assert isinstance(provider, ConfigBackupProvider)
    assert provider.provider_id == PROVIDER_ID == "config_manager"
    assert provider.provider_api_version == PROVIDER_API_VERSION
    # Signatures are copied from core_models, annotations included.
    for name in _PROTOCOL_METHODS:
        ours = inspect.signature(getattr(ConfigManagerProvider, name))
        theirs = inspect.signature(getattr(ConfigBackupProvider, name))
        assert ours == theirs, name
        assert inspect.iscoroutinefunction(
            getattr(ConfigManagerProvider, name)
        ) == inspect.iscoroutinefunction(getattr(ConfigBackupProvider, name))


def test_supported_only_for_active_records() -> None:
    provider = ConfigManagerProvider()
    assert provider.supported(router_record())
    assert not provider.supported(router_record(state=RecordState.ORPHANED))


def test_constructor_rejects_bad_timeouts() -> None:
    with pytest.raises(ValueError):
        ConfigManagerProvider(timeouts={"job": 0})
    with pytest.raises(ValueError):
        ConfigManagerProvider(timeouts={"job": float("nan")})


# ---------------------------------------------------------------------------
# Collect: full archive
# ---------------------------------------------------------------------------


async def test_collect_delivers_three_artifacts_with_consistent_metadata() -> None:
    api = FakeApi()
    version = await collect(api)

    assert set(version.artifacts) == {"archive", "uci", "inventory"}
    for payload in version.artifacts.values():
        assert payload.sha256 == sha(payload.data)
    archive = version.artifacts["archive"]
    assert archive.data == ARCHIVE  # the router's archive, unchanged
    assert archive.content_type == "application/gzip"
    assert version.artifacts["uci"].content_type == "application/json"
    assert version.artifacts["inventory"].content_type == "application/json"

    meta = version.meta
    assert meta.backup_type is BackupType.FULL_ARCHIVE
    assert meta.status is VersionStatus.OK
    assert meta.error_class is None
    assert meta.reason is BackupReason.MANUAL
    assert meta.fetch_method == "cgi"
    assert meta.content_hash == validate_archive(ARCHIVE).content_hash
    assert meta.installation_key_id == installation_key_id(KEY)
    assert meta.board_name == BOARD
    assert meta.hardware_model == "Cudy WR3000 v1"
    assert meta.openwrt_version == "24.10.4"
    assert meta.contains_secrets is True
    compat = meta.compatibility
    assert compat is not None
    assert compat.format == "sysupgrade_tar_gz"
    assert (compat.board_name, compat.target) == (BOARD, "mediatek/filogic")
    assert compat.architecture == "aarch64_cortex-a53"  # from the registry
    assert compat.package_manager == "opkg"

    doc = uci_doc(version)
    assert doc["format"] == SNAPSHOT_FORMAT_UCI_NORMALIZED
    assert doc["format_version"] == 1
    assert doc["uci_hash"] == meta.uci_hash
    assert doc["installation_key_id"] == meta.installation_key_id
    assert doc["source"] == "live"
    assert set(doc["configs"]) == set(FILES)
    assert set(doc["missing"]) == set(UCI_CONFIGS) - set(FILES)

    inventory = json.loads(version.artifacts["inventory"].data)
    assert inventory["format"] == "inventory"
    assert inventory["board_name"] == BOARD
    assert inventory["packages"] == PACKAGES
    assert inventory["partial"] is False
    assert "etc/config/network" in inventory["archive_members"]

    # Configs the router does not have are named, configs it has are not.
    assert "uci_missing:dropbear" in meta.warnings
    assert not any(w.endswith(":network") for w in meta.warnings)
    assert not any(w.startswith("uci_archive_mismatch") for w in meta.warnings)
    assert all(WARNING_CODE_PATTERN.fullmatch(w) for w in meta.warnings)
    assert all("/" not in w for w in meta.warnings)
    assert len(meta.warnings) <= 50

    # cgi delivered, so ssh was never asked.
    assert "ssh" not in methods(api)
    assert methods(api).count("cgi") == 1


async def test_store_accepts_collected_version_and_record_is_usable() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    assert record.usable
    assert record.sha256 == sha(ARCHIVE)


async def test_uci_artifact_holds_digests_not_plaintext() -> None:
    version = await collect()
    text = version.artifacts["uci"].data.decode("ascii")
    inventory = version.artifacts["inventory"].data.decode("ascii")
    for secret in PLAINTEXT:
        assert secret not in text
        assert secret not in inventory
        assert secret not in repr(version)
    key = uci_doc(version)["configs"]["wireless"]["sections"]["default_radio0"][
        "options"
    ]["key"]
    assert set(key) == {"secret"}
    assert len(key["secret"]) == 16
    # The archive artifact is the router's file and does hold the secrets.
    assert version.meta.contains_secrets is True


async def test_same_configuration_twice_gives_same_hashes() -> None:
    first = await collect(FakeApi(cgi=make_archive(mtime=1_700_000_000)))
    second = await collect(
        FakeApi(cgi=make_archive(mtime=1_800_000_000, gzip_mtime=1_800_000_000))
    )
    assert first.artifacts["archive"].sha256 != second.artifacts["archive"].sha256
    assert first.meta.content_hash == second.meta.content_hash
    assert first.meta.uci_hash == second.meta.uci_hash
    assert first.artifacts["uci"].data == second.artifacts["uci"].data
    assert first.artifacts["inventory"].data == second.artifacts["inventory"].data

    edited = changed(channel=True)
    third = await collect(FakeApi(files=edited))
    assert third.meta.content_hash != first.meta.content_hash
    assert third.meta.uci_hash != first.meta.uci_hash


async def test_preferred_fetch_method_goes_first() -> None:
    api = FakeApi()
    version = await collect(api, fetch_method="ssh")
    assert methods(api)[0] == "ssh"
    assert version.meta.fetch_method == "ssh"


async def test_unknown_fetch_method_is_invalid() -> None:
    api = FakeApi()
    with pytest.raises(ProviderError) as info:
        await collect(api, fetch_method="ftp")
    assert info.value.error_class is ErrorClass.INVALID
    assert api.calls == []


async def test_uses_hass_executor_when_given() -> None:
    class Hass:
        calls = 0

        async def async_add_executor_job(self, func: Callable, *args: Any) -> Any:
            Hass.calls += 1
            return await asyncio.get_running_loop().run_in_executor(None, func, *args)

    version = await collect(provider=ConfigManagerProvider(Hass()))  # type: ignore[arg-type]
    assert Hass.calls >= 1
    assert version.meta.status is VersionStatus.OK


# ---------------------------------------------------------------------------
# Collect: partial success, no archive path, failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cgi", "ssh", "error_class"),
    [
        (
            OpenWrtConfigFetchIncompleteError("cut off"),
            OpenWrtConfigFetchIncompleteError("exit 1"),
            ErrorClass.INCOMPLETE,
        ),
        (OpenWrtConfigFetchTooLargeError("cap"), None, ErrorClass.TOO_LARGE),
        (OpenWrtTimeoutError("slow"), None, ErrorClass.TIMEOUT),
        (
            OpenWrtConfigFetchIncompleteError("cut off"),
            OpenWrtConfigFetchPermissionError("not root"),
            ErrorClass.INCOMPLETE,
        ),
    ],
)
async def test_archive_failed_but_uci_ok_is_partial(
    cgi: BaseException, ssh: BaseException | None, error_class: ErrorClass
) -> None:
    api = FakeApi(cgi=cgi, ssh=ssh if ssh is not None else ARCHIVE)
    version = await collect(api)
    meta = version.meta
    assert meta.backup_type is BackupType.PARTIAL
    assert meta.status is VersionStatus.PARTIAL
    assert meta.error_class is error_class
    assert set(version.artifacts) == {"uci", "inventory"}
    assert meta.content_hash is None
    assert meta.uci_hash == uci_doc(version)["uci_hash"]
    assert meta.fetch_method == "uci"
    assert meta.contains_secrets is False
    record = Store().put(ROUTER_A, version)
    assert not record.usable


async def test_router_without_archive_path_gives_usable_uci_snapshot() -> None:
    api = FakeApi(
        cgi=OpenWrtConfigFetchNotAvailableError("no cgi-io"),
        ssh=OpenWrtConfigFetchPermissionError("not root"),
    )
    version = await collect(api)
    meta = version.meta
    assert meta.backup_type is BackupType.UCI_SNAPSHOT
    assert meta.status is VersionStatus.OK
    assert meta.error_class is None
    assert "archive_unavailable:permission" in meta.warnings
    assert set(version.artifacts) == {"uci", "inventory"}
    assert meta.content_hash is None
    assert meta.fetch_method == "uci"
    assert meta.contains_secrets is False
    assert meta.compatibility is not None
    assert meta.compatibility.format == SNAPSHOT_FORMAT_UCI_NORMALIZED
    assert Store().put(ROUTER_A, version).usable

    # Same uci_hash as a full backup of the same configuration (dedup key).
    full = await collect(FakeApi())
    assert meta.uci_hash == full.meta.uci_hash


async def test_uci_snapshot_request_never_asks_for_the_archive() -> None:
    api = FakeApi()
    version = await collect(api, backup_type=BackupType.UCI_SNAPSHOT)
    assert "cgi" not in methods(api) and "ssh" not in methods(api)
    assert version.meta.backup_type is BackupType.UCI_SNAPSHOT
    assert version.meta.status is VersionStatus.OK
    assert not any(w.startswith("archive_") for w in version.meta.warnings)

    api = FakeApi()
    await collect(api, fetch_method="uci")
    assert "cgi" not in methods(api)


async def test_archive_with_live_uci_failure_uses_the_archive_snapshot() -> None:
    api = FakeApi(uci=every_config(OpenWrtConfigFetchPermissionError("acl")))
    version = await collect(api)
    assert version.meta.backup_type is BackupType.FULL_ARCHIVE
    assert version.meta.status is VersionStatus.OK
    assert "uci_source:archive" in version.meta.warnings
    assert "uci_failed:network" in version.meta.warnings
    assert uci_doc(version)["source"] == "archive"
    assert version.meta.uci_hash == (await collect()).meta.uci_hash


async def test_config_missing_in_archive_is_a_warning() -> None:
    archive_files = {k: v for k, v in FILES.items() if k != "firewall"}
    api = FakeApi(cgi=make_archive(archive_files))
    version = await collect(api)
    assert version.meta.status is VersionStatus.OK
    assert "config_missing_in_archive:firewall" in version.meta.warnings


@pytest.mark.parametrize(
    ("error", "expected", "error_class"),
    [
        (
            OpenWrtConnectionError("down"),
            RouterUnavailableError,
            ErrorClass.UNREACHABLE,
        ),
        (OpenWrtTimeoutError("slow"), OperationTimeoutError, ErrorClass.TIMEOUT),
        (OpenWrtAuthError("login"), RouterAuthError, ErrorClass.AUTH),
    ],
)
async def test_dead_router_raises_the_mapped_error(
    error: BaseException, expected: type[Exception], error_class: ErrorClass
) -> None:
    api = FakeApi(cgi=error, ssh=error, uci=every_config(error), packages=error)
    with pytest.raises(expected) as info:
        await collect(api)
    assert info.value.error_class is error_class  # type: ignore[attr-defined]
    assert info.value.router_id == ROUTER_A  # type: ignore[attr-defined]
    # The UCI run stops at the first dead answer.
    assert methods(api).count("uci") == 1


async def test_permission_everywhere_raises_router_permission_error() -> None:
    denied = OpenWrtConfigFetchPermissionError("acl")
    api = FakeApi(cgi=denied, ssh=denied, uci=every_config(denied))
    with pytest.raises(RouterPermissionError):
        await collect(api)


async def test_nothing_available_raises_capability_unavailable() -> None:
    missing = OpenWrtConfigFetchNotAvailableError("none")
    api = FakeApi(cgi=missing, ssh=missing, uci=every_config(missing))
    with pytest.raises(CapabilityUnavailableError) as info:
        await collect(api)
    assert info.value.capability == Capability.CONFIG_BACKUP


async def test_archive_class_wins_when_uci_has_nothing() -> None:
    missing = OpenWrtConfigFetchNotAvailableError("none")
    api = FakeApi(cgi=OpenWrtConfigFetchTooLargeError("cap"), uci=every_config(missing))
    with pytest.raises(ArtifactTooLargeError):
        await collect(api)
    api = FakeApi(
        cgi=OpenWrtConfigFetchIncompleteError("cut"),
        ssh=OpenWrtConfigFetchIncompleteError("cut"),
        uci=every_config(missing),
    )
    with pytest.raises(BackupIncompleteError):
        await collect(api)


@pytest.mark.parametrize(
    ("error_class", "expected"),
    [
        ("unreachable", RouterUnavailableError),
        ("timeout", OperationTimeoutError),
        ("auth", RouterAuthError),
        ("permission", RouterPermissionError),
        ("not_available", CapabilityUnavailableError),
        ("too_large", ArtifactTooLargeError),
        ("incomplete", BackupIncompleteError),
        ("invalid", ProviderError),
        ("checksum_mismatch", BackupIntegrityError),
    ],
)
def test_error_class_mapping(error_class: str, expected: type[Exception]) -> None:
    err = error_for_class(error_class, router_id=ROUTER_A, operation="collect")
    assert type(err) is expected
    assert err.error_class == ErrorClass(error_class)
    assert err.router_id == ROUTER_A


@pytest.mark.parametrize(
    "archive",
    [
        make_archive({k: v for k, v in FILES.items() if k != "network"}),
        ARCHIVE[: len(ARCHIVE) // 2] + bytes(len(ARCHIVE) - len(ARCHIVE) // 2),
        b"<html>login</html>",
        gzip.compress(b"not a tar archive at all" * 40),
    ],
    ids=["incomplete", "tampered", "not_gzip", "not_tar"],
)
async def test_bad_archive_is_never_delivered_as_valid(archive: bytes) -> None:
    version = await collect(FakeApi(cgi=archive))
    assert "archive" not in version.artifacts
    assert version.meta.status is VersionStatus.PARTIAL
    assert version.meta.error_class in {ErrorClass.INCOMPLETE, ErrorClass.INVALID}
    assert version.meta.content_hash is None


# ---------------------------------------------------------------------------
# Deadline, key loss, cancellation, concurrency
# ---------------------------------------------------------------------------


def short(job: float) -> ConfigManagerProvider:
    return ConfigManagerProvider(timeouts={**FETCH_TIMEOUTS, "job": job})


async def test_hanging_archive_uses_its_share_of_the_deadline() -> None:
    api = FakeApi(cgi=hang)
    started = time.monotonic()
    version = await collect(api, provider=short(0.6))
    elapsed = time.monotonic() - started
    assert elapsed < 0.6 + 0.4
    assert version.meta.status is VersionStatus.PARTIAL
    assert version.meta.error_class is ErrorClass.TIMEOUT
    assert {"uci", "inventory"} == set(version.artifacts)
    assert all(kw["timeout"] <= 0.6 for kw in api.kwargs)


async def test_everything_hanging_ends_in_a_clean_timeout() -> None:
    api = FakeApi(cgi=hang, ssh=hang, uci=every_config(hang), packages=hang)
    started = time.monotonic()
    with pytest.raises(OperationTimeoutError) as info:
        await collect(api, provider=short(0.5))
    assert time.monotonic() - started < 0.5 + 0.4
    assert info.value.router_id == ROUTER_A


async def test_total_deadline_covers_the_archive_check() -> None:
    class StuckHass:
        async def async_add_executor_job(self, func: Callable, *args: Any) -> Any:
            await asyncio.Event().wait()

    provider = ConfigManagerProvider(
        StuckHass(),  # type: ignore[arg-type]
        timeouts={**FETCH_TIMEOUTS, "job": 0.4},
    )
    started = time.monotonic()
    with pytest.raises(OperationTimeoutError):
        await collect(provider=provider)
    assert time.monotonic() - started < 0.4 + 0.4


async def test_key_loss_is_not_swallowed() -> None:
    api = FakeApi()
    provider = ConfigManagerProvider()
    ctx = make_ctx(lost=True)
    conn = make_conn(api)
    with pytest.raises(InstallationKeyLostError):
        await provider.async_collect(conn, collect_request(), ctx)
    with pytest.raises(InstallationKeyLostError):
        await provider.async_capture(
            conn, CaptureRequest(router_id=ROUTER_A, actor=Actor.system()), ctx
        )
    assert api.calls == []  # no router call without a key

    store = Store()
    record = store.put(ROUTER_A, await collect())
    lost = make_ctx(store, lost=True)
    with pytest.raises(InstallationKeyLostError):
        await provider.async_detect_drift(
            conn, record, (), lost, router=router_record()
        )
    with pytest.raises(InstallationKeyLostError):
        await provider.async_prepare_restore(conn, record, router_record(), lost)


async def test_cancelled_error_passes_through() -> None:
    api = FakeApi(cgi=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await collect(api)

    api = FakeApi(cgi=hang)
    task = asyncio.ensure_future(collect(api))
    while not api.calls:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_providers_for_different_routers_do_not_interfere() -> None:
    files_b = changed(channel=True, vlan=True)
    api_a, api_b = FakeApi(), FakeApi(files=files_b)
    shared = ConfigManagerProvider()

    async def slow_a() -> bytes:
        await asyncio.sleep(0.02)
        return ARCHIVE

    api_a.cgi = slow_a
    registry = FakeRegistry(router_record(), router_record(ROUTER_B, board=OTHER_BOARD))
    ctx = make_ctx(registry=registry)
    version_a, version_b, other = await asyncio.gather(
        collect(api_a, provider=shared, ctx=ctx),
        collect(
            api_b,
            provider=shared,
            ctx=ctx,
            router_id=ROUTER_B,
            info=router_info(OTHER_BOARD),
        ),
        collect(FakeApi(files=files_b), provider=ConfigManagerProvider()),
    )
    assert version_a.meta.board_name == BOARD
    assert version_b.meta.board_name == OTHER_BOARD
    assert version_a.meta.uci_hash != version_b.meta.uci_hash
    assert version_b.meta.uci_hash == other.meta.uci_hash
    assert version_a.artifacts["archive"].data == ARCHIVE
    assert version_b.artifacts["archive"].data == make_archive(files_b)
    # Each api saw exactly one collect run of its own.
    for api in (api_a, api_b):
        assert methods(api).count("cgi") == 1
        assert methods(api).count("packagelist") == 1
        assert [c[1] for c in api.calls if c[0] == "uci"] == list(UCI_CONFIGS)


# ---------------------------------------------------------------------------
# Capture
# ---------------------------------------------------------------------------


async def test_capture_returns_normalized_snapshot() -> None:
    api = FakeApi()
    provider = ConfigManagerProvider()
    snapshot = await provider.async_capture(
        make_conn(api),
        CaptureRequest(router_id=ROUTER_A, actor=Actor.system()),
        make_ctx(),
    )
    assert isinstance(snapshot, ConfigSnapshot)
    assert snapshot.format == SNAPSHOT_FORMAT_UCI_NORMALIZED
    assert snapshot.router_id == ROUTER_A
    assert snapshot.uci_hash == (await collect()).meta.uci_hash
    assert snapshot.installation_key_id == installation_key_id(KEY)
    assert snapshot.board_name == BOARD
    assert snapshot.openwrt_version == "24.10.4"
    assert set(snapshot.configs) == set(FILES)
    assert "cgi" not in methods(api)
    dumped = json.dumps(snapshot.to_dict())
    for secret in PLAINTEXT:
        assert secret not in dumped
        assert secret not in repr(snapshot)

    subset = await provider.async_capture(
        make_conn(FakeApi()),
        CaptureRequest(router_id=ROUTER_A, actor=Actor.system(), configs=("wireless",)),
        make_ctx(),
    )
    assert set(subset.configs) == {"wireless"}


async def test_capture_of_dead_router_raises() -> None:
    api = FakeApi(uci=every_config(OpenWrtConnectionError("down")))
    with pytest.raises(RouterUnavailableError):
        await ConfigManagerProvider().async_capture(
            make_conn(api),
            CaptureRequest(router_id=ROUTER_A, actor=Actor.system()),
            make_ctx(),
        )


# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------


async def test_validate_good_version() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    info = await ConfigManagerProvider().async_validate(record, make_ctx(store))
    assert info.status is ValidationStatus.VALID
    assert info.details is None
    assert info.checked_at is not None


async def test_validate_uci_only_version() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect(backup_type=BackupType.UCI_SNAPSHOT))
    info = await ConfigManagerProvider().async_validate(record, make_ctx(store))
    assert info.status is ValidationStatus.VALID


@pytest.mark.parametrize("verify", [True, False], ids=["core_check", "own_check"])
async def test_validate_catches_corrupt_bytes(verify: bool) -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    data = bytearray(store.blobs[(record.backup_id, "archive")])
    data[len(data) // 2] ^= 0xFF
    store.blobs[(record.backup_id, "archive")] = bytes(data)
    info = await ConfigManagerProvider().async_validate(
        record, make_ctx(store, verify=verify)
    )
    assert info.status is ValidationStatus.CORRUPT
    assert info.details is not None
    assert info.details.startswith("checksum_mismatch ")
    assert "archive." in info.details


async def test_validate_reports_missing_artifact() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    del store.blobs[(record.backup_id, "uci")]
    info = await ConfigManagerProvider().async_validate(record, make_ctx(store))
    assert info.status is ValidationStatus.MISSING
    assert info.details is not None and "uci.not_found" in info.details


async def test_validate_catches_invalid_structure() -> None:
    store = Store()
    good = await collect()
    garbage = gzip.compress(b"not a tar archive at all" * 40)
    record = store.put_raw(
        ROUTER_A,
        {
            "archive": garbage,
            "uci": good.artifacts["uci"].data,
            "inventory": good.artifacts["inventory"].data,
        },
    )
    provider = ConfigManagerProvider()
    info = await provider.async_validate(record, make_ctx(store))
    assert info.status is ValidationStatus.INVALID
    assert info.details is not None
    assert info.details.startswith("invalid ")
    assert "archive.invalid" in info.details

    broken_uci = store.put_raw(
        ROUTER_A,
        {"uci": b"{not json", "inventory": good.artifacts["inventory"].data},
        backup_type=BackupType.UCI_SNAPSHOT,
    )
    info = await provider.async_validate(broken_uci, make_ctx(store))
    assert info.status is ValidationStatus.INVALID
    assert info.details is not None and "uci." in info.details

    doc = uci_doc(good)
    doc["configs"]["wireless"]["sections"]["radio0"]["options"]["channel"] = "1"
    edited = json.dumps(doc).encode()
    mismatch = store.put_raw(
        ROUTER_A, {"uci": edited}, backup_type=BackupType.UCI_SNAPSHOT
    )
    info = await provider.async_validate(mismatch, make_ctx(store))
    assert info.status is ValidationStatus.INVALID
    assert info.details is not None and "uci.uci_hash_mismatch" in info.details

    no_archive = store.put_raw(ROUTER_A, {"uci": good.artifacts["uci"].data})
    info = await provider.async_validate(no_archive, make_ctx(store))
    assert info.status is ValidationStatus.INVALID
    assert info.details is not None and "archive.absent" in info.details
    for secret in PLAINTEXT:
        assert secret not in info.details
    assert "etc/" not in info.details


# ---------------------------------------------------------------------------
# Compare
# ---------------------------------------------------------------------------


def find_change(diff: Any, config: str, option: str | None = None) -> list[Any]:
    return [
        c
        for c in diff.changes
        if c.config == config and (option is None or c.option == option)
    ]


async def test_compare_two_versions() -> None:
    store = Store()
    base = store.put(ROUTER_A, await collect())
    edited = changed(channel=True, vlan=True, firewall=True, wlan_key=True)
    other = store.put(ROUTER_A, await collect(FakeApi(files=edited)))
    router = router_record()

    diff = await ConfigManagerProvider().async_compare(
        base, other, make_ctx(store), base_router=router, other_router=router
    )
    assert diff.base == ConfigRef.backup(base.backup_id)
    assert diff.other == ConfigRef.backup(other.backup_id)

    (channel,) = find_change(diff, "wireless", "channel")
    assert channel.kind is ChangeKind.MODIFIED
    assert (channel.before, channel.after) == ("6", "11")
    assert channel.area == "wlan"
    vlan = find_change(diff, "network")
    assert vlan and all(c.area == "vlan" and c.risk == "critical" for c in vlan)
    firewall = find_change(diff, "firewall")
    assert firewall and all(c.area == "firewall" for c in firewall)
    for change in diff.changes:
        assert change.area is not None and change.risk is not None

    (key,) = find_change(diff, "wireless", "key")
    assert key.kind is ChangeKind.MODIFIED  # same key: digests comparable
    dumped = json.dumps(diff.to_dict())
    for secret in (*PLAINTEXT, "ProvSecret#NewKey9"):
        assert secret not in dumped
        assert secret not in repr(diff)


async def test_compare_uses_management_host_of_the_router() -> None:
    store = Store()
    base = store.put(ROUTER_A, await collect())
    other = store.put(ROUTER_A, await collect(FakeApi(files=changed(netmask=True))))
    provider = ConfigManagerProvider()

    diff = await provider.async_compare(
        base,
        other,
        make_ctx(store),
        base_router=router_record(),
        other_router=router_record(),
    )
    (netmask,) = find_change(diff, "network", "netmask")
    assert (netmask.area, netmask.risk) == ("mgmt_ip", "critical")

    elsewhere = router_record(host="10.9.9.9")
    diff = await provider.async_compare(
        base, other, make_ctx(store), base_router=elsewhere, other_router=elsewhere
    )
    (netmask,) = find_change(diff, "network", "netmask")
    assert netmask.area != "mgmt_ip"


async def test_compare_live_snapshot_with_version() -> None:
    store = Store()
    base = store.put(ROUTER_A, await collect())
    provider = ConfigManagerProvider()
    live = await provider.async_capture(
        make_conn(FakeApi(files=changed(channel=True))),
        CaptureRequest(router_id=ROUTER_A, actor=Actor.system()),
        make_ctx(),
    )
    diff = await provider.async_compare(
        base,
        live,
        make_ctx(store),
        base_router=router_record(),
        other_router=router_record(),
    )
    assert diff.other == ConfigRef.live(ROUTER_A)
    assert [(c.config, c.option) for c in diff.changes] == [("wireless", "channel")]


async def test_compare_with_other_key_marks_secrets_not_comparable() -> None:
    store = Store()
    base = store.put(ROUTER_A, await collect())
    other = store.put(ROUTER_A, await collect(key=OTHER_KEY))
    diff = await ConfigManagerProvider().async_compare(
        base,
        other,
        make_ctx(store),
        base_router=router_record(),
        other_router=router_record(),
    )
    assert diff.changes
    assert all(c.kind is ChangeKind.NOT_COMPARABLE for c in diff.changes)
    assert diff.comparable_changes == ()


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


def ack(drift_id: str, state: DriftAckState, router_id: str = ROUTER_A) -> DriftAck:
    return DriftAck(
        router_id=router_id,
        drift_id=drift_id,
        state=state,
        actor=Actor.system(),
        ts=utcnow(),
        version_id=new_id(BACKUP_ID_PREFIX) if state is DriftAckState.KNOWN else None,
    )


async def test_drift_detection_with_acknowledgements() -> None:
    store = Store()
    baseline = store.put(ROUTER_A, await collect())
    provider = ConfigManagerProvider()
    router = router_record()

    async def check(files: Mapping[str, str], acks: tuple[DriftAck, ...] = ()):
        return await provider.async_detect_drift(
            make_conn(FakeApi(files=files)),
            baseline,
            acks,
            make_ctx(store),
            router=router,
        )

    same = await check(FILES)
    assert not same.drifted and same.drift_id is None and not same.diff.changes

    edited = changed(channel=True)
    report = await check(edited)
    assert report.drifted
    assert report.drift_id is not None and len(report.drift_id) == 64
    assert report.ack_state is None
    assert report.baseline_backup_id == baseline.backup_id
    assert report.secrets_comparable and not report.rebaseline
    assert report.diff.base == ConfigRef.backup(baseline.backup_id)
    assert report.diff.other == ConfigRef.live(ROUTER_A)
    assert [(c.config, c.option, c.kind) for c in report.diff.changes] == [
        ("wireless", "channel", ChangeKind.MODIFIED)
    ]
    assert report.unknown_count == 0

    seen = await check(edited, (ack(report.drift_id, DriftAckState.ACKNOWLEDGED),))
    assert seen.drifted and seen.ack_state is DriftAckState.ACKNOWLEDGED
    assert seen.drift_id == report.drift_id

    known_ack = ack(report.drift_id, DriftAckState.KNOWN)
    known = await check(edited, (known_ack,))
    assert not known.drifted and known.ack_state is DriftAckState.KNOWN

    foreign = await check(
        edited, (ack(report.drift_id, DriftAckState.KNOWN, router_id=ROUTER_B),)
    )
    assert foreign.drifted and foreign.ack_state is None

    critical = await check(changed(vlan=True))
    assert critical.drifted and critical.critical_count >= 1

    # Nothing was reset or stored: the baseline and the acks stay as they were.
    assert list(store.records) == [baseline.backup_id]
    assert known_ack.state is DriftAckState.KNOWN


async def test_drift_after_key_reset_is_a_rebaseline() -> None:
    """Only the secret digests differ: the baseline is rebuilt (review H1).

    Before the review fix this test used a channel change, which a key
    reset silently turned into "no drift".
    """
    store = Store()
    baseline = store.put(ROUTER_A, await collect(key=OTHER_KEY))
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(files=FILES)),
        baseline,
        (),
        make_ctx(store, key=KEY),
        router=router_record(),
    )
    assert report.rebaseline and not report.drifted
    assert not report.secrets_comparable
    secret = [c for c in report.diff.changes if c.option == "key"]
    assert secret and all(c.kind is ChangeKind.NOT_COMPARABLE for c in secret)


async def test_drift_against_baseline_without_key_id() -> None:
    store = Store()
    good = await collect()
    doc = uci_doc(good)
    doc["installation_key_id"] = None
    baseline = store.put_raw(
        ROUTER_A,
        {"uci": json.dumps(doc).encode()},
        backup_type=BackupType.UCI_SNAPSHOT,
        uci_hash=good.meta.uci_hash,
    )
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(files=changed(wlan_key=True))),
        baseline,
        (),
        make_ctx(store),
        router=router_record(),
    )
    assert not report.secrets_comparable and not report.rebaseline
    assert not report.drifted  # a secret change alone is no drift here
    (secret,) = [c for c in report.diff.changes if c.option == "key"]
    assert secret.kind is ChangeKind.NOT_COMPARABLE


async def test_drift_against_dead_router_raises() -> None:
    store = Store()
    baseline = store.put(ROUTER_A, await collect())
    api = FakeApi(uci=every_config(OpenWrtConnectionError("down")))
    with pytest.raises(RouterUnavailableError):
        await ConfigManagerProvider().async_detect_drift(
            make_conn(api), baseline, (), make_ctx(store), router=router_record()
        )


# ---------------------------------------------------------------------------
# Restore
# ---------------------------------------------------------------------------


async def test_restore_preparation_on_other_board_is_blocked() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    target_api = FakeApi(files=changed(channel=True))
    target = router_record(ROUTER_B, board=OTHER_BOARD, host="192.168.8.1")
    plan = await ConfigManagerProvider().async_prepare_restore(
        make_conn(target_api, ROUTER_B, router_info(OTHER_BOARD)),
        record,
        target,
        make_ctx(store, registry=FakeRegistry(router_record(), target)),
    )
    assert plan.plan_id.startswith("pln_")
    assert plan.provider_id == PROVIDER_ID
    assert (plan.source_router_id, plan.target_router_id) == (ROUTER_A, ROUTER_B)
    assert plan.backup_id == record.backup_id
    assert plan.compatibility.compatible is False
    issues = {issue.code: issue for issue in plan.compatibility.issues}
    assert issues["board_mismatch"].blocking
    assert plan.steps == () and not plan.requires_reboot
    assert "restore_not_reversible" in plan.instructions
    assert "restore_not_reversible" in plan.warnings
    assert plan.live_checksum is not None
    # Read only: the target was asked for UCI and packages, never an archive.
    assert set(methods(target_api)) <= {"uci", "packagelist"}
    dumped = json.dumps(plan.to_dict())
    for secret in PLAINTEXT:
        assert secret not in dumped


async def test_restore_preparation_on_same_board() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    plan = await ConfigManagerProvider().async_prepare_restore(
        make_conn(FakeApi(files=changed(channel=True))),
        record,
        router_record(),
        make_ctx(store),
    )
    assert plan.compatibility.compatible is True
    assert [step.action for step in plan.steps] == ["archive_restore", "reboot"]
    assert plan.requires_reboot
    assert plan.instructions[0] == "restore_not_reversible"
    assert plan.diff is not None
    assert plan.diff.base == ConfigRef.live(ROUTER_A)
    (channel,) = find_change(plan.diff, "wireless", "channel")
    assert (channel.before, channel.after) == ("11", "6")


async def test_restore_plan_warns_about_access_files_without_their_digests() -> None:
    """Review M4: shadow and host keys are named as a warning, never hashed out."""
    store = Store()
    version = await collect()
    shadow = f"root:{SHADOW_HASH}:19000:0:99999:7:::\n".encode()
    host_key = bytes(range(83))
    digests = (sha(shadow), sha(host_key))
    # The archive analysis does see both digests (change detection in HA) ...
    members = {m.name: m for m in validate_archive(ARCHIVE).members}
    assert members["etc/shadow"].sha256 == digests[0]
    assert members["etc/dropbear/dropbear_ed25519_host_key"].sha256 == digests[1]
    # ... but no artifact, warning or plan carries them.
    exported = [
        payload.data.decode()
        for name, payload in version.artifacts.items()
        if name != "archive"
    ]
    exported.append(repr(version.meta))
    record = store.put(ROUTER_A, version)
    plan = await ConfigManagerProvider().async_prepare_restore(
        make_conn(FakeApi(files=changed(channel=True))),
        record,
        router_record(),
        make_ctx(store),
    )
    assert "access_files_overwritten" in plan.warnings
    exported.append(json.dumps(plan.to_dict()))
    exported.append(repr(plan))
    for text in exported:
        for digest in digests:
            assert digest not in text
            assert digest.upper() not in text


async def test_restore_preparation_needs_an_archive() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect(backup_type=BackupType.UCI_SNAPSHOT))
    with pytest.raises(CapabilityUnavailableError) as info:
        await ConfigManagerProvider().async_prepare_restore(
            make_conn(FakeApi()), record, router_record(), make_ctx(store)
        )
    assert info.value.capability == Capability.CONFIG_RESTORE_DRY_RUN


async def test_restore_preparation_refuses_tampered_archive() -> None:
    store = Store()
    record = store.put(ROUTER_A, await collect())
    store.blobs[(record.backup_id, "archive")] = make_archive(changed(channel=True))
    with pytest.raises(BackupIntegrityError):
        await ConfigManagerProvider().async_prepare_restore(
            make_conn(FakeApi()), record, router_record(), make_ctx(store)
        )


async def test_execute_restore_refuses() -> None:
    api = FakeApi()
    with pytest.raises(CapabilityUnavailableError) as info:
        await ConfigManagerProvider().async_execute_restore(
            make_conn(api),
            object(),  # type: ignore[arg-type]
            object(),  # type: ignore[arg-type]
            make_ctx(),
        )
    assert info.value.capability == Capability.CONFIG_RESTORE
    assert info.value.reason == "provider:phase1"
    assert api.calls == []


# ---------------------------------------------------------------------------
# Probe
# ---------------------------------------------------------------------------


async def test_probe_reports_every_config_capability() -> None:
    api = FakeApi()
    caps = await ConfigManagerProvider().async_probe(make_conn(api), make_ctx())
    assert set(caps) == {str(c) for c in CONFIG_CAPABILITIES}
    for name, status in caps.items():
        assert status.capability == name
        assert status.source == "probe:config_manager"
    for name in (
        Capability.CONFIG_CGI_BACKUP,
        Capability.CONFIG_UCI_READ,
        Capability.CONFIG_PACKAGELIST,
        Capability.CONFIG_BACKUP,
        Capability.CONFIG_CAPTURE,
        Capability.CONFIG_DRIFT,
        Capability.CONFIG_RESTORE_DRY_RUN,
        Capability.CONFIG_VALIDATE,
        Capability.CONFIG_DIFF,
        Capability.CONFIG_EXPORT,
    ):
        assert caps[name].state is CapabilityState.AVAILABLE, name
    restore = caps[Capability.CONFIG_RESTORE]
    assert restore.state is CapabilityState.UNAVAILABLE
    assert restore.reason == "provider:phase1"
    detail = caps[Capability.CONFIG_UCI_READ].detail
    assert detail["network"] is True and detail["dropbear"] is False
    # SSH as root is only known to work after the first backup (review M1).
    ssh = caps[Capability.CONFIG_SSH_ROOT]
    assert ssh.state is CapabilityState.UNKNOWN
    assert ssh.reason == CapabilityReason.NOT_PROBED
    # No archive was fetched, so sysupgrade never ran on the router.
    assert not {"cgi", "ssh"} & set(methods(api))
    assert api.kwargs == []


async def test_probe_without_archive_rights() -> None:
    api = FakeApi(access=False, root=False, packages=None)
    caps = await ConfigManagerProvider().async_probe(make_conn(api), make_ctx())
    cgi = caps[Capability.CONFIG_CGI_BACKUP]
    assert cgi.state is CapabilityState.UNAVAILABLE
    assert cgi.reason == CapabilityReason.PERMISSION_DENIED
    assert cgi.required_permissions
    ssh = caps[Capability.CONFIG_SSH_ROOT]
    assert ssh.state is CapabilityState.UNAVAILABLE
    assert ssh.reason == CapabilityReason.PERMISSION_DENIED
    assert caps[Capability.CONFIG_PACKAGELIST].state is CapabilityState.UNAVAILABLE
    assert caps[Capability.CONFIG_BACKUP].state is CapabilityState.AVAILABLE
    assert caps[Capability.CONFIG_RESTORE_DRY_RUN].state is CapabilityState.UNAVAILABLE
    assert not {"cgi", "ssh"} & set(methods(api))


@pytest.mark.parametrize(
    ("access", "packages", "state", "reason"),
    [
        # rpcd gives no clear answer: unknown until the first backup.
        (None, PACKAGES, CapabilityState.UNKNOWN, CapabilityReason.NOT_PROBED),
        (
            OpenWrtConfigFetchIncompleteError("odd"),
            PACKAGES,
            CapabilityState.UNKNOWN,
            CapabilityReason.NOT_PROBED,
        ),
        # Right granted, but no package list to see cgi-io in.
        (True, None, CapabilityState.UNKNOWN, CapabilityReason.NOT_PROBED),
        # Right granted, package list known, cgi-io not installed.
        (
            True,
            {k: v for k, v in PACKAGES.items() if k != "cgi-io"},
            CapabilityState.UNAVAILABLE,
            CapabilityReason.NOT_DETECTED,
        ),
    ],
)
async def test_probe_never_creates_a_backup(
    access: Outcome, packages: Outcome, state: CapabilityState, reason: str
) -> None:
    """Review M1: rights and presence only; never a sysupgrade on the router."""
    boom = AssertionError("the probe must not fetch an archive")
    api = FakeApi(cgi=boom, ssh=boom, access=access, packages=packages)
    caps = await ConfigManagerProvider().async_probe(make_conn(api), make_ctx())
    cgi = caps[Capability.CONFIG_CGI_BACKUP]
    assert (cgi.state, cgi.reason) == (state, reason)
    assert not {"cgi", "ssh"} & set(methods(api))
    assert "backup_access" in methods(api)
    # Archive state unknown at best: the dry run is never claimed available.
    dry_run = caps[Capability.CONFIG_RESTORE_DRY_RUN]
    assert dry_run.state is not CapabilityState.AVAILABLE


async def test_probe_of_offline_router_is_unknown() -> None:
    down = OpenWrtConnectionError("down")
    api = FakeApi(cgi=down, ssh=down, uci=every_config(down), packages=down)
    caps = await ConfigManagerProvider().async_probe(make_conn(api), make_ctx())
    uci = caps[Capability.CONFIG_UCI_READ]
    assert uci.state is CapabilityState.UNKNOWN
    assert uci.reason == CapabilityReason.ROUTER_OFFLINE
    assert caps[Capability.CONFIG_CAPTURE].state is CapabilityState.UNKNOWN
    assert caps[Capability.CONFIG_BACKUP].state is CapabilityState.UNKNOWN
    assert caps[Capability.CONFIG_VALIDATE].state is CapabilityState.AVAILABLE
    assert "cgi" not in methods(api)  # no archive probe against a dead router
    assert "backup_access" not in methods(api)


# ---------------------------------------------------------------------------
# Logs and architecture
# ---------------------------------------------------------------------------


async def test_logs_hold_no_secrets_and_no_archive_bytes(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    store = Store()
    provider = ConfigManagerProvider()
    base = store.put(ROUTER_A, await collect())
    other = store.put(ROUTER_A, await collect(FakeApi(files=changed(wlan_key=True))))
    await provider.async_validate(base, make_ctx(store))
    await provider.async_compare(
        base,
        other,
        make_ctx(store),
        base_router=router_record(),
        other_router=router_record(),
    )
    await provider.async_detect_drift(
        make_conn(FakeApi(files=changed(wlan_key=True))),
        base,
        (),
        make_ctx(store),
        router=router_record(),
    )
    await provider.async_prepare_restore(
        make_conn(FakeApi()), base, router_record(), make_ctx(store)
    )
    await provider.async_probe(make_conn(FakeApi()), make_ctx())
    down = OpenWrtConnectionError("down")
    with pytest.raises(RouterUnavailableError):
        await collect(FakeApi(cgi=down, ssh=down, uci=every_config(down)))

    text = caplog.text
    assert "config collect" in text  # the provider does log
    for secret in (*PLAINTEXT, "ProvSecret#NewKey9", "PlainHomeSsid", "Gast Netz"):
        assert secret not in text
    assert ARCHIVE[:32].hex() not in text
    assert repr(ARCHIVE[:16])[2:-1] not in text
    assert KEY.hex() not in text


_ALLOWED_API_ATTRS = {
    "config_fetch_backup_cgi",
    "config_fetch_backup_ssh",
    "config_uci_get",
    "config_packagelist",
    "config_backup_access",
    "config_ssh_user_is_root",
}


def test_provider_uses_only_the_config_read_methods_of_the_api() -> None:
    tree = ast.parse(Path(cp.__file__).read_text(encoding="utf-8"))

    api_attrs: set[str] = set()
    coordinator_attrs: set[str] = set()
    hass_attrs: set[str] = set()
    all_attrs: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        all_attrs.add(node.attr)
        value = node.value
        if (isinstance(value, ast.Name) and value.id == "api") or (
            isinstance(value, ast.Attribute) and value.attr == "api"
        ):
            api_attrs.add(node.attr)
        if isinstance(value, ast.Attribute) and value.attr == "coordinator":
            coordinator_attrs.add(node.attr)
        if isinstance(value, ast.Attribute) and value.attr == "_hass":
            hass_attrs.add(node.attr)
    assert api_attrs and api_attrs <= _ALLOWED_API_ATTRS
    assert coordinator_attrs <= {"router_info"}
    assert hass_attrs <= {"async_add_executor_job"}
    # No events, no guard, no bus, no writes.
    assert not all_attrs & {"bus", "async_fire", "guard", "consume", "states"}

    # The api is never reached through getattr.
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        ):
            target = node.args[0]
            assert not (isinstance(target, ast.Name) and target.id == "api")
            assert not (isinstance(target, ast.Attribute) and target.attr == "api")

    # No own network or process code; Home Assistant only for typing.
    runtime_imports: set[str] = set()
    for node in tree.body:
        if isinstance(node, ast.Import):
            runtime_imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            runtime_imports.add(("." * node.level) + (node.module or ""))
    assert not runtime_imports & {
        "aiohttp",
        "asyncssh",
        "socket",
        "subprocess",
        "requests",
    }
    assert not any(name.startswith("homeassistant") for name in runtime_imports)
    assert ".api" not in runtime_imports
    assert ".coordinator" not in runtime_imports


# ---------------------------------------------------------------------------
# Security review: drift after a key reset (H1), incomplete UCI reads (H2),
# archive filling the gaps of the live read (H3)
# ---------------------------------------------------------------------------


async def test_key_reset_with_real_changes_is_drift_not_rebaseline() -> None:
    store = Store()
    baseline = store.put(ROUTER_A, await collect(key=OTHER_KEY))
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(files=changed(vlan=True, firewall=True))),
        baseline,
        (),
        make_ctx(store, key=KEY),
        router=router_record(),
    )
    assert report.drifted and not report.rebaseline
    assert report.critical_count >= 2
    assert report.drift_id is not None
    assert not report.secrets_comparable
    secret = [c for c in report.diff.changes if c.option == "key"]
    assert secret and all(c.kind is ChangeKind.NOT_COMPARABLE for c in secret)
    assert find_change(report.diff, "firewall", "input")
    assert find_change(report.diff, "network", "ports")


async def test_uci_read_aborted_without_archive_path_is_partial() -> None:
    uci = ubus_values()
    uci["wireless"] = OpenWrtTimeoutError("slow")
    api = FakeApi(
        uci=uci,
        cgi=OpenWrtConfigFetchPermissionError("acl"),
        ssh=OpenWrtConfigFetchPermissionError("not root"),
    )
    version = await collect(api)
    meta = version.meta
    assert meta.status is VersionStatus.PARTIAL
    assert meta.backup_type is BackupType.PARTIAL
    assert meta.error_class is ErrorClass.TIMEOUT
    assert "uci_failed:firewall" in meta.warnings
    assert not Store().put(ROUTER_A, version).usable


async def test_unreadable_config_without_archive_path_is_partial() -> None:
    uci = ubus_values()
    uci["firewall"] = OpenWrtConfigFetchPermissionError("acl")
    version = await collect(FakeApi(uci=uci), backup_type=BackupType.UCI_SNAPSHOT)
    meta = version.meta
    assert meta.status is VersionStatus.PARTIAL
    assert meta.error_class is ErrorClass.INCOMPLETE
    assert "uci_failed:firewall" in meta.warnings
    # Configs that do not exist on the router (not_available) are fine.
    assert "uci_missing:sqm" in meta.warnings
    assert not Store().put(ROUTER_A, version).usable

    complete = await collect(FakeApi(), backup_type=BackupType.UCI_SNAPSHOT)
    assert complete.meta.status is VersionStatus.OK


async def test_archive_fills_configs_the_live_read_missed() -> None:
    uci = ubus_values()
    uci["firewall"] = OpenWrtConfigFetchPermissionError("acl")
    uci["wireless"] = OpenWrtConfigFetchPermissionError("acl")
    version = await collect(FakeApi(uci=uci))
    meta = version.meta
    assert meta.status is VersionStatus.OK
    assert meta.backup_type is BackupType.FULL_ARCHIVE
    doc = uci_doc(version)
    assert {"network", "wireless", "firewall", "system"} <= set(doc["configs"])
    assert "uci_source:firewall" in meta.warnings
    assert "uci_source:wireless" in meta.warnings
    assert "uci_failed:firewall" in meta.warnings
    assert meta.uci_hash == (await collect()).meta.uci_hash


async def test_baseline_with_unreadable_config_still_sees_drift_there() -> None:
    store = Store()
    uci = ubus_values()
    uci["firewall"] = OpenWrtConfigFetchPermissionError("acl")
    baseline = store.put(ROUTER_A, await collect(FakeApi(uci=uci)))
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(files=changed(firewall=True))),
        baseline,
        (),
        make_ctx(store),
        router=router_record(),
    )
    assert report.drifted
    assert report.critical_count >= 1
    assert find_change(report.diff, "firewall", "input")


# ---------------------------------------------------------------------------
# Security review M6: an oversized UCI file in the archive is never parsed
# ---------------------------------------------------------------------------


def _oversized_firewall() -> str:
    """FIREWALL plus a comment that pushes it over UCI_TEXT_MAX_BYTES.

    Hex noise compresses about 2:1, so the archive ratio check passes.
    """
    noise = random.Random(6).randbytes(UCI_TEXT_MAX_BYTES // 2 + 1).hex()
    return f"{FIREWALL}# {noise}\n"


async def test_oversized_archive_config_is_reported_and_live_used() -> None:
    files = {**FILES, "firewall": _oversized_firewall()}
    archive = make_archive(files)
    version = await collect(FakeApi(cgi=archive, ssh=archive))
    meta = version.meta
    assert meta.backup_type is BackupType.FULL_ARCHIVE
    assert "uci_too_large:firewall" in meta.warnings
    # The live read still delivers firewall; nothing from the archive text.
    assert "firewall" in uci_doc(version)["configs"]
    assert meta.uci_hash == (await collect()).meta.uci_hash


async def test_oversized_archive_config_without_live_read_is_missing() -> None:
    files = {**FILES, "firewall": _oversized_firewall()}
    archive = make_archive(files)
    uci = ubus_values()
    uci["firewall"] = OpenWrtConfigFetchPermissionError("acl")
    version = await collect(FakeApi(cgi=archive, ssh=archive, uci=uci))
    meta = version.meta
    assert "uci_too_large:firewall" in meta.warnings
    assert "uci_failed:firewall" in meta.warnings
    assert "firewall" not in uci_doc(version)["configs"]


# ---------------------------------------------------------------------------
# Security review M2: a config unreadable during the drift check is never
# reported as "no drift"
# ---------------------------------------------------------------------------


async def test_unreadable_changed_config_is_never_reported_clean() -> None:
    store = Store()
    baseline = store.put(ROUTER_A, await collect())
    uci = ubus_values(changed(firewall=True))
    uci["firewall"] = OpenWrtConfigFetchIncompleteError("cut off")
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(uci=uci)),
        baseline,
        (),
        make_ctx(store),
        router=router_record(),
    )
    assert report.drifted
    assert report.drift_id is not None
    assert report.unknown_count >= 1
    assert not report.rebaseline
    gaps = [c for c in report.diff.changes if c.kind is ChangeKind.NOT_COMPARABLE]
    assert [c.config for c in gaps] == ["firewall"]


async def test_unreadable_config_after_key_reset_is_no_rebaseline() -> None:
    store = Store()
    baseline = store.put(ROUTER_A, await collect(key=OTHER_KEY))
    uci = ubus_values()
    uci["firewall"] = OpenWrtConfigFetchPermissionError("acl")
    report = await ConfigManagerProvider().async_detect_drift(
        make_conn(FakeApi(uci=uci)),
        baseline,
        (),
        make_ctx(store, key=KEY),
        router=router_record(),
    )
    assert report.drifted and not report.rebaseline
    assert report.unknown_count >= 1


# ---------------------------------------------------------------------------
# Pinned SSH (the core's runner is the only SSH path)
# ---------------------------------------------------------------------------


async def test_probe_without_pin_store_reports_ssh_unavailable() -> None:
    caps = await ConfigManagerProvider().async_probe(
        make_conn(FakeApi()), make_ctx(ssh=None)
    )
    ssh = caps[Capability.CONFIG_SSH_ROOT]
    assert ssh.state is CapabilityState.UNAVAILABLE
    assert "ssh_pin_unavailable" in str(ssh.reason)


class _PinCtx:
    """Fake ProviderContext: counts calls, raises ``exc``."""

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc
        self.calls = 0

    async def async_ssh_run_pinned(self, *_args: Any, **_kwargs: Any) -> Any:
        self.calls += 1
        raise self.exc


async def test_pinned_ssh_short_circuits_after_first_refusal() -> None:
    ctx = _PinCtx(OpenWrtHostKeyError("pin_pending", "pending"))
    runner = PinnedSsh(ctx, ROUTER_A)
    with pytest.raises(OpenWrtHostKeyError):
        await runner("uci show network", 5.0, 1024)
    with pytest.raises(OpenWrtConfigFetchHostKeyError) as err:
        await runner("uci show wireless", 5.0, 1024)
    assert ctx.calls == 1
    assert runner.refused == "pin_pending"
    assert err.value.reason == "pin_pending"


@pytest.mark.parametrize(
    ("exc", "expected", "refused"),
    [
        (ArtifactTooLargeError("cap"), OpenWrtConfigFetchTooLargeError, None),
        (
            AuthorizationError("x", details={"reason": "ssh_pin_unavailable"}),
            OpenWrtConfigFetchHostKeyError,
            "pin_unavailable",
        ),
    ],
)
async def test_pinned_ssh_maps_core_errors(
    exc: BaseException, expected: type[BaseException], refused: str | None
) -> None:
    runner = PinnedSsh(_PinCtx(exc), ROUTER_A)
    with pytest.raises(expected):
        await runner("uci show network", 5.0, 1024)
    assert runner.refused == refused
