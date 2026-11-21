"""Tests for the configuration collector (configuration manager, G5).

Plan: docs/plans/2026-11-17-config-manager.md, sections 2.3, 3, 4, 11.2 and
16 (cases 1-4). No network: a small fake stands in for ``OpenWrtAPI``; two
tests drive the real ``OpenWrtAPI.config_*`` methods with the ubus call and
the SSH read patched out, so the SSH ``uci show`` fallback of api.py is
exercised for real.
"""

from __future__ import annotations

import ast
import asyncio
import copy
import gzip
import io
import logging
import tarfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from custom_components.openwrt_router import config_collector as cc
from custom_components.openwrt_router.api import (
    OpenWrtAPI,
    OpenWrtAuthBackoffError,
    OpenWrtAuthError,
    OpenWrtConfigFetchIncompleteError,
    OpenWrtConfigFetchNotAvailableError,
    OpenWrtConfigFetchPermissionError,
    OpenWrtConfigFetchTooLargeError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from custom_components.openwrt_router.config_archive import (
    extract_uci_texts,
    validate_archive,
)
from custom_components.openwrt_router.config_collector import (
    ArchiveFetch,
    FetchAttempt,
    UciCollection,
    UciFetch,
    classify_error,
    collect_archive,
    collect_inventory,
    collect_uci,
    collect_uci_snapshot,
    snapshot_from_uci,
)
from custom_components.openwrt_router.config_const import (
    DEFAULT_ARCHIVE_LIMITS,
    ERR_AUTH,
    ERR_INCOMPLETE,
    ERR_INVALID,
    ERR_NOT_AVAILABLE,
    ERR_PERMISSION,
    ERR_TIMEOUT,
    ERR_TOO_LARGE,
    ERR_UNREACHABLE,
    FETCH_TIMEOUTS,
    UCI_CONFIGS,
    ArchiveLimits,
)
from custom_components.openwrt_router.config_diff import Area, evaluate_drift
from custom_components.openwrt_router.config_inventory import (
    PACKAGE_MANAGER_APK,
    PACKAGE_MANAGER_OPKG,
    Inventory,
)
from custom_components.openwrt_router.config_snapshot import (
    build_snapshot,
    parse_uci_file,
)
from custom_components.openwrt_router.core_masking import secret_digest_factory

DIGEST = secret_digest_factory(b"c" * 32)
MGMT = "192.168.1.1"

WLAN_KEY = "UciSecret#WlanKey1"
GUEST_KEY = "UciSecret#Guest2"
PPP_PASSWORD = "UciSecret#Ppp3"
SHADOW_HASH = "$6$ARCHIVESECRET$abcdefghijklmnop"
PLAINTEXT = (WLAN_KEY, GUEST_KEY, PPP_PASSWORD, "ARCHIVESECRET")
# Non-secret raw values: must not show up in a repr or log line either.
RAW_VALUES = ("PlainHomeSsid", "Gast Netz", "isp-user@example")

# ---------------------------------------------------------------------------
# Fixtures: one router in UCI file form, ubus form and `uci show` form
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

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'
\tlist dns '9.9.9.9'

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
\toption htmode 'HE20'
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
\toption isolate '1'
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

config rule
\toption src 'wan'
\toption proto 'tcp'
\toption dest_port '22'
\toption target 'DROP'
"""

SYSTEM = """\
config system
\toption hostname 'OpenWrt-GW'
\toption timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
\toption log_size '64'
"""

FILES: dict[str, str] = {
    "network": NETWORK,
    "wireless": WIRELESS,
    "firewall": FIREWALL,
    "system": SYSTEM,
}

SHOW: dict[str, str] = {
    "network": f"""\
network.loopback=interface
network.loopback.device='lo'
network.loopback.proto='static'
network.loopback.ipaddr='127.0.0.1'
network.loopback.netmask='255.0.0.0'
network.@device[0]=device
network.@device[0].name='br-lan'
network.@device[0].type='bridge'
network.@device[0].ports='lan1' 'lan2'
network.lan=interface
network.lan.device='br-lan'
network.lan.proto='static'
network.lan.ipaddr='192.168.1.1'
network.lan.netmask='255.255.255.0'
network.lan.dns='9.9.9.9'
network.wan=interface
network.wan.device='wan'
network.wan.proto='pppoe'
network.wan.username='isp-user@example'
network.wan.password='{PPP_PASSWORD}'
""",
    "wireless": f"""\
wireless.radio0=wifi-device
wireless.radio0.type='mac80211'
wireless.radio0.band='2g'
wireless.radio0.channel='6'
wireless.radio0.htmode='HE20'
wireless.radio0.country='DE'
wireless.default_radio0=wifi-iface
wireless.default_radio0.device='radio0'
wireless.default_radio0.network='lan'
wireless.default_radio0.mode='ap'
wireless.default_radio0.ssid='PlainHomeSsid'
wireless.default_radio0.encryption='sae-mixed'
wireless.default_radio0.key='{WLAN_KEY}'
wireless.@wifi-iface[1]=wifi-iface
wireless.@wifi-iface[1].device='radio0'
wireless.@wifi-iface[1].network='lan'
wireless.@wifi-iface[1].mode='ap'
wireless.@wifi-iface[1].ssid='Gast Netz'
wireless.@wifi-iface[1].encryption='psk2'
wireless.@wifi-iface[1].key='{GUEST_KEY}'
wireless.@wifi-iface[1].isolate='1'
""",
    "firewall": """\
firewall.@defaults[0]=defaults
firewall.@defaults[0].input='REJECT'
firewall.@defaults[0].output='ACCEPT'
firewall.@defaults[0].forward='REJECT'
firewall.@zone[0]=zone
firewall.@zone[0].name='lan'
firewall.@zone[0].network='lan'
firewall.@zone[0].input='ACCEPT'
firewall.@rule[0]=rule
firewall.@rule[0].src='wan'
firewall.@rule[0].proto='tcp'
firewall.@rule[0].dest_port='22'
firewall.@rule[0].target='DROP'
""",
    "system": """\
system.@system[0]=system
system.@system[0].hostname='OpenWrt-GW'
system.@system[0].timezone='CET-1CEST,M3.5.0,M10.5.0/3'
system.@system[0].log_size='64'
""",
}

CONFIGS = tuple(FILES)


def to_ubus(parsed: Mapping[str, Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    """Turn parse_uci_file output into what rpcd ``uci get`` returns.

    Anonymous sections get random-looking ``cfgXXXXXX`` names like rpcd's,
    one-element lists stay lists (ubus keeps the list type).
    """
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


def ubus_values(files: Mapping[str, str] = FILES) -> dict[str, dict[str, Any]]:
    return {name: to_ubus(parse_uci_file(text)) for name, text in files.items()}


def make_archive(files: Mapping[str, str] = FILES) -> bytes:
    """A sysupgrade-shaped backup: etc/config/*, shadow, host key (GNU tar)."""
    members: dict[str, bytes] = {
        f"etc/config/{name}": text.encode() for name, text in files.items()
    }
    members["etc/shadow"] = f"root:{SHADOW_HASH}:19000:0:99999:7:::\n".encode()
    members["etc/dropbear/dropbear_ed25519_host_key"] = bytes(range(83))
    members["etc/sysupgrade.conf"] = b"## This file contains files to keep\n"
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o600 if "shadow" in name or "dropbear" in name else 0o644
            info.mtime = 1_700_000_000
            info.uname = info.gname = "root"
            tf.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


ARCHIVE = make_archive()

# ---------------------------------------------------------------------------
# Fake api
# ---------------------------------------------------------------------------

Outcome = Any  # bytes / dict / None, an exception instance, or a callable


class FakeApi:
    """Records calls to the four config_* methods and plays scripted outcomes.

    Every other attribute access fails the test: the collector must not use
    anything else of the api.
    """

    def __init__(
        self,
        *,
        cgi: Outcome = ARCHIVE,
        ssh: Outcome = ARCHIVE,
        uci: Mapping[str, Outcome] | None = None,
        packages: Outcome = None,
    ) -> None:
        self.cgi = cgi
        self.ssh = ssh
        self.uci = dict(ubus_values() if uci is None else uci)
        self.packages = packages
        self.calls: list[tuple[str, ...]] = []
        self.kwargs: list[dict[str, Any]] = []
        self.inflight = 0
        self.max_inflight = 0

    async def _play(self, outcome: Outcome) -> Any:
        self.inflight += 1
        self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            await asyncio.sleep(0)
            if callable(outcome):
                outcome = outcome()
                if asyncio.iscoroutine(outcome):
                    outcome = await outcome
            if isinstance(outcome, BaseException):
                raise outcome
            await asyncio.sleep(0)
            return outcome
        finally:
            self.inflight -= 1

    async def config_fetch_backup_cgi(self, *, max_bytes: int, timeout: float) -> bytes:
        self.calls.append(("cgi",))
        self.kwargs.append({"max_bytes": max_bytes, "timeout": timeout})
        return await self._play(self.cgi)

    async def config_fetch_backup_ssh(self, *, max_bytes: int, timeout: float) -> bytes:
        self.calls.append(("ssh",))
        self.kwargs.append({"max_bytes": max_bytes, "timeout": timeout})
        return await self._play(self.ssh)

    async def config_uci_get(self, config: str) -> dict[str, Any]:
        self.calls.append(("uci", config))
        outcome = self.uci.get(
            config, OpenWrtConfigFetchNotAvailableError(f"uci get {config}: no such")
        )
        result = await self._play(outcome)
        return copy.deepcopy(result)

    async def config_packagelist(self) -> dict[str, str] | None:
        self.calls.append(("packagelist",))
        return await self._play(self.packages)


def methods(api: FakeApi) -> list[str]:
    return [call[0] for call in api.calls]


def real_api(username: str = "root") -> OpenWrtAPI:
    api = OpenWrtAPI(
        host="192.0.2.1",
        port=80,
        username=username,
        password="router-pw-never-logged",
        session=MagicMock(),
        protocol="http",
    )
    api._token = "a1" * 16
    api._token_expires_at = time.monotonic() + 3600
    return api


# ---------------------------------------------------------------------------
# Archive chain (plan 2.3, 16 cases 1-4)
# ---------------------------------------------------------------------------


async def test_collect_archive_cgi_success() -> None:
    api = FakeApi()
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]

    assert isinstance(result, ArchiveFetch)
    assert result.ok
    assert result.data == ARCHIVE
    assert result.size == len(ARCHIVE)
    assert (result.method, result.error_class) == ("cgi", None)
    assert [(a.method, a.error_class) for a in result.attempts] == [("cgi", None)]
    assert result.attempts[0].duration_s >= 0
    assert result.skipped == ()
    assert result.skippable_methods == frozenset()
    assert methods(api) == ["cgi"]
    assert api.kwargs == [
        {
            "max_bytes": DEFAULT_ARCHIVE_LIMITS.max_compressed,
            "timeout": FETCH_TIMEOUTS["cgi"],
        }
    ]
    report = validate_archive(result.data or b"", DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OpenWrtConnectionError("no route"), ERR_UNREACHABLE),
        (OpenWrtTimeoutError("60s"), ERR_TIMEOUT),
        # asyncio.TimeoutError is the builtin TimeoutError since 3.11.
        (TimeoutError(), ERR_TIMEOUT),
    ],
    ids=["connection", "api-timeout", "timeout"],
)
async def test_unreachable_stops_chain_with_error_class(
    error: BaseException, expected: str
) -> None:
    api = FakeApi(cgi=error)
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]

    assert methods(api) == ["cgi"]  # SSH would ask the same dead router
    assert not result.ok
    assert result.data is None
    assert (result.method, result.error_class) == (None, expected)
    assert [(a.method, a.error_class) for a in result.attempts] == [("cgi", expected)]
    assert result.skippable_methods == frozenset()
    assert result.attempts[0].skippable is False


@pytest.mark.parametrize(
    "error",
    [
        OpenWrtConfigFetchPermissionError("403 after re-login"),
        OpenWrtConfigFetchNotAvailableError("404"),
    ],
    ids=["permission", "not_available"],
)
async def test_cgi_permission_falls_back_to_ssh_root(error: BaseException) -> None:
    api = FakeApi(cgi=error)
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]

    assert methods(api) == ["cgi", "ssh"]
    assert result.ok and result.data == ARCHIVE
    assert (result.method, result.error_class) == ("ssh", None)
    assert [(a.method, a.error_class) for a in result.attempts] == [
        ("cgi", error.error_class),  # type: ignore[attr-defined]
        ("ssh", None),
    ]
    # The caller remembers "cgi" for 24 h (the collector keeps no state).
    assert result.skippable_methods == frozenset({"cgi"})
    assert api.kwargs[1]["timeout"] == FETCH_TIMEOUTS["ssh"]


@pytest.mark.parametrize(
    "error",
    [
        OpenWrtConfigFetchPermissionError("403"),
        OpenWrtConfigFetchNotAvailableError("404, no LuCI"),
    ],
    ids=["no-acl", "no-luci"],
)
async def test_non_root_without_acl_reports_permission(error: BaseException) -> None:
    api = FakeApi(cgi=error)
    result = await collect_archive(api, is_root=False)  # type: ignore[arg-type]

    assert methods(api) == ["cgi"]  # SSH backup needs root: not even tried
    assert not result.ok
    assert (result.method, result.error_class) == (None, ERR_PERMISSION)
    assert result.skipped == ("ssh",)
    assert result.skippable_methods == frozenset({"cgi"})


async def test_non_root_with_cgi_skipped_reports_permission_without_calls() -> None:
    api = FakeApi()
    result = await collect_archive(
        api,  # type: ignore[arg-type]
        is_root=False,
        skip={"cgi"},
    )
    assert api.calls == []
    assert result.attempts == ()
    assert result.skipped == ("cgi", "ssh")
    assert result.error_class == ERR_PERMISSION


async def test_skip_is_respected() -> None:
    api = FakeApi()
    result = await collect_archive(
        api,  # type: ignore[arg-type]
        is_root=True,
        skip=frozenset({"cgi"}),
    )
    assert methods(api) == ["ssh"]
    assert (result.method, result.skipped) == ("ssh", ("cgi",))
    assert result.ok

    api = FakeApi()
    result = await collect_archive(
        api,  # type: ignore[arg-type]
        is_root=True,
        skip=("cgi", "ssh"),
    )
    assert api.calls == []
    assert result.data is None
    assert result.error_class == ERR_NOT_AVAILABLE
    assert result.skipped == ("cgi", "ssh")


async def test_order_is_followed_and_validated() -> None:
    api = FakeApi()
    result = await collect_archive(
        api,  # type: ignore[arg-type]
        order=("ssh", "cgi", "ssh"),
        is_root=True,
    )
    assert methods(api) == ["ssh"]
    assert result.method == "ssh"

    with pytest.raises(ValueError):
        await collect_archive(
            FakeApi(),  # type: ignore[arg-type]
            order=("cgi", "file-exec"),
            is_root=True,
        )
    with pytest.raises(ValueError):
        await collect_archive(
            FakeApi(),  # type: ignore[arg-type]
            order=(),
            is_root=True,
        )


async def test_ssh_nonzero_exit_is_incomplete() -> None:
    """Real api: sysupgrade exits 1 over SSH -> incomplete, no plaintext."""
    api = real_api()
    api.config_fetch_backup_cgi = AsyncMock(  # type: ignore[method-assign]
        side_effect=OpenWrtConfigFetchNotAvailableError("cgi-backup: HTTP 404")
    )
    api._config_ssh_read = AsyncMock(  # type: ignore[method-assign]
        return_value=(1, b"\x1f\x8bpartial", b"tar: STDERR-SECRET psk=hunter2")
    )
    result = await collect_archive(api, is_root=True)

    assert not result.ok
    assert (result.method, result.error_class) == (None, ERR_INCOMPLETE)
    assert [(a.method, a.error_class) for a in result.attempts] == [
        ("cgi", ERR_NOT_AVAILABLE),
        ("ssh", ERR_INCOMPLETE),
    ]
    assert result.skippable_methods == frozenset({"cgi"})
    assert "STDERR-SECRET" not in repr(result)


async def test_cgi_incomplete_tries_ssh() -> None:
    api = FakeApi(cgi=OpenWrtConfigFetchIncompleteError("cut off"))
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]
    assert methods(api) == ["cgi", "ssh"]
    assert result.ok and result.method == "ssh"
    # incomplete is not remembered: the next run asks cgi again.
    assert result.skippable_methods == frozenset()


async def test_size_cap_aborts_stream() -> None:
    """TooLarge ends the chain: SSH would stream the same oversized archive."""
    limits = ArchiveLimits(max_compressed=4096)
    api = FakeApi(cgi=OpenWrtConfigFetchTooLargeError("exceeds 4096 bytes"))
    result = await collect_archive(
        api,  # type: ignore[arg-type]
        is_root=True,
        limits=limits,
    )

    assert methods(api) == ["cgi"]
    assert api.kwargs[0]["max_bytes"] == 4096
    assert (result.method, result.error_class) == (None, ERR_TOO_LARGE)
    assert result.skippable_methods == frozenset()


async def test_too_large_on_ssh_after_cgi_permission() -> None:
    api = FakeApi(
        cgi=OpenWrtConfigFetchPermissionError("403"),
        ssh=OpenWrtConfigFetchTooLargeError("too big"),
    )
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]
    assert methods(api) == ["cgi", "ssh"]
    assert result.error_class == ERR_TOO_LARGE
    assert result.skippable_methods == frozenset({"cgi"})


async def test_auth_failure_on_cgi_tries_ssh() -> None:
    api = FakeApi(cgi=OpenWrtAuthError("login failed"))
    result = await collect_archive(api, is_root=True)  # type: ignore[arg-type]
    assert methods(api) == ["cgi", "ssh"]
    assert result.ok
    assert result.attempts[0].error_class == ERR_AUTH


async def test_cancelled_error_propagates_from_archive_chain() -> None:
    api = FakeApi(cgi=asyncio.CancelledError())
    with pytest.raises(asyncio.CancelledError):
        await collect_archive(api, is_root=True)  # type: ignore[arg-type]
    assert methods(api) == ["cgi"]

    # A real cancellation from outside while the fetch is waiting.
    started = asyncio.Event()

    async def hang() -> bytes:
        started.set()
        await asyncio.Event().wait()
        return b""

    api = FakeApi(cgi=hang)
    task = asyncio.ensure_future(
        collect_archive(api, is_root=True)  # type: ignore[arg-type]
    )
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert methods(api) == ["cgi"]


@pytest.mark.parametrize(
    "error", [TypeError("bug"), ValueError("max_bytes must be > 0"), KeyError("x")]
)
async def test_programming_errors_propagate(error: BaseException) -> None:
    api = FakeApi(cgi=error)
    with pytest.raises(type(error)):
        await collect_archive(api, is_root=True)  # type: ignore[arg-type]
    assert methods(api) == ["cgi"]


# ---------------------------------------------------------------------------
# UCI (plan 3.1, D6)
# ---------------------------------------------------------------------------


async def test_collect_uci_reads_configs_one_after_another() -> None:
    api = FakeApi()
    fetch = await collect_uci(api, CONFIGS)  # type: ignore[arg-type]

    assert isinstance(fetch, UciFetch)
    assert api.calls == [("uci", name) for name in CONFIGS]
    assert api.max_inflight == 1  # never two router calls at once
    assert fetch.configs == CONFIGS
    assert fetch.failed == ()
    assert fetch.not_tried == ()
    assert fetch.error_class is None
    assert set(fetch.raw) == set(CONFIGS)
    assert all(isinstance(fetch.raw[name], Mapping) for name in CONFIGS)
    assert fetch.duration_s >= 0


async def test_collect_uci_missing_and_denied_configs_are_listed() -> None:
    uci: dict[str, Outcome] = {
        **ubus_values(),
        "rpcd": OpenWrtConfigFetchPermissionError("ubus denied, no SSH"),
        "sqm": OpenWrtConfigFetchNotAvailableError("no such config"),
        "ddns": OpenWrtConfigFetchIncompleteError("reply without values"),
    }
    api = FakeApi(uci=uci)
    wanted = (*CONFIGS, "rpcd", "sqm", "ddns", "upnpd")
    fetch = await collect_uci(api, wanted)  # type: ignore[arg-type]

    assert [call[1] for call in api.calls] == list(wanted)
    assert fetch.error_class is None
    assert fetch.failed == (
        ("rpcd", ERR_PERMISSION),
        ("sqm", ERR_NOT_AVAILABLE),
        ("ddns", ERR_INCOMPLETE),
        ("upnpd", ERR_NOT_AVAILABLE),
    )
    for name in ("rpcd", "sqm", "ddns", "upnpd"):
        assert fetch.raw[name] is None
    snap = snapshot_from_uci(fetch, DIGEST)
    assert snap.missing == frozenset({"rpcd", "sqm", "ddns", "upnpd"})
    assert set(snap.configs) == set(CONFIGS)


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OpenWrtConnectionError("down"), ERR_UNREACHABLE),
        (OpenWrtTimeoutError("30s"), ERR_TIMEOUT),
        (OpenWrtAuthBackoffError("backoff"), ERR_AUTH),
    ],
    ids=["unreachable", "timeout", "auth"],
)
async def test_collect_uci_stops_on_dead_router(
    error: BaseException, expected: str
) -> None:
    uci: dict[str, Outcome] = {**ubus_values(), "firewall": error}
    api = FakeApi(uci=uci)
    fetch = await collect_uci(api, UCI_CONFIGS)  # type: ignore[arg-type]

    # network, wireless, firewall asked; the eleven others never.
    assert [call[1] for call in api.calls] == ["network", "wireless", "firewall"]
    assert fetch.error_class == expected
    assert fetch.failed == (("firewall", expected),)
    assert fetch.not_tried == UCI_CONFIGS[3:]
    assert fetch.raw["network"] is not None
    assert all(fetch.raw[name] is None for name in UCI_CONFIGS[2:])
    snap = snapshot_from_uci(fetch, DIGEST)
    assert snap.missing == frozenset(UCI_CONFIGS[2:])


async def test_collect_uci_applies_per_config_timeout() -> None:
    async def hang() -> dict[str, Any]:
        await asyncio.Event().wait()
        return {}

    api = FakeApi(uci={"network": hang, "wireless": {}})
    fetch = await collect_uci(
        api,  # type: ignore[arg-type]
        ("network", "wireless"),
        timeouts={**FETCH_TIMEOUTS, "uci": 0.01},
    )
    assert fetch.error_class == ERR_TIMEOUT
    assert fetch.not_tried == ("wireless",)


async def test_collect_uci_cancel_and_programming_errors_propagate() -> None:
    api = FakeApi(uci={"network": asyncio.CancelledError()})
    with pytest.raises(asyncio.CancelledError):
        await collect_uci(api, ("network", "wireless"))  # type: ignore[arg-type]
    assert api.calls == [("uci", "network")]

    api = FakeApi(uci={"network": ValueError("invalid UCI config name")})
    with pytest.raises(ValueError):
        await collect_uci(api, ("network",))  # type: ignore[arg-type]


async def test_collect_uci_dedupes_and_keeps_order() -> None:
    api = FakeApi()
    fetch = await collect_uci(
        api,  # type: ignore[arg-type]
        ["system", "network", "system"],
    )
    assert api.calls == [("uci", "system"), ("uci", "network")]
    assert fetch.configs == ("system", "network")


async def test_collect_uci_snapshot_hides_raw_data() -> None:
    api = FakeApi()
    result = await collect_uci_snapshot(
        api,  # type: ignore[arg-type]
        CONFIGS,
        DIGEST,
    )
    assert isinstance(result, UciCollection)
    expected = build_snapshot(ubus_values(), DIGEST, configs=CONFIGS)
    assert result.snapshot.content_hash == expected.content_hash
    assert result.error_class is None and result.failed == ()
    assert not hasattr(result, "raw")
    text = repr(result)
    for value in (*PLAINTEXT, *RAW_VALUES):
        assert value not in text


def _acl_denied(api: Any) -> AsyncMock:
    """rpcd ACL denial, remembered in ``_acl_blocked`` like the real ``_call``."""

    async def call(obj: str, method: str, params: dict[str, Any]) -> Any:
        api._acl_blocked.add(api._acl_cache_key(obj, method, params))
        raise OpenWrtMethodNotFoundError("Access denied")

    return AsyncMock(side_effect=call)


async def test_uci_acl_block_uses_ssh_uci_show() -> None:
    """Real api: ubus denied -> SSH `uci show` -> same snapshot hash as ubus."""
    ubus = ubus_values()

    via_ubus = real_api()
    via_ubus._call = AsyncMock(  # type: ignore[method-assign]
        side_effect=lambda obj, method, params: {
            "values": copy.deepcopy(ubus[params["config"]])
        }
    )
    via_ubus._config_ssh_read = AsyncMock(  # type: ignore[method-assign]
        side_effect=AssertionError("no SSH expected")
    )

    blocked = real_api()
    blocked._call = _acl_denied(blocked)  # type: ignore[method-assign]
    ssh_commands: list[str] = []

    async def ssh_read(cmd: str, _ssh: Any, **_kw: Any) -> tuple[int, bytes, bytes]:
        ssh_commands.append(cmd)
        return 0, SHOW[cmd.split()[-1]].encode(), b""

    blocked._config_ssh_read = ssh_read  # type: ignore[method-assign]

    fetch_ubus = await collect_uci(via_ubus, CONFIGS)
    fetch_ssh = await collect_uci(blocked, CONFIGS)

    assert ssh_commands == [f"uci show {name}" for name in CONFIGS]
    assert fetch_ssh.failed == () and fetch_ssh.error_class is None
    # SSH keys anonymous sections as @type[n], ubus as cfgXXXXXX ...
    assert "@wifi-iface[1]" in (fetch_ssh.raw["wireless"] or {})
    assert not any(key.startswith("@") for key in fetch_ubus.raw["wireless"] or {})
    # ... and both normalise to the same snapshot.
    snap_ubus = snapshot_from_uci(fetch_ubus, DIGEST)
    snap_ssh = snapshot_from_uci(fetch_ssh, DIGEST)
    assert snap_ssh.configs == snap_ubus.configs
    assert snap_ssh.content_hash == snap_ubus.content_hash
    # And the same as the archive files (plan D6 cross-check).
    snap_files = build_snapshot(
        {name: parse_uci_file(text) for name, text in FILES.items()},
        DIGEST,
        configs=CONFIGS,
    )
    assert snap_files.content_hash == snap_ubus.content_hash


async def test_api_uci_show_fallback_multiline_value_matches_ubus() -> None:
    """SSH `uci show` fallback keeps multi-line values whole (same hash as ubus)."""
    show = (
        "system.@system[0]=system\n"
        "system.@system[0].hostname='gw'\n"
        "system.@system[0].notes='line1\nline2'\n"
    )
    ubus = {
        "cfg01": {
            ".anonymous": True,
            ".type": "system",
            ".name": "cfg01",
            ".index": 0,
            "hostname": "gw",
            "notes": "line1\nline2",
        }
    }
    blocked = real_api()
    blocked._call = _acl_denied(blocked)  # type: ignore[method-assign]
    blocked._config_ssh_read = AsyncMock(  # type: ignore[method-assign]
        return_value=(0, show.encode(), b"")
    )
    fetch = await collect_uci(blocked, ("system",))
    expected = build_snapshot({"system": ubus}, DIGEST, configs=("system",))
    assert snapshot_from_uci(fetch, DIGEST).content_hash == expected.content_hash


# ---------------------------------------------------------------------------
# Inventory (plan 4, D17)
# ---------------------------------------------------------------------------

ROUTER_INFO: dict[str, Any] = {
    "model": "Cudy WR3000 v1",
    "hostname": "gw",
    "release": {
        "distribution": "OpenWrt",
        "version": "24.10.4",
        "revision": "r28959-29397011cc",
        "target": "mediatek/filogic",
    },
    "mac": "00:11:22:33:44:55",
    "board_name": "cudy,wr3000-v1",
    "kernel": "6.6.110",
    "platform_architecture": "mediatek/filogic",
}


async def test_inventory_with_package_list() -> None:
    api = FakeApi(packages={"luci": "25.001.123", "dnsmasq-full": "2.90-r4"})
    inv = await collect_inventory(api, ROUTER_INFO)  # type: ignore[arg-type]

    assert isinstance(inv, Inventory)
    assert api.calls == [("packagelist",)]  # no extra system board call
    assert (inv.board_name, inv.model, inv.kernel) == (
        "cudy,wr3000-v1",
        "Cudy WR3000 v1",
        "6.6.110",
    )
    assert (inv.release_version, inv.release_revision, inv.target) == (
        "24.10.4",
        "r28959-29397011cc",
        "mediatek/filogic",
    )
    assert inv.package_manager == PACKAGE_MANAGER_OPKG
    assert dict(inv.packages or {}) == {
        "luci": "25.001.123",
        "dnsmasq-full": "2.90-r4",
    }
    assert inv.partial is False


@pytest.mark.parametrize(
    "packages",
    [None, {}, OpenWrtConnectionError("down"), OpenWrtTimeoutError("60s")],
    ids=["none", "empty", "unreachable", "timeout"],
)
async def test_inventory_without_package_list_is_partial(packages: Outcome) -> None:
    info = {**ROUTER_INFO, "release": {**ROUTER_INFO["release"], "version": "25.12.0"}}
    api = FakeApi(packages=packages)
    inv = await collect_inventory(api, info)  # type: ignore[arg-type]

    assert inv.partial is True
    assert inv.packages is None
    assert inv.package_manager == PACKAGE_MANAGER_APK
    assert inv.board_name == "cudy,wr3000-v1"


async def test_inventory_from_fallback_router_info() -> None:
    """get_router_info without system/board: empty strings, no release."""
    info = {
        "model": "OpenWrt Router",
        "hostname": "192.0.2.1",
        "release": {},
        "mac": "",
        "board_name": "",
        "kernel": "",
        "platform_architecture": "unknown",
    }
    inv = await collect_inventory(FakeApi(packages=None), info)  # type: ignore[arg-type]
    assert inv.board_name is None and inv.kernel is None
    assert inv.release_version is None and inv.target is None
    assert inv.package_manager is None
    assert inv.partial is True
    snapshot_info = {"release": {"version": "SNAPSHOT", "revision": 7}}
    inv = await collect_inventory(FakeApi(packages=None), snapshot_info)  # type: ignore[arg-type]
    assert inv.release_version == "SNAPSHOT"
    assert inv.release_revision is None  # not a string
    assert inv.package_manager is None


async def test_inventory_cancel_and_programming_errors_propagate() -> None:
    with pytest.raises(asyncio.CancelledError):
        await collect_inventory(
            FakeApi(packages=asyncio.CancelledError()),  # type: ignore[arg-type]
            ROUTER_INFO,
        )
    with pytest.raises(TypeError):
        await collect_inventory(
            FakeApi(packages=TypeError("bug")),  # type: ignore[arg-type]
            ROUTER_INFO,
        )


# ---------------------------------------------------------------------------
# Error classes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OpenWrtConfigFetchPermissionError("x"), ERR_PERMISSION),
        (OpenWrtConfigFetchNotAvailableError("x"), ERR_NOT_AVAILABLE),
        (OpenWrtConfigFetchTooLargeError("x"), ERR_TOO_LARGE),
        (OpenWrtConfigFetchIncompleteError("x"), ERR_INCOMPLETE),
        (OpenWrtConnectionError("x"), ERR_UNREACHABLE),
        (ConnectionResetError(), ERR_UNREACHABLE),
        (OSError(113, "No route to host"), ERR_UNREACHABLE),
        (OpenWrtTimeoutError("x"), ERR_TIMEOUT),
        (TimeoutError(), ERR_TIMEOUT),
        (OpenWrtAuthError("x"), ERR_AUTH),
        (OpenWrtAuthBackoffError("x"), ERR_AUTH),
        (OpenWrtMethodNotFoundError("x"), ERR_NOT_AVAILABLE),
        (OpenWrtResponseError("x"), ERR_INVALID),
        (RuntimeError("odd"), ERR_INVALID),
    ],
)
def test_classify_error(error: BaseException, expected: str) -> None:
    assert classify_error(error) == expected


def test_classify_error_unknown_error_class_attribute_is_incomplete() -> None:
    class Odd(OpenWrtConfigFetchIncompleteError):
        error_class = "something_new"

    assert classify_error(Odd("x")) == ERR_INCOMPLETE


@pytest.mark.parametrize(
    "error",
    [
        TypeError("bug"),
        ValueError("bug"),
        AttributeError("bug"),
        KeyError("bug"),
        asyncio.CancelledError(),
        KeyboardInterrupt(),
    ],
)
def test_classify_error_reraises_programming_errors_and_cancellation(
    error: BaseException,
) -> None:
    with pytest.raises(type(error)):
        classify_error(error)


# ---------------------------------------------------------------------------
# Secrets: repr and logs (plan 14.3)
# ---------------------------------------------------------------------------


async def test_repr_and_logs_contain_no_archive_bytes_or_uci_values(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    archive_fetch = await collect_archive(
        FakeApi(cgi=OpenWrtConfigFetchPermissionError("403")),  # type: ignore[arg-type]
        is_root=True,
    )
    uci = {**ubus_values(), "rpcd": OpenWrtConfigFetchPermissionError(WLAN_KEY)}
    uci_fetch = await collect_uci(
        FakeApi(uci=uci),  # type: ignore[arg-type]
        (*CONFIGS, "rpcd"),
    )
    collection = await collect_uci_snapshot(
        FakeApi(),  # type: ignore[arg-type]
        CONFIGS,
        DIGEST,
    )
    await collect_inventory(
        FakeApi(packages=OpenWrtConnectionError(PPP_PASSWORD)),  # type: ignore[arg-type]
        ROUTER_INFO,
    )

    assert archive_fetch.ok
    texts = [repr(archive_fetch), repr(uci_fetch), repr(collection), caplog.text]
    texts += [r.getMessage() for r in caplog.records]
    for text in texts:
        assert "ARCHIVESECRET" not in text
        assert repr(ARCHIVE[:16]) not in text
        for value in (*PLAINTEXT, *RAW_VALUES):
            assert value not in text
    # The log names method, error class, duration and size, nothing else.
    assert any("permission" in r.getMessage() for r in caplog.records)
    assert any(str(len(ARCHIVE)) in r.getMessage() for r in caplog.records)


def test_fetch_attempt_and_results_are_frozen() -> None:
    attempt = FetchAttempt("cgi", None, 0.1)
    with pytest.raises(AttributeError):
        attempt.method = "ssh"  # type: ignore[misc]
    fetch = ArchiveFetch(b"x", "cgi", None, (attempt,))
    with pytest.raises(AttributeError):
        fetch.data = b"y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------

_ALLOWED_API_CALLS = {
    "config_fetch_backup_cgi",
    "config_fetch_backup_ssh",
    "config_uci_get",
    "config_packagelist",
}


def test_collector_uses_only_config_methods_and_no_home_assistant() -> None:
    tree = ast.parse(Path(cc.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add(("." * node.level) + (node.module or ""))
    assert not any(name.startswith("homeassistant") for name in imported)
    assert not any("core_" in name for name in imported)
    assert not imported & {"aiohttp", "asyncssh", "socket", "subprocess"}

    used = {
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "api"
    }
    assert used == _ALLOWED_API_CALLS

    # OpenWrtAPI only as a type: imported under TYPE_CHECKING, never called.
    runtime_names = {
        alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "api"
        for alias in node.names
    }
    assert "OpenWrtAPI" not in runtime_names


# ---------------------------------------------------------------------------
# End to end without network
# ---------------------------------------------------------------------------


def _changed_channel(files: Mapping[str, str]) -> dict[str, str]:
    out = dict(files)
    assert out["wireless"].count("option channel '6'") == 1
    out["wireless"] = out["wireless"].replace(
        "option channel '6'", "option channel '11'"
    )
    return out


async def _run(files: Mapping[str, str]) -> tuple[ArchiveFetch, UciCollection]:
    api = FakeApi(cgi=make_archive(files), uci=ubus_values(files))
    archive_fetch = await collect_archive(api, is_root=False)  # type: ignore[arg-type]
    collection = await collect_uci_snapshot(api, CONFIGS, DIGEST)  # type: ignore[arg-type]
    return archive_fetch, collection


async def test_end_to_end_backup_snapshot_and_drift() -> None:
    first_archive, first = await _run(FILES)
    assert first_archive.ok and first_archive.method == "cgi"
    report = validate_archive(first_archive.data or b"", DEFAULT_ARCHIVE_LIMITS)
    assert report.ok, report.findings
    assert set(CONFIGS) <= report.configs
    assert any(m.secret for m in report.members if m.name == "etc/shadow")

    # The archive's etc/config files give the same snapshot as UCI over ubus.
    texts = extract_uci_texts(first_archive.data or b"", DEFAULT_ARCHIVE_LIMITS)
    from_archive = build_snapshot(
        {name: parse_uci_file(text) for name, text in texts.items()},
        DIGEST,
        configs=CONFIGS,
    )
    assert from_archive.content_hash == first.snapshot.content_hash

    # Second run: the 2.4 GHz channel was changed on the router.
    second_archive, second = await _run(_changed_channel(FILES))
    assert second_archive.ok
    second_report = validate_archive(second_archive.data or b"")
    assert second_report.content_hash != report.content_hash
    assert second.snapshot.content_hash != first.snapshot.content_hash

    drift = evaluate_drift(first.snapshot, second.snapshot, (), mgmt_host=MGMT)
    assert drift.state == "new"
    assert len(drift.changes) == 1
    change = drift.changes[0]
    assert (change.config, change.section, change.option) == (
        "wireless",
        "radio0",
        "channel",
    )
    assert (change.old, change.new, change.area) == ("6", "11", Area.WLAN)
    for secret in PLAINTEXT:
        assert secret not in repr(drift)
