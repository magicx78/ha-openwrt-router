"""Tests for the restore compatibility check and dry run (configuration manager, G4).

Plan: docs/plans/2026-11-17-config-manager.md, sections 8, 11.8 and 16
(cases 5, 13, 14, 15, 16). Archives are real tar.gz files built in memory and
checked with ``config_archive``; snapshots come from
``config_snapshot.build_snapshot``. Phase 1 has no restore execution, so
nothing here talks to a router.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path
from typing import Any

import pytest

from custom_components.openwrt_router import config_inventory as ci
from custom_components.openwrt_router import config_restore as cr
from custom_components.openwrt_router.config_archive import (
    ArchiveReport,
    extract_uci_texts,
    validate_archive,
)
from custom_components.openwrt_router.config_const import (
    MASK_PLACEHOLDER,
    SECRET_MARKER_KEY,
    SNAPSHOT_STALE_S,
)
from custom_components.openwrt_router.config_diff import Area, Risk
from custom_components.openwrt_router.config_inventory import Inventory, parse_release
from custom_components.openwrt_router.config_mask import (
    mask_for_output,
    secret_digest_factory,
)
from custom_components.openwrt_router.config_restore import (
    Compatibility,
    RestorePlan,
    check_compatibility,
    dry_run,
    instructions,
)
from custom_components.openwrt_router.config_snapshot import (
    UciSnapshot,
    build_snapshot,
    parse_uci_file,
)

DIGEST = secret_digest_factory(b"r" * 32)
MGMT = "192.168.1.1"
MIB = 1024 * 1024
WLAN_KEY = "RestoreWlanKey#1"
NEW_WLAN_KEY = "ChangedWlanKey#2"
CONFIGS = ("network", "wireless", "firewall", "system", "dropbear", "sqm")

NETWORK = """\
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
\tlist ports 'lan3'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'wan'
\toption proto 'dhcp'
"""

NETWORK_SWCONFIG = """\
config interface 'loopback'
\toption device 'lo'
\toption proto 'static'
\toption ipaddr '127.0.0.1'
\toption netmask '255.0.0.0'

config switch
\toption name 'switch0'
\toption reset '1'
\toption enable_vlan '1'

config switch_vlan
\toption device 'switch0'
\toption vlan '1'
\toption ports '1 2 3 4 0t'

config switch_vlan
\toption device 'switch0'
\toption vlan '2'
\toption ports '5 0t'

config device
\toption name 'br-lan'
\toption type 'bridge'
\tlist ports 'eth0.1'

config interface 'lan'
\toption device 'br-lan'
\toption proto 'static'
\toption ipaddr '192.168.1.1'
\toption netmask '255.255.255.0'

config interface 'wan'
\toption device 'eth0.2'
\toption proto 'dhcp'
"""

WIRELESS = f"""\
config wifi-device 'radio0'
\toption type 'mac80211'
\toption path 'platform/soc/18000000.wifi'
\toption channel '6'
\toption band '2g'
\toption htmode 'HE20'
\toption country 'DE'

config wifi-iface 'default_radio0'
\toption device 'radio0'
\toption network 'lan'
\toption mode 'ap'
\toption ssid 'HomeNet'
\toption encryption 'sae-mixed'
\toption key '{WLAN_KEY}'
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
\toption output 'ACCEPT'
\toption forward 'ACCEPT'

config zone
\toption name 'wan'
\tlist network 'wan'
\toption input 'REJECT'
\toption output 'ACCEPT'
\toption forward 'REJECT'
\toption masq '1'
"""

SYSTEM = """\
config system
\toption hostname 'OpenWrt'
\toption timezone 'CET-1CEST,M3.5.0,M10.5.0/3'
"""

DROPBEAR = """\
config dropbear
\toption PasswordAuth 'on'
\toption RootPasswordAuth 'on'
\toption Port '22'
"""

SQM = """\
config queue 'eth1'
\toption enabled '1'
\toption interface 'wan'
\toption download '100000'
\toption upload '40000'
"""

BASE = {
    "network": NETWORK,
    "wireless": WIRELESS,
    "firewall": FIREWALL,
    "system": SYSTEM,
    "dropbear": DROPBEAR,
}

PACKAGES = {
    "base-files": "1.6-r1",
    "busybox": "1.36.1-r2",
    "dnsmasq": "2.90-r4",
    "dropbear": "2024.86-r1",
    "firewall4": "2024.12.18~18fc0ead-r1",
    "luci-base": "25.0.0-r1",
    "rpcd": "2024.09.17~d5f6aac4-r1",
    "uhttpd": "2023.06.25~34a8a74d-r4",
    "sqm-scripts": "1.6.0-r2",
}

SOURCE = Inventory(
    board_name="glinet,gl-mt6000",
    model="GL.iNet GL-MT6000",
    release_version="24.10.4",
    release_revision="r28959-29397011cc",
    target="mediatek/filogic",
    kernel="6.6.110",
    package_manager="opkg",
    packages=PACKAGES,
    package_source="rpc-sys",
    free_bytes=80 * MIB,
)
TARGET = SOURCE


def sub(text: str, old: str, new: str) -> str:
    assert old in text, old
    return text.replace(old, new, 1)


def make_archive(texts: dict[str, str]) -> bytes:
    """A tar.gz shaped like `sysupgrade -b` output."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=tarfile.GNU_FORMAT) as tf:
        members = {f"etc/config/{name}": text.encode() for name, text in texts.items()}
        members["etc/shadow"] = b"root:$5$abc$def:19000:0:99999:7:::\n"
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 1_700_000_000
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def snapshot(texts: dict[str, str]) -> UciSnapshot:
    return build_snapshot(
        {name: parse_uci_file(text) for name, text in texts.items()},
        DIGEST,
        configs=CONFIGS,
    )


def prepared(texts: dict[str, str]) -> tuple[bytes, ArchiveReport, UciSnapshot]:
    data = make_archive(texts)
    report = validate_archive(data)
    assert report.ok, report.findings
    uci = extract_uci_texts(data)
    return data, report, snapshot(dict(uci))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def plan_for(
    archive_texts: dict[str, str],
    current_texts: dict[str, str],
    *,
    source: Inventory = SOURCE,
    target: Inventory = TARGET,
    age: float | None = 600.0,
    mgmt_host: str | None = MGMT,
    expected: str | None | bool = True,
) -> RestorePlan:
    data, report, archive_snap = prepared(archive_texts)
    expected_sha = sha(data) if expected is True else expected
    return dry_run(
        report,
        archive_snap,
        snapshot(current_texts),
        source,
        target,
        mgmt_host=mgmt_host,
        snapshot_age_s=age,
        expected_sha256=expected_sha,  # type: ignore[arg-type]
    )


def codes(compat: Compatibility) -> dict[str, str]:
    return {f.code: f.level for f in compat.findings}


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("24.10.4", (24, 10, 4)),
        ("23.05.5", (23, 5, 5)),
        ("25.12.0-rc1", (25, 12, 0)),
        ("22.03", (22, 3, 0)),
        ("SNAPSHOT", None),
        ("", None),
        (None, None),
    ],
)
def test_parse_release(raw: str | None, expected: tuple[int, int, int] | None) -> None:
    assert parse_release(raw) == expected


def test_inventory_is_frozen_and_derives_package_manager() -> None:
    inv = Inventory(board_name="x", release_version="25.12.1")
    assert inv.effective_package_manager == ci.PACKAGE_MANAGER_APK
    assert Inventory(release_version="24.10.4").effective_package_manager == (
        ci.PACKAGE_MANAGER_OPKG
    )
    assert Inventory().effective_package_manager is None
    packages = {"dropbear": "1"}
    inv = Inventory(packages=packages)
    packages["evil"] = "2"
    assert "evil" not in inv.packages  # type: ignore[operator]
    with pytest.raises(dataclasses.FrozenInstanceError):
        inv.board_name = "y"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Plan 16 case 13: dry run
# ---------------------------------------------------------------------------


def test_dry_run_reports_diff_and_instructions() -> None:
    current = {**BASE, "wireless": sub(WIRELESS, "channel '6'", "channel '11'")}
    plan = plan_for(BASE, current)
    assert plan.compatibility.status == cr.COMPAT_OK
    assert plan.compatibility.findings == ()
    # Restoring changes the channel back from 11 to 6.
    (change,) = plan.changes
    assert (change.config, change.section, change.option) == (
        "wireless",
        "radio0",
        "channel",
    )
    assert (change.old, change.new) == ("11", "6")
    assert (change.area, change.risk) == (Area.WLAN, Risk.MEDIUM)
    assert plan.critical_count == 0
    assert plan.instructions == (
        cr.INSTR_NOT_REVERSIBLE,
        cr.INSTR_LUCI_RESTORE,
        cr.INSTR_CLI_RESTORE,
        cr.INSTR_VERIFY_AFTER_REBOOT,
        cr.INSTR_SECRETS_AND_IDENTITY,
    )
    assert all(re.fullmatch(r"[a-z0-9_]+", key) for key in plan.instructions)
    assert plan.reversible is False
    assert plan.warnings == ()
    assert plan.archive_sha256 == sha(make_archive(BASE))
    assert plan.snapshot_age_s == 600.0
    # The configs missing on both sides (sqm) are not "not comparable".
    assert plan.not_comparable == ()


def test_identical_archive_and_current_give_empty_plan() -> None:
    plan = plan_for(BASE, BASE)
    assert plan.changes == ()
    assert plan.compatibility.status == cr.COMPAT_OK


def test_stale_snapshot_warning() -> None:
    stale = plan_for(BASE, BASE, age=SNAPSHOT_STALE_S + 1)
    assert cr.WARN_SNAPSHOT_STALE in stale.warnings
    fresh = plan_for(BASE, BASE, age=SNAPSHOT_STALE_S - 1)
    assert cr.WARN_SNAPSHOT_STALE not in fresh.warnings
    unknown = plan_for(BASE, BASE, age=None)
    assert cr.WARN_SNAPSHOT_AGE_UNKNOWN in unknown.warnings
    skewed = plan_for(BASE, BASE, age=-5.0)
    assert cr.WARN_SNAPSHOT_AGE_UNKNOWN in skewed.warnings
    # A stale snapshot is a hint, never a block.
    assert stale.compatibility.status == cr.COMPAT_OK


def test_not_comparable_configs_are_listed() -> None:
    current = {k: v for k, v in BASE.items() if k != "dropbear"}
    plan = plan_for(BASE, current)
    assert plan.not_comparable == ("dropbear",)
    assert cr.WARN_CONFIG_NOT_COMPARABLE in plan.warnings
    assert all(c.config != "dropbear" for c in plan.changes)


# ---------------------------------------------------------------------------
# Plan 16 case 5 and 14: blocks and warnings
# ---------------------------------------------------------------------------


def test_checksum_mismatch_blocks_dry_run() -> None:
    plan = plan_for(BASE, BASE, expected=sha(b"another file"))
    assert plan.compatibility.status == cr.COMPAT_BLOCK
    assert plan.compatibility.blocked
    assert codes(plan.compatibility)[cr.CODE_CHECKSUM_MISMATCH] == cr.LEVEL_BLOCK
    assert plan.instructions == (cr.INSTR_BLOCKED, cr.INSTR_NOT_REVERSIBLE)
    # Upper-case hex of the right digest is fine.
    ok = plan_for(BASE, BASE, expected=sha(make_archive(BASE)).upper())
    assert ok.compatibility.status == cr.COMPAT_OK
    # Without a stored checksum the dry run says so.
    unverified = plan_for(BASE, BASE, expected=None)
    assert codes(unverified.compatibility) == {
        cr.CODE_CHECKSUM_UNVERIFIED: cr.LEVEL_WARN
    }


def test_invalid_archive_blocks() -> None:
    data = make_archive(BASE)
    truncated = data[: len(data) // 2]
    report = validate_archive(truncated)
    assert not report.ok
    empty = build_snapshot({}, DIGEST, configs=CONFIGS)
    compat = check_compatibility(
        SOURCE, TARGET, report, empty, snapshot(BASE), expected_sha256=sha(truncated)
    )
    assert compat.status == cr.COMPAT_BLOCK
    finding = next(f for f in compat.findings if f.code == cr.CODE_ARCHIVE_INVALID)
    assert finding.level == cr.LEVEL_BLOCK
    assert finding.params["error"] == report.error


def test_board_mismatch_blocks() -> None:
    other = dataclasses.replace(
        TARGET, board_name="glinet,gl-mt3000", model="GL-MT3000"
    )
    plan = plan_for(BASE, BASE, target=other)
    assert codes(plan.compatibility)[cr.CODE_BOARD_MISMATCH] == cr.LEVEL_BLOCK
    finding = plan.compatibility.findings[0]
    assert dict(finding.params) == {
        "source": "glinet,gl-mt6000",
        "target": "glinet,gl-mt3000",
    }
    assert plan.instructions[0] == cr.INSTR_BLOCKED
    # Same board in another spelling is no mismatch; unknown board warns.
    same = dataclasses.replace(TARGET, board_name=" GLINET,GL-MT6000 ")
    assert plan_for(BASE, BASE, target=same).compatibility.status == cr.COMPAT_OK
    unknown = dataclasses.replace(TARGET, board_name=None)
    assert codes(plan_for(BASE, BASE, target=unknown).compatibility) == {
        cr.CODE_BOARD_UNKNOWN: cr.LEVEL_WARN
    }


def test_swconfig_vs_dsa_blocks() -> None:
    swconfig = {**BASE, "network": NETWORK_SWCONFIG}
    plan = plan_for(swconfig, BASE)
    assert codes(plan.compatibility)[cr.CODE_SWITCH_MODEL_MISMATCH] == cr.LEVEL_BLOCK
    finding = next(
        f
        for f in plan.compatibility.findings
        if f.code == cr.CODE_SWITCH_MODEL_MISMATCH
    )
    assert dict(finding.params) == {"archive": "swconfig", "target": "dsa"}
    reverse = plan_for(BASE, swconfig)
    assert reverse.compatibility.blocked
    assert cr.switch_model(snapshot(swconfig)) == cr.SWITCH_SWCONFIG
    assert cr.switch_model(snapshot(BASE)) == cr.SWITCH_DSA
    # A single-port device without VLANs says nothing about the model.
    plain = sub(
        NETWORK,
        "\tlist ports 'lan1'\n\tlist ports 'lan2'\n\tlist ports 'lan3'\n",
        "\tlist ports 'eth0'\n",
    )
    assert cr.switch_model(snapshot({**BASE, "network": plain})) is None


def test_downgrade_warns() -> None:
    older = dataclasses.replace(TARGET, release_version="24.10.2")
    plan = plan_for(BASE, BASE, target=older)
    assert codes(plan.compatibility) == {cr.CODE_RELEASE_DOWNGRADE: cr.LEVEL_WARN}
    assert plan.compatibility.status == cr.COMPAT_WARN
    assert not plan.compatibility.blocked
    assert cr.INSTR_REVIEW_WARNINGS in plan.instructions
    assert cr.INSTR_LUCI_RESTORE in plan.instructions


def test_major_release_change_warns() -> None:
    src = dataclasses.replace(SOURCE, release_version="23.05.5")
    plan = plan_for(BASE, BASE, source=src)
    assert codes(plan.compatibility) == {cr.CODE_RELEASE_MAJOR_CHANGE: cr.LEVEL_WARN}
    fw3 = dataclasses.replace(SOURCE, release_version="21.02.7")
    found = codes(plan_for(BASE, BASE, source=fw3).compatibility)
    assert found == {
        cr.CODE_RELEASE_MAJOR_CHANGE: cr.LEVEL_WARN,
        cr.CODE_FIREWALL_FW3_TO_FW4: cr.LEVEL_WARN,
    }
    apk = dataclasses.replace(TARGET, release_version="25.12.0", package_manager="apk")
    plan = plan_for(BASE, BASE, target=apk)
    assert codes(plan.compatibility) == {
        cr.CODE_RELEASE_MAJOR_CHANGE: cr.LEVEL_WARN,
        cr.CODE_PACKAGE_MANAGER_CHANGE: cr.LEVEL_WARN,
    }
    assert cr.INSTR_APK_PACKAGE_NAMES in plan.instructions
    snap = dataclasses.replace(TARGET, release_version="SNAPSHOT")
    assert codes(plan_for(BASE, BASE, target=snap).compatibility) == {
        cr.CODE_RELEASE_UNKNOWN: cr.LEVEL_WARN
    }


def test_eol_target_release_gets_a_hint() -> None:
    old = dataclasses.replace(SOURCE, release_version="23.05.5")
    plan = plan_for(BASE, BASE, source=old, target=old)
    assert plan.compatibility.status == cr.COMPAT_OK
    assert cr.INSTR_RELEASE_EOL in plan.instructions


def test_missing_package_warns() -> None:
    with_sqm = {**BASE, "sqm": SQM}
    without = dict(PACKAGES)
    del without["sqm-scripts"]
    target = dataclasses.replace(TARGET, packages=without)
    plan = plan_for(with_sqm, BASE, target=target)
    finding = next(
        f for f in plan.compatibility.findings if f.code == cr.CODE_MISSING_PACKAGE
    )
    assert finding.level == cr.LEVEL_WARN
    assert dict(finding.params) == {"config": "sqm", "package": "sqm-scripts"}
    assert cr.INSTR_INSTALL_PACKAGES in plan.instructions
    # sqm is unreadable on the target: not comparable, not "added".
    assert plan.not_comparable == ("sqm",)
    # Installed: no finding.
    assert codes(plan_for(with_sqm, {**BASE, "sqm": SQM}).compatibility) == {}
    # Unknown package list: one warning, no guessing.
    unknown = dataclasses.replace(TARGET, packages=None, partial=True)
    found = codes(plan_for(with_sqm, BASE, target=unknown).compatibility)
    assert found == {
        cr.CODE_PACKAGES_UNKNOWN: cr.LEVEL_WARN,
        cr.CODE_INVENTORY_PARTIAL: cr.LEVEL_WARN,
    }


def test_package_globs_and_generic_config_names() -> None:
    texts = {**BASE, "upnpd": "config upnpd 'config'\n\toption enabled '1'\n"}
    data, report, archive_snap = prepared(texts)
    target = dataclasses.replace(
        TARGET, packages={**PACKAGES, "miniupnpd-nftables": "2.3"}
    )
    compat = check_compatibility(
        SOURCE, target, report, archive_snap, snapshot(BASE), expected_sha256=sha(data)
    )
    assert cr.CODE_MISSING_PACKAGE not in codes(compat)
    compat = check_compatibility(
        SOURCE, TARGET, report, archive_snap, snapshot(BASE), expected_sha256=sha(data)
    )
    finding = next(f for f in compat.findings if f.code == cr.CODE_MISSING_PACKAGE)
    assert dict(finding.params) == {"config": "upnpd", "package": "miniupnpd"}
    # Unknown config named like a package installed on the source only.
    texts = {**BASE, "adblock": "config adblock 'global'\n\toption adb_enabled '1'\n"}
    data, report, archive_snap = prepared(texts)
    source = dataclasses.replace(SOURCE, packages={**PACKAGES, "adblock": "4.2.2-r1"})
    compat = check_compatibility(
        source, TARGET, report, archive_snap, snapshot(BASE), expected_sha256=sha(data)
    )
    finding = next(f for f in compat.findings if f.code == cr.CODE_MISSING_PACKAGE)
    assert dict(finding.params) == {"config": "adblock", "package": "adblock"}


def test_insufficient_space_warns() -> None:
    tiny = dataclasses.replace(TARGET, free_bytes=1024)
    plan = plan_for(BASE, BASE, target=tiny)
    finding = next(
        f for f in plan.compatibility.findings if f.code == cr.CODE_INSUFFICIENT_SPACE
    )
    assert finding.level == cr.LEVEL_WARN
    assert finding.params["free"] == "1024"
    assert int(finding.params["needed"]) > 1024


def test_check_compatibility_equals_dry_run_compatibility() -> None:
    current = {**BASE, "network": sub(NETWORK, "'192.168.1.1'", "'192.168.1.2'")}
    data, report, archive_snap = prepared(BASE)
    compat = check_compatibility(
        SOURCE,
        TARGET,
        report,
        archive_snap,
        snapshot(current),
        mgmt_host="192.168.1.2",
        expected_sha256=sha(data),
    )
    plan = plan_for(BASE, current, mgmt_host="192.168.1.2")
    assert compat == plan.compatibility


# ---------------------------------------------------------------------------
# Plan 16 case 15: no router access in phase 1
# ---------------------------------------------------------------------------

_FORBIDDEN_IMPORTS = (
    "homeassistant",
    "aiohttp",
    "asyncssh",
    "socket",
    "subprocess",
    "http",
    "urllib",
    "ssl",
    "requests",
    "paramiko",
    "shutil",
    "os",
    "pathlib",
    "tempfile",
)
_WRITE_NAME = re.compile(
    r"(write|apply|execute|upload|send|push|commit|reboot|flash|sysupgrade|"
    r"perform|run_restore|do_restore|restore_backup|^restore$)",
    re.IGNORECASE,
)


def _module_tree(name: str) -> ast.Module:
    path = Path(cr.__file__).with_name(f"{name}.py")
    return ast.parse(path.read_text(encoding="utf-8"))


def _imports(tree: ast.Module) -> tuple[set[str], set[str]]:
    """(absolute top-level modules, package-relative modules)."""
    absolute: set[str] = set()
    relative: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            absolute.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                if node.module:
                    relative.add(node.module.split(".")[0])
                else:
                    relative.update(alias.name for alias in node.names)
            elif node.module:
                absolute.add(node.module.split(".")[0])
    return absolute, relative


def test_restore_module_has_no_router_access() -> None:
    # Every module config_restore pulls in from the package, transitively.
    todo, seen = ["config_restore"], set()
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        seen.add(name)
        absolute, relative = _imports(_module_tree(name))
        assert "api" not in relative, name
        assert not absolute & set(_FORBIDDEN_IMPORTS), (name, absolute)
        todo.extend(relative)
    assert {"config_restore", "config_inventory", "config_diff"} <= seen
    assert "api" not in seen

    tree = _module_tree("config_restore")
    for node in ast.walk(tree):
        assert not isinstance(node, (ast.AsyncFunctionDef, ast.Await)), node
        if isinstance(node, ast.FunctionDef):
            assert not _WRITE_NAME.search(node.name), node.name
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in {"open", "exec", "eval", "__import__"}
        if isinstance(node, ast.Name):
            assert node.id != "api"
        if isinstance(node, ast.Attribute):
            assert node.attr != "api"
    # Runtime view: nothing named like a router call is exported.
    public = [n for n in dir(cr) if not n.startswith("_")]
    assert "api" not in public
    assert not [n for n in public if callable(getattr(cr, n)) and _WRITE_NAME.search(n)]


# ---------------------------------------------------------------------------
# Plan 16 case 16: lockout risk
# ---------------------------------------------------------------------------


def test_instructions_cover_lockout_risk() -> None:
    # HA reaches the router on .2 today; the archive puts .1 back.
    current = {**BASE, "network": sub(NETWORK, "'192.168.1.1'", "'192.168.1.2'")}
    plan = plan_for(BASE, current, mgmt_host="192.168.1.2")
    assert plan.critical_count == 1
    (change,) = plan.changes
    assert (change.area, change.risk) == (Area.MGMT_IP, Risk.CRITICAL)
    assert codes(plan.compatibility)[cr.CODE_LOCKOUT_RISK] == cr.LEVEL_WARN
    keys = plan.instructions
    assert keys[0] == cr.INSTR_NOT_REVERSIBLE
    assert keys[1] == cr.INSTR_CONSOLE_FAILSAFE
    assert keys.index(cr.INSTR_CONSOLE_FAILSAFE) < keys.index(cr.INSTR_LUCI_RESTORE)
    assert instructions(TARGET, plan.compatibility) == keys


@pytest.mark.parametrize(
    ("config", "old", "new"),
    [
        ("dropbear", "option Port '22'", "option Port '2222'"),
        (
            "firewall",
            "list network 'wan'\n\toption input 'REJECT'",
            "list network 'wan'\n\toption input 'ACCEPT'",
        ),
    ],
)
def test_lockout_risk_for_ssh_and_firewall(config: str, old: str, new: str) -> None:
    current = {**BASE, config: sub(BASE[config], old, new)}
    plan = plan_for(BASE, current)
    assert cr.CODE_LOCKOUT_RISK in codes(plan.compatibility)
    assert cr.INSTR_CONSOLE_FAILSAFE in plan.instructions


def test_no_console_hint_without_access_changes() -> None:
    current = {**BASE, "system": sub(SYSTEM, "'OpenWrt'", "'Router-1'")}
    plan = plan_for(BASE, current)
    assert plan.changes
    assert cr.INSTR_CONSOLE_FAILSAFE not in plan.instructions


# ---------------------------------------------------------------------------
# Masking and result objects
# ---------------------------------------------------------------------------


def _dump(obj: Any) -> str:
    return json.dumps(obj, default=str, sort_keys=True)


def test_mask_for_output_of_restore_plan_has_no_plaintext() -> None:
    current = {**BASE, "wireless": sub(WIRELESS, WLAN_KEY, NEW_WLAN_KEY)}
    plan = plan_for(BASE, current)
    (change,) = plan.changes
    assert (change.option, change.kind) == ("key", "changed")
    digests = [change.old[SECRET_MARKER_KEY], change.new[SECRET_MARKER_KEY]]
    text = _dump(mask_for_output(plan))
    for secret in (WLAN_KEY, NEW_WLAN_KEY, *digests):
        assert secret not in text
    assert MASK_PLACEHOLDER in text
    assert '"option": "key"' in text
    for secret in (WLAN_KEY, NEW_WLAN_KEY):
        assert secret not in repr(plan)


def test_restore_plan_is_never_reversible() -> None:
    plan = plan_for(BASE, BASE)
    with pytest.raises(ValueError):
        dataclasses.replace(plan, reversible=True)
    with pytest.raises(dataclasses.FrozenInstanceError):
        plan.reversible = True  # type: ignore[misc]
