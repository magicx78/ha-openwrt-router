"""Restore compatibility check and dry run (phase 1: no execution).

Plan: docs/plans/2026-11-17-config-manager.md, sections 8 (D15) and 11.8.

A restore of a ``sysupgrade -b`` archive has no way back in OpenWrt
(``sysupgrade -r`` + reboot, no rollback). Phase 1 therefore only checks,
previews and explains:

- :func:`check_compatibility` says ``ok``, ``warn`` or ``block`` with
  reasons (board, switch model, archive integrity, release, packages,
  space, management access),
- :func:`dry_run` adds the masked diff "current -> archive" from the last
  snapshot (the router is not asked) and the instruction steps,
- :func:`instructions` returns translation keys, never text.

This module never sees ``api``: it has no function that talks to or
writes on a router. The plan it returns always says "not automatically
reversible".

Pure module: no Home Assistant imports, no network, no files.
"""

from __future__ import annotations

import hmac
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from types import MappingProxyType
from typing import Final, Literal

from .config_archive import MEMBER_DIR, ArchiveReport
from .config_const import ACCESS_ARCHIVE_PATHS, SNAPSHOT_STALE_S
from .config_diff import (
    Area,
    Change,
    Risk,
    diff_snapshots,
    not_comparable,
)
from .config_inventory import Inventory, Release
from .config_snapshot import NORM_OPTIONS, NORM_SECTIONS, NORM_TYPE, UciSnapshot

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "COMPAT_BLOCK",
    "COMPAT_OK",
    "COMPAT_WARN",
    "CONFIG_PACKAGES",
    "Compatibility",
    "Finding",
    "RestorePlan",
    "check_compatibility",
    "dry_run",
    "instructions",
    "switch_model",
]

# ---------------------------------------------------------------------------
# Levels, finding codes, warnings, instruction keys
# ---------------------------------------------------------------------------

CompatStatus = Literal["ok", "warn", "block"]
COMPAT_OK: Final = "ok"
COMPAT_WARN: Final = "warn"
COMPAT_BLOCK: Final = "block"

FindingLevel = Literal["warn", "block"]
LEVEL_WARN: Final = "warn"
LEVEL_BLOCK: Final = "block"

# Finding codes (also the translation keys of the reasons).
CODE_ARCHIVE_INVALID: Final = "archive_invalid"
CODE_CHECKSUM_MISMATCH: Final = "checksum_mismatch"
CODE_CHECKSUM_UNVERIFIED: Final = "checksum_unverified"
CODE_BOARD_MISMATCH: Final = "board_mismatch"
CODE_BOARD_UNKNOWN: Final = "board_unknown"
CODE_SWITCH_MODEL_MISMATCH: Final = "switch_model_mismatch"
CODE_RELEASE_UNKNOWN: Final = "release_unknown"
CODE_RELEASE_DOWNGRADE: Final = "release_downgrade"
CODE_RELEASE_MAJOR_CHANGE: Final = "release_major_change"
CODE_FIREWALL_FW3_TO_FW4: Final = "firewall_fw3_to_fw4"
CODE_PACKAGE_MANAGER_CHANGE: Final = "package_manager_change"
CODE_MISSING_PACKAGE: Final = "missing_package"
CODE_PACKAGES_UNKNOWN: Final = "packages_unknown"
CODE_INVENTORY_PARTIAL: Final = "inventory_partial"
CODE_INSUFFICIENT_SPACE: Final = "insufficient_space"
CODE_LOCKOUT_RISK: Final = "lockout_risk"

# Dry-run warnings (not part of the compatibility verdict).
WARN_SNAPSHOT_STALE: Final = "snapshot_stale"
WARN_SNAPSHOT_AGE_UNKNOWN: Final = "snapshot_age_unknown"
WARN_CONFIG_NOT_COMPARABLE: Final = "config_not_comparable"
# The archive writes back passwords, SSH keys or the TLS key pair: the
# login can change (review M4). Presence only, never names or digests.
WARN_ACCESS_FILES: Final = "access_files_overwritten"

# Instruction steps (translation keys, plan 8.4).
INSTR_BLOCKED: Final = "restore_blocked"
INSTR_NOT_REVERSIBLE: Final = "restore_not_reversible"
INSTR_CONSOLE_FAILSAFE: Final = "restore_prepare_console_failsafe"
INSTR_REVIEW_WARNINGS: Final = "restore_review_warnings"
INSTR_INSTALL_PACKAGES: Final = "restore_install_missing_packages"
INSTR_APK_PACKAGE_NAMES: Final = "restore_apk_package_names"
INSTR_RELEASE_EOL: Final = "restore_release_eol"
INSTR_LUCI_RESTORE: Final = "restore_luci_upload"
INSTR_CLI_RESTORE: Final = "restore_cli_sysupgrade"
INSTR_VERIFY_AFTER_REBOOT: Final = "restore_verify_after_reboot"
INSTR_SECRETS_AND_IDENTITY: Final = "restore_secrets_and_identity"

SWITCH_SWCONFIG: Final = "swconfig"
SWITCH_DSA: Final = "dsa"

# Release series that still get updates (plan 8.2: 22.03 and 23.05 are EOL).
_FIRST_SUPPORTED_SERIES: Final = (24, 10)
# fw3 (iptables) up to 21.02, fw4 (nftables) from 22.03.
_FW4_SINCE: Final = Release(22, 3, 0)

# Package(s) owning a config, fnmatch globs; the first one is named in the
# finding. Configs not listed fall back to "a package of the same name that
# the source had installed".
CONFIG_PACKAGES: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "dropbear": ("dropbear",),
        "uhttpd": ("uhttpd",),
        "rpcd": ("rpcd",),
        "firewall": ("firewall4", "firewall"),
        "dhcp": ("dnsmasq", "dnsmasq-*", "odhcpd", "odhcpd-*"),
        "luci": ("luci-base",),
        "ddns": ("ddns-scripts",),
        "sqm": ("sqm-scripts",),
        "usteer": ("usteer",),
        "mwan3": ("mwan3",),
        "upnpd": ("miniupnpd", "miniupnpd-*"),
        "openvpn": ("openvpn-*", "openvpn"),
    }
)

# Areas whose change can lock HA (or the user) out of the router.
_LOCKOUT_AREAS: Final = frozenset({Area.MGMT_IP, Area.VLAN, Area.FIREWALL, Area.SSH})
_SWCONFIG_TYPES: Final = frozenset({"switch", "switch_vlan", "switch_port"})
_DSA_PORT_RE: Final = re.compile(r"(lan\d+|wan\d*|port\d+|sfp\d*)(:[tu*]+)?")

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """One reason of the verdict. ``params`` are placeholders for the text."""

    code: str
    level: FindingLevel
    params: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "params",
            MappingProxyType({str(k): str(v) for k, v in self.params.items()}),
        )


@dataclass(frozen=True, slots=True)
class Compatibility:
    """Verdict of :func:`check_compatibility`: ok, warn or block."""

    status: CompatStatus
    findings: tuple[Finding, ...]

    @property
    def blocked(self) -> bool:
        """True if the archive must not be restored onto this router."""
        return self.status == COMPAT_BLOCK

    @property
    def codes(self) -> frozenset[str]:
        """Codes of all findings."""
        return frozenset(finding.code for finding in self.findings)


@dataclass(frozen=True, slots=True)
class RestorePlan:
    """Outcome of :func:`dry_run`. Phase 1: a preview, never an action.

    ``changes`` is the diff "current -> archive" (what a restore would
    change), secrets as digest markers. ``warnings`` are dry-run hints
    (stale snapshot, configs not comparable, archive warnings).
    ``reversible`` is always False: an archive restore has no way back.
    """

    compatibility: Compatibility
    changes: tuple[Change, ...]
    critical_count: int
    instructions: tuple[str, ...]
    archive_sha256: str
    warnings: tuple[str, ...]
    not_comparable: tuple[str, ...]
    snapshot_age_s: float | None
    reversible: bool = False

    def __post_init__(self) -> None:
        if self.reversible:
            raise ValueError("an archive restore is never automatically reversible")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _norm(value: str | None) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    return value or None


def switch_model(snapshot: UciSnapshot) -> str | None:
    """Return ``swconfig``, ``dsa`` or None (not decidable) for a snapshot.

    swconfig: any ``switch``/``switch_vlan``/``switch_port`` section.
    DSA: ``bridge-vlan`` sections or device ports named like DSA user ports
    (``lan1``, ``wan``, ``port2``, ``sfp``). A device with one plain
    ``eth0`` and no VLANs says nothing.
    """
    network = snapshot.configs.get("network")
    if not isinstance(network, Mapping):
        return None
    sections = network.get(NORM_SECTIONS)
    if not isinstance(sections, Mapping):
        return None
    bodies = [s for s in sections.values() if isinstance(s, Mapping)]
    types = {s.get(NORM_TYPE) for s in bodies}
    if types & _SWCONFIG_TYPES:
        return SWITCH_SWCONFIG
    if "bridge-vlan" in types:
        return SWITCH_DSA
    for body in bodies:
        if body.get(NORM_TYPE) != "device":
            continue
        options = body.get(NORM_OPTIONS)
        ports = options.get("ports") if isinstance(options, Mapping) else None
        values = ports if isinstance(ports, list) else [ports]
        if any(
            isinstance(port, str) and _DSA_PORT_RE.fullmatch(port) for port in values
        ):
            return SWITCH_DSA
    return None


def _installed(packages: Mapping[str, str | None], patterns: Sequence[str]) -> bool:
    return any(fnmatchcase(name, pattern) for name in packages for pattern in patterns)


def _package_findings(
    source: Inventory, target: Inventory, archive: ArchiveReport
) -> list[Finding]:
    if target.packages is None:
        return [Finding(CODE_PACKAGES_UNKNOWN, LEVEL_WARN)] if archive.configs else []
    out: list[Finding] = []
    for config in sorted(archive.configs):
        patterns = CONFIG_PACKAGES.get(config)
        if patterns is None:
            if source.packages is None or config not in source.packages:
                continue
            patterns = (config,)
        if not _installed(target.packages, patterns):
            out.append(
                Finding(
                    CODE_MISSING_PACKAGE,
                    LEVEL_WARN,
                    {"config": config, "package": patterns[0]},
                )
            )
    return out


def _release_findings(source: Inventory, target: Inventory) -> list[Finding]:
    src, tgt = source.release, target.release
    if src is None or tgt is None:
        return [
            Finding(
                CODE_RELEASE_UNKNOWN,
                LEVEL_WARN,
                {
                    "source": source.release_version or "",
                    "target": target.release_version or "",
                },
            )
        ]
    versions = {
        "source": source.release_version or "",
        "target": target.release_version or "",
    }
    out: list[Finding] = []
    if tgt < src:
        out.append(Finding(CODE_RELEASE_DOWNGRADE, LEVEL_WARN, versions))
    if tgt.series != src.series:
        out.append(Finding(CODE_RELEASE_MAJOR_CHANGE, LEVEL_WARN, versions))
    if src < _FW4_SINCE <= tgt:
        out.append(Finding(CODE_FIREWALL_FW3_TO_FW4, LEVEL_WARN, versions))
    src_pm, tgt_pm = source.effective_package_manager, target.effective_package_manager
    if src_pm and tgt_pm and src_pm != tgt_pm:
        out.append(
            Finding(
                CODE_PACKAGE_MANAGER_CHANGE,
                LEVEL_WARN,
                {"source": src_pm, "target": tgt_pm},
            )
        )
    return out


def _has_access_files(archive: ArchiveReport) -> bool:
    """True if a restore of ``archive`` overwrites login data (review M4)."""
    return any(
        member.type != MEMBER_DIR
        and any(
            fnmatchcase(member.name.lower(), pattern)
            for pattern in ACCESS_ARCHIVE_PATHS
        )
        for member in archive.members
    )


def _lockout_changes(changes: Sequence[Change]) -> list[Change]:
    return [c for c in changes if c.area in _LOCKOUT_AREAS or c.risk == Risk.CRITICAL]


def _evaluate(
    source: Inventory,
    target: Inventory,
    archive: ArchiveReport,
    archive_snapshot: UciSnapshot,
    current: UciSnapshot,
    changes: Sequence[Change],
    expected_sha256: str | None,
) -> Compatibility:
    findings: list[Finding] = []

    # Archive integrity.
    if not archive.ok:
        findings.append(
            Finding(
                CODE_ARCHIVE_INVALID, LEVEL_BLOCK, {"error": archive.error or "invalid"}
            )
        )
    if expected_sha256 is None:
        findings.append(Finding(CODE_CHECKSUM_UNVERIFIED, LEVEL_WARN))
    elif not hmac.compare_digest(
        archive.archive_sha256.lower(), expected_sha256.strip().lower()
    ):
        findings.append(Finding(CODE_CHECKSUM_MISMATCH, LEVEL_BLOCK))

    # Hardware.
    src_board, tgt_board = _norm(source.board_name), _norm(target.board_name)
    if src_board is None or tgt_board is None:
        findings.append(Finding(CODE_BOARD_UNKNOWN, LEVEL_WARN))
    elif src_board != tgt_board:
        findings.append(
            Finding(
                CODE_BOARD_MISMATCH,
                LEVEL_BLOCK,
                {"source": src_board, "target": tgt_board},
            )
        )
    archive_switch, target_switch = (
        switch_model(archive_snapshot),
        switch_model(current),
    )
    if archive_switch and target_switch and archive_switch != target_switch:
        findings.append(
            Finding(
                CODE_SWITCH_MODEL_MISMATCH,
                LEVEL_BLOCK,
                {"archive": archive_switch, "target": target_switch},
            )
        )

    # Software.
    findings.extend(_release_findings(source, target))
    findings.extend(_package_findings(source, target, archive))
    if source.partial or target.partial:
        findings.append(Finding(CODE_INVENTORY_PARTIAL, LEVEL_WARN))
    if target.free_bytes is not None and archive.uncompressed_size > target.free_bytes:
        findings.append(
            Finding(
                CODE_INSUFFICIENT_SPACE,
                LEVEL_WARN,
                {
                    "needed": str(archive.uncompressed_size),
                    "free": str(target.free_bytes),
                },
            )
        )

    # Management access.
    risky = _lockout_changes(changes)
    if risky:
        findings.append(
            Finding(
                CODE_LOCKOUT_RISK,
                LEVEL_WARN,
                {
                    "count": str(len(risky)),
                    "areas": ",".join(sorted({str(c.area) for c in risky})),
                },
            )
        )

    levels = {finding.level for finding in findings}
    status: CompatStatus
    if LEVEL_BLOCK in levels:
        status = COMPAT_BLOCK
    elif LEVEL_WARN in levels:
        status = COMPAT_WARN
    else:
        status = COMPAT_OK
    return Compatibility(status=status, findings=tuple(findings))


# ---------------------------------------------------------------------------
# Public API (plan 11.8)
# ---------------------------------------------------------------------------


def check_compatibility(
    source: Inventory,
    target: Inventory,
    archive: ArchiveReport,
    archive_snapshot: UciSnapshot,
    current: UciSnapshot,
    *,
    mgmt_host: str | None = None,
    expected_sha256: str | None = None,
) -> Compatibility:
    """Can ``archive`` (taken on ``source``) go onto ``target``?

    ``archive`` is the report of ``validate_archive`` over the bytes read
    just now, ``expected_sha256`` the checksum stored with the version
    (None = not known, gives a warning). ``archive_snapshot`` is the UCI
    snapshot built from the archive, ``current`` the latest snapshot of the
    target. ``mgmt_host`` is the address HA uses for the target.

    block: archive not ok, checksum mismatch, other board, swconfig vs DSA.
    warn: unknown board/release, downgrade, release series change, fw3 to
    fw4, apk vs opkg, configs of packages missing on the target, unknown
    package list, partial inventory, too little free space, changes to
    management address, VLAN, firewall or SSH/uhttpd/rpcd (lockout risk).
    """
    changes = diff_snapshots(current, archive_snapshot, mgmt_host=mgmt_host)
    return _evaluate(
        source, target, archive, archive_snapshot, current, changes, expected_sha256
    )


def instructions(target: Inventory, compat: Compatibility) -> tuple[str, ...]:
    """Instruction steps as translation keys (plan 8.4), in order.

    Blocked: only "do not restore" and the irreversibility note. Otherwise
    the console/failsafe step comes first whenever management access could
    change.
    """
    if compat.blocked:
        return (INSTR_BLOCKED, INSTR_NOT_REVERSIBLE)
    codes = compat.codes
    steps = [INSTR_NOT_REVERSIBLE]
    if CODE_LOCKOUT_RISK in codes:
        steps.append(INSTR_CONSOLE_FAILSAFE)
    if compat.status == COMPAT_WARN:
        steps.append(INSTR_REVIEW_WARNINGS)
    if CODE_MISSING_PACKAGE in codes:
        steps.append(INSTR_INSTALL_PACKAGES)
    if CODE_PACKAGE_MANAGER_CHANGE in codes:
        steps.append(INSTR_APK_PACKAGE_NAMES)
    release = target.release
    if release is not None and release.series < _FIRST_SUPPORTED_SERIES:
        steps.append(INSTR_RELEASE_EOL)
    steps.extend(
        (
            INSTR_LUCI_RESTORE,
            INSTR_CLI_RESTORE,
            INSTR_VERIFY_AFTER_REBOOT,
            INSTR_SECRETS_AND_IDENTITY,
        )
    )
    return tuple(steps)


def dry_run(
    archive: ArchiveReport,
    archive_snapshot: UciSnapshot,
    current: UciSnapshot,
    source: Inventory,
    target: Inventory,
    *,
    mgmt_host: str | None,
    snapshot_age_s: float | None,
    expected_sha256: str | None = None,
) -> RestorePlan:
    """Preview a restore of ``archive`` onto ``target`` without touching it.

    Uses the latest snapshot ``current`` (the router is not asked); one
    older than ``SNAPSHOT_STALE_S`` (or of unknown age) is flagged, and so
    is an archive that writes back login data (``WARN_ACCESS_FILES``).
    """
    changes = diff_snapshots(current, archive_snapshot, mgmt_host=mgmt_host)
    compat = _evaluate(
        source, target, archive, archive_snapshot, current, changes, expected_sha256
    )
    skipped = not_comparable(current, archive_snapshot)

    warnings: list[str] = []
    if snapshot_age_s is None or snapshot_age_s < 0:
        warnings.append(WARN_SNAPSHOT_AGE_UNKNOWN)
    elif snapshot_age_s > SNAPSHOT_STALE_S:
        warnings.append(WARN_SNAPSHOT_STALE)
    if skipped:
        warnings.append(WARN_CONFIG_NOT_COMPARABLE)
    if _has_access_files(archive):
        warnings.append(WARN_ACCESS_FILES)
    for code in sorted({finding.code for finding in archive.warnings}):
        if code not in warnings:
            warnings.append(code)

    critical = sum(1 for change in changes if change.risk == Risk.CRITICAL)
    _LOGGER.debug(
        "restore dry run: %s, %d change(s), %d critical",
        compat.status,
        len(changes),
        critical,
    )
    return RestorePlan(
        compatibility=compat,
        changes=changes,
        critical_count=critical,
        instructions=instructions(target, compat),
        archive_sha256=archive.archive_sha256,
        warnings=tuple(warnings),
        not_comparable=skipped,
        snapshot_age_s=snapshot_age_s,
    )
