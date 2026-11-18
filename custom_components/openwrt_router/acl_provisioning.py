"""acl_provisioning.py — Auto-deploy rpcd ACL to OpenWrt routers.

When a router is added to Home Assistant, this module checks if the
rpcd ACL file exists on the router. If missing, it deploys it via the
ubus file API (no SSH required; asyncssh fallback when file/write is blocked).

The ACL grants access to the ubus methods needed by the integration:
hostapd, network.wireless, network.interface, network (reload), luci-rpc,
iwinfo, system, log, usteer — plus read access to a fixed set of files.
"""

from __future__ import annotations

import hashlib
import json
import logging
import posixpath
import re
import secrets
import shlex
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final, Protocol

from .api import (
    OpenWrtAuthError,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
)
from .core_errors import AuthorizationError
from .core_models import (
    ACL_CAPABILITIES,
    OPTION_CONFIG_BACKUP_ENABLED,
    Capability,
    DeployedAclObservation,
    GuardedAction,
    WriteAuthorization,
    binding_checksum,
    utcnow,
)

if TYPE_CHECKING:
    from .api import OpenWrtAPI

_LOGGER = logging.getLogger(__name__)

ACL_FILE_PATH = "/usr/share/rpcd/acl.d/ha-openwrt-router.json"

# Bump whenever RPCD_ACL_CONTENT below changes. Used only for log messages —
# staleness is detected by comparing the deployed file's actual content to
# RPCD_ACL_CONTENT, not by this number.
#
# v8: rpcd 2026.10.04 (file.c: realpath() re-check; verified on that build,
# older 2026 builds not checked, 2025.12.03 unaffected) verifies a file ACL
# against the requested path AND its resolved target. /proc/net/* resolves to
# /proc/<pid>/net/*, /sys/class/net/<if>/... to /sys/devices/.../net/<if>/...
# and /var/run to /tmp/run, so without the resolved patterns every such read
# was denied (bridge FDB and ARP fell back to SSH on every poll). Older rpcd
# only checks the requested path; both forms stay granted.
ACL_VERSION = 8

# Marker echoed by the SSH deploy command — _run_ssh() returns None for empty
# stdout even on exit code 0, so success must be detectable from stdout alone.
_SSH_DEPLOY_MARKER = "HA_ACL_DEPLOYED"


class AclDeployError(Exception):
    """Raised when the rpcd ACL could not be deployed by any available path."""

    def __init__(self, reason: str, message: str) -> None:
        """reason: "write_blocked" | "ssh_failed" | "unreachable"."""
        super().__init__(message)
        self.reason = reason


RPCD_ACL_CONTENT: dict = {
    "root": {
        "description": "Full access for Home Assistant openwrt_router integration",
        "read": {
            "file": {
                # rpcd's file object enforces read access per PATH (stat/list are
                # broad, read is not). These are exactly the read-only system
                # paths the integration reads via ubus file/read — without them
                # every read falls back to SSH. No secrets, no broad "/*".
                "/etc/openwrt_release": ["read"],
                "/etc/config/ddns": ["read"],
                "/var/run/ddns": ["list"],
                "/var/run/ddns/*": ["read"],
                # /var -> /tmp on OpenWrt: the resolved path for rpcd >= 2026 (v8).
                "/tmp/run/ddns": ["list"],
                "/tmp/run/ddns/*": ["read"],
                # file/list on the directory itself needs "list" on the exact
                # path — the /sys/class/net/* glob below does not cover it.
                "/sys/class/net": ["list"],
                "/sys/class/net/*": ["read"],  # brforward, statistics/*, brport/port_no
                # /sys/class/net/<if> is a symlink into /sys/devices/...; rpcd
                # >= 2026 re-checks the resolved path (v8). Read-only sysfs.
                "/sys/devices/*/net/*": ["read"],
                # Core count to normalise the load average per core (v7),
                # read once per setup — see OpenWrtAPI._get_cpu_cores.
                "/proc/cpuinfo": ["read"],
                "/proc/net/arp": ["read"],
                "/proc/net/nf_conntrack": ["read"],
                # /proc/net -> /proc/self/net -> /proc/<pid>/net (v8, see above).
                "/proc/*/net/arp": ["read"],
                "/proc/*/net/nf_conntrack": ["read"],
                "/proc/sys/net/netfilter/nf_conntrack_count": ["read"],
                "/tmp/opkg_list": ["read"],
                # Let ensure_acl() verify the deployed ACL via ubus on every
                # start — without this the staleness check needs SSH forever.
                # Deliberately read-only: file/write on acl.d would let any
                # rpcd HTTP session widen its own permissions.
                ACL_FILE_PATH: ["read"],
            },
            "ubus": {
                "file": ["read", "stat", "list", "exec"],
                "hostapd.*": ["get_clients", "get_status"],
                "network.wireless": ["status", "up", "down"],
                "network.device": ["status"],
                "network.interface": ["dump"],
                "network.interface.*": ["status", "statistics"],
                "network.interface.wan": ["status", "statistics"],
                "luci-rpc": [
                    "getDHCPLeases",
                    "getHostHints",
                    "getWirelessDevices",
                ],
                "iwinfo": [
                    "info",
                    "assoclist",
                    "devices",
                    "scan",
                    "freqlist",
                ],
                "system": ["board", "info"],
                "uci": ["get"],
                "rc": ["list"],
                "service": ["list", "get_data"],
                # logd ring buffer, polled every 2nd cycle for Wi-Fi/DHCP
                # events (log_parser.py). Read only, no stream.
                "log": ["read"],
                # usteer's per-client signal map across APs (sticky clients).
                "usteer": ["get_clients"],
            },
        },
        "write": {
            "file": {
                # rpcd restart after an ACL (re)deploy — file/exec enforces
                # per-command, so only exactly this init script is allowed.
                "/etc/init.d/rpcd": ["exec"],
            },
            "ubus": {
                "network.wireless": ["up", "down"],
                # "Reload Wi-Fi" button and the Wi-Fi switches (v7): netifd
                # re-applies network/wireless config. Only reload, no restart.
                "network": ["reload"],
            },
        },
    }
}


@dataclass(frozen=True, slots=True)
class AclEnsureOutcome:
    """What one ensure run saw and did (1.44.0; for the core's rf.* view).

    ``reason``: ``current`` (v8 already there), ``tiered_kept`` (an approved
    tiered ACL, left alone), ``transient`` (read failed on a network blip,
    nothing written), or the redeploy reason ``missing`` / ``outdated`` /
    ``corrupted`` / ``unverifiable`` with ``written`` True.
    ``deployed`` is the parsed file content after the run when known
    (``known``), else None.
    """

    written: bool
    reason: str
    known: bool
    deployed: Any = None


async def ensure_acl(api: OpenWrtAPI) -> bool:
    """Ensure the rpcd ACL on the router exists AND matches the current content.

    Runs on first install AND on every startup/update (called from
    ``async_setup_entry``).  Unlike a pure existence check, this reads the
    deployed file back and compares it to ``RPCD_ACL_CONTENT`` — so an ACL that
    was widened by an integration update (new ubus methods) is re-written on the
    next start instead of silently staying stale.

    Deploys via the ubus file API (file/read + file/write + file/exec); when the
    router blocks ubus file/write, an SSH fallback with the same credentials is
    attempted (see :func:`_deploy_acl_ssh`).

    Args:
        api: Authenticated OpenWrtAPI instance.

    Returns:
        True if the ACL was (re)written (caller should refresh the coordinator).
        False if it was already current or present-but-unverifiable (nothing to do).

    Raises:
        AclDeployError: A deploy was needed but failed on every available path.
            ``async_setup_entry`` catches this (best-effort at startup); the
            config flow surfaces it to the user.
    """
    return (await ensure_acl_outcome(api)).written


async def ensure_acl_outcome(
    api: OpenWrtAPI, *, respect_offer: bool = False
) -> AclEnsureOutcome:
    """:func:`ensure_acl` with the outcome; ONE ``file/read`` either way.

    ``respect_offer``: a deployed tiered ACL (an approved offer) is left
    alone instead of being replaced with v8. That decision uses the content
    of the same read, so it adds no router call: with no tiered ACL on the
    router the calls and bytes are exactly those of :func:`ensure_acl`.
    """
    # Read the currently deployed ACL and decide whether a (re)deploy is needed.
    # file/read returns {"data": "<content>"} on success and raises
    # OpenWrtMethodNotFoundError when the file is missing (ubus NOT_FOUND = 4)
    # OR when the ACL blocks file/read on this path (converted in _call after
    # the confirming re-login) — both cases proceed to a deploy attempt.
    try:
        current = await api._call("file", "read", {"path": ACL_FILE_PATH})
        current_str = current.get("data") if isinstance(current, dict) else current
        try:
            parsed = json.loads(current_str) if isinstance(current_str, str) else None
            if isinstance(current_str, str) and parsed == RPCD_ACL_CONTENT:
                _LOGGER.debug(
                    "rpcd ACL on %s is up to date (v%s) — nothing to do",
                    api._host,
                    ACL_VERSION,
                )
                return AclEnsureOutcome(False, "current", True, parsed)
            if respect_offer and parse_tiered_acl(parsed) is not None:
                _LOGGER.debug(
                    "Tiered ACL on %s (%s) — left alone, changes only via an "
                    "approved offer",
                    api._host,
                    classify_deployed_acl(parsed).value,
                )
                return AclEnsureOutcome(False, "tiered_kept", True, parsed)
            reason = "outdated"  # content differs from what this version expects
        except (ValueError, TypeError, RecursionError):
            # present but not valid JSON (RecursionError: hostile nesting,
            # 1.44.0 hardening; before it escaped from ensure_acl)
            reason = "corrupted"
    except OpenWrtMethodNotFoundError:
        reason = "missing"  # file does not exist yet (first install)
    except (
        OpenWrtAuthError,
        OpenWrtResponseError,
        OpenWrtConnectionError,
        OpenWrtTimeoutError,
    ) as err:
        # file/read blocked by ACL or file module unavailable. Fall back to a
        # cheap existence probe to distinguish "missing" from "present but
        # unreadable".
        _LOGGER.debug(
            "Cannot read ACL on %s via file/read (%s) — probing existence",
            api._host,
            err,
        )
        try:
            await api._call("file", "stat", {"path": ACL_FILE_PATH})
        except OpenWrtMethodNotFoundError:
            reason = "missing"
        except (
            OpenWrtAuthError,
            OpenWrtResponseError,
            OpenWrtConnectionError,
            OpenWrtTimeoutError,
        ):
            reason = "unverifiable"
        else:
            if isinstance(err, (OpenWrtConnectionError, OpenWrtTimeoutError)):
                # Transient read failure while the file demonstrably exists —
                # do not rewrite the ACL (and restart rpcd) on a network blip.
                _LOGGER.debug(
                    "rpcd ACL exists on %s, file/read failed transiently (%s) "
                    "— leaving as-is",
                    api._host,
                    err,
                )
                return AclEnsureOutcome(False, "transient", False)
            # The file exists but reading it is permission-denied. Every ACL
            # shipped since v5 grants file/read on its own path, so a deployed
            # ACL we cannot read back is by definition older than what this
            # version ships. Leaving it "as-is" (as ≤v1.26.3 did) kept such
            # routers in the SSH fallback — with its recurring HA notification
            # and 300s polling — forever.
            reason = "outdated"

    await _deploy_acl(api, reason)
    return AclEnsureOutcome(True, reason, True, RPCD_ACL_CONTENT)


async def _deploy_acl(api: OpenWrtAPI, reason: str) -> bool:
    """Write the ACL via ubus file/write (SSH fallback) and restart rpcd.

    On a rejected ubus file/write — the chicken-and-egg case where deploying
    the ACL requires exactly the file permissions the ACL would grant — the
    SSH fallback writes the file with the same credentials instead.

    Args:
        api: Authenticated OpenWrtAPI instance.
        reason: Why we are (re)deploying ("missing" / "outdated" / ...), logged.

    Returns:
        True once the ACL file was written (via ubus or SSH).

    Raises:
        AclDeployError: Neither ubus file/write nor the SSH fallback succeeded.
    """
    acl_json = json.dumps(RPCD_ACL_CONTENT, indent=2)
    try:
        await api._call("file", "write", {"path": ACL_FILE_PATH, "data": acl_json})
        _LOGGER.info(
            "Deployed rpcd ACL v%s to %s:%s (%s)",
            ACL_VERSION,
            api._host,
            ACL_FILE_PATH,
            reason,
        )
    except (OpenWrtConnectionError, OpenWrtTimeoutError) as err:
        raise AclDeployError(
            "unreachable", f"router unreachable during ACL deploy: {err}"
        ) from err
    except (OpenWrtAuthError, OpenWrtResponseError, OpenWrtMethodNotFoundError) as err:
        # Permission-shaped rejection: an ACL-blocked file/write surfaces as
        # OpenWrtMethodNotFoundError (converted in _call after the confirming
        # re-login); a router without the rpcd file module looks the same.
        # Either way the ubus path is unusable — try SSH.
        _LOGGER.debug(
            "ubus file/write rejected on %s (%s) — trying SSH fallback", api._host, err
        )
        if await _deploy_acl_ssh(api, reason):
            return True
        _LOGGER.warning(
            "Cannot deploy ACL (%s) to %s via ubus file/write (%s) or SSH. "
            "Deploy it manually: scp ha-openwrt-router.json root@%s:%s",
            reason,
            api._host,
            err,
            api._host,
            ACL_FILE_PATH,
        )
        raise AclDeployError(
            "write_blocked", f"ubus file/write rejected and SSH fallback failed: {err}"
        ) from err

    # Restart rpcd so it reloads the ACL directory. Non-fatal on failure —
    # rpcd applies the file on its next restart/reload anyway.
    try:
        await api._call(
            "file",
            "exec",
            {"command": "/etc/init.d/rpcd", "params": ["restart"]},
        )
        _LOGGER.debug("Restarted rpcd on %s", api._host)
    except (
        OpenWrtAuthError,
        OpenWrtResponseError,
        OpenWrtMethodNotFoundError,
        OpenWrtConnectionError,
        OpenWrtTimeoutError,
    ) as err:
        _LOGGER.debug(
            "Could not restart rpcd on %s (non-fatal, ACL active after next restart): %s",
            api._host,
            err,
        )

    return True


async def _deploy_acl_ssh(api: OpenWrtAPI, reason: str) -> bool:
    """Write the ACL file via SSH when ubus file/write is blocked.

    Uses the integration's existing SSH machinery (asyncssh — the password
    never leaves the process). One remote command writes the file, echoes a
    success marker and restarts rpcd; the marker is mandatory because
    ``_run_ssh`` returns None for empty stdout even on exit code 0.

    Returns:
        True only when the marker was seen in stdout (file written and rpcd
        restart triggered on the router).
    """
    acl_json = json.dumps(RPCD_ACL_CONTENT, indent=2)
    remote_cmd = (
        f"printf '%s' {shlex.quote(acl_json)} > {ACL_FILE_PATH} "
        f"&& echo {_SSH_DEPLOY_MARKER} "
        f"&& /etc/init.d/rpcd restart >/dev/null 2>&1"
    )
    out = await api._run_ssh(remote_cmd, timeout=15.0)
    if out and _SSH_DEPLOY_MARKER in out:
        _LOGGER.info(
            "Deployed rpcd ACL v%s to %s:%s via SSH fallback (%s), rpcd restarted",
            ACL_VERSION,
            api._host,
            ACL_FILE_PATH,
            reason,
        )
        return True
    _LOGGER.debug(
        "SSH fallback deploy on %s did not confirm success (stdout=%r)",
        api._host,
        out,
    )
    return False


async def check_and_deploy_acl(api: OpenWrtAPI) -> bool:
    """Backwards-compatible alias for :func:`ensure_acl`.

    Retained so the config_flow "deploy_acl" repair action and any external
    callers keep working unchanged. Prefer ``ensure_acl`` in new code.
    Like ``ensure_acl`` it raises :class:`AclDeployError` when a needed deploy
    fails on every path.
    """
    return await ensure_acl(api)


# =====================================================================
# Tiered ACL (next ACL version) — OFFERED ONLY, never deployed automatically
# =====================================================================
#
# Everything above this line is the automatic path (ensure_acl, ACL v8) and
# is unchanged. Everything below builds an *offer*: a base tier plus tiers
# the user picks per router. Pure helpers (build_acl, acl_checksum,
# describe_offer, ...) never touch a router. The single writing function,
# async_deploy_acl_offer, refuses unless it is handed a WriteAuthorization
# for action ``acl_deploy`` bound to this router and to the checksum of
# exactly the ACL it is about to write (docs/dev/acl-tiers.md).
#
# One file, one write and at most one rpcd restart per router for all tiers
# together: that is the reason for the tier model.

TIERED_ACL_VERSION: Final = 9

# Backups of the replaced ACL live next to acl.d, not in it: rpcd loads
# acl.d/*.json, so a backup inside acl.d with a .json suffix would be active.
ACL_BACKUP_PREFIX: Final = "/usr/share/rpcd/ha-openwrt-router.json.bak-"
# SSH path writes to this temp name first and renames it (no half-written
# ACL file if the connection drops). Not *.json, so rpcd never loads it.
_ACL_TMP_PATH: Final = ACL_FILE_PATH + ".new"
_RPCD_RESTART_CMD: Final = "/etc/init.d/rpcd restart"
_SSH_OFFER_BACKUP_MARKER: Final = "HA_ACL_BACKED_UP"
_SSH_OFFER_DEPLOY_MARKER: Final = "HA_ACL_OFFER_DEPLOYED"

# The group description carries a machine-readable marker so the deployed
# file can be recognised as a tiered ACL (rpcd ignores "description").
TIERED_ACL_DESCRIPTION_PREFIX: Final = (
    "Home Assistant openwrt_router integration, tiered ACL"
)
_TIERED_MARKER_RE: Final = re.compile(
    r"tiered ACL v(?P<version>\d{1,6}); tiers: (?P<tiers>[a-z0-9_]+(?:,[a-z0-9_]+)*)$"
)
# A deployed ACL text above this size is not parsed (hostile file; the
# shipped ACLs are a few kB). Parsing also stops on deep nesting.
MAX_ACL_TEXT_BYTES: Final = 64 * 1024

TIER_READ: Final = "read"
TIER_CONFIG_BACKUP_READ: Final = "config_backup_read"
TIER_RF_SURVEY: Final = "rf_survey"
TIER_RF_SCAN: Final = "rf_scan"

# Capability names served by the RF tiers (module prefix "rf.", owned by
# the WiFi RF module; listed here so the offer can name them).
CAPABILITY_RF_TXPOWERLIST: Final = "rf.txpowerlist"
CAPABILITY_RF_SURVEY: Final = "rf.survey"
CAPABILITY_RF_SCAN: Final = "rf.scan"

ACL_SECTIONS: Final = ("read", "write")
# Scopes whose value is {object: [methods]}; every other scope is a list of
# objects (rpcd grants function = section name, e.g. "cgi-io": ["backup"]).
_MAPPED_SCOPES: Final = frozenset({"ubus", "file"})
_TIER_ID_RE: Final = re.compile(r"[a-z][a-z0-9_]*")

# The UCI configs the Configuration Manager snapshots (config-manager plan
# 2.2, contract section 18). Read access includes every secret in them.
CONFIG_BACKUP_UCI_CONFIGS: Final = (
    "network",
    "wireless",
    "firewall",
    "dhcp",
    "system",
    "dropbear",
    "uhttpd",
    "rpcd",
    "ddns",
    "sqm",
    "usteer",
    "mwan3",
    "upnpd",
    "openvpn",
)


class AclTierError(ValueError):
    """Unknown tier, invalid tier definition or tier not allowed by options."""


class AclOfferRefusedError(AuthorizationError):
    """async_deploy_acl_offer refused before anything was written.

    ``reason`` (also ``details["reason"]``): ``no_authorization``,
    ``option_disabled``, ``not_consumed``, ``action_mismatch``,
    ``router_mismatch``, ``checksum_mismatch``, ``consume_failed`` or the
    guard's own reason (``already_used``, ``expired``,
    ``unknown_authorization``, ...).
    """

    code = "acl_offer_refused"

    def __init__(self, reason: str, message: str, *, router_id: str | None) -> None:
        """Remember the machine-readable reason."""
        super().__init__(message, router_id=router_id, details={"reason": reason})
        self.reason = reason


class AclOfferDeployError(AclDeployError):
    """An authorized offer deploy failed on the router.

    ``reason``: ``unreachable`` | ``write_blocked``.
    ``written`` is False when the ACL file was certainly not replaced, None
    when that is unknown (connection lost during the write).
    ``rollback_command`` is set whenever a backup was taken.
    """

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        written: bool | None = False,
        backup_path: str | None = None,
        rollback_command: str | None = None,
    ) -> None:
        """Remember what happened on the router."""
        super().__init__(reason, message)
        self.written = written
        self.backup_path = backup_path
        self.rollback_command = rollback_command


@dataclass(frozen=True, order=True, slots=True)
class AclRight:
    """One rpcd right: section, scope, object and (mapped scopes) method.

    Examples: ``AclRight("read", "ubus", "iwinfo", "scan")``,
    ``AclRight("read", "file", "/proc/cpuinfo", "read")``,
    ``AclRight("read", "cgi-io", "backup")``, ``AclRight("read", "uci", "network")``.
    """

    section: str
    scope: str
    object: str
    method: str = ""

    def __post_init__(self) -> None:
        """Reject malformed rights early (the ACL is built from them)."""
        if self.section not in ACL_SECTIONS:
            raise AclTierError(f"invalid ACL section {self.section!r}")
        if not self.scope or not self.object:
            raise AclTierError("ACL right needs scope and object")
        if (self.scope in _MAPPED_SCOPES) != bool(self.method):
            raise AclTierError(
                f"scope {self.scope!r}: method is "
                + ("required" if self.scope in _MAPPED_SCOPES else "not allowed")
            )

    @property
    def permission(self) -> str:
        """Permission string as CapabilityStatus.required_permissions uses it."""
        if self.scope == "ubus":
            return f"ubus:{self.object}.{self.method}"
        if self.scope == "file":
            return f"file:{self.object}:{self.method}"
        return f"{self.scope}:{self.object}"

    def describe(self) -> str:
        """One line for the UI, e.g. ``read ubus:iwinfo.scan``."""
        return f"{self.section} {self.permission}"


def rights_from_acl(acl: Mapping[str, Any] | None) -> frozenset[AclRight]:
    """Flatten an rpcd ACL file (all groups) into a set of rights.

    Unknown shapes are skipped, never guessed: a non-table group, section or
    scope value contributes nothing.
    """
    rights: set[AclRight] = set()
    if not isinstance(acl, Mapping):
        return frozenset()
    for group in acl.values():
        if not isinstance(group, Mapping):
            continue
        for section in ACL_SECTIONS:
            scopes = group.get(section)
            if not isinstance(scopes, Mapping):
                continue
            for scope, value in scopes.items():
                if scope in _MAPPED_SCOPES and isinstance(value, Mapping):
                    for obj, methods in value.items():
                        if isinstance(methods, list):
                            rights.update(
                                AclRight(section, scope, str(obj), str(m))
                                for m in methods
                                if isinstance(m, str) and m
                            )
                elif scope not in _MAPPED_SCOPES and isinstance(value, list):
                    rights.update(
                        AclRight(section, scope, str(obj))
                        for obj in value
                        if isinstance(obj, str) and obj
                    )
    return frozenset(rights)


def _sections_from_rights(rights: Iterable[AclRight]) -> dict[str, Any]:
    """Deterministic {section: {scope: ...}} tree, everything sorted."""
    tree: dict[str, dict[str, Any]] = {}
    for right in sorted(set(rights)):
        scopes = tree.setdefault(right.section, {})
        if right.scope in _MAPPED_SCOPES:
            objects = scopes.setdefault(right.scope, {})
            objects.setdefault(right.object, []).append(right.method)
        else:
            scopes.setdefault(right.scope, []).append(right.object)
    return {section: tree[section] for section in ACL_SECTIONS if section in tree}


@dataclass(frozen=True, kw_only=True, slots=True)
class AclTier:
    """One selectable block of rights and the capabilities it serves.

    ``option``: options-flow key that must be on before the tier may be
    offered or deployed (``config_backup_enabled`` for the config tier).
    ``mandatory``: part of every offer (only the base read tier).
    """

    tier_id: str
    title: str
    capabilities: tuple[str, ...]
    rights: frozenset[AclRight]
    risk: str
    module: str = "core"
    mandatory: bool = False
    option: str | None = None

    def __post_init__(self) -> None:
        """Validate id, rights and capability names."""
        if not _TIER_ID_RE.fullmatch(self.tier_id):
            raise AclTierError(f"invalid tier id {self.tier_id!r}")
        if not self.rights:
            raise AclTierError(f"tier {self.tier_id} adds no rights")
        if not self.title or not self.risk:
            raise AclTierError(f"tier {self.tier_id} needs title and risk note")
        for cap in self.capabilities:
            if "." not in cap:
                raise AclTierError(f"capability {cap!r} has no namespace")

    @property
    def permissions(self) -> tuple[str, ...]:
        """Sorted permission strings of this tier."""
        return tuple(sorted({r.permission for r in self.rights}))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for the UI."""
        return {
            "tier_id": self.tier_id,
            "title": self.title,
            "module": self.module,
            "mandatory": self.mandatory,
            "option": self.option,
            "capabilities": list(self.capabilities),
            "rights": [r.describe() for r in sorted(self.rights)],
            "risk": self.risk,
        }


# Optional tiers (everything but the base) may only grant rights from this
# ALLOWLIST (security review 2026-11-18, finding 1). rpcd matches ACL
# entries with fnmatch, so a denylist cannot be complete: ``fil?``, ``f*``,
# ``*`` or ``[w]rite`` grant what a denylist forbids by name. Keys are exact
# (scope, object, method) triples; method "" for list scopes (uci, cgi-io).
# The union of what the built-in optional tiers need:
OPTIONAL_TIER_ALLOWLIST: Final[frozenset[tuple[str, str, str]]] = frozenset(
    {
        ("cgi-io", "backup", ""),
        ("ubus", "rpc-sys", "packagelist"),
        *(("uci", config, "") for config in CONFIG_BACKUP_UCI_CONFIGS),
        ("ubus", "iwinfo", "survey"),
        ("ubus", "iwinfo", "scan"),
    }
)
# Reviewed extensions for later modules (security-center, net-diagnostics).
# A module that needs a new right adds the exact triple HERE, in a reviewed
# change, with a comment why it is read-only. Empty on purpose.
OPTIONAL_TIER_EXTENSIONS: Final[frozenset[tuple[str, str, str]]] = frozenset()
# File rights of optional tiers: "read" only, on a normalised absolute path
# below one of these prefixes (read-only kernel views, no secrets).
OPTIONAL_TIER_FILE_READ_PREFIXES: Final = (
    "/proc/net/",
    "/sys/class/net/",
    "/sys/class/ieee80211/",
)
# fnmatch/glob characters (and the escape) are never accepted in an
# optional right: rpcd would expand them.
_PATTERN_CHARS: Final = frozenset("*?[]{}\\")  # incl. the backslash escape


class AclTierRightRefusedError(AclTierError):
    """A tier carries a right the registry does not accept.

    ``right`` is the refused :class:`AclRight`, ``reason`` the machine code
    (``write_section``, ``pattern``, ``not_allowlisted``, ``file_method``,
    ``file_path``, ``base_tier_fixed``).
    """

    def __init__(self, tier_id: str, right: AclRight | None, reason: str, why: str):
        """Name the tier, the right and why."""
        named = right.describe() if right is not None else "base tier rights"
        super().__init__(f"tier {tier_id}: {named} refused ({reason}: {why})")
        self.tier_id = tier_id
        self.right = right
        self.reason = reason


def _optional_allowlist() -> frozenset[tuple[str, str, str]]:
    return OPTIONAL_TIER_ALLOWLIST | OPTIONAL_TIER_EXTENSIONS


def _forbidden_optional_right(right: AclRight) -> tuple[str, str] | None:
    """(reason, explanation) if an optional tier may not carry ``right``.

    Allowlist, not denylist: read section only; no pattern characters in
    object or method; ubus and every non-file scope only as an exact
    triple of :data:`OPTIONAL_TIER_ALLOWLIST` /
    :data:`OPTIONAL_TIER_EXTENSIONS`; files only ``read`` on a normalised
    path below :data:`OPTIONAL_TIER_FILE_READ_PREFIXES`.
    """
    if right.section != "read":
        return ("write_section", "optional tiers may only add read rights")
    if any(c in _PATTERN_CHARS for c in right.object + right.method):
        return ("pattern", "wildcards and pattern characters are never allowed")
    if right.scope == "file":
        if right.method != "read":
            return ("file_method", "optional file rights are read only")
        path = right.object
        if (
            not path.startswith("/")
            or posixpath.normpath(path) != path
            or not path.startswith(OPTIONAL_TIER_FILE_READ_PREFIXES)
        ):
            return (
                "file_path",
                "file reads only below "
                + ", ".join(OPTIONAL_TIER_FILE_READ_PREFIXES)
                + " with a normalised path",
            )
        return None
    if (right.scope, right.object, right.method) not in _optional_allowlist():
        return (
            "not_allowlisted",
            "not in OPTIONAL_TIER_ALLOWLIST / OPTIONAL_TIER_EXTENSIONS",
        )
    return None


class AclTierRegistry:
    """Ordered registry of tier definitions (not an if-chain).

    The core registers its tiers at import; later modules (security-center,
    net-diagnostics) call :meth:`register` with their own tier. Order of
    registration is the canonical order of tiers in an offer.
    """

    def __init__(self, tiers: Iterable[AclTier] = ()) -> None:
        """Start with ``tiers`` (validated like :meth:`register`)."""
        self._tiers: dict[str, AclTier] = {}
        for tier in tiers:
            self.register(tier)

    def register(self, tier: AclTier) -> None:
        """Add a tier; refuse duplicates, a second base tier and unsafe rights.

        The base (mandatory) tier is fixed: only the built-in rights derived
        from ACL v8 are accepted, so it cannot be used to widen the ACL.
        Optional tiers pass the allowlist (:func:`_forbidden_optional_right`);
        a refusal raises :class:`AclTierRightRefusedError` naming the right.
        """
        if tier.tier_id in self._tiers:
            raise AclTierError(f"tier {tier.tier_id} already registered")
        if tier.mandatory and any(t.mandatory for t in self._tiers.values()):
            raise AclTierError("only one mandatory (base) tier is allowed")
        if tier.mandatory:
            if tier.rights != _base_read_rights():
                extra = sorted(tier.rights - _base_read_rights())
                raise AclTierRightRefusedError(
                    tier.tier_id,
                    extra[0] if extra else None,
                    "base_tier_fixed",
                    "the base tier is derived from ACL v8 and cannot be changed",
                )
        else:
            for right in sorted(tier.rights):
                refused = _forbidden_optional_right(right)
                if refused:
                    _LOGGER.warning(
                        "ACL tier %s refused: %s (%s)",
                        tier.tier_id,
                        right.describe(),
                        refused[0],
                    )
                    raise AclTierRightRefusedError(tier.tier_id, right, *refused)
        self._tiers[tier.tier_id] = tier

    def get(self, tier_id: str) -> AclTier:
        """Tier by id or AclTierError."""
        try:
            return self._tiers[tier_id]
        except KeyError:
            raise AclTierError(f"unknown ACL tier {tier_id!r}") from None

    def tiers(self) -> tuple[AclTier, ...]:
        """All tiers in canonical order."""
        return tuple(self._tiers.values())

    def normalize(self, tier_ids: Iterable[str]) -> tuple[str, ...]:
        """Selected ids + mandatory ones, deduplicated, canonical order."""
        if isinstance(tier_ids, str):
            raise AclTierError("tiers must be an iterable of ids, not a string")
        wanted = set()
        for tier_id in tier_ids:
            self.get(tier_id)  # raises for unknown ids
            wanted.add(tier_id)
        return tuple(
            t.tier_id
            for t in self._tiers.values()
            if t.mandatory or t.tier_id in wanted
        )

    def offerable(self, options: Mapping[str, Any] | None) -> tuple[AclTier, ...]:
        """Tiers the UI may offer under the given entry options."""
        opts = options or {}
        return tuple(
            t
            for t in self._tiers.values()
            if t.option is None or bool(opts.get(t.option))
        )

    def check_options(
        self, tier_ids: Iterable[str], options: Mapping[str, Any] | None
    ) -> None:
        """Raise AclTierError if a selected tier is gated by an option that is off."""
        opts = options or {}
        for tier_id in self.normalize(tier_ids):
            tier = self._tiers[tier_id]
            if tier.option is not None and not bool(opts.get(tier.option)):
                raise AclTierError(
                    f"tier {tier_id} needs option {tier.option} to be enabled"
                )

    def capability_tiers(self) -> dict[str, str]:
        """Capability name -> id of the tier that serves it."""
        return {
            cap: tier.tier_id
            for tier in self._tiers.values()
            for cap in tier.capabilities
        }


# Today's (v8) read rights minus the radio scan, plus txpowerlist. Derived
# from RPCD_ACL_CONTENT so the base tier can never drift from what the
# integration reads; tests pin the exact difference to v8.
_SCAN_RIGHT: Final = AclRight("read", "ubus", "iwinfo", "scan")
_TXPOWERLIST_RIGHT: Final = AclRight("read", "ubus", "iwinfo", "txpowerlist")


def _base_read_rights() -> frozenset[AclRight]:
    return (rights_from_acl(RPCD_ACL_CONTENT) - {_SCAN_RIGHT}) | {_TXPOWERLIST_RIGHT}


def _default_tiers() -> tuple[AclTier, ...]:
    return (
        AclTier(
            tier_id=TIER_READ,
            title="Base: everything the integration reads today, without radio scan",
            capabilities=(
                Capability.DATA_SYSTEM_BOARD.value,
                Capability.DATA_WIRELESS.value,
                Capability.DATA_HOSTAPD_CLIENTS.value,
                Capability.DATA_DHCP_LEASES.value,
                Capability.DATA_LOGS.value,
                Capability.DATA_IWINFO.value,
                Capability.DATA_SERVICES.value,
                Capability.DATA_UCI.value,
                CAPABILITY_RF_TXPOWERLIST,
            ),
            rights=_base_read_rights(),
            risk=(
                "Same rights as ACL v8 (including its existing Wi-Fi on/off, "
                "network reload and rpcd restart rights) minus iwinfo scan, plus "
                "the read-only iwinfo txpowerlist. No access to secrets."
            ),
            mandatory=True,
        ),
        AclTier(
            tier_id=TIER_CONFIG_BACKUP_READ,
            title="Configuration backup (read)",
            capabilities=(
                Capability.CONFIG_CGI_BACKUP.value,
                Capability.CONFIG_UCI_READ.value,
                Capability.CONFIG_PACKAGELIST.value,
            ),
            rights=frozenset(
                {
                    AclRight("read", "cgi-io", "backup"),
                    AclRight("read", "ubus", "rpc-sys", "packagelist"),
                    *(AclRight("read", "uci", c) for c in CONFIG_BACKUP_UCI_CONFIGS),
                }
            ),
            risk=(
                "Gives the Home Assistant rpcd user READ ACCESS TO ALL ROUTER "
                "SECRETS: the backup archive contains /etc/shadow (password hashes "
                "of every router login, including root) and private keys (SSH host "
                "keys, VPN and TLS keys), plus Wi-Fi keys; the UCI configs contain "
                "Wi-Fi, VPN and DDNS passwords. Anyone who can use this HA rpcd "
                "login can read them."
            ),
            option=OPTION_CONFIG_BACKUP_ENABLED,
        ),
        AclTier(
            tier_id=TIER_RF_SURVEY,
            title="Wi-Fi channel survey",
            capabilities=(CAPABILITY_RF_SURVEY,),
            rights=frozenset({AclRight("read", "ubus", "iwinfo", "survey")}),
            risk=(
                "Read-only channel statistics from the driver (busy/noise per "
                "channel). Does not change the channel. Not measured on the "
                "user's hardware yet."
            ),
            module="wifi_rf",
        ),
        AclTier(
            tier_id=TIER_RF_SCAN,
            title="Wi-Fi neighbour scan",
            capabilities=(CAPABILITY_RF_SCAN,),
            rights=frozenset({_SCAN_RIGHT}),
            risk=(
                "A scan can take the radio off its channel for a moment (clients "
                "may see a short gap) and blocks rpcd while it runs. Only for "
                "on-demand use, never in the poll."
            ),
            module="wifi_rf",
        ),
    )


DEFAULT_TIER_REGISTRY: Final = AclTierRegistry(_default_tiers())


def _tiered_description(tier_ids: Iterable[str]) -> str:
    return (
        f"{TIERED_ACL_DESCRIPTION_PREFIX} v{TIERED_ACL_VERSION}; "
        f"tiers: {','.join(tier_ids)}"
    )


def build_acl(
    tiers: Iterable[str], *, registry: AclTierRegistry = DEFAULT_TIER_REGISTRY
) -> dict[str, Any]:
    """Build the tiered ACL for the selected tiers (base tier always included).

    Deterministic: the same set of tiers gives the same dict in any order.
    Pure — no router access.
    """
    tier_ids = registry.normalize(tiers)
    rights: set[AclRight] = set()
    for tier_id in tier_ids:
        rights |= registry.get(tier_id).rights
    group: dict[str, Any] = {"description": _tiered_description(tier_ids)}
    group.update(_sections_from_rights(rights))
    return {"root": group}


def render_acl(acl: Mapping[str, Any]) -> str:
    """Exact text written to the router (sorted keys, 2-space indent)."""
    return json.dumps(acl, indent=2, sort_keys=True, ensure_ascii=True)


def acl_checksum(acl: Mapping[str, Any]) -> str:
    """sha256 hex of :func:`render_acl` — of exactly the bytes written."""
    return hashlib.sha256(render_acl(acl).encode("utf-8")).hexdigest()


def acl_binding_checksum(router_id: str, acl: Mapping[str, Any]) -> str:
    """Checksum an ``acl_deploy`` approval is bound to (contract 6.3)."""
    return binding_checksum(router_id, acl_checksum(acl))


@dataclass(frozen=True, slots=True)
class TieredAclInfo:
    """Marker read back from a deployed tiered ACL."""

    version: int
    tiers: tuple[str, ...]


def parse_tiered_acl(acl: Any) -> TieredAclInfo | None:
    """Return the tier marker of a deployed ACL, or None if it is not tiered."""
    if not isinstance(acl, Mapping):
        return None
    group = acl.get("root")
    if not isinstance(group, Mapping):
        return None
    description = group.get("description")
    if not isinstance(description, str) or not description.startswith(
        TIERED_ACL_DESCRIPTION_PREFIX
    ):
        return None
    match = _TIERED_MARKER_RE.search(description)
    if match is None:
        return None
    return TieredAclInfo(
        version=int(match.group("version")),
        tiers=tuple(match.group("tiers").split(",")),
    )


def parse_acl_text(text: str | None) -> tuple[Any, str | None]:
    """Parse a deployed ACL text defensively: (parsed, None) or (None, why).

    ``why``: ``missing`` (no text), ``too_large`` (above
    :data:`MAX_ACL_TEXT_BYTES`, not parsed), ``too_deep`` (nesting beyond
    the parser's recursion limit) or ``invalid_json``. Never raises.
    """
    if not isinstance(text, str):
        return None, "missing"
    if len(text.encode("utf-8", "surrogatepass")) > MAX_ACL_TEXT_BYTES:
        return None, "too_large"
    # Explicit depth check: whether json.loads raises RecursionError for deep
    # nesting depends on the platform and Python version, so do not rely on it.
    if _json_nesting_depth(text) > MAX_ACL_NESTING_DEPTH:
        return None, "too_deep"
    try:
        return json.loads(text), None
    except RecursionError:
        return None, "too_deep"
    except ValueError:
        return None, "invalid_json"


MAX_ACL_NESTING_DEPTH: Final = 32


def _json_nesting_depth(text: str) -> int:
    """Deepest bracket nesting in a JSON text, ignoring brackets in strings."""
    depth = deepest = 0
    in_string = escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "]}":
            depth -= 1
    return deepest


class DeployedAclKind(StrEnum):
    """What the ACL file on a router is, compared with this code."""

    MISSING = "missing"
    LEGACY_CURRENT = "legacy_current"  # exactly RPCD_ACL_CONTENT (v8)
    TIERED_CURRENT = "tiered_current"  # marker + equals build_acl(its tiers)
    TIERED_OTHER = "tiered_other"  # marker, but other version/content
    FOREIGN = "foreign"  # anything else (older legacy, hand-edited, broken)


def classify_deployed_acl(
    acl: Any, *, registry: AclTierRegistry = DEFAULT_TIER_REGISTRY
) -> DeployedAclKind:
    """Classify a parsed ACL file (None = missing). Pure."""
    if acl is None:
        return DeployedAclKind.MISSING
    if acl == RPCD_ACL_CONTENT:
        return DeployedAclKind.LEGACY_CURRENT
    info = parse_tiered_acl(acl)
    if info is None:
        return DeployedAclKind.FOREIGN
    if info.version == TIERED_ACL_VERSION:
        try:
            if build_acl(info.tiers, registry=registry) == acl:
                return DeployedAclKind.TIERED_CURRENT
        except AclTierError:
            pass
    return DeployedAclKind.TIERED_OTHER


def granted_capabilities(
    acl: Any, *, registry: AclTierRegistry = DEFAULT_TIER_REGISTRY
) -> dict[str, bool]:
    """Capability -> True if ``acl`` grants every right of the serving tier."""
    rights = rights_from_acl(acl)
    return {
        cap: registry.get(tier_id).rights <= rights
        for cap, tier_id in registry.capability_tiers().items()
    }


def missing_permissions(
    acl: Any, capability: str, *, registry: AclTierRegistry = DEFAULT_TIER_REGISTRY
) -> tuple[str, ...]:
    """Permission strings ``acl`` lacks for ``capability`` (for
    ``CapabilityStatus.required_permissions``); () if not tier-served."""
    tier_id = registry.capability_tiers().get(capability)
    if tier_id is None:
        return ()
    missing = registry.get(tier_id).rights - rights_from_acl(acl)
    return tuple(sorted({r.permission for r in missing}))


@dataclass(frozen=True, kw_only=True, slots=True)
class AclOffer:
    """What deploying the selected tiers would change (shown before approval)."""

    tiers: tuple[str, ...]
    acl_json: str = field(repr=False)
    acl_checksum: str
    added: tuple[AclRight, ...]
    removed: tuple[AclRight, ...]
    current_kind: DeployedAclKind
    risks: tuple[tuple[str, str], ...]
    # Every right of the proposed ACL (sorted) and per tier, so an admin
    # approves rights, not only a checksum (security review, finding 1).
    rights: tuple[AclRight, ...] = ()
    tier_rights: tuple[tuple[str, tuple[AclRight, ...]], ...] = ()

    @property
    def unchanged(self) -> bool:
        """True if the router would end up with exactly the same rights."""
        return not self.added and not self.removed

    @property
    def acl(self) -> dict[str, Any]:
        """The proposed ACL as a fresh dict."""
        return json.loads(self.acl_json)

    def binding_checksum(self, router_id: str) -> str:
        """Checksum to pass to ``guard.authorize(acl_deploy, ...)``."""
        return binding_checksum(router_id, self.acl_checksum)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for the UI."""
        return {
            "tiers": list(self.tiers),
            "acl_checksum": self.acl_checksum,
            "acl_version": TIERED_ACL_VERSION,
            "current_kind": self.current_kind.value,
            "added": [r.describe() for r in self.added],
            "removed": [r.describe() for r in self.removed],
            "unchanged": self.unchanged,
            "risks": [{"tier_id": t, "risk": r} for t, r in self.risks],
            "rights": [r.describe() for r in self.rights],
            "tier_rights": {
                t: [r.describe() for r in rs] for t, rs in self.tier_rights
            },
            "rights_text": self.rights_text(),
        }

    def rights_text(self) -> str:
        """Human-readable list of every right, grouped by tier (for approval)."""
        tiers = ", ".join(self.tiers)
        lines = [
            f"ACL v{TIERED_ACL_VERSION}, tiers {tiers}; {len(self.rights)} rights in total:"
        ]
        for tier_id, rights in self.tier_rights:
            lines.append(f"[{tier_id}]")
            lines.extend(f"  {r.describe()}" for r in rights)
        if self.added:
            lines.append("added compared with the router:")
            lines.extend(f"  + {r.describe()}" for r in self.added)
        if self.removed:
            lines.append("removed compared with the router:")
            lines.extend(f"  - {r.describe()}" for r in self.removed)
        return "\n".join(lines)


def describe_offer(
    current: Mapping[str, Any] | int | None,
    tiers: Iterable[str],
    *,
    options: Mapping[str, Any] | None = None,
    registry: AclTierRegistry = DEFAULT_TIER_REGISTRY,
) -> AclOffer:
    """Diff of rights between what is deployed and the offer. Pure.

    ``current``: the parsed ACL file read from the router, ``None`` if there
    is none, or ``ACL_VERSION`` (int) as shorthand for the shipped v8 file.
    ``options``: when given, a tier gated by an option that is off raises
    AclTierError (the UI should only offer ``registry.offerable(options)``).
    """
    if isinstance(current, bool) or (
        isinstance(current, int) and current != ACL_VERSION
    ):
        raise AclTierError(f"only ACL v{ACL_VERSION} can be named by version")
    current_acl: Any = RPCD_ACL_CONTENT if isinstance(current, int) else current
    tier_ids = registry.normalize(tiers)
    if options is not None:
        registry.check_options(tier_ids, options)
    proposed = build_acl(tier_ids, registry=registry)
    have = rights_from_acl(current_acl)
    want = rights_from_acl(proposed)
    return AclOffer(
        tiers=tier_ids,
        acl_json=render_acl(proposed),
        acl_checksum=acl_checksum(proposed),
        added=tuple(sorted(want - have)),
        removed=tuple(sorted(have - want)),
        current_kind=classify_deployed_acl(current_acl, registry=registry),
        risks=tuple((t, registry.get(t).risk) for t in tier_ids),
        rights=tuple(sorted(want)),
        tier_rights=tuple((t, tuple(sorted(registry.get(t).rights))) for t in tier_ids),
    )


class GuardConsume(Protocol):
    """``ActionGuardProtocol.consume`` (pass ``guard.consume``)."""

    def __call__(
        self,
        authorization: WriteAuthorization,
        *,
        action: str,
        router_id: str,
        checksum: str | None = None,
    ) -> None:
        """Check ledger/single use/expiry/binding or raise AuthorizationError."""


@dataclass(frozen=True, kw_only=True, slots=True)
class AclDeployResult:
    """Outcome of an authorized offer deploy — command and way back."""

    router_id: str
    tiers: tuple[str, ...]
    acl_checksum: str
    changed: bool
    transport: str  # "ubus" | "ssh" | "none" (unchanged)
    backup_path: str | None
    previous_checksum: str | None
    previous_content: str | None = field(repr=False)
    command: str | None
    rollback_command: str | None
    rpcd_restarted: bool
    applied_at: datetime

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form for the change log / audit."""
        return {
            "router_id": self.router_id,
            "tiers": list(self.tiers),
            "acl_checksum": self.acl_checksum,
            "changed": self.changed,
            "transport": self.transport,
            "backup_path": self.backup_path,
            "previous_checksum": self.previous_checksum,
            "command": self.command,
            "rollback_command": self.rollback_command,
            "rpcd_restarted": self.rpcd_restarted,
            "applied_at": self.applied_at.isoformat(),
        }


def _rollback_command(backup_path: str | None) -> str:
    if backup_path:
        return f"cp -p {backup_path} {ACL_FILE_PATH} && {_RPCD_RESTART_CMD}"
    # No ACL file existed before: remove ours. ensure_acl redeploys v8 at the
    # next Home Assistant start.
    return f"rm -f {ACL_FILE_PATH} && {_RPCD_RESTART_CMD}"


def _sha256_text(text: str | None) -> str | None:
    return None if text is None else hashlib.sha256(text.encode("utf-8")).hexdigest()


def _refuse(reason: str, router_id: str | None, message: str) -> AclOfferRefusedError:
    _LOGGER.warning("ACL offer deploy refused (%s): %s", reason, message)
    return AclOfferRefusedError(reason, message, router_id=router_id)


def _check_authorization(
    authorization: WriteAuthorization | None,
    guard_consume: GuardConsume,
    *,
    router_id: str,
    checksum: str,
) -> None:
    """Consume the authorization via the guard, then re-check it ourselves.

    The guard does the binding/ledger/single-use checks and audits. The
    re-check afterwards is defence in depth against a ``guard_consume`` that
    does not really consume (e.g. a stub): no write without a used,
    matching authorization.
    """
    if not isinstance(authorization, WriteAuthorization):
        raise _refuse("no_authorization", router_id, "no WriteAuthorization given")
    try:
        guard_consume(
            authorization,
            action=GuardedAction.ACL_DEPLOY.value,
            router_id=router_id,
            checksum=checksum,
        )
    except AuthorizationError as err:
        reason = str(err.details.get("reason") or "consume_failed")
        raise _refuse(reason, router_id, f"guard refused: {reason}") from err
    except Exception as err:  # fail closed on any guard error
        raise _refuse("consume_failed", router_id, f"guard error: {err}") from err
    if not authorization.consumed:
        raise _refuse("not_consumed", router_id, "authorization was not consumed")
    if authorization.action != GuardedAction.ACL_DEPLOY.value:
        raise _refuse("action_mismatch", router_id, "authorization is not acl_deploy")
    if authorization.router_id != router_id:
        raise _refuse(
            "router_mismatch", router_id, "authorization is for another router"
        )
    if authorization.checksum != checksum:
        raise _refuse(
            "checksum_mismatch", router_id, "authorization is for another ACL"
        )


_PERMISSION_ERRORS: Final = (
    OpenWrtAuthError,
    OpenWrtResponseError,
    OpenWrtMethodNotFoundError,
)
_TRANSPORT_ERRORS: Final = (OpenWrtConnectionError, OpenWrtTimeoutError)


async def _read_current_acl(api: OpenWrtAPI) -> tuple[str, str | None]:
    """("present", text) or ("unreadable", None).

    No "missing" via ubus on purpose: _call reports NOT_FOUND and an
    ACL-blocked read with the same exception, so a file we cannot read might
    exist. Writing over it without a backup would break the user's rule
    (every change with a way back); "unreadable" goes to the SSH path, whose
    shell checks existence itself and copies the file before writing.
    """
    try:
        current = await api._call("file", "read", {"path": ACL_FILE_PATH})
    except _TRANSPORT_ERRORS as err:
        raise AclOfferDeployError(
            "unreachable", f"router unreachable before ACL deploy: {err}"
        ) from err
    except _PERMISSION_ERRORS:
        return ("unreadable", None)
    text = current.get("data") if isinstance(current, dict) else current
    if not isinstance(text, str):
        return ("unreadable", None)
    return ("present", text)


# Pinned SSH for the offer deploy: (command, timeout_s) -> stdout or None.
# The core binds it to the router's host-key pin (async_ssh_run_pinned).
AclSshRunner = Callable[[str, float], Awaitable[str | None]]


async def _deploy_offer_ssh(
    ssh_runner: AclSshRunner | None, acl_text: str, backup_path: str
) -> tuple[bool, bool]:
    """Backup + atomic write + one rpcd restart in one SSH command.

    Returns (deployed, backed_up). Backup first: if ``cp`` fails, nothing is
    written. The restart only runs after a successful write. Only over the
    pinned path: without a runner it refuses (``ssh_pin_unavailable``) —
    never the shared, unverified SSH connection (1.44.0).
    """
    if ssh_runner is None:
        raise AclOfferDeployError(
            "ssh_pin_unavailable",
            "ubus cannot write the ACL and no pinned SSH path is available "
            "(no host-key pin store or pin); nothing written",
            written=False,
        )
    remote_cmd = (
        f"{{ [ ! -e {ACL_FILE_PATH} ] || "
        f"{{ cp -p {ACL_FILE_PATH} {backup_path} && echo {_SSH_OFFER_BACKUP_MARKER}; }}; }} "
        f"&& printf '%s' {shlex.quote(acl_text)} > {_ACL_TMP_PATH} "
        f"&& mv {_ACL_TMP_PATH} {ACL_FILE_PATH} "
        f"&& echo {_SSH_OFFER_DEPLOY_MARKER} "
        f"&& {_RPCD_RESTART_CMD} >/dev/null 2>&1"
    )
    out = await ssh_runner(remote_cmd, 15.0) or ""
    return (_SSH_OFFER_DEPLOY_MARKER in out, _SSH_OFFER_BACKUP_MARKER in out)


async def async_deploy_acl_offer(
    api: OpenWrtAPI,
    tiers: Iterable[str],
    *,
    router_id: str,
    authorization: WriteAuthorization | None,
    guard_consume: GuardConsume,
    options: Mapping[str, Any] | None = None,
    registry: AclTierRegistry = DEFAULT_TIER_REGISTRY,
    now: datetime | None = None,
    ssh_runner: AclSshRunner | None = None,
) -> AclDeployResult:
    """Write the tiered ACL for ``tiers`` to ONE router — only when authorized.

    Order: validate tiers and options (pure) -> consume the authorization
    (``guard_consume`` = ``guard.consume``; action ``acl_deploy``, this
    ``router_id``, ``acl_binding_checksum(router_id, acl)``) -> read the
    current ACL -> back it up on the router -> write -> restart rpcd once.
    An identical ACL on the router is left alone (no write, no restart).

    Raises:
        AclTierError: unknown tier or tier gated by an option that is off
            (``options`` None counts as "all options off").
        AclOfferRefusedError: no/invalid/used/mismatching authorization —
            nothing was sent to the router.
        AclOfferDeployError: router-side failure after the authorization was
            used; carries ``rollback_command`` when a backup was taken.
            ``ssh_pin_unavailable`` when ubus cannot write and no pinned
            ``ssh_runner`` was given (the unpinned SSH is never used).
    """
    tier_ids = registry.normalize(tiers)
    try:
        registry.check_options(tier_ids, options)
    except AclTierError as err:
        raise _refuse("option_disabled", router_id, str(err)) from err
    acl = build_acl(tier_ids, registry=registry)
    acl_text = render_acl(acl)
    checksum = acl_checksum(acl)
    _check_authorization(
        authorization,
        guard_consume,
        router_id=router_id,
        checksum=binding_checksum(router_id, checksum),
    )

    applied_at = now or utcnow()
    # Random suffix: two deploys in the same second never share (and so
    # overwrite) one backup file (security review, finding 10).
    backup_path = (
        f"{ACL_BACKUP_PREFIX}{applied_at.strftime('%Y%m%dT%H%M%SZ')}"
        f"-{secrets.token_hex(4)}"
    )
    command = f"write {ACL_FILE_PATH} (sha256 {checksum}) && {_RPCD_RESTART_CMD}"

    def _result(**kw: Any) -> AclDeployResult:
        return AclDeployResult(
            router_id=router_id,
            tiers=tier_ids,
            acl_checksum=checksum,
            applied_at=applied_at,
            **kw,
        )

    state, previous = await _read_current_acl(api)
    if state == "present":
        parsed, _why = parse_acl_text(previous)
        same = parsed == acl
        if same:
            _LOGGER.info(
                "Tiered ACL %s already on %s — nothing written", tier_ids, api._host
            )
            return _result(
                changed=False,
                transport="none",
                backup_path=None,
                previous_checksum=_sha256_text(previous),
                previous_content=previous,
                command=None,
                rollback_command=None,
                rpcd_restarted=False,
            )

    use_ssh = state == "unreadable"
    backed_up_path: str | None = None
    if not use_ssh and state == "present":
        try:
            await api._call(
                "file", "write", {"path": backup_path, "data": previous or ""}
            )
            backed_up_path = backup_path
        except _TRANSPORT_ERRORS as err:
            raise AclOfferDeployError(
                "unreachable", f"router unreachable during ACL backup: {err}"
            ) from err
        except _PERMISSION_ERRORS as err:
            _LOGGER.debug("ubus backup write rejected on %s (%s)", api._host, err)
            use_ssh = True

    if not use_ssh:
        try:
            await api._call("file", "write", {"path": ACL_FILE_PATH, "data": acl_text})
        except _TRANSPORT_ERRORS as err:
            raise AclOfferDeployError(
                "unreachable",
                f"router unreachable during ACL write: {err}",
                written=None,
                backup_path=backed_up_path,
                rollback_command=_rollback_command(backed_up_path),
            ) from err
        except _PERMISSION_ERRORS as err:
            _LOGGER.debug("ubus ACL write rejected on %s (%s)", api._host, err)
            use_ssh = True
        else:
            restarted = True
            try:
                await api._call(
                    "file",
                    "exec",
                    {"command": "/etc/init.d/rpcd", "params": ["restart"]},
                )
            except (*_PERMISSION_ERRORS, *_TRANSPORT_ERRORS) as err:
                restarted = False
                _LOGGER.debug(
                    "rpcd restart on %s failed (non-fatal): %s", api._host, err
                )
            _LOGGER.info(
                "Deployed tiered ACL v%s %s to %s via ubus (backup %s)",
                TIERED_ACL_VERSION,
                tier_ids,
                api._host,
                backed_up_path,
            )
            return _result(
                changed=True,
                transport="ubus",
                backup_path=backed_up_path,
                previous_checksum=_sha256_text(previous),
                previous_content=previous,
                command=command,
                rollback_command=_rollback_command(backed_up_path),
                rpcd_restarted=restarted,
            )

    deployed, ssh_backed_up = await _deploy_offer_ssh(ssh_runner, acl_text, backup_path)
    if ssh_backed_up:
        backed_up_path = backup_path
    if not deployed:
        # Either the backup cp or the write failed; the shell chain stops at
        # the first error, so the ACL file was not replaced by a complete one.
        raise AclOfferDeployError(
            "write_blocked",
            "ubus file/write rejected and SSH deploy did not confirm success",
            written=False,
            backup_path=backed_up_path,
            rollback_command=(
                _rollback_command(backed_up_path) if backed_up_path else None
            ),
        )
    if state == "present" and backed_up_path is None:
        # The chain only writes after a successful cp when a file existed;
        # a missing marker here means the file vanished in between.
        _LOGGER.debug("ACL on %s disappeared before the SSH backup", api._host)
    _LOGGER.info(
        "Deployed tiered ACL v%s %s to %s via SSH (backup %s)",
        TIERED_ACL_VERSION,
        tier_ids,
        api._host,
        backed_up_path,
    )
    return _result(
        changed=True,
        transport="ssh",
        backup_path=backed_up_path,
        previous_checksum=_sha256_text(previous),
        previous_content=previous,
        command=command,
        rollback_command=_rollback_command(backed_up_path),
        rpcd_restarted=True,
    )


async def ensure_acl_respecting_offer(
    api: OpenWrtAPI,
    *,
    observe: Callable[[AclEnsureOutcome], None] | None = None,
) -> bool:
    """Like :func:`ensure_acl`, but never overwrites a deployed tiered ACL.

    ``ensure_acl`` rewrites any ACL that differs from v8, so it would undo a
    user-approved tiered ACL at the next start. ``__init__.py`` and the
    config flow repair use this function (1.44.0). Zero extra router calls:
    the tiered check uses the content of ensure_acl's own ``file/read``;
    with no tiered ACL deployed, calls and written bytes are identical to
    :func:`ensure_acl`.

    ``observe`` receives the :class:`AclEnsureOutcome` (the core turns it
    into the rf.* capabilities); an error in it is logged, never raised.
    Raises AclDeployError like ``ensure_acl``.
    """
    outcome = await ensure_acl_outcome(api, respect_offer=True)
    if observe is not None:
        try:
            observe(outcome)
        except Exception:
            _LOGGER.warning("ACL outcome observer failed", exc_info=True)
    return outcome.written


def observe_deployed_acl(
    outcome: AclEnsureOutcome | None,
    *,
    failure: str | None = None,
    registry: AclTierRegistry = DEFAULT_TIER_REGISTRY,
    now: datetime | None = None,
) -> DeployedAclObservation:
    """Turn an ensure/deploy outcome into what the core keeps. Pure.

    ``failure``: why there is no outcome (``deploy_failed``,
    ``ensure_failed`` ...); the observation is then unknown.
    """
    when = now or utcnow()
    if outcome is None or not outcome.known:
        return DeployedAclObservation(
            known=False,
            reason=failure or (outcome.reason if outcome else "not_read"),
            observed_at=when,
        )
    acl = outcome.deployed
    info = parse_tiered_acl(acl)
    granted = granted_capabilities(acl, registry=registry)
    caps = sorted(str(c) for c in ACL_CAPABILITIES)
    return DeployedAclObservation(
        known=True,
        reason=outcome.reason,
        kind=classify_deployed_acl(acl, registry=registry).value,
        tiers=() if info is None else info.tiers,
        acl_checksum=acl_checksum(acl) if isinstance(acl, Mapping) else None,
        granted=tuple((c, bool(granted.get(c, False))) for c in caps),
        missing=tuple(
            (c, missing_permissions(acl, c, registry=registry)) for c in caps
        ),
        observed_at=when,
    )
