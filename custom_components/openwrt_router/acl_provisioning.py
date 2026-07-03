"""acl_provisioning.py — Auto-deploy rpcd ACL to OpenWrt routers.

When a router is added to Home Assistant, this module checks if the
rpcd ACL file exists on the router. If missing, it deploys it via the
ubus file API (no SSH required; asyncssh fallback when file/write is blocked).

The ACL grants access to the ubus methods needed by the integration:
hostapd, network.wireless, network.interface, luci-rpc, iwinfo, system.
"""

from __future__ import annotations

import json
import logging
import shlex
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import OpenWrtAPI

_LOGGER = logging.getLogger(__name__)

ACL_FILE_PATH = "/usr/share/rpcd/acl.d/ha-openwrt-router.json"

# Bump whenever RPCD_ACL_CONTENT below changes. Used only for log messages —
# staleness is detected by comparing the deployed file's actual content to
# RPCD_ACL_CONTENT, not by this number.
ACL_VERSION = 2

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
                "/etc/config/ddns": ["read"],
                "/var/run/ddns": ["list"],
                "/var/run/ddns/*": ["read"],
            },
            "ubus": {
                "file": ["read", "stat", "list"],
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
            },
        },
        "write": {
            "ubus": {
                "network.wireless": ["up", "down"],
            },
        },
    }
}


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
    from .api import OpenWrtMethodNotFoundError  # avoid circular at module level

    # Read the currently deployed ACL and decide whether a (re)deploy is needed.
    # file/read returns {"data": "<content>"} on success and raises
    # OpenWrtMethodNotFoundError (ubus NOT_FOUND = 4) when the file is missing.
    try:
        current = await api._call("file", "read", {"path": ACL_FILE_PATH})
        current_str = current.get("data") if isinstance(current, dict) else current
        try:
            if (
                isinstance(current_str, str)
                and json.loads(current_str) == RPCD_ACL_CONTENT
            ):
                _LOGGER.debug(
                    "rpcd ACL on %s is up to date (v%s) — nothing to do",
                    api._host,
                    ACL_VERSION,
                )
                return False
            reason = "outdated"  # content differs from what this version expects
        except (ValueError, TypeError):
            reason = "corrupted"  # present but not valid JSON
    except OpenWrtMethodNotFoundError:
        reason = "missing"  # file does not exist yet (first install)
    except Exception as err:  # noqa: BLE001
        # file/read blocked by ACL or file module unavailable. Fall back to a
        # cheap existence probe: if the file clearly exists we leave it alone
        # (we cannot verify content), otherwise we attempt an idempotent write.
        _LOGGER.debug(
            "Cannot read ACL on %s via file/read (%s) — probing existence",
            api._host,
            err,
        )
        try:
            await api._call("file", "stat", {"path": ACL_FILE_PATH})
            _LOGGER.debug(
                "rpcd ACL exists on %s but content is unverifiable — leaving as-is",
                api._host,
            )
            return False
        except OpenWrtMethodNotFoundError:
            reason = "missing"
        except Exception:  # noqa: BLE001
            reason = "unverifiable"

    return await _deploy_acl(api, reason)


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
    from .api import OpenWrtConnectionError, OpenWrtTimeoutError

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
    except Exception as err:  # noqa: BLE001
        # Permission-shaped rejection (ACL blocks file/write). Try SSH.
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
    except Exception as err:  # noqa: BLE001
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
