"""acl_provisioning.py — Auto-deploy rpcd ACL to OpenWrt routers.

When a router is added to Home Assistant, this module checks if the
rpcd ACL file exists on the router. If missing, it deploys it via the
ubus file API (no SSH or sshpass required).

The ACL grants access to the ubus methods needed by the integration:
hostapd, network.wireless, network.interface, luci-rpc, iwinfo, system.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import OpenWrtAPI

_LOGGER = logging.getLogger(__name__)

ACL_FILE_PATH = "/usr/share/rpcd/acl.d/ha-openwrt-router.json"

# Bump whenever RPCD_ACL_CONTENT below changes. Used only for log messages —
# staleness is detected by comparing the deployed file's actual content to
# RPCD_ACL_CONTENT, not by this number.
ACL_VERSION = 2

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

    Uses only the ubus file API (file/read + file/write + file/exec); no SSH or
    sshpass.  Best-effort: a router that blocks file/write logs a clear
    manual-deploy hint and returns False without breaking setup.

    Args:
        api: Authenticated OpenWrtAPI instance.

    Returns:
        True if the ACL was (re)written (caller should refresh the coordinator).
        False if it was already current, or deployment was skipped/failed.
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
    """Write the ACL via ubus file/write and restart rpcd to pick it up.

    Best-effort: returns False (without raising) when file/write is rejected so
    setup is never blocked on a router that disallows it — the SSH fallbacks in
    api.py keep the integration usable and the next startup retries.

    Args:
        api: Authenticated OpenWrtAPI instance.
        reason: Why we are (re)deploying ("missing" / "outdated" / ...), logged.

    Returns:
        True if the ACL file was written; False if the write was rejected.
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
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning(
            "Cannot deploy ACL (%s) to %s via ubus file/write: %s. "
            "Deploy it manually: scp ha-openwrt-router.json root@%s:%s",
            reason,
            api._host,
            err,
            api._host,
            ACL_FILE_PATH,
        )
        return False

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


async def check_and_deploy_acl(api: OpenWrtAPI) -> bool:
    """Backwards-compatible alias for :func:`ensure_acl`.

    Retained so the config_flow "deploy_acl" repair action and any external
    callers keep working unchanged. Prefer ``ensure_acl`` in new code.
    """
    return await ensure_acl(api)
