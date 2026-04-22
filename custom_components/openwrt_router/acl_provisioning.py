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


async def check_and_deploy_acl(api: OpenWrtAPI) -> bool:
    """Check if rpcd ACL exists on router, deploy if missing.

    Uses the ubus file API (file/stat + file/write + file/exec) so no
    SSH or sshpass is required. All operations run through the already-
    authenticated api instance.

    Args:
        api: Authenticated OpenWrtAPI instance.

    Returns:
        True if ACL was newly deployed (caller should refresh coordinator).
        False if ACL already existed, deployment was skipped, or the ubus
        file module is unavailable.
    """
    from .api import OpenWrtMethodNotFoundError  # avoid circular at module level

    # Step 1: Check whether the ACL file already exists.
    # file/stat returns status 0 + metadata when the file exists, and
    # raises OpenWrtMethodNotFoundError (ubus status NOT_FOUND = 4) when it
    # doesn't. Any other exception means the file module is unavailable.
    try:
        await api._call("file", "stat", {"path": ACL_FILE_PATH})
        _LOGGER.debug("rpcd ACL already exists on %s", api._host)
        return False
    except OpenWrtMethodNotFoundError:
        # Status NOT_FOUND → file doesn't exist. Proceed to deploy.
        _LOGGER.debug(
            "rpcd ACL missing on %s — will deploy via ubus file/write", api._host
        )
    except Exception as err:  # noqa: BLE001
        # file module unavailable or permission denied on stat.
        # Still attempt the write; worst case it fails gracefully below.
        _LOGGER.debug(
            "Cannot verify ACL on %s via file/stat (%s) — attempting write anyway",
            api._host,
            err,
        )

    # Step 2: Write the ACL file via ubus file/write.
    acl_json = json.dumps(RPCD_ACL_CONTENT, indent=2)
    try:
        await api._call("file", "write", {"path": ACL_FILE_PATH, "data": acl_json})
        _LOGGER.info("Deployed rpcd ACL to %s:%s", api._host, ACL_FILE_PATH)
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning(
            "Cannot deploy ACL to %s via ubus file/write: %s. "
            "The ACL must be deployed manually: "
            "scp ha-openwrt-router.json root@%s:%s",
            api._host,
            err,
            api._host,
            ACL_FILE_PATH,
        )
        return False

    # Step 3: Restart rpcd so it picks up the new ACL file.
    try:
        await api._call(
            "file",
            "exec",
            {"command": "/etc/init.d/rpcd", "params": ["restart"]},
        )
        _LOGGER.debug("Restarted rpcd on %s", api._host)
    except Exception as err:  # noqa: BLE001
        # Non-fatal: rpcd will pick up the ACL on next restart/reload anyway.
        _LOGGER.debug(
            "Could not restart rpcd on %s (non-fatal, ACL active after next restart): %s",
            api._host,
            err,
        )

    return True
