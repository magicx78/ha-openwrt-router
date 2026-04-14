"""acl_provisioning.py — Auto-deploy rpcd ACL to OpenWrt routers.

When a router is added to Home Assistant, this module checks if the
rpcd ACL file exists on the router. If missing, it deploys it via SSH
and restarts rpcd so the integration gets proper API access.

The ACL grants read access to the ubus methods needed by the integration:
hostapd, network.wireless, network.interface, luci-rpc, iwinfo, system.

This is best-effort: if SSH/sshpass is unavailable, the integration
continues with its existing fallback chain (SSH commands, iw, luci-rpc).
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .api import OpenWrtAPI

_LOGGER = logging.getLogger(__name__)

ACL_FILE_PATH = "/usr/share/rpcd/acl.d/ha-openwrt-router.json"

RPCD_ACL_CONTENT: dict = {
    "root": {
        "description": "Home Assistant openwrt_router integration",
        "read": {
            "ubus": {
                "hostapd.*": ["get_clients", "get_status"],
                "network.wireless": ["status", "up", "down"],
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
            }
        },
    }
}


async def check_and_deploy_acl(api: OpenWrtAPI) -> bool:
    """Check if rpcd ACL exists on router, deploy if missing.

    Args:
        api: Authenticated OpenWrtAPI instance with host/username/password.

    Returns:
        True if ACL was deployed (router needs rpcd restart + data refresh).
        False if ACL already existed or deployment was skipped.

    Raises:
        No exceptions — all errors are caught and logged.
    """
    host = api._host
    username = api._username
    password = api._password

    # Step 1: Check if ACL file exists
    try:
        exists = await _check_acl_exists(host, username, password)
    except Exception as err:  # noqa: BLE001
        _LOGGER.debug(
            "Cannot check ACL on %s (SSH unavailable): %s", host, err
        )
        return False

    if exists:
        _LOGGER.debug("rpcd ACL already exists on %s", host)
        return False

    # Step 2: Deploy ACL file
    try:
        acl_json = json.dumps(RPCD_ACL_CONTENT, indent=2)
        await _deploy_acl(host, username, password, acl_json)
        _LOGGER.info(
            "Deployed rpcd ACL to %s:%s — restarting rpcd",
            host,
            ACL_FILE_PATH,
        )
        return True
    except Exception as err:  # noqa: BLE001
        _LOGGER.warning(
            "Failed to deploy rpcd ACL to %s: %s. "
            "Integration will use fallback methods.",
            host,
            err,
        )
        return False


async def _check_acl_exists(
    host: str, username: str, password: str
) -> bool:
    """Check if the ACL file exists on the router via SSH."""
    cmd = f"test -f {ACL_FILE_PATH} && echo EXISTS || echo MISSING"
    stdout = await _ssh_exec(host, username, password, cmd)
    return "EXISTS" in stdout


async def _deploy_acl(
    host: str, username: str, password: str, acl_json: str
) -> None:
    """Deploy ACL file to router and restart rpcd via SSH."""
    # Write ACL file using cat heredoc (handles special chars safely)
    write_cmd = (
        f"cat > {ACL_FILE_PATH} << 'ACLEOF'\n"
        f"{acl_json}\n"
        f"ACLEOF"
    )
    await _ssh_exec(host, username, password, write_cmd)

    # Restart rpcd to pick up new ACL
    await _ssh_exec(host, username, password, "/etc/init.d/rpcd restart")


async def _ssh_exec(
    host: str,
    username: str,
    password: str,
    command: str,
    timeout: float = 10.0,
) -> str:
    """Execute a command on the router via sshpass + SSH.

    Uses the same SSH pattern as api.py SSH fallback methods.

    Returns:
        stdout as string.

    Raises:
        RuntimeError: SSH command failed or timed out.
    """
    ssh_cmd = [
        "sshpass",
        "-p",
        password,
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=5",
        f"{username}@{host}",
        command,
    ]

    proc = await asyncio.create_subprocess_exec(
        *ssh_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_bytes, stderr_bytes = await asyncio.wait_for(
        proc.communicate(), timeout=timeout
    )

    if proc.returncode != 0:
        stderr = stderr_bytes.decode(errors="replace").strip()
        raise RuntimeError(
            f"SSH command failed on {host} (rc={proc.returncode}): {stderr}"
        )

    return stdout_bytes.decode(errors="replace").strip()
