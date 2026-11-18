"""Repairs issues raised by the OpenWrt Router integration.

Thin wrapper around HA's issue registry so every issue of this integration is
created the same way: non-fixable, not persisted across restarts (the state is
re-derived from live polling after a restart) and translated via the
``issues`` section of strings.json.
"""

from __future__ import annotations

from collections.abc import Sequence

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN

ISSUE_ACL_BASE_RIGHTS_MISSING = "acl_base_rights_missing"
ISSUE_CHANNEL_PLAN_CONFLICT = "channel_plan_conflict"
ISSUE_LAN_UNREACHABLE = "lan_unreachable"
ISSUE_RAM_HIGH = "ram_high"
ISSUE_ROUTER_UNREACHABLE = "router_unreachable"


def router_unreachable_issue_id(entry_id: str) -> str:
    """Return the issue id of the per-router outage issue."""
    return f"{ISSUE_ROUTER_UNREACHABLE}_{entry_id}"


def ram_high_issue_id(entry_id: str) -> str:
    """Return the issue id of the per-router RAM pressure issue."""
    return f"{ISSUE_RAM_HIGH}_{entry_id}"


def acl_base_rights_issue_id(entry_id: str) -> str:
    """Return the issue id of the per-router "kept ACL lacks rights" issue."""
    return f"{ISSUE_ACL_BASE_RIGHTS_MISSING}_{entry_id}"


# Rights listed in the issue text; the count is always complete.
_ACL_RIGHTS_LISTED = 10


@callback
def async_sync_acl_base_rights_issue(
    hass: HomeAssistant,
    entry_id: str,
    title: str,
    missing: Sequence[str] | None,
    acl_path: str,
) -> None:
    """Open or clear the issue for a kept tiered ACL without base rights.

    ``missing`` None = unknown (the ACL was not read): nothing changes.
    Empty = the deployed ACL grants every base read right: cleared.
    """
    if missing is None:
        return
    issue_id = acl_base_rights_issue_id(entry_id)
    if not missing:
        async_clear_issue(hass, issue_id)
        return
    listed = [f"- `{right}`" for right in missing[:_ACL_RIGHTS_LISTED]]
    if len(missing) > _ACL_RIGHTS_LISTED:
        listed.append(f"- … (+{len(missing) - _ACL_RIGHTS_LISTED})")
    async_raise_issue(
        hass,
        issue_id,
        ISSUE_ACL_BASE_RIGHTS_MISSING,
        ir.IssueSeverity.WARNING,
        {
            "router": title,
            "count": str(len(missing)),
            "rights": "\n".join(listed),
            "path": acl_path,
        },
    )


@callback
def async_raise_issue(
    hass: HomeAssistant,
    issue_id: str,
    translation_key: str,
    severity: ir.IssueSeverity,
    placeholders: dict[str, str],
) -> None:
    """Create (or update) a non-fixable, non-persistent issue."""
    ir.async_create_issue(
        hass,
        DOMAIN,
        issue_id,
        is_fixable=False,
        is_persistent=False,
        severity=severity,
        translation_key=translation_key,
        translation_placeholders=placeholders,
    )


@callback
def async_clear_issue(hass: HomeAssistant, issue_id: str) -> None:
    """Delete an issue; no-op if it does not exist."""
    ir.async_delete_issue(hass, DOMAIN, issue_id)
