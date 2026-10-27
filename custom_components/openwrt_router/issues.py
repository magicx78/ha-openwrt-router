"""Repairs issues raised by the OpenWrt Router integration.

Thin wrapper around HA's issue registry so every issue of this integration is
created the same way: non-fixable, not persisted across restarts (the state is
re-derived from live polling after a restart) and translated via the
``issues`` section of strings.json.
"""

from __future__ import annotations

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN

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
