"""Diagnostics support for the OpenWrt Router integration.

Provides a sanitised snapshot of the integration's current state for
troubleshooting.  All sensitive values (passwords, session tokens) are
replaced with the DIAGNOSTICS_REDACTED placeholder before the data is
returned to the user.
"""

from __future__ import annotations

import copy
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from . import OpenWrtConfigEntry
from .const import (
    CONF_PASSWORD,
    DIAGNOSTICS_REDACT_KEYS,
    DIAGNOSTICS_REDACTED,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: OpenWrtConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry.

    Called by HA when the user downloads diagnostics from the UI.

    Returns a dict containing:
        - config: Entry configuration (password redacted).
        - coordinator_data: Last polled data snapshot (tokens redacted).
        - features: Detected feature flags.
        - router_info: Static board information.

    Args:
        hass: Home Assistant instance.
        entry: The config entry to diagnose.

    Returns:
        Sanitised diagnostics dict safe for sharing in bug reports.
    """
    coordinator = entry.runtime_data.coordinator

    # Deep-copy config data so we can safely redact in-place
    config_data = _redact(dict(entry.data))

    coordinator_data: dict[str, Any] = {}
    if coordinator.data:
        coordinator_data = _redact(coordinator.data.as_dict())

    diagnostics: dict[str, Any] = {
        "integration": DOMAIN,
        "entry_id": entry.entry_id,
        "entry_title": entry.title,
        "config": config_data,
        "coordinator": {
            "last_update_success": coordinator.last_update_success,
            "update_interval_seconds": coordinator.update_interval.total_seconds()
            if coordinator.update_interval
            else None,
            "data": coordinator_data,
        },
        "features": _redact(coordinator.features),
        "router_info": _redact(coordinator.router_info),
        # TODO: include bandwidth statistics once the bandwidth sensor is implemented
        # TODO: include per-client online time once implemented
        # TODO: include traffic statistics once implemented
    }

    _LOGGER.debug("Diagnostics generated for entry %s", entry.entry_id)
    return diagnostics


def _redact(data: Any) -> Any:
    """Recursively redact sensitive keys from a data structure.

    Performs a deep copy and replaces the value of any key whose lowercase
    name appears in DIAGNOSTICS_REDACT_KEYS with DIAGNOSTICS_REDACTED.

    Args:
        data: Any JSON-serialisable structure (dict, list, scalar).

    Returns:
        A new structure with sensitive values replaced.
    """
    if isinstance(data, dict):
        return {
            key: DIAGNOSTICS_REDACTED
            if _is_sensitive_key(key)
            else _redact(value)
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [_redact(item) for item in data]

    # Scalars are returned as-is
    return data


def _is_sensitive_key(key: str) -> bool:
    """Return True if the key name indicates a sensitive value.

    Args:
        key: Dict key string.

    Returns:
        True if any redact keyword is a substring of the lowercase key.
    """
    key_lower = key.lower()
    return any(sensitive in key_lower for sensitive in DIAGNOSTICS_REDACT_KEYS)
