"""Diagnostics support for the OpenWrt Router integration.

Provides a sanitised snapshot of the integration's current state for
troubleshooting.  Personal and network identifiers (host, username, MACs,
IPs, hostnames, SSIDs, DDNS domains) are redacted by exact key name the HA
way, secrets (passwords, session tokens) additionally by substring, and
per-client lists are reduced to counts before the data is returned.
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import OpenWrtConfigEntry
from .const import (
    DIAGNOSTICS_CLIENT_LISTS,
    DIAGNOSTICS_REDACT_KEYS,
    DIAGNOSTICS_REDACTED,
    DIAGNOSTICS_TO_REDACT,
    DOMAIN,
)
from .mac_utils import is_mac
from .topology_ports import redacted_port_summary

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
    port_mapping: dict[str, Any] = {}
    if coordinator.data:
        coordinator_data = _redact(coordinator.data.as_dict())
        # DHCP leases are personally identifiable (MAC → IP → hostname for every
        # LAN client).  Replace the full list with a count so the diagnostics
        # export remains useful for troubleshooting without leaking PII.
        if "dhcp_leases" in coordinator_data:
            lease_count = len(coordinator.data.dhcp_leases)
            coordinator_data["dhcp_leases"] = f"<{lease_count} leases redacted>"
        # The ARP table is the same PII class (MAC → IP) — count only.
        if "arp_table" in coordinator_data:
            arp_count = len(coordinator.data.arp_table)
            coordinator_data["arp_table"] = f"<{arp_count} entries redacted>"
        # LLDP neighbors: keep the troubleshooting-relevant link facts (local
        # interface, ports, capabilities) but redact the neighbor's name
        # (usually its hostname), management IP and chassis-ID (MAC), and a
        # port ID that is a MAC (client NICs) — same PII class as ARP/DHCP.
        if "lldp_neighbors" in coordinator_data:
            coordinator_data["lldp_neighbors"] = [
                {
                    "local_interface": n.get("local_interface"),
                    "chassis_name": DIAGNOSTICS_REDACTED
                    if n.get("chassis_name")
                    else None,
                    "chassis_id": DIAGNOSTICS_REDACTED if n.get("chassis_id") else None,
                    "management_ip": DIAGNOSTICS_REDACTED
                    if n.get("management_ip")
                    else None,
                    "port_id": DIAGNOSTICS_REDACTED
                    if is_mac(n.get("port_id"))
                    else n.get("port_id"),
                    "port_descr": n.get("port_descr"),
                    "capabilities": n.get("capabilities"),
                }
                for n in coordinator.data.lldp_neighbors
            ]
        # Connected clients: counts and signal aggregates instead of one
        # record (MAC, IP, hostname, SSID) per device.
        if "clients" in coordinator_data:
            coordinator_data["clients"] = _client_summary(coordinator.data.clients)
        stability = coordinator_data.get("client_stability")
        if isinstance(stability, dict):
            for list_key in DIAGNOSTICS_CLIENT_LISTS:
                if isinstance(stability.get(list_key), list):
                    stability[list_key] = (
                        f"<{len(stability[list_key])} clients redacted>"
                    )
        # PII-free per-port mapping summary (counts, confidence, sources) —
        # the full raw mapping lives only in the auth-protected snapshot.
        port_mapping = redacted_port_summary(coordinator.data)

    diagnostics: dict[str, Any] = {
        "integration": DOMAIN,
        "entry_id": entry.entry_id,
        # Defaults to the router hostname or host (config_flow), so redacted.
        "entry_title": DIAGNOSTICS_REDACTED,
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
        "port_mapping": port_mapping,
        # TODO: include bandwidth statistics once the bandwidth sensor is implemented
        # TODO: include per-client online time once implemented
        # TODO: include traffic statistics once implemented
    }

    _LOGGER.debug("Diagnostics generated for entry %s", entry.entry_id)
    return diagnostics


def _client_summary(clients: list[dict[str, Any]]) -> dict[str, Any]:
    """Reduce the client list to counts and signal aggregates.

    Args:
        clients: Normalised client dicts from the coordinator.

    Returns:
        Count, count per connection type and min/max/avg signal (dBm).
    """
    clients = [c for c in clients if isinstance(c, dict)]
    # type() instead of isinstance(): a bool is an int but not a signal.
    signals = [
        c["signal"]
        for c in clients
        if type(c.get("signal")) is int and c["signal"] != 0
    ]
    by_type = Counter(str(c.get("connection_type") or "unknown") for c in clients)
    return {
        "count": len(clients),
        "by_connection_type": dict(sorted(by_type.items())),
        "signal_min": min(signals) if signals else None,
        "signal_max": max(signals) if signals else None,
        "signal_avg": round(sum(signals) / len(signals), 1) if signals else None,
    }


def _redact(data: Any) -> Any:
    """Recursively redact personal data and secrets from a data structure.

    First pass: HA's ``async_redact_data`` over the exact key names in
    DIAGNOSTICS_TO_REDACT.  Second pass: any key whose lowercase name
    contains one of DIAGNOSTICS_REDACT_KEYS (passwords, tokens, ...).

    Args:
        data: Any JSON-serialisable structure (dict, list, scalar).

    Returns:
        A new structure with sensitive values replaced.
    """
    return _redact_secrets(async_redact_data(data, DIAGNOSTICS_TO_REDACT))


def _redact_secrets(data: Any) -> Any:
    """Recursively replace values of keys that look like secrets (substring)."""
    if isinstance(data, dict):
        return {
            key: DIAGNOSTICS_REDACTED
            if _is_sensitive_key(key)
            else _redact_secrets(value)
            for key, value in data.items()
        }

    if isinstance(data, list):
        return [_redact_secrets(item) for item in data]

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
