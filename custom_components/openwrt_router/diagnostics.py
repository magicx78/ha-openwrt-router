"""Diagnostics support for the OpenWrt Router integration.

Provides a sanitised snapshot of the integration's current state for
troubleshooting.  Personal and network identifiers (host, username, MACs,
IPs, hostnames, SSIDs, DDNS domains) are redacted by exact key name the HA
way, secrets (passwords, session tokens) additionally by substring, and
per-client lists are reduced to counts before the data is returned.
"""

from __future__ import annotations

import logging
import secrets
import time
from collections import Counter
from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant

from . import OpenWrtConfigEntry
from .client_engine import async_get_client_engine
from .const import (
    DIAGNOSTICS_CLIENT_LISTS,
    DIAGNOSTICS_REDACT_KEYS,
    DIAGNOSTICS_REDACTED,
    DIAGNOSTICS_TO_REDACT,
    DOMAIN,
)
from .core_masking import ACTOR_PSEUDONYM_PREFIX as _SHARED_PSEUDONYM_PREFIX
from .core_masking import pseudonymise_user_ids
from .mac_utils import is_mac
from .net_engine import async_get_engine
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
        # Counters, types and times only — no MAC, IP, SSID or names.
        "intelligence": _intelligence_summary(hass, entry.entry_id),
        # Client stability: fleet-wide counts only (no MAC, IP or hostname).
        "client_stability": _client_stability_summary(hass),
        # Enterprise core: registry counts, this router's record (no MAC,
        # host or hostname) and its last audit entries; masked twice.
        "enterprise_core": _enterprise_core_summary(hass, entry.entry_id),
        # --- configuration manager (plan 2026-11-18) ---------------------------
        # State and counters only: no note, no user id, no configuration.
        "config_manager": _config_manager_summary(hass, entry.entry_id),
        # --- end configuration manager -----------------------------------------
        # TODO: include bandwidth statistics once the bandwidth sensor is implemented
        # TODO: include traffic statistics once implemented
    }

    _LOGGER.debug("Diagnostics generated for entry %s", entry.entry_id)
    return diagnostics


def _intelligence_summary(hass: HomeAssistant, entry_id: str) -> dict[str, Any]:
    """Engine summary for one router; never fails the diagnostics download."""
    engine = async_get_engine(hass)
    if engine is None:
        return {"loaded": False}
    try:
        return engine.diagnostics(entry_id, time.time())
    except Exception:
        _LOGGER.debug("Network intelligence diagnostics failed", exc_info=True)
        return {"loaded": engine.loaded, "error": True}


def _client_stability_summary(hass: HomeAssistant) -> dict[str, Any]:
    """Client stability counts; never fails the diagnostics download."""
    cs = async_get_client_engine(hass)
    if cs is None:
        return {"loaded": False}
    try:
        return cs.diagnostics()
    except Exception:
        _LOGGER.debug("Client stability diagnostics failed", exc_info=True)
        return {"loaded": cs.loaded, "error": True}


ENTERPRISE_CORE_AUDIT_ENTRIES = 20
# Actor user ids in the audit entries are replaced by a pseudonym: same user
# -> same pseudonym inside ONE download (a fresh random salt per download),
# never the Home Assistant user id (security review 2026-11-18, #11). The
# helper is shared with the core bus event (core_masking owns the prefix).
ACTOR_PSEUDONYM_PREFIX = _SHARED_PSEUDONYM_PREFIX


def _pseudonymise_actors(
    entries: list[dict[str, Any]], salt: bytes
) -> list[dict[str, Any]]:
    """Copy of ``entries`` with every ``user_id`` (actor included) replaced."""
    return [pseudonymise_user_ids(entry, salt) for entry in entries]


def _enterprise_core_summary(hass: HomeAssistant, entry_id: str) -> dict[str, Any]:
    """Registry summary + last audit entries; never fails the download.

    Goes through core_masking (secrets in keys and free text) and then
    through the integration's own ``_redact`` (keys like host/mac/ip).
    Actor user ids become per-download pseudonyms (``usr_<12 hex>``). The
    record summary and the event data hold no MACs, hosts or hostnames
    (only counts, flags and field names).
    """
    try:
        from .core_masking import mask_for_output
        from .enterprise_core import async_get_core

        core = async_get_core(hass)
        if core is None:
            return {"loaded": False}
        registry = core.registry
        router_id = registry.router_id_for_entry(entry_id)
        summary: dict[str, Any] = {
            "loaded": core.loaded,
            **core.summary(),
            "router_record": None,
            "audit_entries": [],
        }
        if router_id is not None:
            summary["router_record"] = registry.record_summary(router_id)
            summary["audit_entries"] = _pseudonymise_actors(
                [
                    event.to_dict()
                    for event in core.audit.events(
                        router_id=router_id, limit=ENTERPRISE_CORE_AUDIT_ENTRIES
                    )
                ],
                secrets.token_bytes(16),
            )
        return _redact(mask_for_output(summary))
    except Exception:
        _LOGGER.debug("Enterprise core diagnostics failed", exc_info=True)
        return {"loaded": False, "error": True}


# --- configuration manager (plan 2026-11-18) -----------------------------------------


def _iso_or_none(value: Any) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else None


def _config_manager_summary(hass: HomeAssistant, entry_id: str) -> dict[str, Any]:
    """Backup state of this router; never fails the download.

    Memory of the runtime only (no store read, no router call). Leaves out
    notes, user ids, drift ids and every configuration value; masked and
    redacted like the core summary.
    """
    try:
        from .config_manager import async_get_runtime
        from .core_masking import mask_for_output

        runtime = async_get_runtime(hass)
        if runtime is None:
            return {"loaded": False}
        summary: dict[str, Any] = {
            "loaded": True,
            "provider_registered": runtime.provider_registered,
            "provider_conflict": runtime.provider_conflict,
            "stats": dict(runtime.stats),
            "backup": None,
        }
        state = runtime.state_for_entry(entry_id)
        if state is not None:
            rid = state.router_id
            drift = state.drift or {}
            summary["backup"] = {
                "enabled": runtime.enabled(rid),
                "schedule_daily": runtime.schedule_daily(rid),
                "drift_check": runtime.drift_check_enabled(rid),
                "status": runtime.status(rid),
                "error_class": runtime.error_class(rid),
                "running": state.running,
                "version_count": state.version_count,
                "last_backup_at": _iso_or_none(state.last_backup_at),
                "last_attempt_at": _iso_or_none(state.last_attempt_at),
                "next_run_at": _iso_or_none(runtime.next_run_at(rid)),
                "drift": {
                    "state": drift.get("state"),
                    "critical_count": drift.get("critical_count"),
                    "unknown_count": drift.get("unknown_count"),
                    "comparison": drift.get("comparison"),
                    "checked_at": _iso_or_none(drift.get("checked_at")),
                }
                if drift
                else None,
            }
        return _redact(mask_for_output(summary))
    except Exception as err:  # noqa: BLE001 - the download must not fail
        _LOGGER.debug(
            "Configuration manager diagnostics failed: %s", type(err).__name__
        )
        return {"loaded": False, "error": True}


# --- end configuration manager -------------------------------------------------------


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
