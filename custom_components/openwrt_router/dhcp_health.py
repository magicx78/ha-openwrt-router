"""DHCP health checks (pure functions, no HA).

- ``parse_dhcp_config``: pools (``config dhcp``) and static hosts
  (``config host``) from ``uci get dhcp``.
- ``pool_usage``: per active pool the share of its range covered by leases.
- ``client_dhcp_status``: whether an associated Wi-Fi client got an address.

Router output is untrusted: every field is validated, nothing is executed.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime
from typing import Any

DHCP_OK = "ok"
DHCP_PENDING = "pending"
DHCP_MISSING = "dhcp_missing"
DHCP_STATIC_NO_LEASE = "static_no_lease"

# A client must be associated this long before a missing lease counts.
DHCP_MISSING_AFTER_SECONDS = 180


@dataclass(frozen=True)
class Pool:
    """One DHCP pool (uci ``config dhcp`` section)."""

    name: str
    interface: str
    start: int
    limit: int


def parse_dhcp_config(values: Any) -> tuple[list[Pool], frozenset[str]]:
    """Return (active IPv4 pools, MACs of static hosts) from ``uci get dhcp``.

    A pool is active unless ``ignore`` is set or ``dhcpv4`` is ``disabled``.
    Static host MACs may be a list or a space separated string; they are
    upper-cased. Broken sections are skipped.
    """
    pools: list[Pool] = []
    static: set[str] = set()
    if not isinstance(values, dict):
        return pools, frozenset()
    for name, section in values.items():
        if not isinstance(section, dict):
            continue
        kind = section.get(".type")
        if kind == "dhcp":
            if _truthy(section.get("ignore")) or section.get("dhcpv4") == "disabled":
                continue
            interface = section.get("interface")
            start = _as_int(section.get("start"), 100)
            limit = _as_int(section.get("limit"), 150)
            if (
                not isinstance(interface, str)
                or not interface
                or limit <= 0
                or start < 0
            ):
                continue
            # Anonymous sections get a hash name (cfgXXXXXX) that changes
            # with their options: name them after the interface instead.
            pool_name = (
                interface
                if _truthy(section.get(".anonymous"))
                else str(section.get(".name") or name)
            )
            pools.append(Pool(pool_name, interface, start, limit))
        elif kind == "host":
            macs = section.get("mac")
            if isinstance(macs, str):
                macs = macs.split()
            if isinstance(macs, list):
                static.update(m.upper() for m in macs if isinstance(m, str) and m)
    return pools, frozenset(static)


def pool_usage(
    pools: list[Pool],
    network_interfaces: list[dict[str, Any]],
    leases: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return usage per pool whose interface has an IPv4 subnet.

    The pool range is ``network + start … + limit - 1`` (clamped to the
    subnet), usage = leases with an IP in that range / range size.
    """
    subnets: dict[str, ipaddress.IPv4Network] = {}
    for iface in network_interfaces or []:
        if not isinstance(iface, dict):
            continue
        name = iface.get("logical_name")
        addr = iface.get("ipv4_addr")
        prefix = iface.get("prefix_len")
        if not isinstance(name, str) or not isinstance(addr, str):
            continue
        try:
            subnets[name] = ipaddress.IPv4Network(f"{addr}/{int(prefix)}", strict=False)
        except (TypeError, ValueError):
            continue

    lease_ips: list[ipaddress.IPv4Address] = []
    for lease in (leases or {}).values():
        ip = lease.get("ip") if isinstance(lease, dict) else None
        try:
            lease_ips.append(ipaddress.IPv4Address(ip))
        except (ipaddress.AddressValueError, ValueError, TypeError):
            continue

    result: list[dict[str, Any]] = []
    for pool in pools:
        net = subnets.get(pool.interface)
        if net is None or net.num_addresses < 4:
            continue
        first = int(net.network_address) + pool.start
        last = min(first + pool.limit - 1, int(net.broadcast_address) - 1)
        if first > last:
            continue
        size = last - first + 1
        used = sum(1 for ip in lease_ips if first <= int(ip) <= last)
        result.append(
            {
                "name": pool.name,
                "interface": pool.interface,
                "size": size,
                "leases": used,
                "usage_pct": round(used / size * 100, 1),
            }
        )
    return result


def client_dhcp_status(
    mac: str,
    connected_since: Any,
    now: datetime,
    lease_macs: frozenset[str] | set[str],
    arp_macs: frozenset[str] | set[str],
    static_macs: frozenset[str] | set[str],
) -> str:
    """Classify whether an associated Wi-Fi client has an address.

    ``dhcp_missing`` only if all apply: associated for at least
    DHCP_MISSING_AFTER_SECONDS, no lease on any router, not in the ARP table
    of any router and not a static host. A static host without lease is
    ``static_no_lease``. All MAC sets must be upper case.
    """
    mac = mac.upper()
    if mac in lease_macs:
        return DHCP_OK
    since = _parse_time(connected_since)
    settled = (
        since is not None
        and (now - since).total_seconds() >= DHCP_MISSING_AFTER_SECONDS
    )
    if mac in static_macs:
        return DHCP_STATIC_NO_LEASE if settled else DHCP_PENDING
    if mac in arp_macs:
        return DHCP_OK  # address configured on the device itself
    return DHCP_MISSING if settled else DHCP_PENDING


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else None


def _truthy(value: Any) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def _as_int(value: Any, default: int) -> int:
    if value is None:
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default
