"""Interface -> firewall zone per router for ``fw_inter_vlan`` (1.46.2).

fw4 log lines never name the destination zone; they name the outgoing
interface (``OUT=``). This book answers "which zone is ``br-lan.2`` in on
router X", from two tiers, the first one that knows wins:

1. **configured**: a mapping set by a caller that read it from the router's
   configuration (firewall zone ``network`` lists and the interfaces'
   ``device``). Learning never changes it. Today nothing feeds this tier in
   production: the Configuration API gives a module no read access to the
   content of stored versions (``VersionView`` is index only, a live capture
   is a router call). It is here so that a later read path only calls
   :meth:`ZoneBook.set_configured`.
2. **learned** from the lines themselves: in the chains ``in`` and
   ``forward`` the prefix zone (``reject <zone> forward:``) is the zone of
   the ``IN=`` interface. Lines come by UDP and can be forged, so a learned
   entry is weak: it never overrides tier 1, an interface seen with two
   zones within ``ZONE_TTL_S`` is *ambiguous* (unknown, never a majority
   vote), and every table is bounded.

The manual ``subnet_zones`` map of the settings stays a third tier inside
the detector. Memory only: the book is not stored, it is learned again after
a restart (until then the honest limitation ``dest_zone_unknown`` stays).

Pure module: no Home Assistant import, no I/O, no router call, never logs
names or addresses.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Final, TypeGuard

_LOGGER = logging.getLogger(__name__)

# A learned zone of an interface counts while it was seen within this time.
ZONE_TTL_S: Final = 7 * 86400.0
MAX_IFACES_PER_ROUTER: Final = 64
MAX_ZONES_PER_IFACE: Final = 4
MAX_ROUTERS: Final = 64

# The same character sets as the fw4 parser (security_logfmt).
_IFACE_RE: Final = re.compile(r"[A-Za-z0-9_.@-]{1,16}")
_ZONE_RE: Final = re.compile(r"[A-Za-z0-9_-]{1,32}")


def valid_iface(name: object) -> TypeGuard[str]:
    """True for an interface name as fw4 logs it (``br-lan.7``)."""
    return isinstance(name, str) and _IFACE_RE.fullmatch(name) is not None


def valid_zone(name: object) -> TypeGuard[str]:
    """True for a firewall zone name as fw4 logs it."""
    return isinstance(name, str) and _ZONE_RE.fullmatch(name) is not None


class ZoneBook:
    """Interface -> zone per router: configured first, then learned."""

    def __init__(
        self,
        *,
        ttl_s: float = ZONE_TTL_S,
        max_routers: int = MAX_ROUTERS,
        max_ifaces: int = MAX_IFACES_PER_ROUTER,
        max_zones: int = MAX_ZONES_PER_IFACE,
    ) -> None:
        """Empty book with its bounds."""
        self.ttl_s = float(ttl_s)
        self.max_routers = max(1, int(max_routers))
        self.max_ifaces = max(1, int(max_ifaces))
        self.max_zones = max(2, int(max_zones))
        self._configured: dict[str, dict[str, str]] = {}
        # router -> interface -> zone -> last seen (line time)
        self._learned: dict[str, dict[str, dict[str, float]]] = {}
        self.counters: dict[str, int] = {"conflicts": 0, "refused": 0}

    # -- tier 1 -----------------------------------------------------------------

    def set_configured(self, router: str, mapping: Mapping[str, str] | None) -> None:
        """Replace the configured interfaces of ``router`` (None removes them).

        Invalid names are left out; at most ``max_ifaces`` entries are kept.
        """
        if not mapping:
            self._configured.pop(router, None)
            return
        clean: dict[str, str] = {}
        for iface, zone in mapping.items():
            if len(clean) >= self.max_ifaces:
                break
            if valid_iface(iface) and valid_zone(zone):
                clean[iface] = zone
        if clean:
            if router not in self._configured and not self._room_for(router):
                self.counters["refused"] += 1
                return
            self._configured[router] = clean
        else:
            self._configured.pop(router, None)

    # -- tier 2 -----------------------------------------------------------------

    def learn(self, router: str, iface: object, zone: object, ts: float) -> None:
        """Note that ``iface`` was seen in ``zone`` at line time ``ts``."""
        if not (valid_iface(iface) and valid_zone(zone)):
            return
        table = self._learned.get(router)
        if table is None:
            if not self._room_for(router):
                self.counters["refused"] += 1
                return
            table = self._learned[router] = {}
        zones = table.get(iface)
        if zones is None:
            if len(table) >= self.max_ifaces:
                self._expire(table, ts)
            if len(table) >= self.max_ifaces:
                # Refused, never evicted: a flood of forged interfaces must
                # not push the real ones out.
                self.counters["refused"] += 1
                return
            zones = table[iface] = {}
        if zone not in zones and self._live(zones, ts):
            self.counters["conflicts"] += 1
        if zone not in zones and len(zones) >= self.max_zones:
            del zones[min(zones, key=zones.__getitem__)]  # still ambiguous
        zones[zone] = max(ts, zones.get(zone, ts))

    # -- lookup -----------------------------------------------------------------

    def zone_of(self, router: str, iface: object, now: float) -> str | None:
        """Zone of ``iface``; None when unknown or ambiguous."""
        if not valid_iface(iface):
            return None
        configured = self._configured.get(router, {}).get(iface)
        if configured is not None:
            return configured
        zones = self._learned.get(router, {}).get(iface)
        if not zones:
            return None
        live = [z for z, seen in zones.items() if now - seen <= self.ttl_s]
        return live[0] if len(live) == 1 else None

    def knows(self, router: str, now: float) -> bool:
        """True if at least one interface of ``router`` has a known zone."""
        if self._configured.get(router):
            return True
        return any(
            self.zone_of(router, iface, now) is not None
            for iface in self._learned.get(router, {})
        )

    # -- housekeeping -----------------------------------------------------------

    def forget(self, router: str) -> None:
        """Drop everything about a router (router forgotten)."""
        self._configured.pop(router, None)
        self._learned.pop(router, None)

    def size(self) -> int:
        """Stored entries (memory check)."""
        return sum(len(t) for t in self._configured.values()) + sum(
            len(z) for t in self._learned.values() for z in t.values()
        )

    def stats(self) -> dict[str, int]:
        """Counts only, no names (diagnostics)."""
        return {
            "routers": len(set(self._configured) | set(self._learned)),
            "configured": sum(len(t) for t in self._configured.values()),
            "learned": sum(len(t) for t in self._learned.values()),
            **self.counters,
        }

    def _room_for(self, router: str) -> bool:
        routers = set(self._configured) | set(self._learned)
        return router in routers or len(routers) < self.max_routers

    def _live(self, zones: Mapping[str, float], now: float) -> bool:
        return any(now - seen <= self.ttl_s for seen in zones.values())

    def _expire(self, table: dict[str, dict[str, float]], now: float) -> None:
        for iface in [i for i, z in table.items() if not self._live(z, now)]:
            del table[iface]
