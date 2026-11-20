"""Client traffic attribution (plan 2026-11-20, §4; Phase D).

No second client database: the identity of a client is the client engine's
(``client_engine.async_get_client_engine(hass).history.live(mac)``, read
only, asked while the poll is copied) and its ``client_ref``, the core
pseudonym of its MAC with the traffic module key. This module keeps only
counters per ``client_ref`` in memory, never a MAC, IP or host name.

**Identity.** A new IP changes nothing (the ref is built from the MAC). A
new, randomised MAC is a new client: nothing is merged, ever. A client the
registry does not know and whose MAC is locally administered is marked
``unconfirmed`` (shown separately, never joined to another one).

**What a client value is.** Wi-Fi station counters as the AP counted them
(``wlan_traffic_at_ap``): local traffic included, traffic of other paths
(wired, other APs before a roam) not. Every Wi-Fi value carries
``partial``/``station_counters_only``; wired clients have no byte source
(``unavailable``/``no_wired_client_source``) and only show the port the
bridge FDB last saw them on. Which part of the WAN traffic a client caused
is ``unavailable``/``needs_flow_source`` (NAT, see ``traffic_accounting``).

**Roaming.** Each association ``(router_id, radio_id)`` is its own point
with its own baseline (``traffic_counters``): no delta crosses an AP. The
client totals add only the valid deltas of the association that counts
(``traffic_accounting`` marks the others ``stale_source``). A change of
association is a ``roaming_gap``: the bytes between the last read at the
old AP and the roam are lost, the totals become ``partial`` with that
reason and the current rate is None until the new AP gave a valid delta.

**Time windows** (1 h, 24 h, 7 d, 30 d) come from the history store
(Phase I) through :class:`ClientWindowSource`; until it exists every window
is ``unavailable``/``history_not_built`` (never 0).

**Bounds.** Wi-Fi and wired clients have separate hard caps, both separate
from the infrastructure points. A full table lets a client idle for more
than 24 h make room; an active client is never displaced; a refused one is
counted (``dropped_wifi_clients`` / ``dropped_wired_clients``).
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from .traffic_accounting import Availability, wan_client_attribution
from .traffic_collect import Snapshot, WiredSighting
from .traffic_const import (
    BASELINE_TTL_S,
    CLIENT_POINT_IDLE_S,
    CLIENT_VALUE_KIND,
    CLIENT_WINDOWS,
    IDENTITY_MAC_ONLY,
    IDENTITY_REGISTRY,
    IDENTITY_REGISTRY_MISSING,
    IDENTITY_UNCONFIRMED,
    LINK_WIFI,
    LINK_WIRED,
    LOCATION_FDB,
    LOCATION_REGISTRY,
    LOCATION_STATION,
    MAX_TRACKED_WIFI_CLIENTS,
    MAX_TRACKED_WIRED_CLIENTS,
    REASON_HISTORY_NOT_BUILT,
    REASON_NO_COVERED_TIME,
    REASON_NO_LOCATION,
    REASON_NO_RATE_YET,
    REASON_NO_WIFI_VLAN_MAPPING,
    REASON_PORT_VLAN_AMBIGUOUS,
    REASON_PORT_VLAN_UNKNOWN,
)
from .traffic_model import (
    RATE_QUALITIES,
    Coverage,
    CoverageReason,
    Perspective,
    Quality,
    Rate,
    RegistryFacts,
    Scope,
    valid_router_id,
)

_LOGGER = logging.getLogger(__name__)

# Live states of the client history in which its AP is current.
_LOCATED_STATES = frozenset({"online", "grace"})


# --- registry (read only) -------------------------------------------------------------


def registry_lookup(
    history: Any, router_id_of_entry: Callable[[str], str | None]
) -> Callable[[str], RegistryFacts]:
    """A lookup MAC -> :class:`RegistryFacts` over the client history.

    ``history`` is ``client_engine``'s ``ClientHistory`` (only ``live`` is
    used); its AP is an entry id, ``router_id_of_entry`` turns it into the
    core ``router_id``. A failing lookup is "not known", never an error.
    """

    def lookup(mac: str) -> RegistryFacts:
        try:
            live = history.live(mac)
        except Exception as err:  # noqa: BLE001 - the registry stays optional
            _LOGGER.debug("Client registry read failed (%s)", type(err).__name__)
            return RegistryFacts(known=False)
        if live is None:
            return RegistryFacts(known=False)
        state = getattr(live, "state", None)
        state = state if isinstance(state, str) else None
        band = getattr(live, "band", None)
        router_id: str | None = None
        ap = getattr(live, "ap", None)
        if state in _LOCATED_STATES and isinstance(ap, str) and ap:
            try:
                found = router_id_of_entry(ap)
            except Exception:  # noqa: BLE001 - unknown entry: no location
                found = None
            router_id = found if valid_router_id(found) else None
        return RegistryFacts(
            known=True,
            state=state,
            router_id=router_id,
            band=band if isinstance(band, str) else None,
        )

    return lookup


@dataclass(frozen=True, slots=True)
class StationFacts:
    """Per station of a snapshot: randomised MAC and the registry's answer."""

    private_mac: bool | None
    registry: RegistryFacts | None


def station_facts(snapshot: Snapshot) -> dict[str, StationFacts]:
    """``client_ref`` -> facts of every station of ``snapshot``."""
    return {
        s.client_ref: StationFacts(s.private_mac, s.registry)
        for s in snapshot.stations or ()
    }


def registry_routers(facts: Mapping[str, StationFacts]) -> dict[str, str | None]:
    """``client_ref`` -> router the registry names as current (accounting)."""
    return {
        ref: f.registry.router_id
        for ref, f in facts.items()
        if f.registry is not None and f.registry.router_id is not None
    }


def identity_of(private_mac: bool | None, registry: RegistryFacts | None) -> str:
    """How sure the identity is (no merge in any case)."""
    if registry is not None and registry.known:
        return IDENTITY_REGISTRY
    if private_mac:
        return IDENTITY_UNCONFIRMED
    if registry is None:
        return IDENTITY_REGISTRY_MISSING
    return IDENTITY_MAC_ONLY


# --- time windows (filled by Phase I) ---------------------------------------------------


@dataclass(frozen=True, slots=True)
class WindowTotals:
    """Bytes of one client over one window, as the history store has them."""

    down_bytes: int | None
    up_bytes: int | None
    covered_s: float
    coverage: Coverage
    coverage_reasons: tuple[str, ...] = ()


class ClientWindowSource(Protocol):
    """What Phase I implements: totals per client and window (None: none)."""

    def client_window(self, client_ref: str, window_s: int) -> WindowTotals | None:
        """Totals of ``client_ref`` over the last ``window_s`` seconds."""


class NoClientHistory:
    """The window source until the history store exists: nothing, ever."""

    def client_window(self, client_ref: str, window_s: int) -> WindowTotals | None:
        """Always None (``history_not_built``)."""
        return None


def window_values(
    source: ClientWindowSource, client_ref: str, *, wifi: bool
) -> dict[str, dict[str, Any]]:
    """The four windows of a client; missing totals are ``unavailable``.

    A Wi-Fi window is never better than ``partial``/``station_counters_only``
    whatever the source says.
    """
    out: dict[str, dict[str, Any]] = {}
    for name, seconds in CLIENT_WINDOWS.items():
        totals = None
        if wifi:
            try:
                totals = source.client_window(client_ref, seconds)
            except Exception as err:  # noqa: BLE001 - history optional
                _LOGGER.debug("Client window read failed (%s)", type(err).__name__)
        if not isinstance(totals, WindowTotals):
            reason = (
                REASON_HISTORY_NOT_BUILT
                if wifi
                else CoverageReason.NO_WIRED_CLIENT_SOURCE.value
            )
            out[name] = {
                "window_s": seconds,
                "down_bytes": None,
                "up_bytes": None,
                "coverage": Coverage.UNAVAILABLE.value,
                "reasons": [reason],
            }
            continue
        coverage = totals.coverage
        reasons = set(totals.coverage_reasons)
        if coverage is Coverage.FULL:
            coverage = Coverage.PARTIAL
        reasons.add(CoverageReason.STATION_COUNTERS_ONLY.value)
        out[name] = {
            "window_s": seconds,
            "down_bytes": totals.down_bytes,
            "up_bytes": totals.up_bytes,
            "coverage": coverage.value,
            "reasons": sorted(reasons),
        }
    return out


# --- tracker ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Client:
    """Counters of one client (memory only; ``client_ref`` is its only id)."""

    client_ref: str
    link: str
    first_mono: float
    last_mono: float
    identity: str
    router_id: str | None = None
    radio_id: str | None = None
    location_source: str | None = None
    port: str | None = None
    last_rate: Rate | None = None
    last_wall: float | None = None
    down_bytes: int = 0
    up_bytes: int = 0
    covered_s: float = 0.0
    max_down_bps: float | None = None
    max_up_bps: float | None = None
    valid_rates: int = 0
    direction_missing: int = 0
    roaming_gaps: int = 0
    pending_roam: bool = False
    interruptions: int = 0
    stale_sightings: int = 0
    interruption_reasons: Counter[str] = field(default_factory=Counter)


@dataclass(frozen=True, slots=True)
class ClientTrafficView:
    """What the panel and later sensors show of one client.

    Every value that is None has its reason in ``unavailable``. Rates are
    bit/s, sums bytes, both from the client's side (download = what the AP
    sent to the client).
    """

    client_ref: str
    link: str
    identity: str
    value_kind: str | None
    perspective: Perspective | None
    router_id: str | None
    radio_id: str | None
    location_source: str | None
    port: str | None
    down_bps: float | None
    up_bps: float | None
    down_bytes: int | None
    up_bytes: int | None
    covered_s: float
    avg_down_bps: float | None
    avg_up_bps: float | None
    max_down_bps: float | None
    max_up_bps: float | None
    vlan_id: int | None
    coverage: Coverage
    coverage_reasons: tuple[str, ...]
    windows: Mapping[str, Mapping[str, Any]]
    wan_attribution: Availability
    roaming_gaps: int
    interruptions: int
    stale_sightings: int
    last_seen_wall: float | None
    unavailable: Mapping[str, str]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (pseudonyms only)."""
        return {
            "client_ref": self.client_ref,
            "link": self.link,
            "identity": self.identity,
            "value_kind": self.value_kind,
            "perspective": None if self.perspective is None else self.perspective.value,
            "router_id": self.router_id,
            "radio_id": self.radio_id,
            "location_source": self.location_source,
            "port": self.port,
            "down_bps": self.down_bps,
            "up_bps": self.up_bps,
            "down_bytes": self.down_bytes,
            "up_bytes": self.up_bytes,
            "covered_s": self.covered_s,
            "avg_down_bps": self.avg_down_bps,
            "avg_up_bps": self.avg_up_bps,
            "max_down_bps": self.max_down_bps,
            "max_up_bps": self.max_up_bps,
            "vlan_id": self.vlan_id,
            "coverage": self.coverage.value,
            "coverage_reasons": list(self.coverage_reasons),
            "windows": {k: dict(v) for k, v in self.windows.items()},
            "wan_attribution": self.wan_attribution.to_dict(),
            "roaming_gaps": self.roaming_gaps,
            "interruptions": self.interruptions,
            "stale_sightings": self.stale_sightings,
            "last_seen_wall": self.last_seen_wall,
            "unavailable": dict(self.unavailable),
        }


def _vlan_of_port(
    port_vlans: Mapping[str, tuple[int, ...]] | None, port: str | None
) -> tuple[int | None, str | None]:
    if port_vlans is None or port is None or port not in port_vlans:
        return None, REASON_PORT_VLAN_UNKNOWN
    vids = port_vlans[port]
    if len(vids) == 1:
        return vids[0], None
    if not vids:
        return None, REASON_PORT_VLAN_UNKNOWN
    return None, REASON_PORT_VLAN_AMBIGUOUS


class ClientTracker:
    """Per-client counters fed with accounted station rates (bounded)."""

    def __init__(
        self,
        *,
        max_wifi: int = MAX_TRACKED_WIFI_CLIENTS,
        max_wired: int = MAX_TRACKED_WIRED_CLIENTS,
        idle_s: float = CLIENT_POINT_IDLE_S,
    ) -> None:
        """Empty tracker."""
        self._max = {LINK_WIFI: max_wifi, LINK_WIRED: max_wired}
        self._idle_s = idle_s
        self._tables: dict[str, dict[str, _Client]] = {LINK_WIFI: {}, LINK_WIRED: {}}
        self.windows: ClientWindowSource = NoClientHistory()
        self.counters: dict[str, int] = {
            "dropped_wifi_clients": 0,
            "dropped_wired_clients": 0,
            "replaced_clients": 0,
            "pruned_clients": 0,
            "roaming_gaps": 0,
            "stale_sightings": 0,
        }

    # -- size -----------------------------------------------------------------------

    def __len__(self) -> int:
        """Tracked clients (Wi-Fi and wired)."""
        return sum(len(t) for t in self._tables.values())

    @property
    def wifi_count(self) -> int:
        """Tracked Wi-Fi clients."""
        return len(self._tables[LINK_WIFI])

    @property
    def wired_count(self) -> int:
        """Tracked wired clients."""
        return len(self._tables[LINK_WIRED])

    def is_wifi(self, client_ref: str) -> bool:
        """True if ``client_ref`` is tracked as a Wi-Fi client."""
        return client_ref in self._tables[LINK_WIFI]

    def refs(self) -> list[str]:
        """Every tracked ``client_ref`` (sorted)."""
        return sorted(ref for t in self._tables.values() for ref in t)

    # -- admission ----------------------------------------------------------------------

    def _admit(
        self, link: str, client_ref: str, now: float, identity: str
    ) -> _Client | None:
        table = self._tables[link]
        entry = table.get(client_ref)
        if entry is not None:
            return entry
        if len(table) >= self._max[link]:
            idle = [
                (c.last_mono, ref)
                for ref, c in table.items()
                if now - c.last_mono > self._idle_s
            ]
            if not idle:
                self.counters[f"dropped_{link}_clients"] += 1
                return None
            del table[min(idle)[1]]
            self.counters["replaced_clients"] += 1
        entry = table[client_ref] = _Client(client_ref, link, now, now, identity)
        return entry

    # -- feeding ----------------------------------------------------------------------------

    def observe(
        self,
        rates: Iterable[Rate],
        facts: Mapping[str, StationFacts],
        now: float,
    ) -> list[tuple[str, str | None, str | None]]:
        """Take the accounted station rates of one snapshot (or extra call).

        Returns the associations a client left in this call (roams) as
        ``(client_ref, router_id, radio_id)``: the engine drops their
        baselines, so a return to the old AP starts a new baseline.
        """
        ended: list[tuple[str, str | None, str | None]] = []
        for rate in rates:
            point = rate.point
            ref = point.client_ref
            if point.scope is not Scope.STATION or ref is None:
                continue
            fact = facts.get(ref)
            identity = identity_of(
                None if fact is None else fact.private_mac,
                None if fact is None else fact.registry,
            )
            self._tables[LINK_WIRED].pop(ref, None)  # seen on Wi-Fi: not wired
            client = self._admit(LINK_WIFI, ref, now, identity)
            if client is None:
                continue
            if fact is not None:
                client.identity = identity
            left = self._observe_rate(client, rate, fact, now)
            if left is not None:
                ended.append((ref, *left))
        return ended

    def _observe_rate(
        self, client: _Client, rate: Rate, fact: StationFacts | None, now: float
    ) -> tuple[str | None, str | None] | None:
        client.last_mono = now
        if rate.wall_s is not None:
            client.last_wall = rate.wall_s
        point = rate.point
        if rate.quality is Quality.STALE_SOURCE:
            client.stale_sightings += 1
            self.counters["stale_sightings"] += 1
            return None
        assoc = (point.router_id, point.radio_id)
        left: tuple[str | None, str | None] | None = None
        if client.router_id is not None and assoc != (
            client.router_id,
            client.radio_id,
        ):
            left = (client.router_id, client.radio_id)
            client.roaming_gaps += 1
            client.pending_roam = True
            self.counters["roaming_gaps"] += 1
        client.router_id, client.radio_id = assoc
        registry = None if fact is None else fact.registry
        client.location_source = (
            LOCATION_REGISTRY
            if registry is not None and registry.router_id == point.router_id
            else LOCATION_STATION
        )
        client.last_rate = rate
        if rate.quality not in RATE_QUALITIES:
            if rate.quality is not Quality.FIRST_SAMPLE:
                client.interruptions += 1
                client.interruption_reasons[rate.quality.value] += 1
            return left
        client.pending_roam = False
        client.valid_rates += 1
        down, up = rate.tx_delta, rate.rx_delta  # station view, turned
        if down is None or up is None:
            client.direction_missing += 1
        client.down_bytes += down or 0
        client.up_bytes += up or 0
        client.covered_s += rate.interval_s or 0.0
        if rate.tx_bps is not None:
            client.max_down_bps = max(client.max_down_bps or 0.0, rate.tx_bps)
        if rate.rx_bps is not None:
            client.max_up_bps = max(client.max_up_bps or 0.0, rate.rx_bps)
        return left

    def observe_wired(
        self, router_id: str, sightings: Iterable[WiredSighting], now: float
    ) -> None:
        """Take the FDB sightings of one router (skipping Wi-Fi clients)."""
        wifi = self._tables[LINK_WIFI]
        for sighting in sightings:
            ref = sighting.client_ref
            if ref in wifi:
                continue
            identity = identity_of(sighting.private_mac, None)
            if identity == IDENTITY_REGISTRY_MISSING:
                # Entscheidung: the client engine knows Wi-Fi clients only
                # (wish W8); a wired MAC is never "registry missing".
                identity = IDENTITY_MAC_ONLY
            client = self._admit(LINK_WIRED, ref, now, identity)
            if client is None:
                continue
            client.identity = identity
            client.last_mono = now
            client.router_id = router_id
            client.port = sighting.port
            client.location_source = LOCATION_FDB

    # -- maintenance --------------------------------------------------------------------------

    def prune(self, now: float, ttl_s: float = BASELINE_TTL_S) -> int:
        """Forget clients not seen for ``ttl_s``; returns how many."""
        gone = 0
        for table in self._tables.values():
            for ref in [r for r, c in table.items() if now - c.last_mono > ttl_s]:
                del table[ref]
                gone += 1
        self.counters["pruned_clients"] += gone
        return gone

    def drop_router(self, router_id: str) -> None:
        """Forget the clients last located at an unloaded router."""
        for table in self._tables.values():
            for ref in [r for r, c in table.items() if c.router_id == router_id]:
                del table[ref]

    def clear(self) -> None:
        """Forget every client (module switched off); counters stay."""
        for table in self._tables.values():
            table.clear()

    # -- reading ------------------------------------------------------------------------------

    def view(
        self,
        client_ref: str,
        *,
        port_vlans: Mapping[str, Mapping[str, tuple[int, ...]]] | None = None,
    ) -> ClientTrafficView | None:
        """View of one tracked client (None: not tracked).

        ``port_vlans``: ``router_id`` -> port -> configured VLANs (wired
        clients only).
        """
        client = self._tables[LINK_WIFI].get(client_ref) or self._tables[
            LINK_WIRED
        ].get(client_ref)
        if client is None:
            return None
        if client.link == LINK_WIRED:
            return self._wired_view(client, port_vlans)
        return self._wifi_view(client)

    def views(
        self,
        *,
        port_vlans: Mapping[str, Mapping[str, tuple[int, ...]]] | None = None,
    ) -> list[ClientTrafficView]:
        """Views of every tracked client (sorted by ``client_ref``)."""
        out = []
        for ref in self.refs():
            view = self.view(ref, port_vlans=port_vlans)
            if view is not None:
                out.append(view)
        return out

    def _wifi_view(self, c: _Client) -> ClientTrafficView:
        unavailable: dict[str, str] = {}
        rate = c.last_rate
        down_bps = up_bps = None
        if rate is not None and rate.quality in RATE_QUALITIES:
            down_bps, up_bps = rate.tx_bps, rate.rx_bps
            if down_bps is None:
                unavailable["down_bps"] = Quality.SOURCE_MISSING.value
            if up_bps is None:
                unavailable["up_bps"] = Quality.SOURCE_MISSING.value
        else:
            if c.pending_roam:
                reason = CoverageReason.ROAMING_GAP.value
            elif rate is None:
                reason = REASON_NO_RATE_YET
            else:
                reason = rate.quality.value
            unavailable["down_bps"] = unavailable["up_bps"] = reason
        down_bytes: int | None = c.down_bytes
        up_bytes: int | None = c.up_bytes
        avg_down = avg_up = None
        if c.valid_rates == 0:
            down_bytes = up_bytes = None
            for name in ("down_bytes", "up_bytes"):
                unavailable[name] = REASON_NO_RATE_YET
        if c.covered_s > 0:
            avg_down = c.down_bytes * 8 / c.covered_s
            avg_up = c.up_bytes * 8 / c.covered_s
        else:
            unavailable["avg_down_bps"] = unavailable["avg_up_bps"] = (
                REASON_NO_COVERED_TIME
            )
        if c.max_down_bps is None:
            unavailable["max_down_bps"] = REASON_NO_RATE_YET
        if c.max_up_bps is None:
            unavailable["max_up_bps"] = REASON_NO_RATE_YET
        if c.router_id is None:
            unavailable["router_id"] = REASON_NO_LOCATION
        unavailable["vlan_id"] = REASON_NO_WIFI_VLAN_MAPPING
        reasons = {CoverageReason.STATION_COUNTERS_ONLY.value}
        if c.roaming_gaps:
            reasons.add(CoverageReason.ROAMING_GAP.value)
        attribution = wan_client_attribution()
        unavailable["wan_attribution"] = attribution.reason or ""
        return ClientTrafficView(
            client_ref=c.client_ref,
            link=c.link,
            identity=c.identity,
            value_kind=CLIENT_VALUE_KIND,
            perspective=Perspective.STATION,
            router_id=c.router_id,
            radio_id=c.radio_id,
            location_source=c.location_source,
            port=None,
            down_bps=down_bps,
            up_bps=up_bps,
            down_bytes=down_bytes,
            up_bytes=up_bytes,
            covered_s=c.covered_s,
            avg_down_bps=avg_down,
            avg_up_bps=avg_up,
            max_down_bps=c.max_down_bps,
            max_up_bps=c.max_up_bps,
            vlan_id=None,
            coverage=Coverage.PARTIAL if c.valid_rates else Coverage.UNAVAILABLE,
            coverage_reasons=tuple(sorted(reasons)),
            windows=window_values(self.windows, c.client_ref, wifi=True),
            wan_attribution=attribution,
            roaming_gaps=c.roaming_gaps,
            interruptions=c.interruptions,
            stale_sightings=c.stale_sightings,
            last_seen_wall=c.last_wall,
            unavailable=unavailable,
        )

    def _wired_view(
        self,
        c: _Client,
        port_vlans: Mapping[str, Mapping[str, tuple[int, ...]]] | None,
    ) -> ClientTrafficView:
        reason = CoverageReason.NO_WIRED_CLIENT_SOURCE.value
        unavailable = dict.fromkeys(
            (
                "down_bps",
                "up_bps",
                "down_bytes",
                "up_bytes",
                "avg_down_bps",
                "avg_up_bps",
                "max_down_bps",
                "max_up_bps",
            ),
            reason,
        )
        router_vlans = (
            None
            if port_vlans is None or c.router_id is None
            else port_vlans.get(c.router_id)
        )
        vlan_id, vlan_reason = _vlan_of_port(router_vlans, c.port)
        if vlan_reason is not None:
            unavailable["vlan_id"] = vlan_reason
        unavailable["radio_id"] = reason
        attribution = wan_client_attribution()
        unavailable["wan_attribution"] = attribution.reason or ""
        return ClientTrafficView(
            client_ref=c.client_ref,
            link=c.link,
            identity=c.identity,
            value_kind=None,
            perspective=None,
            router_id=c.router_id,
            radio_id=None,
            location_source=c.location_source,
            port=c.port,
            down_bps=None,
            up_bps=None,
            down_bytes=None,
            up_bytes=None,
            covered_s=0.0,
            avg_down_bps=None,
            avg_up_bps=None,
            max_down_bps=None,
            max_up_bps=None,
            vlan_id=vlan_id,
            coverage=Coverage.UNAVAILABLE,
            coverage_reasons=(reason,),
            windows=window_values(self.windows, c.client_ref, wifi=False),
            wan_attribution=attribution,
            roaming_gaps=0,
            interruptions=0,
            stale_sightings=0,
            last_seen_wall=None,
            unavailable=unavailable,
        )

    def summary(self) -> dict[str, Any]:
        """Counts only (no client id)."""
        return {
            "wifi": self.wifi_count,
            "wired": self.wired_count,
            "limits": dict(self._max),
            **self.counters,
        }
