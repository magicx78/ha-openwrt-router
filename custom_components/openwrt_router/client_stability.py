"""Wi-Fi client stability (F4): associations, reconnects, sticky clients.

Pure functions and small state holders, no HA imports.

``usteer get_clients`` answers on every node with the fleet-wide view::

    {"<client mac>": {"hostapd.phy0-ap1": {"connected": true, "signal": -70},
                      "<ip>#hostapd.phy0-ap2": {"connected": false, "signal": -61}}}

Nodes without ``#`` belong to the router that answered, ``<ip>#…`` to other
usteer nodes. A client connected to a local node is *sticky* when another
router's node with the same band and SSID hears it at least STICKY_DELTA_DB
stronger (band/SSID per node from ``node_info``; unknown nodes are compared
anyway).
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from typing import Any

STICKY_DELTA_DB = 8
# A client must stay sticky (or weak, without usteer) this long to count.
STICKY_HOLD_SECONDS = 10 * 60
# Without usteer: signal at or below this is "weak"
WEAK_SIGNAL_DBM = -75
# A connect within this time after a disconnect of the same client on the
# same router counts as a reconnect (roaming to another router does not).
RECONNECT_WINDOW_SECONDS = 300
UNSTABLE_RECONNECTS = 3
TOP_CLIENTS = 10

_MAC_RE = re.compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


@dataclass(frozen=True)
class NodeSignal:
    """One usteer node's view of a client."""

    node: str
    local: bool
    connected: bool
    signal: int | None


def parse_usteer_clients(raw: Any) -> dict[str, list[NodeSignal]]:
    """Return {MAC (upper): [NodeSignal, …]}; broken entries are skipped."""
    out: dict[str, list[NodeSignal]] = {}
    if not isinstance(raw, dict):
        return out
    for mac, nodes in raw.items():
        if not isinstance(mac, str) or not _MAC_RE.fullmatch(mac):
            continue
        if not isinstance(nodes, dict):
            continue
        seen: list[NodeSignal] = []
        for node, info in nodes.items():
            if not isinstance(node, str) or not isinstance(info, dict):
                continue
            signal = info.get("signal")
            if (
                not isinstance(signal, int)
                or isinstance(signal, bool)
                or not -120 <= signal < 0
            ):
                signal = None
            seen.append(
                NodeSignal(
                    node=node,
                    local="#" not in node,
                    connected=info.get("connected") is True,
                    signal=signal,
                )
            )
        if seen:
            out[mac.upper()] = seen
    return out


def iface_band(iface: dict[str, Any]) -> str | None:
    """Band of an AP interface: from the frequency, else its ``band`` key."""
    freq = iface.get("frequency")
    if isinstance(freq, int) and not isinstance(freq, bool) and freq > 0:
        if freq < 3000:
            return "2.4g"
        return "6g" if freq >= 5925 else "5g"
    band = iface.get("band")
    return band if band in ("2.4g", "5g", "6g") else None


def sticky_candidates(
    parsed: dict[str, list[NodeSignal]],
    node_info: dict[str, tuple[str | None, str | None]] | None = None,
    min_delta: int = STICKY_DELTA_DB,
) -> dict[str, dict[str, Any]]:
    """Clients on a local node that another router hears >= min_delta stronger.

    Other SSIDs/radios of the same router are not an alternative: the client
    would stay on the same access point. ``node_info`` maps usteer node names
    to (band, ssid); a remote node only counts with the same band and SSID
    as the client's node, unless one of them is unknown.
    """
    info = node_info or {}
    result: dict[str, dict[str, Any]] = {}
    for mac, seen in parsed.items():
        current = next(
            (s for s in seen if s.connected and s.local and s.signal is not None), None
        )
        if current is None:
            continue
        own = info.get(current.node)
        remote = [
            s
            for s in seen
            if not s.local
            and s.signal is not None
            and _comparable(own, info.get(s.node))
        ]
        if not remote:
            continue
        best = max(remote, key=lambda s: s.signal or -999)
        delta = (best.signal or 0) - (current.signal or 0)
        if delta >= min_delta:
            result[mac] = {
                "signal": current.signal,
                "interface": current.node.removeprefix("hostapd."),
                "better_node": best.node,
                "better_signal": best.signal,
                "delta_db": delta,
            }
    return result


def _comparable(
    own: tuple[str | None, str | None] | None,
    other: tuple[str | None, str | None] | None,
) -> bool:
    if own is None or other is None:
        return True
    return all(
        a is None or b is None or a == b for a, b in zip(own, other, strict=True)
    )


class HoldTimer:
    """Track since when each key fulfils a condition."""

    def __init__(self) -> None:
        self._since: dict[str, int] = {}

    def update(self, keys: set[str] | dict[str, Any], now_ms: int) -> None:
        """Keys that hold now keep (or start) their timer, others are dropped."""
        self._since = {k: self._since.get(k, now_ms) for k in keys}

    def held(self, now_ms: int, hold_seconds: int) -> dict[str, int]:
        """Return {key: since_ms} for keys held at least hold_seconds."""
        return {
            k: t for k, t in self._since.items() if now_ms - t >= hold_seconds * 1000
        }


class AssociationTracker:
    """Per-client associations and reconnects over a sliding window."""

    def __init__(
        self,
        window_ms: int = 24 * 3600 * 1000,
        reconnect_ms: int = RECONNECT_WINDOW_SECONDS * 1000,
        max_items: int = 20000,
    ) -> None:
        self.window_ms = window_ms
        self.reconnect_ms = reconnect_ms
        self._items: deque[tuple[int, str, bool]] = deque(maxlen=max_items)
        self._last_disconnect: dict[str, tuple[int, str | None]] = {}

    def connected(self, mac: str, time_ms: int, interface: str | None = None) -> None:
        """A reconnect is a connect to the same interface shortly after a
        disconnect from it; band steering to another radio is not."""
        last = self._last_disconnect.pop(mac, None)
        reconnect = (
            last is not None
            and 0 <= time_ms - last[0] <= self.reconnect_ms
            and (interface is None or last[1] is None or interface == last[1])
        )
        self._items.append((time_ms, mac, reconnect))

    def disconnected(
        self, mac: str, time_ms: int, interface: str | None = None
    ) -> None:
        self._last_disconnect[mac] = (time_ms, interface)

    def counts(self, now_ms: int) -> dict[str, dict[str, int]]:
        """Return {mac: {"associations_24h", "reconnects_24h"}}."""
        cutoff = now_ms - self.window_ms
        while self._items and self._items[0][0] < cutoff:
            self._items.popleft()
        self._last_disconnect = {
            m: t for m, t in self._last_disconnect.items() if t[0] >= cutoff
        }
        out: dict[str, dict[str, int]] = {}
        for time_ms, mac, reconnect in self._items:
            if time_ms < cutoff:
                continue
            entry = out.setdefault(mac, {"associations_24h": 0, "reconnects_24h": 0})
            entry["associations_24h"] += 1
            if reconnect:
                entry["reconnects_24h"] += 1
        return out


def unstable_top(
    counts: dict[str, dict[str, int]], limit: int = TOP_CLIENTS
) -> list[dict[str, Any]]:
    """Clients with at least one reconnect, most reconnects first."""
    ranked = sorted(
        ((mac, c) for mac, c in counts.items() if c["reconnects_24h"] > 0),
        key=lambda mc: (-mc[1]["reconnects_24h"], -mc[1]["associations_24h"], mc[0]),
    )
    return [{"mac": mac, **c} for mac, c in ranked[:limit]]
