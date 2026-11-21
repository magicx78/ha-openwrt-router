"""WiFi RF Intelligence and Client Stability (release 1.48.0, part 2, Q5).

Read only, both ways, no second client database:

- RF reads the client history of Client Stability through its public
  reads (``history.live``, ``history.ring``, ``history.recent_bucket``):
  disconnects and the mean send rate of a client go into the RF client
  window (``rf_clients.ClientRfWindow``), AP/band changes into the roaming
  analysis (``rf_roaming``). Unknown stays unknown: a client the history
  has not watched for most of the window has no disconnect count (never
  0), a client without rate samples no rate.
- Client Stability gets a busy channel only as a hint (:func:`rf_hint`,
  shown next to a client's last disconnect, with source and measurement
  time). A full channel is no infrastructure cause: it never marks a
  disconnect as infrastructure, never excuses one and never changes a
  Client Stability score.

DECIDED: retry rate and connected time stay in RF. Client Stability has no
clean extension point for them (its observations and buckets are a stored
format), so they are not passed on.
"""

from __future__ import annotations

import itertools
import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .rf_conflicts import DEFAULT_THRESHOLDS, RadioRef
from .rf_models import CapabilityState
from .rf_roaming import (
    ClientRoamWindow,
    RoamEvent,
    RoamStatus,
    detect_flapping,
    roaming_quality,
)

_LOGGER = logging.getLogger(__name__)

SOURCE_CLIENT_HISTORY: Final = "client_history"
# The history must have watched a client this share of the window before
# its disconnect count is a measurement (the event ring starts empty after
# a restart).
WATCHED_SHARE: Final = 0.75
# A busy channel counts as a hint for a disconnect this close to the
# channel measurement.
HINT_MAX_AGE_S: Final = 900.0
# Roaming score below this is a roaming problem (rf_roaming scores 0..100).
POOR_ROAMING_SCORE: Final = 50.0
ROAMING_WINDOW_S: Final = 3600.0


@dataclass(frozen=True)
class ClientHistoryFacts:
    """What RF takes from the client history for one client window."""

    disconnects: int | None
    rate_tx_mean: float | None  # kbit/s


ClientFactsLookup = Callable[[str], ClientHistoryFacts | None]


def history_of(hass: Any) -> Any:
    """The running client history (read only), or None."""
    from .client_engine import async_get_client_engine

    cs = async_get_client_engine(hass)
    return getattr(cs, "history", None) if cs is not None else None


# --- client window ------------------------------------------------------------------


def client_facts(
    history: Any, mac: str, router: str, now: float, window_s: float
) -> ClientHistoryFacts | None:
    """Disconnects and send rate of ``mac`` on ``router`` in the window."""
    if history.live(mac) is None:
        return None
    ring = history.ring(mac)
    start = now - window_s
    watched = bool(ring) and ring[0].ts <= now - WATCHED_SHARE * window_s
    disconnects = None
    if watched:
        bucket = history.recent_bucket(mac, start, now)
        # a client leaving and an infrastructure event are no RF problem
        disconnects = bucket.dc_error + bucket.dc_inactivity + bucket.dc_unknown
    rates = [
        e.rate_tx_kbit
        for e in ring
        if start <= e.ts <= now and e.ap == router and e.rate_tx_kbit is not None
    ]
    rate = sum(rates) / len(rates) if rates else None
    return ClientHistoryFacts(disconnects, rate)


def client_facts_lookup(
    hass: Any, router: str, now: float, window_s: float
) -> ClientFactsLookup | None:
    """Per-MAC lookup for one router's RF evaluation; None without history."""
    try:
        history = history_of(hass)
    except Exception:  # the RF evaluation runs on without it
        _LOGGER.debug("WiFi RF: client history unavailable", exc_info=True)
        return None
    if history is None:
        return None

    def lookup(mac: str) -> ClientHistoryFacts | None:
        try:
            return client_facts(history, mac, router, now, window_s)
        except Exception as err:  # noqa: BLE001 - one client, unknown
            _LOGGER.debug("WiFi RF: client facts failed (%s)", type(err).__name__)
            return None

    return lookup


# --- roaming ------------------------------------------------------------------------


def _resolver(center: Any) -> Callable[[str, str | None], RadioRef | None]:
    """(entry id, band) -> the one RF radio of that band; None if not unique."""
    by_router: dict[str, str] = {
        entry_id: state.router_id
        for entry_id, state in center.routers.items()
        if state.options.enabled and state.router_id is not None
    }
    bands: dict[tuple[str, str], list[RadioRef]] = {}
    for ref, result in center.results.items():
        bands.setdefault((ref.router_id, result.radio.band), []).append(ref)

    def resolve(entry_id: str, band: str | None) -> RadioRef | None:
        router_id = by_router.get(entry_id)
        refs = bands.get((router_id, band), []) if router_id and band else []
        return refs[0] if len(refs) == 1 else None

    return resolve


def roam_events(
    history: Any,
    mac: str,
    resolve: Callable[[str, str | None], RadioRef | None],
    now: float,
    window_s: float = ROAMING_WINDOW_S,
) -> list[RoamEvent]:
    """AP/band changes of ``mac`` in the window from the history's samples.

    A change between two samples whose radios are not both known (RF off
    on a router, two radios in the band) is left out, not guessed.
    """
    samples = [e for e in history.ring(mac) if now - window_s <= e.ts <= now and e.ap]
    out: list[RoamEvent] = []
    for prev, cur in itertools.pairwise(samples):
        if (prev.ap, prev.band) == (cur.ap, cur.band):
            continue
        src, dst = resolve(prev.ap, prev.band), resolve(cur.ap, cur.band)
        if src is None or dst is None or src == dst:
            continue
        out.append(
            RoamEvent(
                client_mac=mac,
                ts=cur.ts,
                from_radio=src,
                to_radio=dst,
                from_band=prev.band,
                to_band=cur.band,
                rssi_before=prev.rssi,
                rssi_after=cur.rssi,
                gap_s=None,  # samples are a poll apart: no measured gap
                handshake_failures=None,
                reauth=False,
            )
        )
    return out


@dataclass(frozen=True)
class RoamingProblems:
    """Fleet roaming problems (counts only, no client identity)."""

    count: int | None
    clients: int
    flapping: int
    poor: int
    roams: int
    source: str = SOURCE_CLIENT_HISTORY

    def as_dict(self) -> dict[str, Any]:
        """Plain attributes (no MAC, no SSID)."""
        return {
            "clients_checked": self.clients,
            "flapping_clients": self.flapping,
            "poor_roaming_clients": self.poor,
            "roams": self.roams,
            "source": self.source,
        }


def roaming_problems(
    center: Any, history: Any, macs: Sequence[str], now: float
) -> RoamingProblems:
    """Clients with flapping or a poor roaming score right now.

    ``count`` is None (unknown) without a client history: no data is no
    proof of good roaming.
    """
    if history is None:
        return RoamingProblems(None, 0, 0, 0, 0)
    resolve = _resolver(center)
    flapping = poor = roams = 0
    for mac in macs:
        events = roam_events(history, mac, resolve, now)
        roams += len(events)
        if not events:
            continue
        if detect_flapping(events):
            flapping += 1
            continue
        live = history.live(mac)
        online = (now - live.session_start) if live and live.session_start else 0.0
        window = ClientRoamWindow(
            client_mac=mac,
            window_s=ROAMING_WINDOW_S,
            online_s=max(0.0, min(ROAMING_WINDOW_S, online)),
            events=tuple(events),
            mobility=None,
        )
        score = roaming_quality(window)
        if score.status is RoamStatus.SCORED and (score.score or 0) < (
            POOR_ROAMING_SCORE
        ):
            poor += 1
    return RoamingProblems(flapping + poor, len(macs), flapping, poor, roams)


# --- the hint for Client Stability ------------------------------------------------------


def rf_hint(center: Any, entry_id: str, band: str | None, ts: float) -> dict | None:
    """A busy channel on the client's router and band near ``ts``; None if
    unknown, not busy, too far apart, RF off or not ready. Hint only."""
    if center is None or not center.enabled or center.status != "ready":
        return None
    state = center.routers.get(entry_id)
    if state is None or not state.options.enabled or state.router_id is None:
        return None
    found = [
        r
        for r in center.results.values()
        if r.ref.router_id == state.router_id and r.radio.band == band
    ]
    if len(found) != 1:
        return None
    result = found[0]
    metric = result.metrics.get("utilization")
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    if metric.measured_at is None or abs(metric.measured_at - ts) > HINT_MAX_AGE_S:
        return None
    sustained = bool(result.summary and result.summary.sustained_overload)
    value = float(metric.value)
    if value < DEFAULT_THRESHOLDS.high_utilization_pct and not sustained:
        return None
    return {
        "kind": "channel_busy",
        "hint_only": True,
        "radio_id": result.ref.radio_id,
        "band": band,
        "utilization_pct": round(value, 1),
        "sustained": sustained,
        "source": metric.source,
        "measured_at": metric.measured_at,
    }


def rf_hint_for_client(hass: Any, live: Any) -> dict | None:
    """:func:`rf_hint` for a client's last disconnect; never raises."""
    try:
        last = getattr(live, "last_disconnect", None)
        if last is None or not getattr(live, "ap", None):
            return None
        from .rf_center import async_get_rf_center

        return rf_hint(async_get_rf_center(hass), live.ap, live.band, last.ts)
    except Exception as err:  # noqa: BLE001 - a hint never breaks a view
        _LOGGER.debug("WiFi RF hint failed (%s)", type(err).__name__)
        return None


__all__ = [
    "ClientHistoryFacts",
    "RoamingProblems",
    "client_facts",
    "client_facts_lookup",
    "history_of",
    "rf_hint",
    "rf_hint_for_client",
    "roam_events",
    "roaming_problems",
]
