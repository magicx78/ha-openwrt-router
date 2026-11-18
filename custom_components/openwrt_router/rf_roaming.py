"""Roaming quality, flapping and sticky-client suspicion (pure, no HA).

Inputs are plain dataclasses that are filled later from Client Stability
(roam transitions, ``weak_share``, dwell time) and from usteer / 802.11k
beacon reports (signal of the same client at other APs). Client Stability's
``roam_burst`` counts roams per AP pair in 30 minutes; :func:`detect_flapping`
is stricter (strict A→B→A alternation) and adds the same-router band switch.

Roaming score parts and weights (:data:`WEIGHTS`, sum 1):

==============  ======  ==========================================================
part            weight  score (0..100)
==============  ======  ==========================================================
gap             0.25    share of roams without a long interruption (``gap_s``)
frequency       0.20    roams per 24 online hours above the free amount, e^-x
signal          0.25    share of classified roams that did not degrade RSSI
handshake       0.15    share of roams without failed authentication handshakes
continuity      0.15    share of roams outside a ping-pong flap
==============  ======  ==========================================================

A part without data is unknown: it is left out, the remaining weights are
renormalised and ``coverage`` (sum of known weights) says how much was seen.
Below ``min_coverage`` there is no score.

Unknown handshake data (``handshake_failures=None``) leaves the share; with no
known roam the handshake part is unknown. The part was called ``auth``:
the Core masks every name with a secret word (``auth``, contract #110), so
neither the part nor its counter would show a value.

Sticky: there is deliberately no "confirmed" status. Only a fresh comparable
measurement of the same client at another AP on the same known band
(``measured_same_client``) can give ``supported_by_measurement`` and name a
``better_radio``. A louder alternative on another or unknown band gives at
most ``suspected`` with ``alternative_other_band_not_comparable``.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from .client_stability import STICKY_DELTA_DB, STICKY_HOLD_SECONDS, WEAK_SIGNAL_DBM
from .rf_conflicts import RadioRef
from .rf_models import CapabilityState, Metric

_LOGGER = logging.getLogger(__name__)

PART_GAP = "gap"
PART_FREQUENCY = "frequency"
PART_SIGNAL = "signal"
PART_HANDSHAKE = "handshake"
PART_CONTINUITY = "continuity"

WEIGHTS: Mapping[str, float] = MappingProxyType(
    {
        PART_GAP: 0.25,
        PART_FREQUENCY: 0.20,
        PART_SIGNAL: 0.25,
        PART_HANDSHAKE: 0.15,
        PART_CONTINUITY: 0.15,
    }
)

BASIS_MEASURED = "measured_same_client"
BASIS_HISTORIC = "historic_same_client"
BASIS_NONE = "none"

_DAY = 86400.0


@dataclass(frozen=True)
class RoamThresholds:
    """Thresholds for roam classification, flapping and the score."""

    # RSSI change (dB) for improved/degraded. Startwert, nicht kalibriert.
    improve_db: float = 5.0
    # Interruption (s) above which a roam counts as long. Startwert.
    long_gap_s: float = 5.0
    # Ping-pong: at least this many strictly alternating switches between the
    # same two radios inside ``flap_window_s``. The window equals Client
    # Stability's FLAP_WINDOW_S (600 s); the count is a Startwert.
    flap_window_s: float = 600.0
    flap_min_switches: int = 4
    # Same-router band flapping (5 → 2.4 → 5). Startwerte.
    band_flap_window_s: float = 600.0
    band_flap_min_switches: int = 2
    # Roams per 24 online hours that cost nothing. Startwerte.
    free_roams_per_day: float = 24.0
    stationary_free_roams_per_day: float = 4.0
    # Scale of the exponential decay above the free amount.
    frequency_scale: float = 24.0
    # Minimum roams and part coverage before a score. Startwerte.
    min_events: int = 3
    min_coverage: float = 0.6


DEFAULT_ROAM_THRESHOLDS = RoamThresholds()


@dataclass(frozen=True)
class RoamEvent:
    """One roam of one client (from Client Stability transitions or NI)."""

    client_mac: str
    ts: float
    from_radio: RadioRef
    to_radio: RadioRef
    from_band: str | None
    to_band: str | None
    rssi_before: float | None
    rssi_after: float | None
    gap_s: float | None
    handshake_failures: int | None  # None: not known for this roam
    reauth: bool


@dataclass(frozen=True)
class ClientRoamWindow:
    """The roams of one client in one window plus its online time."""

    client_mac: str
    window_s: float
    online_s: float
    events: tuple[RoamEvent, ...]
    mobility: str | None


class RoamQuality(StrEnum):
    """Signal effect of one roam."""

    IMPROVED = "improved"
    DEGRADED = "degraded"
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RoamClass:
    """Classification of one roam; flags are None when unknown."""

    event: RoamEvent
    quality: RoamQuality
    delta_db: float | None
    long_gap: bool | None
    band_change: bool | None
    same_router_band_switch: bool
    evidence: tuple[str, ...]


def classify_roam(
    event: RoamEvent, thresholds: RoamThresholds = DEFAULT_ROAM_THRESHOLDS
) -> RoamClass:
    """Classify one roam by RSSI before/after, gap and band."""
    th = thresholds
    evidence = [f"roam:{event.from_radio}->{event.to_radio}"]
    delta = None
    quality = RoamQuality.UNKNOWN
    if event.rssi_before is not None and event.rssi_after is not None:
        delta = event.rssi_after - event.rssi_before
        evidence.append(f"rssi_delta:{delta:+g}dB")
        if delta >= th.improve_db:
            quality = RoamQuality.IMPROVED
        elif delta <= -th.improve_db:
            quality = RoamQuality.DEGRADED
        else:
            quality = RoamQuality.NEUTRAL
    else:
        evidence.append("rssi_unknown")
    long_gap = None if event.gap_s is None else event.gap_s > th.long_gap_s
    if event.gap_s is not None:
        evidence.append(f"gap:{event.gap_s:g}s")
    band_change = None
    if event.from_band is not None and event.to_band is not None:
        band_change = event.from_band != event.to_band
    same_router = event.from_radio.router_id == event.to_radio.router_id
    switch = bool(band_change) and same_router
    if switch:
        evidence.append(f"same_router_band_switch:{event.from_radio.router_id}")
    return RoamClass(
        event, quality, delta, long_gap, band_change, switch, tuple(evidence)
    )


# =====================================================================
# Flapping
# =====================================================================


class FlapKind(StrEnum):
    """Kind of flapping."""

    PING_PONG = "ping_pong"
    BAND_FLAPPING = "band_flapping"


@dataclass(frozen=True)
class Flap:
    """Back-and-forth between the same two radios inside a window."""

    kind: FlapKind
    client_mac: str
    pair: tuple[RadioRef, RadioRef]
    switches: int
    start: float
    end: float
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the flap as a plain dict."""
        return {
            "kind": self.kind.value,
            "client_mac": self.client_mac,
            "pair": [r.as_dict() for r in self.pair],
            "switches": self.switches,
            "start": self.start,
            "end": self.end,
            "evidence": list(self.evidence),
        }


def _alternating_runs(events: Sequence[RoamEvent]) -> list[list[RoamEvent]]:
    """Split time-ordered roams into runs of strict A→B→A alternation."""
    runs: list[list[RoamEvent]] = []
    for ev in events:
        if ev.from_radio == ev.to_radio:
            continue
        last = runs[-1][-1] if runs else None
        if (
            last is not None
            and ev.from_radio == last.to_radio
            and ev.to_radio == last.from_radio
        ):
            runs[-1].append(ev)
        else:
            runs.append([ev])
    return runs


def _densest(run: Sequence[RoamEvent], window_s: float) -> tuple[int, int, int]:
    """Return (count, first index, last index) of the densest window."""
    best = (0, 0, 0)
    lo = 0
    for hi, ev in enumerate(run):
        while ev.ts - run[lo].ts > window_s:
            lo += 1
        if hi - lo + 1 > best[0]:
            best = (hi - lo + 1, lo, hi)
    return best


def _ref_key(ref: RadioRef) -> tuple[str, str]:
    return ref.router_id, ref.radio_id


def _pair(ev: RoamEvent) -> tuple[RadioRef, RadioRef]:
    a, b = sorted((ev.from_radio, ev.to_radio), key=_ref_key)
    return a, b


def _flaps_of(
    events: Sequence[RoamEvent],
    kind: FlapKind,
    window_s: float,
    min_switches: int,
) -> list[Flap]:
    flaps = []
    for run in _alternating_runs(events):
        count, lo, hi = _densest(run, window_s)
        if count < min_switches:
            continue
        first = run[lo]
        evidence = [f"switches:{count}/{window_s:g}s"]
        if kind is FlapKind.BAND_FLAPPING:
            evidence.append(f"router:{first.from_radio.router_id}")
            evidence.append(f"bands:{first.from_band}<->{first.to_band}")
        flaps.append(
            Flap(
                kind,
                first.client_mac,
                _pair(first),
                count,
                first.ts,
                run[hi].ts,
                tuple(evidence),
            )
        )
    return flaps


def _is_band_switch(ev: RoamEvent) -> bool:
    return (
        ev.from_radio.router_id == ev.to_radio.router_id
        and ev.from_band is not None
        and ev.to_band is not None
        and ev.from_band != ev.to_band
    )


def detect_flapping(
    events: Sequence[RoamEvent], thresholds: RoamThresholds = DEFAULT_ROAM_THRESHOLDS
) -> list[Flap]:
    """Return ping-pong and same-router band flapping, per client.

    Single roams, roams through a third radio and slow back-and-forth
    (fewer than the minimum switches inside the window) are never flapping.
    """
    th = thresholds
    by_client: dict[str, list[RoamEvent]] = defaultdict(list)
    for ev in events:
        by_client[ev.client_mac].append(ev)
    flaps: list[Flap] = []
    for client in sorted(by_client):
        ordered = sorted(by_client[client], key=lambda e: e.ts)
        flaps.extend(
            _flaps_of(
                ordered, FlapKind.PING_PONG, th.flap_window_s, th.flap_min_switches
            )
        )
        band = [e for e in ordered if _is_band_switch(e)]
        flaps.extend(
            _flaps_of(
                band,
                FlapKind.BAND_FLAPPING,
                th.band_flap_window_s,
                th.band_flap_min_switches,
            )
        )
    return flaps


# =====================================================================
# Roaming quality
# =====================================================================


class RoamStatus(StrEnum):
    """Whether a roaming score exists."""

    SCORED = "scored"
    NOT_APPLICABLE = "not_applicable"  # no roams: nothing to judge
    INSUFFICIENT = "insufficient"  # too few roams or too little coverage


@dataclass(frozen=True)
class RoamPart:
    """One part of the roaming score; ``score`` None when unknown."""

    name: str
    score: float | None
    weight: float
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the part as a plain dict."""
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RoamingScore:
    """Roaming score of one client window."""

    client_mac: str
    status: RoamStatus
    score: float | None
    coverage: float
    parts: tuple[RoamPart, ...]
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        """Return the score as a plain dict."""
        return {
            "client_mac": self.client_mac,
            "status": self.status.value,
            "score": self.score,
            "coverage": self.coverage,
            "parts": [p.as_dict() for p in self.parts],
            "evidence": list(self.evidence),
        }


def _share_score(bad: int, total: int) -> float | None:
    return None if total == 0 else 100.0 * (1.0 - bad / total)


def _gap_part(classes: Sequence[RoamClass], th: RoamThresholds) -> RoamPart:
    known = [c for c in classes if c.long_gap is not None]
    long = sum(1 for c in known if c.long_gap)
    return RoamPart(
        PART_GAP,
        _share_score(long, len(known)),
        WEIGHTS[PART_GAP],
        (f"long_gaps:{long}/{len(known)}>{th.long_gap_s:g}s",),
    )


def _frequency_part(window: ClientRoamWindow, th: RoamThresholds) -> RoamPart:
    if window.online_s <= 0:
        return RoamPart(
            PART_FREQUENCY, None, WEIGHTS[PART_FREQUENCY], ("online_s_unknown",)
        )
    per_day = len(window.events) / window.online_s * _DAY
    free = (
        th.stationary_free_roams_per_day
        if window.mobility == "stationary"
        else th.free_roams_per_day
    )
    score = 100.0 * math.exp(-max(0.0, per_day - free) / th.frequency_scale)
    evidence = (f"roams_per_online_day:{per_day:.1f}", f"free_per_day:{free:g}")
    return RoamPart(PART_FREQUENCY, score, WEIGHTS[PART_FREQUENCY], evidence)


def _signal_part(classes: Sequence[RoamClass]) -> RoamPart:
    known = [c for c in classes if c.quality is not RoamQuality.UNKNOWN]
    degraded = sum(1 for c in known if c.quality is RoamQuality.DEGRADED)
    improved = sum(1 for c in known if c.quality is RoamQuality.IMPROVED)
    evidence = (
        f"improved:{improved}/{len(known)}",
        f"degraded:{degraded}/{len(known)}",
    )
    return RoamPart(
        PART_SIGNAL, _share_score(degraded, len(known)), WEIGHTS[PART_SIGNAL], evidence
    )


def _handshake_part(events: Sequence[RoamEvent]) -> RoamPart:
    """Share of roams without handshake failures; unknown roams leave the share."""
    known = [e.handshake_failures for e in events if e.handshake_failures is not None]
    failed = sum(1 for n in known if n > 0)
    attempts = sum(max(0, n) for n in known)
    evidence = [
        f"roams_with_handshake_failures:{failed}/{len(known)}",
        f"failures:{attempts}",
    ]
    if len(known) < len(events):
        evidence.append(f"handshake_unknown:{len(events) - len(known)}")
    return RoamPart(
        PART_HANDSHAKE,
        _share_score(failed, len(known)),
        WEIGHTS[PART_HANDSHAKE],
        tuple(evidence),
    )


def _continuity_part(events: Sequence[RoamEvent], th: RoamThresholds) -> RoamPart:
    flaps = [f for f in detect_flapping(events, th) if f.kind is FlapKind.PING_PONG]
    inside = sum(
        1
        for e in events
        if any(f.start <= e.ts <= f.end and _pair(e) == f.pair for f in flaps)
    )
    evidence = (f"roams_in_flaps:{inside}/{len(events)}", f"flaps:{len(flaps)}")
    return RoamPart(
        PART_CONTINUITY,
        _share_score(inside, len(events)),
        WEIGHTS[PART_CONTINUITY],
        evidence,
    )


def _combine(parts: Sequence[RoamPart]) -> tuple[float | None, float]:
    known = [p for p in parts if p.score is not None]
    coverage = sum(p.weight for p in known)
    if coverage <= 0:
        return None, 0.0
    score = sum(p.score * p.weight for p in known if p.score is not None) / coverage
    return score, coverage


def roaming_quality(
    window: ClientRoamWindow, thresholds: RoamThresholds = DEFAULT_ROAM_THRESHOLDS
) -> RoamingScore:
    """Score the roaming of one client window (see module table)."""
    th = thresholds
    events = tuple(sorted(window.events, key=lambda e: e.ts))
    if not events:
        reason = (
            "no_roams:stationary" if window.mobility == "stationary" else "no_roams"
        )
        return RoamingScore(
            window.client_mac, RoamStatus.NOT_APPLICABLE, None, 0.0, (), (reason,)
        )
    classes = [classify_roam(e, th) for e in events]
    parts = (
        _gap_part(classes, th),
        _frequency_part(window, th),
        _signal_part(classes),
        _handshake_part(events),
        _continuity_part(events, th),
    )
    score, coverage = _combine(parts)
    coverage = round(coverage, 6)
    evidence = [f"roams:{len(events)}", f"coverage:{coverage:.2f}"]
    if len(events) < th.min_events or coverage < th.min_coverage:
        evidence.append(
            "too_few_roams" if len(events) < th.min_events else "coverage_too_low"
        )
        return RoamingScore(
            window.client_mac,
            RoamStatus.INSUFFICIENT,
            None,
            coverage,
            parts,
            tuple(evidence),
        )
    return RoamingScore(
        window.client_mac,
        RoamStatus.SCORED,
        None if score is None else round(score, 1),
        coverage,
        parts,
        tuple(evidence),
    )


# =====================================================================
# Sticky clients
# =====================================================================


@dataclass(frozen=True)
class StickyThresholds:
    """Thresholds for :func:`assess_sticky` (defaults from client_stability)."""

    weak_rssi_dbm: float = float(WEAK_SIGNAL_DBM)
    min_dwell_s: float = float(STICKY_HOLD_SECONDS)
    better_by_db: float = float(STICKY_DELTA_DB)
    # Share of the dwell time below the weak level. Startwert.
    min_weak_share: float = 0.5
    # A measured_same_client value older than this is not comparable.
    # Startwert, nicht kalibriert (5 polls at 60 s).
    max_measurement_age_s: float = 300.0
    # Historic values older than the hourly client history (7 days) are
    # ignored.
    max_historic_age_s: float = 7 * _DAY
    confidence_supported: float = 0.8
    confidence_historic: float = 0.5
    confidence_no_measurement: float = 0.3


DEFAULT_STICKY_THRESHOLDS = StickyThresholds()


@dataclass(frozen=True)
class AlternativeAp:
    """Another radio the client could use, with the basis of its signal.

    ``measured_same_client``: comparable measurement of this client at that
    radio (usteer, 802.11k beacon report, later scan). ``historic_same_client``:
    this client was better there before (Client Stability history).
    ``none``: no signal for this client at that radio.
    """

    radio: RadioRef
    rssi: Metric | None
    basis: str
    age_s: float | None
    band: str | None  # None: unknown band, never comparable


@dataclass(frozen=True)
class StickyInput:
    """One client at its current radio.

    ``mobility`` was added to the specified fields: the "no comparable
    measurement" path applies to mobile clients only. ``band`` is the band
    of the current radio; only alternatives on the same known band are
    comparable (signal differs by band).
    """

    client_mac: str
    current_radio: RadioRef
    current_rssi: Metric
    dwell_s: float
    weak_share: float | None
    alternatives: Sequence[AlternativeAp]
    band: str | None
    mobility: str | None = None


class StickyStatus(StrEnum):
    """Sticky verdict; there is deliberately no "confirmed"."""

    NONE = "none"
    SUSPECTED = "suspected"
    SUPPORTED_BY_MEASUREMENT = "supported_by_measurement"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StickyAssessment:
    """Result of :func:`assess_sticky`.

    ``better_radio`` and ``delta_db`` are set only for
    ``supported_by_measurement``.
    """

    client_mac: str
    radio: RadioRef
    status: StickyStatus
    better_radio: RadioRef | None
    delta_db: float | None
    evidence: tuple[str, ...]
    confidence: float

    def as_dict(self) -> dict[str, Any]:
        """Return the assessment as a plain dict."""
        return {
            "client_mac": self.client_mac,
            "radio": self.radio.as_dict(),
            "status": self.status.value,
            "better_radio": self.better_radio.as_dict() if self.better_radio else None,
            "delta_db": self.delta_db,
            "evidence": list(self.evidence),
            "confidence": self.confidence,
        }


def _value(metric: Metric | None, states: frozenset[CapabilityState]) -> float | None:
    if metric is None or metric.state not in states:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


_FRESH = frozenset({CapabilityState.MEASURED})
_ANY_VALUE = frozenset({CapabilityState.MEASURED, CapabilityState.STALE})


def _result(
    inp: StickyInput,
    status: StickyStatus,
    evidence: Sequence[str],
    confidence: float = 0.0,
    better: tuple[RadioRef, float] | None = None,
) -> StickyAssessment:
    return StickyAssessment(
        client_mac=inp.client_mac,
        radio=inp.current_radio,
        status=status,
        better_radio=better[0] if better else None,
        delta_db=better[1] if better else None,
        evidence=tuple(evidence),
        confidence=confidence,
    )


def _best(
    alts: Sequence[AlternativeAp],
    current: float,
    accept: Callable[[AlternativeAp], float | None],
) -> tuple[AlternativeAp, float] | None:
    best: tuple[AlternativeAp, float] | None = None
    for alt in alts:
        value = accept(alt)
        if value is None:
            continue
        delta = value - current
        if best is None or delta > best[1]:
            best = (alt, delta)
    return best


def _same_band(inp: StickyInput, alt: AlternativeAp) -> bool:
    return inp.band is not None and alt.band == inp.band


def _cross_band_better(
    inp: StickyInput,
    alternatives: Sequence[AlternativeAp],
    current: float,
    th: StickyThresholds,
) -> AlternativeAp | None:
    """A louder alternative that is not comparable (other or unknown band)."""
    usable = [a for a in alternatives if not _same_band(inp, a) and _recent(a, th)]
    best = _best(usable, current, lambda a: _value(a.rssi, _ANY_VALUE))
    if best is None or best[1] < th.better_by_db:
        return None
    return best[0]


def _recent(alt: AlternativeAp, th: StickyThresholds) -> bool:
    if alt.basis == BASIS_MEASURED:
        return alt.age_s is not None and alt.age_s <= th.max_measurement_age_s
    if alt.basis == BASIS_HISTORIC:
        return alt.age_s is None or alt.age_s <= th.max_historic_age_s
    return False


def assess_sticky(
    inp: StickyInput, thresholds: StickyThresholds = DEFAULT_STICKY_THRESHOLDS
) -> StickyAssessment:
    """Assess whether a client sticks to a weak AP (see module docstring)."""
    th = thresholds
    current = _value(inp.current_rssi, _FRESH)
    if current is None:
        return _result(inp, StickyStatus.UNKNOWN, ["current_rssi_unknown"])
    evidence = [
        f"current_rssi:{current:g}dBm:{inp.current_rssi.source}",
        f"dwell:{inp.dwell_s:g}s",
    ]
    if current > th.weak_rssi_dbm or inp.dwell_s < th.min_dwell_s:
        return _result(inp, StickyStatus.NONE, [*evidence, "not_weak_long_enough"])
    if inp.weak_share is None:
        return _result(inp, StickyStatus.UNKNOWN, [*evidence, "weak_share_unknown"])
    evidence.append(f"weak_share:{inp.weak_share:.2f}")
    if inp.weak_share < th.min_weak_share:
        return _result(inp, StickyStatus.NONE, [*evidence, "weak_share_low"])

    alternatives = [a for a in inp.alternatives if a.radio != inp.current_radio]
    others = [a for a in alternatives if _same_band(inp, a)]
    measured = [a for a in others if a.basis == BASIS_MEASURED]
    fresh = [
        a
        for a in measured
        if a.age_s is not None and a.age_s <= th.max_measurement_age_s
    ]
    evidence.extend(
        f"measurement_too_old:{a.radio}:{a.age_s:g}s"
        for a in measured
        if a not in fresh and a.age_s is not None
    )
    best = _best(fresh, current, lambda a: _value(a.rssi, _FRESH))
    if best is not None:
        alt, delta = best
        if delta >= th.better_by_db:
            evidence.append(
                f"measured_better:{alt.radio}:{delta:g}dB:age{alt.age_s:g}s"
            )
            return _result(
                inp,
                StickyStatus.SUPPORTED_BY_MEASUREMENT,
                evidence,
                th.confidence_supported,
                (alt.radio, delta),
            )
        evidence.append("no_better_alternative_measured")
        return _result(inp, StickyStatus.NONE, evidence)

    historic = [
        a
        for a in others
        if a.basis == BASIS_HISTORIC
        and (a.age_s is None or a.age_s <= th.max_historic_age_s)
    ]
    best = _best(historic, current, lambda a: _value(a.rssi, _ANY_VALUE))
    if best is not None and best[1] >= th.better_by_db:
        alt, delta = best
        evidence.append(f"historic_better:{alt.radio}:{delta:g}dB")
        return _result(inp, StickyStatus.SUSPECTED, evidence, th.confidence_historic)

    cross = _cross_band_better(inp, alternatives, current, th)
    if cross is not None:
        evidence.append(f"alternative_other_band_not_comparable:{cross.radio}")
        return _result(
            inp, StickyStatus.SUSPECTED, evidence, th.confidence_no_measurement
        )

    if inp.mobility == "mobile":
        evidence.append("no_comparable_measurement")
        return _result(
            inp, StickyStatus.SUSPECTED, evidence, th.confidence_no_measurement
        )
    evidence.append("no_comparable_measurement")
    return _result(inp, StickyStatus.NONE, evidence)
