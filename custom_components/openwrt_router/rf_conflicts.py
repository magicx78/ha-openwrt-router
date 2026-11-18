"""RF conflict detection with evidence (pure, no HA, not wired up yet).

Unlike :func:`channel_plan.analyze` (configuration only) every finding here
says whether it is merely possible from the plan (``potential``), backed by
a measurement (``measured``) or shown harmless by measurements on all
involved radios (``acceptable``). Same channel alone is never a warning.

Pairs with a backhaul radio are not hidden (``channel_plan`` skips them).
Only the real uplink pair (one radio's ``uplink_peer`` is the other) is
``acceptable`` by the backhaul alone and carries ``backhaul_shared_channel``.
A backhaul radio paired with any other radio is judged like every other
pair; the evidence says ``backhaul_peer_unknown`` (peer not known) or
``backhaul_other_peer`` (peer is a different radio). This module does not
replace ``channel_plan.analyze`` and finds the same pairs for
``same_channel``/``overlap`` (tested).
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .channel_plan import BAND_24, STANDARD_24_CHANNELS, Radio

# One severity for RF findings and Core events (CoreEvent.severity).
from .net_events import Severity
from .rf_identity import RadioRef, require_radio_key, require_router_id
from .rf_models import CapabilityState, Metric
from .rf_spectrum import (
    Block,
    OverlapKind,
    RadioRegulatory,
    block_for,
    candidate_blocks,
    classify_overlap,
    overlap_mhz,
    overlap_ratio,
)

_LOGGER = logging.getLogger(__name__)


class ConflictKind(StrEnum):
    """What kind of finding."""

    CO_CHANNEL = "co_channel"
    ADJACENT_OVERLAP = "adjacent_overlap"
    NON_STANDARD_24 = "non_standard_24"
    WIDE_CHANNEL_24 = "wide_channel_24"
    UNEVEN_DISTRIBUTION = "uneven_distribution"


_KIND_ORDER = tuple(ConflictKind)


class ConflictStatus(StrEnum):
    """How well a finding is backed."""

    POTENTIAL = "potential"  # from the channel plan only
    MEASURED = "measured"  # plan plus a measurement that confirms it
    ACCEPTABLE = "acceptable"  # plan, but measurements show no harm


@dataclass(frozen=True)
class ConflictThresholds:
    """Thresholds for :func:`detect_conflicts`."""

    # Same raise level as the NI rule wifi_channel_busy (net_rules.py, 70 %).
    high_utilization_pct: float = 70.0
    # Below this on every involved radio the overlap is harmless.
    # Startwert, nicht kalibriert.
    low_utilization_pct: float = 40.0
    # 802.11 OFDM preamble-detect CCA level for 20 MHz (-82 dBm): a radio
    # heard at or above this makes the other one defer.
    neighbor_signal_dbm: float = -82.0
    # Uneven: at least this many radios on one primary channel ...
    uneven_min_radios: int = 3
    # ... and more than this share of the band's radios. Startwert,
    # nicht kalibriert.
    uneven_min_share: float = 0.5


@dataclass(frozen=True)
class RadioView:
    """What the conflict check needs to know about one radio.

    ``router_key`` is the Core router id, ``radio_key`` the UCI radio name
    (see :mod:`.rf_identity`). ``neighbors`` maps the :class:`RadioRef` (router and radio key) of another
    radio to the measured signal (dBm) at which this radio hears it; the
    radio key alone is not unique (``radio0`` exists on every router).
    ``regulatory`` is the radio's
    reported channel list; without it no ``uneven_distribution`` finding.
    ``uplink_peer`` is the radio at the other end of this radio's WLAN
    uplink (set on the backhaul radio, or on the parent); None means unknown.
    """

    router_key: str
    radio_key: str
    band: str
    channel: int
    width_mhz: int
    backhaul: bool = False
    uplink_peer: RadioRef | None = None
    utilization: Metric | None = None
    noise: Metric | None = None
    client_count: int | None = None
    neighbors: Mapping[RadioRef, Metric] | None = None
    center_channel: int | None = None
    htmode: str | None = None
    regulatory: RadioRegulatory | None = None

    @property
    def ref(self) -> RadioRef:
        """Return the radio's identity."""
        return RadioRef(self.router_key, self.radio_key)


@dataclass(frozen=True)
class Conflict:
    """One finding with its evidence."""

    kind: ConflictKind
    band: str
    members: tuple[RadioRef, ...]
    status: ConflictStatus
    severity: Severity
    evidence: tuple[str, ...]

    @property
    def radio_keys(self) -> tuple[str, ...]:
        """Return the radio keys of the members (see ``members`` for routers)."""
        return tuple(m.radio_key for m in self.members)

    def as_dict(self) -> dict[str, Any]:
        """Return the finding as a plain dict."""
        return {
            "kind": self.kind.value,
            "band": self.band,
            "members": [m.as_dict() for m in self.members],
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
        }


def from_channel_plan_radio(radio: Radio, *, router_id: str, **extra: Any) -> RadioView:
    """Adapt a ``channel_plan.Radio`` (phy → radio_key).

    ``router_id`` is the Core router id of the radio's entry, taken from the
    router registry; ``radio.entry_id`` is never turned into a router id
    (after an adoption they no longer match).
    """
    return RadioView(
        router_key=require_router_id(router_id),
        radio_key=require_radio_key(radio.phy),
        band=radio.band,
        channel=radio.channel,
        width_mhz=radio.width,
        backhaul=radio.backhaul,
        center_channel=radio.center,
        **extra,
    )


def _block(view: RadioView) -> Block | None:
    return block_for(
        view.band,
        view.channel,
        view.width_mhz,
        center_channel=view.center_channel,
        htmode=view.htmode,
    )


def _measured_number(metric: Metric | None) -> float | None:
    """Return a fresh measured number; stale/missing/non-numeric is None."""
    if metric is None or metric.state is not CapabilityState.MEASURED:
        return None
    value = metric.value
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _utilization_evidence(view: RadioView) -> tuple[float | None, str]:
    pct = _measured_number(view.utilization)
    if pct is None:
        state = view.utilization.state.value if view.utilization else "none"
        return None, f"utilization_unknown:{view.ref}:{state}"
    return pct, f"utilization:{view.ref}:{pct:.1f}%:{view.utilization.source}"


def _neighbor_evidence(
    hearer: RadioView, heard: RadioView, threshold: float
) -> tuple[bool, list[str]]:
    metric = (hearer.neighbors or {}).get(heard.ref)
    dbm = _measured_number(metric)
    if dbm is None:
        return False, []
    text = f"neighbor_signal:{hearer.ref}<-{heard.ref}:{dbm:g}dBm:{metric.source}"
    return dbm >= threshold, [text]


def is_uplink_pair(a: RadioView, b: RadioView) -> bool:
    """Return True if ``a`` and ``b`` are the two ends of one WLAN uplink."""
    return a.uplink_peer == b.ref or b.uplink_peer == a.ref


def _backhaul_evidence(a: RadioView, b: RadioView, uplink_pair: bool) -> list[str]:
    if uplink_pair:
        return [
            f"backhaul_shared_channel:{v.ref}"
            for v in (a, b)
            if v.backhaul or v.uplink_peer is not None
        ]
    texts = []
    for view in (a, b):
        if not view.backhaul:
            continue
        code = (
            "backhaul_peer_unknown"
            if view.uplink_peer is None
            else "backhaul_other_peer"
        )
        texts.append(f"{code}:{view.ref}")
    return texts


def _pair_conflict(
    a: RadioView,
    b: RadioView,
    kind: OverlapKind,
    blocks: tuple[Block | None, Block | None],
    th: ConflictThresholds,
) -> Conflict:
    evidence = [f"channel_plan:{kind.value}:{a.band}"]
    if blocks[0] is not None and blocks[1] is not None:
        evidence.append(f"overlap_mhz:{overlap_mhz(*blocks):g}")
        evidence.append(f"overlap_ratio:{overlap_ratio(*blocks):.2f}")
    else:
        evidence.append("block_unknown")
    utils: list[float | None] = []
    for view in (a, b):
        pct, text = _utilization_evidence(view)
        utils.append(pct)
        evidence.append(text)
    heard = False
    for hearer, other in ((a, b), (b, a)):
        loud, texts = _neighbor_evidence(hearer, other, th.neighbor_signal_dbm)
        heard = heard or loud
        evidence.extend(texts)
    uplink_pair = is_uplink_pair(a, b)
    evidence.extend(_backhaul_evidence(a, b, uplink_pair))
    same_router = a.router_key == b.router_key
    if same_router:
        evidence.append(f"same_router:{a.router_key}")

    high = any(u is not None and u >= th.high_utilization_pct for u in utils)
    all_low = all(u is not None and u < th.low_utilization_pct for u in utils)
    if high or heard:
        status = ConflictStatus.MEASURED
    elif same_router:
        status = ConflictStatus.POTENTIAL  # never downgraded on one router
    elif uplink_pair or all_low:
        status = ConflictStatus.ACCEPTABLE
    else:
        status = ConflictStatus.POTENTIAL
    return _conflict(ConflictKind(kind.value), a.band, [a, b], status, evidence)


def _conflict(
    kind: ConflictKind,
    band: str,
    views: Sequence[RadioView],
    status: ConflictStatus,
    evidence: Sequence[str],
) -> Conflict:
    members = tuple(
        sorted({v.ref for v in views}, key=lambda r: (r.router_key, r.radio_key))
    )
    severity = Severity.WARNING if status is ConflictStatus.MEASURED else Severity.INFO
    return Conflict(kind, band, members, status, severity, tuple(evidence))


def _pair_kind(
    a: RadioView, b: RadioView, block_a: Block | None, block_b: Block | None
) -> OverlapKind:
    if a.band != b.band:
        return OverlapKind.NONE
    if block_a is None or block_b is None:
        # Impossible width/channel: only the primary channel can be compared.
        return OverlapKind.CO_CHANNEL if a.channel == b.channel else OverlapKind.NONE
    return classify_overlap(block_a, block_b)


def _single_radio(view: RadioView) -> list[Conflict]:
    if view.band != BAND_24:
        return []
    extra = [f"backhaul_shared_channel:{view.ref}"] if view.backhaul else []
    found = []
    if view.channel not in STANDARD_24_CHANNELS:
        found.append((ConflictKind.NON_STANDARD_24, f"channel:{view.channel}"))
    if view.width_mhz >= 40:
        found.append((ConflictKind.WIDE_CHANNEL_24, f"width_mhz:{view.width_mhz}"))
    return [
        _conflict(kind, view.band, [view], ConflictStatus.POTENTIAL, [text, *extra])
        for kind, text in found
    ]


def _alternatives(
    crowded: Sequence[RadioView],
    crowded_block: Block,
    band_blocks: Sequence[Block],
    count: int,
) -> tuple[list[int], list[str]]:
    """Primary channels a crowded radio could move to, and list sources."""
    found: set[int] = set()
    sources: list[str] = []
    for view in crowded:
        if view.regulatory is None or not view.regulatory.channels:
            continue
        sources.append(f"channel_list_from:{view.ref}")
        for cand in candidate_blocks(view.band, view.width_mhz, view.regulatory).blocks:
            if view.band == BAND_24 and cand.primary not in STANDARD_24_CHANNELS:
                continue  # never suggest an off-grid 2.4 GHz channel
            if overlap_mhz(cand, crowded_block) > 0:
                continue
            usage = sum(1 for blk in band_blocks if overlap_mhz(blk, cand) > 0)
            if usage < count - 1:  # moving one radio there evens things out
                found.add(cand.primary)
    return sorted(found), sources


def _uneven(
    views: Sequence[RadioView],
    blocks: Mapping[RadioRef, Block | None],
    th: ConflictThresholds,
) -> list[Conflict]:
    conflicts: list[Conflict] = []
    for band in sorted({v.band for v in views}):
        in_band = [v for v in views if v.band == band and blocks[v.ref] is not None]
        band_blocks = [blocks[v.ref] for v in in_band]
        for channel, count in sorted(Counter(v.channel for v in in_band).items()):
            if (
                count < th.uneven_min_radios
                or count / len(in_band) <= th.uneven_min_share
            ):
                continue
            crowded = [v for v in in_band if v.channel == channel]
            alternatives, sources = _alternatives(
                crowded, blocks[crowded[0].ref], band_blocks, count
            )
            if not alternatives:
                continue
            evidence = [
                f"crowded:{band}:ch{channel}:{count}/{len(in_band)}",
                "alternatives:" + ",".join(str(ch) for ch in alternatives),
                *sources,
            ]
            conflicts.append(
                _conflict(
                    ConflictKind.UNEVEN_DISTRIBUTION,
                    band,
                    crowded,
                    ConflictStatus.POTENTIAL,
                    evidence,
                )
            )
    return conflicts


DEFAULT_THRESHOLDS = ConflictThresholds()


def detect_conflicts(
    radios: Sequence[RadioView], thresholds: ConflictThresholds = DEFAULT_THRESHOLDS
) -> list[Conflict]:
    """Return all findings for the given radios, sorted by kind, band, members.

    A radio listed twice (same router and radio key) is one radio.
    """
    unique: dict[RadioRef, RadioView] = {}
    for view in radios:
        unique.setdefault(view.ref, view)
    views = list(unique.values())
    blocks = {v.ref: _block(v) for v in views}

    conflicts: list[Conflict] = []
    for view in views:
        conflicts.extend(_single_radio(view))
    for i, a in enumerate(views):
        for b in views[i + 1 :]:
            kind = _pair_kind(a, b, blocks[a.ref], blocks[b.ref])
            if kind is not OverlapKind.NONE:
                pair_blocks = (blocks[a.ref], blocks[b.ref])
                conflicts.append(_pair_conflict(a, b, kind, pair_blocks, thresholds))
    conflicts.extend(_uneven(views, blocks, thresholds))
    conflicts.sort(
        key=lambda c: (
            _KIND_ORDER.index(c.kind),
            c.band,
            [(m.router_key, m.radio_key) for m in c.members],
        )
    )
    return conflicts
