"""Spectrum blocks, regulatory limits and overlap (pure, no HA).

Allowed channels, flags and power levels come only from what the radio
reports (``iwinfo freqlist`` / ``txpowerlist``). Without such a list
"allowed" is unknown: there is deliberately no built-in country table.

Frequency math is reused from :mod:`channel_plan` (``channel_to_mhz``,
``Radio.span_mhz``/``subchannels``, the 5 GHz block centers and the center
derivation), not copied.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .channel_plan import (
    _CENTERS_5G,  # DECIDED: private, reused instead of a second center table
    BAND_5,
    BAND_6,
    BAND_24,
    Radio,
    _derive_center,  # DECIDED: private, same center rules as channel_plan
    channel_to_mhz,
)
from .wifi_band import band_from_frequency

_LOGGER = logging.getLogger(__name__)

BANDS = (BAND_24, BAND_5, BAND_6)
_VALID_WIDTHS = {
    BAND_24: (20, 40),
    BAND_5: (20, 40, 80, 160),
    BAND_6: (20, 40, 80, 160, 320),
}

# 5 GHz ranges in which radar detection (DFS) applies (ETSI/FCC UNII-2 and
# UNII-2e). iwinfo reports no DFS flag, so this is derived, not reported.
DFS_RANGES_MHZ: tuple[tuple[float, float], ...] = ((5250.0, 5350.0), (5470.0, 5730.0))
# 5 GHz band edges used only to tell "5 GHz" from "elsewhere" for DFS.
_BAND_5_RANGE_MHZ = (5150.0, 5925.0)

DFS_BASIS_FREQUENCY_RANGE = "derived_from_frequency_range_not_reported_by_radio"
DFS_BASIS_OUTSIDE_5G = "outside_5ghz_band"
DFS_BASIS_UNKNOWN = "frequency_unknown"

REASON_NO_CHANNEL_LIST = "no_channel_list"
REASON_NO_CHANNEL_OF_BAND = "no_channel_of_band"

FLAG_NO_IR = "NO_IR"
FLAG_NO_20MHZ = "NO_20MHZ"
FLAG_NO_HT40_PLUS = "NO_HT40+"
FLAG_NO_HT40_MINUS = "NO_HT40-"
FLAG_NO_80MHZ = "NO_80MHZ"
FLAG_NO_160MHZ = "NO_160MHZ"
# Width flag per block width (cfg80211 chandef rules). 40 MHz is handled per
# side; 320 MHz has no flag in iwinfo's flag names, so it stays unchecked.
_WIDTH_FLAG = {20: FLAG_NO_20MHZ, 80: FLAG_NO_80MHZ, 160: FLAG_NO_160MHZ}

_BAND_ALIASES = {
    "2.4ghz": BAND_24,
    "2.4g": BAND_24,
    "2g": BAND_24,
    "2.4": BAND_24,
    "5ghz": BAND_5,
    "5g": BAND_5,
    "5": BAND_5,
    "6ghz": BAND_6,
    "6g": BAND_6,
    "6": BAND_6,
}


# =====================================================================
# Reported channel list
# =====================================================================


@dataclass(frozen=True)
class Channel:
    """One entry of the radio's reported channel list.

    ``restricted``/``flags``/``active`` are None when the entry did not say.
    """

    band: str
    channel: int
    mhz: int
    restricted: bool | None
    flags: frozenset[str] | None
    active: bool | None


@dataclass(frozen=True)
class RadioRegulatory:
    """What the radio reported about allowed channels and power.

    An empty channel list counts as unknown (None): a running radio always
    lists at least its own channel, so "empty" means "not reported".
    """

    channels: tuple[Channel, ...] | None
    txpower_dbm_list: tuple[int, ...] | None
    country: str | None

    def __post_init__(self) -> None:
        channels = tuple(self.channels) if self.channels else None
        powers = tuple(self.txpower_dbm_list) if self.txpower_dbm_list else None
        object.__setattr__(self, "channels", channels)
        object.__setattr__(self, "txpower_dbm_list", powers)


def _results(raw: Any) -> list[Any]:
    if isinstance(raw, dict):
        raw = raw.get("results")
    return raw if isinstance(raw, list) else []


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _band_alias(value: Any) -> str | None:
    if not isinstance(value, str):
        return None  # numeric band enums are not documented; not guessed
    return _BAND_ALIASES.get(value.lower().replace(" ", ""))


def _opt_bool(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


def _flags(value: Any) -> frozenset[str] | None:
    if not isinstance(value, list):
        return None
    return frozenset(str(f).upper() for f in value if isinstance(f, str))


def _channel(entry: Any) -> Channel | None:
    if not isinstance(entry, dict):
        return None
    channel = _int(entry.get("channel"))
    if channel is None or channel <= 0:
        return None
    mhz = _int(entry.get("mhz"))
    band = band_from_frequency(mhz) if mhz else _band_alias(entry.get("band"))
    if band not in BANDS:
        return None
    if mhz is None:
        mhz = int(channel_to_mhz(band, channel))
    return Channel(
        band=band,
        channel=channel,
        mhz=mhz,
        restricted=_opt_bool(entry.get("restricted")),
        flags=_flags(entry.get("flags")),
        active=_opt_bool(entry.get("active")),
    )


def channels_from_freqlist(raw: Any) -> list[Channel]:
    """Parse ``iwinfo freqlist`` (``{"results": [...]}`` or a bare list).

    Entries without a channel number or without any way to know the band
    are skipped; other missing fields stay None (unknown).
    """
    channels = (_channel(entry) for entry in _results(raw))
    return [c for c in channels if c is not None]


def txpowers_from_txpowerlist(raw: Any) -> tuple[int, ...] | None:
    """Parse ``iwinfo txpowerlist`` into sorted dBm levels; None if empty."""
    levels = {
        dbm
        for entry in _results(raw)
        if isinstance(entry, dict) and (dbm := _int(entry.get("dbm"))) is not None
    }
    return tuple(sorted(levels)) or None


def tx_power_limits(regulatory: RadioRegulatory) -> tuple[int, int] | None:
    """Return (min, max) dBm from the reported power list, None if unknown."""
    if not regulatory.txpower_dbm_list:
        return None
    return min(regulatory.txpower_dbm_list), max(regulatory.txpower_dbm_list)


# =====================================================================
# Blocks
# =====================================================================


@dataclass(frozen=True)
class Block:
    """Occupied frequency block of a radio."""

    band: str
    primary: int
    width_mhz: int
    center_channel: int
    center_mhz: float
    low_mhz: float
    high_mhz: float
    channels: tuple[int, ...]  # 20 MHz channel numbers inside the block


def _valid_subchannel(band: str, channel: int, width: int) -> bool:
    if band == BAND_24:
        return 1 <= channel <= (13 if width > 20 else 14)
    if band == BAND_6:
        return 1 <= channel <= 233 and channel % 4 == 1
    return 32 <= channel <= 177


def block_for(
    band: str,
    channel: int,
    width_mhz: int,
    *,
    center_channel: int | None = None,
    htmode: str | None = None,
) -> Block | None:
    """Return the block a radio occupies, None for an impossible combination.

    ``center_channel`` is iwinfo's ``center_chan1`` when known; otherwise it
    is derived like :mod:`channel_plan` does (``htmode`` decides the 2.4 GHz
    40 MHz side).
    """
    if band not in _VALID_WIDTHS or width_mhz not in _VALID_WIDTHS[band]:
        return None
    if not isinstance(channel, int) or channel <= 0:
        return None
    center = center_channel
    if center is None or width_mhz == 20:
        center = _derive_center(band, channel, width_mhz, htmode)
    if band == BAND_5 and width_mhz > 20 and center not in _CENTERS_5G[width_mhz]:
        return None
    radio = Radio("", "", "", band, channel, width_mhz, center)
    subchannels = tuple(radio.subchannels())
    if channel not in subchannels or not all(
        _valid_subchannel(band, ch, width_mhz) for ch in subchannels
    ):
        return None
    low, high = radio.span_mhz()
    return Block(
        band=band,
        primary=channel,
        width_mhz=width_mhz,
        center_channel=center,
        center_mhz=radio.center_mhz(),
        low_mhz=low,
        high_mhz=high,
        channels=subchannels,
    )


# =====================================================================
# DFS
# =====================================================================


@dataclass(frozen=True)
class DfsInfo:
    """DFS verdict and where it comes from (never from the radio)."""

    dfs: bool | None
    basis: str


def dfs_info(mhz: Any) -> DfsInfo:
    """Return whether a 20 MHz channel center lies in a DFS range."""
    if isinstance(mhz, bool) or not isinstance(mhz, int | float) or mhz <= 0:
        return DfsInfo(None, DFS_BASIS_UNKNOWN)
    low, high = _BAND_5_RANGE_MHZ
    if not low <= mhz < high:
        return DfsInfo(False, DFS_BASIS_OUTSIDE_5G)
    dfs = any(lo < mhz < hi for lo, hi in DFS_RANGES_MHZ)
    return DfsInfo(dfs, DFS_BASIS_FREQUENCY_RANGE)


def is_dfs(mhz: Any) -> bool | None:
    """Shortcut for ``dfs_info(mhz).dfs``."""
    return dfs_info(mhz).dfs


def block_dfs(block: Block) -> DfsInfo:
    """DFS for a block: True if any 20 MHz sub-channel is a DFS channel."""
    if block.band != BAND_5:
        return DfsInfo(False, DFS_BASIS_OUTSIDE_5G)
    dfs = any(is_dfs(channel_to_mhz(block.band, ch)) for ch in block.channels)
    return DfsInfo(dfs, DFS_BASIS_FREQUENCY_RANGE)


# =====================================================================
# Allowed / candidates
# =====================================================================


@dataclass(frozen=True)
class Allowed:
    """Whether a block may be used: True, False or None (unknown)."""

    ok: bool | None
    reasons: tuple[str, ...]


def _forbidden_flags(block: Block, index: int) -> tuple[str, ...]:
    """Flags that forbid sub-channel ``index`` of the block."""
    flags = [FLAG_NO_IR]
    if block.width_mhz == 40:
        # Lower half needs a usable partner above, upper half one below. The
        # kernel sets these flags symmetrically, so checking both halves
        # equals cfg80211's check of the control channel.
        lower = block.channels[index] < block.center_channel
        flags.append(FLAG_NO_HT40_PLUS if lower else FLAG_NO_HT40_MINUS)
    elif block.width_mhz in _WIDTH_FLAG:
        flags.append(_WIDTH_FLAG[block.width_mhz])
    return tuple(flags)


def _subchannel_reasons(
    block: Block, index: int, listed: dict[int, Channel]
) -> tuple[list[str], list[str]]:
    """Return (bans, unknowns) for one sub-channel."""
    ch = block.channels[index]
    entry = listed.get(int(channel_to_mhz(block.band, ch)))
    if entry is None:
        return [f"not_listed:{ch}"], []
    bans: list[str] = []
    unknowns: list[str] = []
    if entry.restricted is None:
        unknowns.append(f"restricted_unknown:{ch}")
    elif entry.restricted:
        bans.append(f"restricted:{ch}")
    if entry.flags is None:
        unknowns.append(f"flags_unknown:{ch}")
    else:
        bans.extend(
            f"flag:{flag}:{ch}"
            for flag in _forbidden_flags(block, index)
            if flag in entry.flags
        )
    return bans, unknowns


def allowed(block: Block, regulatory: RadioRegulatory | None) -> Allowed:
    """Check every 20 MHz sub-channel against the reported channel list."""
    if regulatory is None or not regulatory.channels:
        return Allowed(None, (REASON_NO_CHANNEL_LIST,))
    listed = {c.mhz: c for c in regulatory.channels}
    bans: list[str] = []
    unknowns: list[str] = []
    for index in range(len(block.channels)):
        sub_bans, sub_unknowns = _subchannel_reasons(block, index, listed)
        bans.extend(sub_bans)
        unknowns.extend(sub_unknowns)
    if bans:
        return Allowed(False, tuple(bans))
    if block.width_mhz not in _WIDTH_FLAG and block.width_mhz != 40:
        unknowns.append(f"width_not_checked:{block.width_mhz}")
    if unknowns:
        return Allowed(None, tuple(unknowns))
    return Allowed(True, ())


@dataclass(frozen=True)
class Candidates:
    """Blocks that are allowed for sure; ``reason`` when there are none."""

    blocks: tuple[Block, ...]
    reason: str | None


def _blocks_for_channel(band: str, channel: int, width: int) -> Iterable[Block]:
    sides = ("HT40+", "HT40-") if band == BAND_24 and width == 40 else (None,)
    for side in sides:
        block = block_for(band, channel, width, htmode=side)
        if block is not None:
            yield block


def candidate_blocks(
    band: str, width_mhz: int, regulatory: RadioRegulatory | None
) -> Candidates:
    """Return all blocks of a width whose ``allowed`` is True.

    One block per frequency span (lowest primary wins); 2.4 GHz 40 MHz is
    tried on both sides. Without a reported list: no candidates plus reason,
    never a default channel list.
    """
    if regulatory is None or not regulatory.channels:
        return Candidates((), REASON_NO_CHANNEL_LIST)
    in_band = sorted(c.channel for c in regulatory.channels if c.band == band)
    if not in_band:
        return Candidates((), REASON_NO_CHANNEL_OF_BAND)
    seen: dict[tuple[float, float], Block] = {}
    for channel in in_band:
        for block in _blocks_for_channel(band, channel, width_mhz):
            span = (block.low_mhz, block.high_mhz)
            if span not in seen and allowed(block, regulatory).ok is True:
                seen[span] = block
    return Candidates(tuple(sorted(seen.values(), key=lambda b: b.low_mhz)), None)


# =====================================================================
# Overlap
# =====================================================================


class OverlapKind(StrEnum):
    """How two blocks share spectrum."""

    CO_CHANNEL = "co_channel"
    ADJACENT_OVERLAP = "adjacent_overlap"
    NONE = "none"


def overlap_mhz(a: Block, b: Block) -> float:
    """Return the shared spectrum in MHz (0 for different bands)."""
    if a.band != b.band:
        return 0.0
    return max(0.0, min(a.high_mhz, b.high_mhz) - max(a.low_mhz, b.low_mhz))


def overlap_ratio(a: Block, b: Block) -> float:
    """Return the shared spectrum as a share of the narrower block."""
    return overlap_mhz(a, b) / min(a.width_mhz, b.width_mhz)


def classify_overlap(a: Block, b: Block) -> OverlapKind:
    """co_channel (same primary or identical block), adjacent_overlap, none."""
    if a.band != b.band:
        return OverlapKind.NONE
    same_block = (a.low_mhz, a.high_mhz) == (b.low_mhz, b.high_mhz)
    if a.primary == b.primary or same_block:
        return OverlapKind.CO_CHANNEL
    if overlap_mhz(a, b) > 0:
        return OverlapKind.ADJACENT_OVERLAP
    return OverlapKind.NONE
