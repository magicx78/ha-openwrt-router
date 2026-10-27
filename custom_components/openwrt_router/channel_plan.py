"""Wi-Fi channel plan analysis across OpenWrt routers (pure functions, no HA).

Input are the ``ap_interfaces`` of every router (``iwinfo info`` per AP
interface). Several SSIDs share one physical radio (``phy``), so interfaces
are first reduced to one :class:`Radio` per router and phy. ``analyze`` then
reports:

- ``same_channel``: two radios in one band on the same primary channel;
- ``overlap``: the occupied spectrum of two radios intersects although the
  primary channels differ (40/80/160 MHz blocks, e.g. 44 and 48 at 40 MHz,
  or 36 at 160 MHz covering 36–64);
- ``non_standard_24``: 2.4 GHz radio outside channels 1/6/11;
- ``dfs``: 5 GHz radio with at least one 20 MHz sub-channel in 52–144.

The first three are conflicts (Repairs issue), ``dfs`` is informational.
A radio that also carries a STA/mesh uplink (repeater, 802.11s) has to share
its partner's channel, so pairs with such a backhaul radio are never
reported as same_channel/overlap.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .const import (
    RADIO_KEY_BAND,
    RADIO_KEY_CENTER_CHAN1,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_ENABLED,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_HTMODE,
    RADIO_KEY_IFNAME,
    RADIO_KEY_MODE,
    RADIO_KEY_PHY,
)
from .wifi_band import band_from_frequency

FINDING_SAME_CHANNEL = "same_channel"
FINDING_OVERLAP = "overlap"
FINDING_NON_STANDARD_24 = "non_standard_24"
FINDING_DFS = "dfs"

CONFLICT_TYPES = frozenset(
    {FINDING_SAME_CHANNEL, FINDING_OVERLAP, FINDING_NON_STANDARD_24}
)
_TYPE_ORDER = (
    FINDING_SAME_CHANNEL,
    FINDING_OVERLAP,
    FINDING_NON_STANDARD_24,
    FINDING_DFS,
)

BAND_24 = "2.4g"
BAND_5 = "5g"
BAND_6 = "6g"
_BAND_LABELS = {BAND_24: "2.4 GHz", BAND_5: "5 GHz", BAND_6: "6 GHz"}

STANDARD_24_CHANNELS = (1, 6, 11)
DFS_FIRST_CHANNEL = 52
DFS_LAST_CHANNEL = 144

# Center channels of the bonded 5 GHz blocks per width (IEEE 802.11 channel
# plan; 320 MHz exists only in 6 GHz).
_CENTERS_5G: dict[int, tuple[int, ...]] = {
    40: (38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175),
    80: (42, 58, 106, 122, 138, 155, 171),
    160: (50, 114, 163),
}

_WIDTH_RE = re.compile(r"(\d+)")

# iwinfo reports "Master", UCI "ap"; anything else is not an AP interface.
_AP_MODES = frozenset({"", "master", "ap"})


@dataclass(frozen=True)
class Radio:
    """One physical radio of one router."""

    entry_id: str
    router: str
    phy: str
    band: str
    channel: int
    width: int
    center: int
    backhaul: bool = False

    def center_mhz(self) -> float:
        """Return the center frequency of the occupied block."""
        return channel_to_mhz(self.band, self.center)

    def span_mhz(self) -> tuple[float, float]:
        """Return the occupied spectrum as (low, high) MHz."""
        mid = self.center_mhz()
        return mid - self.width / 2, mid + self.width / 2

    def subchannels(self) -> list[int]:
        """Return the 20 MHz channel numbers covered (5/6 GHz)."""
        n = self.width // 20
        first = self.center - 2 * (n - 1)
        return [first + 4 * i for i in range(n)]

    def as_attr(self) -> dict[str, Any]:
        """Return the radio as a compact attribute dict."""
        attr: dict[str, Any] = {
            "router": self.router,
            "radio": self.phy,
            "band": self.band,
            "channel": self.channel,
            "width_mhz": self.width,
        }
        if self.backhaul:
            attr["backhaul"] = True
        return attr


def channel_to_mhz(band: str, channel: float) -> float:
    """Return the center frequency of a channel number in a band."""
    if band == BAND_24:
        return 2484.0 if channel == 14 else 2407.0 + 5 * channel
    if band == BAND_6:
        return 5950.0 + 5 * channel
    return 5000.0 + 5 * channel


def htmode_width(htmode: Any) -> int:
    """Return the channel width in MHz from an OpenWrt htmode (HE80, HT40+ …)."""
    if not isinstance(htmode, str):
        return 20
    match = _WIDTH_RE.search(htmode)
    if not match:
        return 20  # NOHT and unknown values
    width = int(match.group(1))
    return width if width in (20, 40, 80, 160, 320) else 20


def _band_of(iface: dict[str, Any], channel: int) -> str | None:
    band = band_from_frequency(iface.get(RADIO_KEY_FREQUENCY))
    if band is not None:
        return band if band in _BAND_LABELS else None  # 60 GHz: no plan
    band = iface.get(RADIO_KEY_BAND)
    if band not in _BAND_LABELS:
        return None
    # The band key may come from a name heuristic (radio0 = 2.4 GHz); the
    # channel number is more reliable for 2.4 vs 5 GHz.
    if band == BAND_24 and channel > 14:
        return BAND_5
    if band == BAND_5 and channel <= 14:
        return BAND_24
    return band


def phy_of(ifname: str) -> str:
    """phy1-ap0 → phy1; other names (UCI sections) stay as they are."""
    return ifname.split("-", 1)[0] or ifname


def _derive_center(band: str, channel: int, width: int, htmode: Any) -> int:
    """Center channel when iwinfo did not report ``center_chan1``."""
    if width == 20:
        return channel
    if band == BAND_24:
        if isinstance(htmode, str) and htmode.endswith("-"):
            return channel - 2
        if isinstance(htmode, str) and htmode.endswith("+"):
            return channel + 2
        # Without an explicit side OpenWrt places the secondary channel
        # above for low and below for high channels.
        return channel + 2 if channel <= 7 else channel - 2
    n = width // 20
    if band == BAND_6:
        block = 4 * n
        return ((channel - 1) // block) * block + 1 + 2 * (n - 1)
    for center in _CENTERS_5G.get(width, ()):
        if abs(channel - center) <= 2 * (n - 1):
            return center
    return channel


def radios_from_ap_interfaces(
    entry_id: str,
    router: str,
    ap_interfaces: list[dict[str, Any]],
    sta_interfaces: list[dict[str, Any]] | None = None,
) -> list[Radio]:
    """Reduce a router's AP interfaces to one Radio per physical radio.

    Interfaces without a usable channel or band, non-AP modes and disabled
    interfaces (UCI fallback: ``enabled`` False when the wifi-iface or its
    wifi-device is disabled; iwinfo lists running interfaces only and sets no
    flag) are skipped. The phy is taken from iwinfo (``phy``) or derived from
    the interface name (``phy1-ap0``); radios are keyed by phy and band
    (multi-band wiphys). ``sta_interfaces`` (repeater/mesh uplinks) mark
    their phy as backhaul.
    """
    backhaul_phys = {
        phy_of(str(sta.get(RADIO_KEY_IFNAME) or ""))
        for sta in sta_interfaces or []
        if isinstance(sta, dict) and sta.get(RADIO_KEY_IFNAME)
    }
    radios: dict[tuple[str, str], Radio] = {}
    for iface in ap_interfaces or []:
        if not isinstance(iface, dict) or not iface.get(RADIO_KEY_ENABLED, True):
            continue
        if str(iface.get(RADIO_KEY_MODE) or "").lower() not in _AP_MODES:
            continue
        channel = _as_int(iface.get(RADIO_KEY_CHANNEL))
        band = _band_of(iface, channel)
        if channel <= 0 or band is None:
            continue
        ifname = str(iface.get(RADIO_KEY_IFNAME) or "")
        phy = str(iface.get(RADIO_KEY_PHY) or phy_of(ifname))
        if not phy or (phy, band) in radios:
            continue
        htmode = iface.get(RADIO_KEY_HTMODE)
        width = htmode_width(htmode)
        if band == BAND_24 and width > 40:
            width = 40
        center = _as_int(iface.get(RADIO_KEY_CENTER_CHAN1))
        if width == 20 or center <= 0:
            center = _derive_center(band, channel, width, htmode)
        radios[(phy, band)] = Radio(
            entry_id=entry_id,
            router=router,
            phy=phy,
            band=band,
            channel=channel,
            width=width,
            center=center,
            backhaul=phy in backhaul_phys or phy_of(ifname) in backhaul_phys,
        )
    return list(radios.values())


def analyze(radios: list[Radio]) -> list[dict[str, Any]]:
    """Return all channel plan findings for the given radios.

    Each finding: ``{"type", "band", "radios": [attr dicts], "entry_ids"}``.
    Pairs are only compared within a band and never with themselves; two
    SSIDs on one radio are a single Radio and therefore never a finding.
    """
    findings: list[dict[str, Any]] = []
    for radio in radios:
        if radio.band == BAND_24 and radio.channel not in STANDARD_24_CHANNELS:
            findings.append(_finding(FINDING_NON_STANDARD_24, [radio]))
        if radio.band == BAND_5 and any(
            DFS_FIRST_CHANNEL <= ch <= DFS_LAST_CHANNEL for ch in radio.subchannels()
        ):
            findings.append(_finding(FINDING_DFS, [radio]))

    for i, a in enumerate(radios):
        for b in radios[i + 1 :]:
            if a.band != b.band or (a.entry_id, a.phy) == (b.entry_id, b.phy):
                continue
            if a.backhaul or b.backhaul:
                continue
            if a.channel == b.channel:
                findings.append(_finding(FINDING_SAME_CHANNEL, [a, b]))
                continue
            a_low, a_high = a.span_mhz()
            b_low, b_high = b.span_mhz()
            if max(a_low, b_low) < min(a_high, b_high):
                findings.append(_finding(FINDING_OVERLAP, [a, b]))

    findings.sort(
        key=lambda f: (
            _TYPE_ORDER.index(f["type"]),
            f["band"],
            [(r["router"], r["radio"]) for r in f["radios"]],
        )
    )
    return findings


def format_finding(finding: dict[str, Any]) -> str:
    """Return a one-line, language-neutral description of a finding."""
    radios = " + ".join(
        f"{r['router']} {r['radio']} ch {r['channel']}/{r['width_mhz']} MHz"
        for r in finding["radios"]
    )
    band = _BAND_LABELS.get(finding["band"], finding["band"])
    return f"{finding['type']} ({band}): {radios}"


def _finding(kind: str, radios: list[Radio]) -> dict[str, Any]:
    ordered = sorted(radios, key=lambda r: (r.router, r.phy))
    return {
        "type": kind,
        "band": ordered[0].band,
        "radios": [r.as_attr() for r in ordered],
        "entry_ids": sorted({r.entry_id for r in ordered}),
    }


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0
