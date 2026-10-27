"""Wi-Fi band helpers (pure, no HA).

Map what a router reports about a radio - its frequency, the UCI ``band``
option, a legacy ``hwmode`` or the channel number - to the band codes used
across the integration: ``2.4g``, ``5g``, ``6g`` or ``unknown`` (60 GHz,
802.11ad). Shared by ``api`` (band detection), ``channel_plan`` and
``client_stability``; must not import from Home Assistant or ``api``.
"""

from __future__ import annotations

from typing import Any

# UCI wifi-device "band" option (replaces hwmode in newer OpenWrt) → normalised band
UCI_BAND_MAP = {"2g": "2.4g", "5g": "5g", "6g": "6g", "60g": "unknown"}


def _as_band_int(value: Any) -> int | None:
    """Return a frequency or channel as int, None for missing/non-numeric values."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def band_from_frequency(value: Any) -> str | None:
    """Map a frequency in MHz to a band; 6 GHz starts at 5925 MHz."""
    freq = _as_band_int(value)
    if freq is None or freq <= 0:
        return None
    if freq < 3000:
        return "2.4g"
    if freq < 5925:
        return "5g"
    if freq <= 7125:
        return "6g"
    return "unknown"  # 60 GHz (802.11ad)


def band_from_hwmode(hwmode: str) -> str | None:
    """Map a legacy hwmode (11a, 11g, bgn …) to a band; None if it is ambiguous."""
    mode = hwmode.lower()
    if "ad" in mode:
        return "unknown"  # 60 GHz (802.11ad)
    # 11n, 11ax, 11be and "auto" run on several bands and say nothing on their own.
    mode = mode.replace("auto", "").replace("ax", "").replace("be", "")
    if "a" in mode:
        return "5g"
    if "b" in mode or "g" in mode:
        return "2.4g"
    return None


def band_from_channel(value: Any) -> str | None:
    """Map a channel number to a band; ambiguous numbers resolve to 2.4/5 GHz.

    6 GHz uses channel 2 and 1, 5, 9 … 233. Of those, 1-13 also exist on
    2.4 GHz and 149-177 on 5 GHz. A 6 GHz radio reports its frequency or band
    option, so the channel only decides when neither is known.
    """
    chan = _as_band_int(value)
    if chan is None or chan < 1:
        return None
    if chan <= 14:
        return "2.4g"
    if 32 <= chan <= 177 and (chan % 2 == 0 or chan >= 149):
        return "5g"
    if chan <= 233 and chan % 4 == 1:
        return "6g"
    return None
