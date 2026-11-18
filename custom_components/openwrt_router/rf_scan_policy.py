"""Scan decision and neighbor redaction (pure, no HA; never starts a scan).

A scan is not a read: the radio leaves its channel or the driver adds a
temporary interface (plan document, section 6). :func:`decide_scan` only
answers "may this scan run now?" with a fixed order of refusal reasons.
A radio carrying an uplink (STA, mesh, WDS, ad-hoc) is always refused; there
is deliberately no force parameter.

:func:`sanitize_neighbors` keeps own BSSs by BSSID and replaces foreign
SSID/BSSID with a salted, shortened hash: neighbors' network names and MAC
addresses are their data and are not kept in clear text.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from .rf_models import CapabilityState
from .wifi_band import band_from_frequency

_LOGGER = logging.getLogger(__name__)

# Interface modes (iwinfo spelling and UCI) that make a radio an uplink.
_UPLINK_MODES = frozenset(
    {
        "sta",
        "client",
        "station",
        "mesh",
        "mesh point",
        "wds",
        "wds sta",
        "adhoc",
        "ad hoc",
    }
)
# Modes that are known not to be an uplink.
_NON_UPLINK_MODES = frozenset({"ap", "master", "monitor"})

# Capability states in which a scan may be tried: measured, or supported
# with no/old results (a first scan has no data yet).
_SCAN_POSSIBLE = frozenset(
    {CapabilityState.MEASURED, CapabilityState.NO_DATA, CapabilityState.STALE}
)

# Plan document 6.4: at most once per hour and radio.
DEFAULT_MIN_INTERVAL_MANUAL_S = 3600.0
# Automatic scans, if ever enabled: at most once a day per radio.
DEFAULT_MIN_INTERVAL_AUTO_S = 24 * 3600.0
# Gap between scans on any radio of one router; rpcd can block for ~19 s per
# scan (plan document 6.2). Startwert, nicht kalibriert.
DEFAULT_MIN_GAP_PER_ROUTER_S = 300.0

# Cap on kept foreign neighbors. Startwert, nicht kalibriert.
DEFAULT_MAX_NEIGHBORS = 50
# Hex digits of the neighbor key (64 bit).
NEIGHBOR_KEY_LENGTH = 16


def _norm_mode(mode: Any) -> str:
    if not isinstance(mode, str):
        return ""
    return " ".join(mode.lower().replace("-", " ").replace("_", " ").split())


def is_uplink_radio(
    interface_modes: Iterable[Any], *, wds: bool, backhaul_flag: bool
) -> bool | None:
    """Return whether a radio carries an uplink; None when modes are unknown.

    Radio-wide: one STA interface makes the whole radio an uplink radio,
    because a scan on its AP interface disturbs the STA link too.
    """
    if wds or backhaul_flag:
        return True
    modes = {m for m in (_norm_mode(x) for x in interface_modes) if m}
    if not modes:
        return None
    if modes & _UPLINK_MODES:
        return True
    if modes <= _NON_UPLINK_MODES:
        return False
    return None  # an unrecognised mode might be an uplink


class ScanReason(StrEnum):
    """Result of :func:`decide_scan`, in the order the checks run."""

    ALLOWED = "allowed"
    SCAN_UNSUPPORTED = "scan_unsupported"
    SCAN_UNAVAILABLE = "scan_unavailable"
    NOT_ADMIN = "not_admin"
    AUTO_DISABLED = "auto_disabled"
    UPLINK_RADIO = "uplink_radio"
    UPLINK_UNKNOWN = "uplink_unknown"
    CAC_ACTIVE = "cac_active"
    CAC_UNKNOWN = "cac_unknown"
    RATE_LIMIT_RADIO = "rate_limit_radio"
    RATE_LIMIT_ROUTER = "rate_limit_router"


@dataclass(frozen=True)
class ScanRequest:
    """A request to scan one radio.

    Automatic requests are issued on behalf of the admin who enabled them,
    so the caller sets ``is_admin`` for those too.
    """

    radio_key: str
    requested_at: float
    manual: bool
    is_admin: bool


@dataclass(frozen=True)
class ScanState:
    """Earlier scans of one router: per radio and for the router as a whole."""

    last_scan_at: Mapping[str, float]
    last_router_scan_at: float | None


@dataclass(frozen=True)
class ScanPolicy:
    """Limits for scans. Automatic scans are off unless enabled."""

    enabled_auto: bool = False
    min_interval_manual_s: float = DEFAULT_MIN_INTERVAL_MANUAL_S
    min_interval_auto_s: float = DEFAULT_MIN_INTERVAL_AUTO_S
    min_gap_per_router_s: float = DEFAULT_MIN_GAP_PER_ROUTER_S


@dataclass(frozen=True)
class ScanDecision:
    """Whether a scan may run, why, and when to ask again (rate limits)."""

    allowed: bool
    reason: ScanReason
    retry_after_s: float | None = None

    def as_dict(self) -> dict[str, Any]:
        """Return the decision as a plain dict."""
        return {
            "allowed": self.allowed,
            "reason": self.reason.value,
            "retry_after_s": self.retry_after_s,
        }


def _refuse(reason: ScanReason, retry_after_s: float | None = None) -> ScanDecision:
    return ScanDecision(False, reason, retry_after_s)


def _wait(last: float | None, now: float, interval: float) -> float | None:
    """Seconds still to wait, None if free. A clock going back waits fully."""
    if last is None:
        return None
    elapsed = now - last
    if elapsed < 0:
        return interval
    return interval - elapsed if elapsed < interval else None


def _gate_reason(
    request: ScanRequest,
    capability: CapabilityState,
    uplink: bool | None,
    cac_active: bool | None,
    policy: ScanPolicy,
) -> ScanReason | None:
    """Refusals that do not depend on time, in fixed order."""
    if capability is CapabilityState.UNSUPPORTED:
        return ScanReason.SCAN_UNSUPPORTED
    if capability not in _SCAN_POSSIBLE:
        return ScanReason.SCAN_UNAVAILABLE
    if not request.is_admin:
        return ScanReason.NOT_ADMIN
    if not request.manual and not policy.enabled_auto:
        return ScanReason.AUTO_DISABLED
    if uplink is True:
        return ScanReason.UPLINK_RADIO
    if uplink is None:
        return ScanReason.UPLINK_UNKNOWN
    if cac_active is True:
        return ScanReason.CAC_ACTIVE
    if cac_active is None:
        return ScanReason.CAC_UNKNOWN
    return None


def decide_scan(
    request: ScanRequest,
    *,
    capability: CapabilityState,
    uplink: bool | None,
    cac_active: bool | None,
    state: ScanState,
    policy: ScanPolicy,
) -> ScanDecision:
    """Decide whether a scan may run now. Never triggers one."""
    reason = _gate_reason(request, capability, uplink, cac_active, policy)
    if reason is not None:
        return _refuse(reason)
    now = request.requested_at
    interval = (
        policy.min_interval_manual_s if request.manual else policy.min_interval_auto_s
    )
    wait = _wait(state.last_scan_at.get(request.radio_key), now, interval)
    if wait is not None:
        return _refuse(ScanReason.RATE_LIMIT_RADIO, wait)
    wait = _wait(state.last_router_scan_at, now, policy.min_gap_per_router_s)
    if wait is not None:
        return _refuse(ScanReason.RATE_LIMIT_ROUTER, wait)
    return ScanDecision(True, ScanReason.ALLOWED)


# =====================================================================
# Neighbor redaction
# =====================================================================


@dataclass(frozen=True)
class NeighborBss:
    """One BSS from a scan, without foreign SSID/BSSID in clear text.

    ``key`` is the BSSID for own BSSs and a salted hash for foreign ones.
    There is no SSID field at all.
    """

    key: str
    own: bool
    band: str | None
    channel: int | None
    signal_dbm: int | None
    width_mhz: int | None
    encryption: str | None

    def as_dict(self) -> dict[str, Any]:
        """Return the neighbor as a plain dict."""
        return {
            "key": self.key,
            "own": self.own,
            "band": self.band,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "width_mhz": self.width_mhz,
            "encryption": self.encryption,
        }


def _norm_bssid(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower().replace("-", ":")


def _int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _signal(value: Any) -> int | None:
    dbm = _int(value)
    return dbm if dbm is not None and -120 <= dbm < 0 else None


def _width(entry: Mapping[str, Any]) -> int | None:
    """Width from rpcd's ht/vht operation tables (Annahme: rpcd field names).

    vht ``channel_width`` 80/160 is the width, 8080 counts as 160; a vht
    value of 40 means "20 or 40", so ht decides. ht ``channel_width`` 2040
    with a secondary channel is 40, otherwise 20.
    """
    vht = entry.get("vht_operation")
    if isinstance(vht, Mapping):
        vht_width = _int(vht.get("channel_width"))
        if vht_width in (80, 160):
            return vht_width
        if vht_width == 8080:
            return 160
    ht = entry.get("ht_operation")
    if isinstance(ht, Mapping):
        offset = str(ht.get("secondary_channel_offset") or "").lower()
        if _int(ht.get("channel_width")) == 2040 and offset in ("above", "below"):
            return 40
        if offset == "no secondary" or _int(ht.get("channel_width")) == 20:
            return 20
    return None


def _encryption(value: Any) -> str | None:
    """Summarise rpcd's encryption table, e.g. ``open`` or ``wpa2-psk``."""
    if not isinstance(value, Mapping) or not isinstance(value.get("enabled"), bool):
        return None
    if not value["enabled"]:
        return "open"
    wpa = [v for v in value.get("wpa") or [] if isinstance(v, int)]
    if not wpa:
        return "wep" if value.get("wep") else "unknown"
    auth = sorted(str(a).lower() for a in value.get("authentication") or [])
    suffix = "-" + "+".join(auth) if auth else ""
    return f"wpa{max(wpa)}{suffix}"


def _neighbor_key(bssid: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}|{bssid}".encode()).hexdigest()
    return digest[:NEIGHBOR_KEY_LENGTH]


def _neighbor(entry: Any, own: frozenset[str], salt: str) -> NeighborBss | None:
    if not isinstance(entry, Mapping):
        return None
    bssid = _norm_bssid(entry.get("bssid"))
    if bssid is None:
        return None  # nothing to key it by
    is_own = bssid in own
    band = band_from_frequency(entry.get("mhz")) or _band_field(entry.get("band"))
    return NeighborBss(
        key=bssid if is_own else _neighbor_key(bssid, salt),
        own=is_own,
        band=band,
        channel=_int(entry.get("channel")),
        signal_dbm=_signal(entry.get("signal")),
        width_mhz=_width(entry),
        encryption=_encryption(entry.get("encryption")),
    )


def _band_field(value: Any) -> str | None:
    return value if value in ("2.4g", "5g", "6g") else None


def _strongest_first(n: NeighborBss) -> tuple[bool, int]:
    return (n.signal_dbm is None, -(n.signal_dbm or 0))


def sanitize_neighbors(
    raw: Any,
    own_bssids: Iterable[str],
    *,
    salt: str,
    max_neighbors: int = DEFAULT_MAX_NEIGHBORS,
) -> list[NeighborBss]:
    """Turn an ``iwinfo scan`` result into redacted neighbors, strongest first.

    Own BSSs are all kept; foreign BSSs are capped at ``max_neighbors``.
    Entries without a BSSID are dropped. ``salt`` must be a non-empty secret
    of the caller (a MAC hash without salt is easy to reverse).
    """
    if not isinstance(salt, str) or not salt:
        raise ValueError("salt must be a non-empty string")
    own = frozenset(b for b in (_norm_bssid(x) for x in own_bssids) if b)
    results = raw.get("results") if isinstance(raw, Mapping) else raw
    if not isinstance(results, list):
        return []
    parsed = [n for n in (_neighbor(e, own, salt) for e in results) if n is not None]
    foreign = sorted((n for n in parsed if not n.own), key=_strongest_first)
    kept = [n for n in parsed if n.own] + foreign[: max(0, max_neighbors)]
    return sorted(kept, key=_strongest_first)
