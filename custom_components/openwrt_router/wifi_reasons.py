"""IEEE 802.11 disconnect reason interpretation (pure, dependency-free).

Maps numeric reason codes and the plain-text forms OpenWrt hostapd writes to
the log onto stable keys and categories, so later steps can tell client-side,
AP-side, security and inactivity causes apart.  Never guesses: anything not
provable maps to ``UNKNOWN``.

Sources (fetched 2026-11-16):
- Reason code numbers and names: every ``WLAN_REASON_*`` define in hostapd
  ``src/common/ieee802_11_defs.h``,
  https://w1.fi/cgit/hostap/plain/src/common/ieee802_11_defs.h
  (redirects to https://git.w1.fi/cgit/hostap/plain/src/common/ieee802_11_defs.h).
- RCPI: Wireshark ``epan/dissectors/packet-ieee80211.c``
  (``rcpi_and_power_level_custom``, citing IEEE 802.11-2016 section 9.4.2.38):
  RCPI = |2 x (P + 110)| in 0.5 dB steps; 0 = P < -109.5 dBm, 220 = P >= 0 dBm,
  221..254 reserved, 255 = measurement not available.
  https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-ieee80211.c
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

_LOGGER = logging.getLogger(__name__)

CATEGORY_CLIENT = "client"
CATEGORY_AP = "ap"
CATEGORY_SECURITY = "security"
CATEGORY_INACTIVITY = "inactivity"
CATEGORY_RADIO = "radio"
CATEGORY_UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReasonInfo:
    """Interpretation of one disconnect reason."""

    key: str
    category: str
    code: int | None = None
    weak_signal_hint: bool = False
    auth_problem: bool = False
    # True = AP sent it, False = station sent it, None = not provable
    ap_initiated: bool | None = None


UNKNOWN = ReasonInfo(key="unknown", category=CATEGORY_UNKNOWN)

# Flag letters: w = weak_signal_hint, a = auth_problem, p = ap_initiated True,
# s = ap_initiated False (station-sent per spec meaning).
# (code, WLAN_REASON_ suffix, category, flags)
_RAW: tuple[tuple[int, str, str, str], ...] = (
    (1, "UNSPECIFIED", CATEGORY_UNKNOWN, ""),
    # doubtful: "previous authentication no longer valid" can come from either side
    (2, "PREV_AUTH_NOT_VALID", CATEGORY_UNKNOWN, ""),
    (3, "DEAUTH_LEAVING", CATEGORY_CLIENT, "s"),
    (4, "DISASSOC_DUE_TO_INACTIVITY", CATEGORY_INACTIVITY, "p"),
    (5, "DISASSOC_AP_BUSY", CATEGORY_AP, "p"),
    # doubtful (6, 7): AP tells a station its frame class was wrong
    (6, "CLASS2_FRAME_FROM_NONAUTH_STA", CATEGORY_AP, "p"),
    (7, "CLASS3_FRAME_FROM_NONASSOC_STA", CATEGORY_AP, "p"),
    (8, "DISASSOC_STA_HAS_LEFT", CATEGORY_CLIENT, "s"),
    (9, "STA_REQ_ASSOC_WITHOUT_AUTH", CATEGORY_AP, "p"),
    # doubtful (10, 11): capability rejections sent by the AP
    (10, "PWR_CAPABILITY_NOT_VALID", CATEGORY_AP, "p"),
    (11, "SUPPORTED_CHANNEL_NOT_VALID", CATEGORY_AP, "p"),
    (12, "BSS_TRANSITION_DISASSOC", CATEGORY_AP, "p"),
    # doubtful: protocol error, filed under security
    (13, "INVALID_IE", CATEGORY_SECURITY, ""),
    (14, "MICHAEL_MIC_FAILURE", CATEGORY_SECURITY, "a"),
    (15, "4WAY_HANDSHAKE_TIMEOUT", CATEGORY_SECURITY, "a"),
    (16, "GROUP_KEY_UPDATE_TIMEOUT", CATEGORY_SECURITY, "a"),
    (17, "IE_IN_4WAY_DIFFERS", CATEGORY_SECURITY, "a"),
    (18, "GROUP_CIPHER_NOT_VALID", CATEGORY_SECURITY, "a"),
    (19, "PAIRWISE_CIPHER_NOT_VALID", CATEGORY_SECURITY, "a"),
    (20, "AKMP_NOT_VALID", CATEGORY_SECURITY, "a"),
    (21, "UNSUPPORTED_RSN_IE_VERSION", CATEGORY_SECURITY, "a"),
    (22, "INVALID_RSN_IE_CAPAB", CATEGORY_SECURITY, "a"),
    (23, "IEEE_802_1X_AUTH_FAILED", CATEGORY_SECURITY, "a"),
    (24, "CIPHER_SUITE_REJECTED", CATEGORY_SECURITY, "a"),
    # doubtful (25, 26): TDLS peer teardown, not AP/client link
    (25, "TDLS_TEARDOWN_UNREACHABLE", CATEGORY_UNKNOWN, ""),
    (26, "TDLS_TEARDOWN_UNSPECIFIED", CATEGORY_UNKNOWN, ""),
    (27, "SSP_REQUESTED_DISASSOC", CATEGORY_AP, "p"),
    (28, "NO_SSP_ROAMING_AGREEMENT", CATEGORY_AP, "p"),
    (29, "BAD_CIPHER_OR_AKM", CATEGORY_SECURITY, "a"),
    (30, "NOT_AUTHORIZED_THIS_LOCATION", CATEGORY_AP, "p"),
    (31, "SERVICE_CHANGE_PRECLUDES_TS", CATEGORY_AP, "p"),
    (32, "UNSPECIFIED_QOS_REASON", CATEGORY_UNKNOWN, ""),
    (33, "NOT_ENOUGH_BANDWIDTH", CATEGORY_AP, "p"),
    (34, "DISASSOC_LOW_ACK", CATEGORY_RADIO, "w"),
    # doubtful: station exceeded TXOP, sent by AP
    (35, "EXCEEDED_TXOP", CATEGORY_AP, "p"),
    (36, "STA_LEAVING", CATEGORY_CLIENT, "s"),
    (37, "END_TS_BA_DLS", CATEGORY_CLIENT, "s"),
    (38, "UNKNOWN_TS_BA", CATEGORY_UNKNOWN, ""),
    # doubtful: peer did not respond in time, filed under inactivity
    (39, "TIMEOUT", CATEGORY_INACTIVITY, ""),
    (45, "PEERKEY_MISMATCH", CATEGORY_SECURITY, "a"),
    (46, "AUTHORIZED_ACCESS_LIMIT_REACHED", CATEGORY_AP, "p"),
    (47, "EXTERNAL_SERVICE_REQUIREMENTS", CATEGORY_AP, "p"),
    # doubtful: fast-transition validation failures filed under security
    (48, "INVALID_FT_ACTION_FRAME_COUNT", CATEGORY_SECURITY, ""),
    (49, "INVALID_PMKID", CATEGORY_SECURITY, "a"),
    (50, "INVALID_MDE", CATEGORY_SECURITY, ""),
    (51, "INVALID_FTE", CATEGORY_SECURITY, ""),
    # doubtful (52-66): mesh peering reasons, not relevant to AP/client links
    (52, "MESH_PEERING_CANCELLED", CATEGORY_UNKNOWN, ""),
    (53, "MESH_MAX_PEERS", CATEGORY_UNKNOWN, ""),
    (54, "MESH_CONFIG_POLICY_VIOLATION", CATEGORY_UNKNOWN, ""),
    (55, "MESH_CLOSE_RCVD", CATEGORY_UNKNOWN, ""),
    (56, "MESH_MAX_RETRIES", CATEGORY_UNKNOWN, ""),
    (57, "MESH_CONFIRM_TIMEOUT", CATEGORY_UNKNOWN, ""),
    (58, "MESH_INVALID_GTK", CATEGORY_UNKNOWN, ""),
    (59, "MESH_INCONSISTENT_PARAMS", CATEGORY_UNKNOWN, ""),
    (60, "MESH_INVALID_SECURITY_CAP", CATEGORY_UNKNOWN, ""),
    (61, "MESH_PATH_ERROR_NO_PROXY_INFO", CATEGORY_UNKNOWN, ""),
    (62, "MESH_PATH_ERROR_NO_FORWARDING_INFO", CATEGORY_UNKNOWN, ""),
    (63, "MESH_PATH_ERROR_DEST_UNREACHABLE", CATEGORY_UNKNOWN, ""),
    (64, "MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS", CATEGORY_UNKNOWN, ""),
    (65, "MESH_CHANNEL_SWITCH_REGULATORY_REQ", CATEGORY_UNKNOWN, ""),
    (66, "MESH_CHANNEL_SWITCH_UNSPECIFIED", CATEGORY_UNKNOWN, ""),
)


def _build(code: int, name: str, category: str, flags: str) -> ReasonInfo:
    ap: bool | None = True if "p" in flags else False if "s" in flags else None
    return ReasonInfo(
        key=name.lower(),
        category=category,
        code=code,
        weak_signal_hint="w" in flags,
        auth_problem="a" in flags,
        ap_initiated=ap,
    )


_BY_CODE: dict[int, ReasonInfo] = {r[0]: _build(*r) for r in _RAW}


def lookup_code(code: int) -> ReasonInfo:
    """Return the info for a numeric reason code; unknown codes never raise."""
    try:
        return _BY_CODE.get(int(code), UNKNOWN)
    except (TypeError, ValueError):
        return UNKNOWN


_INACTIVITY = ReasonInfo("inactivity", CATEGORY_INACTIVITY, ap_initiated=True)
_LOCAL = ReasonInfo("local_request", CATEGORY_AP, ap_initiated=True)
# equivalent to DISASSOC_LOW_ACK (34)
_MISSING_ACKS = ReasonInfo(
    "missing_acks", CATEGORY_RADIO, code=34, weak_signal_hint=True
)
_HANDSHAKE_FAILED = ReasonInfo("handshake_failed", CATEGORY_SECURITY, auth_problem=True)
_HANDSHAKE_TIMEOUT = ReasonInfo(
    "handshake_timeout", CATEGORY_SECURITY, auth_problem=True
)
_INVALID_MIC = ReasonInfo("invalid_mic", CATEGORY_SECURITY, auth_problem=True)
_PSK = ReasonInfo("psk_mismatch", CATEGORY_SECURITY, auth_problem=True)
_MAX_STA = ReasonInfo("max_sta", CATEGORY_AP, ap_initiated=True)
_BLOCKED = ReasonInfo("blocked", CATEGORY_AP, ap_initiated=True)
# RT1 decision: "prune" and "other" stay unknown, their cause is not provable.
_PRUNE = ReasonInfo("prune", CATEGORY_UNKNOWN)
_OTHER = ReasonInfo("other", CATEGORY_UNKNOWN)

_LOG_KEYS: dict[str, ReasonInfo] = {
    "inactivity": _INACTIVITY,
    "local_request": _LOCAL,
    "prune": _PRUNE,
    "other": _OTHER,
    "timeout": _HANDSHAKE_TIMEOUT,
    "invalid_mic": _INVALID_MIC,
    "failed": _HANDSHAKE_FAILED,
    "psk": _PSK,
    "max_sta": _MAX_STA,
    "blocked": _BLOCKED,
}


def from_log_reason(key: str | None) -> ReasonInfo:
    """Map a normalised ``log_parser`` ``REASON_*`` key (None = no reason)."""
    if not key:
        return UNKNOWN
    return _LOG_KEYS.get(key.strip().lower(), UNKNOWN)


_REASON_NUM_RE = re.compile(r"\breason(?:[\s=:]+|\s*code\s*)(\d{1,5})\b")

# (needle, info) checked in order against lower-cased text
_TEXT_RULES: tuple[tuple[str, ReasonInfo], ...] = (
    ("possible-psk-mismatch", _PSK),
    ("invalid mic", _INVALID_MIC),
    ("eapol-key timeout", _HANDSHAKE_TIMEOUT),
    ("group key handshake failed", _HANDSHAKE_FAILED),
    ("pairwise key handshake failed", _HANDSHAKE_FAILED),
    ("4-way handshake failed", _HANDSHAKE_FAILED),
    ("due to inactivity", _INACTIVITY),
    ("local deauth request", _LOCAL),
    ("excessive missing acks", _MISSING_ACKS),
)


def classify_text(text: str) -> ReasonInfo:
    """Classify hostapd log text or a ``reason=N`` fragment."""
    if not text or not isinstance(text, str):
        return UNKNOWN
    low = text.lower()
    hit = _REASON_NUM_RE.search(low)
    if hit:
        info = lookup_code(int(hit.group(1)))
        if info is not UNKNOWN:
            return info
    for needle, info in _TEXT_RULES:
        if needle in low:
            return info
    # RT1 decision: bare "disassociated"/"deauthenticated" -> unknown, since a
    # client-initiated leave is not provable from the text alone.
    return UNKNOWN


def rcpi_to_dbm(rcpi: int) -> float | None:
    """Convert RCPI (0..220, 0.5 dB steps from -110 dBm) to dBm.

    Outside 0..220 (incl. 255 = not available) returns None.
    """
    if isinstance(rcpi, bool):
        return None
    try:
        value = int(rcpi)
    except (TypeError, ValueError):
        return None
    if not 0 <= value <= 220:
        return None
    return value / 2 - 110.0
