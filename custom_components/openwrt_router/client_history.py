"""Client stability history: per-client online state machine and buckets (B1).

Pure module, no Home Assistant imports and no package imports. Time is never
read from the clock here: every entry point takes ``now`` (epoch seconds, the
engine clock) as an argument, so the history is fully deterministic.

What it does (plan ``docs/plans/2026-11-16-client-stability.md`` 2.3-2.5, 4):

* one fleet-wide :class:`ClientHistory`, fed once per router poll with a
  :class:`PollInput`;
* a state machine per MAC (``online`` / ``grace`` / ``offline`` /
  ``unknown``) that tolerates roaming, AP outages, poll gaps and HA restarts:
  a client goes ``offline`` only when it is missing from every *fresh* client
  list of the fleet for ``OFFLINE_AFTER_POLLS`` polls of its router and at
  least ``roam_grace(interval)`` seconds; time without fresh data is a
  measurement gap (``gap_s``), never offline;
* time and counters per (MAC, hour, AP) in hour buckets (7 days), folded into
  day buckets per (MAC, day, AP) when the hour closes (``retention_days``),
  plus a sparse per-day histogram of disconnects per UTC hour and a coverage
  mask for the pattern detection of B3;
* transitions (24 h, at most 64 per MAC) and a raw ring per poll (1 h, at most
  120 per MAC, memory only).

Persistence: ``to_dict`` gives JSON-safe data with packed strings, closed
buckets are packed when the hour closes. ``from_dict`` never raises: a
damaged client is dropped, a damaged bucket or transition is skipped.

[CS-Entscheidung] Input shape. B2 maps the engine's ``PollFacts`` onto
:class:`PollInput`:

* ``router``/``now``/``interval`` come straight from ``PollFacts``;
* ``fresh`` is ``PollFacts.fresh_clients``; ``clients`` holds one
  :class:`ClientObs` per MAC of the router's client list (rates already in
  kbit/s, hostapd ``rate`` / 100; ``ip_visible`` from ``lease_macs`` or
  ``arp_macs``);
* ``events`` are the classified per-client facts: connect and disconnect lines
  from ``wifi_lines`` (disconnect with the parser's plain-text reason), and
  the NI events ``wifi.reconnect``, ``wifi.roam``, ``wifi.band_change``, the
  auth/assoc failures and DHCP failures from ``stored_events``. Reconnects and
  roams are only counted from these events; the history has no own
  reconnect or roam definition. A location change it sees in the lists only
  moves the time attribution to the new AP;
* ``loc`` is the NI location decision (``WifiState.loc``) for MACs listed by
  two routers; ``down_routers`` the routers in outage per the fleet tracker;
  ``infra`` the routers with an open NI root (router -> incident id).

Excluded MACs (NI ``exclusions``) are filtered by B2 before the input is built;
``forget()`` drops existing history.
"""

from __future__ import annotations

import itertools
import logging
import math
import re
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, NamedTuple

_LOGGER = logging.getLogger(__name__)

# --- Constants ---------------------------------------------------------------

SCHEMA_VERSION = 1

STATE_ONLINE = "online"
STATE_GRACE = "grace"
STATE_OFFLINE = "offline"
STATE_UNKNOWN = "unknown"
STATES = frozenset({STATE_ONLINE, STATE_GRACE, STATE_OFFLINE, STATE_UNKNOWN})

DC_ERROR = "error"
DC_INACTIVITY = "inactivity"
DC_LEAVE = "leave"
DC_UNKNOWN = "unknown"
DC_INFRA = "infra"
DC_CLASSES = frozenset({DC_ERROR, DC_INACTIVITY, DC_LEAVE, DC_UNKNOWN, DC_INFRA})

EV_CONNECT = "connect"
EV_DISCONNECT = "disconnect"
EV_RECONNECT = "reconnect"
EV_ROAM = "roam"
EV_BAND_CHANGE = "band_change"
EV_AUTH_FAIL = "auth_fail"
EV_ASSOC_FAIL = "assoc_fail"
EV_DHCP_FAIL = "dhcp_fail"
EVENT_KINDS = frozenset(
    {
        EV_CONNECT,
        EV_DISCONNECT,
        EV_RECONNECT,
        EV_ROAM,
        EV_BAND_CHANGE,
        EV_AUTH_FAIL,
        EV_ASSOC_FAIL,
        EV_DHCP_FAIL,
    }
)

TR_START = "start"  # session begins
TR_END = "end"  # session ended (disconnect), backdated to the grace start
TR_MOVE = "move"  # location (AP) changed inside a session
TR_GAP = "gap"  # measurement gap begins
TR_RESUME = "resume"  # measurement gap ends
TR_BLIP = "blip"  # missing for less than the offline rule, no disconnect
TRANSITION_KINDS = frozenset({TR_START, TR_END, TR_MOVE, TR_GAP, TR_RESUME, TR_BLIP})

# Plain-text reasons of log_parser.REASON_* (copied, no package import).
_REASON_PRUNE = "prune"
_REASON_INACTIVITY = "inactivity"
_LEAVE_REASONS = frozenset({"local_request", "leave", "sta_leaving"})
# [CS-Anpassung 1.41] ``missing_acks`` (reason 34, new in log_parser 1.41) is
# a link error like ``timeout``.
_ERROR_REASONS = frozenset(
    {
        "timeout",
        "invalid_mic",
        "failed",
        "psk",
        "max_sta",
        "blocked",
        "other",
        "missing_acks",
    }
)

WEAK_SIGNAL_DBM = -75  # same value as client_stability.WEAK_SIGNAL_DBM
ROAM_GRACE_MIN_S = 150.0
OFFLINE_AFTER_POLLS = 2
FRESH_FACTOR = 1.25  # a list older than 1.25 poll intervals is not fresh
FLAP_WINDOW_S = 600.0

RAW_RING_S = 3600.0
RAW_RING_MAX = 120
TRANSITIONS_KEEP_S = 86400.0
TRANSITIONS_MAX = 64
# [CS 1.43] Event counts of the last hour (memory only, like the raw ring):
# the trailing 1 h window counts log events from here, not from the clock
# hour bucket. Capped per client; a storm beyond the cap is undercounted in
# the 1 h view only (the buckets keep every count).
RECENT_EVENTS_MAX = 64
FAIL_KINDS = (EV_AUTH_FAIL, EV_ASSOC_FAIL, EV_DHCP_FAIL)
HOURS_KEEP = 168
RETENTION_DAYS_DEFAULT = 30
RETENTION_DAYS_MAX = 90
MAX_CLIENTS_DEFAULT = 1000
# [CS-Entscheidung] A client unknown for longer than a day, or offline for
# longer than a week, stops filling buckets (state kept). Without this every
# long-gone guest writes an hour bucket every hour until retention drops it.
GAP_TRACK_S = 86400.0
OFFLINE_TRACK_S = 7 * 86400.0
# Hours with at least 80 % observed time set the day coverage bit (plan 5).
COVERAGE_MIN_S = 0.8 * 3600

_HOUR = 3600
_DAY = 86400
_MAX_HOUR = 10**7  # far beyond any real hour index; larger is damaged data
_ACCRUE_MAX_S = (HOURS_KEEP + 24) * 3600.0  # older time is pruned anyway

# Load limits (damaged or oversized store data drops the client).
_MAX_APS = 64
_MAX_HOUR_ROWS = HOURS_KEEP * 16
_MAX_DAY_ROWS = RETENTION_DAYS_MAX * 16
_MAX_PACKED_LEN = 600
_MAX_TEXT_LEN = 128

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")

# --- Buckets -----------------------------------------------------------------

BUCKET_FIELDS: tuple[str, ...] = (
    "observed_s",
    "online_s",
    "gap_s",
    "sessions",
    "associations",
    "longest_stable_s",
    "dc_error",
    "dc_inactivity",
    "dc_leave",
    "dc_unknown",
    "dc_infra",
    "reconnects",
    "roams_in",
    "roams_out",
    "roam_flaps",
    "band_changes",
    "auth_fail",
    "assoc_fail",
    "dhcp_fail",
    "rssi_n",
    "rssi_sum",
    "rssi_min",
    "rssi_max",
    "weak_s",
    "ip_visible_n",
    "rate_rx_sum",
    "rate_tx_sum",
    "rate_n",
    # [CS-Entscheidung] Appended after the plan's 28 fields (follow-up to B1):
    # online time per band (2.4/5/6 GHz; the rest of online_s is "band
    # unknown") for the signal-trend rule "same AP and band", and the
    # durations of sessions that ended in the bucket (sum plus a log-scale
    # histogram) so part U can take a median over 7 and 30 days. Rows
    # written before these fields simply lack the trailing fields and load
    # as 0 (= unknown band, no session lengths).
    "online_2g_s",
    "online_5g_s",
    "online_6g_s",
    "session_s_sum",
    *(
        f"sess_{name}"
        for name in (
            "lt5m",
            "lt15m",
            "lt30m",
            "lt1h",
            "lt2h",
            "lt4h",
            "lt6h",
            "lt12h",
            "lt24h",
            "ge24h",
        )
    ),
)
_N = len(BUCKET_FIELDS)
_IX = {name: i for i, name in enumerate(BUCKET_FIELDS)}
I_OBSERVED = _IX["observed_s"]
I_ONLINE = _IX["online_s"]
I_GAP = _IX["gap_s"]
I_SESSIONS = _IX["sessions"]
I_ASSOC = _IX["associations"]
I_LONGEST = _IX["longest_stable_s"]
I_RECONNECTS = _IX["reconnects"]
I_ROAMS_IN = _IX["roams_in"]
I_ROAMS_OUT = _IX["roams_out"]
I_FLAPS = _IX["roam_flaps"]
I_BAND = _IX["band_changes"]
I_RSSI_N = _IX["rssi_n"]
I_RSSI_SUM = _IX["rssi_sum"]
I_RSSI_MIN = _IX["rssi_min"]
I_RSSI_MAX = _IX["rssi_max"]
I_WEAK = _IX["weak_s"]
I_IP = _IX["ip_visible_n"]
I_RATE_RX = _IX["rate_rx_sum"]
I_RATE_TX = _IX["rate_tx_sum"]
I_RATE_N = _IX["rate_n"]
I_SESSION_SUM = _IX["session_s_sum"]
I_SESS_FIRST = _IX["sess_lt5m"]

BAND_2G = "2.4g"
BAND_5G = "5g"
BAND_6G = "6g"
BANDS: tuple[str, ...] = (BAND_2G, BAND_5G, BAND_6G)
_BAND_INDEX = {
    BAND_2G: _IX["online_2g_s"],
    BAND_5G: _IX["online_5g_s"],
    BAND_6G: _IX["online_6g_s"],
}
_BAND_ALIASES = {
    "2.4g": BAND_2G,
    "2g": BAND_2G,
    "2.4": BAND_2G,
    "2.4ghz": BAND_2G,
    "5g": BAND_5G,
    "5": BAND_5G,
    "5ghz": BAND_5G,
    "6g": BAND_6G,
    "6": BAND_6G,
    "6ghz": BAND_6G,
}

# Session duration histogram: upper edges in seconds (last bin open ended)
# and the representative length of each bin in hours (geometric middle of
# the edges; first bin 2.5 min, last bin 24 h as a lower bound).
SESSION_EDGES_S: tuple[float, ...] = (
    300.0,
    900.0,
    1800.0,
    3600.0,
    7200.0,
    14400.0,
    21600.0,
    43200.0,
    86400.0,
)
SESSION_BIN_HOURS: tuple[float, ...] = (
    300.0 / 2 / 3600,
    *((lo * hi) ** 0.5 / 3600 for lo, hi in itertools.pairwise(SESSION_EDGES_S)),
    24.0,
)
SESSION_BINS = len(SESSION_BIN_HOURS)
_DC_INDEX = {
    DC_ERROR: _IX["dc_error"],
    DC_INACTIVITY: _IX["dc_inactivity"],
    DC_LEAVE: _IX["dc_leave"],
    DC_UNKNOWN: _IX["dc_unknown"],
    DC_INFRA: _IX["dc_infra"],
}
_EVENT_INDEX = {
    EV_CONNECT: I_ASSOC,
    EV_RECONNECT: I_RECONNECTS,
    EV_BAND_CHANGE: I_BAND,
    EV_AUTH_FAIL: _IX["auth_fail"],
    EV_ASSOC_FAIL: _IX["assoc_fail"],
    EV_DHCP_FAIL: _IX["dhcp_fail"],
}
# Disconnect classes of the time-pattern histogram (plan 5).
_HIST_INDEXES = (_IX["dc_error"], _IX["dc_unknown"], _IX["dc_inactivity"])
# Only the RSSI sum, min and max may be negative.
_SIGNED = frozenset({I_RSSI_SUM, I_RSSI_MIN, I_RSSI_MAX})


class Bucket(NamedTuple):
    """One hour or day bucket (plan 2.4). All values are ints, 0 = none."""

    observed_s: int = 0
    online_s: int = 0
    gap_s: int = 0
    sessions: int = 0
    associations: int = 0
    longest_stable_s: int = 0
    dc_error: int = 0
    dc_inactivity: int = 0
    dc_leave: int = 0
    dc_unknown: int = 0
    dc_infra: int = 0
    reconnects: int = 0
    roams_in: int = 0
    roams_out: int = 0
    roam_flaps: int = 0
    band_changes: int = 0
    auth_fail: int = 0
    assoc_fail: int = 0
    dhcp_fail: int = 0
    rssi_n: int = 0
    rssi_sum: int = 0
    rssi_min: int = 0
    rssi_max: int = 0
    weak_s: int = 0
    ip_visible_n: int = 0
    rate_rx_sum: int = 0
    rate_tx_sum: int = 0
    rate_n: int = 0
    online_2g_s: int = 0
    online_5g_s: int = 0
    online_6g_s: int = 0
    session_s_sum: int = 0
    sess_lt5m: int = 0
    sess_lt15m: int = 0
    sess_lt30m: int = 0
    sess_lt1h: int = 0
    sess_lt2h: int = 0
    sess_lt4h: int = 0
    sess_lt6h: int = 0
    sess_lt12h: int = 0
    sess_lt24h: int = 0
    sess_ge24h: int = 0


def band_key(value: object) -> str | None:
    """``2.4g`` / ``5g`` / ``6g`` for the usual band spellings, else None."""
    if not isinstance(value, str):
        return None
    return _BAND_ALIASES.get(value.strip().lower().replace(" ", ""))


def band_online(bucket: Bucket) -> dict[str, int]:
    """Online seconds per band; the rest of ``online_s`` has no known band."""
    return {band: bucket[i] for band, i in _BAND_INDEX.items()}


def session_bin(seconds: float) -> int:
    """Histogram bin of a session length."""
    for i, edge in enumerate(SESSION_EDGES_S):
        if seconds < edge:
            return i
    return SESSION_BINS - 1


def session_histogram(bucket: Bucket) -> tuple[int, ...]:
    """Counts of sessions that ended in the bucket, per duration bin."""
    return tuple(bucket[I_SESS_FIRST : I_SESS_FIRST + SESSION_BINS])


def _zeros() -> list[float]:
    return [0] * _N


def merge_into(target: list[float], other: Iterable[float]) -> None:
    """Merge ``other`` into ``target`` in place (both full-length lists).

    Sums everything except ``longest_stable_s`` (max) and ``rssi_min`` /
    ``rssi_max`` (min/max over the buckets that have RSSI values).
    """
    src = list(other)
    a_n, b_n = target[I_RSSI_N], src[I_RSSI_N]
    a_min, a_max = target[I_RSSI_MIN], target[I_RSSI_MAX]
    for i in range(_N):
        target[i] += src[i]
    target[I_LONGEST] = max(target[I_LONGEST] - src[I_LONGEST], src[I_LONGEST])
    if not b_n:
        target[I_RSSI_MIN], target[I_RSSI_MAX] = a_min, a_max
    elif a_n:
        target[I_RSSI_MIN] = min(a_min, src[I_RSSI_MIN])
        target[I_RSSI_MAX] = max(a_max, src[I_RSSI_MAX])
    else:
        target[I_RSSI_MIN], target[I_RSSI_MAX] = src[I_RSSI_MIN], src[I_RSSI_MAX]


def sum_buckets(buckets: Iterable[Bucket]) -> Bucket:
    """Merge any number of buckets into one (see :func:`merge_into`)."""
    total = _zeros()
    for bucket in buckets:
        merge_into(total, bucket)
    return Bucket(*(int(v) for v in total))


def _fmt(value: float) -> str:
    if not value:
        return ""
    if isinstance(value, int) or float(value).is_integer():
        return str(int(value))
    return repr(float(value))


def pack_bucket(values: Iterable[float]) -> str:
    """Pack bucket values as a comma string, zeros empty, trailing commas cut.

    Integral floats are written as ints; other floats (only in still open hour
    buckets) keep their exact ``repr`` so a restart continues losslessly.
    """
    return ",".join(_fmt(v) for v in values).rstrip(",")


def unpack_bucket(packed: Any) -> list[float] | None:
    """Values from :func:`pack_bucket`; None for damaged data (never raises)."""
    if not isinstance(packed, str) or len(packed) > _MAX_PACKED_LEN:
        return None
    parts = packed.split(",") if packed else []
    if len(parts) > _N:
        return None
    out = _zeros()
    for i, part in enumerate(parts):
        if not part:
            continue
        try:
            value: float = int(part)
        except ValueError:
            try:
                value = float(part)
            except ValueError:
                return None
            if not math.isfinite(value):
                return None
        if value < 0 and i not in _SIGNED:
            return None
        out[i] = value
    return out


def _observed(packed: str) -> bool:
    """Whether a packed row has observed time (reads the first field only)."""
    head = packed.partition(",")[0]
    return bool(head) and round(float(head)) > 0


def _bucket(values: list[float]) -> Bucket:
    return Bucket(*(round(v) for v in values))


# --- Input -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClientObs:
    """One client in a fresh client list of the polling router."""

    mac: str
    band: str | None = None
    rssi: int | None = None
    rate_rx_kbit: int | None = None
    rate_tx_kbit: int | None = None
    ip_visible: bool = False
    hostname: str | None = None
    ip: str | None = None


@dataclass(frozen=True, slots=True)
class ClientEvent:
    """One classified per-client fact (log line or NI event).

    ``kind`` is one of ``EVENT_KINDS``. ``router`` is where it happened (for a
    roam: the new AP; ``peer`` the AP left). ``reason`` is the parser's plain
    text reason of a disconnect line. ``infra``/``incident_id`` mark a
    disconnect inside the window of an NI root cause. ``count`` is the number
    of attempts for the failure kinds.
    """

    mac: str
    kind: str
    ts: float
    router: str
    reason: str | None = None
    peer: str | None = None
    count: int = 1
    infra: bool = False
    incident_id: str | None = None


@dataclass(frozen=True, slots=True)
class PollInput:
    """Everything the history needs from one poll of one router."""

    router: str
    now: float
    interval: float
    fresh: bool
    clients: tuple[ClientObs, ...] = ()
    events: tuple[ClientEvent, ...] = ()
    down_routers: frozenset[str] = frozenset()
    infra: Mapping[str, str] = field(default_factory=dict)
    loc: Mapping[str, str] = field(default_factory=dict)


# --- Output views --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Transition:
    """One state change (plan 2.4 ``(t, art, ap, grund, klasse, incident_id)``).

    ``timed`` is False when the moment is not known (a disconnect found after
    a measurement gap; ``ts`` is then the start of the gap).
    """

    ts: float
    kind: str
    ap: str
    reason: str | None = None
    cls: str | None = None
    incident_id: str | None = None
    timed: bool = True


@dataclass(frozen=True, slots=True)
class RingEntry:
    """One raw poll sample (memory only)."""

    ts: float
    ap: str
    band: str | None
    rssi: int | None
    state: str
    ip_visible: bool = False
    rate_rx_kbit: int | None = None
    rate_tx_kbit: int | None = None


@dataclass(frozen=True, slots=True)
class LastDisconnect:
    """The last finished session end."""

    ts: float
    reason: str | None
    cls: str
    timed: bool


@dataclass(frozen=True, slots=True)
class LastFailure:
    """The last auth, association or DHCP failure (``kind`` = event kind)."""

    ts: float
    kind: str


@dataclass(frozen=True, slots=True)
class ClientLive:
    """Read-only snapshot of one client's live state."""

    mac: str
    private_mac: bool
    state: str
    since: float | None
    ap: str | None
    band: str | None
    rssi: int | None
    session_start: float | None
    session_start_known: bool
    first_seen: float | None
    last_seen: float | None
    last_disconnect: LastDisconnect | None
    hostname: str | None
    hostname_changed: float | None
    ip: str | None
    ip_changed: float | None
    last_failure: LastFailure | None = None


class HourBucket(NamedTuple):
    """Hour bucket view: ``hour`` = ``ts // 3600``; ``ap`` "" = no AP (offline)."""

    hour: int
    ap: str
    bucket: Bucket
    closed: bool


class DayBucket(NamedTuple):
    """Day bucket view: ``day`` = ``ts // 86400`` (UTC)."""

    day: int
    ap: str
    bucket: Bucket


@dataclass(frozen=True, slots=True)
class DayMeta:
    """Per (MAC, UTC day) data for the time-pattern detection (B3).

    ``coverage_mask`` bit h is set when hour h (UTC) had at least 80 %
    observed time; ``disconnects`` maps hour h to the error, unknown and
    inactivity disconnects in it (sparse).
    """

    coverage_mask: int
    disconnects: Mapping[int, int]


# --- Helpers -------------------------------------------------------------------


def roam_grace(interval: float) -> float:
    """``max(2 * interval, 150 s)`` (plan 2.3)."""
    return max(2.0 * float(interval), ROAM_GRACE_MIN_S)


def classify_disconnect(reason: str | None, infra: bool = False) -> str | None:
    """Disconnect class of a disconnect line; None for ``prune`` (= roaming)."""
    text = (reason or "").strip().lower()
    if text == _REASON_PRUNE:
        return None
    if infra:
        return DC_INFRA
    if text == _REASON_INACTIVITY:
        return DC_INACTIVITY
    if text in _LEAVE_REASONS:
        return DC_LEAVE
    if text in _ERROR_REASONS:
        return DC_ERROR
    return DC_UNKNOWN


def normalize_mac(value: Any) -> str | None:
    """Upper-case ``AA:BB:..`` form, or None when it is not a MAC."""
    if not isinstance(value, str):
        return None
    mac = value.strip().upper().replace("-", ":")
    return mac if _MAC_RE.match(mac) else None


def is_private_mac(mac: str) -> bool:
    """Locally administered MAC (bit 0x02 of the first octet)."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def _finite(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _opt_float(value: Any) -> float | None:
    return float(value) if _finite(value) else None


def _opt_text(value: Any) -> str | None:
    if isinstance(value, str) and len(value) <= _MAX_TEXT_LEN:
        return value
    return None


# --- Internal state ------------------------------------------------------------


@dataclass(slots=True)
class _RouterList:
    t: float
    interval: float
    macs: frozenset[str]
    stale: bool = False


@dataclass(slots=True)
class _Pending:
    """A disconnect or connect line waiting for the presence decision."""

    ts: float
    router: str
    reason: str | None = None
    cls: str | None = None
    incident_id: str | None = None


@dataclass(slots=True)
class _Client:
    mac: str
    private: bool
    first_seen: float | None = None
    last_seen: float | None = None
    last_activity: float = 0.0
    state: str = STATE_UNKNOWN
    since: float | None = None
    ap: str | None = None
    band: str | None = None
    rssi: int | None = None
    # time up to which online/offline/gap seconds are booked; None = never
    # located, nothing to book
    acc: float | None = None
    session_start: float | None = None
    start_known: bool = False
    grace_start: float | None = None  # session end if the grace turns offline
    grace_from: float | None = None  # missing time is measured from here
    grace_polls: int = 0
    grace_timed: bool = True
    grace_reason: str | None = None
    grace_cls: str | None = None
    infra: str | None = None  # incident id ("" unknown) of an NI root seen
    pend_down: _Pending | None = None
    pend_connect: _Pending | None = None
    last_roam: tuple[float, str, str] | None = None  # ts, from, to
    last_dc: LastDisconnect | None = None
    host: str | None = None
    host_t: float | None = None
    ip: str | None = None
    ip_t: float | None = None
    ring: deque[RingEntry] = field(default_factory=lambda: deque(maxlen=RAW_RING_MAX))
    transitions: deque[Transition] = field(
        default_factory=lambda: deque(maxlen=TRANSITIONS_MAX)
    )
    # (ts, ((field index, value), ...)) of the log events of the last hour
    recent: deque[tuple[float, tuple[tuple[int, float], ...]]] = field(
        default_factory=lambda: deque(maxlen=RECENT_EVENTS_MAX)
    )
    last_fail: LastFailure | None = None
    open: dict[tuple[int, str], list[float]] = field(default_factory=dict)
    closed: dict[tuple[int, str], str] = field(default_factory=dict)
    days: dict[tuple[int, str], str] = field(default_factory=dict)
    meta: dict[int, tuple[int, dict[int, int]]] = field(default_factory=dict)


# --- History -------------------------------------------------------------------


class ClientHistory:
    """Fleet-wide client stability history (state machine + buckets)."""

    def __init__(
        self,
        retention_days: int = RETENTION_DAYS_DEFAULT,
        max_clients: int = MAX_CLIENTS_DEFAULT,
    ) -> None:
        self.retention_days = max(1, min(RETENTION_DAYS_MAX, int(retention_days)))
        self.max_clients = max(1, int(max_clients))
        self._clients: dict[str, _Client] = {}
        self._lists: dict[str, _RouterList] = {}
        # hours below the mark are closed (packed, folded into days)
        self._mark: int | None = None
        # start of a fleet-wide blind window (no fresh list) during an ingest
        self._blind_from: float | None = None

    # --- reading -------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._clients)

    def __contains__(self, mac: object) -> bool:
        return normalize_mac(mac) in self._clients

    def macs(self) -> list[str]:
        """All tracked MACs, sorted."""
        return sorted(self._clients)

    def live(self, mac: str) -> ClientLive | None:
        """Live state of one client."""
        c = self._get(mac)
        if c is None:
            return None
        return ClientLive(
            mac=c.mac,
            private_mac=c.private,
            state=c.state,
            since=c.since,
            ap=c.ap,
            band=c.band,
            rssi=c.rssi,
            session_start=c.session_start,
            session_start_known=c.start_known,
            first_seen=c.first_seen,
            last_seen=c.last_seen,
            last_disconnect=c.last_dc,
            hostname=c.host,
            hostname_changed=c.host_t,
            ip=c.ip,
            ip_changed=c.ip_t,
            last_failure=c.last_fail,
        )

    def hours(
        self,
        mac: str,
        first: int | None = None,
        last: int | None = None,
        *,
        open_only: bool = False,
    ) -> list[HourBucket]:
        """Hour buckets (closed and open) with ``first <= hour <= last``;
        ``open_only`` skips the closed ones without unpacking them."""
        c = self._get(mac)
        if c is None:
            return []
        out: list[HourBucket] = []
        for (hour, ap), packed in () if open_only else c.closed.items():
            if not _in(hour, first, last):
                continue
            values = unpack_bucket(packed)
            if values is not None:
                out.append(HourBucket(hour, ap, _bucket(values), True))
        for (hour, ap), values in c.open.items():
            if _in(hour, first, last):
                out.append(HourBucket(hour, ap, _bucket(values), False))
        out.sort(key=lambda b: (b.hour, b.ap))
        return out

    def days(
        self, mac: str, first: int | None = None, last: int | None = None
    ) -> list[DayBucket]:
        """Day buckets (from closed hours) with ``first <= day <= last``."""
        c = self._get(mac)
        if c is None:
            return []
        out = [
            DayBucket(day, ap, _bucket(values))
            for (day, ap), packed in c.days.items()
            if _in(day, first, last) and (values := unpack_bucket(packed)) is not None
        ]
        out.sort(key=lambda b: (b.day, b.ap))
        return out

    def span(self, mac: str, first: int, last: int) -> list[tuple[str, Bucket]]:
        """(AP, bucket) pairs covering the hours ``first..last``.

        Whole UTC days inside the range come from their day bucket (the
        closed hours folded with the same merge as :func:`sum_buckets`); the
        edge hours and every open hour come from the hour buckets. Merged per
        AP this equals :meth:`hours` but unpacks far fewer rows; after
        :meth:`trim_closed_hours` the whole days keep their data.
        """
        c = self._get(mac)
        if c is None:
            return []
        day_first, day_last = -(-first // 24), (last + 1) // 24 - 1
        out: list[tuple[str, Bucket]] = []
        for (day, ap), packed in c.days.items():
            if not day_first <= day <= day_last:
                continue
            if (values := unpack_bucket(packed)) is not None:
                out.append((ap, _bucket(values)))
        for (hour, ap), packed in c.closed.items():
            if not first <= hour <= last or day_first <= hour // 24 <= day_last:
                continue
            if (values := unpack_bucket(packed)) is not None:
                out.append((ap, _bucket(values)))
        out.extend(
            (ap, _bucket(values))
            for (hour, ap), values in c.open.items()
            if first <= hour <= last
        )
        return out

    def observed_days(self, mac: str) -> int:
        """UTC days with observed time (day buckets, closed and open hours).

        Reads only the leading ``observed_s`` field of the packed rows (they
        are validated on load and written by :func:`pack_bucket`), so no
        bucket is unpacked just to count days.
        """
        c = self._get(mac)
        if c is None:
            return 0
        days = {day for (day, _ap), packed in c.days.items() if _observed(packed)}
        days.update(
            hour // 24 for (hour, _ap), packed in c.closed.items() if _observed(packed)
        )
        days.update(
            hour // 24 for (hour, _ap), values in c.open.items() if round(values[0]) > 0
        )
        return len(days)

    def day_meta(self, mac: str) -> dict[int, DayMeta]:
        """Coverage mask and disconnect histogram per UTC day."""
        c = self._get(mac)
        if c is None:
            return {}
        return {
            day: DayMeta(mask, dict(hist))
            for day, (mask, hist) in sorted(c.meta.items())
        }

    def transitions(self, mac: str) -> tuple[Transition, ...]:
        """Stored transitions, oldest first."""
        c = self._get(mac)
        return tuple(c.transitions) if c is not None else ()

    def ring(self, mac: str) -> tuple[RingEntry, ...]:
        """Raw poll samples of the last hour (memory only), oldest first."""
        c = self._get(mac)
        return tuple(c.ring) if c is not None else ()

    def recent_bucket(self, mac: str, start: float, end: float) -> Bucket:
        """Log event counts with ``start <= ts <= end`` from the in-memory
        event ring (last hour, :data:`RECENT_EVENTS_MAX` events; empty after
        a restart). Only the event fields are set."""
        c = self._get(mac)
        values = _zeros()
        for ts, delta in c.recent if c is not None else ():
            if start <= ts <= end:
                for index, value in delta:
                    values[index] += value
        return _bucket(values)

    # --- maintenance -----------------------------------------------------------

    def forget(self, mac: str) -> bool:
        """Drop all history of one MAC (exclusion, user request)."""
        key = normalize_mac(mac)
        return key is not None and self._clients.pop(key, None) is not None

    def remove_router(self, router: str) -> None:
        """Forget a router's client list; its clients become a gap next poll."""
        self._lists.pop(router, None)

    def shift_clock(self, delta: float) -> None:
        """Move all live times by ``delta`` seconds (NI clock model).

        Bucket indexes stay (they are wall-clock hours and days).
        """
        if not _finite(delta) or not delta:
            return
        for lst in self._lists.values():
            lst.t += delta
        for c in self._clients.values():
            _shift_client(c, delta)

    def prune(self, now: float) -> None:
        """Apply retention: hours 7 d, days ``retention_days``, transitions
        24 h, clients idle longer than ``retention_days``."""
        if not _finite(now):
            return
        hour_cut = int(now // _HOUR) - HOURS_KEEP
        day_cut = int(now // _DAY) - self.retention_days
        idle_cut = now - self.retention_days * _DAY
        tr_cut = now - TRANSITIONS_KEEP_S
        for mac in list(self._clients):
            c = self._clients[mac]
            if c.state in (STATE_OFFLINE, STATE_UNKNOWN) and c.last_activity < idle_cut:
                del self._clients[mac]
                continue
            for key in [k for k in c.open if k[0] < hour_cut]:
                del c.open[key]
            for key in [k for k in c.closed if k[0] < hour_cut]:
                del c.closed[key]
            for key in [k for k in c.days if k[0] <= day_cut]:
                del c.days[key]
            for day in [d for d in c.meta if d <= day_cut]:
                del c.meta[day]
            while c.transitions and c.transitions[0].ts < tr_cut:
                c.transitions.popleft()
            while c.ring and c.ring[0].ts < now - RAW_RING_S:
                c.ring.popleft()
            while c.recent and c.recent[0][0] < now - RAW_RING_S:
                c.recent.popleft()

    # --- store size trimming (B8) ----------------------------------------------

    def trim_transitions(self) -> int:
        """Drop the transitions of offline and unknown clients; returns count."""
        dropped = 0
        for c in self._clients.values():
            if c.state in (STATE_OFFLINE, STATE_UNKNOWN) and c.transitions:
                dropped += len(c.transitions)
                c.transitions.clear()
        return dropped

    def trim_closed_hours(self, before_hour: int, private_only: bool = False) -> int:
        """Drop closed hour buckets below ``before_hour``; returns count.

        Closed hours are already folded into the day buckets, so only the hour
        resolution of that time is lost.
        """
        dropped = 0
        for c in self._clients.values():
            if private_only and not c.private:
                continue
            for key in [k for k in c.closed if k[0] < before_hour]:
                del c.closed[key]
                dropped += 1
        return dropped

    def drop_oldest(self, count: int) -> int:
        """Drop up to ``count`` clients, least recently active first.

        Offline and unknown clients go before online ones.
        """
        order = sorted(
            self._clients.values(),
            key=lambda c: (
                c.state not in (STATE_OFFLINE, STATE_UNKNOWN),
                c.last_activity,
                c.mac,
            ),
        )
        victims = order[: max(0, int(count))]
        for c in victims:
            del self._clients[c.mac]
        return len(victims)

    # --- ingest ----------------------------------------------------------------

    def ingest(self, poll: PollInput) -> None:
        """Apply one router poll. Invalid input is ignored, never raised."""
        if not _finite(poll.now) or not _finite(poll.interval) or poll.interval <= 0:
            _LOGGER.debug("client history: invalid poll time or interval, skipped")
            return
        if not isinstance(poll.router, str) or not poll.router:
            return
        now = float(poll.now)
        router = poll.router
        if self._mark is None:
            self._mark = int(now // _HOUR)

        # Fleet freshness before this poll (gap detection for offline clients).
        # A stale list's ``t`` is still the time it was last fresh.
        fleet_fresh = any(self._fresh(r, now) for r in self._lists)
        fleet_last = max((lst.t for lst in self._lists.values()), default=-math.inf)
        self._blind_from = None if fleet_fresh else fleet_last

        for down in poll.down_routers:
            if down != router or not poll.fresh:
                self._mark_stale(down)
        if not poll.fresh:
            self._mark_stale(router)

        # 1. clients whose router is no longer fresh go to a measurement gap
        for c in self._clients.values():
            if c.state in (STATE_ONLINE, STATE_GRACE) and not self._fresh(c.ap, now):
                self._to_gap(c, now, poll)
            if (
                c.state in (STATE_GRACE, STATE_UNKNOWN)
                and c.ap is not None
                and c.ap in poll.infra
            ):
                c.infra = poll.infra.get(c.ap) or ""

        # 2. classified events, oldest first
        self._apply_events(poll, now)

        # 3. presence in the fresh list of the polling router
        if poll.fresh:
            self._apply_list(poll, now, router)

        # 4. book gap and offline time of everybody else up to now
        for c in self._clients.values():
            if c.acc is None:
                continue
            if c.state == STATE_UNKNOWN:
                self._book_gap(c, now)
            elif c.state == STATE_OFFLINE:
                self._book_offline(c, now, self._blind_from)

        # 5. close finished hours (pack, fold into days) and prune hourly
        hour = int(now // _HOUR)
        if hour > self._mark:
            for c in self._clients.values():
                self._close_hours(c, hour)
            self._mark = hour
            self.prune(now)

    # --- ingest steps ------------------------------------------------------------

    def _apply_events(self, poll: PollInput, now: float) -> None:
        events = [
            ev
            for ev in poll.events
            if isinstance(ev, ClientEvent)
            and ev.kind in EVENT_KINDS
            and _finite(ev.ts)
            and isinstance(ev.router, str)
            and ev.router
            and now - ev.ts <= HOURS_KEEP * _HOUR
        ]
        events.sort(key=lambda ev: ev.ts)
        for ev in events:
            mac = normalize_mac(ev.mac)
            if mac is None:
                continue
            c = self._client(mac, now)
            if c is None:
                continue
            ts = min(float(ev.ts), now)
            c.last_activity = max(c.last_activity, ts)
            if ev.kind == EV_DISCONNECT:
                cls = classify_disconnect(ev.reason, ev.infra)
                if cls is None:  # prune: roaming, not a disconnect
                    continue
                if c.ap is None or c.ap == ev.router:
                    c.pend_down = _Pending(
                        ts,
                        ev.router,
                        _opt_text(ev.reason),
                        cls,
                        _opt_text(ev.incident_id),
                    )
                continue
            if ev.kind == EV_ROAM:
                self._apply_roam(c, ts, ev)
                continue
            count = ev.count if isinstance(ev.count, int) and ev.count > 0 else 1
            delta = _zeros()
            delta[_EVENT_INDEX[ev.kind]] = min(count, 1000)
            self._add(c, ts, ev.router, delta)
            _remember(c, ts, delta)
            if ev.kind in FAIL_KINDS and (c.last_fail is None or ts >= c.last_fail.ts):
                c.last_fail = LastFailure(ts, ev.kind)
            if ev.kind == EV_CONNECT:
                c.pend_connect = _Pending(ts, ev.router)

    def _apply_roam(self, c: _Client, ts: float, ev: ClientEvent) -> None:
        delta = _zeros()
        delta[I_ROAMS_IN] = 1
        peer = ev.peer if isinstance(ev.peer, str) and ev.peer else None
        last = c.last_roam
        if (
            peer is not None
            and last is not None
            and last[1] == ev.router
            and last[2] == peer
            and 0 <= ts - last[0] <= FLAP_WINDOW_S
        ):
            delta[I_FLAPS] = 1
        self._add(c, ts, ev.router, delta)
        _remember(c, ts, delta)
        if peer is not None:
            out = _zeros()
            out[I_ROAMS_OUT] = 1
            self._add(c, ts, peer, out)
            _remember(c, ts, out)
            c.last_roam = (ts, peer, ev.router)

    def _apply_list(self, poll: PollInput, now: float, router: str) -> None:
        seen: dict[str, ClientObs] = {}
        for obs in poll.clients:
            if not isinstance(obs, ClientObs):
                continue
            mac = normalize_mac(obs.mac)
            if mac is not None:
                seen[mac] = obs
        self._lists[router] = _RouterList(
            now, float(poll.interval), frozenset(seen), False
        )
        for mac, obs in seen.items():
            c = self._client(mac, now)
            if c is None:
                continue
            if (
                c.state == STATE_ONLINE
                and c.ap is not None
                and c.ap != router
                and poll.loc.get(mac) != router
                and self._fresh(c.ap, now)
                and mac in self._lists[c.ap].macs
            ):
                # Listed by two routers: the time counts once, at the current
                # location (NI W9: undecided stays at the previous place).
                continue
            self._see(c, now, router, obs, poll)
        for c in list(self._clients.values()):
            if c.ap == router and c.mac not in seen and c.state != STATE_OFFLINE:
                self._missing(c, now, router, poll)

    # --- state machine -----------------------------------------------------------

    def _see(
        self, c: _Client, now: float, ap: str, obs: ClientObs, poll: PollInput
    ) -> None:
        pc = c.pend_connect
        connect_ts = pc.ts if pc is not None and pc.ts <= now else None
        if (c.acc is None or c.state == STATE_OFFLINE) and obs.band is not None:
            # A new session is booked with the band of its first sample; an
            # ongoing one with the band of the previous sample (like RSSI).
            c.band = _opt_text(obs.band)
        if c.acc is None:
            # First sighting: a connect line in this poll window dates the start.
            window = FRESH_FACTOR * float(poll.interval)
            if connect_ts is not None and now - connect_ts <= window:
                self._start_session(c, connect_ts, ap, known=True)
                self._accrue_online(c, connect_ts, now, ap)
            else:
                self._start_session(c, now, ap, known=False)
            c.first_seen = now if c.first_seen is None else c.first_seen
        elif c.state == STATE_ONLINE:
            self._accrue_online(c, c.acc, now, c.ap or ap)
            if c.ap != ap:
                self._transition(c, Transition(now, TR_MOVE, ap))
        elif c.state == STATE_GRACE:
            self._accrue_online(c, c.acc, now, c.ap or ap)
            self._transition(c, Transition(now, TR_BLIP, ap, c.grace_reason))
            if c.ap != ap:
                self._transition(c, Transition(now, TR_MOVE, ap))
        elif c.state == STATE_UNKNOWN:
            self._book_gap(c, now)
            self._transition(c, Transition(now, TR_RESUME, ap))
            if c.session_start is None:
                self._start_session(c, now, ap, known=False)
            elif c.ap != ap:
                self._transition(c, Transition(now, TR_MOVE, ap))
        else:  # offline
            start = now
            if connect_ts is not None and connect_ts > c.acc:
                start = connect_ts
            self._book_offline(c, start, self._blind_from)
            self._start_session(c, start, ap, known=True)
            self._accrue_online(c, start, now, ap)
        c.state = STATE_ONLINE
        # [CS-Entscheidung] "online since" = session start (a blip or a gap
        # inside the session does not reset it).
        c.since = c.session_start if c.session_start is not None else now
        self._clear_grace(c)
        c.pend_down = None
        c.pend_connect = None
        c.ap = ap
        c.acc = now
        c.last_seen = now
        c.last_activity = max(c.last_activity, now)
        if obs.band is not None:
            c.band = _opt_text(obs.band)
        self._sample(c, now, ap, obs)
        rates = _rate_ok(obs.rate_rx_kbit) and _rate_ok(obs.rate_tx_kbit)
        c.ring.append(
            RingEntry(
                now,
                ap,
                c.band,
                c.rssi,
                STATE_ONLINE,
                bool(obs.ip_visible),
                obs.rate_rx_kbit if rates else None,
                obs.rate_tx_kbit if rates else None,
            )
        )

    def _missing(self, c: _Client, now: float, router: str, poll: PollInput) -> None:
        other = self._listed_elsewhere(c.mac, now, router, poll)
        if other is not None:
            # Roamed (or a stale second table): no disconnect, follow it.
            if c.state == STATE_UNKNOWN:
                self._book_gap(c, now)
                self._transition(c, Transition(now, TR_RESUME, other))
            else:
                self._accrue_online(c, c.acc, now, router)
                if c.state == STATE_GRACE:
                    self._transition(c, Transition(now, TR_BLIP, other, c.grace_reason))
            self._transition(c, Transition(now, TR_MOVE, other))
            self._clear_grace(c)
            c.state = STATE_ONLINE
            c.since = c.session_start if c.session_start is not None else now
            c.ap = other
            c.acc = now
            c.ring.append(RingEntry(now, other, c.band, c.rssi, STATE_ONLINE))
            return
        if router in poll.infra:
            c.infra = poll.infra.get(router) or ""
        pd = c.pend_down
        if pd is not None and (pd.router != router or (c.last_seen or 0) > pd.ts):
            pd = None
        if c.state == STATE_ONLINE:
            acc = c.acc if c.acc is not None else now
            start = min(max(pd.ts, acc), now) if pd is not None else acc
            self._accrue_online(c, acc, start, router)
            c.state = STATE_GRACE
            c.since = start
            c.grace_start = start
            c.grace_from = start
            c.grace_timed = True
            c.grace_polls = 1
            c.grace_reason = pd.reason if pd else None
            c.grace_cls = pd.cls if pd else None
            if pd is not None and pd.cls == DC_INFRA:
                c.infra = pd.incident_id or ""
            c.acc = start
        elif c.state == STATE_GRACE:
            c.grace_polls += 1
        elif c.state == STATE_UNKNOWN:
            # Router back after a gap and the client is gone: disconnect at an
            # unknown time inside the gap, after the usual grace.
            self._book_gap(c, now)
            self._transition(c, Transition(now, TR_RESUME, router))
            gap_start = c.since if c.since is not None else now
            if pd is not None:
                c.grace_start, c.grace_timed = pd.ts, True
                c.grace_reason, c.grace_cls = pd.reason, pd.cls
            else:
                if c.grace_start is None:
                    c.grace_start = gap_start
                c.grace_timed = False
            c.state = STATE_GRACE
            c.since = c.grace_start
            c.grace_from = now
            c.grace_polls = 1
            c.acc = now
        c.ring.append(RingEntry(now, router, c.band, None, c.state))
        if c.state == STATE_GRACE:
            self._check_offline(c, now, router, poll)

    def _check_offline(
        self, c: _Client, now: float, router: str, poll: PollInput
    ) -> None:
        grace_from = c.grace_from if c.grace_from is not None else now
        if c.grace_polls < OFFLINE_AFTER_POLLS:
            return
        if now - grace_from < roam_grace(poll.interval):
            return
        pc = c.pend_connect
        if (
            pc is not None
            and pc.router != router
            and c.grace_start is not None
            and pc.ts >= c.grace_start
        ):
            lst = self._lists.get(pc.router)
            if lst is not None and not lst.stale and lst.t < pc.ts:
                return  # connected elsewhere, that router has not polled since
        self._end_session(c, now, router, poll)

    def _end_session(
        self, c: _Client, now: float, router: str, poll: PollInput
    ) -> None:
        end = c.grace_start if c.grace_start is not None else now
        cls = c.grace_cls or DC_UNKNOWN
        incident: str | None = None
        if c.infra is not None or router in poll.infra or cls == DC_INFRA:
            cls = DC_INFRA
            incident = c.infra or poll.infra.get(router) or None
        self._book_offline(c, now, None, force=True)
        delta = _zeros()
        delta[_DC_INDEX[cls]] = 1
        if c.session_start is not None:
            length = max(0.0, end - c.session_start)
            delta[I_LONGEST] = length
            delta[I_SESSION_SUM] = length
            delta[I_SESS_FIRST + session_bin(length)] = 1
        self._add(c, end, router, delta)
        self._transition(
            c,
            Transition(
                end, TR_END, router, c.grace_reason, cls, incident, c.grace_timed
            ),
        )
        c.last_dc = LastDisconnect(end, c.grace_reason, cls, c.grace_timed)
        c.state = STATE_OFFLINE
        c.since = end
        c.session_start = None
        c.start_known = False
        self._clear_grace(c)
        c.pend_down = None
        c.acc = now

    def _to_gap(self, c: _Client, now: float, poll: PollInput) -> None:
        lst = self._lists.get(c.ap) if c.ap is not None else None
        acc = c.acc if c.acc is not None else now
        last = min(max(lst.t, acc), now) if lst is not None else acc
        if c.state == STATE_ONLINE:
            self._accrue_online(c, acc, last, c.ap or "")
            c.acc = last
        # A grace that loses its router stays undecided: gap from grace_from.
        c.state = STATE_UNKNOWN
        c.since = c.acc
        c.grace_polls = 0
        c.grace_from = None
        if c.ap is not None and c.ap in poll.infra:
            c.infra = poll.infra.get(c.ap) or ""
        self._transition(c, Transition(c.acc or now, TR_GAP, c.ap or ""))
        c.ring.append(RingEntry(now, c.ap or "", c.band, None, STATE_UNKNOWN))

    def _start_session(self, c: _Client, start: float, ap: str, known: bool) -> None:
        c.session_start = start
        c.start_known = known
        c.since = start
        c.state = STATE_ONLINE
        delta = _zeros()
        delta[I_SESSIONS] = 1
        self._add(c, start, ap, delta)
        self._transition(c, Transition(start, TR_START, ap))

    @staticmethod
    def _clear_grace(c: _Client) -> None:
        c.grace_start = None
        c.grace_from = None
        c.grace_polls = 0
        c.grace_timed = True
        c.grace_reason = None
        c.grace_cls = None
        c.infra = None

    # --- booking time --------------------------------------------------------------

    def _accrue_online(self, c: _Client, a: float | None, b: float, ap: str) -> None:
        if a is None:
            return
        weak = c.rssi is not None and c.rssi <= WEAK_SIGNAL_DBM
        band_ix = _BAND_INDEX.get(band_key(c.band) or "")
        for hour_start, secs in _split(a, b):
            delta = _zeros()
            delta[I_OBSERVED] = secs
            delta[I_ONLINE] = secs
            if weak:
                delta[I_WEAK] = secs
            if band_ix is not None:
                delta[band_ix] = secs
            self._add(c, hour_start, ap, delta)

    def _book_gap(self, c: _Client, now: float) -> None:
        if c.acc is None or now <= c.acc:
            return
        since = c.since if c.since is not None else c.acc
        end = min(now, max(c.acc, since + GAP_TRACK_S))
        for hour_start, secs in _split(c.acc, end):
            delta = _zeros()
            delta[I_GAP] = secs
            self._add(c, hour_start, c.ap or "", delta)
        c.acc = now

    def _book_offline(
        self, c: _Client, now: float, blind_from: float | None, force: bool = False
    ) -> None:
        """Book offline time ``[acc, now)``; the part after ``blind_from``
        (no fresh list anywhere in the fleet) is a gap instead."""
        if c.acc is None or now <= c.acc:
            return
        a = c.acc
        split = now if blind_from is None else min(max(blind_from, a), now)
        since = c.since if c.since is not None else a
        end = now if force else min(now, max(a, since + OFFLINE_TRACK_S))
        for hour_start, secs in _split(a, min(split, end)):
            delta = _zeros()
            delta[I_OBSERVED] = secs
            self._add(c, hour_start, "", delta)
        for hour_start, secs in _split(split, end):
            delta = _zeros()
            delta[I_GAP] = secs
            self._add(c, hour_start, "", delta)
        c.acc = now

    def _sample(self, c: _Client, now: float, ap: str, obs: ClientObs) -> None:
        delta = _zeros()
        rssi = obs.rssi
        if isinstance(rssi, int) and not isinstance(rssi, bool) and -120 <= rssi < 0:
            delta[I_RSSI_N] = 1
            delta[I_RSSI_SUM] = rssi
            delta[I_RSSI_MIN] = rssi
            delta[I_RSSI_MAX] = rssi
            c.rssi = rssi
        if obs.ip_visible:
            delta[I_IP] = 1
        rx, tx = obs.rate_rx_kbit, obs.rate_tx_kbit
        # [CS-Entscheidung] A rate sample counts only with both directions.
        if _rate_ok(rx) and _rate_ok(tx):
            delta[I_RATE_RX] = rx
            delta[I_RATE_TX] = tx
            delta[I_RATE_N] = 1
        self._add(c, now, ap, delta)
        host = _opt_text(obs.hostname)
        if host and host != c.host:
            c.host, c.host_t = host, now
        ip = _opt_text(obs.ip)
        if ip and ip != c.ip:
            c.ip, c.ip_t = ip, now

    def _add(self, c: _Client, ts: float, ap: str, delta: list[float]) -> None:
        hour = int(ts // _HOUR)
        key = (hour, ap)
        if self._mark is None or hour >= self._mark:
            cur = c.open.get(key)
            if cur is None:
                c.open[key] = cur = _zeros()
            merge_into(cur, delta)
            return
        # Late write into a closed hour (e.g. a grace resolved after the hour
        # closed): update the packed hour, the day and the day meta.
        rounded = [round(v) for v in delta]
        cur_closed = unpack_bucket(c.closed.get(key, "")) or _zeros()
        merge_into(cur_closed, rounded)
        c.closed[key] = pack_bucket(round(v) for v in cur_closed)
        self._fold_day(c, hour, ap, rounded)
        self._refresh_meta(c, hour)

    def _close_hours(self, c: _Client, hour_now: int) -> None:
        done = [k for k in c.open if k[0] < hour_now]
        if not done:
            return
        hours: set[int] = set()
        for key in sorted(done):
            values = [round(v) for v in c.open.pop(key)]
            prev = unpack_bucket(c.closed.get(key, ""))
            if prev is not None and key in c.closed:
                merge_into(values, prev)
            c.closed[key] = pack_bucket(values)
            self._fold_day(c, key[0], key[1], values)
            hours.add(key[0])
        for hour in hours:
            self._refresh_meta(c, hour)

    @staticmethod
    def _fold_day(c: _Client, hour: int, ap: str, values: list[float]) -> None:
        key = (hour // 24, ap)
        day = unpack_bucket(c.days.get(key, "")) or _zeros()
        merge_into(day, values)
        c.days[key] = pack_bucket(day)

    @staticmethod
    def _refresh_meta(c: _Client, hour: int) -> None:
        observed = 0.0
        dc = 0
        for (h, _ap), packed in c.closed.items():
            if h != hour:
                continue
            values = unpack_bucket(packed)
            if values is None:
                continue
            observed += values[I_OBSERVED]
            dc += int(sum(values[i] for i in _HIST_INDEXES))
        day = hour // 24
        mask, hist = c.meta.get(day, (0, {}))
        bit = 1 << (hour % 24)
        mask = mask | bit if observed >= COVERAGE_MIN_S else mask & ~bit
        hist = dict(hist)
        if dc > 0:
            hist[hour % 24] = dc
        else:
            hist.pop(hour % 24, None)
        if mask or hist:
            c.meta[day] = (mask, hist)
        else:
            c.meta.pop(day, None)

    # --- helpers -------------------------------------------------------------------

    def _get(self, mac: str) -> _Client | None:
        key = normalize_mac(mac)
        return self._clients.get(key) if key is not None else None

    def _client(self, mac: str, now: float) -> _Client | None:
        c = self._clients.get(mac)
        if c is not None:
            return c
        if len(self._clients) >= self.max_clients and not self._evict():
            _LOGGER.debug("client history: max_clients reached, new client not tracked")
            return None
        c = _Client(mac=mac, private=is_private_mac(mac), last_activity=now)
        self._clients[mac] = c
        return c

    def _evict(self) -> bool:
        """Drop the least recently active client that is not online."""
        idle = [
            c
            for c in self._clients.values()
            if c.state in (STATE_OFFLINE, STATE_UNKNOWN)
        ]
        if not idle:
            return False
        victim = min(idle, key=lambda c: (c.last_activity, c.mac))
        del self._clients[victim.mac]
        return True

    def _fresh(self, router: str | None, now: float) -> bool:
        if router is None:
            return False
        lst = self._lists.get(router)
        return (
            lst is not None
            and not lst.stale
            and now - lst.t <= FRESH_FACTOR * lst.interval
        )

    def _mark_stale(self, router: str) -> None:
        lst = self._lists.get(router)
        if lst is not None:
            lst.stale = True

    def _listed_elsewhere(
        self, mac: str, now: float, router: str, poll: PollInput
    ) -> str | None:
        found = [
            (lst.t, r)
            for r, lst in self._lists.items()
            if r != router and mac in lst.macs and self._fresh(r, now)
        ]
        if not found:
            return None
        hint = poll.loc.get(mac)
        if hint is not None and any(r == hint for _t, r in found):
            return hint
        return max(found)[1]

    @staticmethod
    def _transition(c: _Client, tr: Transition) -> None:
        c.transitions.append(tr)

    # --- persistence ---------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe snapshot (the raw ring is not included)."""
        return {
            "v": SCHEMA_VERSION,
            "mark": self._mark,
            "lists": {
                r: [lst.t, lst.interval, int(lst.stale), sorted(lst.macs)]
                for r, lst in self._lists.items()
            },
            "clients": {mac: _dump_client(c) for mac, c in self._clients.items()},
        }

    @classmethod
    def from_dict(
        cls,
        data: Any,
        retention_days: int = RETENTION_DAYS_DEFAULT,
        max_clients: int = MAX_CLIENTS_DEFAULT,
    ) -> ClientHistory:
        """Rebuild leniently; damaged parts are dropped, never raised."""
        hist = cls(retention_days, max_clients)
        if not isinstance(data, dict) or data.get("v") != SCHEMA_VERSION:
            if data:
                _LOGGER.warning("client history: unknown store schema, starting empty")
            return hist
        mark = data.get("mark")
        if (
            isinstance(mark, int)
            and not isinstance(mark, bool)
            and 0 <= mark < _MAX_HOUR
        ):
            hist._mark = mark
        lists = data.get("lists")
        if isinstance(lists, dict):
            for router, raw in lists.items():
                lst = _load_list(raw)
                if isinstance(router, str) and router and lst is not None:
                    hist._lists[router] = lst
        clients = data.get("clients")
        loaded: list[_Client] = []
        dropped = 0
        if isinstance(clients, dict):
            for key, raw in clients.items():
                mac = normalize_mac(key)
                c = None
                if mac is not None:
                    try:
                        c = _load_client(mac, raw)
                    except (
                        TypeError,
                        ValueError,
                        AttributeError,
                        KeyError,
                        IndexError,
                    ):
                        c = None
                if c is None:
                    dropped += 1
                else:
                    loaded.append(c)
        if len(loaded) > hist.max_clients:
            loaded.sort(key=lambda c: (-c.last_activity, c.mac))
            dropped += len(loaded) - hist.max_clients
            loaded = loaded[: hist.max_clients]
        for c in loaded:
            hist._clients[c.mac] = c
        if dropped:
            _LOGGER.warning(
                "client history: %d damaged or surplus clients dropped", dropped
            )
        return hist


# --- module helpers -------------------------------------------------------------


def _in(index: int, first: int | None, last: int | None) -> bool:
    return (first is None or index >= first) and (last is None or index <= last)


def _rate_ok(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 100_000_000
    )


def _split(a: float, b: float) -> list[tuple[float, float]]:
    """``[a, b)`` cut at hour borders: ``(segment start, seconds)``."""
    if b <= a:
        return []
    a = max(a, b - _ACCRUE_MAX_S)
    out: list[tuple[float, float]] = []
    t = a
    while t < b:
        end = min(b, (math.floor(t / _HOUR) + 1) * _HOUR)
        out.append((t, end - t))
        t = end
    return out


def _remember(c: _Client, ts: float, delta: list[float]) -> None:
    """Keep the non-zero event fields for the trailing hour (memory only)."""
    c.recent.append((ts, tuple((i, v) for i, v in enumerate(delta) if v)))


def _shift_client(c: _Client, delta: float) -> None:
    for name in (
        "first_seen",
        "last_seen",
        "since",
        "acc",
        "session_start",
        "grace_start",
        "grace_from",
        "host_t",
        "ip_t",
    ):
        value = getattr(c, name)
        if value is not None:
            setattr(c, name, value + delta)
    c.last_activity += delta
    for pend in (c.pend_down, c.pend_connect):
        if pend is not None:
            pend.ts += delta
    if c.last_roam is not None:
        ts, a, b = c.last_roam
        c.last_roam = (ts + delta, a, b)
    if c.last_dc is not None:
        last = c.last_dc
        c.last_dc = LastDisconnect(last.ts + delta, last.reason, last.cls, last.timed)
    if c.last_fail is not None:
        c.last_fail = LastFailure(c.last_fail.ts + delta, c.last_fail.kind)
    c.recent = deque(
        ((ts + delta, values) for ts, values in c.recent), maxlen=RECENT_EVENTS_MAX
    )
    c.transitions = deque(
        (
            Transition(
                t.ts + delta, t.kind, t.ap, t.reason, t.cls, t.incident_id, t.timed
            )
            for t in c.transitions
        ),
        maxlen=TRANSITIONS_MAX,
    )
    c.ring = deque((replace(r, ts=r.ts + delta) for r in c.ring), maxlen=RAW_RING_MAX)


def _clean(value: str | None) -> str:
    """Transition text field: '' for None and for text with the separator."""
    return value if value and "|" not in value else ""


def _dump_client(c: _Client) -> dict[str, Any]:
    aps: dict[str, int] = {}

    def ap_ix(ap: str) -> int:
        if ap not in aps:
            aps[ap] = len(aps)
        return aps[ap]

    hours = [
        f"{h}:{ap_ix(ap)}:{packed}" for (h, ap), packed in sorted(c.closed.items())
    ]
    open_hours = [
        f"{h}:{ap_ix(ap)}:{pack_bucket(values)}"
        for (h, ap), values in sorted(c.open.items())
    ]
    days = [f"{d}:{ap_ix(ap)}:{packed}" for (d, ap), packed in sorted(c.days.items())]
    meta = [
        f"{day}:{mask}:" + ";".join(f"{h}={n}" for h, n in sorted(hist.items()))
        for day, (mask, hist) in sorted(c.meta.items())
    ]
    trans = [
        "|".join(
            (
                repr(float(t.ts)),
                t.kind,
                str(ap_ix(t.ap)),
                _clean(t.reason),
                t.cls or "",
                _clean(t.incident_id),
                "1" if t.timed else "0",
            )
        )
        for t in c.transitions
    ]
    live: dict[str, Any] = {
        "s": c.state,
        "si": c.since,
        "ap": c.ap,
        "b": c.band,
        "r": c.rssi,
        "acc": c.acc,
        "ss": c.session_start,
        "sk": int(c.start_known),
        "gs": c.grace_start,
        "gf": c.grace_from,
        "gp": c.grace_polls,
        "gt": int(c.grace_timed),
        "gr": c.grace_reason,
        "gc": c.grace_cls,
        "inf": c.infra,
        "pd": _dump_pending(c.pend_down),
        "pc": _dump_pending(c.pend_connect),
        "lr": list(c.last_roam) if c.last_roam else None,
        "ld": (
            [c.last_dc.ts, c.last_dc.reason, c.last_dc.cls, int(c.last_dc.timed)]
            if c.last_dc
            else None
        ),
        "lf": [c.last_fail.ts, c.last_fail.kind] if c.last_fail else None,
    }
    meta_info: dict[str, Any] = {
        "p": int(c.private),
        "fs": c.first_seen,
        "ls": c.last_seen,
        "la": c.last_activity,
        "hn": c.host,
        "ht": c.host_t,
        "ip": c.ip,
        "it": c.ip_t,
    }
    out: dict[str, Any] = {
        "m": {k: v for k, v in meta_info.items() if v is not None},
        "l": {k: v for k, v in live.items() if v is not None},
        "aps": list(aps),
    }
    for key, rows in (
        ("h", hours),
        ("ho", open_hours),
        ("d", days),
        ("dm", meta),
        ("tr", trans),
    ):
        if rows:
            out[key] = rows
    return out


def _dump_pending(p: _Pending | None) -> list[Any] | None:
    if p is None:
        return None
    return [p.ts, p.router, p.reason, p.cls, p.incident_id]


def _load_pending(raw: Any) -> _Pending | None:
    if not isinstance(raw, list) or len(raw) != 5 or not _finite(raw[0]):
        return None
    if not isinstance(raw[1], str) or not raw[1]:
        return None
    cls = raw[3] if raw[3] in DC_CLASSES else None
    return _Pending(float(raw[0]), raw[1], _opt_text(raw[2]), cls, _opt_text(raw[4]))


def _load_list(raw: Any) -> _RouterList | None:
    if not isinstance(raw, list) or len(raw) != 4:
        return None
    t, interval, stale, macs = raw
    if not _finite(t) or not _finite(interval) or interval <= 0:
        return None
    if not isinstance(macs, list) or len(macs) > MAX_CLIENTS_DEFAULT * 4:
        return None
    clean = frozenset(m for m in (normalize_mac(x) for x in macs) if m is not None)
    return _RouterList(float(t), float(interval), clean, bool(stale))


def _parse_rows(
    raw: Any, aps: list[str], limit: int, closed: bool
) -> dict[tuple[int, str], list[float]] | None:
    """``"<index>:<ap index>:<packed>"`` rows; None when oversized."""
    out: dict[tuple[int, str], list[float]] = {}
    if raw is None:
        return out
    if not isinstance(raw, list) or len(raw) > limit:
        return None
    for row in raw:
        if not isinstance(row, str):
            continue
        parts = row.split(":", 2)
        if len(parts) != 3:
            continue
        try:
            index, ap_i = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        if not 0 <= index < _MAX_HOUR or not 0 <= ap_i < len(aps):
            continue
        values = unpack_bucket(parts[2])
        if values is None:
            continue
        if closed:
            values = [round(v) for v in values]
        out[(index, aps[ap_i])] = values
    return out


def _load_meta(raw: Any) -> dict[int, tuple[int, dict[int, int]]]:
    out: dict[int, tuple[int, dict[int, int]]] = {}
    if not isinstance(raw, list):
        return out
    for row in raw[:_MAX_DAY_ROWS]:
        if not isinstance(row, str):
            continue
        parts = row.split(":", 2)
        if len(parts) != 3:
            continue
        try:
            day, mask = int(parts[0]), int(parts[1])
            hist: dict[int, int] = {}
            for item in parts[2].split(";") if parts[2] else ():
                h, _sep, n = item.partition("=")
                hour, count = int(h), int(n)
                if 0 <= hour < 24 and count > 0:
                    hist[hour] = count
        except ValueError:
            continue
        if 0 <= day < _MAX_HOUR and 0 <= mask < (1 << 24):
            out[day] = (mask, hist)
    return out


def _load_transition(row: Any, aps: list[str]) -> Transition | None:
    if not isinstance(row, str):
        return None
    parts = row.split("|")
    if len(parts) != 7:
        return None
    try:
        ts, ap_i = float(parts[0]), int(parts[2])
    except ValueError:
        return None
    if not math.isfinite(ts) or not 0 <= ap_i < len(aps):
        return None
    if parts[1] not in TRANSITION_KINDS:
        return None
    cls = parts[4] if parts[4] in DC_CLASSES else None
    return Transition(
        ts,
        parts[1],
        aps[ap_i],
        parts[3] or None,
        cls,
        parts[5] or None,
        parts[6] != "0",
    )


def _load_client(mac: str, raw: Any) -> _Client | None:
    if not isinstance(raw, dict):
        return None
    meta = raw.get("m")
    live = raw.get("l")
    aps = raw.get("aps", [])
    if not isinstance(meta, dict) or not isinstance(live, dict):
        return None
    if not isinstance(aps, list) or len(aps) > _MAX_APS:
        return None
    if not all(isinstance(ap, str) and len(ap) <= _MAX_TEXT_LEN for ap in aps):
        return None
    state = live.get("s")
    if state not in STATES:
        return None
    c = _Client(mac=mac, private=is_private_mac(mac))
    c.first_seen = _opt_float(meta.get("fs"))
    c.last_seen = _opt_float(meta.get("ls"))
    c.last_activity = _opt_float(meta.get("la")) or 0.0
    c.host, c.host_t = _opt_text(meta.get("hn")), _opt_float(meta.get("ht"))
    c.ip, c.ip_t = _opt_text(meta.get("ip")), _opt_float(meta.get("it"))
    c.state = state
    c.since = _opt_float(live.get("si"))
    c.ap = _opt_text(live.get("ap"))
    c.band = _opt_text(live.get("b"))
    rssi = live.get("r")
    c.rssi = rssi if isinstance(rssi, int) and not isinstance(rssi, bool) else None
    c.acc = _opt_float(live.get("acc"))
    c.session_start = _opt_float(live.get("ss"))
    c.start_known = bool(live.get("sk"))
    c.grace_start = _opt_float(live.get("gs"))
    c.grace_from = _opt_float(live.get("gf"))
    polls = live.get("gp", 0)
    c.grace_polls = polls if isinstance(polls, int) and 0 <= polls < 10**6 else 0
    c.grace_timed = bool(live.get("gt", 1))
    c.grace_reason = _opt_text(live.get("gr"))
    c.grace_cls = live.get("gc") if live.get("gc") in DC_CLASSES else None
    c.infra = _opt_text(live.get("inf"))
    c.pend_down = _load_pending(live.get("pd"))
    c.pend_connect = _load_pending(live.get("pc"))
    lr = live.get("lr")
    if (
        isinstance(lr, list)
        and len(lr) == 3
        and _finite(lr[0])
        and isinstance(lr[1], str)
        and isinstance(lr[2], str)
    ):
        c.last_roam = (float(lr[0]), lr[1], lr[2])
    ld = live.get("ld")
    if isinstance(ld, list) and len(ld) == 4 and _finite(ld[0]) and ld[2] in DC_CLASSES:
        c.last_dc = LastDisconnect(float(ld[0]), _opt_text(ld[1]), ld[2], bool(ld[3]))
    lf = live.get("lf")  # [CS 1.43] absent in 1.42 stores
    if isinstance(lf, list) and len(lf) == 2 and _finite(lf[0]) and lf[1] in FAIL_KINDS:
        c.last_fail = LastFailure(float(lf[0]), lf[1])
    if state in (STATE_ONLINE, STATE_GRACE) and (c.ap is None or c.acc is None):
        return None  # a located state without location or booking time
    if state == STATE_GRACE and (c.grace_start is None or c.grace_from is None):
        return None

    closed = _parse_rows(raw.get("h"), aps, _MAX_HOUR_ROWS, closed=True)
    opened = _parse_rows(raw.get("ho"), aps, _MAX_HOUR_ROWS, closed=False)
    days = _parse_rows(raw.get("d"), aps, _MAX_DAY_ROWS, closed=True)
    if closed is None or opened is None or days is None:
        return None
    c.closed = {k: pack_bucket(v) for k, v in closed.items()}
    c.open = opened
    c.days = {k: pack_bucket(v) for k, v in days.items()}
    c.meta = _load_meta(raw.get("dm"))
    trans = raw.get("tr")
    if trans is not None:
        if not isinstance(trans, list) or len(trans) > TRANSITIONS_MAX:
            return None
        for row in trans:
            tr = _load_transition(row, aps)
            if tr is not None:
                c.transitions.append(tr)
    return c
