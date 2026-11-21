"""Evaluation of one poll's WiFi RF data (pure, no HA; release 1.48.0 part 1).

Turns the poll data the coordinator already has plus the answers of the
extra RF reads (:class:`.rf_collector.RoundResult`) into one
:class:`RadioResult` per radio, and all radios of the fleet into one
:class:`FleetResult`. Every figure comes from the ``rf_*`` modules; this
module only feeds them:

* utilization: counter delta of ``hostapd get_status`` (``airtime.time`` /
  ``time_busy``, :func:`.rf_utilization.bss_load_from_get_status`), never
  the ``utilization`` byte; ``iwinfo survey`` only when get_status is off;
* retries: delta of the ``iwinfo assoclist`` TX counters between two reads;
* signal: the hostapd client signal of every poll (a one-hour window per
  client kept in :class:`RadioMemory`);
* noise, TX power, country, HT mode, center channel: ``iwinfo info`` of the
  poll (AP interface details).

Unknown stays unknown: a missing source, a failed read, a router restart
(uptime went back) or a reset counter gives a metric without value, never 0
and never "good". :class:`RadioMemory` is the only state (memory only, the
history lives in :mod:`.rf_store`).
"""

from __future__ import annotations

import logging
import statistics
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .channel_plan import (
    _AP_MODES,
    _as_int,
    _band_of,
    phy_of,
    radios_from_ap_interfaces,
)
from .client_history import WEAK_SIGNAL_DBM
from .const import (
    CLIENT_KEY_MAC,
    CLIENT_KEY_RADIO,
    CLIENT_KEY_SIGNAL,
    RADIO_KEY_CHANNEL,
    RADIO_KEY_ENABLED,
    RADIO_KEY_FREQUENCY,
    RADIO_KEY_HTMODE,
    RADIO_KEY_IFNAME,
    RADIO_KEY_IFNAME_IS_SECTION,
    RADIO_KEY_MODE,
    RADIO_KEY_NAME,
    RADIO_KEY_PHY,
    RADIO_KEY_TXPOWER,
)
from .rf_clients import (
    AssocCounters,
    ClientAssessment,
    ClientRfWindow,
    RadioClientSummary,
    assess_client,
    assoc_counters_from_assoclist,
    counter_delta,
    summarize_radio_clients,
)
from .rf_collector import (
    RF_KIND_ASSOCLIST,
    RF_KIND_FREQLIST,
    RF_KIND_GET_STATUS,
    RF_KIND_SURVEY,
    RF_KIND_TXPOWERLIST,
)
from .rf_conflicts import (
    Conflict,
    ConflictKind,
    RadioView,
    detect_conflicts,
)
from .rf_health import (
    AggregateHealth,
    HealthScore,
    ap_health,
    component_from_metric,
    item_from,
    monitoring_coverage,
    network_health,
    overlap_component,
    radio_health,
    score_retry_rate,
    score_utilization,
)
from .rf_identity import RadioRef, require_radio_id
from .rf_load import (
    ApLoadInput,
    DistributionReport,
    LoadReport,
    RadioLoad,
    assess_load,
    distribution,
)
from .rf_models import (
    METRIC_ACTIVE_TIME,
    METRIC_BUSY_TIME,
    METRIC_CHANNEL,
    METRIC_CLIENT_AIRTIME,
    METRIC_CLIENTS,
    METRIC_CONNECTED_TIME,
    METRIC_COUNTRY,
    METRIC_FAILED,
    METRIC_FREQLIST,
    METRIC_NOISE,
    METRIC_RATE,
    METRIC_RETRIES,
    METRIC_RSSI,
    METRIC_RX_TIME,
    METRIC_SCAN,
    METRIC_TX_TIME,
    METRIC_TXPOWER,
    METRIC_TXPOWER_MAX,
    METRIC_UTILIZATION,
    METRIC_WIDTH,
    SOURCE_HOSTAPD_STATUS,
    SOURCE_IWINFO_ASSOCLIST,
    SOURCE_IWINFO_INFO,
    SOURCE_IWINFO_SURVEY,
    CapabilityState,
    Metric,
    RadioCapabilities,
    metric_measured,
    metric_missing,
    with_staleness,
)
from .rf_recommend import (
    Recommendation,
    recommend_channel,
    recommend_load,
    recommend_tx_power,
    recommend_width,
)
from .rf_scan_policy import DEFAULT_SCAN_CAPABILITY
from .rf_spectrum import (
    Channel,
    RadioRegulatory,
    channels_from_freqlist,
    tx_power_limits,
    txpowers_from_txpowerlist,
)
from .rf_utilization import (
    DEFAULT_MAX_GAP_S,
    SurveySample,
    UnknownReason,
    UtilizationResult,
    UtilizationSummary,
    UtilizationThresholds,
    bss_load_from_get_status,
    summarize,
    survey_samples_from_iwinfo,
    utilization_from_delta,
)

_LOGGER = logging.getLogger(__name__)

# Source of the figures taken from the poll's hostapd client list.
SOURCE_HOSTAPD_CLIENTS = "hostapd.get_clients"
RADIO_ID_UCI = "uci"
RADIO_ID_PHY = "phy"
# Per-client signal window (Client Stability works on the same hour).
SIGNAL_WINDOW_S = 3600.0
SIGNAL_SAMPLES_MAX = 60
CLIENTS_PER_RADIO_MAX = 256
UTIL_WINDOW_S = 3600.0
UTIL_POINTS_MAX = 120
_ERROR_STATES = frozenset({CapabilityState.UNSUPPORTED, CapabilityState.UNREACHABLE})
_OVERLAP_KINDS = frozenset({ConflictKind.CO_CHANNEL, ConflictKind.ADJACENT_OVERLAP})

KindState = Callable[[str, str], tuple[CapabilityState | None, str | None]]


def _whole(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    if isinstance(value, float) and not value.is_integer():
        return None
    return int(value)


def _token(value: Any) -> str | None:
    try:
        return require_radio_id(value)
    except ValueError:
        return None


# --- radios of one poll -------------------------------------------------------------


@dataclass(frozen=True)
class RadioInput:
    """One radio of one poll, from data the poll already has."""

    radio_id: str
    radio_id_source: str
    phy: str
    band: str
    channel: int
    width: int
    center: int
    backhaul: bool
    htmode: str | None
    mhz: int | None
    devices: tuple[str, ...]  # kernel AP interfaces, first = primary
    noise: int | None
    txpower: int | None
    country: str | None

    @property
    def primary(self) -> str | None:
        """The interface asked for the per-radio reads."""
        return self.devices[0] if self.devices else None


def _iface_matches(iface: dict[str, Any], phy: str, band: str) -> bool:
    if not iface.get(RADIO_KEY_ENABLED, True):
        return False
    if str(iface.get(RADIO_KEY_MODE) or "").lower() not in _AP_MODES:
        return False
    ifname = str(iface.get(RADIO_KEY_IFNAME) or "")
    if str(iface.get(RADIO_KEY_PHY) or phy_of(ifname)) != phy:
        return False
    return _band_of(iface, _as_int(iface.get(RADIO_KEY_CHANNEL))) == band


def _radio_id(
    phy: str, band: str, names: set[str], seen: set[str]
) -> tuple[str | None, str]:
    """UCI radio name when exactly one is known, else the phy (marked)."""
    if len(names) == 1:
        name = _token(next(iter(names)))
        if name is not None and name != phy and name not in seen:
            return name, RADIO_ID_UCI
    radio_id = _token(phy)
    if radio_id in seen:
        # Multi-band wiphy without UCI names: one phy, two bands.
        radio_id = _token(f"{phy}@{band}")
    return radio_id, RADIO_ID_PHY


def radio_inputs(data: Any) -> list[RadioInput]:
    """One :class:`RadioInput` per physical radio of the poll's AP interfaces."""
    ap = [i for i in getattr(data, "ap_interfaces", None) or [] if isinstance(i, dict)]
    sta = getattr(data, "sta_interfaces", None) or []
    uci = {
        r.get(RADIO_KEY_IFNAME): r.get(RADIO_KEY_NAME)
        for r in getattr(data, "wifi_radios", None) or []
        if isinstance(r, dict) and r.get(RADIO_KEY_IFNAME)
    }
    out: list[RadioInput] = []
    seen: set[str] = set()
    for radio in radios_from_ap_interfaces("", "", ap, sta):
        ifaces = [i for i in ap if _iface_matches(i, radio.phy, radio.band)]
        if not ifaces:
            continue
        names = {str(n) for i in ifaces if (n := uci.get(i.get(RADIO_KEY_IFNAME)))}
        radio_id, source = _radio_id(radio.phy, radio.band, names, seen)
        if radio_id is None:
            continue
        seen.add(radio_id)
        first = ifaces[0]
        noise = _whole(first.get("noise"))
        country = first.get("country")
        htmode = first.get(RADIO_KEY_HTMODE)
        mhz = _whole(first.get(RADIO_KEY_FREQUENCY))
        out.append(
            RadioInput(
                radio_id=radio_id,
                radio_id_source=source,
                phy=radio.phy,
                band=radio.band,
                channel=radio.channel,
                width=radio.width,
                center=radio.center,
                backhaul=radio.backhaul,
                htmode=htmode if isinstance(htmode, str) and htmode else None,
                mhz=mhz if mhz and mhz > 0 else None,
                devices=tuple(
                    str(i.get(RADIO_KEY_IFNAME))
                    for i in ifaces
                    if i.get(RADIO_KEY_IFNAME)
                    and not i.get(RADIO_KEY_IFNAME_IS_SECTION)
                ),
                # iwinfo reports 0 when the driver gave no noise: unknown
                noise=noise if noise is not None and noise < 0 else None,
                txpower=_whole(first.get(RADIO_KEY_TXPOWER)),
                country=country if isinstance(country, str) and country else None,
            )
        )
    return out


def clients_by_device(data: Any) -> dict[str, list[dict[str, Any]]]:
    """The poll's WiFi clients per kernel interface."""
    out: dict[str, list[dict[str, Any]]] = {}
    for client in getattr(data, "clients", None) or []:
        if isinstance(client, dict) and client.get(CLIENT_KEY_RADIO):
            out.setdefault(str(client[CLIENT_KEY_RADIO]), []).append(client)
    return out


def client_mac(client: Mapping[str, Any]) -> str | None:
    """Lower-case MAC of a client dict (memory only, never output)."""
    mac = client.get(CLIENT_KEY_MAC)
    return mac.lower() if isinstance(mac, str) and mac else None


# --- memory ---------------------------------------------------------------------------


@dataclass
class SourceMemory:
    """Last sample and result of one counter source (get_status or survey)."""

    sample: SurveySample | None = None
    result: UtilizationResult | None = None
    noise: int | None = None
    at: float | None = None


@dataclass
class RadioMemory:
    """What is remembered of one radio between polls (memory only)."""

    channel: int | None = None
    status: SourceMemory = field(default_factory=SourceMemory)
    survey: SourceMemory = field(default_factory=SourceMemory)
    util_points: deque[tuple[float, float | None]] = field(
        default_factory=lambda: deque(maxlen=UTIL_POINTS_MAX)
    )
    assoc_prev: dict[str, AssocCounters] = field(default_factory=dict)
    assoc_read: bool = False
    assoc_delta: dict[str, tuple[int | None, int | None, int | None]] = field(
        default_factory=dict
    )
    assoc_at: float | None = None
    signals: dict[str, deque[tuple[float, float]]] = field(default_factory=dict)
    airtime_prev: dict[str, int] = field(default_factory=dict)
    channels: tuple[Channel, ...] | None = None
    txpowers: tuple[int, ...] | None = None


@dataclass(frozen=True)
class RadioResult:
    """Evaluation of one radio in one poll (memory only, not yet masked)."""

    ref: RadioRef
    radio: RadioInput
    view: RadioView
    caps: RadioCapabilities
    utilization: UtilizationResult | None
    summary: UtilizationSummary | None
    client_summary: RadioClientSummary
    assessments: tuple[ClientAssessment, ...]
    metrics: Mapping[str, Metric | None]
    sources: Mapping[str, Mapping[str, Any]]
    load: RadioLoad
    client_macs: tuple[str, ...]
    store_values: Mapping[str, Any]
    measured_at: float

    @property
    def client_count(self) -> int:
        """Clients on the radio in this poll."""
        return len(self.client_macs)


# --- one radio -------------------------------------------------------------------------


@dataclass(frozen=True)
class PollInput:
    """Everything of one poll that one radio's evaluation reads."""

    kinds: frozenset[str]
    answers: Mapping[tuple[str, str], Mapping[str, Any]]
    errors: Mapping[tuple[str, str], str]
    kind_state: KindState
    now: float
    uptime: float | None
    max_age_s: float
    interval_s: float
    # Part 2 (Q5): per-MAC facts of the Client Stability history
    # (``rf_client_link.ClientHistoryFacts``); None without the history.
    history: Callable[[str], Any] | None = None


def _error(poll: PollInput, kind: str, device: str | None) -> CapabilityState | None:
    """UNSUPPORTED/UNREACHABLE of the last attempt, else None."""
    if kind not in poll.kinds or device is None:
        return None
    state, _reason = poll.kind_state(kind, device)
    return state if state in _ERROR_STATES else None


def _read_source(
    memory: SourceMemory,
    sample: SurveySample | None,
    radio: RadioInput,
    now: float,
    source: str,
    max_gap_s: float = DEFAULT_MAX_GAP_S,
) -> None:
    if sample is None:
        memory.result = UtilizationResult(
            radio_id=radio.radio_id,
            measured_at=now,
            reason=UnknownReason.MISSING_FIELD,
            source=source,
        )
        memory.noise = None
    else:
        memory.result = utilization_from_delta(
            memory.sample, sample, max_gap_s=max_gap_s
        )
        memory.sample = sample
        memory.noise = sample.noise
    memory.at = now


def _update_counters(memory: RadioMemory, radio: RadioInput, poll: PollInput) -> bool:
    """Read get_status/survey answers; True when the utilization source read."""
    device = radio.primary
    if device is None:
        return False
    # The allowed gap between two samples follows the real read interval
    # (1.49.3): with a fixed 600 s, wifi_rf_every_n_polls >= 10 (reads every
    # 600 s plus the poll time) left the utilization unknown for good.
    gap = max(DEFAULT_MAX_GAP_S, poll.max_age_s)
    status = poll.answers.get((RF_KIND_GET_STATUS, device))
    if status is not None:
        bss = bss_load_from_get_status(status)
        sample = bss.as_sample(radio.radio_id, poll.now, poll.uptime) if bss else None
        _read_source(memory.status, sample, radio, poll.now, SOURCE_HOSTAPD_STATUS, gap)
    survey = poll.answers.get((RF_KIND_SURVEY, device))
    if survey is not None:
        samples = survey_samples_from_iwinfo(
            survey, radio.radio_id, poll.now, poll.uptime, mhz=radio.mhz
        )
        sample = samples[0] if samples and radio.mhz else None
        _read_source(memory.survey, sample, radio, poll.now, SOURCE_IWINFO_SURVEY, gap)
    kind = _util_kind(poll.kinds)
    if kind is None:
        return False
    if (kind, device) in poll.answers:
        chosen = memory.status if kind == RF_KIND_GET_STATUS else memory.survey
        pct = chosen.result.busy_pct if chosen.result else None
        memory.util_points.append((poll.now, pct))
        return True
    if (kind, device) in poll.errors:  # a failed read is a gap, not a value
        memory.util_points.append((poll.now, None))
        return True
    return False


def _util_kind(kinds: frozenset[str]) -> str | None:
    """get_status is the utilization source; survey only when it is off."""
    if RF_KIND_GET_STATUS in kinds:
        return RF_KIND_GET_STATUS
    if RF_KIND_SURVEY in kinds:
        return RF_KIND_SURVEY
    return None


def _util_metric(
    memory: RadioMemory, radio: RadioInput, poll: PollInput
) -> tuple[Metric | None, UtilizationResult | None]:
    kind = _util_kind(poll.kinds)
    if kind is None:
        return None, None
    chosen = memory.status if kind == RF_KIND_GET_STATUS else memory.survey
    source = (
        SOURCE_HOSTAPD_STATUS if kind == RF_KIND_GET_STATUS else SOURCE_IWINFO_SURVEY
    )
    error = _error(poll, kind, radio.primary)
    if error is not None:
        return metric_missing(error, source), chosen.result
    if chosen.result is None:
        return metric_missing(CapabilityState.NO_DATA, source), None
    metric = with_staleness(chosen.result.busy_metric(), poll.now, poll.max_age_s)
    return metric, chosen.result


def _update_lists(memory: RadioMemory, radio: RadioInput, poll: PollInput) -> None:
    device = radio.primary
    if device is None:
        return
    freq = poll.answers.get((RF_KIND_FREQLIST, device))
    if freq is not None:
        memory.channels = tuple(channels_from_freqlist(freq)) or None
    power = poll.answers.get((RF_KIND_TXPOWERLIST, device))
    if power is not None:
        memory.txpowers = txpowers_from_txpowerlist(power)


def _update_assoc(memory: RadioMemory, radio: RadioInput, poll: PollInput) -> bool:
    """Assoclist counters of all AP interfaces; True when a delta was taken."""
    answered = [d for d in radio.devices if (RF_KIND_ASSOCLIST, d) in poll.answers]
    if not answered:
        return False
    current: dict[str, AssocCounters] = {}
    for device in answered:
        current.update(
            assoc_counters_from_assoclist(poll.answers[(RF_KIND_ASSOCLIST, device)])
        )
    current = dict(list(current.items())[:CLIENTS_PER_RADIO_MAX])
    had_previous = memory.assoc_read
    previous = memory.assoc_prev
    memory.assoc_delta = {
        mac: (
            counter_delta(old.tx_packets, new.tx_packets),
            counter_delta(old.tx_retries, new.tx_retries),
            counter_delta(old.tx_failed, new.tx_failed),
        )
        for mac, new in current.items()
        if (old := previous.get(mac)) is not None
    }
    memory.assoc_prev = current
    memory.assoc_read = True
    if had_previous:
        memory.assoc_at = poll.now
    return had_previous


def _update_signals(
    memory: RadioMemory, clients: Sequence[Mapping[str, Any]], now: float
) -> None:
    cutoff = now - SIGNAL_WINDOW_S
    for client in clients:
        mac = client_mac(client)
        signal = client.get(CLIENT_KEY_SIGNAL)
        if (
            mac is None
            or isinstance(signal, bool)
            or not isinstance(signal, int | float)
        ):
            continue
        if signal >= 0:
            continue  # 0 / positive: no signal reported
        window = memory.signals.get(mac)
        if window is None:
            if len(memory.signals) >= CLIENTS_PER_RADIO_MAX:
                continue
            window = memory.signals[mac] = deque(maxlen=SIGNAL_SAMPLES_MAX)
        window.append((now, float(signal)))
    for mac in list(memory.signals):
        window = memory.signals[mac]
        while window and window[0][0] < cutoff:
            window.popleft()
        if not window:
            del memory.signals[mac]


def _airtime(
    memory: RadioMemory, clients: Sequence[Mapping[str, Any]], now: float
) -> Metric | None:
    """Share (%) of the busiest client in the airtime of all clients."""
    current: dict[str, int] = {}
    for client in clients:
        mac = client_mac(client)
        rx, tx = _whole(client.get("airtime_rx")), _whole(client.get("airtime_tx"))
        if mac is not None and rx is not None and tx is not None and min(rx, tx) >= 0:
            current[mac] = rx + tx
    previous, memory.airtime_prev = memory.airtime_prev, current
    if not clients:
        return None
    deltas = [
        d
        for mac, value in current.items()
        if (d := counter_delta(previous.get(mac), value)) is not None
    ]
    total = sum(deltas)
    if not deltas or total <= 0:
        return metric_missing(CapabilityState.NO_DATA, SOURCE_HOSTAPD_CLIENTS)
    return metric_measured(
        100.0 * max(deltas) / total, SOURCE_HOSTAPD_CLIENTS, measured_at=now
    )


def _signal_stats(
    window: Iterable[tuple[float, float]],
) -> tuple[float | None, float | None, float | None, float | None, int]:
    values = [v for _ts, v in window]
    if not values:
        return None, None, None, None, 0
    stddev = statistics.pstdev(values) if len(values) > 1 else None
    weak = sum(1 for v in values if v < WEAK_SIGNAL_DBM) / len(values)
    mean = sum(values) / len(values)
    return mean, min(values), stddev, weak, len(values)


def _assoc_fresh(memory: RadioMemory, poll: PollInput) -> bool:
    return (
        RF_KIND_ASSOCLIST in poll.kinds
        and memory.assoc_at is not None
        and poll.now - memory.assoc_at <= poll.max_age_s
    )


def _counts_retries(memory: RadioMemory, macs: Sequence[str], poll: PollInput) -> bool:
    """True when a client of this radio had retries > 0 in the window.

    Then the driver demonstrably counts retries, so a 0 of another client on
    the same radio is a real 0 (1.49.3).
    """
    if not _assoc_fresh(memory, poll):
        return False
    for mac in macs:
        retries = memory.assoc_delta.get(mac, (None, None, None))[1]
        if isinstance(retries, int) and retries > 0:
            return True
    return False


def _tx_counters(
    memory: RadioMemory, mac: str, poll: PollInput, *, counts_retries: bool = False
) -> tuple[int | None, int | None, int | None]:
    if not _assoc_fresh(memory, poll):
        return None, None, None
    packets, retries, failed = memory.assoc_delta.get(mac, (None, None, None))
    # DECIDED: the driver is not in the poll data, and mt76 with WED reports
    # 0 retries for everything. A 0 from an unknown driver is unknown, not a
    # perfect link (rf_clients treats an mt76 0 the same way) -- unless
    # another client of the same radio had retries in the window (1.49.3):
    # dropping the clean clients made the packet-weighted radio rate far too
    # high (9 clean + 1 client at 30 % gave 30 % instead of 3 %).
    if retries == 0 and not counts_retries:
        retries = None
    return packets, retries, failed


def _assessments(
    ref: RadioRef,
    radio: RadioInput,
    memory: RadioMemory,
    macs: Sequence[str],
    noise: Metric,
    poll: PollInput,
) -> list[ClientAssessment]:
    out = []
    counted = macs[:CLIENTS_PER_RADIO_MAX]
    counts = _counts_retries(memory, counted, poll)
    for mac in counted:
        mean, low, stddev, weak, samples = _signal_stats(memory.signals.get(mac, ()))
        packets, retries, failed = _tx_counters(
            memory, mac, poll, counts_retries=counts
        )
        facts = poll.history(mac) if poll.history is not None else None
        window = ClientRfWindow(
            client_mac=mac,
            radio=ref,
            band=radio.band,
            driver=None,
            window_s=SIGNAL_WINDOW_S,
            rssi_mean=mean,
            rssi_min=low,
            rssi_stddev=stddev,
            weak_share=weak,
            noise=noise,
            rate_tx_mean=getattr(facts, "rate_tx_mean", None),
            rate_tx_trend=None,
            tx_packets=packets,
            tx_retries=retries,
            tx_failed=failed,
            disconnects=getattr(facts, "disconnects", None),
            disconnects_weak=None,
            mobility=None,
            demand=None,
            samples=samples,
        )
        out.append(assess_client(window))
    return out


def _retry_metric(
    memory: RadioMemory,
    radio: RadioInput,
    summary: RadioClientSummary,
    poll: PollInput,
) -> Metric | None:
    if RF_KIND_ASSOCLIST not in poll.kinds:
        return None
    for device in radio.devices:
        error = _error(poll, RF_KIND_ASSOCLIST, device)
        if error is not None:
            return metric_missing(error, SOURCE_IWINFO_ASSOCLIST)
    if memory.assoc_at is None or not summary.retry_rate.is_measured:
        return metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_ASSOCLIST)
    measured = metric_measured(
        summary.retry_rate.value, SOURCE_IWINFO_ASSOCLIST, measured_at=memory.assoc_at
    )
    return with_staleness(measured, poll.now, poll.max_age_s)


def _noise_metric(memory: RadioMemory, radio: RadioInput, poll: PollInput) -> Metric:
    if radio.noise is not None:
        return metric_measured(radio.noise, SOURCE_IWINFO_INFO, measured_at=poll.now)
    survey = memory.survey
    if RF_KIND_SURVEY in poll.kinds and survey.noise is not None and survey.at:
        metric = metric_measured(
            survey.noise, SOURCE_IWINFO_SURVEY, measured_at=survey.at
        )
        return with_staleness(metric, poll.now, poll.max_age_s)
    return metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_INFO)


def _state(metric: Metric | None) -> CapabilityState | None:
    return metric.state if metric is not None else None


def _kind_state(
    poll: PollInput, kind: str, device: str | None, measured: bool
) -> CapabilityState | None:
    """State of a metric fed by one extra read; None when its switch is off."""
    if kind not in poll.kinds:
        return None
    if measured:
        return CapabilityState.MEASURED
    return _error(poll, kind, device) or CapabilityState.NO_DATA


def _any(clients: Sequence[Mapping[str, Any]], key: str) -> CapabilityState:
    found = any(
        isinstance(c.get(key), int | float) and not isinstance(c.get(key), bool)
        for c in clients
    )
    return CapabilityState.MEASURED if found else CapabilityState.NO_DATA


def _capabilities(
    ref: RadioRef,
    radio: RadioInput,
    memory: RadioMemory,
    clients: Sequence[Mapping[str, Any]],
    metrics: Mapping[str, Metric | None],
    poll: PollInput,
) -> RadioCapabilities:
    measured = CapabilityState.MEASURED
    no_data = CapabilityState.NO_DATA
    primary = radio.primary
    status_ok = memory.status.result is not None and memory.status.sample is not None
    survey = memory.survey
    survey_ok = survey.sample is not None
    split_ok = survey_ok and survey.sample.rx_ms is not None
    counters_ok = memory.assoc_read and bool(memory.assoc_prev)
    states: dict[str, CapabilityState | None] = {
        METRIC_CHANNEL: measured,
        METRIC_WIDTH: measured if radio.htmode else no_data,
        METRIC_TXPOWER: measured if radio.txpower is not None else no_data,
        METRIC_TXPOWER_MAX: _kind_state(
            poll, RF_KIND_TXPOWERLIST, primary, bool(memory.txpowers)
        ),
        METRIC_NOISE: _state(metrics.get("noise")),
        METRIC_BUSY_TIME: _kind_state(poll, RF_KIND_GET_STATUS, primary, status_ok)
        or _kind_state(poll, RF_KIND_SURVEY, primary, survey_ok),
        METRIC_ACTIVE_TIME: _kind_state(poll, RF_KIND_GET_STATUS, primary, status_ok)
        or _kind_state(poll, RF_KIND_SURVEY, primary, survey_ok),
        METRIC_RX_TIME: _kind_state(poll, RF_KIND_SURVEY, primary, split_ok),
        METRIC_TX_TIME: _kind_state(poll, RF_KIND_SURVEY, primary, split_ok),
        METRIC_UTILIZATION: _state(metrics.get("utilization")),
        METRIC_CLIENT_AIRTIME: _state(metrics.get("airtime_top_client")),
        METRIC_CLIENTS: measured,
        METRIC_RSSI: _any(clients, CLIENT_KEY_SIGNAL),
        METRIC_RATE: _any(clients, "tx_rate"),
        METRIC_RETRIES: _kind_state(poll, RF_KIND_ASSOCLIST, primary, counters_ok),
        METRIC_FAILED: _kind_state(poll, RF_KIND_ASSOCLIST, primary, counters_ok),
        METRIC_CONNECTED_TIME: _any(clients, "connected_since"),
        METRIC_FREQLIST: _kind_state(
            poll, RF_KIND_FREQLIST, primary, bool(memory.channels)
        ),
        METRIC_COUNTRY: measured if radio.country else no_data,
        # No scan in part 1: never proven, so unsupported (rf_scan_policy).
        METRIC_SCAN: DEFAULT_SCAN_CAPABILITY,
    }
    return RadioCapabilities(
        ref.router_id,
        ref.radio_id,
        {name: state for name, state in states.items() if state is not None},
    )


def _sources(radio: RadioInput, poll: PollInput) -> dict[str, dict[str, Any]]:
    """State and reason token of every extra read that is switched on."""
    out: dict[str, dict[str, Any]] = {}
    for kind in sorted(poll.kinds):
        devices = radio.devices if kind == RF_KIND_ASSOCLIST else radio.devices[:1]
        states = [poll.kind_state(kind, d) for d in devices]
        worst = next((s for s in states if s[0] in _ERROR_STATES), None)
        state, reason = worst or (states[0] if states else (None, None))
        out[kind] = {"state": state.value if state else None, "reason": reason}
    return out


def evaluate_radio(
    router_id: str,
    radio: RadioInput,
    memory: RadioMemory,
    clients: Sequence[Mapping[str, Any]],
    poll: PollInput,
) -> RadioResult:
    """Evaluate one radio of one poll (updates ``memory``)."""
    ref = RadioRef(router_id, radio.radio_id)
    channel_changed = memory.channel is not None and memory.channel != radio.channel
    memory.channel = radio.channel
    util_read = _update_counters(memory, radio, poll)
    _update_lists(memory, radio, poll)
    retry_read = _update_assoc(memory, radio, poll)
    _update_signals(memory, clients, poll.now)
    macs = tuple(dict.fromkeys(m for c in clients if (m := client_mac(c))))
    airtime = _airtime(memory, clients, poll.now)
    noise = _noise_metric(memory, radio, poll)
    assessments = _assessments(ref, radio, memory, macs, noise, poll)
    client_summary = summarize_radio_clients(assessments)
    util, util_result = _util_metric(memory, radio, poll)
    retry = _retry_metric(memory, radio, client_summary, poll)
    signal = None
    if client_summary.signal_quality_mean is not None:
        signal = metric_measured(
            client_summary.signal_quality_mean,
            SOURCE_HOSTAPD_CLIENTS,
            measured_at=poll.now,
        )
    elif macs:
        signal = metric_missing(CapabilityState.NO_DATA, SOURCE_HOSTAPD_CLIENTS)
    rssi = [s[-1][1] for m in macs if (s := memory.signals.get(m))]
    rssi_mean = (
        metric_measured(
            sum(rssi) / len(rssi), SOURCE_HOSTAPD_CLIENTS, measured_at=poll.now
        )
        if rssi
        else None
    )
    txpower = (
        metric_measured(radio.txpower, SOURCE_IWINFO_INFO, measured_at=poll.now)
        if radio.txpower is not None
        else metric_missing(CapabilityState.NO_DATA, SOURCE_IWINFO_INFO)
    )
    metrics: dict[str, Metric | None] = {
        "utilization": util,
        "noise": noise,
        "txpower": txpower,
        "retry_rate": retry,
        "signal_quality": signal,
        "rssi_mean": rssi_mean,
        "airtime_top_client": airtime,
    }
    regulatory = None
    if memory.channels or memory.txpowers:
        regulatory = RadioRegulatory(memory.channels, memory.txpowers, radio.country)
    view = RadioView(
        router_id=router_id,
        radio_id=radio.radio_id,
        band=radio.band,
        channel=radio.channel,
        width_mhz=radio.width,
        backhaul=radio.backhaul,
        utilization=util,
        noise=noise,
        client_count=len(macs),
        center_channel=radio.center,
        htmode=radio.htmode,
        regulatory=regulatory,
    )
    summary = None
    if util is not None:
        summary = summarize(
            list(memory.util_points),
            now=poll.now,
            window_s=UTIL_WINDOW_S,
            thresholds=UtilizationThresholds(),
            expected_interval_s=poll.interval_s,
        )
    store_values: dict[str, Any] = {
        "noise": noise.value if noise.is_measured else None,
        "clients": len(macs),
        "channel_changes": 1 if channel_changed else 0,
    }
    if util_read:
        store_values["utilization"] = memory.util_points[-1][1]
    if retry_read:
        store_values["retry_rate"] = (
            retry.value if retry is not None and retry.is_measured else None
        )
    return RadioResult(
        ref=ref,
        radio=radio,
        view=view,
        caps=_capabilities(ref, radio, memory, clients, metrics, poll),
        utilization=util_result,
        summary=summary,
        client_summary=client_summary,
        assessments=tuple(assessments),
        metrics=metrics,
        sources=_sources(radio, poll),
        load=RadioLoad(
            ref=ref,
            band=radio.band,
            client_count=len(macs),
            utilization=util,
            airtime_share_top_client=airtime,
            rssi_mean=rssi_mean,
            retry_rate=retry,
            driver=None,
            tx_bytes_rate=None,
            rx_bytes_rate=None,
            problem_clients=client_summary.problem_clients if macs else None,
        ),
        client_macs=macs,
        store_values=store_values,
        measured_at=poll.now,
    )


# --- the fleet ----------------------------------------------------------------------


@dataclass(frozen=True)
class FleetResult:
    """Fleet-wide findings of the latest results (memory only)."""

    conflicts: tuple[Conflict, ...]
    health: Mapping[RadioRef, HealthScore]
    ap_health: Mapping[str, AggregateHealth]
    network: AggregateHealth | None
    load: LoadReport
    distribution: DistributionReport
    recommendations: tuple[Recommendation, ...]
    coverage: float
    errors: int = 0


def _signal_score(value: float) -> float:
    """``signal_quality_mean`` is Client Stability's 0..100 score already."""
    return max(0.0, min(100.0, value))


def _health(result: RadioResult, conflicts: Sequence[Conflict]) -> HealthScore:
    metrics = result.metrics
    return radio_health(
        [
            component_from_metric(
                "utilization", metrics.get("utilization"), score_utilization
            ),
            component_from_metric(
                "retries", metrics.get("retry_rate"), score_retry_rate
            ),
            component_from_metric(
                "signal", metrics.get("signal_quality"), _signal_score
            ),
            overlap_component(result.ref, conflicts),
        ]
    )


def _per_channel(
    results: Sequence[RadioResult], ref: RadioRef
) -> dict[tuple[str, int], UtilizationSummary]:
    out: dict[tuple[str, int], UtilizationSummary] = {}
    for other in results:
        if other.ref != ref and other.summary is not None:
            out.setdefault((other.view.band, other.view.channel), other.summary)
    return out


def _radio_recommendations(
    result: RadioResult,
    results: Sequence[RadioResult],
    conflicts: Sequence[Conflict],
) -> list[Recommendation]:
    view = result.view
    others = [r.view for r in results if r.ref != result.ref]
    overlap = [
        c for c in conflicts if result.ref in c.members and c.kind in _OVERLAP_KINDS
    ]
    limits = tx_power_limits(view.regulatory) if view.regulatory else None
    txpower = result.metrics.get("txpower") or metric_missing(
        CapabilityState.NO_DATA, SOURCE_IWINFO_INFO
    )
    found = [
        recommend_channel(
            view, result.summary, others, _per_channel(results, result.ref) or None
        ),
        recommend_width(view, result.summary, others, conflicts=conflicts),
        recommend_tx_power(
            view, txpower, limits, result.client_summary, (), overlap, others=others
        ),
    ]
    return [r for r in found if r is not None]


def evaluate_fleet(results: Sequence[RadioResult]) -> FleetResult:
    """Conflicts, health, load and recommendations of all radios."""
    errors = 0
    conflicts = tuple(detect_conflicts([r.view for r in results]))
    health = {r.ref: _health(r, conflicts) for r in results}
    by_router: dict[str, list[RadioResult]] = {}
    for result in results:
        by_router.setdefault(result.ref.router_id, []).append(result)
    aps = {
        rid: ap_health(
            [item_from(r.ref.radio_id, health[r.ref], r.client_count) for r in radios]
        )
        for rid, radios in sorted(by_router.items())
    }
    network = None
    if aps:
        network = network_health(
            [
                item_from(rid, ap, sum(r.client_count for r in by_router[rid]))
                for rid, ap in aps.items()
            ]
        )
    inputs = [
        ApLoadInput(rid, [r.load for r in radios])
        for rid, radios in sorted(by_router.items())
    ]
    load = assess_load(inputs)
    spread = distribution(inputs)
    recommendations: list[Recommendation] = []
    for result in results:
        try:
            recommendations.extend(_radio_recommendations(result, results, conflicts))
        except Exception as err:  # noqa: BLE001 - one radio never stops the rest
            errors += 1
            _LOGGER.debug("WiFi RF recommendation failed (%s)", type(err).__name__)
    try:
        recommendations.extend(recommend_load(load, spread))
    except Exception as err:  # noqa: BLE001 - see above
        errors += 1
        _LOGGER.debug("WiFi RF load recommendation failed (%s)", type(err).__name__)
    return FleetResult(
        conflicts=conflicts,
        health=health,
        ap_health=aps,
        network=network,
        load=load,
        distribution=spread,
        recommendations=tuple(recommendations),
        coverage=monitoring_coverage([r.caps for r in results]),
        errors=errors,
    )


def empty_fleet() -> FleetResult:
    """The fleet result without any radio."""
    return evaluate_fleet([])
