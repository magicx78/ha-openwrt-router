"""Client stability engine (B2): poll observer, adapter, store and settings.

One instance per Home Assistant (``hass.data``). It observes the network
intelligence engine (``NetIntelligence.add_poll_observer``) and maps every
ingested poll onto a :class:`client_history.PollInput`. It makes no router
call of its own and reads nothing the engine did not already have: the
client list, the accepted log lines, the stored events and findings, the
fleet's lease and ARP MACs and the open NI root incidents.

Store: own key ``openwrt_router.client_history`` (plan 4.1), written at most
every ``CLIENT_SAVE_DELAY_SECONDS`` and only after a change; the last unload
writes at once and waits. A damaged store is copied to ``.bak`` and the
history starts empty. The file is capped at ``max_store_mb``; above it the
history is trimmed in the planned order (plan 4.2).

Privacy: log lines name no MAC, IP or hostname; diagnostics give counts.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import math
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import voluptuous as vol
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.json import prepare_save_json
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util

from .client_analysis import (
    DEFAULT_CLASSES,
    DEFAULT_WEIGHTS,
    PARTS,
    IncidentRef,
    ScoreResult,
    ScoreSettings,
    WindowStats,
    active_patterns,
    ap_pattern,
    collect_window,
    collect_window_days,
    make_settings,
    score_window,
    signal_trend,
    time_pattern,
)
from .client_history import (
    EV_ASSOC_FAIL,
    EV_AUTH_FAIL,
    EV_BAND_CHANGE,
    EV_CONNECT,
    EV_DHCP_FAIL,
    EV_DISCONNECT,
    EV_RECONNECT,
    EV_ROAM,
    RETENTION_DAYS_DEFAULT,
    RETENTION_DAYS_MAX,
    STATE_OFFLINE,
    ClientEvent,
    ClientHistory,
    ClientObs,
    PollInput,
    band_key,
    normalize_mac,
)
from .const import (
    CLIENT_ENTITY_MAX,
    CLIENT_MAX_STORE_MB,
    CLIENT_PUBLISH_SECONDS,
    CLIENT_SAVE_DELAY_SECONDS,
    CLIENT_STORE_KEY,
    CLIENT_STORE_MINOR_VERSION,
    CLIENT_STORE_VERSION,
    DOMAIN,
    SIGNAL_CLIENT_STABILITY,
)
from .log_parser import WIFI_CONNECTED
from .net_engine import NetIntelligence, PollFacts, _backup_file, async_get_engine
from .net_events import Incident, IncidentStatus
from .net_rules import (
    ROOT_TIERS,
    WIFI_ASSOC_REJECTED_KIND,
    WIFI_AUTH_KINDS,
    WIFI_BACKHAUL_AUTH_KIND,
    WIFI_BAND_CHANGE_KIND,
    WIFI_DHCP_AFTER_CONNECT_KIND,
    WIFI_NO_IP_KIND,
    WIFI_RECONNECT_KIND,
    WIFI_ROAM_KIND,
)

_LOGGER = logging.getLogger(__name__)

_DATA_KEY = f"{DOMAIN}_client_stability"
_FLUSH_KEY = f"{DOMAIN}_client_stability_flush"

_HOUR = 3600
# Root incidents whose routers' disconnects are infrastructure (plan 5):
# every NI root except a WAN outage (Wi-Fi clients stay associated).
INFRA_ROOT_TYPES = frozenset(t for t in ROOT_TIERS if t != "wan_down")
# Roots that mark a moment (the incident may stay open long after it):
# they count only while last seen within the window.
_EVENT_ROOTS = frozenset(
    {"system_reboot", "wifi_radio_change", "lan_port_flap", "wifi_mass_disconnect"}
)
INFRA_WINDOW_S = 300.0
# Roots on a port: ``routers`` is the port's owner, not the routers behind it.
_PORT_ROOTS = frozenset({"lan_port_flap", "lan_uplink_down"})
_OPEN = (IncidentStatus.ACTIVE, IncidentStatus.ACKNOWLEDGED)
# hostapd ``rate`` values are in 100 kbit/s
_RATE_DIVISOR = 100
# A down line without a reason takes the reason of the line just before it
# (``deauthenticated due to inactivity`` + ``AP-STA-DISCONNECTED``).
_REASON_PAIR_S = 5.0
# Router time of a line is used when it is plausible, else the poll time.
_LINE_MAX_AGE_MIN_S = 600.0
_LINE_AHEAD_S = 60.0
_DOWN_KINDS = frozenset({"disconnected", "deauth", "disassoc", "inactivity_timeout"})
_DHCP_FAIL_KINDS = frozenset({WIFI_DHCP_AFTER_CONNECT_KIND, WIFI_NO_IP_KIND})
# Closed hour buckets older than this many hours go first when trimming.
_TRIM_KEEP_HOURS = 48
_MB = 1_000_000


# --- settings --------------------------------------------------------------------


def _mac(value: Any) -> str:
    mac = normalize_mac(value)
    if mac is None:
        raise vol.Invalid("not a MAC address")
    return mac


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _descending(values: list[float]) -> list[float]:
    if any(a <= b for a, b in itertools.pairwise(values)):
        raise vol.Invalid("class thresholds must be strictly descending")
    return values


def _int(low: int, high: int) -> Any:
    return vol.All(vol.Coerce(int), vol.Range(min=low, max=high))


def _no_bool(value: Any) -> Any:
    if isinstance(value, bool):
        raise vol.Invalid("expected a number")
    return value


SETTINGS_SCHEMA = vol.Schema(
    {
        vol.Optional("enabled"): bool,
        vol.Optional("retention_days"): vol.All(_no_bool, _int(1, RETENTION_DAYS_MAX)),
        vol.Optional("entity_macs"): vol.All(
            [_mac], _unique, vol.Length(max=CLIENT_ENTITY_MAX)
        ),
        vol.Optional("sleepy_macs"): vol.All([_mac], _unique, vol.Length(max=1000)),
        vol.Optional("weights"): {
            vol.In(PARTS): vol.All(
                _no_bool, vol.Coerce(float), vol.Range(min=0, max=100)
            )
        },
        vol.Optional("classes"): vol.All(
            [vol.All(_no_bool, vol.Coerce(float), vol.Range(min=0, max=100))],
            vol.Length(min=4, max=4),
            _descending,
        ),
        vol.Optional("max_store_mb"): vol.All(_no_bool, _int(1, 8)),
    },
    extra=vol.PREVENT_EXTRA,
)


def default_settings() -> dict[str, Any]:
    """The settings of a new installation."""
    return {
        "enabled": True,
        "retention_days": RETENTION_DAYS_DEFAULT,
        "entity_macs": [],
        "sleepy_macs": [],
        "weights": dict(DEFAULT_WEIGHTS),
        "classes": list(DEFAULT_CLASSES),
        "max_store_mb": CLIENT_MAX_STORE_MB,
    }


def merge_settings(current: Mapping[str, Any], update: Any) -> dict[str, Any]:
    """``current`` with a validated partial ``update``; raises ``vol.Invalid``."""
    checked = SETTINGS_SCHEMA(update)
    merged = {**current, **checked}
    if "weights" in checked:
        merged["weights"] = {**current.get("weights", {}), **checked["weights"]}
    if not any(merged["weights"].get(p, 0) > 0 for p in PARTS):
        raise vol.Invalid("at least one weight must be above 0")
    return merged


def settings_from_store(raw: Any) -> dict[str, Any]:
    """Stored settings, field by field; a damaged field keeps its default."""
    settings = default_settings()
    if not isinstance(raw, dict):
        return settings
    for key, value in raw.items():
        try:
            settings = merge_settings(settings, {key: value})
        except vol.Invalid:
            _LOGGER.warning("Client stability setting %s is invalid, default used", key)
    return settings


# --- adapter: PollFacts -> PollInput (pure) ------------------------------------------


def infra_roots(
    incidents: Iterable[Incident], now: float, skip: Iterable[str] = ()
) -> dict[str, str]:
    """Router -> id of the NI root that explains disconnects there now.

    Open roots (and roots resolved within ``INFRA_WINDOW_S``) of
    ``INFRA_ROOT_TYPES``; the routers of their linked children count too.
    A port root names the router owning the port, not the routers behind
    it, so only its linked children count (NI links only drops behind the
    port, or at the owner when its own uplink port flaps). Moment roots
    only while last seen within the window. Routers in ``skip`` (failing on
    their credentials) are never infrastructure. The lowest root tier wins
    on a router; a root linked under another root reports its parent.
    """
    items = list(incidents)
    roots: dict[str, Incident] = {}
    for inc in items:
        if inc.type not in INFRA_ROOT_TYPES or not _recent(inc, now):
            continue
        if inc.type in _EVENT_ROOTS and now - inc.last_seen > INFRA_WINDOW_S:
            continue
        roots[inc.id] = inc
    # A root linked under another root reports the top one (its parent).
    ordered = sorted(
        roots.values(),
        key=lambda i: (i.parent_id in roots, ROOT_TIERS[i.type], i.id),
    )
    out: dict[str, str] = {}
    for inc in ordered:
        top = inc.parent_id if inc.parent_id in roots else inc.id
        for router in _explained(inc):
            out.setdefault(router, top)
    for inc in items:
        if inc.parent_id in roots and _recent(inc, now):
            for router in _explained(inc):
                out.setdefault(router, inc.parent_id)
    for router in skip:
        out.pop(router, None)
    return out


def _explained(inc: Incident) -> Iterable[str]:
    """Routers whose disconnects ``inc`` explains itself (none for a port
    root: its owner's Wi-Fi is not behind the port)."""
    return () if inc.type in _PORT_ROOTS else inc.routers


def _recent(inc: Incident, now: float) -> bool:
    if inc.status in _OPEN:
        return True
    return inc.resolved_at is not None and now - inc.resolved_at <= INFRA_WINDOW_S


def incident_ref(inc: Incident) -> IncidentRef:
    """What the analysis needs about one NI incident."""
    status = inc.cause_status.value if inc.cause_status is not None else None
    return IncidentRef(inc.id, status, inc.cause, inc.confidence)


def poll_input(
    facts: PollFacts, *, interval: float, infra: Mapping[str, str]
) -> PollInput:
    """The history input of one poll (excluded MACs are left out)."""
    exclude = facts.exclude
    clients: list[ClientObs] = []
    for mac, client in (facts.context.clients or {}).items():
        if mac in exclude or not isinstance(client, Mapping):
            continue
        clients.append(_client_obs(mac, client, facts))
    events = [
        ev
        for ev in (
            *_line_events(facts, interval, infra),
            *_finding_events(facts, infra),
            *_stored_events(facts),
        )
        if normalize_mac(ev.mac) not in exclude
    ]
    return PollInput(
        router=facts.router,
        now=facts.now,
        interval=interval,
        fresh=facts.fresh_clients,
        clients=tuple(clients),
        events=tuple(events),
        down_routers=facts.down_routers,
        infra=dict(infra),
        loc=dict(facts.loc),
    )


def _client_obs(mac: str, client: Mapping[str, Any], facts: PollFacts) -> ClientObs:
    radio = client.get("radio")
    band, _ssid, _phy = facts.context.iface(radio if isinstance(radio, str) else None)
    signal = client.get("signal")
    rssi = (
        int(signal)
        if isinstance(signal, (int, float))
        and not isinstance(signal, bool)
        and -120 <= signal < 0
        else None
    )
    ip = client.get("ip")
    ip = ip if isinstance(ip, str) and ip else None
    host = client.get("hostname")
    return ClientObs(
        mac=mac,
        band=band_key(band),
        rssi=rssi,
        rate_rx_kbit=_kbit(client.get("rx_rate")),
        rate_tx_kbit=_kbit(client.get("tx_rate")),
        ip_visible=ip is not None or mac in facts.lease_macs or mac in facts.arp_macs,
        hostname=host if isinstance(host, str) and host else None,
        ip=ip,
    )


def _kbit(value: Any) -> int | None:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return None
    if not math.isfinite(value) or value < 0:
        return None
    return int(value) // _RATE_DIVISOR


def _line_ts(time_ms: int, now: float, interval: float) -> float:
    if time_ms <= 0:
        return now
    ts = time_ms / 1000
    oldest = now - max(_LINE_MAX_AGE_MIN_S, 3 * interval)
    return min(ts, now) if oldest <= ts <= now + _LINE_AHEAD_S else now


def _line_events(
    facts: PollFacts, interval: float, infra: Mapping[str, str]
) -> list[ClientEvent]:
    out: list[ClientEvent] = []
    last_down: dict[str, tuple[float, str | None]] = {}
    lines = sorted(facts.wifi_lines, key=lambda e: (e.time_ms, e.log_id))
    root = infra.get(facts.router)
    for line in lines:
        mac = normalize_mac(line.mac)
        if mac is None:
            continue
        ts = _line_ts(line.time_ms, facts.now, interval)
        if line.kind == WIFI_CONNECTED:
            out.append(ClientEvent(mac, EV_CONNECT, ts, facts.router))
        elif line.kind in _DOWN_KINDS:
            reason = line.reason
            prev = last_down.get(mac)
            if reason is None and prev is not None and ts - prev[0] <= _REASON_PAIR_S:
                reason = prev[1]
            last_down[mac] = (ts, reason)
            out.append(
                ClientEvent(
                    mac,
                    EV_DISCONNECT,
                    ts,
                    facts.router,
                    reason=reason,
                    infra=root is not None,
                    incident_id=root,
                )
            )
    return out


def _finding_events(facts: PollFacts, infra: Mapping[str, str]) -> list[ClientEvent]:
    out: list[ClientEvent] = []
    for f in facts.findings:
        mac = normalize_mac(f.scope_key)
        if mac is None:
            continue
        if f.kind == WIFI_RECONNECT_KIND:
            count = f.count if isinstance(f.count, int) and f.count > 0 else 1
            out.append(
                ClientEvent(mac, EV_RECONNECT, facts.now, facts.router, count=count)
            )
        elif f.kind == WIFI_ROAM_KIND:
            to = f.params.get("to_router")
            frm = f.params.get("from_router")
            if isinstance(to, str) and to:
                peer = frm if isinstance(frm, str) and frm else None
                out.append(ClientEvent(mac, EV_ROAM, facts.now, to, peer=peer))
        elif f.kind == WIFI_BAND_CHANGE_KIND:
            out.append(ClientEvent(mac, EV_BAND_CHANGE, facts.now, facts.router))
        elif f.kind in _DHCP_FAIL_KINDS:
            out.append(ClientEvent(mac, EV_DHCP_FAIL, facts.now, facts.router))
    return out


def _stored_events(facts: PollFacts) -> list[ClientEvent]:
    out: list[ClientEvent] = []
    for event in facts.stored_events:
        mac = normalize_mac(event.subject.get("mac"))
        if mac is None:
            continue
        if event.kind in WIFI_AUTH_KINDS and event.kind != WIFI_BACKHAUL_AUTH_KIND:
            if event.id in facts.auth_attempts:
                out.append(ClientEvent(mac, EV_AUTH_FAIL, event.ts, facts.router))
        elif event.kind == WIFI_ASSOC_REJECTED_KIND:
            out.append(ClientEvent(mac, EV_ASSOC_FAIL, event.ts, facts.router))
    return out


# --- entity view -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClientEntityState:
    """What the sensors of one selected client show (rebuilt <= every 60 s)."""

    name: str
    score: float | None
    cls: str
    score_7d: float | None
    coverage: float
    reconnects_24h: int | None
    connected: bool
    session_start: float | None
    last_disconnect: float | None


# --- life cycle --------------------------------------------------------------------


@callback
def async_get_client_engine(hass: HomeAssistant) -> ClientStability | None:
    """The running client stability engine, or None."""
    cs = hass.data.get(_DATA_KEY)
    return cs if isinstance(cs, ClientStability) else None


async def async_get_client_stability(
    hass: HomeAssistant, engine: NetIntelligence
) -> ClientStability:
    """Create and load the per-HA engine once; observe ``engine``."""
    cs = async_get_client_engine(hass)
    if cs is None:
        cs = ClientStability(hass)
        hass.data[_DATA_KEY] = cs
    await cs.async_load()
    cs.attach(engine)
    return cs


async def async_unload_client_stability(hass: HomeAssistant) -> None:
    """After the last router: stop, write the store now and wait for it."""
    cs = async_get_client_engine(hass)
    if cs is None:
        return
    engine = async_get_engine(hass)
    if engine is not None and engine.routers:
        return
    hass.data.pop(_DATA_KEY, None)
    cs.close()
    claim: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    hass.data[_FLUSH_KEY] = claim
    try:
        if cs.dirty:
            await cs.async_flush()
    finally:
        claim.set_result(None)
        if hass.data.get(_FLUSH_KEY) is claim:
            hass.data.pop(_FLUSH_KEY, None)


class ClientStability:
    """Fleet-wide client stability: history, store, settings, entity view."""

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass
        self._store: Store[dict[str, Any]] = Store(
            hass,
            CLIENT_STORE_VERSION,
            CLIENT_STORE_KEY,
            minor_version=CLIENT_STORE_MINOR_VERSION,
        )
        self._lock = asyncio.Lock()
        self.loaded = False
        self.load_failed = False
        self.settings: dict[str, Any] = default_settings()
        self.history = ClientHistory(RETENTION_DAYS_DEFAULT)
        self.dirty = False
        self._save_pending = False
        self._closed = False
        self._engine: NetIntelligence | None = None
        self._unsub: Callable[[], None] | None = None
        # in memory: last ingest time and log coverage per router
        self._seen: dict[str, float] = {}
        self._log_cov: dict[str, float | None] = {}
        self.last_now: float | None = None
        self._last_publish: float | None = None
        self.entity_states: dict[str, ClientEntityState] = {}
        # MAC -> (hour index, active patterns) of the part W cache
        self._patterns: dict[str, tuple[int, int]] = {}
        # MAC -> SSID of the last client list it was in (memory only)
        self._ssid: dict[str, str] = {}
        self.last_save_bytes: int | None = None
        self.trimmed = 0

    # -- store ------------------------------------------------------------------------

    async def async_load(self) -> None:
        """Read the store once; a damaged store is kept as ``.bak``."""
        async with self._lock:
            if self.loaded:
                return
            pending = self.hass.data.get(_FLUSH_KEY)
            if isinstance(pending, asyncio.Future) and not pending.done():
                await pending
            try:
                stored = await self._store.async_load()
            except Exception:
                _LOGGER.warning(
                    "Client stability store %s could not be read; starting empty",
                    CLIENT_STORE_KEY,
                    exc_info=True,
                )
                stored = None
                self.load_failed = True
            if stored is not None and not isinstance(stored, dict):
                _LOGGER.warning(
                    "Client stability store %s has an unknown format; starting empty",
                    CLIENT_STORE_KEY,
                )
                stored = None
                self.load_failed = True
            if stored:
                self._restore(stored)
            if self.load_failed:
                await self._async_backup()
            self.loaded = True

    def _restore(self, stored: dict[str, Any]) -> None:
        self.settings = settings_from_store(stored.get("settings"))
        self.history = ClientHistory.from_dict(
            stored.get("history"), self.settings["retention_days"]
        )

    async def _async_backup(self) -> None:
        path = getattr(self._store, "path", None)
        try:
            copied = await self.hass.async_add_executor_job(_backup_file, path)
        except Exception:
            _LOGGER.warning(
                "Client stability store backup failed; the next save replaces it",
                exc_info=True,
            )
            return
        if copied:
            _LOGGER.warning(
                "Client stability kept a copy of the unreadable store at %s.bak",
                path,
            )

    @callback
    def schedule_save(self) -> None:
        """Mark a change; write at most ``CLIENT_SAVE_DELAY_SECONDS`` from now."""
        self.dirty = True
        if self._save_pending or self._closed:
            return
        self._save_pending = True
        self._store.async_delay_save(self._data_to_save, CLIENT_SAVE_DELAY_SECONDS)

    async def async_flush(self) -> None:
        """Write the store now."""
        await self._store.async_save(self._data_to_save())

    @callback
    def _data_to_save(self) -> dict[str, Any]:
        """Store payload, trimmed to ``max_store_mb`` (plan 4.2 order)."""
        self._save_pending = False
        self.dirty = False
        limit = int(self.settings["max_store_mb"]) * _MB
        payload = self._payload()
        size = _store_size(payload)
        if size > limit:
            size = self._trim(limit, size)
            payload = self._payload()
            _LOGGER.warning(
                "Client stability store trimmed to %d bytes (limit %d)", size, limit
            )
        self.last_save_bytes = size
        return payload

    def _payload(self) -> dict[str, Any]:
        return {
            "settings": self.settings,
            "history": self.history.to_dict(),
            "saved_at": self.last_now,
        }

    def _trim(self, limit: int, size: int) -> int:
        now = self.last_now if self.last_now is not None else time.time()
        cut = int(now // _HOUR) - _TRIM_KEEP_HOURS
        steps: tuple[Callable[[], int], ...] = (
            self.history.trim_transitions,
            lambda: self.history.trim_closed_hours(cut, private_only=True),
            lambda: self.history.trim_closed_hours(cut),
        )
        for step in steps:
            dropped = step()
            if dropped:
                self.trimmed += dropped
                size = _store_size(self._payload())
                if size <= limit:
                    return size
        while size > limit and len(self.history):
            count = max(1, math.ceil(len(self.history) * (size - limit) / size))
            self.trimmed += self.history.drop_oldest(count)
            size = _store_size(self._payload())
        return size

    # -- observer ---------------------------------------------------------------------

    @callback
    def attach(self, engine: NetIntelligence) -> None:
        """Observe ``engine`` (again after a new engine was created)."""
        if self._engine is engine:
            return
        if self._unsub is not None:
            self._unsub()
        self._engine = engine
        self._unsub = engine.add_poll_observer(self)

    @callback
    def close(self) -> None:
        """Stop observing; no writes are scheduled after this."""
        self._closed = True
        if self._unsub is not None:
            self._unsub()
            self._unsub = None
        self._engine = None

    def on_poll(self, facts: PollFacts) -> None:
        """One poll of one router (called by the engine, errors stay there)."""
        if self._closed or not self.loaded or not self.settings["enabled"]:
            return
        now = facts.now
        self.last_now = now
        interval = self._interval(facts.router, now, facts.interval)
        self._seen[facts.router] = now
        self._log_cov[facts.router] = facts.log_coverage
        for mac in facts.exclude:
            self.history.forget(mac)
            self._ssid.pop(mac, None)
        infra = self._infra(now, facts.auth_failed)
        self.history.ingest(poll_input(facts, interval=interval, infra=infra))
        self._remember_ssids(facts)
        self.schedule_save()
        if (
            self._last_publish is None
            or now - self._last_publish >= CLIENT_PUBLISH_SECONDS
            or now < self._last_publish
        ):
            self._publish(now)

    def on_clock_shift(self, delta: float) -> None:
        """The engine clock jumped back by ``delta``."""
        self.history.shift_clock(delta)
        self._seen = {r: t + delta for r, t in self._seen.items()}
        if self._last_publish is not None:
            self._last_publish += delta
        if self.last_now is not None:
            self.last_now += delta

    def on_router_removed(self, router: str) -> None:
        """A removed router: forget its client list (buckets age out)."""
        self.history.remove_router(router)
        self._seen.pop(router, None)
        self._log_cov.pop(router, None)
        self.schedule_save()

    def _remember_ssids(self, facts: PollFacts) -> None:
        """SSID per listed client (memory only; bounded by the history)."""
        for mac, client in (facts.context.clients or {}).items():
            if mac in facts.exclude or not isinstance(client, Mapping):
                continue
            radio = client.get("radio")
            _band, ssid, _phy = facts.context.iface(
                radio if isinstance(radio, str) else None
            )
            if isinstance(ssid, str) and ssid:
                self._ssid[mac] = ssid
        if len(self._ssid) > len(self.history) + 64:
            self._ssid = {
                m: v for m, v in self._ssid.items() if self.history.live(m) is not None
            }

    def _interval(self, router: str, now: float, configured: float) -> float:
        """The configured interval, or the observed one when polls run late
        (at most twice the configured one: a slow poll is no outage)."""
        last = self._seen.get(router)
        if last is None or now <= last:
            return configured
        return max(configured, min(now - last, 2 * configured))

    def _infra(self, now: float, auth_failed: frozenset[str]) -> dict[str, str]:
        engine = self._engine
        if engine is None:
            return {}
        # peek: no copies on every poll; infra_roots only reads them
        return infra_roots(engine.machine.peek(), now, auth_failed)

    # -- reading (views, entities) -------------------------------------------------------

    def infra_routers(self, now: float) -> frozenset[str]:
        """Routers with an NI root that explains disconnects there now."""
        return frozenset(self._infra(now, frozenset()))

    def ssid(self, mac: str) -> str | None:
        """SSID of the last client list the client was in (None = unknown)."""
        return self._ssid.get(mac)

    def log_coverage(self, router: str | None) -> float | None:
        """Log coverage of the router a client is on (None = unknown)."""
        return self._log_cov.get(router) if router else None

    def incident_refs(self, ids: Iterable[str]) -> dict[str, IncidentRef]:
        """NI references of the given incident ids (unknown ids left out)."""
        engine = self._engine
        if engine is None:
            return {}
        by_id = {inc.id: inc for inc in engine.machine.peek()}  # read only
        out: dict[str, IncidentRef] = {}
        for inc_id in ids:
            inc = by_id.get(inc_id) if inc_id else None
            if inc is not None:
                out[inc_id] = incident_ref(inc)
        return out

    def patterns(self, mac: str, now: float, compute: bool = True) -> int | None:
        """Active recurring patterns (part W), cached per hour; None when not
        cached and ``compute`` is False."""
        hour = int(now // _HOUR)
        cached = self._patterns.get(mac)
        if cached is not None and cached[0] == hour:
            return cached[1]
        if not compute:
            return None
        n = active_patterns(
            time_pattern(self.history, mac, dt_util.get_default_time_zone()),
            signal_trend(self.history, mac, now),
            ap_pattern(self.history, mac, now),
        )
        if len(self._patterns) >= max(64, 2 * len(self.history)):
            self._patterns.clear()
        self._patterns[mac] = (hour, n)
        return n

    def score(
        self,
        mac: str,
        now: float,
        hours: int = 24,
        *,
        end: float | None = None,
        compute_patterns: bool = True,
    ) -> ScoreResult | None:
        """Score of one client over the ``hours`` before ``end`` (or now)."""
        found = self.window(mac, now, hours, end=end, compute_patterns=compute_patterns)
        return found[1] if found is not None else None

    def window(
        self,
        mac: str,
        now: float,
        hours: int = 24,
        *,
        end: float | None = None,
        compute_patterns: bool = True,
    ) -> tuple[WindowStats, ScoreResult] | None:
        """Statistics and score of one client over ``hours`` hour buckets."""
        live = self.history.live(mac)
        if live is None:
            return None
        stats = collect_window(
            self.history,
            mac,
            now,
            hours,
            end=end,
            log_coverage=self.log_coverage(live.ap),
            patterns=self.patterns(mac, now, compute_patterns) or 0,
        )
        if stats is None:
            return None
        return stats, score_window(stats, self.score_settings(live.mac))

    def window_days(
        self, mac: str, now: float, days: int = 30
    ) -> tuple[WindowStats, ScoreResult] | None:
        """Statistics and score of one client over ``days`` day buckets."""
        live = self.history.live(mac)
        if live is None:
            return None
        stats = collect_window_days(
            self.history,
            mac,
            now,
            days,
            log_coverage=self.log_coverage(live.ap),
            patterns=self.patterns(mac, now) or 0,
        )
        if stats is None:
            return None
        return stats, score_window(stats, self.score_settings(live.mac))

    def score_settings(self, mac: str) -> ScoreSettings:
        """Weights, classes and the ``sleepy`` option of one client."""
        return make_settings(
            self.settings["weights"],
            self.settings["classes"],
            mac in self.settings["sleepy_macs"],
        )

    @callback
    def _publish(self, now: float) -> None:
        self._last_publish = now
        states: dict[str, ClientEntityState] = {}
        # disabled: no states, so the sensors go unavailable instead of stale
        for mac in self.settings["entity_macs"] if self.settings["enabled"] else ():
            state = self._entity_state(mac, now)
            if state is not None:
                states[mac] = state
        self.entity_states = states
        async_dispatcher_send(self.hass, SIGNAL_CLIENT_STABILITY)

    def _entity_state(self, mac: str, now: float) -> ClientEntityState | None:
        live = self.history.live(mac)
        if live is None:
            return None
        day = self.score(mac, now, 24)
        week = self.score(mac, now, 168)
        last = math.ceil(now / _HOUR) - 1
        reconnects = sum(
            b.bucket.reconnects for b in self.history.hours(mac, last - 23, last)
        )
        cov = self.log_coverage(live.ap)
        return ClientEntityState(
            name=live.hostname or mac,
            score=round(day.score, 1) if day and day.score is not None else None,
            cls=day.cls if day else "unknown",
            score_7d=round(week.score, 1) if week and week.score is not None else None,
            coverage=round(day.coverage, 2) if day else 0.0,
            reconnects_24h=reconnects if cov else None,
            connected=live.state != STATE_OFFLINE and live.session_start is not None,
            session_start=live.session_start if live.state != STATE_OFFLINE else None,
            last_disconnect=live.last_disconnect.ts if live.last_disconnect else None,
        )

    # -- settings ----------------------------------------------------------------------

    @callback
    def update_settings(self, update: Any) -> dict[str, Any]:
        """Validate and apply a partial update; raises ``vol.Invalid``."""
        merged = merge_settings(self.settings, update)
        self.settings = merged
        self.history.retention_days = merged["retention_days"]
        self._patterns.clear()
        self.schedule_save()
        if self.last_now is not None:
            self._publish(self.last_now)
        return merged

    def diagnostics(self) -> dict[str, Any]:
        """Counts only (no MAC, IP or hostname)."""
        states: dict[str, int] = {}
        for mac in self.history.macs():
            live = self.history.live(mac)
            if live is not None:
                states[live.state] = states.get(live.state, 0) + 1
        return {
            "enabled": self.settings["enabled"],
            "loaded": self.loaded,
            "store_load_failed": self.load_failed,
            "clients": len(self.history),
            "clients_by_state": dict(sorted(states.items())),
            "entity_clients": len(self.settings["entity_macs"]),
            "retention_days": self.settings["retention_days"],
            "store_bytes_last_save": self.last_save_bytes,
            "store_limit_bytes": int(self.settings["max_store_mb"]) * _MB,
            "trimmed_for_size": self.trimmed,
        }


def _store_size(payload: dict[str, Any]) -> int:
    """Bytes of the store file exactly as HA's ``Store`` writes it."""
    wrapped = {
        "version": CLIENT_STORE_VERSION,
        "minor_version": CLIENT_STORE_MINOR_VERSION,
        "key": CLIENT_STORE_KEY,
        "data": payload,
    }
    _mode, data = prepare_save_json(wrapped)
    return len(data.encode("utf-8") if isinstance(data, str) else data)
