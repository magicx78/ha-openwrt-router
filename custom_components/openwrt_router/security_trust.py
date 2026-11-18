"""Device trust state machine of the Security Center (stage 2, pure logic).

States: ``known`` / ``new`` / ``unrecognized`` / ``suspicious`` /
``quarantined``. No clock, no I/O: ``now`` is always a parameter.

Rules (plan 3.1 and the stage-2 task):

* An unknown MAC on its own is never ``suspicious`` and never an attack:
  a newly seen device is ``new`` and gets one ``noticeable`` notice.
* ``suspicious`` needs at least ``suspicious_min_indicators`` (default 2)
  *different* indicator kinds inside ``indicator_window_s``.
* A randomised / private MAC (flag from Client Stability ``ClientLive.
  private_mac``, else ``mac_utils.is_locally_administered``) is not
  alarmed as a new unknown device; it gets its own low notice.
* A known device with a new IP (DHCP renewal) is normal; only
  ``ip_churn_min`` changes inside ``ip_churn_window_s`` are an indicator.
* Missing client data gives ``unrecognized`` ("unknown"), never ``known``.
* ``quarantined`` is never set automatically: only :meth:`TrustBook.
  quarantine` sets it and it requires an :class:`IsolationProof` (no caller
  in this stage). Nothing automatic leaves or overwrites it; only the
  explicit :meth:`TrustBook.release_quarantine` does.
* A manual confirmation makes a device ``known`` and clears its current
  indicators (the user vouched for it); new indicators count again.
* Every manual action (confirm, rename, quarantine, release) returns a
  :class:`TrustAction` with the acting core ``Actor`` without context ids
  (``security_model.event_actor``) for the audit event: the core keeps the
  user id in its audit store and puts its own stable pseudonym on the bus,
  so no second pseudonym scheme exists here. Its event types are
  ``security_model.AUDIT_MANDATORY_TYPES``. The display name never goes
  into it. None = refused.

No second client database: the input is a narrow observation Protocol (the
fields of Client Stability ``ClientLive``); this layer keeps only trust
state, name, times, the last IP/hostname (to see a change) and indicators,
for at most ``max_entries`` devices. When full, the least recently seen
unconfirmed, unquarantined entry *without active indicators* is evicted
(review H4). Confirmed, quarantined and suspicious-in-the-making entries
are never evicted silently: the new device is then not tracked,
``capacity_overflow`` counts it and a ``capacity`` notice reports it.

Entries created only by :meth:`TrustBook.add_indicator` (a MAC that was
never observed as a client, e.g. from a forged log line) live in their own
smaller area of at most ``max_indicator_only`` entries. A flood of such
MACs displaces only its own oldest entry, and every such displacement is
counted in ``capacity_overflow`` and reported with a ``capacity`` notice.
"""

from __future__ import annotations

import logging
import math
import secrets
from collections import OrderedDict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final, Protocol

from .mac_utils import is_locally_administered
from .security_model import (
    Actor,
    Assessment,
    DataSource,
    EventResult,
    SecCategory,
    SecurityEvent,
    Severity,
    clean_text,
    event_actor,
    event_type,
    make_dedup_key,
    make_event_id,
    normalize_mac,
)

_LOGGER = logging.getLogger(__name__)

STORE_VERSION: Final = 1
DEFAULT_NEW_PERIOD_S: Final = 86400.0
DEFAULT_IP_CHURN_WINDOW_S: Final = 3600.0
DEFAULT_IP_CHURN_MIN: Final = 4
DEFAULT_INDICATOR_WINDOW_S: Final = 3600.0
DEFAULT_SUSPICIOUS_MIN_INDICATORS: Final = 2
DEFAULT_MAX_ENTRIES: Final = 2048
MAX_IP_CHANGES: Final = 32
MAX_INDICATORS: Final = 16
MAX_NAME_LEN: Final = 64


class TrustState(StrEnum):
    """Trust state of one device."""

    KNOWN = "known"
    NEW = "new"
    UNRECOGNIZED = "unrecognized"
    SUSPICIOUS = "suspicious"
    QUARANTINED = "quarantined"


class Indicator(StrEnum):
    """Independent indicator kinds (several kinds make a device suspicious)."""

    IP_CHURN = "ip_churn"
    HOSTNAME_CHANGE = "hostname_change"
    LOGIN_FAILURES = "login_failures"
    MULTI_AP_AUTH = "multi_ap_auth"
    ASSOC_BURST = "assoc_burst"
    PORT_SCAN = "port_scan"
    MGMT_ACCESS = "mgmt_access"
    INTER_VLAN = "inter_vlan"
    DNS_ANOMALY = "dns_anomaly"
    TRAFFIC_ANOMALY = "traffic_anomaly"
    MAC_SPOOF = "mac_spoof"


class NoticeKind(StrEnum):
    """What a trust notice reports."""

    NEW_DEVICE = "new_device"
    PRIVATE_MAC = "private_mac"
    INCOMPLETE = "incomplete"
    IP_CHURN = "ip_churn"
    SUSPICIOUS = "suspicious"
    CAPACITY = "capacity"


class TrustActionKind(StrEnum):
    """Manual trust actions (each one is an audit entry)."""

    CONFIRMED = "confirmed"
    RENAMED = "renamed"
    QUARANTINED = "quarantined"
    RELEASED = "released"


_NOTICE_LEVEL: Final[Mapping[NoticeKind, tuple[Severity, Assessment]]] = {
    NoticeKind.NEW_DEVICE: (Severity.INFO, Assessment.NOTICEABLE),
    NoticeKind.PRIVATE_MAC: (Severity.INFO, Assessment.NORMAL),
    NoticeKind.INCOMPLETE: (Severity.INFO, Assessment.NORMAL),
    NoticeKind.IP_CHURN: (Severity.INFO, Assessment.NOTICEABLE),
    NoticeKind.SUSPICIOUS: (Severity.WARNING, Assessment.SUSPICIOUS),
    NoticeKind.CAPACITY: (Severity.WARNING, Assessment.NORMAL),
}


class ClientObservation(Protocol):
    """Narrow view of one client (the fields of ``ClientLive``)."""

    @property
    def mac(self) -> str:
        """Client MAC in any common form."""

    @property
    def private_mac(self) -> bool | None:
        """Client Stability's private-MAC flag; None = not known."""

    @property
    def first_seen(self) -> float | None:
        """First time Client Stability saw the client."""

    @property
    def last_seen(self) -> float | None:
        """Last time Client Stability saw the client."""

    @property
    def ip(self) -> str | None:
        """Current IP address, None if not known."""

    @property
    def hostname(self) -> str | None:
        """Current hostname, None if not known."""


@dataclass(frozen=True, kw_only=True, slots=True)
class IsolationProof:
    """Evidence that a device really is isolated (needed for quarantine)."""

    method: str
    verified_at: float
    reference: str | None = None

    def __post_init__(self) -> None:
        """A proof needs a method and a finite verification time."""
        method = clean_text(self.method, 64) if isinstance(self.method, str) else ""
        if not method:
            raise ValueError("isolation proof needs a method")
        if not _is_time(self.verified_at):
            raise ValueError("isolation proof needs a finite verified_at")
        object.__setattr__(self, "method", method)
        ref = self.reference
        object.__setattr__(
            self, "reference", None if ref is None else clean_text(ref, 96)
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class TrustNotice:
    """Result of an update worth reporting (identity hidden in repr)."""

    kind: NoticeKind
    state: TrustState
    at: float
    mac: str | None = field(default=None, repr=False)
    indicators: tuple[str, ...] = ()

    @property
    def severity(self) -> Severity:
        """Severity of this notice kind."""
        return _NOTICE_LEVEL[self.kind][0]

    @property
    def assessment(self) -> Assessment:
        """Classification of this notice kind (never confirmed)."""
        return _NOTICE_LEVEL[self.kind][1]

    def to_event(self, *, router_id: str | None = None) -> SecurityEvent:
        """The notice as a :class:`SecurityEvent` (router id from the caller)."""
        name = f"trust_{self.kind.value}"
        return SecurityEvent(
            event_id=make_event_id(name, router_id, self.mac, self.at),
            ts=self.at,
            type=event_type(name),
            router_id=router_id,
            category=SecCategory.DEVICE,
            severity=self.severity,
            assessment=self.assessment,
            data_source=DataSource.CLIENT_HISTORY,
            client=self.mac,
            evidence=(f"state={self.state.value}",)
            + tuple(f"indicator={i}" for i in self.indicators),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class TrustAction:
    """One manual trust action; the actor is pseudonymous, no name inside."""

    kind: TrustActionKind
    at: float
    mac: str = field(repr=False)
    actor: Actor | None = field(default=None, repr=False)
    method: str | None = None  # isolation method of a quarantine
    nonce: str = field(default_factory=lambda: secrets.token_hex(8), repr=False)

    def to_event(self, *, router_id: str | None = None) -> SecurityEvent:
        """The action as a successful :class:`SecurityEvent` (own dedup scope)."""
        name = f"trust_{self.kind.value}"
        severity = (
            Severity.WARNING
            if self.kind is TrustActionKind.QUARANTINED
            else Severity.INFO
        )
        return SecurityEvent(
            event_id=make_event_id(name, router_id, self.mac, self.at, self.nonce),
            ts=self.at,
            type=event_type(name),
            router_id=router_id,
            category=SecCategory.DEVICE,
            severity=severity,
            result=EventResult.SUCCESS,
            dedup_key=make_dedup_key(name, self.mac, self.at, self.nonce),
            client=self.mac,
            actor=self.actor,
            evidence=() if self.method is None else (f"method={self.method}",),
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class TrustRecord:
    """Trust facts of one device (identities hidden in repr)."""

    mac: str = field(repr=False)
    first_seen: float | None = None
    last_seen: float | None = None
    private_mac: bool = False
    name: str | None = field(default=None, repr=False)
    confirmed_at: float | None = None
    ip: str | None = field(default=None, repr=False)
    hostname: str | None = field(default=None, repr=False)
    ip_changes: tuple[float, ...] = ()
    indicators: tuple[tuple[str, float], ...] = ()
    notified: bool = False
    quarantined_at: float | None = None
    quarantine_method: str | None = None
    observed: bool = True  # False: only known from indicators so far

    @property
    def confirmed(self) -> bool:
        """True after a manual confirmation."""
        return self.confirmed_at is not None

    @property
    def quarantined(self) -> bool:
        """True while quarantined (only set and cleared explicitly)."""
        return self.quarantined_at is not None

    def active_indicators(self, now: float, window_s: float) -> tuple[str, ...]:
        """Distinct indicator kinds seen within ``window_s`` before ``now``."""
        return tuple(sorted({k for k, ts in self.indicators if now - ts <= window_s}))

    def to_dict(self) -> dict[str, Any]:
        """Store form (contains the MAC: never log it)."""
        return {
            "mac": self.mac,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "private_mac": self.private_mac,
            "name": self.name,
            "confirmed_at": self.confirmed_at,
            "ip": self.ip,
            "hostname": self.hostname,
            "ip_changes": list(self.ip_changes),
            "indicators": [[k, ts] for k, ts in self.indicators],
            "notified": self.notified,
            "quarantined_at": self.quarantined_at,
            "quarantine_method": self.quarantine_method,
            "observed": self.observed,
        }

    @classmethod
    def from_dict(cls, data: Any) -> TrustRecord | None:
        """Lenient inverse of :meth:`to_dict`; None if unusable."""
        if not isinstance(data, Mapping):
            return None
        mac = normalize_mac(data.get("mac"))
        if mac is None:
            return None
        changes = data.get("ip_changes")
        inds = data.get("indicators")
        quarantined_at = _opt_time(data.get("quarantined_at"))
        return cls(
            mac=mac,
            first_seen=_opt_time(data.get("first_seen")),
            last_seen=_opt_time(data.get("last_seen")),
            private_mac=data.get("private_mac") is True,
            name=_opt_str(data.get("name"), MAX_NAME_LEN),
            confirmed_at=_opt_time(data.get("confirmed_at")),
            ip=_opt_str(data.get("ip"), 64),
            hostname=_opt_str(data.get("hostname"), 64),
            ip_changes=tuple(
                t for t in (changes if isinstance(changes, list) else ()) if _is_time(t)
            )[-MAX_IP_CHANGES:],
            indicators=tuple(
                (str(i[0]), float(i[1]))
                for i in (inds if isinstance(inds, list) else ())
                if isinstance(i, list | tuple)
                and len(i) == 2
                and isinstance(i[0], str)
                and _is_time(i[1])
            )[-MAX_INDICATORS:],
            notified=data.get("notified") is True,
            quarantined_at=quarantined_at,
            quarantine_method=(
                (_opt_str(data.get("quarantine_method"), 64) or "unknown")
                if quarantined_at is not None
                else None
            ),
            observed=data.get("observed") is not False,
        )


def _is_time(value: Any) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _opt_time(value: Any) -> float | None:
    return float(value) if _is_time(value) else None


def _opt_str(value: Any, max_len: int) -> str | None:
    if not isinstance(value, str):
        return None
    text = clean_text(value, max_len)
    return text or None


class TrustBook:
    """Trust state of all devices, bounded by ``max_entries``."""

    def __init__(
        self,
        *,
        new_period_s: float = DEFAULT_NEW_PERIOD_S,
        ip_churn_window_s: float = DEFAULT_IP_CHURN_WINDOW_S,
        ip_churn_min: int = DEFAULT_IP_CHURN_MIN,
        indicator_window_s: float = DEFAULT_INDICATOR_WINDOW_S,
        suspicious_min_indicators: int = DEFAULT_SUSPICIOUS_MIN_INDICATORS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_indicator_only: int | None = None,
    ) -> None:
        """Create an empty book; all thresholds are parameters.

        ``max_indicator_only`` (default ``max_entries // 8``, at least 1)
        bounds the entries known only from indicators.
        """
        self.new_period_s = float(new_period_s)
        self.ip_churn_window_s = float(ip_churn_window_s)
        self.ip_churn_min = max(2, int(ip_churn_min))
        self.indicator_window_s = float(indicator_window_s)
        # An unknown MAC alone must never be suspicious: at least 2 kinds.
        self.suspicious_min_indicators = max(2, int(suspicious_min_indicators))
        self.max_entries = max(1, int(max_entries))
        cap = (
            self.max_entries // 8 if max_indicator_only is None else max_indicator_only
        )
        self.max_indicator_only = min(self.max_entries, max(1, int(cap)))
        self.capacity_overflow = 0
        self._records: dict[str, TrustRecord] = {}
        # Evictable (unconfirmed, unquarantined) MACs, least recently seen first.
        self._evictable: OrderedDict[str, None] = OrderedDict()
        # Never-observed MACs (only from indicators), oldest first.
        self._indicator_only: OrderedDict[str, None] = OrderedDict()

    def __len__(self) -> int:
        """Number of tracked devices."""
        return len(self._records)

    def __repr__(self) -> str:
        """Counts only, no identities."""
        return (
            f"TrustBook(entries={len(self._records)}, max={self.max_entries}, "
            f"overflow={self.capacity_overflow})"
        )

    # --- reading ---------------------------------------------------------------

    def get(self, mac: str) -> TrustRecord | None:
        """Record of ``mac`` or None."""
        key = normalize_mac(mac)
        return None if key is None else self._records.get(key)

    def state(self, mac: str, now: float) -> TrustState:
        """Trust state; an untracked or unidentifiable device is unrecognized."""
        record = self.get(mac)
        return TrustState.UNRECOGNIZED if record is None else self._derive(record, now)

    def counts(self, now: float) -> dict[str, int]:
        """Number of devices per state (for the score and diagnostics)."""
        out = {state.value: 0 for state in TrustState}
        for record in self._records.values():
            out[self._derive(record, now).value] += 1
        return out

    def _derive(self, record: TrustRecord, now: float) -> TrustState:
        if record.quarantined:
            return TrustState.QUARANTINED
        active = record.active_indicators(now, self.indicator_window_s)
        if len(active) >= self.suspicious_min_indicators:
            return TrustState.SUSPICIOUS
        if record.confirmed:
            return TrustState.KNOWN
        if record.first_seen is None:
            return TrustState.UNRECOGNIZED
        if now - record.first_seen <= self.new_period_s:
            return TrustState.NEW
        return TrustState.UNRECOGNIZED

    # --- updates ---------------------------------------------------------------

    def observe(self, obs: ClientObservation, now: float) -> tuple[TrustNotice, ...]:
        """Take one client observation; returns the notices it causes."""
        mac = normalize_mac(getattr(obs, "mac", None))
        if mac is None:
            return ()
        old = self._records.get(mac)
        private = getattr(obs, "private_mac", None)
        if not isinstance(private, bool):
            private = is_locally_administered(mac)
        room: tuple[TrustNotice, ...] = ()
        if old is None:
            room = self._make_room(now)
            if len(self._records) >= self.max_entries:
                return (*room, self._overflow_notice(now))
            old = TrustRecord(mac=mac, private_mac=private)
        created = mac not in self._records
        before = None if created else self._derive(old, now)
        record, notices = self._apply(old, obs, private, now, created)
        self._store(replace(record, observed=True))
        return room + tuple(notices) + self._transition(before, record, now)

    def _apply(
        self,
        old: TrustRecord,
        obs: ClientObservation,
        private: bool,
        now: float,
        created: bool,
    ) -> tuple[TrustRecord, list[TrustNotice]]:
        notices: list[TrustNotice] = []
        first_seen = old.first_seen
        if first_seen is None:
            first_seen = _opt_time(getattr(obs, "first_seen", None))
        last_seen = _opt_time(getattr(obs, "last_seen", None)) or old.last_seen
        ip = _opt_str(getattr(obs, "ip", None), 64)
        host = _opt_str(getattr(obs, "hostname", None), 64)
        changes = old.ip_changes
        indicators = old.indicators
        if ip is not None and old.ip is not None and ip != old.ip:
            changes = tuple(
                t for t in (*changes, now) if now - t <= self.ip_churn_window_s
            )[-MAX_IP_CHANGES:]
            if len(changes) >= self.ip_churn_min:
                indicators = _add_indicator(indicators, Indicator.IP_CHURN, now)
                if len(changes) == self.ip_churn_min:
                    notices.append(self._notice(NoticeKind.IP_CHURN, old.mac, now))
        if host is not None and old.hostname is not None and host != old.hostname:
            indicators = _add_indicator(indicators, Indicator.HOSTNAME_CHANGE, now)
        record = replace(
            old,
            first_seen=first_seen,
            last_seen=last_seen,
            private_mac=private,
            ip=ip if ip is not None else old.ip,
            hostname=host if host is not None else old.hostname,
            ip_changes=changes,
            indicators=indicators,
        )
        if not record.notified and not record.confirmed:
            kind = self._first_notice(record, now)
            if kind is NoticeKind.INCOMPLETE and not created:
                kind = None  # reported once, when the device was first tracked
            if kind is not None:
                notices.append(self._notice(kind, record.mac, now, record))
                if kind is not NoticeKind.INCOMPLETE:
                    record = replace(record, notified=True)
        return record, notices

    def _first_notice(self, record: TrustRecord, now: float) -> NoticeKind | None:
        if record.first_seen is None:
            return NoticeKind.INCOMPLETE
        if now - record.first_seen > self.new_period_s:
            return None  # long known to Client Stability: not new, no alarm
        return NoticeKind.PRIVATE_MAC if record.private_mac else NoticeKind.NEW_DEVICE

    def add_indicator(
        self, mac: str, kind: Indicator | str, now: float
    ) -> tuple[TrustNotice, ...]:
        """Record one indicator (from a detector); notices on a state change."""
        key = normalize_mac(mac)
        if key is None:
            return ()
        old = self._records.get(key)
        room: tuple[TrustNotice, ...] = ()
        if old is None:
            room = self._trim_indicator_only(self.max_indicator_only - 1, now)
            room += self._make_room(now)
            if len(self._records) >= self.max_entries:
                return (*room, self._overflow_notice(now))
            old = TrustRecord(
                mac=key, private_mac=is_locally_administered(key), observed=False
            )
        before = self._derive(old, now) if key in self._records else None
        name = clean_text(str(kind), 32)
        record = replace(old, indicators=_add_indicator(old.indicators, name, now))
        self._store(record)
        return room + self._transition(before, record, now)

    def _action(
        self,
        kind: TrustActionKind,
        record: TrustRecord,
        at: float | None,
        actor: Actor | None,
        method: str | None = None,
    ) -> TrustAction:
        when = at if _is_time(at) else (record.last_seen or record.first_seen or 0.0)
        return TrustAction(
            kind=kind,
            at=float(when),  # type: ignore[arg-type]
            mac=record.mac,
            actor=event_actor(actor),
            method=method,
        )

    def confirm(
        self,
        mac: str,
        now: float,
        *,
        name: str | None = None,
        actor: Actor | None = None,
    ) -> TrustAction | None:
        """Manual confirmation → known; refused (None) for a quarantined device."""
        key = normalize_mac(mac)
        if key is None:
            return None
        old = self._records.get(key)
        if old is not None and old.quarantined:
            return None
        if old is None:
            self._make_room(now)  # notices of a manual action are not returned
            if len(self._records) >= self.max_entries:
                self.capacity_overflow += 1
                return None
            old = TrustRecord(mac=key, private_mac=is_locally_administered(key))
        record = replace(
            old,
            observed=True,
            confirmed_at=now,
            indicators=(),
            ip_changes=(),
            notified=True,
            name=_opt_str(name, MAX_NAME_LEN) if name is not None else old.name,
        )
        self._store(record)
        return self._action(TrustActionKind.CONFIRMED, record, now, actor)

    def set_name(
        self,
        mac: str,
        name: str | None,
        *,
        actor: Actor | None = None,
        now: float | None = None,
    ) -> TrustAction | None:
        """Give a tracked device a display name (None clears it).

        ``now`` dates the action (default: the device's last seen time).
        """
        record = self.get(mac)
        if record is None:
            return None
        record = replace(record, name=_opt_str(name, MAX_NAME_LEN))
        self._store(record)
        return self._action(TrustActionKind.RENAMED, record, now, actor)

    def quarantine(
        self,
        mac: str,
        proof: IsolationProof,
        now: float,
        *,
        actor: Actor | None = None,
    ) -> TrustAction | None:
        """Mark a tracked device quarantined; requires an isolation proof.

        Never called automatically (no caller in this stage). Raises
        TypeError without a proper :class:`IsolationProof`.
        """
        if not isinstance(proof, IsolationProof):
            raise TypeError("quarantine requires an IsolationProof")
        record = self.get(mac)
        if record is None:
            return None
        record = replace(record, quarantined_at=now, quarantine_method=proof.method)
        self._store(record)
        return self._action(
            TrustActionKind.QUARANTINED, record, now, actor, proof.method
        )

    def release_quarantine(
        self, mac: str, *, actor: Actor | None = None, now: float | None = None
    ) -> TrustAction | None:
        """Explicitly leave quarantine (the only way out).

        ``now`` dates the action (default: the device's last seen time).
        """
        record = self.get(mac)
        if record is None or not record.quarantined:
            return None
        record = replace(record, quarantined_at=None, quarantine_method=None)
        self._store(record)
        return self._action(TrustActionKind.RELEASED, record, now, actor)

    # --- internals -------------------------------------------------------------

    def _transition(
        self, before: TrustState | None, record: TrustRecord, now: float
    ) -> tuple[TrustNotice, ...]:
        after = self._derive(record, now)
        if after is TrustState.SUSPICIOUS and before is not TrustState.SUSPICIOUS:
            return (self._notice(NoticeKind.SUSPICIOUS, record.mac, now, record),)
        return ()

    def _notice(
        self,
        kind: NoticeKind,
        mac: str | None,
        now: float,
        record: TrustRecord | None = None,
    ) -> TrustNotice:
        state = self._derive(record, now) if record else TrustState.UNRECOGNIZED
        inds = record.active_indicators(now, self.indicator_window_s) if record else ()
        return TrustNotice(kind=kind, state=state, at=now, mac=mac, indicators=inds)

    def _overflow_notice(self, now: float) -> TrustNotice:
        self.capacity_overflow += 1
        _LOGGER.debug("Trust book full of confirmed/quarantined devices")
        return TrustNotice(
            kind=NoticeKind.CAPACITY, state=TrustState.UNRECOGNIZED, at=now
        )

    def _make_room(self, now: float) -> tuple[TrustNotice, ...]:
        """Free one entry if full; the book may stay full (caller checks).

        First choice: the least recently seen evictable entry without active
        indicators (silent: nothing is lost). Otherwise the oldest entry
        known only from indicators (counted and reported). Entries with
        active indicators that were observed as clients are never evicted.
        """
        if len(self._records) < self.max_entries:
            return ()
        for mac in self._evictable:
            record = self._records[mac]
            if not record.active_indicators(now, self.indicator_window_s):
                self._drop(mac)
                return ()
        return self._trim_indicator_only(len(self._indicator_only) - 1, now)

    def _trim_indicator_only(self, keep: int, now: float) -> tuple[TrustNotice, ...]:
        """Displace the oldest indicator-only entries down to ``keep``."""
        notices: list[TrustNotice] = []
        while self._indicator_only and len(self._indicator_only) > max(0, keep):
            mac = next(iter(self._indicator_only))
            self._drop(mac)
            if not notices:
                notices.append(self._overflow_notice(now))
            else:
                self.capacity_overflow += 1
        return tuple(notices)

    def _drop(self, mac: str) -> None:
        self._records.pop(mac, None)
        self._evictable.pop(mac, None)
        self._indicator_only.pop(mac, None)

    def _store(self, record: TrustRecord) -> None:
        self._records[record.mac] = record
        if record.confirmed or record.quarantined:
            self._evictable.pop(record.mac, None)
        else:
            self._evictable[record.mac] = None
            self._evictable.move_to_end(record.mac)
        if record.observed or record.confirmed or record.quarantined:
            self._indicator_only.pop(record.mac, None)
        elif record.mac not in self._indicator_only:
            self._indicator_only[record.mac] = None

    # --- persistence -----------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Store form (contains MACs: never log it)."""
        order = list(self._evictable)
        fixed = [m for m in self._records if m not in self._evictable]
        return {
            "v": STORE_VERSION,
            "records": [self._records[m].to_dict() for m in (*fixed, *order)],
        }

    @classmethod
    def from_dict(cls, data: Any, **params: Any) -> TrustBook:
        """Rebuild from :meth:`to_dict`; damaged records are skipped."""
        book = cls(**params)
        rows = data.get("records") if isinstance(data, Mapping) else None
        for row in rows if isinstance(rows, list) else ():
            record = TrustRecord.from_dict(row)
            if record is None or record.mac in book._records:
                continue
            if len(book._records) >= book.max_entries and not book._load_room():
                book.capacity_overflow += 1
                continue
            book._store(record)
        return book

    def _load_room(self) -> bool:
        """Room while loading (no clock): oldest evictable; counted if it
        carried indicators."""
        if not self._evictable:
            return False
        victim = next(iter(self._evictable))
        if self._records[victim].indicators:
            self.capacity_overflow += 1
        self._drop(victim)
        return True


def _add_indicator(
    indicators: Iterable[tuple[str, float]], kind: str, now: float
) -> tuple[tuple[str, float], ...]:
    kept = [(k, ts) for k, ts in indicators if k != kind]
    kept.append((str(kind), now))
    return tuple(kept[-MAX_INDICATORS:])
