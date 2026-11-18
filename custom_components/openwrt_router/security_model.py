"""Security Center data model: normalised security events and source status.

Pure module (plan ``docs/plans/2026-11-17-security-center.md``, stage 2).
No clock, no I/O, no global mutable state: every time is a ``float`` epoch
second passed in by the caller. It imports the enterprise core contract
(``core_models``, ``core_masking``; ``docs/dev/configuration-api-v1.md``)
and has no Home Assistant import of its own (``core_models`` pulls in
``homeassistant.exceptions`` through ``core_errors``).

Alignment with the core contract (section 12):

* :class:`SecurityEvent` uses the field names of ``CoreEvent`` wherever the
  core has the concept (``event_id``, ``ts``, ``type``, ``severity``,
  ``result``, ``router_id``, ``entry_id``, ``correlation_id``,
  ``dedup_key``). ``CoreEvent.source`` names the emitting module, so the
  data source of a finding is ``data_source``. Security-only fields
  (client, endpoints, evidence, assessment, confidence, proof, links to
  existing incidents) map into ``CoreEvent.data`` via
  :meth:`SecurityEvent.to_core_event`, the contract's extension point.
* ``ts`` is a float here (the pure modules never build datetimes from a
  clock); ``to_core_event`` converts it to an aware UTC datetime.
* ``type`` is ``security_center.<name>``: module event types live outside
  the core namespaces (contract 12.3; ``security.`` is core-only and
  rejected), while capability names stay below ``security.center.``
  (contract 5). Both prefixes come from the core tables
  (``MODULE_EVENT_PREFIXES``, ``MODULE_CAPABILITY_NAMESPACES``). The
  matching incident type is ``sec_<name>`` (plan 3).
* ``router_id`` is a contract router id (``rtr_`` + 32 hex, checked with
  ``core_models.is_valid_id``; :func:`valid_router_id`). It stays a
  parameter: this module never reads the registry.
* ``actor`` is a ``core_models.Actor`` that carries no Home Assistant user
  id: :func:`pseudonymous_actor` replaces it with the core pseudonym
  (``core_masking.pseudonymise_user_id``, ``usr_<12 hex>``) and drops the
  context ids (the recorder links a context id to its user).
* Client and endpoint addresses reach ``CoreEvent.data`` only as references
  made with the core digest (``core_masking.secret_digest_factory``,
  :func:`identity_digest`).
* ``dedup_key`` is only the discriminator; the scope is
  ``(router_id or "-", type, dedup_key)`` (contract 12.4,
  :attr:`SecurityEvent.dedup_scope`). Merged duplicates map to
  ``CoreEvent.repeat_count`` / ``last_repeat_at``.
* Ids follow the core formats (``evt_``/``cor_`` + 32 hex) but are derived
  deterministically from their inputs, so the same finding gets the same id.

Data source keys are capability names (contract section 5): core names
where the core already has the capability, names below
``security.center.`` otherwise.

This module is the only Security Center module that touches the core
(``core_models``, ``core_masking``): the other ``security_*`` modules import
core symbols only through it, so a contract revision changes one file.

Masking: secrets go through ``core_masking.mask_for_output`` (secret keys
and secrets in free text) FIRST, on the uncut text. The core masks no
identities; MAC, IP, domain, identity keys (``const.DIAGNOSTICS_TO_REDACT``)
and identity ``key=value`` pairs in free text are masked afterwards by the
one helper :func:`mask_identities` (the only masking helper of the Security
Center; all other modules call it).

Forgotten routers (core event ``router.forgotten``): :func:`forgotten_router_id`
reads the event, :func:`forget_router` drops the router's state from every
holder (detectors, baselines, dedup, liveness, key assigner). The trust book
is fleet-wide and keeps its records.

Sensitive reads (note for the wiring stage, nothing enforced here): the
store forms ``SecurityEvent.to_dict``, ``TrustBook.to_dict``/``get``,
``BaselineBook.to_dict`` and the log records hold MACs, IPs, names and
domains unmasked. Any later read path for users (panel, service, websocket)
must require an admin user like the core does for ``config_capture`` /
``config_compare`` (contract 19.1 #95) and hand out only masked forms.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, Protocol

from .const import DIAGNOSTICS_TO_REDACT
from .core_masking import (
    ACTOR_PSEUDONYM_HEX_LENGTH,
    ACTOR_PSEUDONYM_PREFIX,
    MASK,
    MAX_DEPTH,
    TRUNCATED,
    mask_for_output,
    pseudonymise_user_id,
    secret_digest_factory,
)
from .core_models import (
    CORRELATION_ID_PREFIX,
    EVENT_ID_PREFIX,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    ROUTER_ID_PREFIX,
    Actor,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    CoreEventType,
    EventResult,
    Severity,
    is_core_event_type,
    is_valid_id,
)
from .core_models import normalize_mac as _core_normalize_mac

_LOGGER = logging.getLogger(__name__)

# re-exported for the security modules
__all__ = ["Actor", "EventResult", "Severity"]

SCHEMA_VERSION: Final = 1
MODULE_SOURCE: Final = "security_center"  # CoreEvent.source, core module name
# Event types (contract 12.3) and capabilities (contract 5 / 17.1).
EVENT_PREFIX: Final = MODULE_EVENT_PREFIXES[MODULE_SOURCE]
CAPABILITY_PREFIX: Final = f"{MODULE_CAPABILITY_NAMESPACES[MODULE_SOURCE]}center."
INCIDENT_PREFIX: Final = "sec_"
# Domain of the identity references (the core digest key is shared with
# the configuration digests, so the value names its use).
IDENTITY_DIGEST_DOMAIN: Final = "security_center/identity/"

MAX_EVIDENCE: Final = 8
MAX_EVIDENCE_LEN: Final = 160
MAX_TEXT_LEN: Final = 200
MAX_ID_LEN: Final = 96
MAX_LINKED_INCIDENTS: Final = 16
# Confidence of a finding without measured proof (a hint, plan 3 wording).
HYPOTHESIS_CONFIDENCE_CAP: Final = 0.6
# Default age after which a source that delivered before counts as stale
# (plan 4.9: 15 minutes without records).
DEFAULT_STALE_AFTER_S: Final = 900.0

MASK_MAC: Final = "<mac>"
MASK_IP: Final = "<ip>"
MASK_DOMAIN: Final = "<domain>"


class SecCategory(StrEnum):
    """Area of a security event (plan section 3)."""

    DEVICE = "device"
    WIFI = "wifi"
    FIREWALL = "firewall"
    DNS = "dns"
    VLAN = "vlan"
    ADMIN = "admin"
    CONFIG = "config"
    SYSTEM = "system"


class Assessment(StrEnum):
    """How a finding is classified.

    ``confirmed`` needs an explicit proof flag and a data source that is not
    only log text (syslog is forgeable, plan D-TRUST); counters alone never
    confirm anything.
    """

    NORMAL = "normal"
    NOTICEABLE = "noticeable"
    SUSPICIOUS = "suspicious"  # several independent indicators
    CONFIRMED = "confirmed"

    @property
    def rank(self) -> int:
        """Ordering value: normal < noticeable < suspicious < confirmed."""
        return _ASSESSMENT_RANK[self.value]


_ASSESSMENT_RANK = {"normal": 0, "noticeable": 1, "suspicious": 2, "confirmed": 3}


class Availability(StrEnum):
    """State of one data source as the detectors see it."""

    AVAILABLE = "available"
    NOT_AVAILABLE = "not_available"
    STALE = "stale"


class DataSource(StrEnum):
    """Data source keys = capability names (contract section 5).

    Numbers refer to the source matrix of the plan (section 2.2). The ubus
    event stream (#16) and the full conntrack table (#4) are deliberately
    absent (master decision); the firewall configuration (#25, firewall part)
    comes as drift events of the configuration manager (``config.drift``).
    """

    # Core capabilities reused as they are.
    ROUTER_LOG = Capability.DATA_LOGS.value  # #6, #21 (log read)
    HOSTAPD_CLIENTS = Capability.DATA_HOSTAPD_CLIENTS.value  # #15
    DHCP_LEASES = Capability.DATA_DHCP_LEASES.value  # #10
    SERVICES = Capability.DATA_SERVICES.value  # #22
    WIFI_SCAN = Capability.DATA_IWINFO.value  # #20 (manual scan only)
    NETWORK_UCI = Capability.DATA_UCI.value  # #25 network part, #26
    CONFIG_DRIFT = Capability.CONFIG_DRIFT.value  # #25 zones, management
    # Security Center names below the registered prefix.
    WIFI_EVENTS = "security.center.wifi_events"  # #17, #18, #19 (NI events)
    NI_INCIDENTS = "security.center.ni_incidents"  # #30
    CLIENT_HISTORY = "security.center.client_history"  # #29 (Client Stability)
    ARP_TABLE = "security.center.arp_table"  # #27
    BRIDGE_FDB = "security.center.bridge_fdb"  # #28
    IFACE_COUNTERS = "security.center.iface_counters"  # #7
    ROUTER_UPTIME = "security.center.router_uptime"  # #23
    DNS_ERRORS = "security.center.dns_errors"  # #11, #13 (dnsmasq/odhcpd lines)
    ADMIN_LOGIN_LOG = "security.center.admin_login_log"  # #24
    CONNTRACK_STATS = "security.center.conntrack_stats"  # #3 (count + max)
    NFT_COUNTERS = "security.center.nft_counters"  # #1, #2 (on request, SSH)
    NET_SNMP = "security.center.net_snmp"  # #8
    DNSMASQ_METRICS = "security.center.dnsmasq_metrics"  # #9
    IPV6_NEIGHBORS = "security.center.ipv6_neighbors"  # #14
    FIREWALL_LOG = "security.center.firewall_log"  # #5 (log path only)
    DNS_QUERY_LOG = "security.center.dns_query_log"  # #12 (log path only)


class LogPath(StrEnum):
    """Off-router log delivery path setting (plan 4.1); at most one is active.

    ``off`` is the setting "no off-router logs"; it has no capability name.
    """

    SYSLOG = "syslog"
    COLLECTOR = "collector"
    OFF = "off"


def log_path_capability(path: LogPath | str) -> str:
    """Capability name of one log path, e.g. ``security.center.log_path.syslog``.

    Raises ValueError for ``off`` (no delivery path, nothing to report).
    """
    value = LogPath(path)
    if value is LogPath.OFF:
        raise ValueError("log path 'off' has no capability")
    return f"{CAPABILITY_PREFIX}log_path.{value.value}"


# Matrix group of each source (plan 2.1): a = data already present,
# b = new light-weight read, c = needs a router change / off-router path.
SOURCE_GROUPS: Final[Mapping[str, str]] = MappingProxyType(
    {
        DataSource.ROUTER_LOG: "a",
        DataSource.HOSTAPD_CLIENTS: "a",
        DataSource.DHCP_LEASES: "a",
        DataSource.SERVICES: "a",
        DataSource.WIFI_SCAN: "b",
        DataSource.NETWORK_UCI: "a",
        DataSource.CONFIG_DRIFT: "b",
        DataSource.WIFI_EVENTS: "a",
        DataSource.NI_INCIDENTS: "a",
        DataSource.CLIENT_HISTORY: "a",
        DataSource.ARP_TABLE: "a",
        DataSource.BRIDGE_FDB: "a",
        DataSource.IFACE_COUNTERS: "a",
        DataSource.ROUTER_UPTIME: "a",
        DataSource.DNS_ERRORS: "a",
        DataSource.ADMIN_LOGIN_LOG: "a",
        DataSource.CONNTRACK_STATS: "b",
        DataSource.NFT_COUNTERS: "b",
        DataSource.NET_SNMP: "b",
        DataSource.DNSMASQ_METRICS: "b",
        DataSource.IPV6_NEIGHBORS: "b",
        DataSource.FIREWALL_LOG: "c",
        DataSource.DNS_QUERY_LOG: "c",
    }
)
# Sources that only reach HA through an off-router log path (plan 4).
PATH_SOURCES: Final = frozenset({DataSource.FIREWALL_LOG, DataSource.DNS_QUERY_LOG})
# Sources that are log text: forgeable, never enough for "confirmed".
LOG_DERIVED_SOURCES: Final = frozenset(
    {
        DataSource.ROUTER_LOG,
        DataSource.WIFI_EVENTS,
        DataSource.DNS_ERRORS,
        DataSource.ADMIN_LOGIN_LOG,
        DataSource.FIREWALL_LOG,
        DataSource.DNS_QUERY_LOG,
    }
)

# --- text hygiene and masking ------------------------------------------------

_MAC_RE = re.compile(
    r"(?<![0-9A-Fa-f:-])[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}(?![0-9A-Fa-f:-])"
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+"
    r"[A-Za-z][A-Za-z0-9-]{1,62}\.?(?![\w-])"
)
# Two-label names of our own vocabulary (``wifi.roam``, ``fw.drop``) are no
# domains; anything with three or more labels is masked.
_OWN_NAMESPACES = frozenset(
    {"wifi", "fw", "dns", "dhcp", "system", "lan", "wan", "sec", "auth", "link"}
    | {"iface", "dfs", "mesh", "ids", "data", "security", "config", "log", "stream"}
)
# Extra identity keys of this module (masked like DIAGNOSTICS_TO_REDACT).
_IDENTITY_KEYS = frozenset(
    {k.lower() for k in DIAGNOSTICS_TO_REDACT}
    | {"client", "addr", "src", "dst", "name", "names", "sender", "client_ip"}
)


# ``key=value`` / ``key: value`` pairs in free text whose key names an
# identity (a bare hostname is otherwise not recognisable in text).
_KV_RE = re.compile(
    r"(?i)\b(host|hostname|name|client|mac|ip|addr|domain|sender|example|user)"
    r"(\s*[=:]\s*)(?!<|\*\*)[^\s,;\]\)}\"']+"
)


def clean_text(value: object, max_len: int = MAX_TEXT_LEN) -> str:
    """Untrusted text made safe to keep: control characters dropped, capped.

    Router log text is foreign input: every Unicode "other" character
    (control, format such as bidi overrides, private use, unassigned) is
    removed, then the text is cut to ``max_len`` characters ("…" at the end).
    """
    text = value if isinstance(value, str) else str(value)
    text = text[: max(1, max_len) * 4]  # bound the work on huge input
    text = "".join(ch for ch in text if not unicodedata.category(ch).startswith("C"))
    text = text.strip()
    if len(text) > max_len:
        text = text[: max(0, max_len - 1)] + "…"
    return text


def _mask_ipv6(match: re.Match[str]) -> str:
    text = match.group(0)
    return MASK_IP if "::" in text or text.count(":") >= 5 else text


def _mask_domain(match: re.Match[str]) -> str:
    text = match.group(0)
    labels = text.rstrip(".").split(".")
    if len(labels) == 2 and labels[0].lower() in _OWN_NAMESPACES:
        return text
    return MASK_DOMAIN


def _mask_text(text: str) -> str:
    text = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    text = _MAC_RE.sub(MASK_MAC, text)
    text = _IPV4_RE.sub(MASK_IP, text)
    text = _IPV6_RE.sub(_mask_ipv6, text)
    return _DOMAIN_RE.sub(_mask_domain, text)


def mask_identities(value: Any) -> Any:
    """Copy of ``value`` with secrets and identities masked (logs, diagnostics).

    First ``core_masking.mask_for_output`` on the original value (secret
    keys, secrets in free text): the core must judge the uncut text, since
    a token cut by the length cap below is too short for it to recognise.
    A secret value is masked by the core up to the end of its line, so an
    identity behind it is gone with it.

    Then the identities (the part the core does not cover): mapping keys
    that name one (``mac``, ``ip``, ``hostname``, ``domain``, ``client`` …)
    get the core MASK; strings anywhere are cleaned and capped
    (:func:`clean_text`) and have identity ``key=value`` pairs, MACs,
    IPv4/IPv6 addresses and domain names replaced. A bare hostname inside
    free text without a key cannot be recognised: keep hostnames in keyed
    fields. ``None`` stays ``None``; deeper than the core's ``MAX_DEPTH``
    becomes the core's ``TRUNCATED``.
    """
    return _mask_identity_walk(mask_for_output(value))


def _mask_identity_walk(value: Any, _depth: int = 0) -> Any:
    if _depth > MAX_DEPTH:
        return TRUNCATED
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _mask_text(clean_text(value, MAX_TEXT_LEN))
    if isinstance(value, Mapping):
        return {
            key: (
                (None if item is None else MASK)
                if str(key).lower() in _IDENTITY_KEYS
                else _mask_identity_walk(item, _depth + 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, list | tuple | set | frozenset):
        return [_mask_identity_walk(item, _depth + 1) for item in value]
    return _mask_text(clean_text(str(value), MAX_TEXT_LEN))


def normalize_mac(value: object) -> str | None:
    """``aa:bb:cc:dd:ee:ff`` (core contract form) or None if not a MAC."""
    return _core_normalize_mac(value)


def valid_router_id(value: object) -> str | None:
    """``value`` if it is a contract router id (``rtr_`` + 32 hex), else None.

    No normalisation: the registry hands out exactly this form and rejects
    every other one (contract 3, 19.1 #61).
    """
    return value if is_valid_id(value, ROUTER_ID_PREFIX) else None  # type: ignore[return-value]


# --- actors and identity references -------------------------------------------

_PSEUDONYM_RE = re.compile(
    rf"{re.escape(ACTOR_PSEUDONYM_PREFIX)}[0-9a-f]{{{ACTOR_PSEUDONYM_HEX_LENGTH}}}"
)


def is_pseudonym(value: object) -> bool:
    """True for a core user pseudonym ``usr_<12 hex>``."""
    return isinstance(value, str) and _PSEUDONYM_RE.fullmatch(value) is not None


def pseudonymous_actor(actor: Actor | None, salt: bytes) -> Actor | None:
    """Copy of ``actor`` fit for an event: no Home Assistant user id.

    ``user_id`` becomes ``core_masking.pseudonymise_user_id(user_id, salt)``
    (an existing pseudonym is kept); ``context_id`` and
    ``parent_context_id`` are dropped, because the recorder stores the user
    of every context. Kind, module and ``is_admin`` stay.
    """
    if actor is None:
        return None
    user = actor.user_id
    if user is not None and not is_pseudonym(user):
        user = pseudonymise_user_id(user, salt)
    return Actor(
        kind=actor.kind, user_id=user, module=actor.module, is_admin=actor.is_admin
    )


def _check_actor(actor: Any) -> None:
    if actor is None:
        return
    if not isinstance(actor, Actor):
        raise TypeError("actor must be a core Actor")
    if actor.user_id is not None and not is_pseudonym(actor.user_id):
        raise ValueError("events carry user pseudonyms only (pseudonymous_actor)")
    if actor.context_id is not None or actor.parent_context_id is not None:
        raise ValueError("events carry no context ids (pseudonymous_actor)")


def identity_digest(key: bytes) -> Callable[[str], str]:
    """Reference function for client and endpoint identities (core digest).

    ``core_masking.secret_digest_factory(key)`` (HMAC-SHA256, 16 hex, key of
    at least 16 bytes; TypeError/ValueError otherwise) over
    ``IDENTITY_DIGEST_DOMAIN + value``. A MAC is normalised first, other
    values are stripped and lower-cased, so one device has one reference.
    """
    digest = secret_digest_factory(key)

    def ref(value: str) -> str:
        mac = normalize_mac(value)
        return digest(IDENTITY_DIGEST_DOMAIN + (mac or value.strip().lower()))

    return ref


# --- ids ----------------------------------------------------------------------


def _digest(parts: Iterable[Any], size: int = 16) -> str:
    text = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.blake2b(text.encode("utf-8"), digest_size=size).hexdigest()


def make_event_id(*parts: Any) -> str:
    """Deterministic ``evt_<32 hex>`` id (core format) from ``parts``."""
    return EVENT_ID_PREFIX + _digest(parts)


def make_correlation_id(*parts: Any) -> str:
    """Deterministic ``cor_<32 hex>`` id (core format) from ``parts``."""
    return CORRELATION_ID_PREFIX + _digest(parts)


def make_dedup_key(*identity: Any) -> str:
    """Dedup discriminator (contract 12.4): a digest of the identity parts.

    Router and type are not part of it; they form the scope
    (:attr:`SecurityEvent.dedup_scope`). Identities are only hashed.
    """
    return _digest(identity, 8)


def event_type(name: str) -> str:
    """``security_center.<name>`` (CoreEvent.type below the module prefix)."""
    return f"{EVENT_PREFIX}{name}"


# --- assessment ---------------------------------------------------------------


def can_confirm(data_source: str, proof: bool) -> bool:
    """True only with an explicit proof from a source that is not log text."""
    return (
        proof is True and bool(data_source) and data_source not in LOG_DERIVED_SOURCES
    )


def assess(
    indicators: int, *, proof: bool = False, data_source: str = ""
) -> Assessment:
    """Classification from independent indicators (never confirmed by counts)."""
    if can_confirm(data_source, proof):
        return Assessment.CONFIRMED
    if indicators >= 2:
        return Assessment.SUSPICIOUS
    if indicators == 1:
        return Assessment.NOTICEABLE
    return Assessment.NORMAL


# --- endpoint and event -------------------------------------------------------


def _opt_text(value: Any, max_len: int = MAX_ID_LEN) -> str | None:
    if value is None:
        return None
    text = clean_text(value, max_len)
    return text or None


def _finite(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if isinstance(value, int) and 0 <= value <= 65535:
        return value
    return None


@dataclass(frozen=True, kw_only=True, slots=True)
class Endpoint:
    """Source or destination of a network finding (address hidden in repr)."""

    addr: str | None = field(default=None, repr=False)
    port: int | None = None
    zone: str | None = None

    def __post_init__(self) -> None:
        """Sanitise untrusted values."""
        object.__setattr__(self, "addr", _opt_text(self.addr, 64))
        object.__setattr__(self, "port", _port(self.port))
        object.__setattr__(self, "zone", _opt_text(self.zone, 32))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form (unmasked: store only)."""
        return {"addr": self.addr, "port": self.port, "zone": self.zone}

    @classmethod
    def from_dict(cls, data: Any) -> Endpoint | None:
        """Lenient inverse of :meth:`to_dict`; None for a non-mapping."""
        if not isinstance(data, Mapping):
            return None
        return cls(addr=data.get("addr"), port=data.get("port"), zone=data.get("zone"))


_REQUIRED = ("event_id", "ts", "type", "category")


@dataclass(frozen=True, kw_only=True, slots=True)
class SecurityEvent:
    """One normalised security finding; field names follow ``CoreEvent``.

    Construction sanitises every text (control characters dropped, lengths
    and the evidence list capped). ``assessment=CONFIRMED`` without
    :func:`can_confirm` raises ValueError, so do a ``router_id`` that is not
    a contract router id and an ``actor`` with a raw user id or a context
    id. ``repr`` never shows the client, addresses, actor or evidence text.
    """

    event_id: str
    ts: float
    type: str
    category: SecCategory
    router_id: str | None = None  # contract router id (rtr_…); None = fleet
    severity: Severity = Severity.INFO
    result: EventResult = EventResult.INFO
    entry_id: str | None = None
    correlation_id: str | None = None
    dedup_key: str | None = None
    data_source: str = ""
    assessment: Assessment = Assessment.NORMAL
    client: str | None = field(default=None, repr=False)
    src: Endpoint | None = field(default=None, repr=False)
    dst: Endpoint | None = field(default=None, repr=False)
    evidence: tuple[str, ...] = field(default=(), repr=False)
    confidence: float = HYPOTHESIS_CONFIDENCE_CAP
    proof: bool = False
    linked_incident_ids: tuple[str, ...] = ()
    count: int = 1
    last_ts: float | None = None
    actor: Actor | None = field(default=None, repr=False)  # pseudonymous only

    def __post_init__(self) -> None:
        """Validate and sanitise (frozen: values are set once, here)."""
        ts = _finite(self.ts)
        if ts is None:
            raise ValueError("ts must be a finite number")
        for name in ("event_id", "type"):
            text = _opt_text(getattr(self, name))
            if not text:
                raise ValueError(f"{name} must be a non-empty string")
            object.__setattr__(self, name, text)
        if is_core_event_type(self.type):
            raise ValueError("core event namespaces are reserved for the core")
        set_ = object.__setattr__
        set_(self, "ts", ts)
        set_(self, "category", SecCategory(self.category))
        set_(self, "severity", Severity(self.severity))
        set_(self, "result", EventResult(self.result))
        set_(self, "assessment", Assessment(self.assessment))
        if self.router_id is not None and valid_router_id(self.router_id) is None:
            raise ValueError("router_id must be a contract router id (rtr_...)")
        set_(self, "entry_id", _opt_text(self.entry_id))
        set_(self, "correlation_id", _opt_text(self.correlation_id))
        set_(self, "data_source", _opt_text(self.data_source) or "")
        set_(self, "client", _opt_text(self.client, 64))
        set_(self, "evidence", _cap_evidence(self.evidence))
        set_(self, "linked_incident_ids", _cap_links(self.linked_incident_ids))
        conf = _finite(self.confidence)
        set_(self, "confidence", 0.0 if conf is None else min(1.0, max(0.0, conf)))
        set_(self, "proof", self.proof is True)
        count = self.count if isinstance(self.count, int) else 1
        set_(self, "count", max(1, count) if not isinstance(count, bool) else 1)
        set_(self, "last_ts", _finite(self.last_ts))
        for name in ("src", "dst"):
            if not isinstance(getattr(self, name), Endpoint | None):
                raise TypeError(f"{name} must be an Endpoint")
        _check_actor(self.actor)
        if self.assessment is Assessment.CONFIRMED and not can_confirm(
            self.data_source, self.proof
        ):
            raise ValueError("confirmed needs proof from a non-log data source")
        key = _opt_text(self.dedup_key, 128)
        set_(self, "dedup_key", key or self._default_dedup_key())

    def _default_dedup_key(self) -> str:
        src, dst = self.src, self.dst
        return make_dedup_key(
            self.client,
            src.addr if src else None,
            src.zone if src else None,
            dst.addr if dst else None,
            dst.zone if dst else None,
            dst.port if dst else None,
        )

    @property
    def name(self) -> str:
        """Type without the module prefix, e.g. ``wifi_auth_repeat``."""
        return self.type.removeprefix(EVENT_PREFIX)

    @property
    def dedup_scope(self) -> tuple[str, str, str]:
        """Dedup scope as in the core: ``(router_id or "-", type, dedup_key)``."""
        return (self.router_id or "-", self.type, self.dedup_key or self.event_id)

    @property
    def incident_type(self) -> str:
        """NI incident type of this finding (``sec_<name>``, plan D-PREFIX)."""
        return INCIDENT_PREFIX + self.name

    def __repr__(self) -> str:
        """Identity-free representation (router id masked like any text)."""
        return (
            f"SecurityEvent(event_id={self.event_id!r}, type={self.type!r}, "
            f"router_id={mask_identities(self.router_id)!r}, "
            f"severity={self.severity.value!r}, "
            f"assessment={self.assessment.value!r}, count={self.count}, "
            f"has_client={self.client is not None}, "
            f"evidence={len(self.evidence)}, "
            f"linked_incident_ids={self.linked_incident_ids!r})"
        )

    def merged_with(self, other: SecurityEvent) -> SecurityEvent:
        """Duplicate merge (same dedup key): counts add, nothing is dropped.

        Earliest ``ts``, latest ``last_ts``, strongest severity/assessment
        (with that event's data source), union of evidence and links.
        """
        first, second = (self, other) if self.ts <= other.ts else (other, self)
        lead = max((first, second), key=lambda e: (e.assessment.rank, e.severity.rank))
        last = max(
            first.last_ts or first.ts,
            second.last_ts or second.ts,
        )
        return replace(
            first,
            severity=max(first.severity, second.severity, key=lambda s: s.rank),
            assessment=lead.assessment,
            data_source=lead.data_source,
            proof=lead.proof,
            evidence=_union(first.evidence, second.evidence, MAX_EVIDENCE),
            linked_incident_ids=_union(
                first.linked_incident_ids,
                second.linked_incident_ids,
                MAX_LINKED_INCIDENTS,
            ),
            confidence=max(first.confidence, second.confidence),
            count=first.count + second.count,
            last_ts=last,
            correlation_id=first.correlation_id or second.correlation_id,
        )

    def to_dict(self) -> dict[str, Any]:
        """Store form (lossless, unmasked): never log or publish it."""
        return {
            "v": SCHEMA_VERSION,
            "event_id": self.event_id,
            "ts": self.ts,
            "type": self.type,
            "router_id": self.router_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "result": self.result.value,
            "entry_id": self.entry_id,
            "correlation_id": self.correlation_id,
            "dedup_key": self.dedup_key,
            "data_source": self.data_source,
            "assessment": self.assessment.value,
            "client": self.client,
            "src": None if self.src is None else self.src.to_dict(),
            "dst": None if self.dst is None else self.dst.to_dict(),
            "evidence": list(self.evidence),
            "confidence": self.confidence,
            "proof": self.proof,
            "linked_incident_ids": list(self.linked_incident_ids),
            "count": self.count,
            "last_ts": self.last_ts,
            "actor": None if self.actor is None else self.actor.to_dict(),
        }

    def redacted(self) -> dict[str, Any]:
        """Diagnostics form: identities and secrets masked."""
        return mask_identities(self.to_dict())

    @classmethod
    def from_dict(cls, data: Any) -> SecurityEvent | None:
        """Lenient inverse of :meth:`to_dict`; None (never raises) if unusable.

        Unknown keys are ignored; optional values of a wrong type fall back
        to the defaults; a stored ``confirmed`` that does not meet the rule
        is downgraded to ``suspicious``; an actor that is not pseudonymous
        is dropped; an invalid router id makes the event unusable.
        """
        if not isinstance(data, Mapping) or any(k not in data for k in _REQUIRED):
            return None
        try:
            return cls(**_from_dict_kwargs(data))
        except (TypeError, ValueError) as err:
            _LOGGER.debug("Skipping stored security event: %s", type(err).__name__)
            return None

    def to_core_event(self, *, identity_key: bytes | None = None) -> CoreEvent:
        """The event as a core ``CoreEvent``; security fields go to ``data``.

        Typed core fields: ids, time, type, severity, result, router, entry,
        ``actor`` (pseudonymous), correlation, dedup, ``repeat_count``
        (``count - 1``) and ``last_repeat_at``. ``data`` carries ids,
        counters and masked evidence (the core has no typed fields for
        them). The client and endpoint addresses appear only as references
        made with the core digest (:func:`identity_digest` with
        ``identity_key``, e.g. the installation key); without a key they are
        left out.
        """
        payload: dict[str, Any] = {
            "schema": SCHEMA_VERSION,
            "category": self.category.value,
            "name": self.name,
            "incident_type": self.incident_type,
            "data_source": self.data_source,
            "assessment": self.assessment.value,
            "confidence": self.confidence,
            "proof": self.proof,
            "evidence": mask_identities(list(self.evidence)),
            "linked_incident_ids": list(self.linked_incident_ids),
            "src_zone": self.src.zone if self.src else None,
            "dst_zone": self.dst.zone if self.dst else None,
            "dst_port": self.dst.port if self.dst else None,
        }
        if identity_key is not None:
            ref = identity_digest(identity_key)
            payload["client_ref"] = _ref(ref, self.client)
            payload["src_ref"] = _ref(ref, self.src and self.src.addr)
            payload["dst_ref"] = _ref(ref, self.dst and self.dst.addr)
        return CoreEvent(
            event_id=self.event_id,
            ts=datetime.fromtimestamp(self.ts, UTC),
            type=self.type,
            source=MODULE_SOURCE,
            severity=self.severity,
            result=self.result,
            router_id=self.router_id,
            entry_id=self.entry_id,
            actor=self.actor,
            correlation_id=self.correlation_id,
            dedup_key=self.dedup_key,
            repeat_count=self.count - 1,
            last_repeat_at=(
                datetime.fromtimestamp(self.last_ts, UTC)
                if self.count > 1 and self.last_ts is not None
                else None
            ),
            data=payload,
        )


def _ref(digest: Callable[[str], str], value: str | None) -> str | None:
    return None if value is None else digest(value)


def _cap_evidence(items: Any) -> tuple[str, ...]:
    if isinstance(items, str) or not isinstance(items, Iterable):
        return ()
    out: list[str] = []
    for item in items:
        if len(out) >= MAX_EVIDENCE:
            break
        text = clean_text(item, MAX_EVIDENCE_LEN)
        if text:
            out.append(text)
    return tuple(out)


def _cap_links(items: Any) -> tuple[str, ...]:
    if isinstance(items, str) or not isinstance(items, Iterable):
        return ()
    out: list[str] = []
    for item in items:
        text = _opt_text(item) if isinstance(item, str) else None
        if text and text not in out:
            out.append(text)
        if len(out) >= MAX_LINKED_INCIDENTS:
            break
    return tuple(out)


def _union(a: tuple[str, ...], b: tuple[str, ...], cap: int) -> tuple[str, ...]:
    out = list(a)
    for item in b:
        if len(out) >= cap:
            break
        if item not in out:
            out.append(item)
    return tuple(out[:cap])


def _from_dict_kwargs(data: Mapping[str, Any]) -> dict[str, Any]:
    def text(key: str) -> str | None:
        value = data.get(key)
        return value if isinstance(value, str) else None

    def enum(cls: type[StrEnum], key: str, default: StrEnum) -> Any:
        try:
            return cls(data.get(key, default))
        except ValueError:
            return default

    assessment = enum(Assessment, "assessment", Assessment.NORMAL)
    source = text("data_source") or ""
    proof = data.get("proof") is True
    if assessment is Assessment.CONFIRMED and not can_confirm(source, proof):
        assessment = Assessment.SUSPICIOUS
    evidence = data.get("evidence")
    links = data.get("linked_incident_ids")
    count = data.get("count")
    return {
        "event_id": data["event_id"],
        "ts": data["ts"],
        "type": data["type"],
        "router_id": text("router_id"),
        "category": data["category"],
        "severity": enum(Severity, "severity", Severity.INFO),
        "result": enum(EventResult, "result", EventResult.INFO),
        "entry_id": text("entry_id"),
        "correlation_id": text("correlation_id"),
        "dedup_key": text("dedup_key"),
        "data_source": source,
        "assessment": assessment,
        "client": text("client"),
        "src": Endpoint.from_dict(data.get("src")),
        "dst": Endpoint.from_dict(data.get("dst")),
        "evidence": tuple(evidence) if isinstance(evidence, list) else (),
        "confidence": _finite(data.get("confidence")) or 0.0,
        "proof": proof,
        "linked_incident_ids": tuple(links) if isinstance(links, list) else (),
        "count": count if isinstance(count, int) and not isinstance(count, bool) else 1,
        "last_ts": _finite(data.get("last_ts")),
        "actor": _stored_actor(data.get("actor")),
    }


def _stored_actor(value: Any) -> Actor | None:
    """A stored pseudonymous actor; anything else is dropped (None)."""
    if value is None:
        return None
    try:
        actor = Actor.from_dict(value)
        _check_actor(actor)
    except (KeyError, TypeError, ValueError):
        return None
    return actor


# --- source status --------------------------------------------------------------

REASON_OK: Final = CapabilityReason.OK.value
REASON_NO_DATA: Final = CapabilityReason.NO_DATA_YET.value
REASON_DISABLED: Final = CapabilityReason.DISABLED.value
REASON_STALE: Final = "stale"
REASON_NOT_REPORTED: Final = "not_reported"


@dataclass(frozen=True, kw_only=True, slots=True)
class SourceStatus:
    """Availability of one data source; ``reason`` uses core reason codes."""

    source: str
    availability: Availability
    reason: str = REASON_OK
    last_ok: float | None = None

    @property
    def usable(self) -> bool:
        """True if a detector may treat silence of this source as "no finding"."""
        return self.availability is Availability.AVAILABLE

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "source": self.source,
            "availability": self.availability.value,
            "reason": self.reason,
            "last_ok": self.last_ok,
        }

    @classmethod
    def from_dict(cls, data: Any) -> SourceStatus | None:
        """Lenient inverse of :meth:`to_dict`."""
        if not isinstance(data, Mapping) or not isinstance(data.get("source"), str):
            return None
        try:
            availability = Availability(data.get("availability"))
        except ValueError:
            return None
        reason = data.get("reason")
        return cls(
            source=data["source"],
            availability=availability,
            reason=reason if isinstance(reason, str) else REASON_OK,
            last_ok=_finite(data.get("last_ok")),
        )


def source_status(
    source: str,
    *,
    now: float,
    last_ok: float | None,
    enabled: bool = True,
    stale_after_s: float = DEFAULT_STALE_AFTER_S,
) -> SourceStatus:
    """Status from the last successful delivery time of a source.

    Disabled → not_available/disabled; never delivered → not_available/
    no_data_yet; older than ``stale_after_s`` → stale; else available.
    """
    if not enabled:
        return SourceStatus(
            source=source,
            availability=Availability.NOT_AVAILABLE,
            reason=REASON_DISABLED,
            last_ok=last_ok,
        )
    if last_ok is None:
        return SourceStatus(
            source=source,
            availability=Availability.NOT_AVAILABLE,
            reason=REASON_NO_DATA,
        )
    if now - last_ok > stale_after_s:
        return SourceStatus(
            source=source,
            availability=Availability.STALE,
            reason=REASON_STALE,
            last_ok=last_ok,
        )
    return SourceStatus(
        source=source, availability=Availability.AVAILABLE, last_ok=last_ok
    )


def status_from_capability(
    capability: CapabilityStatus,
    *,
    now: float,
    last_ok: float | None,
    stale_after_s: float = DEFAULT_STALE_AFTER_S,
) -> SourceStatus:
    """Combine a core ``CapabilityStatus`` with the last delivery time.

    An available capability, and an ``unknown`` one with reason
    ``determined_on_first_use`` (contract 5: it may be used, the first use
    settles it; here the deliveries show it), is judged by ``last_ok`` like
    :func:`source_status`. Any other unavailable or unknown capability is
    ``not_available`` with the core reason.
    """
    first_use = (
        capability.state is CapabilityState.UNKNOWN
        and capability.reason == CapabilityReason.DETERMINED_ON_FIRST_USE
    )
    if not capability.available and not first_use:
        return SourceStatus(
            source=str(capability.capability),
            availability=Availability.NOT_AVAILABLE,
            reason=str(capability.reason),
            last_ok=last_ok,
        )
    return source_status(
        str(capability.capability),
        now=now,
        last_ok=last_ok,
        stale_after_s=stale_after_s,
    )


def missing_status(source: str) -> SourceStatus:
    """Status of a source the caller did not report: not available."""
    return SourceStatus(
        source=source,
        availability=Availability.NOT_AVAILABLE,
        reason=REASON_NOT_REPORTED,
    )


# --- forgotten routers ----------------------------------------------------------


class RouterStateHolder(Protocol):
    """Anything that keeps per-router state (detectors, dedup, liveness …)."""

    def forget_router(self, router_id: str) -> None:
        """Drop every piece of state of ``router_id``; others stay."""


def forgotten_router_id(event: CoreEvent) -> str | None:
    """Router id of a core ``router.forgotten`` event, else None."""
    if str(event.type) != CoreEventType.ROUTER_FORGOTTEN.value:
        return None
    return valid_router_id(event.router_id)


def forget_router(router_id: str, holders: Iterable[RouterStateHolder]) -> int:
    """Drop the state of a forgotten router from every holder.

    ValueError if ``router_id`` is no contract router id (prefix matches in
    the holders must not reach another router). Returns the number of
    holders asked. The trust book is fleet-wide and is no holder.
    """
    if valid_router_id(router_id) is None:
        raise ValueError("router_id must be a contract router id (rtr_...)")
    count = 0
    for holder in holders:
        holder.forget_router(router_id)
        count += 1
    _LOGGER.debug("Forgotten router: state dropped from %d holders", count)
    return count
