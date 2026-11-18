"""Targets for active network diagnostics: allowlist, validation, SSRF guard.

Pure module: standard library only, no Home Assistant imports, no name
resolution and no network I/O. Callers (a web API, a service, the scheduler)
only ever pass a target *ID*; ``TargetRegistry.resolve`` turns it into a
checked target or a typed ``Refusal``. An IP literal comes back as a usable
``PinnedTarget``; a hostname comes back as a ``PendingTarget`` that has no
connectable address until ``check_resolved`` vets what it resolved to and
returns a ``PinnedTarget``. There is no function that takes a free-form host
and hands it to a test without the same checks.

Rules in short:

* ``normalize_host`` accepts an IP literal or an RFC 1123 hostname and
  nothing else (no URLs, userinfo, ports, shell metacharacters, leading
  ``-``, non-ASCII or broken punycode, no numeric tricks like ``127.1`` or
  ``0x7f.1``). The result contains only ``[a-z0-9.:-]``, never starts with
  ``-`` and is safe as one argv element. Nothing here builds a command line.
* ``classify_ip`` uses explicit range tables (not ``ipaddress``' ``is_*``
  flags, whose meaning changed between Python releases) and looks through
  IPv4-mapped/compatible IPv6, NAT64, 6to4 and Teredo.
* External targets must be globally routable and confirmed by the user;
  internal targets must lie in a configured internal network. Loopback is
  never allowed; link-local and cloud metadata addresses only when exactly
  such a network is configured. Loopback and metadata *names* are refused in
  every scope; an internal hostname must be an internal name.
* ``check_resolved`` is the DNS-rebinding guard for addresses a hostname
  resolved to (the resolution itself happens elsewhere).
* ``may_query`` keeps internal names away from external resolvers.

Refusal reasons are an enum so an API can answer precisely; the offending
input is logged at debug level only.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from types import MappingProxyType
from typing import Any

_LOGGER = logging.getLogger(__name__)

type IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
type IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_TARGETS = 64
MAX_TARGETS_LIMIT = 256
MAX_INTERNAL_NETWORKS = 64
MAX_LOCAL_DOMAINS = 32
MAX_RESOLVED_ADDRESSES = 32
# Configured internal networks must be at least this specific.
MIN_INTERNAL_PREFIX_V4 = 8
MIN_INTERNAL_PREFIX_V6 = 8

_MAX_HOST_LEN = 253
_MAX_LABEL_LEN = 63
_ID_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_LABEL_RE = re.compile(r"[a-z0-9-]+")
_NUMERIC_LABEL_RE = re.compile(r"0x[0-9a-f]*|[0-9]+")
_PORT_SUFFIX_RE = re.compile(r"[^:]+:[0-9]*")
_HOST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-")
_IPV6_CHARS = frozenset("0123456789abcdef:.")
_URL_CHARS = frozenset("/@?#\\")

# Names that only make sense inside a home network (or must never reach
# public DNS at all, RFC 6761/6762/7686/8375).
_INTERNAL_SUFFIXES = (
    "lan",
    "local",
    "home.arpa",
    "internal",
    "localdomain",
    "fritz.box",
    "localhost",
    "home",
    "corp",
    "intranet",
    "private",
    "test",
    "invalid",
    "example",
    "onion",
    "alt",  # RFC 9476
    "box",  # router names such as fritz.box
    "ip",  # router names such as speedport.ip
)
# Hostnames that point at the machine itself, in every scope.
_LOOPBACK_LABELS = frozenset(
    {"localhost", "localhost6", "ip6-localhost", "ip6-loopback", "loopback"}
)
# Cloud metadata service names (metadata.google.internal, instance-data...).
_METADATA_LABELS = frozenset({"metadata", "instance-data"})


class TargetKind(StrEnum):
    """What kind of test a target is meant for."""

    ICMP = "icmp"
    DNS = "dns"
    TCP = "tcp"
    HTTP = "http"


class TargetScope(StrEnum):
    """Where a target (or a resolver) lives."""

    INTERNAL = "internal"
    EXTERNAL = "external"


class AddressClass(StrEnum):
    """Classification of one IP address."""

    GLOBAL = "global"
    LOOPBACK = "loopback"
    PRIVATE = "private"
    CGNAT = "cgnat"
    LINK_LOCAL = "link_local"
    METADATA = "metadata"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"
    DOCUMENTATION = "documentation"
    # IPv6 form that carries a global IPv4 address (mapped, NAT64, 6to4, …)
    TRANSLATED = "translated"


class Refusal(Enum):
    """Why a target, host, ID or resolved address was refused.

    Deliberately not a ``str`` subclass: a refusal can never be mistaken for a
    host by ``isinstance(result, str)``. Use ``.value`` for the reason code.
    """

    INVALID_ID = "invalid_id"
    UNKNOWN_TARGET = "unknown_target"
    INVALID_TARGET = "invalid_target"
    DUPLICATE_ID = "duplicate_id"
    REGISTRY_FULL = "registry_full"
    NOT_CONFIRMED = "not_confirmed"
    INVALID_KIND = "invalid_kind"
    INVALID_SCOPE = "invalid_scope"
    INVALID_PORT = "invalid_port"
    PORT_REQUIRED = "port_required"
    EMPTY_HOST = "empty_host"
    HOST_TOO_LONG = "host_too_long"
    NON_ASCII_HOST = "non_ascii_host"
    BAD_CHARACTER = "bad_character"
    URL_NOT_ALLOWED = "url_not_allowed"
    LEADING_DASH = "leading_dash"
    PORT_IN_HOST = "port_in_host"
    INVALID_IP = "invalid_ip"
    NUMERIC_HOST = "numeric_host"
    EMPTY_LABEL = "empty_label"
    LABEL_TOO_LONG = "label_too_long"
    BAD_LABEL = "bad_label"
    BAD_PUNYCODE = "bad_punycode"
    INTERNAL_NAME = "internal_name"
    NOT_INTERNAL_NAME = "not_internal_name"
    LOOPBACK = "loopback"
    LINK_LOCAL = "link_local"
    METADATA = "metadata"
    MULTICAST = "multicast"
    BROADCAST = "broadcast"
    UNSPECIFIED = "unspecified"
    RESERVED = "reserved"
    DOCUMENTATION = "documentation"
    TRANSLATED = "translated"
    NOT_GLOBAL = "not_global"
    NOT_INTERNAL_NETWORK = "not_internal_network"
    RESOLVED_EMPTY = "resolved_empty"
    RESOLVED_INVALID = "resolved_invalid"
    TOO_MANY_ADDRESSES = "too_many_addresses"


_CLASS_REFUSAL: Mapping[AddressClass, Refusal] = MappingProxyType(
    {
        AddressClass.LOOPBACK: Refusal.LOOPBACK,
        AddressClass.PRIVATE: Refusal.NOT_GLOBAL,
        AddressClass.CGNAT: Refusal.NOT_GLOBAL,
        AddressClass.LINK_LOCAL: Refusal.LINK_LOCAL,
        AddressClass.METADATA: Refusal.METADATA,
        AddressClass.MULTICAST: Refusal.MULTICAST,
        AddressClass.BROADCAST: Refusal.BROADCAST,
        AddressClass.UNSPECIFIED: Refusal.UNSPECIFIED,
        AddressClass.RESERVED: Refusal.RESERVED,
        AddressClass.DOCUMENTATION: Refusal.DOCUMENTATION,
        AddressClass.TRANSLATED: Refusal.TRANSLATED,
    }
)


def _nets(*cidrs: str) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(c) for c in cidrs)


# First match wins, so specific entries come before the ranges holding them.
_V4_TABLE: tuple[tuple[IPNetwork, AddressClass], ...] = tuple(
    (net, cls)
    for cls, nets in (
        (AddressClass.UNSPECIFIED, _nets("0.0.0.0/32")),
        (AddressClass.RESERVED, _nets("0.0.0.0/8")),
        (AddressClass.LOOPBACK, _nets("127.0.0.0/8")),
        (AddressClass.PRIVATE, _nets("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")),
        (AddressClass.METADATA, _nets("169.254.169.254/32", "100.100.100.200/32")),
        (AddressClass.CGNAT, _nets("100.64.0.0/10")),
        (AddressClass.LINK_LOCAL, _nets("169.254.0.0/16")),
        (AddressClass.RESERVED, _nets("192.0.0.0/24")),
        (
            AddressClass.DOCUMENTATION,
            _nets("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"),
        ),
        (AddressClass.RESERVED, _nets("192.88.99.0/24", "198.18.0.0/15")),
        (AddressClass.MULTICAST, _nets("224.0.0.0/4")),
        (AddressClass.BROADCAST, _nets("255.255.255.255/32")),
        (AddressClass.RESERVED, _nets("240.0.0.0/4")),
    )
    for net in nets
)

_V6_UNSPECIFIED = ipaddress.ip_network("::/128")
_V6_LOOPBACK = ipaddress.ip_network("::1/128")
_V6_MAPPED = ipaddress.ip_network("::ffff:0:0/96")
_V6_COMPAT = ipaddress.ip_network("::/96")
_V6_NAT64 = _nets("64:ff9b::/96", "64:ff9b:1::/48")
_V6_TEREDO = ipaddress.ip_network("2001::/32")
_V6_6TO4 = ipaddress.ip_network("2002::/16")
_V6_GLOBAL_UNICAST = ipaddress.ip_network("2000::/3")

_V6_TABLE: tuple[tuple[IPNetwork, AddressClass], ...] = tuple(
    (net, cls)
    for cls, nets in (
        (
            AddressClass.RESERVED,
            _nets("100::/64", "2001::/23", "5f00::/16", "fec0::/10"),
        ),
        (AddressClass.DOCUMENTATION, _nets("2001:db8::/32", "3fff::/20")),
        (AddressClass.METADATA, _nets("fd00:ec2::254/128")),
        (AddressClass.PRIVATE, _nets("fc00::/7")),
        (AddressClass.LINK_LOCAL, _nets("fe80::/10")),
        (AddressClass.MULTICAST, _nets("ff00::/8")),
    )
    for net in nets
)

# Everything in these ranges counts as "not plain global" for reverse zones.
_V6_EMBEDDING = (
    _V6_UNSPECIFIED,
    _V6_LOOPBACK,
    _V6_MAPPED,
    _V6_COMPAT,
    _V6_TEREDO,
    _V6_6TO4,
)
_V6_EMBEDDING += _V6_NAT64


# --- host syntax ----------------------------------------------------------------


def normalize_host(raw: Any) -> str | Refusal:
    """Return the canonical host (IP literal or lower-case hostname) or a refusal.

    Never resolves anything. Hostnames must already be ASCII (punycode for
    IDNs); a trailing dot is refused.
    """
    if not isinstance(raw, str) or not raw:
        return Refusal.EMPTY_HOST
    if len(raw) > _MAX_HOST_LEN:
        return Refusal.HOST_TOO_LONG
    if not raw.isascii():
        return Refusal.NON_ASCII_HOST
    if any(ch.isspace() or not ch.isprintable() for ch in raw):
        return Refusal.BAD_CHARACTER
    if _URL_CHARS.intersection(raw):
        return Refusal.URL_NOT_ALLOWED
    if raw.startswith("-"):
        return Refusal.LEADING_DASH
    host = raw.lower()
    if ":" in host or "[" in host:
        return _normalize_ipv6(host)
    if not _HOST_CHARS.issuperset(host):
        return Refusal.BAD_CHARACTER
    if all(ch.isdigit() or ch == "." for ch in host):
        return _normalize_ipv4(host)
    return _check_hostname(host)


def _normalize_ipv6(host: str) -> str | Refusal:
    if "[" in host or "]" in host or _PORT_SUFFIX_RE.fullmatch(host):
        return Refusal.PORT_IN_HOST
    if not _IPV6_CHARS.issuperset(host):
        return Refusal.BAD_CHARACTER
    try:
        return ipaddress.IPv6Address(host).compressed
    except ValueError:
        return Refusal.INVALID_IP


def _normalize_ipv4(host: str) -> str | Refusal:
    """Strict dotted quad only: refuses ``127.1``, ``2130706433``, ``0177.0.0.1``."""
    parts = host.split(".")
    if len(parts) != 4:
        return Refusal.NUMERIC_HOST
    for part in parts:
        if not part or (len(part) > 1 and part.startswith("0")) or int(part) > 255:
            return Refusal.NUMERIC_HOST
    return str(ipaddress.IPv4Address(host))


def _check_hostname(host: str) -> str | Refusal:
    labels = host.split(".")
    for label in labels:
        refused = _check_label(label)
        if refused is not None:
            return refused
    # inet_aton() would read "0x7f.1" or "foo.123"-like names as numbers
    if all(_NUMERIC_LABEL_RE.fullmatch(lbl) for lbl in labels):
        return Refusal.NUMERIC_HOST
    if _NUMERIC_LABEL_RE.fullmatch(labels[-1]):
        return Refusal.NUMERIC_HOST
    return host


def _check_label(label: str) -> Refusal | None:
    if not label:
        return Refusal.EMPTY_LABEL
    if len(label) > _MAX_LABEL_LEN:
        return Refusal.LABEL_TOO_LONG
    if not _LABEL_RE.fullmatch(label) or label[0] == "-" or label[-1] == "-":
        return Refusal.BAD_LABEL
    if label[2:4] == "--":
        if not label.startswith("xn--"):
            return Refusal.BAD_LABEL
        if not _punycode_ok(label[4:]):
            return Refusal.BAD_PUNYCODE
    return None


def _punycode_ok(encoded: str) -> bool:
    """True for canonical punycode that decodes to printable non-ASCII text."""
    try:
        decoded = encoded.encode("ascii").decode("punycode")
        again = decoded.encode("punycode").decode("ascii")
    except UnicodeError:
        return False
    if not decoded or decoded.isascii() or again != encoded:
        return False
    return all(ch.isprintable() and not ch.isspace() and ch != "." for ch in decoded)


def _as_ip(host: str) -> IPAddress | None:
    """IP object for an already normalised host, else None."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


# --- IP classification ------------------------------------------------------------


def classify_ip(addr: IPAddress) -> AddressClass:
    """Classify one address; IPv6 forms embedding IPv4 are looked through."""
    if isinstance(addr, ipaddress.IPv4Address):
        return _lookup(addr, _V4_TABLE, AddressClass.GLOBAL)
    if addr in _V6_UNSPECIFIED:
        return AddressClass.UNSPECIFIED
    if addr in _V6_LOOPBACK:
        return AddressClass.LOOPBACK
    embedded = _embedded_v4(addr)
    if embedded is not None:
        return _worst_of(embedded)
    fallback = (
        AddressClass.GLOBAL if addr in _V6_GLOBAL_UNICAST else AddressClass.RESERVED
    )
    return _lookup(addr, _V6_TABLE, fallback)


def _lookup(
    addr: IPAddress,
    table: tuple[tuple[IPNetwork, AddressClass], ...],
    fallback: AddressClass,
) -> AddressClass:
    for net, cls in table:
        if addr in net:
            return cls
    return fallback


def _embedded_v4(
    addr: ipaddress.IPv6Address,
) -> tuple[ipaddress.IPv4Address, ...] | None:
    """IPv4 addresses carried inside an IPv6 address, or None."""
    low32 = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
    if addr in _V6_MAPPED or addr in _V6_COMPAT:
        return (low32,)
    if any(addr in net for net in _V6_NAT64):
        return (low32,)
    if addr in _V6_TEREDO and addr.teredo is not None:
        return addr.teredo
    if addr in _V6_6TO4 and addr.sixtofour is not None:
        return (addr.sixtofour,)
    return None


def _worst_of(embedded: tuple[ipaddress.IPv4Address, ...]) -> AddressClass:
    for v4 in embedded:
        cls = classify_ip(v4)
        if cls is not AddressClass.GLOBAL:
            return cls
    return AddressClass.TRANSLATED


# --- policy and scope rules --------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    """Configured internal networks and local DNS domains (server-side only)."""

    internal_networks: tuple[IPNetwork, ...] = ()
    local_domains: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Refuse networks that would weaken the scope rules."""
        if len(self.internal_networks) > MAX_INTERNAL_NETWORKS:
            raise ValueError("too many internal networks")
        if len(self.local_domains) > MAX_LOCAL_DOMAINS:
            raise ValueError("too many local domains")
        for net in self.internal_networks:
            _validate_internal_network(net)
        for domain in self.local_domains:
            if normalize_host(domain) != domain or _as_ip(domain) is not None:
                raise ValueError("invalid local domain")

    @classmethod
    def from_config(
        cls, networks: Iterable[str], local_domains: Iterable[str] = ()
    ) -> ScopePolicy:
        """Build from CIDR strings and domain names; raises ValueError."""
        nets = tuple(ipaddress.ip_network(n, strict=True) for n in networks)
        domains = tuple(d.lower() if isinstance(d, str) else d for d in local_domains)
        return cls(nets, domains)


def _validate_internal_network(net: IPNetwork) -> None:
    if not isinstance(net, ipaddress.IPv4Network | ipaddress.IPv6Network):
        raise TypeError("internal network must be an ip_network")
    minimum = MIN_INTERNAL_PREFIX_V4 if net.version == 4 else MIN_INTERNAL_PREFIX_V6
    if net.prefixlen < minimum:
        raise ValueError("internal network too broad")
    loopback = ipaddress.ip_network("127.0.0.0/8" if net.version == 4 else "::1/128")
    if net.overlaps(loopback):  # type: ignore[arg-type]
        raise ValueError("loopback can never be an internal network")


_LINK_LOCAL_RANGES = _nets("169.254.0.0/16", "fe80::/10")


def check_address(
    addr: IPAddress, scope: TargetScope, policy: ScopePolicy
) -> Refusal | None:
    """Scope rule for one address: None when allowed, else the reason."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id:
        return Refusal.RESOLVED_INVALID
    cls = classify_ip(addr)
    if cls is AddressClass.LOOPBACK:
        return Refusal.LOOPBACK
    if scope is TargetScope.EXTERNAL:
        return None if cls is AddressClass.GLOBAL else _CLASS_REFUSAL[cls]
    nets = policy.internal_networks
    if cls is AddressClass.METADATA:
        exact = any(net.num_addresses == 1 and addr in net for net in nets)
        return None if exact else Refusal.METADATA
    if cls is AddressClass.LINK_LOCAL:
        return None if _in_link_local_network(addr, nets) else Refusal.LINK_LOCAL
    if cls not in (AddressClass.PRIVATE, AddressClass.CGNAT, AddressClass.GLOBAL):
        return _CLASS_REFUSAL[cls]
    if not any(addr in net for net in nets):
        return Refusal.NOT_INTERNAL_NETWORK
    return None


def _in_link_local_network(addr: IPAddress, nets: tuple[IPNetwork, ...]) -> bool:
    """True when a configured network holding ``addr`` is itself link-local."""
    for net in nets:
        if addr not in net:
            continue
        if any(
            net.version == ll.version and net.subnet_of(ll)  # type: ignore[arg-type]
            for ll in _LINK_LOCAL_RANGES
        ):
            return True
    return False


# --- hostname classification ---------------------------------------------------------


def is_internal_name(name: Any, local_domains: Iterable[str] = ()) -> bool:
    """True if ``name`` must stay inside the home network.

    Invalid names and non-global IP literals count as internal (fail closed).
    """
    host = normalize_host(name)
    if isinstance(host, Refusal):
        return True
    addr = _as_ip(host)
    if addr is not None:
        return classify_ip(addr) is not AddressClass.GLOBAL
    if "." not in host:
        return True
    reverse = _reverse_zone_internal(host)
    if reverse is not None:
        return reverse
    for suffix in (*_INTERNAL_SUFFIXES, *local_domains):
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def may_query(
    name: Any, resolver_scope: TargetScope, *, local_domains: Iterable[str] = ()
) -> bool:
    """True if a DNS test may ask a resolver of ``resolver_scope`` for ``name``.

    Internal names never go to an external resolver. IP literals and invalid
    names are never queried.
    """
    host = normalize_host(name)
    if isinstance(host, Refusal) or _as_ip(host) is not None:
        return False
    if resolver_scope is TargetScope.INTERNAL:
        return True
    return not is_internal_name(host, local_domains)


def _reverse_zone_internal(host: str) -> bool | None:
    """None if ``host`` is no reverse name, else whether its zone is internal."""
    for suffix, version in (("in-addr.arpa", 4), ("ip6.arpa", 6)):
        if host == suffix:
            return True
        if host.endswith("." + suffix):
            net = _reverse_network(host[: -len(suffix) - 1].split("."), version)
            return True if net is None else _overlaps_non_global(net)
    return None


def _reverse_network(labels: list[str], version: int) -> IPNetwork | None:
    """Network named by reverse-zone labels; None when malformed."""
    parts = list(reversed(labels))
    if version == 4:
        if len(parts) > 4 or not all(p.isdigit() and int(p) <= 255 for p in parts):
            return None
        octets = [int(p) for p in parts] + [0] * (4 - len(parts))
        packed = int.from_bytes(bytes(octets), "big")
        return ipaddress.IPv4Network((packed, 8 * len(parts)))
    hexdigits = "0123456789abcdef"
    if len(parts) > 32 or not all(len(p) == 1 and p in hexdigits for p in parts):
        return None
    value = int("".join(parts).ljust(32, "0"), 16)
    return ipaddress.IPv6Network((value, 4 * len(parts)))


def _overlaps_non_global(net: IPNetwork) -> bool:
    if isinstance(net, ipaddress.IPv4Network):
        return any(net.overlaps(rng) for rng, _cls in _V4_TABLE)  # type: ignore[arg-type]
    if not net.subnet_of(_V6_GLOBAL_UNICAST):
        return True
    ranges = (*(rng for rng, _cls in _V6_TABLE), *_V6_EMBEDDING)
    return any(net.overlaps(rng) for rng in ranges)  # type: ignore[arg-type]


# --- targets ------------------------------------------------------------------------


def _port_refusal(kind: TargetKind, port: Any) -> Refusal | None:
    if port is None:
        return Refusal.PORT_REQUIRED if kind is TargetKind.TCP else None
    if kind is TargetKind.ICMP:
        return Refusal.INVALID_PORT
    if type(port) is not int or not 1 <= port <= 65535:
        return Refusal.INVALID_PORT
    return None


@dataclass(frozen=True, slots=True)
class DiagTarget:
    """One allowlisted target. Construction refuses anything not normalised.

    ``host`` is always the output of ``normalize_host`` and can be passed as a
    single argv element. Scope rules are checked by ``check_target``.
    """

    target_id: str
    kind: TargetKind
    scope: TargetScope
    host: str
    port: int | None = None
    confirmed: bool = False
    _ip: IPAddress | None = field(init=False, repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        """Raise ValueError (with the reason code, never the input)."""
        reason = _field_refusal(
            self.target_id, self.kind, self.scope, self.host, self.port, self.confirmed
        )
        if reason is None and normalize_host(self.host) != self.host:
            reason = Refusal.BAD_CHARACTER
        if reason is not None:
            raise ValueError(f"invalid diagnostic target ({reason.value})")
        object.__setattr__(self, "_ip", _as_ip(self.host))

    @property
    def is_ip(self) -> bool:
        """True if ``host`` is an IP literal (no resolution needed)."""
        return self._ip is not None

    @property
    def ip(self) -> IPAddress | None:
        """The host as an IP object, or None for hostnames."""
        return self._ip


def _field_refusal(
    target_id: Any, kind: Any, scope: Any, host: Any, port: Any, confirmed: Any
) -> Refusal | None:
    if not isinstance(target_id, str) or not _ID_RE.fullmatch(target_id):
        return Refusal.INVALID_ID
    if not isinstance(kind, TargetKind):
        return Refusal.INVALID_KIND
    if not isinstance(scope, TargetScope):
        return Refusal.INVALID_SCOPE
    if not isinstance(confirmed, bool):
        return Refusal.INVALID_TARGET
    host_norm = normalize_host(host)
    if isinstance(host_norm, Refusal):
        return host_norm
    return _port_refusal(kind, port)


def make_target(
    target_id: Any,
    kind: Any,
    scope: Any,
    host: Any,
    *,
    port: Any = None,
    confirmed: bool = False,
) -> DiagTarget | Refusal:
    """Build a ``DiagTarget`` from configuration values, or say why not.

    Only syntax is checked here; scope rules need a policy (``check_target``).
    """
    if not isinstance(target_id, str) or not _ID_RE.fullmatch(target_id):
        return Refusal.INVALID_ID
    try:
        kind_enum = TargetKind(kind)
    except ValueError:
        return Refusal.INVALID_KIND
    try:
        scope_enum = TargetScope(scope)
    except ValueError:
        return Refusal.INVALID_SCOPE
    host_norm = normalize_host(host)
    if isinstance(host_norm, Refusal):
        _LOGGER.debug("Refused host %r: %s", host, host_norm.value)
        return host_norm
    reason = _field_refusal(
        target_id, kind_enum, scope_enum, host_norm, port, confirmed
    )
    if reason is not None:
        return reason
    return DiagTarget(target_id, kind_enum, scope_enum, host_norm, port, confirmed)


def check_target(target: DiagTarget, policy: ScopePolicy) -> Refusal | None:
    """Scope rules for a target (confirmation is checked by the registry).

    Hostnames: loopback and metadata names are refused in every scope; an
    external target must not have an internal name, an internal target must.
    """
    if target.ip is not None:
        return check_address(target.ip, target.scope, policy)
    reason = _name_refusal(target.host)
    if reason is not None:
        return reason
    internal = is_internal_name(target.host, policy.local_domains)
    if target.scope is TargetScope.EXTERNAL and internal:
        return Refusal.INTERNAL_NAME
    if target.scope is TargetScope.INTERNAL and not internal:
        return Refusal.NOT_INTERNAL_NAME
    return None


def _name_refusal(host: str) -> Refusal | None:
    """Refusal for loopback and cloud-metadata hostnames, else None."""
    first = host.split(".", 1)[0]
    if first in _LOOPBACK_LABELS or host.endswith(".localhost"):
        return Refusal.LOOPBACK
    if first in _METADATA_LABELS or host == "metadata.goog":
        return Refusal.METADATA
    return None


_ISSUER = object()


@dataclass(frozen=True, slots=True)
class PendingTarget:
    """A hostname target that is NOT usable yet.

    Resolve ``name`` with a resolver of ``resolver_scope`` (see ``may_query``),
    then pass the addresses to ``check_resolved``; only the ``PinnedTarget`` it
    returns may be connected to. There is deliberately no ``host`` or
    ``address`` attribute. Issued by ``TargetRegistry.resolve`` only.
    """

    target: DiagTarget
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Refuse construction outside this module."""
        if self._issuer is not _ISSUER or not isinstance(self.target, DiagTarget):
            raise TypeError("PendingTarget is issued by TargetRegistry.resolve only")
        if self.target.is_ip:
            raise TypeError("IP literal targets are pinned directly")

    @property
    def needs_resolution(self) -> bool:
        """Always True: resolve and vet before use."""
        return True

    @property
    def name(self) -> str:
        """The hostname to resolve (never to hand to a tool that resolves it)."""
        return self.target.host

    @property
    def resolver_scope(self) -> TargetScope:
        """Which resolver may be asked: an internal target needs an internal one."""
        return self.target.scope

    @property
    def target_id(self) -> str:
        """ID of the underlying target."""
        return self.target.target_id


@dataclass(frozen=True, slots=True)
class PinnedTarget:
    """A target bound to one vetted IP address: the only usable form.

    Tests connect to ``host`` (the address as an argv-safe string), never to
    the original name; ``server_name`` is only for an HTTP Host header or TLS
    SNI. Issued by ``TargetRegistry.resolve`` (IP literals) and
    ``check_resolved`` (hostnames) only.
    """

    target: DiagTarget
    address: IPAddress
    _issuer: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Refuse construction outside this module."""
        if self._issuer is not _ISSUER or not isinstance(self.target, DiagTarget):
            raise TypeError("PinnedTarget is issued by TargetRegistry only")
        if not isinstance(self.address, ipaddress.IPv4Address | ipaddress.IPv6Address):
            raise TypeError("address must be an ipaddress object")

    @property
    def needs_resolution(self) -> bool:
        """Always False: ready to use."""
        return False

    @property
    def host(self) -> str:
        """The vetted address as one argv-safe string."""
        return str(self.address)

    @property
    def server_name(self) -> str | None:
        """Original hostname for Host/SNI, None for IP literal targets."""
        return None if self.target.is_ip else self.target.host

    @property
    def target_id(self) -> str:
        """ID of the underlying target."""
        return self.target.target_id

    @property
    def kind(self) -> TargetKind:
        """Test kind of the underlying target."""
        return self.target.kind

    @property
    def scope(self) -> TargetScope:
        """Scope of the underlying target."""
        return self.target.scope

    @property
    def port(self) -> int | None:
        """Port of the underlying target."""
        return self.target.port


def check_resolved(
    pending: PendingTarget, addresses: Iterable[Any], policy: ScopePolicy
) -> PinnedTarget | Refusal:
    """DNS-rebinding guard: pin a pending target to a vetted address.

    Every resolved address must satisfy the scope rule; the first one is
    pinned. ``addresses`` are strings or ``ipaddress`` objects produced by a
    resolver elsewhere; this function performs no resolution. Only a
    ``PendingTarget`` (from ``TargetRegistry.resolve``) is accepted.
    """
    if not isinstance(pending, PendingTarget):
        return Refusal.INVALID_TARGET
    target = pending.target
    reason = check_target(target, policy)
    if reason is not None:
        return reason
    vetted = _vet_addresses(target, addresses, policy)
    if isinstance(vetted, Refusal):
        return vetted
    return PinnedTarget(target, vetted, _ISSUER)


def _vet_addresses(
    target: DiagTarget, addresses: Iterable[Any], policy: ScopePolicy
) -> IPAddress | Refusal:
    """First address if every address passes the scope rule, else the refusal."""
    items = []
    for item in addresses:
        items.append(item)
        if len(items) > MAX_RESOLVED_ADDRESSES:
            return Refusal.TOO_MANY_ADDRESSES
    if not items:
        return Refusal.RESOLVED_EMPTY
    vetted: list[IPAddress] = []
    for item in items:
        addr = _parse_resolved(item)
        if addr is None:
            _LOGGER.debug("Unusable resolved address for %s", target.target_id)
            return Refusal.RESOLVED_INVALID
        reason = check_address(addr, target.scope, policy)
        if reason is not None:
            _LOGGER.debug(
                "Resolved address %s refused for %s: %s",
                addr,
                target.target_id,
                reason.value,
            )
            return reason
        vetted.append(addr)
    return vetted[0]


def _parse_resolved(item: Any) -> IPAddress | None:
    if isinstance(item, ipaddress.IPv4Address | ipaddress.IPv6Address):
        addr: IPAddress = item
    elif isinstance(item, str) and item.isascii() and "%" not in item:
        try:
            addr = ipaddress.ip_address(item)
        except ValueError:
            return None
    else:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.scope_id:
        return None
    return addr


# --- registry -------------------------------------------------------------------------


class TargetRegistry:
    """Immutable, bounded allowlist of targets, looked up by ID only.

    ``with_target`` / ``without_target`` / ``with_policy`` return new
    registries; the original never changes.
    """

    __slots__ = ("_max", "_policy", "_targets")

    def __init__(self, policy: ScopePolicy, *, max_targets: int = MAX_TARGETS) -> None:
        """Create an empty registry; add targets with ``with_target``/``build``."""
        if type(max_targets) is not int or not 1 <= max_targets <= MAX_TARGETS_LIMIT:
            raise ValueError("max_targets out of range")
        if not isinstance(policy, ScopePolicy):
            raise TypeError("policy must be a ScopePolicy")
        self._policy = policy
        self._max = max_targets
        self._targets: Mapping[str, DiagTarget] = MappingProxyType({})

    def _derive(
        self, policy: ScopePolicy, targets: Mapping[str, DiagTarget]
    ) -> TargetRegistry:
        """Validated copy with other contents (the only way to fill a registry)."""
        if not isinstance(policy, ScopePolicy):
            raise TypeError("policy must be a ScopePolicy")
        if len(targets) > self._max:
            raise ValueError("too many targets")
        for key, target in targets.items():
            if not isinstance(target, DiagTarget) or key != target.target_id:
                raise ValueError("target table inconsistent")
        clone = object.__new__(TargetRegistry)
        clone._policy = policy
        clone._max = self._max
        clone._targets = MappingProxyType(dict(targets))
        return clone

    @classmethod
    def build(
        cls,
        policy: ScopePolicy,
        targets: Iterable[DiagTarget],
        *,
        max_targets: int = MAX_TARGETS,
    ) -> tuple[TargetRegistry, list[tuple[str, Refusal]]]:
        """Registry from configured targets plus the (id, reason) of refused ones."""
        registry = cls(policy, max_targets=max_targets)
        refused: list[tuple[str, Refusal]] = []
        for target in targets:
            result = registry.with_target(target)
            if isinstance(result, Refusal):
                target_id = target.target_id if isinstance(target, DiagTarget) else "?"
                refused.append((target_id, result))
            else:
                registry = result
        return registry, refused

    @property
    def policy(self) -> ScopePolicy:
        """The scope policy all targets are checked against."""
        return self._policy

    @property
    def ids(self) -> tuple[str, ...]:
        """Sorted target IDs."""
        return tuple(sorted(self._targets))

    def __len__(self) -> int:
        """Number of stored targets."""
        return len(self._targets)

    def entries(self) -> tuple[DiagTarget, ...]:
        """All stored targets for display; use ``resolve`` before testing one."""
        return tuple(self._targets[tid] for tid in self.ids)

    def with_target(self, target: DiagTarget) -> TargetRegistry | Refusal:
        """New registry with ``target`` added, or the refusal reason."""
        if not isinstance(target, DiagTarget):
            return Refusal.INVALID_TARGET
        if target.target_id in self._targets:
            return Refusal.DUPLICATE_ID
        if len(self._targets) >= self._max:
            return Refusal.REGISTRY_FULL
        reason = check_target(target, self._policy)
        if reason is not None:
            _LOGGER.debug("Target %s refused: %s", target.target_id, reason.value)
            return reason
        return self._derive(self._policy, {**self._targets, target.target_id: target})

    def without_target(self, target_id: str) -> TargetRegistry:
        """New registry without ``target_id`` (unchanged copy if absent)."""
        kept = {k: v for k, v in self._targets.items() if k != target_id}
        return self._derive(self._policy, kept)

    def with_policy(self, policy: ScopePolicy) -> TargetRegistry:
        """Same targets under a new policy; ``resolve`` re-checks each one."""
        return self._derive(policy, self._targets)

    def resolve(self, target_id: Any) -> PinnedTarget | PendingTarget | Refusal:
        """API entry point: target ID -> checked target or refusal.

        IP literal targets come back pinned (usable). Hostname targets come
        back as ``PendingTarget``: resolve the name, then ``check_resolved``.
        """
        if not isinstance(target_id, str) or not _ID_RE.fullmatch(target_id):
            _LOGGER.debug("Refused malformed target id %r", target_id)
            return Refusal.INVALID_ID
        target = self._targets.get(target_id)
        if target is None:
            return Refusal.UNKNOWN_TARGET
        if target.scope is TargetScope.EXTERNAL and not target.confirmed:
            return Refusal.NOT_CONFIRMED
        reason = check_target(target, self._policy)
        if reason is not None:
            return reason
        if target.ip is not None:
            return PinnedTarget(target, target.ip, _ISSUER)
        return PendingTarget(target, _ISSUER)

    def check_resolved(
        self, pending: PendingTarget, addresses: Iterable[Any]
    ) -> PinnedTarget | Refusal:
        """DNS-rebinding guard under this registry's policy."""
        return check_resolved(pending, addresses, self._policy)

    def may_query(self, name: Any, resolver_scope: TargetScope) -> bool:
        """``may_query`` with this registry's local domains."""
        return may_query(name, resolver_scope, local_domains=self._policy.local_domains)
