"""Structured diff of UCI snapshots and drift evaluation.

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.6, 14.1 and 23.

``diff_snapshots`` compares two normalized snapshots
(``config_snapshot.UciSnapshot``) section by section and option by option
and classifies every change by area and risk. ``evaluate_drift`` turns the
diff against a baseline into a report and applies the user's drift
acknowledgements. Nothing here resets, stores or sends anything.

Matching of sections:

- named sections and anonymous sections with identity fields
  (``@rule{"name":"Allow-Ping"}``) by their key,
- anonymous sections without identity (``@rule[n]``) per type by aligning
  their contents in ``order`` (a deleted rule in the middle is one removal,
  not a cascade of changes),
- remaining removed/added anonymous sections of the same type by content
  similarity and position, so a changed identity field (an SSID that is part
  of the key, a rule that gains a name) is one changed section, not
  "removed + added".

Secrets are digest markers ``{"secret": "<hmac16>"}`` in the snapshot and
stay markers in ``Change.old``/``Change.new``; the plaintext never exists
here. The digest is bound to the section key (config_snapshot), so for a
section whose key changed a secret cannot be compared: such changes carry
``detail = DETAIL_SECRET_UNVERIFIABLE``.

Pure module: no Home Assistant imports, no network, no files, never logs
values.
"""

from __future__ import annotations

import difflib
import hashlib
import ipaddress
import logging
import re
from bisect import bisect_left
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final, Literal

from .config_const import (
    AREA_DHCP,
    AREA_DNS,
    AREA_FIREWALL,
    AREA_INTERFACE,
    AREA_MGMT_IP,
    AREA_OTHER,
    AREA_ROUTING,
    AREA_SERVICES,
    AREA_SSH,
    AREA_SYSTEM,
    AREA_VLAN,
    AREA_WLAN,
    FIREWALL_INPUT_SECTION_TYPES,
    MGMT_IP_OPTIONS,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RISK_REORDERED,
    RISKS,
    SECRET_MARKER_KEY,
    SSH_PORTS,
    UPLINK_INTERFACE_NAMES,
    lookup_risk_rule,
)
from .config_mask import is_secret_option
from .config_snapshot import (
    ANON_PREFIX,
    NORM_OPTIONS,
    NORM_ORDER,
    NORM_SECTIONS,
    NORM_TYPE,
    SECTION_IDENTITY_FIELDS,
    UciSnapshot,
    canonical_json,
)
from .const import WAN_PROTOS

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "ACK_ACKNOWLEDGED",
    "ACK_KNOWN",
    "DETAIL_SECRET_CHANGED",
    "DETAIL_SECRET_UNVERIFIABLE",
    "DRIFT_ACKNOWLEDGED",
    "DRIFT_KNOWN",
    "DRIFT_NEW",
    "DRIFT_NONE",
    "Area",
    "Change",
    "DriftAck",
    "DriftReport",
    "Risk",
    "classify",
    "diff_snapshots",
    "drift_id",
    "evaluate_drift",
    "max_risk",
    "not_comparable",
]


class Area(StrEnum):
    """Configuration area of a change (values = config_const.AREA_*)."""

    VLAN = AREA_VLAN
    INTERFACE = AREA_INTERFACE
    MGMT_IP = AREA_MGMT_IP
    FIREWALL = AREA_FIREWALL
    DHCP = AREA_DHCP
    DNS = AREA_DNS
    WLAN = AREA_WLAN
    ROUTING = AREA_ROUTING
    SERVICES = AREA_SERVICES
    SSH = AREA_SSH
    SYSTEM = AREA_SYSTEM
    OTHER = AREA_OTHER


class Risk(StrEnum):
    """Risk of a change, highest first (values = config_const.RISK_*)."""

    CRITICAL = RISK_CRITICAL
    HIGH = RISK_HIGH
    MEDIUM = RISK_MEDIUM
    LOW = RISK_LOW


ChangeKind = Literal["added", "removed", "changed", "reordered"]
KIND_ADDED: Final = "added"
KIND_REMOVED: Final = "removed"
KIND_CHANGED: Final = "changed"
KIND_REORDERED: Final = "reordered"

# Change.detail values.
DETAIL_SECRET_CHANGED: Final = "secret_changed"
DETAIL_SECRET_UNVERIFIABLE: Final = "secret_unverifiable"

AckState = Literal["acknowledged", "known"]
ACK_ACKNOWLEDGED: Final = "acknowledged"
ACK_KNOWN: Final = "known"
_ACK_STATES: Final = frozenset({ACK_ACKNOWLEDGED, ACK_KNOWN})

DriftState = Literal["none", "new", "acknowledged", "known"]
DRIFT_NONE: Final = "none"
DRIFT_NEW: Final = "new"
DRIFT_ACKNOWLEDGED: Final = "acknowledged"
DRIFT_KNOWN: Final = "known"

# Section types whose order decides behaviour (first matching rule wins).
_ORDER_SENSITIVE: Final[frozenset[tuple[str, str]]] = frozenset(
    {("firewall", "rule"), ("firewall", "redirect"), ("firewall", "nat")}
)
# Options naming the ports a firewall rule/redirect matches.
_PORT_OPTIONS: Final = ("dest_port", "src_dport", "port")
_ADDRESS_OPTIONS: Final = ("ipaddr", "ip6addr")
_SSH_PORT_NUMBERS: Final[frozenset[int]] = frozenset(int(p) for p in SSH_PORTS)
_SSH_SERVICE_NAMES: Final = frozenset({"ssh"})
# Pairing threshold: share of comparable options that must be equal.
_PAIR_MIN_SIMILARITY: Final = 0.5
_SECRET_PLACEHOLDER: Final = "<secret>"
_DRIFT_ID_SCHEME: Final = 1
_FALLBACK_KEY_RE: Final = re.compile(r"@[A-Za-z0-9_\-]+\[\d+\]")
_RISK_RANK: Final = {risk: rank for rank, risk in enumerate(RISKS)}

# ---------------------------------------------------------------------------
# Result objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Change:
    """One difference between two snapshots.

    ``option`` is None for a whole section (added, removed, reordered). For
    a section, ``old``/``new`` hold ``{"type", "options"}``; for a reordered
    section the positions in ``order``; for an option its value. Values are
    taken from the snapshot, so secrets are digest markers, never plaintext.
    ``section`` is the key in the new snapshot (the old one for "removed");
    ``old_section`` is set when a matched section changed its key.
    ``detail`` is ``DETAIL_SECRET_CHANGED`` for a secret whose digest changed
    and ``DETAIL_SECRET_UNVERIFIABLE`` when the section key changed and the
    digests cannot be compared. Values are plain JSON types (dict/list), so a
    ``Change`` with such values is not hashable.
    """

    kind: ChangeKind
    config: str
    section: str
    option: str | None
    area: Area
    risk: Risk
    old: Any
    new: Any
    section_type: str = ""
    old_section: str | None = None
    detail: str | None = None


@dataclass(frozen=True, slots=True)
class DriftAck:
    """A user's decision about one drift (read-only here, stored in Ia).

    ``acknowledged``: seen, the baseline stays. ``known``: the drifted state
    with this ``drift_id`` becomes the new baseline.
    """

    drift_id: str
    state: AckState
    by_user: str | None
    at: datetime

    def __post_init__(self) -> None:
        if self.state not in _ACK_STATES:
            raise ValueError(f"unknown drift ack state: {self.state!r}")


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Outcome of ``evaluate_drift``.

    ``state``: ``none`` (no change), ``new`` (not acknowledged yet),
    ``acknowledged`` or ``known`` (see ``DriftAck``). ``not_comparable``
    lists configs readable on one side only; they are never reported as
    removed or added. The report changes nothing; the caller acts on
    ``rebaseline``.
    """

    state: DriftState
    drift_id: str | None
    changes: tuple[Change, ...]
    not_comparable: tuple[str, ...]
    baseline_hash: str
    current_hash: str
    highest_risk: Risk | None
    critical_count: int
    ack: DriftAck | None = None

    @property
    def is_drift(self) -> bool:
        """True while the router differs from its baseline."""
        return self.state in (DRIFT_NEW, DRIFT_ACKNOWLEDGED)

    @property
    def notify(self) -> bool:
        """True for a drift nobody has looked at yet."""
        return self.state == DRIFT_NEW

    @property
    def rebaseline(self) -> bool:
        """True when the caller should take the current snapshot as baseline."""
        return self.state == DRIFT_KNOWN


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def max_risk(*risks: Risk | str) -> Risk:
    """Return the most severe of the given risks."""
    return Risk(min(risks, key=lambda risk: _RISK_RANK[str(risk)]))


def _is_marker(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and len(value) == 1
        and isinstance(value.get(SECRET_MARKER_KEY), str)
    )


def _has_marker(value: Any) -> bool:
    if isinstance(value, list):
        return any(_is_marker(item) for item in value)
    return _is_marker(value)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _sections(cfg: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    sections = cfg.get(NORM_SECTIONS)
    return sections if isinstance(sections, Mapping) else {}


def _order(cfg: Mapping[str, Any]) -> list[str]:
    """Section keys in source order; keys missing from ``order`` go last."""
    sections = _sections(cfg)
    raw = cfg.get(NORM_ORDER)
    order = [key for key in (raw if isinstance(raw, list) else []) if key in sections]
    seen = set(order)
    order.extend(sorted(key for key in sections if key not in seen))
    return order


def _stype(section: Mapping[str, Any]) -> str:
    stype = section.get(NORM_TYPE)
    return stype if isinstance(stype, str) else ""


def _options(section: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if section is None:
        return {}
    options = section.get(NORM_OPTIONS)
    return options if isinstance(options, Mapping) else {}


def _section_value(section: Mapping[str, Any]) -> dict[str, Any]:
    return {NORM_TYPE: _stype(section), NORM_OPTIONS: dict(_options(section))}


def _is_anonymous(key: str) -> bool:
    return key.startswith(ANON_PREFIX)


def _is_fallback(key: str) -> bool:
    return _FALLBACK_KEY_RE.fullmatch(key) is not None


def _rule_name(key: str) -> str:
    """Section name for the static table: only named sections have one."""
    return "" if _is_anonymous(key) else key


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _host_address(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return None


def _carries_host(options: Mapping[str, Any], host: str) -> bool:
    """True if an interface's static address equals the management host."""
    wanted = _host_address(host)
    plain = host.strip().strip("[]").lower()
    for opt in _ADDRESS_OPTIONS:
        for value in _as_list(options.get(opt)):
            if not isinstance(value, str):
                continue
            for token in value.split():
                addr = token.split("/", 1)[0]
                if wanted is not None:
                    parsed = _host_address(addr)
                    if parsed is not None and parsed == wanted:
                        return True
                elif addr.lower() == plain:
                    return True
    return False


def _is_uplink(name: str, options: Mapping[str, Any]) -> bool:
    """Same idea as api.wan_interface_tier 0/1 (named WAN, upstream proto)."""
    iface = name.lower()
    proto = options.get("proto")
    proto = proto.lower() if isinstance(proto, str) else ""
    if proto == "none":
        return False
    if iface in UPLINK_INTERFACE_NAMES or iface == "pppoe-wan":
        return True
    if iface.startswith(("wan", "wwan")):
        return True
    return proto in WAN_PROTOS


def _port_spec_hits(spec: str, ports: frozenset[int]) -> bool:
    for token in re.split(r"[\s,]+", spec.strip()):
        if not token:
            continue
        if token.lower() in _SSH_SERVICE_NAMES:
            return True
        bounds = re.fullmatch(r"!?(\d+)(?:[-:](\d+))?", token)
        if bounds is None or token.startswith("!"):
            continue
        low = int(bounds.group(1))
        high = int(bounds.group(2)) if bounds.group(2) else low
        if any(low <= port <= high for port in ports):
            return True
    return False


def _touches_ssh(options: Mapping[str, Any]) -> bool:
    return any(
        isinstance(value, str) and _port_spec_hits(value, _SSH_PORT_NUMBERS)
        for opt in _PORT_OPTIONS
        for value in _as_list(options.get(opt))
    )


def classify(
    config: str,
    section_type: str,
    option: str | None,
    *,
    mgmt_host: str | None,
    section_name: str = "",
    section_options: Iterable[Mapping[str, Any]] = (),
    uplinks: Iterable[str] = (),
) -> tuple[Area, Risk]:
    """Return (area, risk) of a change.

    Starts from the static table (``config_const.lookup_risk_rule``) and
    raises the risk where the value decides (plan 11.6 and 23; the extra
    keyword arguments carry the values the plan signature lacks):

    - ``network.interface`` whose static address (``ipaddr``/``ip6addr`` on
      either side) is ``mgmt_host``: management options -> MGMT_IP/critical,
    - uplink interfaces (name ``wan*``/``wwan*``, upstream protocol, or
      listed in ``uplinks``) -> critical,
    - firewall rule/redirect without ``dest`` (acts on input) -> critical,
    - firewall rule/redirect matching an SSH port -> SSH/critical.

    ``section_name`` is the section key (anonymous keys are ignored by the
    table), ``section_options`` the option maps of the section before and/or
    after the change.
    """
    area_s, risk_s = lookup_risk_rule(
        config, section_type, option, section_name=_rule_name(section_name)
    )
    area, risk = Area(area_s), Risk(risk_s)
    cfg = config.lower()
    stype = section_type.lower()
    opt = option.lower() if option is not None else None
    sides = [o for o in section_options if isinstance(o, Mapping)]

    if cfg == "network" and stype == "interface":
        name = _rule_name(section_name)
        uplink_names = {u.lower() for u in uplinks}
        if name and (
            name.lower() in uplink_names or any(_is_uplink(name, o) for o in sides)
        ):
            risk = Risk.CRITICAL
        if (
            mgmt_host
            and (opt is None or opt in MGMT_IP_OPTIONS)
            and any(_carries_host(o, mgmt_host) for o in sides)
        ):
            area, risk = Area.MGMT_IP, Risk.CRITICAL
    elif cfg == "firewall" and stype in FIREWALL_INPUT_SECTION_TYPES and sides:
        if any(not o.get("dest") for o in sides):
            risk = Risk.CRITICAL
        if any(_touches_ssh(o) for o in sides):
            area, risk = Area.SSH, Risk.CRITICAL
    return area, risk


def _uplinks(*configs: Mapping[str, Any] | None) -> frozenset[str]:
    """Uplink interface names from network and firewall configs.

    Interfaces named/protocol'd as WAN plus the networks of masquerading
    zones or the zone named ``wan``.
    """
    found: set[str] = set()
    for cfg in configs:
        if not cfg:
            continue
        for key, section in _sections(cfg).items():
            stype = _stype(section)
            options = _options(section)
            if stype == "interface" and not _is_anonymous(key):
                if _is_uplink(key, options):
                    found.add(key.lower())
            elif stype == "zone" and (
                options.get("name") == "wan" or options.get("masq") == "1"
            ):
                found.update(
                    n.lower()
                    for value in _as_list(options.get("network"))
                    if isinstance(value, str)
                    for n in value.split()
                )
    return frozenset(found)


# ---------------------------------------------------------------------------
# Section matching
# ---------------------------------------------------------------------------


def _signature(section: Mapping[str, Any]) -> str:
    """Content of a section with secrets blanked (digests are key-bound)."""
    options = {
        opt: (_SECRET_PLACEHOLDER if _has_marker(value) else value)
        for opt, value in _options(section).items()
    }
    return canonical_json({NORM_TYPE: _stype(section), NORM_OPTIONS: options})


def _identity_fields(config: str, stype: str) -> frozenset[str]:
    return frozenset(
        field
        for fields in SECTION_IDENTITY_FIELDS.get((config, stype), ())
        for field in fields
    )


def _similarity(
    config: str, stype: str, old: Mapping[str, Any], new: Mapping[str, Any]
) -> float | None:
    """Share of equal options, identity fields and secrets left out.

    None when there is nothing to compare.
    """
    skip = _identity_fields(config, stype)
    old_opts, new_opts = _options(old), _options(new)
    names = {
        name
        for name in set(old_opts) | set(new_opts)
        if name not in skip
        and not is_secret_option(config, stype, name)
        and not _has_marker(old_opts.get(name))
        and not _has_marker(new_opts.get(name))
    }
    if not names:
        return None
    equal = sum(1 for name in names if old_opts.get(name) == new_opts.get(name))
    return equal / len(names)


def _match_sections(
    config: str,
    old_secs: Mapping[str, Mapping[str, Any]],
    new_secs: Mapping[str, Mapping[str, Any]],
    old_order: Sequence[str],
    new_order: Sequence[str],
) -> dict[str, str]:
    """Return old key -> new key for sections that are the same section."""
    pairs: dict[str, str] = {}
    # 1. Named and identity keys: same key, same type.
    for key in old_order:
        if (
            not _is_fallback(key)
            and key in new_secs
            and _stype(old_secs[key]) == _stype(new_secs[key])
        ):
            pairs[key] = key

    # 2. Anonymous sections without identity: align contents per type.
    types = dict.fromkeys(
        _stype(secs[k])
        for secs, order in ((old_secs, old_order), (new_secs, new_order))
        for k in order
        if _is_fallback(k)
    )
    for stype in types:
        olds = [
            k for k in old_order if _is_fallback(k) and _stype(old_secs[k]) == stype
        ]
        news = [
            k for k in new_order if _is_fallback(k) and _stype(new_secs[k]) == stype
        ]
        matcher = difflib.SequenceMatcher(
            a=[_signature(old_secs[k]) for k in olds],
            b=[_signature(new_secs[k]) for k in news],
            autojunk=False,
        )
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ("equal", "replace"):
                pairs.update(zip(olds[i1:i2], news[j1:j2], strict=False))

    # 3. Remaining anonymous sections of one type: content, then position.
    used = set(pairs.values())
    removed = [k for k in old_order if k not in pairs and _is_anonymous(k)]
    added = [k for k in new_order if k not in used and _is_anonymous(k)]
    for stype in dict.fromkeys(_stype(old_secs[k]) for k in removed):
        rem = [k for k in removed if _stype(old_secs[k]) == stype]
        add = [k for k in added if _stype(new_secs[k]) == stype and k not in used]
        if not add:
            continue
        old_pos = {
            k: i
            for i, k in enumerate(k for k in old_order if _stype(old_secs[k]) == stype)
        }
        new_pos = {
            k: i
            for i, k in enumerate(k for k in new_order if _stype(new_secs[k]) == stype)
        }

        def take(old_key: str, new_key: str) -> None:
            pairs[old_key] = new_key
            used.add(new_key)

        # a) identical content (moved section).
        for old_key in rem:
            sig = _signature(old_secs[old_key])
            hit = next(
                (k for k in add if k not in used and _signature(new_secs[k]) == sig),
                None,
            )
            if hit is not None:
                take(old_key, hit)
        # b) same position among sections of the type.
        for old_key in rem:
            if old_key in pairs:
                continue
            hit = next(
                (k for k in add if k not in used and new_pos[k] == old_pos[old_key]),
                None,
            )
            if hit is None:
                continue
            sim = _similarity(config, stype, old_secs[old_key], new_secs[hit])
            if sim is None or sim >= _PAIR_MIN_SIMILARITY:
                take(old_key, hit)
        # c) most similar, nearest position.
        for old_key in rem:
            if old_key in pairs:
                continue
            best: tuple[float, int, str] | None = None
            for k in add:
                if k in used:
                    continue
                sim = _similarity(config, stype, old_secs[old_key], new_secs[k])
                if sim is None or sim < _PAIR_MIN_SIMILARITY:
                    continue
                score = (sim, -abs(new_pos[k] - old_pos[old_key]), k)
                if best is None or score[:2] > best[:2]:
                    best = score
            if best is not None:
                take(old_key, best[2])
    return pairs


def _lis_keep(seq: Sequence[int]) -> set[int]:
    """Indices of one longest increasing subsequence of ``seq``."""
    tails: list[int] = []
    tail_idx: list[int] = []
    prev = [-1] * len(seq)
    for i, value in enumerate(seq):
        pos = bisect_left(tails, value)
        if pos == len(tails):
            tails.append(value)
            tail_idx.append(i)
        else:
            tails[pos] = value
            tail_idx[pos] = i
        prev[i] = tail_idx[pos - 1] if pos else -1
    keep: set[int] = set()
    i = tail_idx[-1] if tail_idx else -1
    while i >= 0:
        keep.add(i)
        i = prev[i]
    return keep


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------


def not_comparable(old: UciSnapshot, new: UciSnapshot) -> tuple[str, ...]:
    """Configs present on one side only (unreadable or not collected).

    A config missing on both sides has nothing to compare and is left out.
    """
    present_old, present_new = set(old.configs), set(new.configs)
    return tuple(sorted(present_old ^ present_new))


def _option_changes(
    config: str,
    old_key: str,
    new_key: str,
    old_sec: Mapping[str, Any],
    new_sec: Mapping[str, Any],
    mgmt_host: str | None,
    uplinks: frozenset[str],
) -> list[Change]:
    stype = _stype(new_sec)
    old_opts, new_opts = _options(old_sec), _options(new_sec)
    sides = (old_opts, new_opts)
    rekeyed = old_key != new_key
    out: list[Change] = []
    for opt in sorted(set(old_opts) | set(new_opts)):
        before, after = old_opts.get(opt), new_opts.get(opt)
        if before == after:
            continue
        area, risk = classify(
            config,
            stype,
            opt,
            mgmt_host=mgmt_host,
            section_name=new_key,
            section_options=sides,
            uplinks=uplinks,
        )
        secret = (
            is_secret_option(config, stype, opt)
            or _has_marker(before)
            or _has_marker(after)
        )
        detail: str | None = None
        if opt not in old_opts:
            kind: ChangeKind = KIND_ADDED
        elif opt not in new_opts:
            kind = KIND_REMOVED
        elif (
            isinstance(before, list)
            and isinstance(after, list)
            and sorted(map(canonical_json, before))
            == sorted(map(canonical_json, after))
            and not (secret and rekeyed)
        ):
            kind, risk = KIND_REORDERED, Risk(RISK_REORDERED)
        else:
            kind = KIND_CHANGED
            if secret:
                detail = (
                    DETAIL_SECRET_UNVERIFIABLE if rekeyed else DETAIL_SECRET_CHANGED
                )
        out.append(
            Change(
                kind=kind,
                config=config,
                section=new_key,
                option=opt,
                area=area,
                risk=risk,
                old=before,
                new=after,
                section_type=stype,
                old_section=old_key if rekeyed else None,
                detail=detail,
            )
        )
    return out


def _diff_config(
    config: str,
    old_cfg: Mapping[str, Any],
    new_cfg: Mapping[str, Any],
    mgmt_host: str | None,
    uplinks: frozenset[str],
) -> list[Change]:
    old_secs, new_secs = _sections(old_cfg), _sections(new_cfg)
    old_order, new_order = _order(old_cfg), _order(new_cfg)
    pairs = _match_sections(config, old_secs, new_secs, old_order, new_order)
    by_new = {new: old for old, new in pairs.items()}
    out: list[Change] = []

    for new_key in new_order:
        new_sec = new_secs[new_key]
        old_key = by_new.get(new_key)
        if old_key is not None:
            out.extend(
                _option_changes(
                    config,
                    old_key,
                    new_key,
                    old_secs[old_key],
                    new_sec,
                    mgmt_host,
                    uplinks,
                )
            )
            continue
        stype = _stype(new_sec)
        area, risk = classify(
            config,
            stype,
            None,
            mgmt_host=mgmt_host,
            section_name=new_key,
            section_options=(_options(new_sec),),
            uplinks=uplinks,
        )
        out.append(
            Change(
                KIND_ADDED,
                config,
                new_key,
                None,
                area,
                risk,
                None,
                _section_value(new_sec),
                section_type=stype,
            )
        )

    for old_key in old_order:
        if old_key in pairs:
            continue
        old_sec = old_secs[old_key]
        stype = _stype(old_sec)
        area, risk = classify(
            config,
            stype,
            None,
            mgmt_host=mgmt_host,
            section_name=old_key,
            section_options=(_options(old_sec),),
            uplinks=uplinks,
        )
        out.append(
            Change(
                KIND_REMOVED,
                config,
                old_key,
                None,
                area,
                risk,
                _section_value(old_sec),
                None,
                section_type=stype,
            )
        )

    # Reordering: sections outside one longest run that kept its order.
    old_index = {key: i for i, key in enumerate(old_order)}
    new_index = {key: i for i, key in enumerate(new_order)}
    matched = [key for key in old_order if key in pairs]
    keep = _lis_keep([new_index[pairs[key]] for key in matched])
    for i, old_key in enumerate(matched):
        if i in keep:
            continue
        new_key = pairs[old_key]
        new_sec = new_secs[new_key]
        stype = _stype(new_sec)
        area, base_risk = classify(
            config,
            stype,
            None,
            mgmt_host=mgmt_host,
            section_name=new_key,
            section_options=(_options(old_secs[old_key]), _options(new_sec)),
            uplinks=uplinks,
        )
        if (config, stype) in _ORDER_SENSITIVE:
            risk = max_risk(Risk.HIGH, base_risk)
        else:
            risk = Risk(RISK_REORDERED)
        out.append(
            Change(
                KIND_REORDERED,
                config,
                new_key,
                None,
                area,
                risk,
                old_index[old_key],
                new_index[new_key],
                section_type=stype,
                old_section=old_key if old_key != new_key else None,
            )
        )
    return out


def diff_snapshots(
    old: UciSnapshot, new: UciSnapshot, *, mgmt_host: str | None
) -> tuple[Change, ...]:
    """Return every change from ``old`` to ``new``.

    Only configs present in both snapshots are compared; the others are
    listed by :func:`not_comparable` and never reported as removed/added.
    ``mgmt_host`` is the address HA uses for the router (None = unknown).
    """
    if old.content_hash == new.content_hash:
        return ()
    uplinks = _uplinks(
        old.configs.get("network"),
        new.configs.get("network"),
        old.configs.get("firewall"),
        new.configs.get("firewall"),
    )
    changes: list[Change] = []
    for config in sorted(set(old.configs) & set(new.configs)):
        old_cfg, new_cfg = old.configs[config], new.configs[config]
        if old_cfg == new_cfg:
            continue
        changes.extend(_diff_config(config, old_cfg, new_cfg, mgmt_host, uplinks))
    _LOGGER.debug("config diff: %d change(s)", len(changes))
    return tuple(changes)


# ---------------------------------------------------------------------------
# Drift
# ---------------------------------------------------------------------------


def drift_id(changes: Sequence[Change], content_hash: str) -> str:
    """Stable id of a drift: SHA-256 hex over the changes and the content.

    Independent of the order of ``changes`` and of area/risk (those depend
    on ``mgmt_host``). 64 hex characters on purpose: ``redact_text`` masks
    stand-alone 32-hex strings as session tokens.
    """
    rows = sorted(
        canonical_json(
            [c.kind, c.config, c.section, c.old_section, c.option, c.old, c.new]
        )
        for c in changes
    )
    payload = canonical_json([_DRIFT_ID_SCHEME, content_hash, rows])
    return hashlib.sha256(payload.encode("utf-8", errors="surrogatepass")).hexdigest()


def _latest_ack(acks: Iterable[DriftAck], wanted: str) -> DriftAck | None:
    """Latest ack for ``wanted``; on equal time ``known`` wins."""
    matching = [ack for ack in acks if ack.drift_id == wanted]
    if not matching:
        return None
    return max(matching, key=lambda ack: (ack.at.timestamp(), ack.state == ACK_KNOWN))


def evaluate_drift(
    baseline: UciSnapshot,
    current: UciSnapshot,
    acks: Iterable[DriftAck],
    *,
    mgmt_host: str | None,
) -> DriftReport:
    """Compare ``current`` with ``baseline`` and apply the acknowledgements.

    Never changes the baseline itself: ``known`` only sets
    ``DriftReport.rebaseline``. Of several acks for the same drift the
    latest counts.
    """
    changes = diff_snapshots(baseline, current, mgmt_host=mgmt_host)
    skipped = not_comparable(baseline, current)
    if not changes:
        return DriftReport(
            state=DRIFT_NONE,
            drift_id=None,
            changes=(),
            not_comparable=skipped,
            baseline_hash=baseline.content_hash,
            current_hash=current.content_hash,
            highest_risk=None,
            critical_count=0,
        )
    did = drift_id(changes, current.content_hash)
    ack = _latest_ack(acks, did)
    state: DriftState = DRIFT_NEW if ack is None else ack.state
    return DriftReport(
        state=state,
        drift_id=did,
        changes=changes,
        not_comparable=skipped,
        baseline_hash=baseline.content_hash,
        current_hash=current.content_hash,
        highest_risk=max_risk(*(c.risk for c in changes)),
        critical_count=sum(1 for c in changes if c.risk == Risk.CRITICAL),
        ack=ack,
    )
