"""Router identity of the enterprise core: pure functions (contract §3/§4).

* :func:`router_id_for_entry` gives the stable ``rtr_…`` id of a config
  entry. It depends on the entry id ONLY, so it exists before the router
  was ever reached and never follows an IP, hostname or hardware change.
* :func:`observe` turns the data of ONE finished poll into an
  :class:`Observation` (hardware fingerprint, firmware, APs). It reads only
  what the coordinator already fetched: no router call.
* :func:`hardware_matches` / :func:`assess` compare an observation with the
  reference fingerprint of the record and decide the identity flags
  (``unverified`` / ``changed`` / ``duplicate_suspected``; ``confirmed`` is
  "no flag").
* :func:`duplicate_groups` finds active routers that share hardware MACs.
  Nothing is ever merged; both sides are flagged.

Locally administered MACs (randomised, virtual interfaces) never count as
hardware: ``HardwareFingerprint.build`` drops them, :func:`observe` counts
how many were ignored.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .const import (
    OPENWRT_DEFAULT_HOSTNAME,
    ROUTER_FINGERPRINT_MAX_MACS,
    ROUTER_INFO_FALLBACK_MODEL,
)
from .core_models import (
    AccessPointInfo,
    HardwareFingerprint,
    IdentityFlag,
    InterfaceInfo,
    RouterRole,
    default_router_id,
    normalize_mac,
)
from .mac_utils import is_locally_administered

_LOGGER = logging.getLogger(__name__)

# Upper bounds of what one observation keeps (a record is stored as JSON).
MAX_ACCESS_POINTS = 32
MAX_INTERFACES = 32


def router_id_for_entry(entry_id: str) -> str:
    """The deterministic router id of a config entry (``rtr_`` + uuid5 hex)."""
    return default_router_id(entry_id)


def alternate_router_id(entry_id: str, attempt: int) -> str:
    """Fallback id if the default one is taken by another record.

    Only reachable after a manual store edit or an adoption across
    restores; deterministic as well (``entry_id#<attempt>``).
    """
    return default_router_id(f"{entry_id}#{attempt}")


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


@dataclass(frozen=True, slots=True)
class Observation:
    """What one finished poll says about the router's identity."""

    has_data: bool
    hostname: str | None
    model: str | None
    board_name: str | None
    architecture: str | None
    distribution: str | None
    openwrt_version: str | None
    openwrt_revision: str | None
    target: str | None
    kernel: str | None
    fingerprint: HardwareFingerprint
    access_points: tuple[AccessPointInfo, ...]
    interfaces: tuple[InterfaceInfo, ...]
    ignored_local_macs: int = 0

    @property
    def identifying(self) -> bool:
        """True if board, model or a hardware MAC is known."""
        return not self.fingerprint.is_empty


def _ap_info(item: Mapping[str, Any]) -> AccessPointInfo | None:
    ifname = _text(item.get("ifname"))
    if ifname is None:
        return None
    return AccessPointInfo(
        ifname=ifname,
        ssid=_text(item.get("ssid")),
        bssid=normalize_mac(item.get("bssid")),
        band=_text(item.get("band")),
    )


def _interface_info(item: Mapping[str, Any]) -> InterfaceInfo | None:
    name = _text(item.get("logical_name")) or _text(item.get("interface"))
    if name is None:
        return None
    status = item.get("status")
    up: bool | None
    if isinstance(status, bool):
        up = status
    elif isinstance(status, str) and status:
        up = status.lower() == "up"
    else:
        up = None
    return InterfaceInfo(
        name=name,
        device=_text(item.get("interface")),
        mac=normalize_mac(item.get("mac")),
        proto=_text(item.get("proto")),
        up=up,
    )


def _dicts(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, Mapping)]


def candidate_macs(data: Any) -> list[str]:
    """Every MAC the poll reports as the router's OWN (before filtering).

    Sources: ``router_info.mac``, the BSSIDs of the own AP interfaces and
    radios, and the own MAC of STA interfaces. The STA ``bssid`` is the
    upstream AP (another device) and is deliberately NOT used.
    """
    macs: list[str] = []
    info = getattr(data, "router_info", None)
    if isinstance(info, Mapping):
        macs.append(info.get("mac"))
    for item in _dicts(getattr(data, "ap_interfaces", None)):
        macs.append(item.get("bssid"))
    for item in _dicts(getattr(data, "wifi_radios", None)):
        macs.append(item.get("bssid"))
    for item in _dicts(getattr(data, "sta_interfaces", None)):
        macs.append(item.get("mac"))
    return [m for m in macs if m]


def observe(data: Any, *, management_host: str | None) -> Observation:
    """Build the observation of one poll; never raises for odd data."""
    info = getattr(data, "router_info", None)
    info = info if isinstance(info, Mapping) else {}
    release = info.get("release")
    release = release if isinstance(release, Mapping) else {}

    model = _text(info.get("model"))
    if model == ROUTER_INFO_FALLBACK_MODEL:
        model = None  # api.py fallback when system/board is not readable
    hostname = _text(info.get("hostname"))
    if hostname is not None and hostname == _text(management_host):
        hostname = None  # api.py falls back to the host when board is missing
    board_name = _text(info.get("board_name"))

    raw_macs = candidate_macs(data)
    fingerprint = HardwareFingerprint.build(
        board_name=board_name, model=model, macs=raw_macs
    )
    ignored = sum(
        1
        for mac in {normalize_mac(m) for m in raw_macs} - {None}
        if mac not in fingerprint.macs and is_locally_administered(mac)
    )
    access_points = tuple(
        ap
        for ap in (_ap_info(i) for i in _dicts(getattr(data, "ap_interfaces", None)))
        if ap is not None
    )[:MAX_ACCESS_POINTS]
    interfaces = tuple(
        i
        for i in (
            _interface_info(x)
            for x in _dicts(getattr(data, "network_interfaces", None))
        )
        if i is not None
    )[:MAX_INTERFACES]
    return Observation(
        has_data=bool(info),
        hostname=hostname,
        model=model,
        board_name=board_name,
        architecture=_text(info.get("platform_architecture")),
        distribution=_text(release.get("distribution")),
        openwrt_version=_text(release.get("version")),
        openwrt_revision=_text(release.get("revision")),
        target=_text(release.get("target")),
        kernel=_text(info.get("kernel")),
        fingerprint=fingerprint,
        access_points=access_points,
        interfaces=interfaces,
        ignored_local_macs=ignored,
    )


def identity_signature(data: Any, management_host: str | None) -> tuple[Any, ...]:
    """Cheap tuple of everything :func:`observe` depends on.

    The registry recomputes the identity only when this changes, so a
    steady router costs one tuple build per poll.
    """
    info = getattr(data, "router_info", None)
    info = info if isinstance(info, Mapping) else {}
    release = info.get("release")
    release = release if isinstance(release, Mapping) else {}
    wan = getattr(data, "wan_status", None)
    wan = wan if isinstance(wan, Mapping) else {}
    return (
        management_host,
        info.get("hostname"),
        info.get("model"),
        info.get("board_name"),
        info.get("mac"),
        info.get("kernel"),
        info.get("platform_architecture"),
        release.get("distribution"),
        release.get("version"),
        release.get("revision"),
        release.get("target"),
        tuple(
            (i.get("ifname"), i.get("bssid"), i.get("ssid"), i.get("band"))
            for i in _dicts(getattr(data, "ap_interfaces", None))
        ),
        tuple(i.get("bssid") for i in _dicts(getattr(data, "wifi_radios", None))),
        tuple(i.get("mac") for i in _dicts(getattr(data, "sta_interfaces", None))),
        tuple(
            (i.get("interface"), i.get("logical_name"), i.get("status"))
            for i in _dicts(getattr(data, "network_interfaces", None))
        ),
        wan.get("wan_found"),
        wan.get("proto"),
        wan.get("connected"),
        wan.get("interface"),
        wan.get("ipv4"),
    )


def hardware_matches(
    reference: HardwareFingerprint, observed: HardwareFingerprint
) -> bool | None:
    """Same device? True / False, None if there is nothing to compare.

    A shared hardware MAC always wins over model text (firmware updates
    rename models). With MACs on both sides and none shared: another
    device. Without MACs on one side, the board name decides, then the
    model.
    """
    if reference.macs and observed.macs:
        return bool(reference.mac_overlap(observed))
    if reference.board_name and observed.board_name:
        return reference.board_name == observed.board_name
    if reference.model and observed.model:
        return reference.model == observed.model
    return None


def merge_reference(
    reference: HardwareFingerprint, observed: HardwareFingerprint
) -> tuple[HardwareFingerprint, int]:
    """Reference fingerprint after a matching observation, and MACs dropped.

    MACs accumulate (radios come and go with config), capped at
    ``ROUTER_FINGERPRINT_MAX_MACS``; board/model take the newest known
    value. The second value counts MACs that did not fit (visible as a
    registry counter).
    """
    macs = sorted(reference.macs | observed.macs)
    dropped = max(0, len(macs) - ROUTER_FINGERPRINT_MAX_MACS)
    if dropped:
        # keep what the device shows now, then the oldest known ones
        current = sorted(observed.macs)[:ROUTER_FINGERPRINT_MAX_MACS]
        rest = [m for m in macs if m not in observed.macs]
        macs = current + rest[: ROUTER_FINGERPRINT_MAX_MACS - len(current)]
    return (
        HardwareFingerprint(
            board_name=observed.board_name or reference.board_name,
            model=observed.model or reference.model,
            macs=frozenset(macs),
        ),
        dropped,
    )


def is_factory_default_hostname(hostname: str | None) -> bool:
    """True for OpenWrt's default hostname (case-insensitive)."""
    return bool(hostname) and hostname.lower() == OPENWRT_DEFAULT_HOSTNAME.lower()


@dataclass(frozen=True, slots=True)
class IdentityAssessment:
    """Outcome of comparing one observation with the stored identity."""

    flags: frozenset[IdentityFlag]
    hardware_changed: bool = False  # new CHANGED flag
    hardware_restored: bool = False  # CHANGED cleared, same hardware again
    changed_fields: tuple[str, ...] = ()
    factory_reset_suspected: bool = False
    shared_mac_count: int = 0
    update_reference: bool = False


def assess(
    *,
    flags: Iterable[IdentityFlag],
    reference: HardwareFingerprint,
    previous_hostname: str | None,
    previous_version: str | None,
    previous_host: str | None,
    observation: Observation,
    management_host: str | None,
) -> IdentityAssessment:
    """Decide the new flags of a router after one observation.

    * UNVERIFIED goes away with the first poll that delivered data.
    * CHANGED is set when the hardware does not match the reference and
      cleared when it matches again. While CHANGED, the reference is kept
      (so the original device is recognised when it comes back).
    * DUPLICATE_SUSPECTED is fleet-wide and handled by the registry
      (:func:`duplicate_groups`); it is passed through unchanged here.
    * ``changed_fields`` lists hostname / firmware / management host
      changes (they never change the router id). A default hostname on
      matching hardware means a factory reset is suspected.
    """
    current = set(flags)
    if observation.has_data:
        current.discard(IdentityFlag.UNVERIFIED)

    match = hardware_matches(reference, observation.fingerprint)
    was_changed = IdentityFlag.CHANGED in current
    hardware_changed = False
    hardware_restored = False
    if match is False and not was_changed:
        current.add(IdentityFlag.CHANGED)
        hardware_changed = True
    elif match is True and was_changed:
        current.discard(IdentityFlag.CHANGED)
        hardware_restored = True

    changed_fields: list[str] = []
    if (
        observation.hostname is not None
        and previous_hostname is not None
        and observation.hostname != previous_hostname
    ):
        changed_fields.append("hostname")
    if (
        observation.openwrt_version is not None
        and previous_version is not None
        and observation.openwrt_version != previous_version
    ):
        changed_fields.append("openwrt_version")
    if (
        management_host is not None
        and previous_host is not None
        and management_host != previous_host
    ):
        changed_fields.append("management_host")

    factory_reset = (
        "hostname" in changed_fields
        and is_factory_default_hostname(observation.hostname)
        and match is not False
    )
    update_reference = observation.identifying and IdentityFlag.CHANGED not in current
    return IdentityAssessment(
        flags=frozenset(current),
        hardware_changed=hardware_changed,
        hardware_restored=hardware_restored,
        changed_fields=tuple(changed_fields),
        factory_reset_suspected=factory_reset,
        shared_mac_count=len(reference.mac_overlap(observation.fingerprint)),
        update_reference=update_reference,
    )


def duplicate_groups(
    mac_sets: Mapping[str, frozenset[str]],
) -> dict[str, dict[str, int]]:
    """``router_id -> {other_router_id: shared MAC count}`` for shared MACs.

    ``mac_sets`` holds the current hardware MACs of ACTIVE routers only.
    Symmetric: if A shares with B, B shares with A.
    """
    owners: dict[str, set[str]] = {}
    for router_id, macs in mac_sets.items():
        for mac in macs:
            owners.setdefault(mac, set()).add(router_id)
    result: dict[str, dict[str, int]] = {}
    for routers in owners.values():
        if len(routers) < 2:
            continue
        for router_id in routers:
            others = result.setdefault(router_id, {})
            for other in routers:
                if other != router_id:
                    others[other] = others.get(other, 0) + 1
    return result


def derive_role(
    data: Any, management_host: str | None, previous: RouterRole
) -> RouterRole:
    """Gateway / access point from the WAN evidence of ``topology_mesh``.

    Strong evidence (connected ISP-uplink WAN) means gateway, no evidence
    means access point; weak or SSH-only evidence keeps the previous role.
    Without WAN data or if the mesh module cannot be used: unknown/previous.
    """
    wan = getattr(data, "wan_status", None)
    if not isinstance(wan, Mapping) or not wan:
        return previous
    try:
        from .topology_mesh import _gateway_evidence
    except Exception:  # import guarded on purpose (no side effects needed)
        _LOGGER.debug("Router role: topology_mesh not importable", exc_info=True)
        return previous
    try:
        evidence = _gateway_evidence(data, management_host or "")
    except Exception:
        _LOGGER.debug("Router role: WAN evidence failed", exc_info=True)
        return previous
    if evidence >= 3:
        return RouterRole.GATEWAY
    if evidence == 0:
        return RouterRole.ACCESS_POINT
    return previous
