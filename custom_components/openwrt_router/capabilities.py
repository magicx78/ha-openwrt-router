"""Capability detection of the enterprise core (contract §5).

Everything here is derived from data the coordinator ALREADY has after a
poll: ``features``, ``api.uses_ssh_fallback``, ``lldp_status``,
``log_status``, ``updates_available["package_manager"]`` and
``router_info``. No router call, no probe: the router-side probes of the
configuration provider (``config.cgi_backup`` …) belong to part 2 and never
run in the poll.

* :func:`capability_signature` is the cheap tuple the registry compares on
  every poll; :func:`evaluate` runs only when it changed.
* :func:`merge` applies a fresh evaluation to the stored map. An
  ``unknown`` never overwrites a known state (a hiccup is not a change),
  an identical status keeps its ``detected_at``, and only a change between
  two KNOWN states is reported (``router.capabilities_changed``). First
  detections are counted, never announced.
* ``config.*`` capabilities are decided by the configuration provider.
  Part 1 has none: they are ``unavailable``/``no_provider`` (or
  ``disabled`` when the entry option ``config_backup_enabled`` is off).
  Part 2 registers a :data:`ConfigCapabilityProvider` hook.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from .const import (
    LLDP_STATUS_ERROR,
    LLDP_STATUS_NO_NEIGHBORS,
    LLDP_STATUS_OK,
    LLDP_STATUS_UNAVAILABLE,
    LOG_STATUS_ERROR,
    LOG_STATUS_NOT_PERMITTED,
    LOG_STATUS_OK,
    LOG_STATUS_PENDING,
    ROUTER_INFO_FALLBACK_MODEL,
)
from .core_models import (
    CONFIG_CAPABILITIES,
    FEATURE_CAPABILITIES,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    RouterRecord,
)

_LOGGER = logging.getLogger(__name__)

# Part 2 hook: router record -> config.* statuses it decides (sync, no I/O;
# probe results are cached by the provider side). None = no provider.
ConfigCapabilityProvider = Callable[[RouterRecord], Mapping[str, CapabilityStatus]]

SOURCE_SSH_FLAG = "api.uses_ssh_fallback"
SOURCE_ROUTER_INFO = "router_info"
SOURCE_WIFI_RADIOS = "wifi_radios"
SOURCE_AP_INTERFACES = "ap_interfaces"
SOURCE_LLDP = "lldp_status"
SOURCE_LOG = "log_status"
SOURCE_PACKAGE_MANAGER = "updates_available.package_manager"
SOURCE_STREAM = "ubus_stream"
SOURCE_CONFIG = "config_provider"
SOURCE_CONFIG_OPTION = "options.config_backup_enabled"


def capability_signature(
    data: Any,
    *,
    uses_ssh_fallback: bool,
    ssh_seen: bool,
    config_enabled: bool,
    provider_token: Any,
) -> tuple[Any, ...]:
    """Cheap tuple of every input of :func:`evaluate`."""
    info = getattr(data, "router_info", None)
    info = info if isinstance(info, Mapping) else {}
    features = getattr(data, "features", None)
    features = features if isinstance(features, Mapping) else {}
    updates = getattr(data, "updates_available", None)
    updates = updates if isinstance(updates, Mapping) else {}
    return (
        bool(uses_ssh_fallback),
        bool(ssh_seen),
        bool(config_enabled),
        provider_token,
        bool(info),
        info.get("board_name"),
        info.get("model"),
        bool(getattr(data, "wifi_radios", None)),
        bool(getattr(data, "ap_interfaces", None)),
        tuple(features.get(key) for key in FEATURE_CAPABILITIES),
        getattr(data, "lldp_status", None),
        getattr(data, "log_status", None),
        updates.get("package_manager"),
    )


def _status(
    capability: Capability | str,
    state: CapabilityState,
    reason: CapabilityReason | str,
    source: str,
    now: datetime,
    *,
    text: str | None = None,
    permissions: tuple[str, ...] = (),
    detail: Mapping[str, Any] | None = None,
) -> CapabilityStatus:
    return CapabilityStatus(
        capability=str(capability),
        state=state,
        reason=str(reason),
        source=source,
        detected_at=now,
        reason_text=text,
        required_permissions=permissions,
        detail=dict(detail or {}),
    )


def _available(
    cap: Capability, source: str, now: datetime, **kw: Any
) -> CapabilityStatus:
    return _status(
        cap, CapabilityState.AVAILABLE, CapabilityReason.OK, source, now, **kw
    )


def _unknown(
    cap: Capability | str,
    source: str,
    now: datetime,
    reason: CapabilityReason = CapabilityReason.NOT_CHECKED,
    **kw: Any,
) -> CapabilityStatus:
    return _status(cap, CapabilityState.UNKNOWN, reason, source, now, **kw)


def _unavailable(
    cap: Capability | str,
    source: str,
    now: datetime,
    reason: CapabilityReason | str = CapabilityReason.NOT_DETECTED,
    **kw: Any,
) -> CapabilityStatus:
    return _status(cap, CapabilityState.UNAVAILABLE, reason, source, now, **kw)


def _system_board(info: Mapping[str, Any], now: datetime) -> CapabilityStatus:
    cap = Capability.DATA_SYSTEM_BOARD
    if not info:
        return _unknown(cap, SOURCE_ROUTER_INFO, now, CapabilityReason.NO_DATA_YET)
    model = info.get("model")
    if info.get("board_name") or (model and model != ROUTER_INFO_FALLBACK_MODEL):
        return _available(cap, SOURCE_ROUTER_INFO, now)
    return _unavailable(
        cap,
        SOURCE_ROUTER_INFO,
        now,
        text="system/board not readable, fallback router info in use",
        permissions=("ubus:system.board",),
    )


def _lldp(status: Any, now: datetime) -> CapabilityStatus:
    cap = Capability.DATA_LLDP
    if status in (LLDP_STATUS_OK, LLDP_STATUS_NO_NEIGHBORS):
        return _available(cap, SOURCE_LLDP, now, detail={"status": status})
    if status == LLDP_STATUS_UNAVAILABLE:
        return _unavailable(cap, SOURCE_LLDP, now, text="lldpd/lldpcli not available")
    if status == LLDP_STATUS_ERROR:
        return _unknown(cap, SOURCE_LLDP, now, text="last LLDP read failed")
    return _unknown(cap, SOURCE_LLDP, now, CapabilityReason.NO_DATA_YET)


def _logs(status: Any, now: datetime) -> CapabilityStatus:
    cap = Capability.DATA_LOGS
    if status == LOG_STATUS_OK:
        return _available(cap, SOURCE_LOG, now)
    if status == LOG_STATUS_NOT_PERMITTED:
        return _unavailable(
            cap,
            SOURCE_LOG,
            now,
            CapabilityReason.PERMISSION_DENIED,
            permissions=("ubus:log.read",),
        )
    if status == LOG_STATUS_ERROR:
        return _unknown(cap, SOURCE_LOG, now, text="last log read failed")
    if status == LOG_STATUS_PENDING:
        return _unknown(cap, SOURCE_LOG, now, CapabilityReason.NO_DATA_YET)
    return _unknown(cap, SOURCE_LOG, now)


def _packages(manager: Any, now: datetime) -> list[CapabilityStatus]:
    if manager not in ("apk", "opkg"):
        return [
            _unknown(cap, SOURCE_PACKAGE_MANAGER, now)
            for cap in (Capability.PKG_APK, Capability.PKG_OPKG)
        ]
    return [
        _available(cap, SOURCE_PACKAGE_MANAGER, now)
        if cap.value == f"pkg.{manager}"
        else _unavailable(cap, SOURCE_PACKAGE_MANAGER, now)
        for cap in (Capability.PKG_APK, Capability.PKG_OPKG)
    ]


def _config(
    record: RouterRecord | None,
    *,
    config_enabled: bool,
    provider: ConfigCapabilityProvider | None,
    now: datetime,
) -> list[CapabilityStatus]:
    names = sorted(CONFIG_CAPABILITIES)
    if not config_enabled:
        return [
            _unavailable(c, SOURCE_CONFIG_OPTION, now, CapabilityReason.DISABLED)
            for c in names
        ]
    if provider is None or record is None:
        return [
            _unavailable(c, SOURCE_CONFIG, now, CapabilityReason.NO_PROVIDER)
            for c in names
        ]
    try:
        reported = dict(provider(record) or {})
    except Exception:
        _LOGGER.warning(
            "Config capability provider failed for %s; config.* stay unknown",
            record.router_id,
            exc_info=True,
        )
        reported = {}
    out: list[CapabilityStatus] = []
    for name in names:
        status = reported.get(name) or reported.get(str(name))
        if isinstance(status, CapabilityStatus):
            out.append(status)
        else:
            out.append(_unknown(name, SOURCE_CONFIG, now, CapabilityReason.NOT_PROBED))
    return out


def evaluate(
    data: Any,
    *,
    uses_ssh_fallback: bool,
    ssh_seen: bool,
    now: datetime,
    record: RouterRecord | None = None,
    config_enabled: bool = True,
    provider: ConfigCapabilityProvider | None = None,
) -> dict[str, CapabilityStatus]:
    """All core capabilities of one router from one finished poll."""
    info = getattr(data, "router_info", None)
    info = info if isinstance(info, Mapping) else {}
    features = getattr(data, "features", None)
    features = features if isinstance(features, Mapping) else {}
    updates = getattr(data, "updates_available", None)
    updates = updates if isinstance(updates, Mapping) else {}

    items: list[CapabilityStatus] = [
        _available(
            Capability.TRANSPORT_UBUS,
            SOURCE_SSH_FLAG,
            now,
            detail={"ssh_fallback_used": bool(uses_ssh_fallback)},
        ),
        (
            _available(Capability.TRANSPORT_SSH, SOURCE_SSH_FLAG, now)
            if ssh_seen
            else _unknown(Capability.TRANSPORT_SSH, SOURCE_SSH_FLAG, now)
        ),
        _system_board(info, now),
        (
            _available(Capability.DATA_WIRELESS, SOURCE_WIFI_RADIOS, now)
            if getattr(data, "wifi_radios", None)
            else _unavailable(Capability.DATA_WIRELESS, SOURCE_WIFI_RADIOS, now)
        ),
        (
            _available(Capability.DATA_HOSTAPD_CLIENTS, SOURCE_AP_INTERFACES, now)
            if getattr(data, "ap_interfaces", None)
            else _unavailable(
                Capability.DATA_HOSTAPD_CLIENTS,
                SOURCE_AP_INTERFACES,
                now,
                permissions=("ubus:hostapd.*",),
            )
        ),
        _lldp(getattr(data, "lldp_status", None), now),
        _logs(getattr(data, "log_status", None), now),
        _unknown(Capability.STREAM_UBUS, SOURCE_STREAM, now),
    ]
    for key, cap in FEATURE_CAPABILITIES.items():
        source = f"features.{key}"
        value = features.get(key)
        if value is True:
            items.append(_available(cap, source, now))
        elif value is False:
            items.append(_unavailable(cap, source, now))
        else:
            items.append(_unknown(cap, source, now))
    items.extend(_packages(updates.get("package_manager"), now))
    items.extend(
        _config(record, config_enabled=config_enabled, provider=provider, now=now)
    )
    return {status.capability: status for status in items}


@dataclass(slots=True)
class MergeResult:
    """Outcome of :func:`merge`."""

    capabilities: dict[str, CapabilityStatus]
    changes: list[dict[str, str]] = field(default_factory=list)
    first_detections: int = 0
    kept_stale: int = 0
    updated: int = 0

    @property
    def stored_changed(self) -> bool:
        """True if anything worth persisting changed."""
        return bool(self.changes or self.first_detections or self.updated)


def _same(a: CapabilityStatus, b: CapabilityStatus) -> bool:
    return (
        a.state is b.state
        and a.reason == b.reason
        and a.source == b.source
        and a.reason_text == b.reason_text
        and a.required_permissions == b.required_permissions
        and dict(a.detail) == dict(b.detail)
    )


def merge(
    previous: Mapping[str, CapabilityStatus],
    fresh: Mapping[str, CapabilityStatus],
) -> MergeResult:
    """Apply ``fresh`` to ``previous`` (see module docstring for the rules)."""
    result = MergeResult(capabilities=dict(previous))
    for name, new in fresh.items():
        old = previous.get(name)
        if old is None:
            result.capabilities[name] = new
            result.first_detections += 1
            continue
        if _same(old, new):
            continue
        new_known = new.state is not CapabilityState.UNKNOWN
        old_known = old.state is not CapabilityState.UNKNOWN
        # config.* follow the provider/option exactly (a new provider turns
        # no_provider into not_probed); everything else keeps its last
        # known state through a hiccup.
        if not new_known and old_known and name not in CONFIG_CAPABILITIES:
            result.kept_stale += 1
            continue
        result.capabilities[name] = new
        if not old_known and new_known:
            result.first_detections += 1
        elif not old_known or not new_known or old.state is new.state:
            result.updated += 1
        else:
            result.changes.append(
                {"capability": name, "from": old.state.value, "to": new.state.value}
            )
    result.changes.sort(key=lambda c: c["capability"])
    return result
