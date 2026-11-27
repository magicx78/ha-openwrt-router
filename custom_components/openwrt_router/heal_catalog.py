"""Self-Healing: the closed, versioned catalog of typed actions (package D).

Pure module (no Home Assistant import, no clock, no router call). The
catalog is data: one frozen :class:`CatalogEntry` per action type with its
version, its parameters as closed sets, the router call it would map to (a
name only; nothing here calls anything), the ACL it needs, its status
(ready or disabled, with the reason), its base risk, the context facts the
policy needs, the verification probes it would use and the honest rollback
statement. Developer document: ``docs/self-healing.md`` §7.

Closed means:

* :data:`CATALOG` is a read-only mapping built once at import; there is no
  function that adds, replaces or removes an action. An action type from a
  frontend, a service call or an incident string is looked up, never
  interpreted.
* Every parameter is a closed set (``choices``) or a core id of a fixed
  shape (``id_prefix`` + 32 hex). A value is taken only if it is a plain
  ``str`` and equal to a member; nothing that could reach a shell passes.
* Unknown action types and unknown, missing or bad parameters are refused
  with a :class:`CatalogError` whose message and ``code`` never repeat the
  value.

Owner decisions (2026-11-27): ``service.restart`` for dnsmasq and odhcpd is
the only write intended for the first write release (Risk 2, approval
only). Radio restart, reboot, restore and interface up/down are modelled
but disabled. Client actions (deauth, block, forced roaming), firewall,
VLAN, management IP, routing and firmware changes, ``network reload`` and a
``wpad`` restart are not in the catalog at all. Release 1.53.0 is Observe
only: :data:`EXECUTABLE_IN_RELEASE` names the only action that may "run",
and it makes no router call.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from .heal_model import (
    Component,
    ComponentKind,
    RiskClass,
    Rollback,
    RollbackMechanism,
    RollbackStatus,
)

_LOGGER = logging.getLogger(__name__)

CATALOG_VERSION: Final = 1

# The services a typed restart may name (owner decision). Not: wpad (the
# Wi-Fi of every client), network (a full reload), firewall, dropbear,
# uhttpd, rpcd (management path and security).
SERVICE_NAMES: Final = ("dnsmasq", "odhcpd")
# uci wifi-device sections as OpenWrt names them (disabled action).
RADIO_NAMES: Final = tuple(f"radio{i}" for i in range(4))
# the standard interface names only (disabled action; DECIDED: no free
# interface name, not even a validated one).
INTERFACE_NAMES: Final = ("lan", "wan", "wan6")
BACKUP_ID_PREFIX: Final = "bkp_"

_ACTION_TYPE_RE: Final = re.compile(
    r"[a-z][a-z0-9_]{0,31}(\.[a-z][a-z0-9_]{0,31}){1,3}"
)
_HEX32_RE: Final = re.compile(r"[0-9a-f]{32}")


class CatalogStatus(StrEnum):
    """Whether an action may be proposed as executable at all."""

    READY = "ready"  # may be proposed; executable once its release allows it
    DISABLED = "disabled"  # modelled only: never proposable as executable


class RollbackKind(StrEnum):
    """The honest rollback statement of an action (no mechanism exists).

    There is no confirmed commit, no watchdog and no out-of-band path on the
    platform (docs §1); :class:`heal_model.RollbackMechanism` has only
    ``none``. These kinds say what a human can expect, nothing more.
    """

    READ_ONLY = "read_only"  # nothing on the router changes
    # a second call (``up`` after ``down``) undoes it, but only while the
    # management path holds; otherwise manual recovery
    SECOND_CALL = "second_call"
    MANUAL_RECOVERY = "manual_recovery"  # no rollback: manual recovery


class Disruption(StrEnum):
    """What the action interrupts while it runs (used by the risk rules)."""

    NONE = "none"
    SERVICE = "service"
    RADIO = "radio"
    INTERFACE = "interface"
    ROUTER = "router"


class CatalogError(ValueError):
    """A request outside the catalog; ``code`` says why (never the value)."""

    def __init__(self, code: str) -> None:
        """Refusal with a reason code."""
        super().__init__(f"refused: {code}")
        self.code = code


@dataclass(frozen=True, kw_only=True, slots=True)
class ParamSpec:
    """One parameter: a closed set of names, or a core id of fixed shape."""

    name: str
    choices: tuple[str, ...] = ()
    id_prefix: str | None = None

    def accepts(self, value: Any) -> bool:
        """``value`` is a plain str inside the closed set."""
        if type(value) is not str:
            return False
        if self.choices:
            return value in self.choices
        if self.id_prefix is None or not value.startswith(self.id_prefix):
            return False
        return _HEX32_RE.fullmatch(value[len(self.id_prefix) :]) is not None


@dataclass(frozen=True, kw_only=True, slots=True)
class CatalogEntry:
    """One typed action of the catalog (data only)."""

    action_type: str
    version: int
    params: tuple[ParamSpec, ...]
    # the router call it would map to, as a name; None: no router call
    router_call: str | None
    required_acl: tuple[str, ...]
    acl_granted: bool  # granted by the integration's ACL v8 file
    status: CatalogStatus
    status_reason: str | None
    base_risk: RiskClass
    writes: bool  # changes state on the router
    disruption: Disruption
    target_kind: ComponentKind | None
    target_param: str | None
    needs_facts: tuple[str, ...]  # RiskContext fields the policy needs
    verification_probes: tuple[str, ...]
    rollback: RollbackKind
    rollback_statement: str
    est_outage_s: int = 0


@dataclass(frozen=True, kw_only=True, slots=True)
class ValidatedAction:
    """An action type and parameters that passed the catalog."""

    entry: CatalogEntry
    params: Mapping[str, str] = field(default_factory=dict)
    components: tuple[Component, ...] = ()

    @property
    def action_type(self) -> str:
        """The catalog id."""
        return self.entry.action_type


# Facts every write needs (the policy reads them from ``RiskContext``).
_WRITE_FACTS: Final = (
    "role",
    "identity_confirmed",
    "reachable",
    "open_security_findings",
    "in_maintenance",
    "concurrent_repair",
    "breaker_open",
)


def _entry(**kwargs: Any) -> CatalogEntry:
    return CatalogEntry(**kwargs)


_ENTRIES: Final = (
    _entry(
        action_type="observe.evaluate",
        version=1,
        params=(),
        router_call=None,
        required_acl=(),
        acl_granted=True,
        status=CatalogStatus.READY,
        status_reason=None,
        base_risk=RiskClass.READ_ONLY,
        writes=False,
        disruption=Disruption.NONE,
        target_kind=None,
        target_param=None,
        needs_facts=(),
        verification_probes=(),
        rollback=RollbackKind.READ_ONLY,
        rollback_statement="read_only_nothing_changes",
    ),
    _entry(
        action_type="diag.refresh",
        version=1,
        params=(),
        router_call="coordinator.refresh",
        required_acl=("existing_poll_reads",),
        acl_granted=True,
        status=CatalogStatus.READY,
        status_reason=None,
        base_risk=RiskClass.LOW,
        writes=False,
        disruption=Disruption.NONE,
        target_kind=None,
        target_param=None,
        needs_facts=(),
        verification_probes=("poll_arrived",),
        rollback=RollbackKind.READ_ONLY,
        rollback_statement="read_only_nothing_changes",
    ),
    _entry(
        action_type="diag.ha_probes",
        version=1,
        params=(),
        router_call="diag.manual_run",
        required_acl=(),
        acl_granted=True,
        status=CatalogStatus.READY,
        status_reason=None,
        base_risk=RiskClass.LOW,
        writes=False,
        disruption=Disruption.NONE,
        target_kind=None,
        target_param=None,
        needs_facts=("diag_enabled",),
        verification_probes=("probe_results",),
        rollback=RollbackKind.READ_ONLY,
        rollback_statement="read_only_nothing_changes",
    ),
    _entry(
        action_type="service.restart",
        version=1,
        params=(ParamSpec(name="service", choices=SERVICE_NAMES),),
        router_call="rc.init.restart",
        required_acl=("rc/init",),
        acl_granted=False,
        status=CatalogStatus.READY,
        status_reason="first_write_release_approval_only",
        base_risk=RiskClass.MEDIUM,
        writes=True,
        disruption=Disruption.SERVICE,
        target_kind=ComponentKind.SERVICE,
        target_param="service",
        needs_facts=(*_WRITE_FACTS, "service_enabled", "clients_on_router"),
        verification_probes=(
            "service_running_new_pid",
            "service_stable_two_polls",
            "root_incident_not_reopened",
            "no_new_service_error_lines",
            "ha_dns_probe_if_configured",
        ),
        rollback=RollbackKind.MANUAL_RECOVERY,
        rollback_statement="no_config_change_manual_if_not_back",
        est_outage_s=5,
    ),
    _entry(
        action_type="wifi.radio_restart",
        version=1,
        params=(ParamSpec(name="radio", choices=RADIO_NAMES),),
        router_call="network.wireless.down_up",
        required_acl=("network.wireless/down", "network.wireless/up"),
        acl_granted=True,
        status=CatalogStatus.DISABLED,
        status_reason="call_unverified_on_fleet",
        base_risk=RiskClass.MEDIUM,
        writes=True,
        disruption=Disruption.RADIO,
        target_kind=ComponentKind.RADIO,
        target_param="radio",
        needs_facts=(
            *_WRITE_FACTS,
            "target_is_wireless_uplink",
            "target_on_mgmt_path",
            "target_carries_dependants",
            "clients_on_target",
        ),
        verification_probes=(
            "radio_up_ap_present",
            "clients_back_to_most",
            "no_new_mass_disconnect",
        ),
        rollback=RollbackKind.SECOND_CALL,
        rollback_statement="up_undoes_down_only_while_path_holds",
        est_outage_s=30,
    ),
    _entry(
        action_type="router.reboot",
        version=1,
        params=(),
        router_call="system.reboot",
        required_acl=("system/reboot",),
        acl_granted=False,
        status=CatalogStatus.DISABLED,
        status_reason="modelled_blocked_no_out_of_band",
        base_risk=RiskClass.HIGH,
        writes=True,
        disruption=Disruption.ROUTER,
        target_kind=None,
        target_param=None,
        needs_facts=(*_WRITE_FACTS, "dependants", "clients_on_router"),
        verification_probes=("router_back_and_polled",),
        rollback=RollbackKind.MANUAL_RECOVERY,
        rollback_statement="no_rollback_no_out_of_band_path",
        est_outage_s=120,
    ),
    _entry(
        action_type="config.restore",
        version=1,
        params=(ParamSpec(name="version_id", id_prefix=BACKUP_ID_PREFIX),),
        router_call=None,
        required_acl=(),
        acl_granted=False,
        status=CatalogStatus.DISABLED,
        status_reason="restore_dry_run_only",
        base_risk=RiskClass.HIGH,
        writes=True,
        disruption=Disruption.ROUTER,
        target_kind=ComponentKind.CONFIG,
        target_param="version_id",
        needs_facts=(*_WRITE_FACTS, "dependants", "clients_on_router"),
        verification_probes=("config_matches_version", "router_back_and_polled"),
        rollback=RollbackKind.MANUAL_RECOVERY,
        rollback_statement="no_rollback_restore_is_manual",
        est_outage_s=120,
    ),
    _entry(
        action_type="interface.cycle",
        version=1,
        params=(ParamSpec(name="interface", choices=INTERFACE_NAMES),),
        router_call="network.interface.down_up",
        required_acl=("network.interface/down", "network.interface/up"),
        acl_granted=False,
        status=CatalogStatus.DISABLED,
        status_reason="recommendation_only_no_acl",
        base_risk=RiskClass.HIGH,
        writes=True,
        disruption=Disruption.INTERFACE,
        target_kind=ComponentKind.INTERFACE,
        target_param="interface",
        needs_facts=(
            *_WRITE_FACTS,
            "target_on_mgmt_path",
            "target_carries_dependants",
            "dependants",
            "clients_on_router",
        ),
        verification_probes=("interface_up", "uplink_stable"),
        rollback=RollbackKind.SECOND_CALL,
        rollback_statement="up_undoes_down_only_while_path_holds",
        est_outage_s=30,
    ),
)

CATALOG: Final[Mapping[str, CatalogEntry]] = MappingProxyType(
    {e.action_type: e for e in _ENTRIES}
)

# Release 1.53.0 is Observe only: no action that calls a router may run.
# The write package (C2, 1.54.0) adds ``service.restart`` here.
EXECUTABLE_IN_RELEASE: Final = frozenset({"observe.evaluate"})

# Families that are never in the catalog, with their own reason (only for
# the explanation; such an id is refused like every unknown one).
NEVER_IN_CATALOG: Final[Mapping[str, str]] = MappingProxyType(
    {
        "client.": "never_client_action",
        "firewall.": "never_firewall",
        "vlan.": "never_vlan",
        "mgmt.": "never_management_ip",
        "management.": "never_management_ip",
        "routing.": "never_routing",
        "route.": "never_routing",
        "firmware.": "never_firmware",
        "sysupgrade.": "never_firmware",
        "network.": "never_network_reload",
        "wpad.": "never_wpad_restart",
        "uci.": "never_config_write",
        "shell.": "never_shell",
        "ssh.": "never_shell",
    }
)

REFUSAL_CODES: Final = frozenset(
    {
        "action_type_invalid",
        "unknown_action",
        "params_invalid",
        "param_unknown",
        "param_missing",
        "param_value_invalid",
        *NEVER_IN_CATALOG.values(),
    }
)
STATUS_REASONS: Final = frozenset(
    e.status_reason for e in _ENTRIES if e.status_reason is not None
)


def refusal_reason(action_type: Any) -> str:
    """Why ``action_type`` is not in the catalog (a code, no value)."""
    if type(action_type) is not str or _ACTION_TYPE_RE.fullmatch(action_type) is None:
        return "action_type_invalid"
    for prefix, code in NEVER_IN_CATALOG.items():
        if action_type.startswith(prefix):
            return code
    return "unknown_action"


def entry(action_type: Any) -> CatalogEntry:
    """The entry of ``action_type``; raises :class:`CatalogError` if unknown."""
    if type(action_type) is str:
        found = CATALOG.get(action_type)
        if found is not None:
            return found
    raise CatalogError(refusal_reason(action_type))


def _params(value: Any) -> Mapping[Any, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise CatalogError("params_invalid")
    return value


def validate_params(
    found: CatalogEntry, params: Any, *, subset: bool = False
) -> dict[str, str]:
    """The parameters of ``found`` as plain strs from their closed sets.

    ``subset``: missing parameters are allowed (an allowlist entry names a
    subset); unknown names and values outside the sets never are.
    """
    raw = _params(params)
    specs = {p.name: p for p in found.params}
    out: dict[str, str] = {}
    for key in raw:
        if type(key) is not str or key not in specs:
            raise CatalogError("param_unknown")
    for name, spec in specs.items():
        if name not in raw:
            if subset:
                continue
            raise CatalogError("param_missing")
        value = raw[name]
        if not spec.accepts(value):
            raise CatalogError("param_value_invalid")
        out[name] = value
    return out


def validate(action_type: Any, params: Any) -> ValidatedAction:
    """``action_type`` with ``params`` as a typed action, or :class:`CatalogError`.

    Validation is about shape only: a disabled action validates (the policy
    refuses it as Unsupported with its reason).
    """
    found = entry(action_type)
    clean = validate_params(found, params)
    components: tuple[Component, ...] = ()
    if found.target_param is not None and found.target_kind is not None:
        components = (
            Component(kind=found.target_kind, name=clean[found.target_param]),
        )
    return ValidatedAction(
        entry=found, params=MappingProxyType(clean), components=components
    )


def try_validate(
    action_type: Any, params: Any
) -> tuple[ValidatedAction | None, str | None]:
    """:func:`validate` without raising: (action, None) or (None, code)."""
    try:
        return validate(action_type, params), None
    except CatalogError as err:
        return None, err.code


def rollback_record(found: CatalogEntry) -> Rollback:
    """The model's rollback part for an action: the statement, no mechanism."""
    return Rollback(
        mechanism=RollbackMechanism.NONE,
        statement=found.rollback_statement,
        status=RollbackStatus.NOT_AVAILABLE,
    )


def catalog_table() -> list[dict[str, Any]]:
    """The catalog as plain JSON rows (for a view or the docs)."""
    rows: list[dict[str, Any]] = []
    for e in _ENTRIES:
        rows.append(
            {
                "action_type": e.action_type,
                "version": e.version,
                "params": [
                    {
                        "name": p.name,
                        "choices": list(p.choices),
                        "id_prefix": p.id_prefix,
                    }
                    for p in e.params
                ],
                "router_call": e.router_call,
                "required_acl": list(e.required_acl),
                "acl_granted": e.acl_granted,
                "status": e.status.value,
                "status_reason": e.status_reason,
                "base_risk": int(e.base_risk),
                "writes": e.writes,
                "disruption": e.disruption.value,
                "needs_facts": list(e.needs_facts),
                "verification_probes": list(e.verification_probes),
                "rollback": e.rollback.value,
                "rollback_statement": e.rollback_statement,
                "est_outage_s": e.est_outage_s,
                "executable_in_release": e.action_type in EXECUTABLE_IN_RELEASE,
            }
        )
    return rows


__all__ = [
    "CATALOG",
    "CATALOG_VERSION",
    "EXECUTABLE_IN_RELEASE",
    "NEVER_IN_CATALOG",
    "CatalogEntry",
    "CatalogError",
    "CatalogStatus",
    "Disruption",
    "ParamSpec",
    "RollbackKind",
    "ValidatedAction",
    "catalog_table",
    "entry",
    "refusal_reason",
    "rollback_record",
    "try_validate",
    "validate",
    "validate_params",
]
