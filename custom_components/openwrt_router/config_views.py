"""HTTP routes of the configuration manager (plan 2026-11-18, section 7).

Base ``/api/openwrt_topology/config``; routes R1 to R20 of the plan. Rules
that hold for every route, checked in this order before anything else:

* ``requires_auth`` (HA answers 401 without a login),
* admin only (403), also while the topology panel is open to every user,
* 410 after the last unload (the panel's soft-disable flag),
* 503 without a running configuration manager,
* POST routes: 409 ``provider_conflict`` while another provider holds the
  core's slot (the panel then only reads).

Inputs: ids only in their strict shape (``rtr_``/``bkp_``/``apr_`` + 32 hex,
drift ids 1-128 of ``[A-Za-z0-9_-]``) and never used as a path; bodies at
most 4 KB, JSON objects, unknown keys rejected. Outputs: actor fields become
``{"kind", "mine"}``, user ids are pseudonymised with the module key
(``ConfigManagerRuntime.async_route_salt``) and every JSON body goes
through ``config_mask_for_output`` (the core's ``mask_for_output`` plus the
bridge names); ``Cache-Control: no-store`` on every response. Error bodies are built from the error code
(``{message, code, error_class, retryable, details}``), never from router
text. There is no route that deletes versions or executes a restore.

Network: none here. Every router call happens in the core and its provider.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from aiohttp import web
from homeassistant.components.http import KEY_HASS_USER, HomeAssistantView
from homeassistant.core import Context, HomeAssistant, callback
from homeassistant.util import dt as dt_util

from .acl_provisioning import (
    ACL_BACKUP_PREFIX,
    ACL_FILE_PATH,
    DEFAULT_TIER_REGISTRY,
    TIER_CONFIG_BACKUP_READ,
    AclTierError,
    _rollback_command,
)
from .config_const import ROUTER_BUSY_RETRY_AFTER_S, config_mask_for_output
from .const import (
    DATA_CONFIG_VIEWS_BOUND,
    DEFAULT_CONFIG_BACKUP_TIME,
    OPTION_CONFIG_BACKUP_TIME,
)
from .core_errors import (
    ApprovalInvalidError,
    BackupIntegrityError,
    BackupNotFoundError,
    CapabilityUnavailableError,
    ConfigApiError,
    ProviderConflictError,
    RouterNotFoundError,
)
from .core_masking import pseudonymise_user_ids
from .core_models import (
    APPROVAL_TTL,
    CONFIG_CAPABILITIES,
    ArtifactKind,
    Capability,
    ConfigRef,
    DriftAckState,
    GuardedAction,
    async_actor_from_context,
    is_valid_id,
)
from .topology_panel import _PANEL_VIEW_DISABLED_KEY

try:
    from homeassistant.helpers.http import KEY_HASS
except ImportError:  # pragma: no cover - older Home Assistant
    KEY_HASS = "hass"  # type: ignore[assignment]

_LOGGER = logging.getLogger(__name__)

BASE_URL = "/api/openwrt_topology/config"
VIEW_NAME_PREFIX = "api:openwrt_topology:config:"
BODY_MAX_BYTES = 4096
LIST_LIMIT_DEFAULT = 50
LIST_LIMIT_MAX = 200
RETRY_AFTER_SECONDS = ROUTER_BUSY_RETRY_AFTER_S
# R15 body field: required (true) to approve an export (plain-text secrets).
ACK_PLAINTEXT = "acknowledge_plaintext"
LIVE = "live"

NO_STORE = {"Cache-Control": "no-store"}

_DRIFT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}")
_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_UNSAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]")
_FILENAME_MAX = 100

# Approval actions these routes may decide, redeem or execute (R14-R20).
PANEL_ACTIONS = frozenset(
    {
        str(GuardedAction.EXPORT),
        str(GuardedAction.ACL_DEPLOY),
        str(GuardedAction.SSH_PIN_CONFIRM),
        str(GuardedAction.SSH_PIN_RESET),
    }
)
SSH_PIN_OPS = ("confirm", "reset")
_EXPORT_CONTENT_TYPES = frozenset({"application/gzip", "application/json"})
_ACK_STATES = frozenset(s.value for s in DriftAckState)
_ARTIFACTS = frozenset(k.value for k in ArtifactKind)

# Error code -> HTTP status (plan 7.3).
_STATUS_BY_CODE: dict[str, int] = {
    "router_not_found": 404,
    "backup_not_found": 404,
    "authorization_denied": 403,
    "approval_required": 409,
    "approval_invalid": 409,
    "operation_in_progress": 409,
    "rate_limited": 429,
    "version_protected": 409,
    "provider_conflict": 409,
    "capability_unavailable": 409,
    "backup_integrity_failed": 422,
    "backup_incomplete": 422,
    "restore_incompatible": 422,
    "storage_ref_invalid": 422,
    "router_unavailable": 503,
    "provider_unavailable": 503,
    "core_not_running": 503,
    "operation_timeout": 504,
    "router_auth_failed": 502,
    "router_permission_denied": 502,
    "provider_error": 502,
    "artifact_too_large": 502,
    "storage_full": 507,
    "storage_error": 500,
}
# Codes the table does not name (e.g. the generic ``config_api_error`` of
# "no pending SSH pin"): by error class, else 500.
_STATUS_BY_CLASS: dict[str, int] = {
    "not_found": 404,
    "denied": 403,
    "conflict": 409,
    "approval": 409,
    "busy": 409,
    "invalid": 422,
    "incomplete": 422,
    "checksum_mismatch": 422,
    "incompatible": 422,
    "not_available": 503,
    "unreachable": 503,
    "timeout": 504,
}
# The text of an error body comes from its code only.
_MESSAGES: dict[str, str] = {
    "router_not_found": "Router not found",
    "backup_not_found": "Version not found",
    "authorization_denied": "Administrators only",
    "approval_required": "This action needs an approval first",
    "approval_invalid": "The approval is not valid (expired, used or unknown)",
    "operation_in_progress": "Another configuration operation is running",
    "rate_limited": "Too soon after the last manual run, try again later",
    "version_protected": "The version is protected",
    "provider_conflict": "Another configuration provider is registered",
    "capability_unavailable": "Not available for this router",
    "backup_integrity_failed": "The stored file does not match its checksum",
    "backup_incomplete": "The version is incomplete",
    "restore_incompatible": "The version does not fit this router",
    "storage_ref_invalid": "The storage reference of the version is invalid",
    "router_unavailable": "The router is not reachable",
    "provider_unavailable": "The configuration provider is not available",
    "core_not_running": "The configuration manager is not running",
    "operation_timeout": "The router did not answer in time",
    "router_auth_failed": "The router rejected the login",
    "router_permission_denied": "The router does not allow this call",
    "provider_error": "The configuration provider failed",
    "artifact_too_large": "The file is too large",
    "storage_full": "The version storage is full",
    "storage_error": "The version storage failed",
    "integration_not_loaded": "OpenWrt Router integration not loaded",
    "invalid_request": "Invalid request",
    "plaintext_not_acknowledged": (
        "Approving an export needs acknowledge_plaintext: the file contains "
        "every secret of the router in plain text"
    ),
    "body_too_large": "The request body is too large",
    "internal": "Internal error",
}
_DEFAULT_MESSAGE = "The request failed"
_DETAIL_KEYS = ("capability", "reason", "state", "field", "artifact")


# -- output ---------------------------------------------------------------------------

_ACTOR_KEYS = frozenset({"created_by", "requested_by", "decided_by", "actor", "by"})


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    return value if isinstance(value, str) else None


def _actor_view(value: Any, user_id: str | None) -> dict[str, Any] | None:
    """``{"kind", "mine"}`` for an actor dict; never the user id."""
    if not isinstance(value, Mapping):
        return None
    kind = value.get("kind")
    return {
        "kind": kind if isinstance(kind, str) else "system",
        "mine": bool(user_id) and value.get("user_id") == user_id,
    }


def _is_actor_key(key: Any) -> bool:
    return isinstance(key, str) and (key in _ACTOR_KEYS or key.endswith("_by"))


def _actor_field(value: Any, user_id: str | None, depth: int) -> Any:
    """An actor dict or a bare user id string (e.g. ``confirmed_by``)."""
    if isinstance(value, Mapping):
        return _actor_view(value, user_id)
    if isinstance(value, str):
        return {"kind": "user", "mine": bool(user_id) and value == user_id}
    return _replace_actors(value, user_id, depth + 1)


def _replace_actors(data: Any, user_id: str | None, depth: int = 0) -> Any:
    if depth > 32:
        return None
    if isinstance(data, Mapping):
        return {
            key: (
                _actor_field(value, user_id, depth)
                if _is_actor_key(key)
                else _replace_actors(value, user_id, depth + 1)
            )
            for key, value in data.items()
        }
    if isinstance(data, list | tuple):
        return [_replace_actors(value, user_id, depth + 1) for value in data]
    return data


def output(data: Any, salt: bytes, user_id: str | None) -> Any:
    """The last step of every JSON body: actors, pseudonyms, masking."""
    return config_mask_for_output(
        pseudonymise_user_ids(_replace_actors(data, user_id), salt)
    )


# Version warning ``ssh_host_key:<reason>`` (config_provider.WARN_SSH_HOST_KEY)
# with the core's fixed host-key reasons (config_collector._pin_reason). The
# text masker reads it as a ``name: value`` pair ("key") and masks the reason;
# exactly these codes come back. Fingerprints are never a warning item.
_HOST_KEY_WARNINGS = frozenset(
    f"ssh_host_key:{reason}"
    for reason in (
        "pin_pending",
        "pin_refused",
        "mismatch",
        "algorithm_unavailable",
        "pin_invalid",
        "pin_save_failed",
        "pin_store_unavailable",
        "pin_unavailable",
        "no_host_key",
        "refused",
    )
)


def restore_warning_codes(raw: Any, body: Any, depth: int = 0) -> None:
    """Put fixed host-key warning codes back that the masker cut (1.46.1).

    Walks the unmasked ``raw`` result and the masked ``body`` side by side;
    in every ``warnings`` list an item comes back only if the unmasked item
    is one of ``_HOST_KEY_WARNINGS``. Everything else stays masked.
    """
    if depth > 8:
        return
    if isinstance(raw, Mapping) and isinstance(body, dict):
        for key, value in body.items():
            raw_value = raw.get(key)
            if (
                key == "warnings"
                and isinstance(value, list)
                and isinstance(raw_value, list | tuple)
                and len(value) == len(raw_value)
            ):
                body[key] = [
                    old if isinstance(old, str) and old in _HOST_KEY_WARNINGS else new
                    for old, new in zip(raw_value, value, strict=True)
                ]
            else:
                restore_warning_codes(raw_value, value, depth + 1)
    elif (
        isinstance(raw, list | tuple)
        and isinstance(body, list)
        and len(raw) == len(body)
    ):
        for old, new in zip(raw, body, strict=True):
            restore_warning_codes(old, new, depth + 1)


def _tokens(values: Iterable[Any]) -> list[str]:
    """Machine codes only (free text is dropped)."""
    return [v for v in values if isinstance(v, str) and _TOKEN.fullmatch(v)]


def capability_view(status: Any) -> dict[str, Any]:
    reason = getattr(status, "reason", None)
    return {
        "state": str(getattr(getattr(status, "state", None), "value", "unknown")),
        "reason": reason if isinstance(reason, str) and reason else None,
        "required_permissions": _tokens(getattr(status, "required_permissions", ())),
    }


def version_view(record: Any) -> dict[str, Any]:
    """A version without storage locators and content fingerprints."""
    data = record.to_dict()
    validation = record.validation
    return {
        "backup_id": record.backup_id,
        "router_id": record.router_id,
        "created_at": _iso(record.created_at),
        "last_seen_at": _iso(record.last_seen_at),
        "reason": record.reason.value,
        "backup_type": record.backup_type.value,
        "status": record.status.value,
        "error_class": data.get("error_class"),
        "protected": record.protected,
        "usable": record.usable,
        "created_by": data.get("created_by"),
        "openwrt_version": record.openwrt_version,
        "board_name": record.board_name,
        "fetch_method": record.fetch_method,
        "validation": {
            "state": validation.status.value,
            "status": validation.status.value,
            "checked_at": _iso(validation.checked_at),
        },
        "warnings": _tokens(record.warnings),
        "note": record.note,
        "contains_secrets": record.contains_secrets,
        "artifacts": [
            {
                "kind": kind,
                "size_bytes": ref.size_bytes,
                "sha256": ref.sha256,
                "content_type": ref.content_type,
            }
            for kind, ref in sorted(record.artifacts.items())
        ],
        "size_bytes": record.size_bytes,
        "sha256": record.sha256,
    }


def approval_view(approval: Any) -> dict[str, Any]:
    data = approval.to_dict()
    return {
        "approval_id": data.get("approval_id"),
        "action": data.get("action"),
        "router_id": data.get("router_id"),
        "subject_id": data.get("subject_id"),
        "status": data.get("status"),
        "requested_by": data.get("requested_by"),
        "requested_at": data.get("requested_at"),
        "expires_at": data.get("expires_at"),
        "decided_by": data.get("decided_by"),
        "decided_at": data.get("decided_at"),
    }


def drift_view(summary: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """The runtime's drift summary for the panel (``clear`` -> ``clean``)."""
    if summary is None:
        return None
    state = summary.get("state")
    state = "clean" if state == "clear" else state
    return {
        "state": state,
        "open": state == "open",
        "drift_id": summary.get("drift_id"),
        "critical_count": summary.get("critical_count", 0),
        "unknown_count": summary.get("unknown_count", 0),
        "comparison": summary.get("comparison"),
        "baseline_backup_id": summary.get("baseline_backup_id"),
        "checked_at": _iso(summary.get("checked_at")),
    }


def change_view(change: Mapping[str, Any]) -> dict[str, Any]:
    """One change (``ConfigChange.to_dict``: secrets already masked)."""
    kind = change.get("kind")
    op = "changed" if kind == "modified" else kind
    return {
        "area": change.get("area"),
        "risk": change.get("risk"),
        "config": change.get("config"),
        "section": change.get("section"),
        "section_type": change.get("section_type"),
        "option": change.get("option"),
        "op": op,
        "old": change.get("before"),
        "new": change.get("after"),
        "secret": change.get("secret") is True,
    }


# Restore check (plan 7.7): keys the panel has a text for.
_STEP_INSTRUCTIONS = {"archive_restore": "config.restore.manual_upload"}
_ACCESS_CONFIGS = frozenset({"dropbear", "uhttpd", "rpcd"})
_ACCESS_NETWORK_OPTIONS = frozenset({"ipaddr", "netmask", "proto", "gateway"})
INSTR_BLOCKED = "restore_blocked"
INSTR_CONSOLE_FAILSAFE = "restore_prepare_console_failsafe"
INSTR_NOT_REVERSIBLE = "restore_not_reversible"
INSTR_VERIFY_AFTER_REBOOT = "restore_verify_after_reboot"
FINDING_LOCKOUT_RISK = "lockout_risk"


def _touches_access(changes: Iterable[Mapping[str, Any]]) -> bool:
    """Access, management IP or firewall input change (lockout risk)."""
    for change in changes:
        config, option = change.get("config"), change.get("option")
        if config in _ACCESS_CONFIGS:
            return True
        if config == "firewall" and option in (None, "input"):
            return True
        if config == "network" and option in _ACCESS_NETWORK_OPTIONS:
            return True
    return False


def restore_view(plan: Any) -> dict[str, Any]:
    """Findings, manual steps and the checklist; nothing here executes."""
    findings = [
        {
            "code": issue.code,
            "blocking": issue.blocking,
            "level": "block" if issue.blocking else "warning",
        }
        for issue in plan.compatibility.issues
        if isinstance(issue.code, str) and _TOKEN.fullmatch(issue.code)
    ]
    steps = [
        {
            "order": step.order,
            "action": step.action,
            "instructions": _STEP_INSTRUCTIONS.get(step.action),
        }
        for step in plan.steps
    ]
    changes = (
        []
        if plan.diff is None
        else [change_view(c) for c in plan.diff.to_dict()["changes"]]
    )
    lockout = any(f["code"] == FINDING_LOCKOUT_RISK for f in findings)
    lockout = lockout or _touches_access(changes)
    instructions = _tokens(plan.instructions)

    def add(key: str) -> None:
        if key not in instructions:
            instructions.append(key)

    if not plan.compatibility.compatible:
        add(INSTR_BLOCKED)
    if lockout:
        add(INSTR_CONSOLE_FAILSAFE)
    add(INSTR_NOT_REVERSIBLE)
    add(INSTR_VERIFY_AFTER_REBOOT)
    return {
        "backup_id": plan.backup_id,
        "router_id": plan.target_router_id,
        "compatible": plan.compatibility.compatible,
        "findings": findings,
        "steps": steps,
        "warnings": _tokens(plan.warnings),
        "instructions": instructions,
        "lockout_risk": lockout,
        "requires_reboot": plan.requires_reboot
        or any(s["action"] == "reboot" for s in steps),
        "changes": changes,
        "expires_at": _iso(plan.created_at + APPROVAL_TTL),
        # Phase 1: a manual restore only; no route executes one.
        "manual": True,
        "executable": False,
    }


def safe_filename(name: Any) -> str:
    """``[A-Za-z0-9._-]`` only, no leading dot, at most 100 characters."""
    text = _UNSAFE_FILENAME.sub("_", name if isinstance(name, str) else "")
    text = text.lstrip(".")[:_FILENAME_MAX]
    return text or "config-backup.bin"


# -- errors ---------------------------------------------------------------------------


class RequestError(Exception):
    """A rejected request (400, 403, 404, 409, 410, 413, 503)."""

    def __init__(
        self,
        status: int,
        code: str,
        *,
        error_class: str = "invalid",
        retryable: bool = False,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.error_class = error_class
        self.retryable = retryable
        self.details = dict(details or {})


def _bad(field: str, reason: str = "invalid") -> RequestError:
    return RequestError(
        400, "invalid_request", details={"field": field, "reason": reason}
    )


def _details(details: Mapping[str, Any]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for key in _DETAIL_KEYS:
        value = details.get(key)
        if value is None and key in details:
            out[key] = None
        elif isinstance(value, str) and _TOKEN.fullmatch(value):
            out[key] = value
    return out


def error_response(
    status: int,
    code: str,
    *,
    error_class: str,
    retryable: bool,
    details: Mapping[str, Any] | None = None,
    retry_after: float | None = None,
) -> web.Response:
    """The masked error body; 409 busy and 429 carry ``Retry-After``."""
    body = {
        "message": _MESSAGES.get(code, _DEFAULT_MESSAGE),
        "code": code,
        "error_class": error_class,
        "retryable": retryable,
        "details": _details(details or {}),
    }
    headers = dict(NO_STORE)
    if code == "operation_in_progress":
        headers["Retry-After"] = str(RETRY_AFTER_SECONDS)
    elif code == "rate_limited" and retry_after is not None:
        headers["Retry-After"] = str(max(1, math.ceil(retry_after)))
    return HomeAssistantView.json(config_mask_for_output(body), status, headers=headers)


def status_for(err: ConfigApiError) -> int:
    status = _STATUS_BY_CODE.get(err.code)
    if status is None:
        status = _STATUS_BY_CLASS.get(err.error_class.value, 500)
    return status


def api_error_response(err: ConfigApiError, api: Any = None) -> web.Response:
    """The error body of a core error (code, class, retryable, details)."""
    details = dict(err.details)
    if isinstance(err, CapabilityUnavailableError):
        details["state"] = _capability_state(api, err)
    return error_response(
        status_for(err),
        err.code,
        error_class=err.error_class.value,
        retryable=err.retryable,
        details=details,
        retry_after=getattr(err, "retry_after", None),
    )


def _capability_state(api: Any, err: CapabilityUnavailableError) -> str:
    if err.reason == "disabled":
        return "disabled"
    if api is not None and err.router_id:
        try:
            return str(api.capability(err.router_id, err.capability).state.value)
        except Exception:  # noqa: BLE001 - unknown router: the generic state
            _LOGGER.debug("No capability state for the error body")
    return "unavailable"


def _disabled(
    router_id: str | None, capability: str = Capability.CONFIG_BACKUP
) -> None:
    """The option is off: refuse before the core or a router is asked."""
    raise CapabilityUnavailableError(
        capability=str(capability), reason="disabled", router_id=router_id
    )


# Reason code of a plain HTTP entry (config_provider.REASON_INSECURE_TRANSPORT).
REASON_INSECURE_TRANSPORT = "insecure_transport"


def _refuse_acl_on_http(runtime: Any, router_id: str) -> None:
    """L1: no backup tier (``cgi-io: backup``) for a plain HTTP entry.

    The right is useless there (no cgi-backup over HTTP) and would belong to
    a session whose token travels unencrypted. The tier is refused whole: a
    variant without that right is not in the tier registry.
    """
    if not runtime.cgi_transport_secure(router_id):
        raise CapabilityUnavailableError(
            capability=Capability.CONFIG_CGI_BACKUP.value,
            reason=REASON_INSECURE_TRANSPORT,
            router_id=router_id,
        )


# -- request context and validation -------------------------------------------------


@dataclass(frozen=True)
class RequestContext:
    """What every handler gets after the access checks."""

    hass: HomeAssistant
    runtime: Any
    api: Any
    actor: Any
    user_id: str | None
    # Pseudonym salt: the module key or a random salt of this run (never shown).
    salt: bytes = field(repr=False)

    def out(self, data: Any) -> Any:
        return output(data, self.salt, self.user_id)

    def router(self, router_id: Any) -> Any:
        """The router state of a path id (400 malformed, 404 unknown)."""
        if not is_valid_id(router_id, "rtr_"):
            raise _bad("router_id")
        state = self.runtime.routers.get(router_id)
        if state is None:
            raise RouterNotFoundError("Unknown router", router_id=router_id)
        return state

    async def backup(self, backup_id: Any, router_id: str | None = None) -> Any:
        """A version by path id; with ``router_id`` it must be that router's."""
        if not is_valid_id(backup_id, "bkp_"):
            raise _bad("backup_id")
        record = await self.api.async_get_backup(backup_id)
        if router_id is not None and record.router_id != router_id:
            raise BackupNotFoundError("Unknown version", router_id=router_id)
        return record

    def approval(self, approval_id: Any) -> Any:
        """A request of one of the panel's actions (others: 409)."""
        if not is_valid_id(approval_id, "apr_"):
            raise _bad("approval_id")
        approval = self.api.get_approval(approval_id)
        if str(approval.action) not in PANEL_ACTIONS:
            raise ApprovalInvalidError(
                "Not an action of this panel",
                details={"reason": "action_not_supported"},
            )
        return approval


def _note(field: str) -> Callable[[Any], str | None]:
    def check(value: Any) -> str | None:
        from .config_manager import validate_note

        try:
            return validate_note(value)
        except (TypeError, ValueError):
            raise _bad(field) from None

    return check


def _bool(field: str) -> Callable[[Any], bool]:
    def check(value: Any) -> bool:
        if not isinstance(value, bool):
            raise _bad(field)
        return value

    return check


def _choice(field: str, choices: frozenset[str]) -> Callable[[Any], str]:
    def check(value: Any) -> str:
        if not isinstance(value, str) or value not in choices:
            raise _bad(field)
        return value

    return check


async def read_body(
    request: web.Request,
    fields: Mapping[str, Callable[[Any], Any]] | None = None,
    *,
    required: Iterable[str] = (),
) -> dict[str, Any]:
    """A JSON object of at most 4 KB with only the known keys."""
    fields = fields or {}
    length = request.content_length
    if length is not None and length > BODY_MAX_BYTES:
        raise RequestError(413, "body_too_large")
    chunks: list[bytes] = []
    size = 0
    while chunk := await request.content.read(BODY_MAX_BYTES + 1 - size):
        size += len(chunk)
        if size > BODY_MAX_BYTES:  # also a chunked body without a length
            raise RequestError(413, "body_too_large")
        chunks.append(chunk)
    raw = b"".join(chunks)
    if not raw.strip():
        data: Any = {}
    else:
        try:
            data = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise _bad("body", "not_json") from None
        except RecursionError:
            # Nesting deeper than the parser follows ("[" * 4000 fits in
            # 4 KiB): a bad body, not a server error.
            raise _bad("body", "invalid_body") from None
    if not isinstance(data, dict):
        raise _bad("body", "not_an_object")
    if any(key not in fields for key in data):
        raise _bad("body", "unknown_key")
    for key in required:
        if key not in data:
            raise _bad(key, "missing")
    return {key: fields[key](value) for key, value in data.items()}


def _limit(value: str | None) -> int:
    if value is None or value == "":
        return LIST_LIMIT_DEFAULT
    if not value.isdigit() or len(value) > 4:
        raise _bad("limit")
    limit = int(value)
    if not 1 <= limit <= LIST_LIMIT_MAX:
        raise _bad("limit")
    return limit


def _datetime(value: str, field: str) -> datetime:
    if len(value) > 40:
        raise _bad(field)
    parsed = dt_util.parse_datetime(value)
    if parsed is None:
        raise _bad(field)
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


# -- base views -----------------------------------------------------------------------


class _ConfigView(HomeAssistantView):
    """Access checks, error mapping and output of every config route."""

    requires_auth = True
    # POST routes act through the provider: refused while another holds it.
    acts = False
    # With the router's backup option off a route answers "disabled" before
    # its handler runs (``_gate``), unless it only reads stored data or
    # memory (the exceptions set True; listed with reasons in the tests).
    readable_when_disabled: ClassVar[bool] = False
    # Capability named in that "disabled" answer.
    capability: ClassVar[str] = Capability.CONFIG_BACKUP.value
    # Top-level keys the masker redacts by their name although the value
    # is masked on its own (``ssh_pin``: "pin"): masked under the neutral
    # name, renamed afterwards.
    renames: ClassVar[Mapping[str, str]] = {}

    async def _context(self, request: web.Request) -> RequestContext:
        hass: HomeAssistant = request.app[KEY_HASS]
        user = request.get(KEY_HASS_USER)
        if user is None or getattr(user, "is_admin", False) is not True:
            raise RequestError(403, "authorization_denied", error_class="denied")
        if hass.data.get(_PANEL_VIEW_DISABLED_KEY):
            raise RequestError(410, "integration_not_loaded", error_class="internal")
        from .config_manager import async_get_runtime

        runtime = async_get_runtime(hass)
        if runtime is None:
            raise RequestError(
                503, "core_not_running", error_class="not_available", retryable=True
            )
        if self.acts and runtime.provider_conflict:
            raise ProviderConflictError("Another configuration provider")
        user_id = getattr(user, "id", None)
        user_id = user_id if isinstance(user_id, str) and user_id else None
        actor = await async_actor_from_context(hass, Context(user_id=user_id))
        return RequestContext(
            hass=hass,
            runtime=runtime,
            api=runtime.api,
            actor=actor,
            user_id=user_id,
            salt=await runtime.async_route_salt(),
        )

    async def _respond(
        self, request: web.Request, match: Mapping[str, str]
    ) -> web.StreamResponse:
        ctx: RequestContext | None = None
        try:
            ctx = await self._context(request)
            await self._gate(ctx, match)
            result = await self.handle(ctx, request, **match)
        except RequestError as err:
            return error_response(
                err.status,
                err.code,
                error_class=err.error_class,
                retryable=err.retryable,
                details=err.details,
            )
        except ConfigApiError as err:
            return api_error_response(err, None if ctx is None else ctx.api)
        except Exception as err:  # noqa: BLE001 - never a trace or text out
            # Only the type: the message may carry router data.
            _LOGGER.warning(
                "Configuration route %s failed: %s", self.name, type(err).__name__
            )
            return error_response(
                500, "internal", error_class="internal", retryable=False
            )
        if isinstance(result, web.StreamResponse):
            return result
        body = ctx.out(result)
        if isinstance(body, dict):
            for neutral, name in self.renames.items():
                if neutral in body:
                    body[name] = body.pop(neutral)
            restore_warning_codes(result, body)
            self.restore_constants(result, body)
        return self.json(body, headers=dict(NO_STORE))

    async def _gate(self, ctx: RequestContext, match: Mapping[str, str]) -> None:
        """The one place the backup option is checked for every route.

        The route's router comes from its path: ``router_id`` directly, a
        ``backup_id`` or ``approval_id`` through an index lookup (no write,
        no provider, no router). Option off: ``CapabilityUnavailableError``
        with reason ``disabled`` before the handler, so before any core
        action or router call.
        """
        if self.readable_when_disabled:
            return
        router_id: str | None
        if "router_id" in match:
            router_id = ctx.router(match["router_id"]).router_id
        elif "backup_id" in match:
            router_id = (await ctx.backup(match["backup_id"])).router_id
        elif "approval_id" in match:
            router_id = ctx.approval(match["approval_id"]).router_id
        else:
            router_id = None
        if router_id is None or not ctx.runtime.enabled(router_id):
            _disabled(router_id, self.capability)

    async def handle(
        self, ctx: RequestContext, request: web.Request, **match: str
    ) -> Any:
        """The route itself (after the access checks)."""
        raise NotImplementedError

    def restore_constants(self, raw: Any, body: dict[str, Any]) -> None:
        """Put back texts of the code the masker over-masked (default: none).

        Only constants of this integration may come back, never a value
        from a router, a store or a request.
        """


class _GetView(_ConfigView):
    async def get(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Read."""
        return await self._respond(request, match)


class _PostView(_ConfigView):
    acts = True

    async def post(self, request: web.Request, **match: str) -> web.StreamResponse:
        """Act."""
        return await self._respond(request, match)


# -- builders shared by several routes -----------------------------------------------


def _schedule_time(runtime: Any, router_id: str) -> str:
    from .config_manager import _parse_time

    value = runtime.options(router_id).get(
        OPTION_CONFIG_BACKUP_TIME, DEFAULT_CONFIG_BACKUP_TIME
    )
    return _parse_time(value).strftime("%H:%M")


def _router_name(runtime: Any, state: Any) -> str:
    entry = runtime.entries.get(state.entry_id)
    title = getattr(entry, "title", None)
    return title if isinstance(title, str) and title else state.router_id


def _openwrt_version(api: Any, router_id: str) -> str | None:
    record = api.registry.find(router_id)
    version = getattr(getattr(record, "firmware", None), "version", None)
    return version if isinstance(version, str) else None


def router_summary(ctx: RequestContext, state: Any) -> dict[str, Any]:
    """One router of the overview (R1); memory and registry only."""
    runtime, rid = ctx.runtime, state.router_id
    status = runtime.status(rid)
    return {
        "router_id": rid,
        "name": _router_name(runtime, state),
        "enabled": runtime.enabled(rid),
        "status": status,
        "state": status,
        "error_class": runtime.error_class(rid),
        "error_reason": runtime.error_reason(rid),
        "running": state.running,
        "last_backup_at": _iso(state.last_backup_at),
        "last_success_at": _iso(state.last_backup_at),
        "last_attempt_at": _iso(state.last_attempt_at),
        "versions": state.version_count,
        "version_count": state.version_count,
        "capability": capability_view(
            ctx.api.capability(rid, Capability.CONFIG_BACKUP)
        ),
        "schedule": {
            "mode": "daily" if runtime.schedule_daily(rid) else "off",
            "time": _schedule_time(runtime, rid),
            "next_run_at": _iso(runtime.next_run_at(rid)),
        },
        "drift": drift_view(state.drift),
        "openwrt_version": _openwrt_version(ctx.api, rid),
    }


def _panel_approvals(api: Any, router_id: str | None = None) -> list[Any]:
    return [
        a for a in api.pending_approvals(router_id) if str(a.action) in PANEL_ACTIONS
    ]


async def drift_state(
    ctx: RequestContext, state: Any, *, ack: tuple[str, str] | None = None
) -> dict[str, Any]:
    """DriftState (R9-R11): summary, report and the newest acknowledgements."""
    summary = drift_view(state.drift)
    if summary is not None and ack is not None and summary["drift_id"] == ack[0]:
        summary["state"] = ack[1]
        summary["open"] = False
    acks = sorted(
        await ctx.api.async_list_drift_acks(state.router_id),
        key=lambda a: a.ts,
        reverse=True,
    )[:20]
    return {
        "state": "unknown" if summary is None else summary["state"],
        "open": summary is not None and summary["open"],
        "report": summary,
        "acks": [
            {
                "drift_id": a.drift_id,
                "state": a.state.value,
                "at": _iso(a.ts),
                "note": a.note,
                "version_id": a.version_id,
                "by": a.actor.to_dict(),
            }
            for a in acks
        ],
    }


# -- R1 - R20 -------------------------------------------------------------------------


class OverviewView(_GetView):
    """R1: every router of ours, its state and the open panel approvals."""

    readable_when_disabled = True  # the disabled state itself (memory)

    url = f"{BASE_URL}/overview"
    name = f"{VIEW_NAME_PREFIX}overview"

    async def handle(self, ctx: RequestContext, request: web.Request, **_: str) -> Any:
        routers = sorted(
            ctx.runtime.routers.values(),
            key=lambda s: (_router_name(ctx.runtime, s).lower(), s.router_id),
        )
        return {
            "provider": ctx.api.provider_id,
            "provider_registered": ctx.runtime.provider_registered,
            "provider_conflict": ctx.runtime.provider_conflict,
            "pending_approvals": len(_panel_approvals(ctx.api)),
            "routers": [router_summary(ctx, s) for s in routers],
        }


class RouterView(_GetView):
    """R2: capabilities, SSH pin and the ACL offer state of one router."""

    readable_when_disabled = True  # capabilities, the disabled state (memory)

    url = BASE_URL + "/routers/{router_id}"
    name = f"{VIEW_NAME_PREFIX}router"
    renames: ClassVar[Mapping[str, str]] = {"ssh_pinning": "ssh_pin"}

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        rid = state.router_id
        enabled = ctx.runtime.enabled(rid)
        try:
            pin: Mapping[str, Any] | None = ctx.api.ssh_pin_status(rid)
        except ConfigApiError:
            pin = None
        offerable = (
            [
                tier.tier_id
                for tier in DEFAULT_TIER_REGISTRY.offerable(ctx.runtime.options(rid))
                if tier.tier_id == TIER_CONFIG_BACKUP_READ
            ]
            if enabled and ctx.runtime.cgi_transport_secure(rid)
            else []
        )
        return {
            **router_summary(ctx, state),
            "capabilities": {
                str(name): capability_view(ctx.api.capability(rid, name))
                for name in sorted(CONFIG_CAPABILITIES)
            },
            "ssh_pinning": None
            if pin is None
            else {
                "state": pin.get("state"),
                "fingerprint": pin.get("pending_fingerprint") or pin.get("fingerprint"),
                "pending_fingerprint": pin.get("pending_fingerprint"),
                "pinned_fingerprint": pin.get("fingerprint"),
                "algorithm": pin.get("algorithm"),
                "policy": pin.get("policy"),
            },
            # deployed_version: the core does not expose it (gap, null).
            "acl": {"offerable": offerable, "deployed_version": None},
        }


class VersionsView(_GetView):
    """R3: versions of one router, newest first."""

    readable_when_disabled = True  # stored versions (store index)

    url = BASE_URL + "/routers/{router_id}/versions"
    name = f"{VIEW_NAME_PREFIX}versions"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        limit = _limit(request.query.get("limit"))
        since_raw = request.query.get("since")
        since: datetime | None = None
        if since_raw:
            if since_raw.startswith("bkp_"):
                since = (await ctx.backup(since_raw, state.router_id)).created_at
            else:
                since = _datetime(since_raw, "since")
        records = await ctx.api.async_list_backups(
            state.router_id, since=since, limit=limit
        )
        versions = [version_view(r) for r in records]
        return {"versions": versions, "count": len(versions)}


class VersionView(_GetView):
    """R4: one version with its artifacts (kind, size, sha256)."""

    readable_when_disabled = True  # one stored version (store index)

    url = BASE_URL + "/versions/{backup_id}"
    name = f"{VIEW_NAME_PREFIX}version"

    async def handle(
        self, ctx: RequestContext, request: web.Request, backup_id: str = "", **_: str
    ) -> Any:
        return version_view(await ctx.backup(backup_id))


class BackupView(_PostView):
    """R5: a manual version now (409 + Retry-After while one runs)."""

    url = BASE_URL + "/routers/{router_id}/backup"
    name = f"{VIEW_NAME_PREFIX}backup"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        body = await read_body(request, {"note": _note("note")})
        result = await ctx.runtime.async_backup_now(
            state.router_id, actor=ctx.actor, note=body.get("note"), wait=False
        )
        record = result.record
        return {
            "backup_id": record.backup_id,
            "created": result.created,
            "status": record.status.value,
            "version": version_view(record),
        }


class ValidateView(_PostView):
    """R6: check the stored bytes and the provider's validation."""

    capability = Capability.CONFIG_VALIDATE.value

    url = BASE_URL + "/versions/{backup_id}/validate"
    name = f"{VIEW_NAME_PREFIX}validate"

    async def handle(
        self, ctx: RequestContext, request: web.Request, backup_id: str = "", **_: str
    ) -> Any:
        record = await ctx.backup(backup_id)
        await read_body(request)
        # The core requires an actor (contract #111): the admin of the request.
        return version_view(
            await ctx.api.async_validate_backup(record.backup_id, actor=ctx.actor)
        )


class ProtectView(_PostView):
    """R7: protect or unprotect a version."""

    url = BASE_URL + "/versions/{backup_id}/protect"
    name = f"{VIEW_NAME_PREFIX}protect"

    async def handle(
        self, ctx: RequestContext, request: web.Request, backup_id: str = "", **_: str
    ) -> Any:
        record = await ctx.backup(backup_id)
        body = await read_body(
            request, {"protected": _bool("protected")}, required=("protected",)
        )
        return version_view(
            await ctx.api.async_set_protected(
                record.backup_id, body["protected"], actor=ctx.actor
            )
        )


class DiffView(_GetView):
    """R8: compare two versions of the router or a version with live."""

    readable_when_disabled = True  # stored versions; a live diff is refused in handle

    url = BASE_URL + "/routers/{router_id}/diff"
    name = f"{VIEW_NAME_PREFIX}diff"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        rid = state.router_id
        from_raw = request.query.get("from")
        to_raw = request.query.get("to") or LIVE
        if from_raw == LIVE and to_raw == LIVE:
            raise _bad("to")
        base, base_id = await _diff_ref(ctx, rid, from_raw, "from")
        other, other_id = await _diff_ref(ctx, rid, to_raw, "to")
        if LIVE in (base_id, other_id):
            if not ctx.runtime.enabled(rid):
                _disabled(rid, Capability.CONFIG_DIFF)
            async with ctx.runtime.async_live_access(rid):
                diff = await ctx.api.async_compare(base, other, actor=ctx.actor)
        else:
            diff = await ctx.api.async_compare(base, other, actor=ctx.actor)
        data = diff.to_dict()
        return {
            "from": base_id,
            "to": other_id,
            "complete": not diff.truncated,
            "truncated": diff.truncated,
            "compared_at": data.get("compared_at"),
            "counts": data.get("counts"),
            "changes": [change_view(c) for c in data["changes"]],
        }


async def _diff_ref(
    ctx: RequestContext, router_id: str, value: str | None, field: str
) -> tuple[Any, str]:
    if value == LIVE:
        return ConfigRef.live(router_id), LIVE
    if not value:
        raise _bad(field, "missing")
    if not is_valid_id(value, "bkp_"):
        raise _bad(field)
    record = await ctx.backup(value, router_id)
    return ConfigRef.backup(record.backup_id), record.backup_id


class DriftView(_GetView):
    """R9: the last drift result (memory) and the acknowledgements."""

    readable_when_disabled = True  # last drift result (memory)

    url = BASE_URL + "/routers/{router_id}/drift"
    name = f"{VIEW_NAME_PREFIX}drift"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        return await drift_state(ctx, ctx.router(router_id))


class DriftCheckView(_PostView):
    """R10: check the drift now (an admin's wish: no hourly limit)."""

    capability = Capability.CONFIG_DRIFT.value

    url = BASE_URL + "/routers/{router_id}/drift/check"
    name = f"{VIEW_NAME_PREFIX}drift_check"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        await read_body(request)
        await ctx.runtime.async_check_drift(state.router_id, actor=ctx.actor)
        return await drift_state(ctx, state)


class DriftAckView(_PostView):
    """R11: acknowledge a drift or mark it as known."""

    capability = Capability.CONFIG_DRIFT.value

    url = BASE_URL + "/routers/{router_id}/drift/{drift_id}/ack"
    name = f"{VIEW_NAME_PREFIX}drift_ack"

    async def handle(
        self,
        ctx: RequestContext,
        request: web.Request,
        router_id: str = "",
        drift_id: str = "",
        **_: str,
    ) -> Any:
        state = ctx.router(router_id)
        if not isinstance(drift_id, str) or not _DRIFT_ID.fullmatch(drift_id):
            raise _bad("drift_id")
        body = await read_body(
            request,
            {"state": _choice("state", _ACK_STATES), "note": _note("note")},
            required=("state",),
        )
        ack = await ctx.api.async_acknowledge_drift(
            state.router_id,
            drift_id,
            state=DriftAckState(body["state"]),
            actor=ctx.actor,
            note=body.get("note"),
        )
        return await drift_state(ctx, state, ack=(ack.drift_id, ack.state.value))


class RestoreCheckView(_PostView):
    """R12: dry run of a restore; findings, manual steps, checklist."""

    capability = Capability.CONFIG_RESTORE_DRY_RUN.value

    url = BASE_URL + "/versions/{backup_id}/restore-check"
    name = f"{VIEW_NAME_PREFIX}restore_check"

    async def handle(
        self, ctx: RequestContext, request: web.Request, backup_id: str = "", **_: str
    ) -> Any:
        record = await ctx.backup(backup_id)
        await read_body(request)
        target = ctx.runtime.routers.get(record.router_id)
        if target is None:
            raise RouterNotFoundError("Router not loaded", router_id=record.router_id)
        async with ctx.runtime.async_live_access(target.router_id):
            plan = await ctx.api.async_prepare_restore(
                record.backup_id, target.router_id, actor=ctx.actor
            )
        return restore_view(plan)


class ExportView(_PostView):
    """R13: ask to export one artifact (a critical action: approval)."""

    capability = Capability.CONFIG_EXPORT.value

    url = BASE_URL + "/versions/{backup_id}/export"
    name = f"{VIEW_NAME_PREFIX}export"

    async def handle(
        self, ctx: RequestContext, request: web.Request, backup_id: str = "", **_: str
    ) -> Any:
        record = await ctx.backup(backup_id)
        body = await read_body(request, {"artifact": _choice("artifact", _ARTIFACTS)})
        approval = await ctx.api.async_request_export(
            record.backup_id,
            actor=ctx.actor,
            artifact=body.get("artifact", ArtifactKind.ARCHIVE.value),
        )
        return approval_view(approval)


class ApprovalsView(_GetView):
    """R14: open requests of the panel's actions (optionally one router)."""

    readable_when_disabled = True  # open requests, so they can be rejected

    url = f"{BASE_URL}/approvals"
    name = f"{VIEW_NAME_PREFIX}approvals"

    async def handle(self, ctx: RequestContext, request: web.Request, **_: str) -> Any:
        router_id = request.query.get("router_id")
        rid = None if not router_id else ctx.router(router_id).router_id
        return {"approvals": [approval_view(a) for a in _panel_approvals(ctx.api, rid)]}


class ApproveView(_PostView):
    """R15: approve a request (the requester may approve their own)."""

    url = BASE_URL + "/approvals/{approval_id}/approve"
    name = f"{VIEW_NAME_PREFIX}approve"

    async def handle(
        self, ctx: RequestContext, request: web.Request, approval_id: str = "", **_: str
    ) -> Any:
        approval = ctx.approval(approval_id)
        body = await read_body(request, {ACK_PLAINTEXT: _bool(ACK_PLAINTEXT)})
        export = str(approval.action) == GuardedAction.EXPORT
        if export and body.get(ACK_PLAINTEXT) is not True:
            # An export hands out the archive in plain text (all secrets):
            # the approver confirms that explicitly, not by a bare click.
            raise RequestError(
                400,
                "plaintext_not_acknowledged",
                details={"field": ACK_PLAINTEXT, "reason": "required"},
            )
        approved = await ctx.api.async_approve(approval.approval_id, actor=ctx.actor)
        if export:
            # The core's approve takes no note: our own log, no user id.
            _LOGGER.info(
                "Plaintext export %s approved with acknowledge_plaintext",
                approval.approval_id,
            )
        return approval_view(approved)


class RejectView(_PostView):
    """R16: reject a request."""

    readable_when_disabled = True  # rejecting only takes a right away

    url = BASE_URL + "/approvals/{approval_id}/reject"
    name = f"{VIEW_NAME_PREFIX}reject"

    async def handle(
        self, ctx: RequestContext, request: web.Request, approval_id: str = "", **_: str
    ) -> Any:
        approval = ctx.approval(approval_id)
        body = await read_body(request, {"reason": _note("reason")})
        return approval_view(
            await ctx.api.async_reject(
                approval.approval_id, actor=ctx.actor, reason=body.get("reason")
            )
        )


class DownloadView(_PostView):
    """R17: redeem an approved export once; the file, never JSON."""

    capability = Capability.CONFIG_EXPORT.value

    url = BASE_URL + "/approvals/{approval_id}/download"
    name = f"{VIEW_NAME_PREFIX}download"

    async def handle(
        self, ctx: RequestContext, request: web.Request, approval_id: str = "", **_: str
    ) -> Any:
        approval = ctx.approval(approval_id)
        await read_body(request)
        if str(approval.action) != GuardedAction.EXPORT:
            raise ApprovalInvalidError(
                "Not an export", details={"reason": "action_not_supported"}
            )
        handle = await ctx.api.async_export_backup(
            approval.approval_id, actor=ctx.actor
        )
        data = await handle.reader()
        digest = await ctx.hass.async_add_executor_job(_sha256, data)
        if digest != handle.sha256 or len(data) != handle.size_bytes:
            # Nothing of the file goes out.
            raise BackupIntegrityError(
                "Export checksum mismatch", router_id=approval.router_id
            )
        content_type = (
            handle.content_type
            if handle.content_type in _EXPORT_CONTENT_TYPES
            else "application/octet-stream"
        )
        return web.Response(
            body=data,
            status=200,
            headers={
                "Content-Type": content_type,
                "Content-Disposition": (
                    f'attachment; filename="{safe_filename(handle.filename)}"'
                ),
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Referrer-Policy": "no-referrer",
                "X-Checksum-SHA256": handle.sha256,
            },
        )


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AclOfferView(_PostView):
    """R18: ask to deploy the backup read tier (only with the option on)."""

    url = BASE_URL + "/routers/{router_id}/acl-offer"
    name = f"{VIEW_NAME_PREFIX}acl_offer"

    async def handle(
        self, ctx: RequestContext, request: web.Request, router_id: str = "", **_: str
    ) -> Any:
        state = ctx.router(router_id)
        await read_body(request)
        _refuse_acl_on_http(ctx.runtime, state.router_id)
        approval = await ctx.api.async_request_acl_deploy(
            state.router_id, [TIER_CONFIG_BACKUP_READ], actor=ctx.actor
        )
        offer = ctx.api.acl_offer(approval.approval_id).to_dict()
        risks = offer.get("risks") or []
        return {
            "approval": approval_view(approval),
            "offer": {
                "tiers": offer.get("tiers"),
                "added": offer.get("added"),
                "removed": offer.get("removed"),
                "unchanged": offer.get("unchanged"),
                "current_kind": offer.get("current_kind"),
                "acl_version": offer.get("acl_version"),
                "risks": [r.get("risk") for r in risks if isinstance(r, Mapping)],
                "risk_details": risks,
                **acl_offer_explain(offer),
            },
        }

    def restore_constants(self, raw: Any, body: dict[str, Any]) -> None:
        """The tiers' fixed risk sentences, which the text masker cuts.

        ``core_masking.redact_text`` reads "... ROUTER SECRETS: the backup
        archive ..." as a ``name: value`` pair and masks the rest of the
        sentence, so the panel would show ``**REDACTED**`` instead of the
        warning an admin must read before approving. A risk comes back only
        if the core's offer carried exactly the text of that tier in the
        tier registry (code, no router data); anything else stays masked.
        """
        offer, raw_offer = body.get("offer"), raw.get("offer")
        if not isinstance(offer, dict) or not isinstance(raw_offer, Mapping):
            return
        raw_details = raw_offer.get("risk_details")
        details = offer.get("risk_details")
        if not isinstance(raw_details, list) or not isinstance(details, list):
            return
        if len(raw_details) != len(details):
            return
        for raw_item, item in zip(raw_details, details, strict=True):
            if not isinstance(raw_item, Mapping) or not isinstance(item, dict):
                continue
            text = _tier_risk(raw_item.get("tier_id"))
            if text is not None and raw_item.get("risk") == text:
                item["risk"] = text
        offer["risks"] = [
            item.get("risk") for item in details if isinstance(item, dict)
        ]
        # risk_text: only the registry sentence of the requested tier
        if raw_offer.get("risk_text") == _tier_risk(TIER_CONFIG_BACKUP_READ):
            offer["risk_text"] = raw_offer.get("risk_text")


# Fixed rollback texts of R18 (the core's own command, with the timestamp of
# the backup file as a placeholder: the real path exists only after R20).
ACL_ROLLBACK_TEXT = (
    "The deploy keeps a copy of the replaced file next to acl.d and restarts "
    "rpcd. To undo it, copy that file back and restart rpcd (command below; "
    "the deploy result names the exact file). Without a previous file, remove "
    "the deployed file instead; Home Assistant puts its base file back at the "
    "next start."
)
ACL_ROLLBACK_TEMPLATE = _rollback_command(f"{ACL_BACKUP_PREFIX}<timestamp>")
ACL_ROLLBACK_TEMPLATE_NO_PREVIOUS = _rollback_command(None)


def _registry_rights(tier_ids: Iterable[str] | None = None) -> frozenset[str]:
    """``describe()`` lines of the registry's rights (all tiers or some)."""
    lines: set[str] = set()
    for tier in DEFAULT_TIER_REGISTRY.tiers():
        if tier_ids is None or tier.tier_id in tier_ids:
            lines.update(right.describe() for right in tier.rights)
    return frozenset(lines)


def acl_offer_explain(offer: Mapping[str, Any]) -> dict[str, Any]:
    """R18's readable change, only from fixed registry texts (no router data).

    ``rights_added``: lines of the offer that are rights of the offered
    registry tiers (the base tier and config_backup_read); ``rights_removed``: lines that are rights of any registry tier;
    ``rights_unlisted``: how many offer lines matched neither (never shown,
    they may name router-specific entries). ``target_file``,
    ``risk_text`` and the rollback texts are code constants.
    """
    added = offer.get("added")
    removed = offer.get("removed")
    added = added if isinstance(added, list) else []
    removed = removed if isinstance(removed, list) else []
    tiers = offer.get("tiers")
    tier_ids = (
        {t for t in tiers if isinstance(t, str)} if isinstance(tiers, list) else set()
    )
    tier_rights = _registry_rights(tier_ids | {TIER_CONFIG_BACKUP_READ})
    known = _registry_rights()
    rights_added = sorted({r for r in added if isinstance(r, str) and r in tier_rights})
    rights_removed = sorted({r for r in removed if isinstance(r, str) and r in known})
    unlisted = len(added) + len(removed) - len(rights_added) - len(rights_removed)
    return {
        "target_file": ACL_FILE_PATH,
        "rights_added": rights_added,
        "rights_removed": rights_removed,
        "rights_unlisted": max(0, unlisted),
        "risk_text": _tier_risk(TIER_CONFIG_BACKUP_READ),
        "rollback_text": ACL_ROLLBACK_TEXT,
        "rollback_template": ACL_ROLLBACK_TEMPLATE,
        "rollback_template_no_previous": ACL_ROLLBACK_TEMPLATE_NO_PREVIOUS,
    }


def _tier_risk(tier_id: Any) -> str | None:
    """Risk sentence of a known tier (a code constant), else None."""
    if not isinstance(tier_id, str):
        return None
    try:
        risk = DEFAULT_TIER_REGISTRY.get(tier_id).risk
    except AclTierError:
        return None
    return risk if isinstance(risk, str) else None


class SshPinView(_PostView):
    """R19: ask to confirm the pending SSH host key or to reset the pin."""

    url = BASE_URL + "/routers/{router_id}/ssh-pin/{op}"
    name = f"{VIEW_NAME_PREFIX}ssh_pin"

    async def handle(
        self,
        ctx: RequestContext,
        request: web.Request,
        router_id: str = "",
        op: str = "",
        **_: str,
    ) -> Any:
        state = ctx.router(router_id)
        if op not in SSH_PIN_OPS:
            raise _bad("op")
        await read_body(request)
        if op == "confirm":
            approval = await ctx.api.async_request_ssh_pin_confirm(
                state.router_id, actor=ctx.actor
            )
        else:
            approval = await ctx.api.async_request_ssh_pin_reset(
                state.router_id, actor=ctx.actor
            )
        return approval_view(approval)


class ExecuteView(_PostView):
    """R20: carry out an approved ACL deploy or SSH pin change.

    Exports are redeemed by R17; anything else (restore, delete, key reset)
    is refused: these routes never execute a restore.
    """

    url = BASE_URL + "/approvals/{approval_id}/execute"
    name = f"{VIEW_NAME_PREFIX}execute"

    async def handle(
        self, ctx: RequestContext, request: web.Request, approval_id: str = "", **_: str
    ) -> Any:
        approval = ctx.approval(approval_id)
        await read_body(request)
        action = str(approval.action)
        aid = approval.approval_id
        if action == GuardedAction.ACL_DEPLOY:
            # R18 offers only the backup tier: never written on plain HTTP.
            _refuse_acl_on_http(ctx.runtime, approval.router_id)
            result = await ctx.api.async_deploy_acl_offer(aid, actor=ctx.actor)
        elif action == GuardedAction.SSH_PIN_CONFIRM:
            result = await ctx.api.async_confirm_ssh_pin(aid, actor=ctx.actor)
        elif action == GuardedAction.SSH_PIN_RESET:
            result = await ctx.api.async_reset_ssh_pin(aid, actor=ctx.actor)
        else:
            raise ApprovalInvalidError(
                "Redeem exports with the download route",
                details={"reason": "use_download"},
            )
        return {
            "done": True,
            "action": action,
            "result": dict(result) if isinstance(result, Mapping) else {},
        }


# Every config route, in plan order R1-R20 (tests walk this list).
CONFIG_VIEWS: tuple[type[_ConfigView], ...] = (
    OverviewView,
    RouterView,
    VersionsView,
    VersionView,
    BackupView,
    ValidateView,
    ProtectView,
    DiffView,
    DriftView,
    DriftCheckView,
    DriftAckView,
    RestoreCheckView,
    ExportView,
    ApprovalsView,
    ApproveView,
    RejectView,
    DownloadView,
    AclOfferView,
    SshPinView,
    ExecuteView,
)


@callback
def async_register_config_views(hass: HomeAssistant) -> int:
    """Bind the routes once per HA session (aiohttp cannot unbind them).

    ``hass.data[DATA_CONFIG_VIEWS_BOUND]`` remembers the bound names, so a
    retry after a failure part-way binds only the missing ones. Returns how
    many were bound now.
    """
    http = getattr(hass, "http", None)
    if http is None:
        return 0
    bound = hass.data.setdefault(DATA_CONFIG_VIEWS_BOUND, set())
    added = 0
    for view_class in CONFIG_VIEWS:
        if view_class.name in bound:
            continue
        http.register_view(view_class())
        bound.add(view_class.name)
        added += 1
    return added


__all__ = [
    "BASE_URL",
    "BODY_MAX_BYTES",
    "CONFIG_VIEWS",
    "PANEL_ACTIONS",
    "async_register_config_views",
    "output",
    "restore_view",
    "safe_filename",
]
