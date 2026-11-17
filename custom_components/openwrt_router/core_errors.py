"""Error classes of the enterprise core and the Configuration API v1.

Every error has a stable machine-readable ``code`` (part of the API contract,
never renamed within v1), an ``error_class`` (coarse category shared with the
version records and events), the ``router_id`` it concerns (if any), a
``retryable`` flag and a JSON-safe, secret-masked :meth:`to_dict`.
See ``docs/dev/configuration-api-v1.md`` for when each one is raised.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from enum import StrEnum
from typing import Any, ClassVar

from homeassistant.exceptions import HomeAssistantError

from .core_masking import mask_secrets

_LOGGER = logging.getLogger(__name__)


class ErrorClass(StrEnum):
    """Coarse error category (version records, events, dedup keys).

    The first eleven come from the config-manager plan (section 12.2); the
    rest are core categories. New members are an additive change.
    """

    UNREACHABLE = "unreachable"
    TIMEOUT = "timeout"
    AUTH = "auth"  # router login failed
    PERMISSION = "permission"  # router ACL / SSH user lacks the right
    NOT_AVAILABLE = "not_available"  # feature/capability/provider missing
    TOO_LARGE = "too_large"
    INCOMPLETE = "incomplete"
    INVALID = "invalid"
    CHECKSUM_MISMATCH = "checksum_mismatch"
    STORAGE_FULL = "storage_full"
    STORAGE_ERROR = "storage_error"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    DENIED = "denied"  # guard policy said no
    APPROVAL = "approval"  # approval missing, invalid or expired
    BUSY = "busy"
    INCOMPATIBLE = "incompatible"
    UNSUPPORTED_VERSION = "unsupported_version"
    INTERNAL = "internal"


class ConfigApiError(HomeAssistantError):
    """Base class of all enterprise core / Configuration API errors."""

    code: ClassVar[str] = "config_api_error"
    default_error_class: ClassVar[ErrorClass] = ErrorClass.INTERNAL
    default_retryable: ClassVar[bool] = False

    def __init__(
        self,
        message: str = "",
        *,
        router_id: str | None = None,
        retryable: bool | None = None,
        error_class: ErrorClass | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Create the error; ``message`` must not contain secrets."""
        super().__init__(message or self.code)
        self.message = message or self.code
        self.router_id = router_id
        self.retryable = self.default_retryable if retryable is None else retryable
        self.error_class = (
            self.default_error_class if error_class is None else ErrorClass(error_class)
        )
        self.details: dict[str, Any] = dict(details or {})

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-safe description with masked details."""
        return {
            "code": self.code,
            "error_class": self.error_class.value,
            "message": self.message,
            "router_id": self.router_id,
            "retryable": self.retryable,
            "details": mask_secrets(self.details),
        }


class ApiVersionError(ConfigApiError):
    """A consumer asked for an API version this core does not provide."""

    code = "api_version_unsupported"
    default_error_class = ErrorClass.UNSUPPORTED_VERSION

    def __init__(
        self,
        message: str = "",
        *,
        requested: object = None,
        supported_versions: Iterable[int] = (),
    ) -> None:
        """Remember the requested and the supported versions."""
        self.requested = requested
        self.supported_versions = tuple(supported_versions)
        super().__init__(
            message or f"Configuration API version {requested!r} is not supported",
            details={
                "requested": requested if isinstance(requested, int) else None,
                "supported_versions": list(self.supported_versions),
            },
        )


class RouterNotFoundError(ConfigApiError):
    """No router record (or config entry) for the given id."""

    code = "router_not_found"
    default_error_class = ErrorClass.NOT_FOUND


class RouterIdentityError(ConfigApiError):
    """Identity conflict: adoption refused, orphaned record used as live, …"""

    code = "router_identity_error"
    default_error_class = ErrorClass.CONFLICT


class RouterUnavailableError(ConfigApiError):
    """The router's entry is not loaded or the router is offline."""

    code = "router_unavailable"
    default_error_class = ErrorClass.UNREACHABLE
    default_retryable = True


class RouterAuthError(ConfigApiError):
    """The router rejected the integration's login."""

    code = "router_auth_failed"
    default_error_class = ErrorClass.AUTH


class RouterPermissionError(ConfigApiError):
    """The router's ACL or SSH user does not allow the call."""

    code = "router_permission_denied"
    default_error_class = ErrorClass.PERMISSION


class OperationTimeoutError(ConfigApiError):
    """A router call or core operation took too long."""

    code = "operation_timeout"
    default_error_class = ErrorClass.TIMEOUT
    default_retryable = True


class CapabilityUnavailableError(ConfigApiError):
    """A required capability is not available for this router."""

    code = "capability_unavailable"
    default_error_class = ErrorClass.NOT_AVAILABLE

    def __init__(
        self,
        message: str = "",
        *,
        capability: str,
        reason: str | None = None,
        router_id: str | None = None,
    ) -> None:
        """Name the missing capability and the reason code."""
        self.capability = capability
        self.reason = reason
        super().__init__(
            message or f"Capability {capability} is not available",
            router_id=router_id,
            details={"capability": capability, "reason": reason},
        )


class ProviderUnavailableError(ConfigApiError):
    """No configuration provider is registered."""

    code = "provider_unavailable"
    default_error_class = ErrorClass.NOT_AVAILABLE


class ProviderConflictError(ConfigApiError):
    """A second provider tried to register while one is registered."""

    code = "provider_conflict"
    default_error_class = ErrorClass.CONFLICT


class AuthorizationError(ConfigApiError):
    """The actor may not perform the action, or a WriteAuthorization is invalid.

    ``details["reason"]`` says why (for example ``not_admin``,
    ``already_used``, ``expired``, ``action_mismatch``).
    """

    code = "authorization_denied"
    default_error_class = ErrorClass.DENIED


class ApprovalRequiredError(ConfigApiError):
    """A critical action was called without a valid approved request."""

    code = "approval_required"
    default_error_class = ErrorClass.APPROVAL


class ApprovalInvalidError(ConfigApiError):
    """The approval is unknown, expired, used, rejected or bound elsewhere."""

    code = "approval_invalid"
    default_error_class = ErrorClass.APPROVAL


class BackupNotFoundError(ConfigApiError):
    """No backup (version) with this id in the index."""

    code = "backup_not_found"
    default_error_class = ErrorClass.NOT_FOUND


class BackupIntegrityError(ConfigApiError):
    """Stored bytes do not match the index (checksum, size)."""

    code = "backup_integrity_failed"
    default_error_class = ErrorClass.CHECKSUM_MISMATCH


class BackupMetadataError(ConfigApiError):
    """Backup metadata is malformed or has an unknown (newer) version."""

    code = "backup_metadata_invalid"
    default_error_class = ErrorClass.INVALID


class BackupIncompleteError(ConfigApiError):
    """A version could not be collected completely (no usable artifact)."""

    code = "backup_incomplete"
    default_error_class = ErrorClass.INCOMPLETE


class ArtifactTooLargeError(ConfigApiError):
    """One artifact exceeds the per-artifact or per-router size limit."""

    code = "artifact_too_large"
    default_error_class = ErrorClass.TOO_LARGE


class StorageFullError(ConfigApiError):
    """The total storage limit is reached; nothing was written."""

    code = "storage_full"
    default_error_class = ErrorClass.STORAGE_FULL


class StorageError(ConfigApiError):
    """File system error in the version store (write, rename, read)."""

    code = "storage_error"
    default_error_class = ErrorClass.STORAGE_ERROR


class UnsupportedStorageFormatError(ConfigApiError):
    """A stored artifact has a storage_format this core cannot read."""

    code = "storage_format_unsupported"
    default_error_class = ErrorClass.INVALID


class RestoreIncompatibleError(ConfigApiError):
    """The backup cannot be restored to the target router."""

    code = "restore_incompatible"
    default_error_class = ErrorClass.INCOMPATIBLE


class OperationInProgressError(ConfigApiError):
    """Another mutating operation holds this router's lock."""

    code = "operation_in_progress"
    default_error_class = ErrorClass.BUSY
    default_retryable = True


class ProviderError(ConfigApiError):
    """Unexpected provider failure; the cause is chained and named."""

    code = "provider_error"

    def __init__(
        self,
        message: str = "",
        *,
        router_id: str | None = None,
        retryable: bool | None = None,
        error_class: ErrorClass | None = None,
        cause: BaseException | None = None,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        """Wrap ``cause``; only its type name goes into ``details``."""
        merged = dict(details or {})
        if cause is not None:
            merged["cause"] = type(cause).__name__
        super().__init__(
            message,
            router_id=router_id,
            retryable=retryable,
            error_class=error_class,
            details=merged,
        )
        if cause is not None:
            self.__cause__ = cause
