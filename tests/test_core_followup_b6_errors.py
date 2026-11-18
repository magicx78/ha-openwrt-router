"""Follow-up B6: ``RateLimitedError`` and ``SafetyRefusedError``.

* ``RateLimitedError(retry_after=...)``: code ``rate_limited``, error class
  ``rate_limited``, always retryable, ``retry_after`` (seconds, finite, >= 0)
  as attribute, in ``details`` and at the top of ``to_dict()``.
* ``SafetyRefusedError(reason=...)``: code ``safety_refused``, error class
  ``safety_refused``, never retryable, ``details["reason"]`` a machine code.
* Both error classes are call-time only: ``NON_PERSISTED_ERROR_CLASSES``.
  ``VersionMeta`` and ``BackupRecord`` refuse them, so no stored record ever
  carries a value an older core could not read (no metadata version bump).
"""

from __future__ import annotations

import math
from datetime import UTC, datetime

import pytest

from custom_components.openwrt_router.core_errors import (
    NON_PERSISTED_ERROR_CLASSES,
    ConfigApiError,
    ErrorClass,
    RateLimitedError,
    SafetyRefusedError,
)
from custom_components.openwrt_router.core_models import (
    Actor,
    BackupReason,
    BackupRecord,
    BackupType,
    VersionMeta,
    VersionStatus,
)
from custom_components.openwrt_router.version_store import version_error_class


def test_rate_limited_shape():
    err = RateLimitedError("too many scans", retry_after=12.5, router_id=None)
    assert isinstance(err, ConfigApiError)
    assert err.code == "rate_limited"
    assert err.error_class is ErrorClass.RATE_LIMITED
    assert err.retryable is True
    assert err.retry_after == 12.5
    assert err.details["retry_after"] == 12.5
    data = err.to_dict()
    assert data["code"] == "rate_limited"
    assert data["error_class"] == "rate_limited"
    assert data["retryable"] is True
    assert data["retry_after"] == 12.5
    assert data["details"]["retry_after"] == 12.5


def test_rate_limited_extra_details_kept_and_masked():
    err = RateLimitedError(
        retry_after=1, details={"action": "net_scan", "password": "hunter2"}
    )
    assert err.retry_after == 1.0 and isinstance(err.retry_after, float)
    data = err.to_dict()
    assert data["details"]["action"] == "net_scan"
    assert "hunter2" not in str(data)
    assert err.message == "rate_limited"


@pytest.mark.parametrize("bad", [-1, math.inf, math.nan, "5", True, None])
def test_rate_limited_bad_retry_after(bad):
    with pytest.raises((TypeError, ValueError)):
        RateLimitedError(retry_after=bad)


def test_safety_refused_shape():
    err = SafetyRefusedError(
        "would cut the management link", reason="management_link", router_id=None
    )
    assert isinstance(err, ConfigApiError)
    assert err.code == "safety_refused"
    assert err.error_class is ErrorClass.SAFETY_REFUSED
    assert err.retryable is False
    assert err.reason == "management_link"
    data = err.to_dict()
    assert data["details"]["reason"] == "management_link"
    assert data["retryable"] is False


@pytest.mark.parametrize("bad", ["", "Has Space", "x" * 65, 3, None])
def test_safety_refused_bad_reason(bad):
    with pytest.raises((TypeError, ValueError)):
        SafetyRefusedError(reason=bad)


def test_codes_are_distinct():
    codes = {cls.code for cls in ConfigApiError.__subclasses__()}
    assert {"rate_limited", "safety_refused"} <= codes
    assert len(codes) == len(ConfigApiError.__subclasses__())


def test_non_persisted_set():
    assert (
        frozenset({ErrorClass.RATE_LIMITED, ErrorClass.SAFETY_REFUSED})
        == NON_PERSISTED_ERROR_CLASSES
    )


@pytest.mark.parametrize("cls", sorted(NON_PERSISTED_ERROR_CLASSES))
def test_records_refuse_call_time_classes(cls):
    with pytest.raises(ValueError):
        VersionMeta(
            backup_type=BackupType.UCI_SNAPSHOT,
            reason=BackupReason.MANUAL,
            status=VersionStatus.FAILED,
            error_class=cls,
        )
    with pytest.raises(ValueError):
        BackupRecord(
            backup_id="bkp_" + "0" * 32,
            router_id="rtr_" + "0" * 32,
            created_at=datetime(2026, 11, 18, tzinfo=UTC),
            backup_type=BackupType.UCI_SNAPSHOT,
            reason=BackupReason.MANUAL,
            created_by=Actor.system(),
            status=VersionStatus.FAILED,
            error_class=cls,
        )


def test_version_error_class_maps_call_time_classes():
    assert version_error_class(RateLimitedError(retry_after=3)) is ErrorClass.BUSY
    assert version_error_class(SafetyRefusedError(reason="x")) is ErrorClass.DENIED
    assert version_error_class(ValueError()) is ErrorClass.INTERNAL
