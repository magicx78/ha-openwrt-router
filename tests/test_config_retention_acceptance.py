"""Acceptance of the core GFS retention for the configuration manager.

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.7 (D18), 16
(case 11) and 23. These are the cases of the former
``tests/test_config_retention.py`` (``config_retention.select_for_deletion``,
removed) with their assertions unchanged, run against the core's
:func:`core_models.plan_retention` with ``RetentionPolicy.gfs``. A thin
adapter keeps the readable version names of the old tests: it builds one
``BackupRecord`` per name and maps the core's ids back to the names.
Mapping: ``ok=False`` -> ``VersionStatus.FAILED``; ``kind`` ->
``BackupReason``; ``max_bytes`` -> ``max_bytes_per_router``; ``KEEP_*`` ->
``KeepReason``. ``now`` and time zones come from the test.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, timezone

import pytest

from custom_components.openwrt_router.core_errors import ErrorClass
from custom_components.openwrt_router.core_models import (
    Actor,
    ArtifactKind,
    ArtifactRef,
    BackupReason,
    BackupRecord,
    BackupType,
    KeepReason,
    StorageRef,
    VersionStatus,
    plan_retention,
)
from custom_components.openwrt_router.core_models import (
    RetentionPolicy as CoreRetentionPolicy,
)

ROUTER = "rtr_" + "c" * 32
LOCAL = timezone(timedelta(hours=1), "CET")
# Tuesday, ISO week 47 of 2026.
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=LOCAL)
KB = 100 * 1024
DEFAULT_MAX_BYTES = 50 * 1024 * 1024

KEEP_PROTECTED = KeepReason.PROTECTED
KEEP_NEWEST_OK = KeepReason.NEWEST_VALID
KEEP_DAILY = KeepReason.DAILY
KEEP_WEEKLY = KeepReason.WEEKLY
KEEP_MONTHLY = KeepReason.MONTHLY
KEEP_RECENT_FAILED = KeepReason.RECENT_FAILED

_KIND = {
    "scheduled": BackupReason.SCHEDULED,
    "manual": BackupReason.MANUAL,
    "drift": BackupReason.DRIFT,
    "release_change": BackupReason.RELEASE_CHANGE,
}
# Core id -> readable name of the test.
_NAMES: dict[str, str] = {}


# ---------------------------------------------------------------------------
# Adapter: the old test vocabulary on top of the core
# ---------------------------------------------------------------------------


def _version_id(name: str) -> str:
    """Core version id (``bkp_<32 hex>``) for a readable test name."""
    return "bkp_" + hashlib.md5(name.encode()).hexdigest()


def RetentionItem(
    name: str,
    created: datetime,
    size_bytes: int,
    protected: bool,
    ok: bool,
    kind: str,
) -> BackupRecord:
    """One core version under the readable ``name``."""
    version_id = _version_id(name)
    _NAMES[version_id] = name
    return BackupRecord(
        backup_id=version_id,
        router_id=ROUTER,
        created_at=created,
        backup_type=BackupType.UCI_SNAPSHOT,
        reason=_KIND[kind],
        created_by=Actor.system(),
        status=VersionStatus.OK if ok else VersionStatus.FAILED,
        error_class=None if ok else ErrorClass.TIMEOUT,
        artifacts={
            ArtifactKind.UCI: ArtifactRef(
                storage=StorageRef(locator=f"{version_id}.uci"),
                sha256="a" * 64,
                size_bytes=size_bytes,
            )
        },
        protected=protected,
    )


def RetentionPolicy(
    *,
    daily: int = 7,
    weekly: int = 4,
    monthly: int = 6,
    max_bytes: int | None = DEFAULT_MAX_BYTES,
) -> CoreRetentionPolicy:
    """The core GFS policy with the old defaults (7/4/6, 50 MiB)."""
    return CoreRetentionPolicy.gfs(
        daily, weekly, monthly, max_bytes_per_router=max_bytes
    )


@dataclass(frozen=True, slots=True)
class RetentionDecision:
    """The core's RetentionResult in the old shape, with readable names."""

    delete: tuple[str, ...]
    keep: tuple[str, ...]
    reasons: Mapping[str, tuple[KeepReason, ...]]
    total_bytes: int
    max_bytes: int | None
    over_limit: bool


def select_for_deletion(
    items: Sequence[BackupRecord], policy: CoreRetentionPolicy, now: datetime
) -> RetentionDecision:
    """Run the core's plan_retention and map its ids back to the names."""
    result = plan_retention(ROUTER, items, policy, now=now)
    assert result.router_id == ROUTER
    deleted = set(result.deleted)
    kept = set(result.kept)
    assert not deleted & kept
    assert deleted | kept == {record.backup_id for record in items}
    return RetentionDecision(
        delete=tuple(_NAMES[v] for v in result.deleted),
        keep=tuple(_NAMES[v] for v in result.kept),
        reasons={_NAMES[v]: tuple(r) for v, r in result.reasons.items()},
        total_bytes=result.total_bytes,
        max_bytes=result.max_bytes,
        over_limit=result.over_limit,
    )


def item(
    day: date,
    *,
    hour: int = 3,
    ok: bool = True,
    protected: bool = False,
    size: int = KB,
    kind: str = "scheduled",
    suffix: str = "",
) -> BackupRecord:
    created = datetime.combine(day, time(hour), tzinfo=LOCAL)
    return RetentionItem(
        f"v{day.isoformat()}T{hour:02d}{suffix}",
        created,
        size,
        protected,
        ok,
        kind,
    )


def daily_items(first: date, last: date, **kwargs: object) -> list[BackupRecord]:
    out = []
    day = first
    while day <= last:
        out.append(item(day, **kwargs))  # type: ignore[arg-type]
        day += timedelta(days=1)
    return out


def ids(*days: date) -> set[str]:
    return {f"v{d.isoformat()}T03" for d in days}


def name_of(record: BackupRecord) -> str:
    return _NAMES[record.backup_id]


BIG = RetentionPolicy(max_bytes=1 << 40)


# ---------------------------------------------------------------------------
# The cases (assertions as in the former test_config_retention.py)
# ---------------------------------------------------------------------------


def test_gfs_7_4_6() -> None:
    items = daily_items(date(2025, 10, 1), date(2026, 11, 17))
    decision = select_for_deletion(items, BIG, NOW)

    daily = {date(2026, 11, d) for d in range(11, 18)}
    # ISO weeks 47 (Nov 16-22), 46 (Nov 9-15), 45 (Nov 2-8), 44 (Oct 26-Nov 1).
    weekly = {
        date(2026, 11, 17),
        date(2026, 11, 15),
        date(2026, 11, 8),
        date(2026, 11, 1),
    }
    # Nov, Oct, Sep, Aug, Jul, Jun: newest of each month.
    monthly = {
        date(2026, 11, 17),
        date(2026, 10, 31),
        date(2026, 9, 30),
        date(2026, 8, 31),
        date(2026, 7, 31),
        date(2026, 6, 30),
    }
    expected = ids(*(daily | weekly | monthly))
    assert len(expected) == 14
    assert set(decision.keep) == expected
    assert set(decision.delete) == {name_of(i) for i in items} - expected
    assert decision.over_limit is False
    # Reasons are reported per kept version.
    assert KEEP_DAILY in decision.reasons["v2026-11-12T03"]
    assert decision.reasons["v2026-11-08T03"] == (KEEP_WEEKLY,)
    assert decision.reasons["v2026-06-30T03"] == (KEEP_MONTHLY,)
    assert set(decision.reasons["v2026-11-17T03"]) == {
        KEEP_DAILY,
        KEEP_WEEKLY,
        KEEP_MONTHLY,
        KEEP_NEWEST_OK,
    }
    # Oldest first, nothing twice.
    assert list(decision.delete) == sorted(decision.delete)
    assert len(set(decision.delete)) == len(decision.delete)


def test_newest_version_of_a_day_represents_it() -> None:
    items = [
        item(date(2026, 11, 16), hour=1),
        item(date(2026, 11, 16), hour=9, kind="manual"),
        item(date(2026, 11, 16), hour=22, kind="drift"),
        item(date(2026, 11, 17), hour=3),
    ]
    decision = select_for_deletion(items, RetentionPolicy(weekly=0, monthly=0), NOW)
    assert set(decision.keep) == {"v2026-11-16T22", "v2026-11-17T03"}
    assert set(decision.delete) == {"v2026-11-16T01", "v2026-11-16T09"}


def test_days_use_the_callers_time_zone() -> None:
    # 23:30 UTC on Nov 15 is 00:30 CET on Nov 16, the same local day as 10:00.
    night = RetentionItem(
        "night", datetime(2026, 11, 15, 23, 30, tzinfo=UTC), KB, False, True, "manual"
    )
    morning = RetentionItem(
        "morning",
        datetime(2026, 11, 16, 10, 0, tzinfo=LOCAL),
        KB,
        False,
        True,
        "manual",
    )
    newest = item(date(2026, 11, 17))
    policy = RetentionPolicy(weekly=0, monthly=0)
    decision = select_for_deletion([night, morning, newest], policy, NOW)
    assert "morning" in decision.keep
    assert "night" in decision.delete
    # Seen in UTC they fall on different days, and both stay.
    decision_utc = select_for_deletion(
        [night, morning, newest], policy, NOW.astimezone(UTC)
    )
    assert {"night", "morning"} <= set(decision_utc.keep)


def test_protected_never_deleted() -> None:
    old_protected = item(date(2024, 1, 1), protected=True, size=10 * KB)
    items = [old_protected, *daily_items(date(2026, 11, 1), date(2026, 11, 17))]
    decision = select_for_deletion(items, BIG, NOW)
    assert name_of(old_protected) in decision.keep
    assert decision.reasons[name_of(old_protected)] == (KEEP_PROTECTED,)
    # Also under a size limit far too small and with GFS switched off.
    tight = RetentionPolicy(daily=0, weekly=0, monthly=0, max_bytes=1)
    decision = select_for_deletion(items, tight, NOW)
    assert name_of(old_protected) in decision.keep
    assert name_of(old_protected) not in decision.delete
    assert decision.over_limit is True


def test_newest_ok_always_kept() -> None:
    newest_ok = item(date(2026, 9, 1))
    failed_after = [item(date(2026, 11, d), ok=False) for d in (15, 16, 17)]
    nothing = RetentionPolicy(daily=0, weekly=0, monthly=0, max_bytes=1)
    decision = select_for_deletion(
        [item(date(2026, 8, 1)), newest_ok, *failed_after], nothing, NOW
    )
    assert name_of(newest_ok) in decision.keep
    assert KEEP_NEWEST_OK in decision.reasons[name_of(newest_ok)]
    assert name_of(newest_ok) not in decision.delete
    assert "v2026-08-01T03" in decision.delete


def test_failed_versions_do_not_represent_a_period() -> None:
    ok_morning = item(date(2026, 11, 16), hour=3)
    failed_evening = item(date(2026, 11, 16), hour=21, ok=False)
    newest = item(date(2026, 11, 17))
    decision = select_for_deletion(
        [ok_morning, failed_evening, newest], RetentionPolicy(weekly=0, monthly=0), NOW
    )
    assert name_of(ok_morning) in decision.keep
    assert KEEP_DAILY in decision.reasons[name_of(ok_morning)]
    # Failed versions inside the daily window stay for diagnosis ...
    assert decision.reasons[name_of(failed_evening)] == (KEEP_RECENT_FAILED,)


def test_old_failed_versions_are_deleted() -> None:
    old_failed = item(date(2026, 10, 1), ok=False, suffix="-failed")
    month_end_failed = item(date(2026, 10, 31), hour=23, ok=False)
    items = [
        *daily_items(date(2026, 10, 1), date(2026, 11, 17)),
        old_failed,
        month_end_failed,
    ]
    decision = select_for_deletion(items, BIG, NOW)
    # ... outside it they go, even where they are the newest of their month.
    assert name_of(old_failed) in decision.delete
    assert name_of(month_end_failed) in decision.delete
    assert "v2026-10-31T03" in decision.keep


def test_size_limit_evicts_oldest_unprotected() -> None:
    items = daily_items(date(2026, 11, 11), date(2026, 11, 17), size=KB)
    protected = item(date(2026, 1, 1), protected=True, size=KB)
    policy = RetentionPolicy(max_bytes=5 * KB)
    decision = select_for_deletion([protected, *items], policy, NOW)
    # 8 versions, room for 5: the 3 oldest unprotected go, oldest first.
    assert list(decision.delete) == [
        "v2026-11-11T03",
        "v2026-11-12T03",
        "v2026-11-13T03",
    ]
    assert name_of(protected) in decision.keep
    assert decision.total_bytes == 5 * KB
    assert decision.over_limit is False


def test_size_limit_evicts_failed_before_successful() -> None:
    items = daily_items(date(2026, 11, 11), date(2026, 11, 17), size=KB)
    failed = item(date(2026, 11, 17), hour=1, ok=False, size=KB)
    decision = select_for_deletion(
        [*items, failed], RetentionPolicy(max_bytes=7 * KB), NOW
    )
    assert list(decision.delete) == [name_of(failed)]


def test_over_limit_reported_not_forced() -> None:
    protected = [item(date(2026, 1, d), protected=True, size=3 * KB) for d in (1, 2)]
    newest = item(date(2026, 11, 17), size=3 * KB)
    older = item(date(2026, 11, 16), size=KB)
    decision = select_for_deletion(
        [*protected, older, newest], RetentionPolicy(max_bytes=4 * KB), NOW
    )
    assert decision.over_limit is True
    assert decision.delete == (name_of(older),)
    assert set(decision.keep) == {name_of(p) for p in protected} | {name_of(newest)}
    assert decision.total_bytes == 9 * KB
    assert decision.max_bytes == 4 * KB


def test_no_size_limit() -> None:
    items = daily_items(date(2026, 11, 1), date(2026, 11, 17), size=10 * 1024 * KB)
    decision = select_for_deletion(items, RetentionPolicy(max_bytes=None), NOW)
    assert decision.over_limit is False


def test_empty_and_result_shape() -> None:
    decision = select_for_deletion([], RetentionPolicy(), NOW)
    assert decision == RetentionDecision(
        delete=(),
        keep=(),
        reasons={},
        total_bytes=0,
        max_bytes=50 * 1024 * 1024,
        over_limit=False,
    )


def test_input_validation() -> None:
    with pytest.raises(ValueError):
        select_for_deletion([], RetentionPolicy(), datetime(2026, 11, 17))
    # A naive creation time is refused when the version is built.
    with pytest.raises(ValueError):
        RetentionItem("x", datetime(2026, 11, 17), KB, False, True, "manual")
    with pytest.raises(ValueError):
        select_for_deletion(
            [item(date(2026, 11, 1)), item(date(2026, 11, 1))], RetentionPolicy(), NOW
        )
    with pytest.raises(ValueError):
        RetentionPolicy(daily=-1)
    with pytest.raises(ValueError):
        RetentionPolicy(max_bytes=-5)
    with pytest.raises(ValueError):
        RetentionItem("y", NOW, -1, False, True, "manual")
