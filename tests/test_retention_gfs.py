"""GFS retention of the core (contract §7.5), ported from config-manager.

The 13 cases of ``tests/test_config_retention.py`` on branch
``claude/config-manager-d9fdac`` (``select_for_deletion``), run against
the core's :func:`plan_retention`. Mapping: ``RetentionItem.ok=False`` ->
a FAILED version; ``kind`` -> BackupReason; ``RetentionPolicy.max_bytes``
-> ``max_bytes_per_router`` / ``plan_retention(max_bytes=)``; KEEP_* ->
KeepReason. Days, weeks and months are counted in ``now``'s time zone.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, time, timedelta, timezone

import pytest

from custom_components.openwrt_router.core_errors import ErrorClass
from custom_components.openwrt_router.core_models import (
    DEFAULT_RETENTION_POLICY,
    Actor,
    ArtifactKind,
    ArtifactRef,
    BackupReason,
    BackupRecord,
    BackupType,
    KeepReason,
    RetentionPolicy,
    RetentionResult,
    StorageRef,
    VersionStatus,
    plan_retention,
)

ROUTER = "rtr_" + "a" * 32
LOCAL = timezone(timedelta(hours=1), "CET")
# Tuesday, ISO week 47 of 2026.
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=LOCAL)
KB = 100 * 1024
MIB50 = 50 * 1024 * 1024


def V(name: str) -> str:
    """Version id for a readable name (ids must be ``bkp_<32 hex>``)."""
    return "bkp_" + hashlib.md5(name.encode()).hexdigest()


def record(
    name: str,
    created: datetime,
    *,
    size: int = KB,
    ok: bool = True,
    protected: bool = False,
    reason: BackupReason = BackupReason.SCHEDULED,
) -> BackupRecord:
    version_id = V(name)
    return BackupRecord(
        backup_id=version_id,
        router_id=ROUTER,
        created_at=created,
        backup_type=BackupType.UCI_SNAPSHOT,
        reason=reason,
        created_by=Actor.system(),
        status=VersionStatus.OK if ok else VersionStatus.FAILED,
        error_class=None if ok else ErrorClass.TIMEOUT,
        artifacts={
            ArtifactKind.UCI: ArtifactRef(
                storage=StorageRef(locator=f"{version_id}.uci"),
                sha256="a" * 64,
                size_bytes=size,
            )
        },
        protected=protected,
    )


def item(
    day: date,
    *,
    hour: int = 3,
    ok: bool = True,
    protected: bool = False,
    size: int = KB,
    reason: BackupReason = BackupReason.SCHEDULED,
    suffix: str = "",
) -> BackupRecord:
    return record(
        f"v{day.isoformat()}T{hour:02d}{suffix}",
        datetime.combine(day, time(hour), tzinfo=LOCAL),
        size=size,
        ok=ok,
        protected=protected,
        reason=reason,
    )


def daily_items(first: date, last: date, **kwargs: object) -> list[BackupRecord]:
    out = []
    day = first
    while day <= last:
        out.append(item(day, **kwargs))  # type: ignore[arg-type]
        day += timedelta(days=1)
    return out


def ids(*days: date) -> set[str]:
    return {V(f"v{d.isoformat()}T03") for d in days}


def gfs(
    daily: int = 7, weekly: int = 4, monthly: int = 6, max_bytes: int | None = None
) -> RetentionPolicy:
    return RetentionPolicy.gfs(daily, weekly, monthly, max_bytes_per_router=max_bytes)


def plan(
    items: list[BackupRecord], policy: RetentionPolicy, now: datetime = NOW
) -> RetentionResult:
    return plan_retention(ROUTER, items, policy, now=now)


def test_gfs01_7_4_6() -> None:
    items = daily_items(date(2025, 10, 1), date(2026, 11, 17))
    result = plan(items, DEFAULT_RETENTION_POLICY)

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
    assert set(result.kept) == expected
    assert set(result.deleted) == {i.backup_id for i in items} - expected
    assert result.over_limit is False
    assert KeepReason.DAILY in result.reasons[V("v2026-11-12T03")]
    assert result.reasons[V("v2026-11-08T03")] == (KeepReason.WEEKLY,)
    assert result.reasons[V("v2026-06-30T03")] == (KeepReason.MONTHLY,)
    assert set(result.reasons[V("v2026-11-17T03")]) == {
        KeepReason.DAILY,
        KeepReason.WEEKLY,
        KeepReason.MONTHLY,
        KeepReason.NEWEST_VALID,
    }
    # Oldest first, nothing twice.
    created = {i.backup_id: i.created_at for i in items}
    assert [created[v] for v in result.deleted] == sorted(
        created[v] for v in result.deleted
    )
    assert len(set(result.deleted)) == len(result.deleted)


def test_gfs02_newest_version_of_a_day_represents_it() -> None:
    items = [
        item(date(2026, 11, 16), hour=1),
        item(date(2026, 11, 16), hour=9, reason=BackupReason.MANUAL),
        item(date(2026, 11, 16), hour=22, reason=BackupReason.DRIFT),
        item(date(2026, 11, 17), hour=3),
    ]
    result = plan(items, gfs(weekly=0, monthly=0))
    assert set(result.kept) == {V("v2026-11-16T22"), V("v2026-11-17T03")}
    assert set(result.deleted) == {V("v2026-11-16T01"), V("v2026-11-16T09")}


def test_gfs03_days_use_the_callers_time_zone() -> None:
    # 23:30 UTC on Nov 15 is 00:30 CET on Nov 16, the same local day as 10:00.
    night = record("night", datetime(2026, 11, 15, 23, 30, tzinfo=UTC))
    morning = record("morning", datetime(2026, 11, 16, 10, 0, tzinfo=LOCAL))
    newest = item(date(2026, 11, 17))
    policy = gfs(weekly=0, monthly=0)
    result = plan([night, morning, newest], policy)
    assert V("morning") in result.kept
    assert V("night") in result.deleted
    # Seen in UTC they fall on different days, and both stay.
    result_utc = plan([night, morning, newest], policy, NOW.astimezone(UTC))
    assert {V("night"), V("morning")} <= set(result_utc.kept)


def test_gfs04_protected_never_deleted() -> None:
    old_protected = item(date(2024, 1, 1), protected=True, size=10 * KB)
    items = [old_protected, *daily_items(date(2026, 11, 1), date(2026, 11, 17))]
    result = plan(items, DEFAULT_RETENTION_POLICY)
    assert old_protected.backup_id in result.kept
    assert result.reasons[old_protected.backup_id] == (KeepReason.PROTECTED,)
    # Also under a size limit far too small and with GFS switched off.
    result = plan(items, gfs(0, 0, 0, max_bytes=1))
    assert old_protected.backup_id in result.kept
    assert old_protected.backup_id not in result.deleted
    assert result.over_limit is True


def test_gfs05_newest_ok_always_kept() -> None:
    newest_ok = item(date(2026, 9, 1))
    failed_after = [item(date(2026, 11, d), ok=False) for d in (15, 16, 17)]
    result = plan(
        [item(date(2026, 8, 1)), newest_ok, *failed_after], gfs(0, 0, 0, max_bytes=1)
    )
    assert newest_ok.backup_id in result.kept
    assert KeepReason.NEWEST_VALID in result.reasons[newest_ok.backup_id]
    assert newest_ok.backup_id not in result.deleted
    assert V("v2026-08-01T03") in result.deleted


def test_gfs06_failed_versions_do_not_represent_a_period() -> None:
    ok_morning = item(date(2026, 11, 16), hour=3)
    failed_evening = item(date(2026, 11, 16), hour=21, ok=False)
    newest = item(date(2026, 11, 17))
    result = plan([ok_morning, failed_evening, newest], gfs(weekly=0, monthly=0))
    assert ok_morning.backup_id in result.kept
    assert KeepReason.DAILY in result.reasons[ok_morning.backup_id]
    # Failed versions inside the daily window stay for diagnosis ...
    assert result.reasons[failed_evening.backup_id] == (KeepReason.RECENT_FAILED,)


def test_gfs07_old_failed_versions_are_deleted() -> None:
    old_failed = item(date(2026, 10, 1), ok=False, suffix="-failed")
    month_end_failed = item(date(2026, 10, 31), hour=23, ok=False)
    items = [
        *daily_items(date(2026, 10, 1), date(2026, 11, 17)),
        old_failed,
        month_end_failed,
    ]
    result = plan(items, DEFAULT_RETENTION_POLICY)
    # ... outside it they go, even where they are the newest of their month.
    assert old_failed.backup_id in result.deleted
    assert month_end_failed.backup_id in result.deleted
    assert V("v2026-10-31T03") in result.kept


def test_gfs08_size_limit_evicts_oldest_unprotected() -> None:
    items = daily_items(date(2026, 11, 11), date(2026, 11, 17), size=KB)
    protected = item(date(2026, 1, 1), protected=True, size=KB)
    result = plan([protected, *items], gfs(max_bytes=5 * KB))
    # 8 versions, room for 5: the 3 oldest unprotected go, oldest first.
    assert list(result.deleted) == [
        V("v2026-11-11T03"),
        V("v2026-11-12T03"),
        V("v2026-11-13T03"),
    ]
    assert protected.backup_id in result.kept
    assert result.total_bytes == 5 * KB
    assert result.over_limit is False


def test_gfs09_size_limit_evicts_failed_before_successful() -> None:
    items = daily_items(date(2026, 11, 11), date(2026, 11, 17), size=KB)
    failed = item(date(2026, 11, 17), hour=1, ok=False, size=KB)
    result = plan([*items, failed], gfs(max_bytes=7 * KB))
    assert list(result.deleted) == [failed.backup_id]


def test_gfs10_over_limit_reported_not_forced() -> None:
    protected = [item(date(2026, 1, d), protected=True, size=3 * KB) for d in (1, 2)]
    newest = item(date(2026, 11, 17), size=3 * KB)
    older = item(date(2026, 11, 16), size=KB)
    result = plan([*protected, older, newest], gfs(max_bytes=4 * KB))
    assert result.over_limit is True
    assert result.deleted == (older.backup_id,)
    assert set(result.kept) == {p.backup_id for p in protected} | {newest.backup_id}
    assert result.total_bytes == 9 * KB
    assert result.max_bytes == 4 * KB


def test_gfs11_no_size_limit() -> None:
    items = daily_items(date(2026, 11, 1), date(2026, 11, 17), size=10 * 1024 * KB)
    result = plan(items, gfs(max_bytes=None))
    assert result.over_limit is False
    assert result.max_bytes is None


def test_gfs12_empty_and_result_shape() -> None:
    result = plan_retention(
        ROUTER, [], DEFAULT_RETENTION_POLICY, now=NOW, max_bytes=MIB50
    )
    assert result == RetentionResult(
        router_id=ROUTER,
        evaluated_at=NOW,
        deleted=(),
        kept={},
        reasons={},
        total_bytes=0,
        max_bytes=MIB50,
        over_limit=False,
    )
    # The store's limit and the policy's limit: the smaller one applies.
    assert (
        plan_retention(
            ROUTER, [], gfs(max_bytes=KB), now=NOW, max_bytes=MIB50
        ).max_bytes
        == KB
    )


def test_gfs13_input_validation() -> None:
    with pytest.raises(ValueError):
        plan_retention(ROUTER, [], DEFAULT_RETENTION_POLICY, now=datetime(2026, 11, 17))
    with pytest.raises(ValueError):
        plan([item(date(2026, 11, 1)), item(date(2026, 11, 1))], gfs())
    with pytest.raises(ValueError):
        RetentionPolicy.gfs(daily=-1)
    with pytest.raises(ValueError):
        RetentionPolicy.gfs(max_bytes_per_router=-5)
    with pytest.raises(ValueError):
        ArtifactRef(storage=StorageRef(locator="x"), sha256="a" * 64, size_bytes=-1)
    with pytest.raises(ValueError):  # GFS is never mixed with count/age rules
        RetentionPolicy(daily=7, max_versions=3)
    with pytest.raises(ValueError):  # foreign router
        plan_retention("rtr_" + "b" * 32, [item(date(2026, 11, 1))], gfs(), now=NOW)
    # a naive created_at is refused already when the record is built
    with pytest.raises(ValueError, match="aware"):
        record("naive", datetime(2026, 11, 17))
