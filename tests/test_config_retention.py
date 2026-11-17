"""Tests for the GFS retention selection (configuration manager, G4).

Plan: docs/plans/2026-11-17-config-manager.md, sections 11.7 (D18) and 16
(case 11). Pure function; ``now`` and time zones come from the test.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta, timezone

import pytest

from custom_components.openwrt_router.config_retention import (
    KEEP_DAILY,
    KEEP_MONTHLY,
    KEEP_NEWEST_OK,
    KEEP_PROTECTED,
    KEEP_RECENT_FAILED,
    KEEP_WEEKLY,
    RetentionDecision,
    RetentionItem,
    RetentionPolicy,
    select_for_deletion,
)

LOCAL = timezone(timedelta(hours=1), "CET")
# Tuesday, ISO week 47 of 2026.
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=LOCAL)
KB = 100 * 1024


def item(
    day: date,
    *,
    hour: int = 3,
    ok: bool = True,
    protected: bool = False,
    size: int = KB,
    kind: str = "scheduled",
    suffix: str = "",
) -> RetentionItem:
    created = datetime.combine(day, time(hour), tzinfo=LOCAL)
    return RetentionItem(
        version_id=f"v{day.isoformat()}T{hour:02d}{suffix}",
        created=created,
        size_bytes=size,
        protected=protected,
        ok=ok,
        kind=kind,  # type: ignore[arg-type]
    )


def daily_items(first: date, last: date, **kwargs: object) -> list[RetentionItem]:
    out = []
    day = first
    while day <= last:
        out.append(item(day, **kwargs))  # type: ignore[arg-type]
        day += timedelta(days=1)
    return out


def ids(*days: date) -> set[str]:
    return {f"v{d.isoformat()}T03" for d in days}


BIG = RetentionPolicy(max_bytes=1 << 40)


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
    assert set(decision.delete) == {i.version_id for i in items} - expected
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
    assert old_protected.version_id in decision.keep
    assert decision.reasons[old_protected.version_id] == (KEEP_PROTECTED,)
    # Also under a size limit far too small and with GFS switched off.
    tight = RetentionPolicy(daily=0, weekly=0, monthly=0, max_bytes=1)
    decision = select_for_deletion(items, tight, NOW)
    assert old_protected.version_id in decision.keep
    assert old_protected.version_id not in decision.delete
    assert decision.over_limit is True


def test_newest_ok_always_kept() -> None:
    newest_ok = item(date(2026, 9, 1))
    failed_after = [item(date(2026, 11, d), ok=False) for d in (15, 16, 17)]
    nothing = RetentionPolicy(daily=0, weekly=0, monthly=0, max_bytes=1)
    decision = select_for_deletion(
        [item(date(2026, 8, 1)), newest_ok, *failed_after], nothing, NOW
    )
    assert newest_ok.version_id in decision.keep
    assert KEEP_NEWEST_OK in decision.reasons[newest_ok.version_id]
    assert newest_ok.version_id not in decision.delete
    assert "v2026-08-01T03" in decision.delete


def test_failed_versions_do_not_represent_a_period() -> None:
    ok_morning = item(date(2026, 11, 16), hour=3)
    failed_evening = item(date(2026, 11, 16), hour=21, ok=False)
    newest = item(date(2026, 11, 17))
    decision = select_for_deletion(
        [ok_morning, failed_evening, newest], RetentionPolicy(weekly=0, monthly=0), NOW
    )
    assert ok_morning.version_id in decision.keep
    assert KEEP_DAILY in decision.reasons[ok_morning.version_id]
    # Failed versions inside the daily window stay for diagnosis ...
    assert decision.reasons[failed_evening.version_id] == (KEEP_RECENT_FAILED,)


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
    assert old_failed.version_id in decision.delete
    assert month_end_failed.version_id in decision.delete
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
    assert protected.version_id in decision.keep
    assert decision.total_bytes == 5 * KB
    assert decision.over_limit is False


def test_size_limit_evicts_failed_before_successful() -> None:
    items = daily_items(date(2026, 11, 11), date(2026, 11, 17), size=KB)
    failed = item(date(2026, 11, 17), hour=1, ok=False, size=KB)
    decision = select_for_deletion(
        [*items, failed], RetentionPolicy(max_bytes=7 * KB), NOW
    )
    assert list(decision.delete) == [failed.version_id]


def test_over_limit_reported_not_forced() -> None:
    protected = [item(date(2026, 1, d), protected=True, size=3 * KB) for d in (1, 2)]
    newest = item(date(2026, 11, 17), size=3 * KB)
    older = item(date(2026, 11, 16), size=KB)
    decision = select_for_deletion(
        [*protected, older, newest], RetentionPolicy(max_bytes=4 * KB), NOW
    )
    assert decision.over_limit is True
    assert decision.delete == (older.version_id,)
    assert set(decision.keep) == {p.version_id for p in protected} | {newest.version_id}
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
    naive = RetentionItem("x", datetime(2026, 11, 17), KB, False, True, "manual")
    with pytest.raises(ValueError):
        select_for_deletion([naive], RetentionPolicy(), NOW)
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
