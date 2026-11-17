"""Retention of configuration backup versions (grandfather-father-son).

Plan: docs/plans/2026-11-17-config-manager.md, section 11.7 (D18).

``select_for_deletion`` is a pure function: it gets the versions, the
policy and ``now`` and returns which versions to delete. It deletes nothing
itself.

Rules:

- Kept is the union of
  - the newest successful version of each of the last ``daily`` calendar
    days (today included),
  - the newest successful version of each of the last ``weekly`` ISO weeks
    (the current week included),
  - the newest successful version of each of the last ``monthly`` calendar
    months (the current month included),
  - every ``protected`` version,
  - the newest successful version overall.
- Days, weeks and months are counted in the time zone of ``now``; every
  ``created`` is converted into it. Both must be time-zone aware.
- Failed versions (``ok=False``) never represent a day, week or month. They
  are kept while they fall into the daily window (for diagnosis) and
  deleted after that.
- If the kept versions exceed ``max_bytes``, versions that are neither
  protected nor the newest successful one are evicted: failed ones first,
  then successful ones, oldest first within each group. If that is not
  enough, ``over_limit`` is reported and nothing protected is touched.

Pure module: no Home Assistant imports, no I/O.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from types import MappingProxyType
from typing import Final, Literal

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "KEEP_DAILY",
    "KEEP_MONTHLY",
    "KEEP_NEWEST_OK",
    "KEEP_PROTECTED",
    "KEEP_RECENT_FAILED",
    "KEEP_WEEKLY",
    "RetentionDecision",
    "RetentionItem",
    "RetentionPolicy",
    "select_for_deletion",
]

VersionKind = Literal["scheduled", "manual", "drift", "release_change"]

KEEP_PROTECTED: Final = "protected"
KEEP_NEWEST_OK: Final = "newest_ok"
KEEP_DAILY: Final = "daily"
KEEP_WEEKLY: Final = "weekly"
KEEP_MONTHLY: Final = "monthly"
KEEP_RECENT_FAILED: Final = "recent_failed"
_REASON_ORDER: Final = (
    KEEP_PROTECTED,
    KEEP_NEWEST_OK,
    KEEP_DAILY,
    KEEP_WEEKLY,
    KEEP_MONTHLY,
    KEEP_RECENT_FAILED,
)

DEFAULT_MAX_BYTES: Final = 50 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class RetentionItem:
    """One stored version as far as retention cares."""

    version_id: str
    created: datetime
    size_bytes: int
    protected: bool
    ok: bool
    kind: VersionKind

    def __post_init__(self) -> None:
        if self.size_bytes < 0:
            raise ValueError("size_bytes must not be negative")


@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """GFS counts and the size limit per router (None = no limit)."""

    daily: int = 7
    weekly: int = 4
    monthly: int = 6
    max_bytes: int | None = DEFAULT_MAX_BYTES

    def __post_init__(self) -> None:
        if min(self.daily, self.weekly, self.monthly) < 0:
            raise ValueError("retention counts must not be negative")
        if self.max_bytes is not None and self.max_bytes < 0:
            raise ValueError("max_bytes must not be negative")


@dataclass(frozen=True, slots=True)
class RetentionDecision:
    """Outcome of ``select_for_deletion``.

    ``delete`` and ``keep`` are version ids, oldest first. ``reasons`` maps
    every kept id to why it stays (``KEEP_*``). ``total_bytes`` is the size
    of the kept versions; ``over_limit`` is True when it still exceeds
    ``max_bytes``.
    """

    delete: tuple[str, ...]
    keep: tuple[str, ...]
    reasons: Mapping[str, tuple[str, ...]]
    total_bytes: int
    max_bytes: int | None
    over_limit: bool


def _require_aware(value: datetime, what: str) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{what} must be a time-zone aware datetime")


def _month_back(day: date, months: int) -> tuple[int, int]:
    index = day.year * 12 + (day.month - 1) - months
    return index // 12, index % 12 + 1


def select_for_deletion(
    items: Sequence[RetentionItem], policy: RetentionPolicy, now: datetime
) -> RetentionDecision:
    """Return which versions to delete under ``policy`` at ``now``.

    Raises ValueError for naive datetimes and duplicate version ids.
    """
    _require_aware(now, "now")
    seen: set[str] = set()
    for entry in items:
        _require_aware(entry.created, f"created of {entry.version_id!r}")
        if entry.version_id in seen:
            raise ValueError(f"duplicate version id {entry.version_id!r}")
        seen.add(entry.version_id)

    tz = now.tzinfo
    today = now.date()
    local = {entry.version_id: entry.created.astimezone(tz) for entry in items}
    chrono = sorted(items, key=lambda e: (local[e.version_id], e.version_id))

    daily_days = {today - timedelta(days=k) for k in range(policy.daily)}
    weekly_weeks = {
        (today - timedelta(weeks=k)).isocalendar()[:2] for k in range(policy.weekly)
    }
    monthly_months = {_month_back(today, k) for k in range(policy.monthly)}

    reasons: dict[str, set[str]] = {}

    def keep(version_id: str, reason: str) -> None:
        reasons.setdefault(version_id, set()).add(reason)

    # Newest successful version per period: later entries overwrite.
    newest_day: dict[date, str] = {}
    newest_week: dict[tuple[int, int], str] = {}
    newest_month: dict[tuple[int, int], str] = {}
    newest_ok: str | None = None
    for entry in chrono:
        when = local[entry.version_id]
        if entry.protected:
            keep(entry.version_id, KEEP_PROTECTED)
        if not entry.ok:
            if when.date() in daily_days:
                keep(entry.version_id, KEEP_RECENT_FAILED)
            continue
        newest_ok = entry.version_id
        newest_day[when.date()] = entry.version_id
        newest_week[when.isocalendar()[:2]] = entry.version_id
        newest_month[(when.year, when.month)] = entry.version_id
    if newest_ok is not None:
        keep(newest_ok, KEEP_NEWEST_OK)
    for day, version_id in newest_day.items():
        if day in daily_days:
            keep(version_id, KEEP_DAILY)
    for week, version_id in newest_week.items():
        if week in weekly_weeks:
            keep(version_id, KEEP_WEEKLY)
    for month, version_id in newest_month.items():
        if month in monthly_months:
            keep(version_id, KEEP_MONTHLY)

    by_id = {entry.version_id: entry for entry in items}
    total = sum(by_id[version_id].size_bytes for version_id in reasons)
    limit = policy.max_bytes
    if limit is not None and total > limit:
        evictable = [
            entry
            for entry in chrono
            if entry.version_id in reasons
            and not entry.protected
            and entry.version_id != newest_ok
        ]
        # Failed versions first, then the oldest successful ones.
        evictable.sort(key=lambda e: (e.ok, local[e.version_id], e.version_id))
        for entry in evictable:
            if total <= limit:
                break
            del reasons[entry.version_id]
            total -= entry.size_bytes

    over_limit = limit is not None and total > limit
    delete = tuple(e.version_id for e in chrono if e.version_id not in reasons)
    kept = tuple(e.version_id for e in chrono if e.version_id in reasons)
    if over_limit and limit is not None:
        _LOGGER.debug(
            "retention: %d byte(s) kept over the limit of %d", total - limit, limit
        )
    return RetentionDecision(
        delete=delete,
        keep=kept,
        reasons=MappingProxyType(
            {
                version_id: tuple(r for r in _REASON_ORDER if r in reasons[version_id])
                for version_id in kept
            }
        ),
        total_bytes=total,
        max_bytes=limit,
        over_limit=over_limit,
    )
