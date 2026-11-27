"""Self-Healing package G: the link to the Configuration Manager.

``heal_config_link`` turns what the Configuration Manager already holds (the
core's version index in memory, and the comparison of two STORED versions)
into ``heal_playbooks.ConfigFact`` and the preflight's configuration facts.
Order tests 14 (drift recovery, deep), 18 (rollback available) and 19
(rollback not available): after a configuration change a drift is recognised
and the plan names the backup it would use; a restore is reported as not
executable; nothing is rolled back. The recorded-call test proves zero router
calls (the core's coordinator api is a recording mock).

Closed sets are pinned by literal lists. The random test checks against a
simulated ground truth (the real change times), not against the algorithm.
"""

from __future__ import annotations

import dataclasses
import json
import logging
import random
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from core_test_provider import (
    FakeConfigProvider,
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import ADMIN_ID, FakeDisks, bus_events, user_actor
from test_heal_playbooks_v1530 import T_START, ctx, dhcp_ev, incident

from custom_components.openwrt_router import config_const as cc
from custom_components.openwrt_router import heal_config_link as hcl
from custom_components.openwrt_router import heal_playbooks as pb
from custom_components.openwrt_router import heal_preflight as hpf
from custom_components.openwrt_router.core_models import (
    BackupReason,
    BackupType,
    ChangeKind,
    ConfigChange,
    ConfigDiff,
    ConfigRef,
    ValidationStatus,
    VersionStatus,
)

RID = "rtr_" + "1" * 32
OTHER_RID = "rtr_" + "2" * 32
T0 = 1_789_000_000.0


def bid(n: int) -> str:
    return f"bkp_{n:032x}"


def h(n: int) -> str:
    return f"{n:064x}"


def dt(t: float) -> datetime:
    return datetime.fromtimestamp(t, UTC)


def rec(
    n: int,
    t: float,
    content: int | None,
    *,
    seen: float | None = None,
    status: Any = VersionStatus.OK,
    validation: Any = ValidationStatus.UNVERIFIED,
    archive: bool = True,
    backup_type: Any = BackupType.FULL_ARCHIVE,
    router_id: str = RID,
) -> SimpleNamespace:
    """A version as the core's index holds it (BackupRecord attributes)."""
    return SimpleNamespace(
        backup_id=bid(n),
        router_id=router_id,
        created_at=dt(t),
        last_seen_at=None if seen is None else dt(seen),
        status=status,
        validation=SimpleNamespace(status=validation),
        sha256="a" * 64 if archive else None,
        uci_hash=None if content is None else h(content),
        backup_type=backup_type,
    )


class Versions:
    """The core's version store as far as the link reads it."""

    def __init__(self, *records: Any, loaded: bool = True) -> None:
        self.loaded = loaded
        self._records = records
        self.asked: list[str] = []

    def records(self, router_id: str) -> tuple[Any, ...]:
        self.asked.append(router_id)
        return self._records


def knowledge(*records: Any) -> hcl.ConfigKnowledge:
    return hcl.knowledge_from_versions(Versions(*records), RID)


def diff_of(
    base: str,
    other: str,
    *changes: tuple[str, str | None, str | None],
    truncated: bool = False,
) -> ConfigDiff:
    """A core ConfigDiff of two stored versions; changes: (kind, area, risk)."""
    return ConfigDiff(
        base=ConfigRef.backup(base),
        other=ConfigRef.backup(other),
        compared_at=dt(T0),
        changes=tuple(
            ConfigChange(kind=k, config="dhcp", section="lan", area=a, risk=r)
            for k, a, r in changes
        ),
        truncated=truncated,
    )


def link(
    k: hcl.ConfigKnowledge,
    *,
    wall: float = T0 + 3600,
    before: float | None = None,
    diff: hcl.StoredDiff | None = None,
) -> hcl.ConfigLink:
    return hcl.ConfigLink(knowledge=k, wall_at=wall, before=before, diff=diff)


def changed_link(**over: Any) -> hcl.ConfigLink:
    """Two versions, the second one after a DHCP change (both before T_START)."""
    k = knowledge(rec(1, T_START - 7200, 1), rec(2, T_START - 600, 2))
    sd = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("modified", "dhcp", "medium")), bid(1), bid(2)
    )
    args: dict[str, Any] = {"wall": T_START + 60, "diff": sd}
    args.update(over)
    return link(k, **args)


# ---------------------------------------------------------------------------
# Closed sets, pinned literally
# ---------------------------------------------------------------------------


def test_reason_codes_are_a_closed_literal_set_with_german_texts() -> None:
    expected = [
        "core_not_running",
        "versions_not_loaded",
        "source_error",
        "invalid_router_id",
        "no_usable_version",
        "single_content",
        "ambiguous_order",
        "diff_not_read",
        "diff_other_versions",
        "diff_failed",
        "diff_unreadable",
        "diff_truncated",
        "diff_area_unknown",
        "secrets_not_comparable",
        "snapshot_time_ahead",
        "backup_time_ahead",
        "running_config_not_tracked",
        "restore_dry_run_not_run",
        "restore_unsupported_dry_run_only",
    ]
    assert list(hcl.REASONS) == expected
    assert sorted(hcl.REASON_TEXT_DE) == sorted(expected)
    for text in hcl.REASON_TEXT_DE.values():
        assert text and "{" not in text


def test_value_sets_and_constants_are_pinned() -> None:
    assert hcl.CAPTURED_VALUES == ("current", "outdated", "none")
    assert hcl.BACKUP_VALUES == ("verified", "unverified", "outdated", "none")
    assert hcl.RESTORE_STATEMENT == "restore_unsupported_dry_run_only"
    assert hcl.CHANGE_WINDOW_S == 86400
    assert hcl.LINK_VERSION == 1
    assert hcl.ACTOR_MODULE == "self_healing"
    assert hcl.USABLE_STATUSES == ("ok", "partial")
    assert hcl.DIFF_VALIDATIONS == ("valid", "unverified")
    assert hcl.BACKUP_TYPES == ("full_archive", "uci_snapshot", "partial")


def test_constants_agree_with_the_modules_they_mirror() -> None:
    from custom_components.openwrt_router import heal_engine

    assert heal_engine.MODULE == "self_healing"
    assert sorted(k.value for k in ChangeKind) == sorted(
        ["added", "removed", "modified", "reordered", "not_comparable"]
    )
    assert sorted(t.value for t in BackupType) == sorted(
        ["full_archive", "uci_snapshot", "partial"]
    )
    assert hpf.SNAPSHOT_MAX_AGE_S == 86400
    assert set(cc.AREAS) == set(pb.CONFIG_AREAS)


# ---------------------------------------------------------------------------
# Normalisation (anything odd is unknown, never an error)
# ---------------------------------------------------------------------------


def test_version_row_normalises_odd_values() -> None:
    row = hcl.VersionRow(
        backup_id="bkp_XYZ",
        created_at=True,
        last_seen_at=float("nan"),
        status="OK",
        validation="192.168.1.1",
        has_checksum="yes",
        content_hash="AB" * 32,
        backup_type="tarball",
    )
    assert (row.backup_id, row.created_at, row.last_seen_at) == (None, None, None)
    assert (row.status, row.validation) == ("unknown", "unknown")
    assert row.has_checksum is False
    assert row.content_hash is None and row.backup_type is None
    assert row.complete is False and row.comparable is False


def test_version_row_times() -> None:
    naive = datetime(2026, 1, 1)
    assert hcl.VersionRow(created_at=naive).created_at is None
    assert hcl.VersionRow(created_at=-1).created_at is None
    assert hcl.VersionRow(created_at=2e11).created_at is None
    assert hcl.VersionRow(created_at=dt(T0)).created_at == T0
    # a last_seen before created is dropped; equal is kept
    assert hcl.VersionRow(created_at=T0, last_seen_at=T0 - 1).last_seen_at is None
    assert hcl.VersionRow(created_at=T0, last_seen_at=T0).last_seen_at == T0
    assert hcl.VersionRow(created_at=None, last_seen_at=T0).last_seen_at is None


def test_version_row_validates_again_on_replace() -> None:
    row = hcl.VersionRow(backup_id=bid(1), created_at=T0, status="ok")
    assert replace(row, backup_id="nope").backup_id is None
    assert replace(row, status="O K").status == "unknown"


def test_version_row_restorable_only_as_usable_full_archive() -> None:
    def row(**over: Any) -> hcl.VersionRow:
        base: dict[str, Any] = {
            "backup_id": bid(1),
            "created_at": T0,
            "status": "ok",
            "validation": "valid",
            "has_checksum": True,
            "backup_type": "full_archive",
        }
        base.update(over)
        return hcl.VersionRow(**base)

    assert row().restorable_by_hand is True
    assert row(validation="unverified").restorable_by_hand is True
    assert row(validation="corrupt").restorable_by_hand is False
    assert row(status="partial").restorable_by_hand is False
    assert row(has_checksum=False).restorable_by_hand is False
    assert row(backup_type="uci_snapshot").restorable_by_hand is False


def test_knowledge_normalises_and_never_raises() -> None:
    bad = hcl.ConfigKnowledge(router_id="router-1", rows=())
    assert (bad.router_id, bad.rows, bad.reason) == (None, None, "invalid_router_id")
    assert hcl.ConfigKnowledge(router_id=RID).reason == "source_error"
    assert hcl.ConfigKnowledge(router_id=RID, reason="anything").reason == (
        "source_error"
    )
    assert hcl.ConfigKnowledge(router_id=RID, reason="versions_not_loaded").reason == (
        "versions_not_loaded"
    )
    assert hcl.ConfigKnowledge(router_id=RID, rows="abc").rows is None
    assert hcl.ConfigKnowledge(router_id=RID, rows={"a": 1}).rows is None
    assert hcl.ConfigKnowledge(router_id=RID, rows=5).reason == "source_error"
    good = hcl.VersionRow(backup_id=bid(2), created_at=T0 + 5, status="ok")
    older = hcl.VersionRow(backup_id=bid(1), created_at=T0, status="ok")
    twice = hcl.VersionRow(backup_id=bid(2), created_at=T0 - 99, status="failed")
    k = hcl.ConfigKnowledge(
        router_id=RID,
        rows=[good, "row", hcl.VersionRow(created_at=T0), older, twice],
    )
    assert [r.backup_id for r in k.rows] == [bid(1), bid(2)]  # oldest first
    assert k.rows[1].status == "ok"  # the first of a duplicate id wins
    assert k.readable is True and k.reason is None
    assert hcl.ConfigKnowledge(router_id=RID, rows=()).rows == ()


def test_knowledge_keeps_the_newest_rows_only() -> None:
    rows = [
        hcl.VersionRow(backup_id=bid(i), created_at=T0 + i, status="ok")
        for i in range(hcl.ROWS_MAX + 5)
    ]
    k = hcl.ConfigKnowledge(router_id=RID, rows=rows)
    assert len(k.rows) == hcl.ROWS_MAX
    assert k.rows[0].backup_id == bid(5) and k.rows[-1].backup_id == bid(1004)


def test_knowledge_from_versions_reports_unknown_with_reasons() -> None:
    assert hcl.knowledge_from_versions(None, RID).reason == "core_not_running"
    assert hcl.knowledge_from_versions(Versions(loaded=False), RID).reason == (
        "versions_not_loaded"
    )
    assert hcl.knowledge_from_versions(Versions(), "nope").reason == (
        "invalid_router_id"
    )

    class Broken:
        loaded = True

        def records(self, router_id: str) -> Any:
            raise RuntimeError("192.168.1.1 secret")

    class BadRecord:
        @property
        def backup_id(self) -> str:
            raise KeyError("x")

    assert hcl.knowledge_from_versions(Broken(), RID).reason == "source_error"
    assert hcl.knowledge_from_versions(Versions(BadRecord()), RID).reason == (
        "source_error"
    )
    garbage = hcl.knowledge_from_versions(Versions(object(), 5, None), RID)
    assert garbage.rows == ()
    # a version of another router is left out
    mixed = knowledge(rec(1, T0, 1), rec(2, T0 + 1, 2, router_id=OTHER_RID))
    assert [r.backup_id for r in mixed.rows] == [bid(1)]


def test_knowledge_from_versions_asks_only_for_this_router() -> None:
    versions = Versions(rec(1, T0, 1))
    hcl.knowledge_from_versions(versions, RID)
    assert versions.asked == [RID]


# ---------------------------------------------------------------------------
# The stored comparison
# ---------------------------------------------------------------------------


def test_stored_diff_areas_and_risk() -> None:
    d = diff_of(
        bid(1),
        bid(2),
        ("modified", "dhcp", "medium"),
        ("added", "wlan", "low"),
        ("removed", "vlan", "critical"),
    )
    sd = hcl.stored_diff_from(d, bid(1), bid(2))
    assert sd.proven is True
    assert sd.areas == frozenset({"dhcp", "wlan", "vlan"})
    assert sd.change_risk == "critical"
    assert sd.reason is None
    one = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("reordered", "dns", "high")), bid(1), bid(2)
    )
    assert (one.areas, one.change_risk) == (frozenset({"dns"}), "high")


def test_stored_diff_unknown_risk_makes_the_risk_unknown_only() -> None:
    d = diff_of(bid(1), bid(2), ("modified", "dhcp", "low"), ("added", "dns", None))
    sd = hcl.stored_diff_from(d, bid(1), bid(2))
    assert sd.proven is True and sd.change_risk is None
    assert sd.areas == frozenset({"dhcp", "dns"})


@pytest.mark.parametrize(
    ("changes", "truncated", "reason"),
    [
        ((("not_comparable", "wlan", "low"),), False, "secrets_not_comparable"),
        (
            (("modified", "dhcp", "low"), ("not_comparable", "wlan", "low")),
            False,
            "secrets_not_comparable",
        ),
        ((("modified", None, "low"),), False, "diff_area_unknown"),
        ((("modified", "nowhere", "low"),), False, "diff_area_unknown"),
        ((("modified", "dhcp", "low"),), True, "diff_truncated"),
    ],
)
def test_stored_diff_incomplete_is_unknown(
    changes: tuple[Any, ...], truncated: bool, reason: str
) -> None:
    sd = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), *changes, truncated=truncated), bid(1), bid(2)
    )
    assert (sd.proven, sd.areas, sd.change_risk, sd.reason) == (
        None,
        None,
        None,
        reason,
    )


def test_stored_diff_without_changes_is_a_known_no() -> None:
    sd = hcl.stored_diff_from(diff_of(bid(1), bid(2)), bid(1), bid(2))
    assert (sd.proven, sd.areas, sd.reason) == (False, frozenset(), None)


def test_stored_diff_of_other_or_live_versions_is_unknown() -> None:
    assert (
        hcl.stored_diff_from(diff_of(bid(1), bid(3)), bid(1), bid(2)).reason
        == "diff_other_versions"
    )
    assert (
        hcl.stored_diff_from(diff_of(bid(3), bid(2)), bid(1), bid(2)).reason
        == "diff_other_versions"
    )
    live = ConfigDiff(
        base=ConfigRef.backup(bid(1)),
        other=ConfigRef.live(RID),
        compared_at=dt(T0),
    )
    assert hcl.stored_diff_from(live, bid(1), bid(2)).reason == "diff_other_versions"
    assert hcl.stored_diff_from(None, bid(1), bid(2)).reason == "diff_unreadable"
    odd = SimpleNamespace(
        base=ConfigRef.backup(bid(1)),
        other=ConfigRef.backup(bid(2)),
        changes=(SimpleNamespace(kind="exploded", area="dhcp", risk="low"),),
        truncated=False,
    )
    assert hcl.stored_diff_from(odd, bid(1), bid(2)).reason == "diff_unreadable"
    no_flag = SimpleNamespace(
        base=ConfigRef.backup(bid(1)), other=ConfigRef.backup(bid(2)), changes=()
    )
    assert hcl.stored_diff_from(no_flag, bid(1), bid(2)).reason == "diff_truncated"

    class Hostile:
        @property
        def changes(self) -> Any:
            raise RuntimeError("boom")

    assert hcl.stored_diff_from(Hostile(), bid(1), bid(2)).reason == "diff_unreadable"


def test_stored_diff_validates_again() -> None:
    sd = hcl.StoredDiff(base_id=bid(1), other_id=bid(2), proven=True, areas={"dhcp"})
    assert sd.areas == frozenset({"dhcp"})
    for bad in (
        {"areas": set()},
        {"areas": {"moon"}},
        {"areas": None},
        {"areas": 5},
        {"other_id": bid(1)},
        {"base_id": "x"},
    ):
        out = replace(sd, **bad)
        assert (out.proven, out.areas, out.reason) == (None, None, "diff_unreadable")
    assert replace(sd, proven=False, areas={"dhcp"}).reason == "diff_unreadable"
    assert replace(sd, proven=False, areas=()).proven is False
    assert replace(sd, proven="yes", reason=None).reason == "diff_unreadable"
    assert replace(sd, proven=None, reason="diff_failed").reason == "diff_failed"
    assert replace(sd, change_risk="extreme").change_risk is None
    assert replace(sd, proven=False, areas=(), change_risk="low").change_risk is None


# ---------------------------------------------------------------------------
# Which versions, and the time bounds
# ---------------------------------------------------------------------------


def test_last_change_and_its_bounds() -> None:
    k = knowledge(
        rec(1, T0, 1),
        rec(2, T0 + 100, 1, seen=T0 + 200),
        rec(3, T0 + 300, 2),
        rec(4, T0 + 400, 2),
    )
    sel = hcl.select_versions(k)
    pair = sel.pair
    assert pair is not None and sel.reason is None
    assert (pair.base_id, pair.other_id) == (bid(2), bid(4))
    # the old content was last seen at T0+200 (dedup), the new first at T0+300
    assert (pair.changed_after, pair.changed_at) == (T0 + 200, T0 + 300)
    assert sel.latest is not None and sel.latest.backup_id == bid(4)


def test_a_revert_seen_by_a_dedup_hit_is_the_last_change() -> None:
    # content 1 at T0, content 2 at T0+100, content 1 again at T0+200 (the
    # older version's dedup hit): the last change is 2 -> 1
    k = knowledge(rec(1, T0, 1, seen=T0 + 200), rec(2, T0 + 100, 2))
    pair = hcl.select_versions(k).pair
    assert pair is not None
    assert (pair.base_id, pair.other_id) == (bid(2), bid(1))
    assert (pair.changed_after, pair.changed_at) == (T0 + 100, T0 + 200)


def test_cutoff_is_strict() -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2), rec(3, T0 + 200, 3))
    at = hcl.select_versions(k, before=T0 + 200).pair
    assert at is not None and (at.base_id, at.other_id) == (bid(1), bid(2))
    after = hcl.select_versions(k, before=T0 + 200.5).pair
    assert after is not None and (after.base_id, after.other_id) == (bid(2), bid(3))
    only = hcl.select_versions(k, before=T0 + 100)
    assert only.pair is None and only.reason == "single_content"
    assert only.latest is not None and only.latest.backup_id == bid(1)
    none = hcl.select_versions(k, before=T0)
    assert (none.pair, none.latest, none.reason) == (None, None, "no_usable_version")


def test_dedup_seen_after_the_cutoff_is_not_used() -> None:
    k = knowledge(rec(1, T0, 1, seen=T0 + 500), rec(2, T0 + 100, 2))
    pair = hcl.select_versions(k, before=T0 + 300).pair
    assert pair is not None and (pair.base_id, pair.other_id) == (bid(1), bid(2))


def test_equal_times_of_two_contents_are_ambiguous() -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2), rec(3, T0 + 100, 3))
    sel = hcl.select_versions(k)
    assert (sel.pair, sel.reason) == (None, "ambiguous_order")
    k2 = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 1), rec(3, T0 + 100, 3))
    assert hcl.select_versions(k2).reason == "ambiguous_order"


@pytest.mark.parametrize(
    "bad",
    [
        {"status": VersionStatus.PARTIAL},
        {"status": VersionStatus.FAILED},
        {"validation": ValidationStatus.INVALID},
        {"validation": ValidationStatus.CORRUPT},
        {"validation": ValidationStatus.MISSING},
    ],
)
def test_only_usable_versions_with_content_take_part(bad: dict[str, Any]) -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2, **bad))
    assert hcl.select_versions(k).reason == "single_content"
    no_hash = knowledge(rec(1, T0, 1), rec(2, T0 + 100, None))
    assert hcl.select_versions(no_hash).reason == "single_content"
    valid = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2, validation="valid"))
    assert hcl.select_versions(valid).pair is not None


def test_plan_backup_is_the_newest_restorable_archive_of_the_old_content() -> None:
    k = knowledge(
        rec(1, T0, 1),  # archive, old content
        rec(2, T0 + 50, 1, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
        rec(3, T0 + 100, 2),
    )
    pair = hcl.select_versions(k).pair
    assert pair is not None
    assert pair.base_id == bid(2)
    assert (pair.plan_backup_id, pair.plan_backup_restorable) == (bid(1), True)
    # an archive of the old content before ANOTHER content does not count
    k2 = knowledge(
        rec(1, T0, 1),
        rec(2, T0 + 20, 5),
        rec(3, T0 + 50, 1, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
        rec(4, T0 + 100, 2),
    )
    pair2 = hcl.select_versions(k2).pair
    assert pair2 is not None
    assert (pair2.plan_backup_id, pair2.plan_backup_restorable) == (bid(3), False)


def test_version_pair_validates() -> None:
    good: dict[str, Any] = {
        "base_id": bid(1),
        "other_id": bid(2),
        "changed_after": T0,
        "changed_at": T0 + 1,
        "plan_backup_id": bid(1),
        "plan_backup_restorable": True,
    }
    hcl.VersionPair(**good)
    for bad in (
        {"other_id": bid(1)},
        {"changed_at": T0},
        {"changed_after": float("inf")},
        {"plan_backup_id": "x"},
        {"plan_backup_restorable": 1},
        {"base_id": None},
    ):
        with pytest.raises(hcl.ConfigLinkError):
            hcl.VersionPair(**{**good, **bad})


def test_select_versions_inputs() -> None:
    with pytest.raises(hcl.ConfigLinkError):
        hcl.select_versions(object())  # type: ignore[arg-type]
    with pytest.raises(hcl.ConfigLinkError):
        hcl.select_versions(knowledge(), before=float("nan"))
    unreadable = hcl.select_versions(hcl.knowledge_from_versions(None, RID))
    assert (unreadable.pair, unreadable.reason) == (None, "core_not_running")


def _simulate(rng: random.Random) -> tuple[list[Any], list[float], Any, float | None]:
    """A true configuration timeline and the versions that observed it."""
    times = sorted(rng.sample(range(1, 400), rng.randint(0, 6)))
    contents = [rng.randint(1, 3) for _ in range(len(times) + 1)]

    def at(t: float) -> int:
        return contents[sum(1 for c in times if c <= t)]

    true_changes = [
        float(times[i]) for i in range(len(times)) if contents[i + 1] != contents[i]
    ]
    records = []
    for n in range(rng.randint(0, 8)):
        t = float(rng.randint(0, 450))
        seen = None
        if rng.random() < 0.4:
            later = t + rng.randint(0, 60)
            if at(later) == at(t):
                seen = later
        status = rng.choice([VersionStatus.OK] * 4 + [VersionStatus.PARTIAL])
        validation = rng.choice(
            [ValidationStatus.UNVERIFIED, ValidationStatus.VALID] * 2
            + [ValidationStatus.CORRUPT]
        )
        records.append(
            (
                rec(
                    n + 1,
                    T0 + t,
                    None if rng.random() < 0.1 else at(t),
                    seen=None if seen is None else T0 + seen,
                    status=status,
                    validation=validation,
                ),
                t,
                seen,
            )
        )
    before = None if rng.random() < 0.3 else float(rng.randint(0, 460))
    return records, true_changes, at, before


def test_random_histories_against_the_true_change_times() -> None:
    rng = random.Random(15300)
    pairs = 0
    for _ in range(3000):
        records, true_changes, at, before = _simulate(rng)
        k = knowledge(*(r for r, _t, _s in records))
        sel = hcl.select_versions(k, before=None if before is None else T0 + before)
        # the observations, from the inputs
        points = []
        for r, t, seen in records:
            usable = r.status is VersionStatus.OK and r.validation.status in (
                ValidationStatus.UNVERIFIED,
                ValidationStatus.VALID,
            )
            if not usable or r.uci_hash is None:
                continue
            for p in {t, seen} - {None}:
                if before is None or p < before:
                    points.append((p, at(p)))
        if len({c for _p, c in points}) < 2:
            assert sel.pair is None
            assert sel.reason == ("single_content" if points else "no_usable_version")
            continue
        pair = sel.pair
        assert pair is not None
        pairs += 1
        after, changed = pair.changed_after - T0, pair.changed_at - T0
        newest = max(points)[1]
        # the real last change lies in (changed_after, changed_at]
        real = [c for c in true_changes if c <= changed]
        assert real and after < max(real) <= changed
        if before is not None:
            assert changed < before  # so the real change is strictly before
        # the bounds are tight: observations of the old content up to
        # changed_after, of the newest content from changed_at on, none between
        assert (after, at(after)) in points and at(after) != newest
        assert (changed, newest) in points
        assert all(c == newest for p, c in points if p >= changed)
        assert not [p for p, _c in points if after < p < changed]
    assert pairs > 500


# ---------------------------------------------------------------------------
# The link: ConfigFact
# ---------------------------------------------------------------------------


def test_unreadable_index_leaves_everything_unknown() -> None:
    for versions, reason in (
        (None, "core_not_running"),
        (Versions(loaded=False), "versions_not_loaded"),
    ):
        lk = link(hcl.knowledge_from_versions(versions, RID))
        assert lk.config_fact == pb.ConfigFact()
        for fact in (lk.backups, lk.config_captured, lk.backup_present):
            assert (fact.value, fact.reason, fact.source) == (
                None,
                reason,
                "core.versions",
            )
        assert lk.reasons["version_known"] == reason
        assert lk.reasons["diff_proven"] == reason


def test_empty_index_is_a_known_no() -> None:
    lk = link(knowledge())
    assert lk.config_fact == pb.ConfigFact(version_known=False, backup_present=False)
    assert lk.backups.value == ()
    assert lk.config_captured.value == "none"
    assert lk.backup_present.value == "none"
    assert lk.reasons["version_known"] == "no_usable_version"


def test_one_content_names_the_latest_version_but_proves_no_change() -> None:
    lk = link(knowledge(rec(1, T0, 1), rec(2, T0 + 10, 1)))
    cf = lk.config_fact
    assert (cf.version_known, cf.version_id, cf.backup_present) == (True, bid(2), True)
    assert (cf.diff_proven, cf.changed_areas, cf.changed_at) == (None, None, None)
    assert lk.reasons["diff_proven"] == "single_content"
    uci = link(knowledge(rec(1, T0, 1, archive=False)))
    assert uci.config_fact.backup_present is False


def test_change_without_a_read_diff_stays_unknown() -> None:
    lk = changed_link(diff=None)
    cf = lk.config_fact
    assert (cf.version_known, cf.version_id) == (True, bid(1))
    assert (cf.diff_proven, cf.changed_areas, cf.changed_at) == (None, None, None)
    assert lk.reasons["diff_proven"] == "diff_not_read"


def test_change_with_the_stored_diff() -> None:
    lk = changed_link()
    cf = lk.config_fact
    assert cf.diff_proven is True
    assert cf.changed_areas == frozenset({"dhcp"})
    assert cf.change_risk == "medium"
    assert cf.changed_at == T_START - 600
    assert cf.version_id == bid(1) and cf.backup_present is True
    assert cf.restore_check is None  # the dry run talks to the router: not run
    assert "diff_proven" not in lk.reasons
    assert lk.reasons["restore_check"] == "restore_dry_run_not_run"
    assert lk.pair is not None and lk.pair.changed_after == T_START - 7200


def test_a_diff_of_other_versions_or_an_unknown_diff_is_not_used() -> None:
    other = hcl.StoredDiff(base_id=bid(1), other_id=bid(9), proven=True, areas={"dns"})
    lk = changed_link(diff=other)
    assert lk.config_fact.diff_proven is None
    assert lk.reasons["diff_proven"] == "diff_other_versions"
    failed = hcl.StoredDiff(base_id=bid(1), other_id=bid(2), reason="diff_failed")
    lk2 = changed_link(diff=failed)
    assert lk2.config_fact.diff_proven is None
    assert lk2.reasons["diff_proven"] == "diff_failed"
    same = hcl.StoredDiff(base_id=bid(1), other_id=bid(2), proven=False, areas=())
    lk3 = changed_link(diff=same)
    assert lk3.config_fact.diff_proven is False
    assert lk3.config_fact.changed_areas == frozenset()
    assert lk3.config_fact.changed_at is None


def test_the_cutoff_picks_the_change_before_the_incident() -> None:
    k = knowledge(
        rec(1, T_START - 7200, 1), rec(2, T_START - 600, 2), rec(3, T_START + 60, 3)
    )
    sd12 = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("modified", "dhcp", "low")), bid(1), bid(2)
    )
    lk = link(k, wall=T_START + 120, before=T_START, diff=sd12)
    assert lk.config_fact.changed_at == T_START - 600
    assert lk.config_fact.diff_proven is True
    # without the cutoff the last change is 2 -> 3, after the start: the
    # diff of 1 -> 2 is not the selected pair
    lk2 = link(k, wall=T_START + 120, diff=sd12)
    assert lk2.config_fact.diff_proven is None
    assert lk2.reasons["diff_proven"] == "diff_other_versions"


def test_link_validates_its_inputs_and_derives_again() -> None:
    k = knowledge(rec(1, T0, 1))
    for bad in (
        {"knowledge": object()},
        {"wall_at": float("inf")},
        {"wall_at": True},
        {"before": "now"},
        {"diff": "diff"},
    ):
        args: dict[str, Any] = {"knowledge": k, "wall_at": T0}
        args.update(bad)
        with pytest.raises(hcl.ConfigLinkError):
            hcl.ConfigLink(**args)
    lk = changed_link()
    with pytest.raises((TypeError, ValueError)):
        hcl.ConfigLink(  # type: ignore[call-arg]
            knowledge=k, wall_at=T0, config_fact=pb.ConfigFact(diff_proven=True)
        )
    again = replace(lk, diff=None)
    assert again.config_fact.diff_proven is None
    # a row forced into the frozen knowledge is validated again
    forced = knowledge(rec(1, T0, 1))
    object.__setattr__(forced, "rows", (hcl.VersionRow(created_at=T0),))
    assert link(forced).knowledge.rows == ()


def test_restore_is_never_executable() -> None:
    lk = changed_link()
    assert lk.restore_executable is False
    assert lk.reasons["restore"] == "restore_unsupported_dry_run_only"
    assert lk.to_dict()["restore_executable"] is False
    with pytest.raises(dataclasses.FrozenInstanceError):
        lk.restore_executable = True  # type: ignore[misc]
    with pytest.raises((TypeError, ValueError)):
        replace(lk, restore_executable=True)


# ---------------------------------------------------------------------------
# Order tests 14, 18, 19: playbook F with the link
# ---------------------------------------------------------------------------


def test_order_14_change_before_the_incident_gives_a_plan_naming_the_backup() -> None:
    lk = changed_link(before=T_START)
    inc = incident(service="odhcpd", cause="dhcp_server")
    a = pb.assess(inc, dhcp_ev(config=lk.config_fact))
    assert a.match.playbook_id == "drift_recovery"
    assert a.match.drift_overlay is True
    f = a.finding
    assert f is not None and f.plan is not None
    plan = f.plan
    assert plan.version_id == bid(1)  # the version before the change
    assert plan.changed_areas == ("dhcp",)
    assert plan.relevant_areas == ("dhcp",)
    assert plan.backup_present is True
    assert plan.restore_check is None
    assert plan.executes is False
    assert plan.requires_explicit_approval is True
    assert plan.restore_executable is False
    assert f.proposal is None
    assert [(w.action_type, w.reason) for w in f.withheld] == [
        ("config.restore", "restore_dry_run_only")
    ]
    assert "wont_restore_automatically" in f.will_not
    assert (
        pb.to_decision_input(f, context=ctx()) is None
    )  # nothing to decide, nothing runs
    d = f.to_dict()
    assert json.loads(json.dumps(d)) == d
    assert d["plan"]["version_id"] == bid(1)
    assert d["plan"]["restore_executable"] is False


def test_change_seen_at_or_after_the_start_is_only_a_hint() -> None:
    k = knowledge(rec(1, T_START - 7200, 1), rec(2, T_START, 2))
    sd = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("modified", "dhcp", "low")), bid(1), bid(2)
    )
    lk = link(k, wall=T_START + 60, diff=sd)
    assert lk.config_fact.changed_at == T_START
    a = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact))
    assert a.match.playbook_id == "dhcp_recovery"
    assert a.match.drift_overlay is False and a.match.drift_hint is True


def test_change_in_another_area_does_not_overlay() -> None:
    k = knowledge(rec(1, T_START - 7200, 1), rec(2, T_START - 60, 2))
    sd = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("modified", "firewall", "high")), bid(1), bid(2)
    )
    lk = link(k, wall=T_START + 60, diff=sd)
    a = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact))
    assert a.match.playbook_id == "dhcp_recovery"
    assert a.match.drift_hint is False


def test_without_a_diff_playbook_f_never_takes_over() -> None:
    lk = changed_link(diff=None, before=T_START)
    a = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact))
    assert a.match.playbook_id == "dhcp_recovery"
    assert a.match.drift_overlay is False and a.match.drift_hint is False


def test_order_19_no_restorable_backup_is_said_honestly() -> None:
    k = knowledge(
        rec(1, T_START - 7200, 1, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
        rec(2, T_START - 600, 2, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
    )
    sd = hcl.stored_diff_from(
        diff_of(bid(1), bid(2), ("modified", "dhcp", "low")), bid(1), bid(2)
    )
    lk = link(k, wall=T_START + 60, before=T_START, diff=sd)
    f = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact)).finding
    assert f is not None and f.plan is not None
    assert f.plan.version_id == bid(1)
    assert f.plan.backup_present is False
    assert "rec_enable_config_backup" in f.recommendations
    assert f.plan.restore_executable is False


def test_order_18_a_restorable_backup_is_still_no_executable_restore() -> None:
    lk = changed_link(before=T_START)
    facts = hpf.PreflightFacts(
        router_id=RID,
        safe_at=1.0,
        wall_at=T_START + 60,
        capabilities=hpf.known((("config.restore", "unavailable"),), "core.registry"),
        **lk.preflight_overrides(),
    )
    result = hpf.run_preflight(facts, "config.restore", {"version_id": bid(1)})
    checks = {c.check: c for c in result.checks}
    rec_check = checks["recovery_path_checked"]
    assert rec_check.status is hpf.CheckStatus.FAIL
    assert rec_check.reason == "restore_unavailable_dry_run_only"
    assert result.verdict is hpf.Verdict.BLOCKED


def test_plan_names_the_restorable_archive_not_the_snapshot() -> None:
    k = knowledge(
        rec(1, T_START - 9000, 1),
        rec(2, T_START - 7200, 1, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
        rec(3, T_START - 600, 2, archive=False, backup_type=BackupType.UCI_SNAPSHOT),
    )
    sd = hcl.stored_diff_from(
        diff_of(bid(2), bid(3), ("modified", "dhcp", "low")), bid(2), bid(3)
    )
    lk = link(k, wall=T_START + 60, before=T_START, diff=sd)
    f = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact)).finding
    assert f is not None and f.plan is not None
    assert f.plan.version_id == bid(1)
    assert f.plan.backup_present is True


# ---------------------------------------------------------------------------
# DriftPlan: validated again, never executable (heal_playbooks, package G)
# ---------------------------------------------------------------------------


def _plan() -> pb.DriftPlan:
    lk = changed_link(before=T_START)
    f = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact)).finding
    assert f is not None and f.plan is not None
    return f.plan


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ({"restore_executable": True}, "restore_not_executable"),
        ({"restore_executable": 1}, "restore_not_executable"),
        ({"executes": True}, "plan_must_not_execute"),
        ({"version_id": "bkp_nothex"}, "invalid_plan"),
        ({"version_known": "yes"}, "invalid_plan"),
        ({"backup_present": 1}, "invalid_plan"),
        ({"changed_areas": ("moon",)}, "invalid_plan"),
        ({"changed_areas": ["dhcp"]}, "invalid_plan"),
        ({"changed_areas": ("wlan", "dhcp")}, "invalid_plan"),
        ({"changed_areas": ("dhcp", "dhcp")}, "invalid_plan"),
        ({"changed_areas": ()}, "invalid_plan"),
        ({"relevant_areas": ("dhcp", "dns")}, "invalid_plan"),
        ({"critical_areas": ("vlan",)}, "invalid_plan"),
        ({"change_risk": "extreme"}, "invalid_plan"),
        ({"restore_check": "maybe"}, "invalid_plan"),
        ({"manual_steps": ("restore_by_hand",)}, "invalid_plan"),
        ({"manual_steps": list(pb.DRIFT_MANUAL_STEPS)}, "invalid_plan"),
    ],
)
def test_drift_plan_is_validated_again(change: dict[str, Any], code: str) -> None:
    plan = _plan()
    with pytest.raises(pb.PlaybookError, match=code):
        replace(plan, **change)


def test_drift_plan_accepts_sound_variants() -> None:
    plan = _plan()
    assert replace(plan, version_id=None).version_id is None
    assert replace(plan, change_risk=None, restore_check="compatible")
    wide = replace(plan, changed_areas=("dhcp", "firewall", "vlan"))
    assert wide.changed_areas == ("dhcp", "firewall", "vlan")
    vlan = replace(
        plan,
        changed_areas=("dhcp", "vlan"),
        relevant_areas=("dhcp", "vlan"),
        critical_areas=("vlan",),
    )
    assert vlan.critical_areas == ("vlan",)


def test_drift_plan_dict_keys_are_pinned() -> None:
    lk = changed_link(before=T_START)
    f = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact)).finding
    assert f is not None
    assert sorted(f.to_dict()["plan"]) == sorted(
        [
            "version_id",
            "version_known",
            "changed_areas",
            "relevant_areas",
            "critical_areas",
            "change_risk",
            "restore_check",
            "backup_present",
            "manual_steps",
            "requires_explicit_approval",
            "executes",
            "restore_executable",
        ]
    )


# ---------------------------------------------------------------------------
# The preflight's configuration facts
# ---------------------------------------------------------------------------


def _parity_records() -> list[Any]:
    return [
        rec(1, T0, 1, validation=ValidationStatus.VALID),
        rec(2, T0 + 1.9, 2, status=VersionStatus.PARTIAL, archive=False),
        rec(3, T0 + 2, 3, status="weird status", validation=" x"),
        rec(4, T0 + 3, 4, status=VersionStatus.FAILED, validation="192.168.1.1"),
        SimpleNamespace(backup_id="bkp_bad", created_at=dt(T0 + 4)),
        SimpleNamespace(backup_id=bid(6), created_at=datetime(2026, 1, 1)),
        *(rec(10 + i, T0 + 10 + i, 5) for i in range(70)),
    ]


def test_backups_fact_is_the_preflights_own() -> None:
    for records in (
        _parity_records(),
        [rec(1, T0, 1)],
        [],
        [rec(1, T0, 1, archive=False, validation=ValidationStatus.VALID)],
    ):
        versions = Versions(*records)
        theirs = hpf._backup_facts(hpf.FactSources(store=None, versions=versions), RID)
        ours = link(hcl.knowledge_from_versions(versions, RID)).backups
        assert ours == theirs
    for versions in (None, Versions(loaded=False)):
        theirs = hpf._backup_facts(hpf.FactSources(store=None, versions=versions), RID)
        ours = link(hcl.knowledge_from_versions(versions, RID)).backups
        assert ours == theirs


_CAPTURED_CHECK = {
    "current": ("pass", "current_snapshot"),
    "outdated": ("fail", "snapshot_outdated"),
    "none": ("fail", "no_snapshot"),
}
_BACKUP_CHECK = {
    "verified": ("pass", "validated_backup"),
    "unverified": ("fail", "backup_not_validated"),
    "outdated": ("fail", "backup_outdated"),
    "none": ("fail", "no_backup"),
}


@pytest.mark.parametrize(
    ("records", "wall", "captured", "backup"),
    [
        (
            [rec(1, T0, 1, validation=ValidationStatus.VALID)],
            T0 + 60,
            "current",
            "verified",
        ),
        ([rec(1, T0, 1)], T0 + 60, "current", "unverified"),
        ([rec(1, T0, 1, archive=False, validation="valid")], T0 + 5, "current", "none"),
        ([rec(1, T0, 1, validation="valid")], T0 + 86401, "outdated", "outdated"),
        ([rec(1, T0, 1, validation="valid")], T0 + 86400, "current", "verified"),
        ([rec(1, T0, 1, status=VersionStatus.PARTIAL)], T0 + 5, "current", "none"),
        ([rec(1, T0, 1, status=VersionStatus.FAILED)], T0 + 5, "none", "none"),
        ([], T0, "none", "none"),
        ([rec(1, T0 + 100, 1, validation="valid")], T0, None, None),
        (
            [
                rec(1, T0, 1, validation="valid"),
                rec(2, T0 + 90000, 2),
            ],
            T0 + 90060,
            "current",
            "outdated",
        ),
    ],
)
def test_summary_facts_agree_with_the_preflight_checks(
    records: list[Any], wall: float, captured: str | None, backup: str | None
) -> None:
    lk = link(knowledge(*records), wall=wall)
    facts = hpf.PreflightFacts(
        router_id=RID, safe_at=1.0, wall_at=wall, **lk.preflight_overrides()
    )
    result = hpf.run_preflight(facts, "config.restore", {"version_id": bid(1)})
    checks = {c.check: c for c in result.checks}
    cc_check, bp_check = checks["config_captured"], checks["backup_present"]
    assert lk.config_captured.value == captured
    assert lk.backup_present.value == backup
    if captured is None:
        assert lk.config_captured.reason == "snapshot_time_ahead"
        assert (cc_check.status.value, cc_check.reason) == (
            "unknown",
            "snapshot_time_ahead",
        )
    else:
        assert (cc_check.status.value, cc_check.reason) == _CAPTURED_CHECK[captured]
    if backup is None:
        assert lk.backup_present.reason == "backup_time_ahead"
        assert (bp_check.status.value, bp_check.reason) == (
            "unknown",
            "backup_time_ahead",
        )
    else:
        assert (bp_check.status.value, bp_check.reason) == _BACKUP_CHECK[backup]


def test_summary_ages() -> None:
    lk = link(
        knowledge(rec(1, T0, 1, validation="valid"), rec(2, T0 + 100, 2)),
        wall=T0 + 160,
    )
    assert lk.config_captured.age_s == 60.0  # the newest usable one
    assert lk.backup_present.age_s == 160.0  # the newest validated one
    waiting = link(knowledge(rec(1, T0, 1)), wall=T0 + 30)
    assert (waiting.backup_present.value, waiting.backup_present.age_s) == (
        "unverified",
        30.0,
    )
    ahead = link(knowledge(rec(1, T0 + 50, 1)), wall=T0)
    assert (ahead.backup_present.value, ahead.backup_present.age_s) == (
        "unverified",
        None,
    )


def test_service_config_unapplied_is_never_known() -> None:
    for lk in (
        changed_link(),
        link(knowledge()),
        link(hcl.knowledge_from_versions(None, RID)),
    ):
        fact = lk.service_config_unapplied
        assert (fact.value, fact.reason) == (None, "running_config_not_tracked")
        assert lk.preflight_overrides()["service_config_unapplied"] is fact
    facts = hpf.PreflightFacts(
        router_id=RID,
        safe_at=1.0,
        wall_at=T_START,
        **changed_link().preflight_overrides(),
    )
    result = hpf.run_preflight(facts, "service.restart", {"service": "dnsmasq"})
    check = next(c for c in result.checks if c.check == "config_captured")
    assert check.status is hpf.CheckStatus.UNKNOWN
    assert check.reason == "running_config_not_tracked"
    assert check.blocks is True and result.verdict is hpf.Verdict.BLOCKED


def test_overrides_name_exactly_preflight_fields() -> None:
    lk = changed_link()
    assert sorted(lk.preflight_overrides()) == ["backups", "service_config_unapplied"]
    names = {f.name for f in dataclasses.fields(hpf.PreflightFacts)}
    assert set(lk.preflight_overrides()) <= names


# ---------------------------------------------------------------------------
# config_change_24h for the policy
# ---------------------------------------------------------------------------


def test_config_change_24h_true_only_when_proven_recent_and_in_area() -> None:
    lk = changed_link()  # change between T_START-7200 and T_START-600
    assert lk.config_change_24h(["dhcp"]) is True
    assert lk.config_change_24h(("dns", "dhcp")) is True
    assert lk.config_change_24h(["dns"]) is None
    assert lk.config_change_24h("dhcp") is None  # a str is no area list
    assert changed_link(diff=None).config_change_24h(["dhcp"]) is None
    # the earlier bound must be inside the window
    late = changed_link(wall=T_START - 7200 + 86400)
    assert late.config_change_24h(["dhcp"]) is True
    old = changed_link(wall=T_START - 7200 + 86400.5)
    assert old.config_change_24h(["dhcp"]) is None
    # a change "seen" after the snapshot time (clock set back) is not counted
    back = changed_link(wall=T_START - 601)
    assert back.config_change_24h(["dhcp"]) is None
    exact = changed_link(wall=T_START - 600)
    assert exact.config_change_24h(["dhcp"]) is True


def test_config_change_24h_is_never_false() -> None:
    rng = random.Random(7)
    for _ in range(300):
        records, _true, _at, before = _simulate(rng)
        k = knowledge(*(r for r, _t, _s in records))
        cut = None if before is None else T0 + before
        lk = link(k, wall=T0 + rng.randint(0, 100000), before=cut)
        for areas in (["dhcp"], ["wlan", "dns"], []):
            assert lk.config_change_24h(areas) in (True, None)


# ---------------------------------------------------------------------------
# Output: codes and ids only
# ---------------------------------------------------------------------------


def test_to_dict_is_json_and_carries_no_hash_or_address() -> None:
    lk = changed_link(before=T_START)
    d = lk.to_dict()
    text = json.dumps(d)
    assert json.loads(text) == d
    assert h(1) not in text and h(2) not in text and "a" * 64 not in text
    assert d["router_id"] == RID
    assert d["config_fact"]["changed_areas"] == ["dhcp"]
    assert d["change"]["plan_backup_id"] == bid(1)
    assert sorted(d) == sorted(
        [
            "link_version",
            "router_id",
            "config_fact",
            "change",
            "preflight",
            "restore_executable",
            "reasons",
        ]
    )
    assert link(knowledge()).to_dict()["change"] is None


def test_errors_are_logged_by_type_only(caplog: pytest.LogCaptureFixture) -> None:
    class Broken:
        loaded = True

        def records(self, router_id: str) -> Any:
            raise RuntimeError("192.168.1.1 hunter2")

    with caplog.at_level(logging.DEBUG, logger=hcl.__name__):
        hcl.knowledge_from_versions(Broken(), RID)
    assert "RuntimeError" in caplog.text
    assert "192.168.1.1" not in caplog.text and "hunter2" not in caplog.text


# ---------------------------------------------------------------------------
# The stored comparison reader (async; never raises)
# ---------------------------------------------------------------------------


class Api:
    """The parts of ConfigurationApi the reader may touch."""

    def __init__(self, answer: Any = None, error: BaseException | None = None) -> None:
        self.answer = answer
        self.error = error
        self.calls: list[tuple[Any, Any, Any]] = []

    async def async_compare(self, base: Any, other: Any, *, actor: Any) -> Any:
        self.calls.append((base, other, actor))
        if self.error is not None:
            raise self.error
        return self.answer


async def test_reader_compares_two_stored_versions_as_the_module() -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2))
    api = Api(diff_of(bid(1), bid(2), ("modified", "wlan", "medium")))
    sd = await hcl.async_read_stored_diff(api, k)
    assert sd is not None and sd.proven is True and sd.areas == frozenset({"wlan"})
    ((base, other, actor),) = api.calls
    assert base == ConfigRef.backup(bid(1)) and other == ConfigRef.backup(bid(2))
    assert base.router_id is None and other.router_id is None  # never live
    assert (actor.kind.value, actor.module) == ("module", "self_healing")


async def test_reader_never_raises_and_asks_nothing_without_a_change() -> None:
    api = Api()
    assert await hcl.async_read_stored_diff(api, knowledge(rec(1, T0, 1))) is None
    assert await hcl.async_read_stored_diff(api, knowledge()) is None
    unreadable = hcl.knowledge_from_versions(None, RID)
    assert await hcl.async_read_stored_diff(api, unreadable) is None
    assert await hcl.async_read_stored_diff(api, object()) is None  # type: ignore[arg-type]
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2))
    assert await hcl.async_read_stored_diff(api, k, before="soon") is None
    assert api.calls == []
    failing = Api(error=RuntimeError("10.0.0.1"))
    sd = await hcl.async_read_stored_diff(failing, k)
    assert sd is not None and (sd.proven, sd.reason) == (None, "diff_failed")
    odd = await hcl.async_read_stored_diff(Api(answer="diff"), k)
    assert odd is not None and odd.reason == "diff_unreadable"


async def test_reader_lets_a_cancellation_through() -> None:
    import asyncio

    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2))
    with pytest.raises(asyncio.CancelledError):
        await hcl.async_read_stored_diff(Api(error=asyncio.CancelledError()), k)


async def test_reader_uses_the_cutoff() -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2), rec(3, T0 + 200, 3))
    api = Api(diff_of(bid(1), bid(2)))
    await hcl.async_read_stored_diff(api, k, before=T0 + 150)
    assert [(b.backup_id, o.backup_id) for b, o, _a in api.calls] == [(bid(1), bid(2))]


def test_hass_collectors_without_a_core() -> None:
    from core_testkit import make_hass

    hass = make_hass()
    k = hcl.collect_config_knowledge(hass, RID)
    assert (k.rows, k.reason) == (None, "core_not_running")
    lk = hcl.config_link_for(hass, RID, wall_now=T0)
    assert lk.config_fact == pb.ConfigFact()

    class Exploding:
        @property
        def data(self) -> Any:
            raise RuntimeError("x")

    assert hcl.collect_config_knowledge(Exploding(), RID).reason == "core_not_running"


async def test_async_link_without_a_core() -> None:
    from core_testkit import make_hass

    lk = await hcl.async_config_link_for(make_hass(), RID, wall_now=T0)
    assert lk.config_fact == pb.ConfigFact()
    assert lk.diff is None


# ---------------------------------------------------------------------------
# Recorded calls: a real core, zero router calls
# ---------------------------------------------------------------------------


class AreaProvider(FakeConfigProvider):
    """The test provider, with the areas the real provider sets."""

    async def async_compare(self, base: Any, other: Any, ctx: Any, **kw: Any) -> Any:
        diff = await super().async_compare(base, other, ctx, **kw)
        return replace(
            diff,
            changes=tuple(
                replace(c, area=cc.AREA_RULES.get(c.config, "other"), risk="medium")
                for c in diff.changes
            ),
        )


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _saves(disks: FakeDisks) -> dict[str, tuple[int, int]]:
    return {k: (len(d.saves), len(d.delayed)) for k, d in disks.disks.items()}


async def test_recorded_calls_zero_router_calls(
    disks: FakeDisks, tmp_path: Any
) -> None:
    env = await start_env(disks, tmp_path, provider=AreaProvider())
    try:
        rid = env.rid
        admin = user_actor(ADMIN_ID)
        first = await env.api.async_create_backup(
            rid, reason=BackupReason.MANUAL, actor=admin
        )
        env.provider.live(rid)["dhcp"] = {"lan": {"start": "100", "limit": "50"}}
        second = await env.api.async_create_backup(
            rid, reason=BackupReason.MANUAL, actor=admin
        )
        router_before = list(env.router_calls())
        provider_before = len(env.provider.calls)
        saves_before = _saves(disks)
        events_before = len(bus_events(env.hass))

        knowledge_now = hcl.collect_config_knowledge(env.hass, rid)
        sync_link = hcl.config_link_for(env.hass, rid, wall_now=time.time())
        lk = await hcl.async_config_link_for(env.hass, rid, wall_now=time.time())

        # not one call on the router's api object, no provider call but the
        # stored comparison, nothing written, no audit entry
        assert env.router_calls() == router_before
        assert env.provider.calls[provider_before:] == [("compare", rid)]
        assert _saves(disks) == saves_before
        assert len(bus_events(env.hass)) == events_before

        assert [r.backup_id for r in knowledge_now.rows] == [
            first.record.backup_id,
            second.record.backup_id,
        ]
        assert sync_link.config_fact.diff_proven is None
        assert sync_link.reasons["diff_proven"] == "diff_not_read"
        cf = lk.config_fact
        assert cf.diff_proven is True
        assert cf.changed_areas == frozenset({"dhcp"})
        assert cf.version_id == first.record.backup_id
        assert cf.changed_at == pytest.approx(second.record.created_at.timestamp())
        a = pb.assess(
            incident(service="odhcpd", started_at=cf.changed_at + 60),
            dhcp_ev(config=cf),
        )
        assert a.match.playbook_id == "drift_recovery"
        assert a.finding is not None and a.finding.plan is not None
        assert a.finding.plan.version_id == first.record.backup_id
        assert a.finding.plan.restore_executable is False
    finally:
        await stop_env(env)


async def test_recorded_calls_with_backup_off_stay_unknown(
    disks: FakeDisks, tmp_path: Any
) -> None:
    env = await start_env(disks, tmp_path, provider=AreaProvider(), options={})
    try:
        before = list(env.router_calls())
        calls = len(env.provider.calls)
        lk = await hcl.async_config_link_for(env.hass, env.rid, wall_now=time.time())
        assert env.router_calls() == before
        assert env.provider.calls[calls:] == []
        assert lk.config_fact == pb.ConfigFact(
            version_known=False, backup_present=False
        )
        assert lk.backup_present.value == "none"
    finally:
        await stop_env(env)


async def test_real_provider_compares_stored_versions_without_the_router() -> None:
    from test_config_provider import (
        FakeApi,
        Store,
        changed,
        collect,
        make_ctx,
        methods,
        router_record,
    )

    from custom_components.openwrt_router.config_provider import (
        ConfigManagerProvider,
    )

    store = Store()
    base = store.put("rtr_" + "a" * 32, await collect())
    other = store.put(
        "rtr_" + "a" * 32, await collect(FakeApi(files=changed(channel=True)))
    )
    watched = FakeApi()
    provider = ConfigManagerProvider()
    diff = await provider.async_compare(
        base,
        other,
        make_ctx(store),
        base_router=router_record(),
        other_router=router_record(),
    )
    assert methods(watched) == []
    sd = hcl.stored_diff_from(diff, base.backup_id, other.backup_id)
    assert sd.proven is True and sd.areas == frozenset({"wlan"})


def test_no_router_module_is_imported_at_module_level() -> None:
    import ast
    import pathlib

    source = pathlib.Path(hcl.__file__).read_text(encoding="utf-8")
    top = [
        node
        for node in ast.parse(source).body
        if isinstance(node, ast.Import | ast.ImportFrom)
    ]
    names = {
        (node.module or "") if isinstance(node, ast.ImportFrom) else node.names[0].name
        for node in top
    }
    assert not any(n.startswith("homeassistant") for n in names)
    for forbidden in (
        "api",
        "coordinator",
        "config_api",
        "config_manager",
        "heal_engine",
    ):
        assert forbidden not in names


def test_wall_clock_after_restore_window_constant() -> None:
    # the window the policy means: 24 h, exclusive of anything older
    assert timedelta(seconds=hcl.CHANGE_WINDOW_S) == timedelta(hours=24)


# ---------------------------------------------------------------------------
# Found by the mutation loop (each test kills one loosening)
# ---------------------------------------------------------------------------


def test_a_code_carrying_an_address_is_unknown() -> None:
    for odd in ("v10.0.0.1", "ma00:11:22:33:44:55", "x::1"):
        row = hcl.VersionRow(status=odd, validation=odd)
        assert (row.status, row.validation) == ("unknown", "unknown")
    assert hcl.VersionRow(status="ok.v1").status == "ok.v1"


def test_stored_diff_reason_outside_the_set_is_unreadable() -> None:
    sd = hcl.StoredDiff(base_id=bid(1), other_id=bid(2), reason="no_idea")
    assert (sd.proven, sd.reason) == (None, "diff_unreadable")


def test_a_live_reference_never_counts_even_with_a_backup_id() -> None:
    odd = SimpleNamespace(
        base=ConfigRef.backup(bid(1)),
        other=SimpleNamespace(router_id=RID, backup_id=bid(2)),
        changes=(),
        truncated=False,
    )
    assert hcl.stored_diff_from(odd, bid(1), bid(2)).reason == "diff_other_versions"


def test_latest_is_a_usable_version_only() -> None:
    lk = link(knowledge(rec(1, T0, 1, status=VersionStatus.FAILED)))
    assert lk.config_fact == pb.ConfigFact(version_known=False, backup_present=False)
    assert lk.selection.latest is None


def test_a_forced_diff_is_validated_again_by_the_link() -> None:
    k = knowledge(rec(1, T0, 1), rec(2, T0 + 100, 2))
    sd = hcl.StoredDiff(base_id=bid(1), other_id=bid(2), proven=True, areas={"dhcp"})
    object.__setattr__(sd, "areas", frozenset({"moon"}))
    lk = link(k, diff=sd)
    assert lk.config_fact.diff_proven is None
    assert lk.reasons["diff_proven"] == "diff_unreadable"


def test_config_change_24h_skips_odd_area_items() -> None:
    lk = changed_link()
    assert lk.config_change_24h([["dhcp"], 5, "dhcp"]) is True  # type: ignore[list-item]


def test_checksum_needs_a_full_sha256() -> None:
    for sha in ("abc", 5, "a" * 63):
        r = rec(1, T0, 1)
        r.sha256 = sha
        assert (
            hcl.knowledge_from_versions(Versions(r), RID).rows[0].has_checksum is False
        )


def _fake_core(monkeypatch: pytest.MonkeyPatch, **attrs: Any) -> SimpleNamespace:
    from custom_components.openwrt_router import enterprise_core

    core = SimpleNamespace(**{"loaded": True, "closed": False, **attrs})
    monkeypatch.setattr(enterprise_core, "async_get_core", lambda hass: core)
    return core


def test_a_closed_or_unloaded_core_is_not_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    core = _fake_core(monkeypatch, versions=Versions(rec(1, T0, 1)))
    assert hcl.collect_config_knowledge(object(), RID).readable is True
    for change in ({"closed": True}, {"loaded": False}):
        for name, value in change.items():
            setattr(core, name, value)
        assert hcl.collect_config_knowledge(object(), RID).reason == "core_not_running"
        core.loaded, core.closed = True, False


async def test_async_link_reads_the_pair_before_the_cutoff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api = Api(diff_of(bid(1), bid(2), ("modified", "dhcp", "low")))
    _fake_core(
        monkeypatch,
        versions=Versions(rec(1, T0, 1), rec(2, T0 + 100, 2), rec(3, T0 + 200, 3)),
        manager=SimpleNamespace(api=lambda version: api),
    )
    lk = await hcl.async_config_link_for(
        object(), RID, wall_now=T0 + 300, before=T0 + 150
    )
    assert [(b.backup_id, o.backup_id) for b, o, _a in api.calls] == [(bid(1), bid(2))]
    assert lk.config_fact.diff_proven is True
    assert lk.config_fact.changed_at == T0 + 100


def test_plan_lists_every_changed_area_and_the_relevant_ones() -> None:
    k = knowledge(rec(1, T_START - 7200, 1), rec(2, T_START - 600, 2))
    sd = hcl.stored_diff_from(
        diff_of(
            bid(1), bid(2), ("modified", "dhcp", "low"), ("added", "firewall", "high")
        ),
        bid(1),
        bid(2),
    )
    lk = link(k, wall=T_START + 60, before=T_START, diff=sd)
    f = pb.assess(incident(service="odhcpd"), dhcp_ev(config=lk.config_fact)).finding
    assert f is not None and f.plan is not None
    assert f.plan.changed_areas == ("dhcp", "firewall")
    assert f.plan.relevant_areas == ("dhcp",)


def test_rows_are_ordered_by_time_not_by_id() -> None:
    k = knowledge(rec(9, T0, 1), rec(1, T0 + 5, 2), rec(5, T0 + 5, 3))
    assert [r.backup_id for r in k.rows] == [bid(9), bid(1), bid(5)]
    rows = [
        hcl.VersionRow(backup_id=bid(hcl.ROWS_MAX + 5 - i), created_at=T0 + i)
        for i in range(hcl.ROWS_MAX + 5)
    ]
    kept = hcl.ConfigKnowledge(router_id=RID, rows=rows).rows
    assert kept[0].created_at == T0 + 5 and kept[-1].created_at == T0 + hcl.ROWS_MAX + 4
