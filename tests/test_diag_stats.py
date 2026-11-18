"""Tests for the active-diagnostics statistics: diag_stats.py.

Pure logic: no network, no Home Assistant, no wall clock. Timestamps are
plain epoch seconds chosen by the test.
"""

from __future__ import annotations

import ast
import math
import random
from pathlib import Path

import pytest

from custom_components.openwrt_router import diag_stats as ds
from custom_components.openwrt_router.diag_stats import (
    DAY_RETENTION_S,
    DAY_S,
    DNS_ERROR,
    DNS_GAP,
    DNS_NOERROR,
    DNS_NXDOMAIN,
    DNS_SERVFAIL,
    DNS_TIMEOUT,
    HOUR_RETENTION_S,
    HOUR_S,
    OUTCOME_ANSWERED,
    OUTCOME_GAP,
    OUTCOME_LOST,
    WINDOWS,
    Bucket,
    DnsSample,
    Sample,
    SeriesKey,
    add_sample,
    bucket_samples,
    bucket_summary,
    empty_bucket,
    fold_into_days,
    mark_restart_gap,
    merge_all,
    merge_buckets,
    prune_buckets,
    prune_history,
    summarize,
    summarize_dns,
    window_bucket,
    window_summaries,
)

T0 = 20834 * DAY_S  # exact UTC day border (2026-01-14), also an hour border
R = 300.0  # one probe round every 5 minutes


def ans(ts: float, rtt: float) -> Sample:
    return Sample.answered(ts, rtt)


def lost(ts: float) -> Sample:
    return Sample.lost(ts)


def gap(ts: float) -> Sample:
    return Sample.gap(ts)


# --- module hygiene -----------------------------------------------------------


def test_module_is_stdlib_only_and_pure() -> None:
    src = Path(ds.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0, "no relative imports in diag_stats"
            roots.add((node.module or "").split(".")[0])
    assert "homeassistant" not in roots
    assert roots <= {
        "__future__",
        "itertools",
        "logging",
        "math",
        "dataclasses",
        "collections",
        "typing",
        "statistics",
    }
    assert "time.time" not in src and "datetime.now" not in src
    assert "from __future__ import annotations" in src
    assert "_LOGGER = logging.getLogger(__name__)" in src


# --- Sample -------------------------------------------------------------------


def test_sample_constructors_and_validation() -> None:
    assert ans(T0, 5.0).outcome == OUTCOME_ANSWERED
    assert lost(T0).outcome == OUTCOME_LOST and lost(T0).rtt_ms is None
    assert gap(T0).outcome == OUTCOME_GAP and gap(T0).rtt_ms is None
    with pytest.raises(ValueError):
        Sample(T0, OUTCOME_ANSWERED, None)
    with pytest.raises(ValueError):
        Sample(T0, OUTCOME_LOST, 3.0)
    with pytest.raises(ValueError):
        Sample(T0, OUTCOME_GAP, 3.0)
    with pytest.raises(ValueError):
        Sample(T0, "weird", None)
    with pytest.raises(ValueError):
        ans(T0, -1.0)
    with pytest.raises(ValueError):
        ans(T0, float("nan"))
    with pytest.raises(ValueError):
        Sample(float("inf"), OUTCOME_GAP)


def test_series_key_is_opaque_and_distinct() -> None:
    k4 = SeriesKey("ha", "target-1", "icmp", "ipv4")
    k6 = SeriesKey("ha", "target-1", "icmp", "ipv6")
    assert k4 != k6
    assert k4 == SeriesKey("ha", "target-1", "icmp", "ipv4")
    assert len({k4, k6}) == 2
    with pytest.raises(ValueError):
        SeriesKey("", "t", "icmp", "ipv4")
    with pytest.raises(TypeError):
        SeriesKey("ha", 3, "icmp", "ipv4")  # type: ignore[arg-type]


# --- summarize ------------------------------------------------------------------


def test_summary_without_samples_is_all_none_and_zero_coverage() -> None:
    s = summarize([])
    assert s.answered == s.lost == s.gaps == 0
    assert s.current_ms is None and s.mean_ms is None and s.min_ms is None
    assert s.max_ms is None and s.jitter_ms is None and s.loss_pct is None
    assert s.coverage == 0.0
    assert s.outliers == 0
    # expected rounds but nothing ran: still nothing, coverage 0
    s2 = summarize([], expected=12)
    assert s2.coverage == 0.0 and s2.expected == 12 and s2.loss_pct is None


def test_summary_only_gaps_is_unknown_not_healthy() -> None:
    s = summarize([gap(T0 + i * R) for i in range(5)])
    assert s.gaps == 5
    assert s.loss_pct is None and s.mean_ms is None
    assert s.coverage == 0.0


def test_summary_basic_values_and_jitter_formula() -> None:
    samples = [
        ans(T0, 10.0),
        ans(T0 + R, 14.0),
        lost(T0 + 2 * R),
        ans(T0 + 3 * R, 12.0),
    ]
    s = summarize(samples)
    assert s.answered == 3 and s.lost == 1 and s.gaps == 0
    assert s.mean_ms == pytest.approx(12.0)
    assert s.min_ms == 10.0 and s.max_ms == 14.0
    # jitter = mean |d| of consecutive answered rtts: (|14-10| + |12-14|) / 2 = 3
    assert s.jitter_ms == pytest.approx(3.0)
    assert s.loss_pct == pytest.approx(25.0)
    assert s.coverage == 1.0
    assert s.current_ms == 12.0


def test_summary_sorts_by_time() -> None:
    samples = [
        ans(T0 + 3 * R, 12.0),
        ans(T0, 10.0),
        lost(T0 + 2 * R),
        ans(T0 + R, 14.0),
    ]
    s = summarize(samples)
    assert s.jitter_ms == pytest.approx(3.0)
    assert s.current_ms == 12.0


def test_current_is_none_when_newest_probe_was_lost() -> None:
    s = summarize([ans(T0, 10.0), lost(T0 + R), gap(T0 + 2 * R)])
    # newest measured probe was lost: no stale "current" value; gap is ignored
    assert s.current_ms is None
    assert s.mean_ms == 10.0


def test_jitter_needs_two_answers() -> None:
    assert summarize([ans(T0, 10.0)]).jitter_ms is None
    assert summarize([ans(T0, 10.0), lost(T0 + R)]).jitter_ms is None


def test_rule_1_gaps_are_not_loss_and_lower_coverage() -> None:
    samples = [ans(T0, 10.0), lost(T0 + R), gap(T0 + 2 * R), gap(T0 + 3 * R)]
    s = summarize(samples)
    assert s.loss_pct == pytest.approx(50.0)  # 1 lost / (1 answered + 1 lost)
    assert s.gaps == 2
    assert s.coverage == pytest.approx(0.5)  # 2 measured / 4 expected


def test_expected_overrides_coverage_denominator_and_is_clamped() -> None:
    samples = [ans(T0, 10.0), ans(T0 + R, 10.0)]
    assert summarize(samples, expected=8).coverage == pytest.approx(0.25)
    assert summarize(samples, expected=1).coverage == 1.0  # clamp
    with pytest.raises(ValueError):
        summarize(samples, expected=-1)


def test_outliers_need_enough_samples_and_floor() -> None:
    base = [ans(T0 + i * R, 10.0) for i in range(6)]
    spike = ans(T0 + 6 * R, 80.0)
    assert summarize([*base, spike]).outliers == 1
    # few samples: no outlier verdict
    assert (
        summarize([ans(T0, 10.0), ans(T0 + R, 10.0), ans(T0 + 2 * R, 80.0)]).outliers
        == 0
    )
    # LAN: 2 ms -> 5 ms is more than 2x but below the absolute floor
    lan = [ans(T0 + i * R, 2.0) for i in range(6)] + [ans(T0 + 6 * R, 5.0)]
    assert summarize(lan).outliers == 0


# --- DNS ----------------------------------------------------------------------


def test_dns_sample_validation() -> None:
    with pytest.raises(ValueError):
        DnsSample(T0, DNS_NOERROR, None)
    with pytest.raises(ValueError):
        DnsSample(T0, DNS_TIMEOUT, 5.0)
    with pytest.raises(ValueError):
        DnsSample(T0, DNS_GAP, 5.0)
    with pytest.raises(ValueError):
        DnsSample(T0, "bogus", None)
    DnsSample(T0, DNS_SERVFAIL, None)
    DnsSample(T0, DNS_SERVFAIL, 40.0)


def test_dns_summary_empty() -> None:
    s = summarize_dns([])
    assert s.queries == 0 and s.coverage == 0.0
    assert s.failure_pct is None and s.mean_ms is None and s.timeout_pct is None


def test_case_09_dns_timeouts() -> None:
    samples = [
        DnsSample(T0, DNS_NOERROR, 20.0),
        DnsSample(T0 + R, DNS_NXDOMAIN, 30.0),  # an answer, not a failure
        DnsSample(T0 + 2 * R, DNS_TIMEOUT),
        DnsSample(T0 + 3 * R, DNS_TIMEOUT),
        DnsSample(T0 + 4 * R, DNS_SERVFAIL, 900.0),
        DnsSample(T0 + 5 * R, DNS_ERROR, 5.0),
        DnsSample(T0 + 6 * R, DNS_NOERROR, 40.0),
        DnsSample(T0 + 7 * R, DNS_GAP),  # scheduler skipped: not a timeout
    ]
    s = summarize_dns(samples)
    assert s.queries == 7
    assert s.answered == 3
    assert s.noerror == 2 and s.nxdomain == 1
    assert s.timeouts == 2 and s.servfail == 1 and s.errors == 1
    assert s.gaps == 1
    # failures = timeouts + servfail + other errors; nxdomain is not one
    assert s.failure_pct == pytest.approx(4 / 7 * 100)
    assert s.timeout_pct == pytest.approx(2 / 7 * 100)
    # response time from real answers only (noerror + nxdomain), not SERVFAIL
    assert s.mean_ms == pytest.approx(30.0)
    assert s.min_ms == 20.0 and s.max_ms == 40.0
    assert s.current_ms == 40.0
    assert s.coverage == pytest.approx(7 / 8)

    only_timeouts = summarize_dns(
        [DnsSample(T0 + i * R, DNS_TIMEOUT) for i in range(3)]
    )
    assert only_timeouts.failure_pct == 100.0
    assert only_timeouts.mean_ms is None
    assert only_timeouts.coverage == 1.0

    nx_only = summarize_dns([DnsSample(T0, DNS_NXDOMAIN, 12.0)])
    assert nx_only.failure_pct == 0.0


# --- restart gaps (rule 6) ------------------------------------------------------


def test_case_18_router_restart_is_gap_not_loss() -> None:
    # Router rebooted between T0+2R and T0+5R: the probes in that window got
    # no answer. The caller learns of the reboot (uptime reset) and marks the
    # window; those probes become gaps, answered ones stay untouched.
    samples = [
        ans(T0, 10.0),
        ans(T0 + R, 11.0),
        lost(T0 + 2 * R),
        lost(T0 + 3 * R),
        lost(T0 + 4 * R),
        ans(T0 + 5 * R, 10.0),
        lost(T0 + 6 * R),  # after the window: real loss
    ]
    raw = summarize(samples)
    assert raw.loss_pct == pytest.approx(4 / 7 * 100)

    marked = mark_restart_gap(samples, start=T0 + 2 * R, end=T0 + 5 * R)
    assert isinstance(marked, tuple)
    assert samples[2].outcome == OUTCOME_LOST  # input not changed
    s = summarize(marked)
    assert s.gaps == 3
    assert s.lost == 1
    assert s.loss_pct == pytest.approx(25.0)  # 1 / 4, the reboot is no loss
    assert s.coverage == pytest.approx(4 / 7)  # but coverage drops

    dns = [DnsSample(T0 + 3 * R, DNS_TIMEOUT), DnsSample(T0 + 6 * R, DNS_TIMEOUT)]
    dns_marked = mark_restart_gap(dns, start=T0 + 2 * R, end=T0 + 5 * R)
    assert [d.outcome for d in dns_marked] == [DNS_GAP, DNS_TIMEOUT]

    with pytest.raises(ValueError):
        mark_restart_gap(samples, start=T0 + 5 * R, end=T0)


# --- buckets ------------------------------------------------------------------


def test_add_sample_builds_new_bucket_and_checks_range_and_order() -> None:
    b0 = empty_bucket(T0, HOUR_S)
    b1 = add_sample(b0, ans(T0 + 10, 10.0))
    assert b0.answered == 0 and b1.answered == 1  # new value, old untouched
    b2 = add_sample(b1, ans(T0 + 20, 14.0), outlier=True)
    assert b2.outliers == 1 and b2.diff_sum == 4.0
    with pytest.raises(ValueError):
        add_sample(b2, ans(T0 + HOUR_S, 1.0))  # outside the bucket
    with pytest.raises(ValueError):
        add_sample(b2, ans(T0 + 5, 1.0))  # out of time order
    with pytest.raises(ValueError):
        empty_bucket(T0, 0)


def test_bucket_summary_matches_raw_summary() -> None:
    rng = random.Random(7)
    samples = []
    for i in range(36):
        roll = rng.random()
        ts = T0 + i * R
        if roll < 0.1:
            samples.append(lost(ts))
        elif roll < 0.2:
            samples.append(gap(ts))
        else:
            samples.append(ans(ts, rng.randint(5, 40) * 0.5))
    raw = summarize(samples)
    hours = bucket_samples(samples)
    assert len(hours) == 3
    merged = bucket_summary(merge_all(hours))
    for field in (
        "answered",
        "lost",
        "gaps",
        "min_ms",
        "max_ms",
        "current_ms",
        "coverage",
    ):
        assert getattr(merged, field) == getattr(raw, field), field
    for field in ("mean_ms", "jitter_ms", "loss_pct"):
        assert getattr(merged, field) == pytest.approx(getattr(raw, field)), field


def test_bucket_summary_none_and_empty() -> None:
    s = bucket_summary(None)
    assert s.coverage == 0.0 and s.mean_ms is None
    assert bucket_summary(empty_bucket(T0, HOUR_S)).loss_pct is None


def test_merge_associativity() -> None:
    a = bucket_samples([ans(T0 + 10, 4.0), ans(T0 + 20, 8.0), lost(T0 + 30)])[0]
    b = bucket_samples([gap(T0 + HOUR_S + 5), lost(T0 + HOUR_S + 6)])[0]  # no answers
    c = bucket_samples([ans(T0 + 2 * HOUR_S, 2.0), ans(T0 + 2 * HOUR_S + 1, 16.0)])[0]
    d = bucket_samples([ans(T0 + 3 * HOUR_S, 1.0)])[0]
    left = merge_buckets(merge_buckets(merge_buckets(a, b), c), d)
    right = merge_buckets(a, merge_buckets(b, merge_buckets(c, d)))
    mid = merge_buckets(merge_buckets(a, merge_buckets(b, c)), d)
    assert left == right == mid
    # argument order does not matter (buckets are ordered by time)
    assert merge_buckets(c, a) == merge_buckets(a, c)
    # jitter across the merge border is exact: answered rtts 4, 8, 2, 16, 1
    assert left.diff_sum == 4 + 6 + 14 + 15
    assert bucket_summary(left).jitter_ms == pytest.approx(39 / 4)


def test_merge_associativity_random() -> None:
    rng = random.Random(11)
    parts = []
    for h in range(6):
        samples = [
            ans(T0 + h * HOUR_S + i * R, rng.randint(1, 200) * 0.25)
            if rng.random() > 0.2
            else lost(T0 + h * HOUR_S + i * R)
            for i in range(12)
        ]
        parts.append(bucket_samples(samples)[0])
    ref = merge_all(parts)

    def tree(items: list[Bucket]) -> Bucket:
        # random grouping of neighbouring buckets, random argument order
        if len(items) == 1:
            return items[0]
        cut = rng.randint(1, len(items) - 1)
        left, right = tree(items[:cut]), tree(items[cut:])
        return (
            merge_buckets(right, left)
            if rng.random() < 0.5
            else merge_buckets(left, right)
        )

    for _ in range(50):
        acc = tree(parts)
        assert acc.answered == ref.answered and acc.lost == ref.lost
        assert acc.rtt_sum == pytest.approx(ref.rtt_sum)
        assert acc.diff_sum == pytest.approx(ref.diff_sum)
        assert (acc.first_rtt, acc.last_rtt, acc.tail_lost) == (
            ref.first_rtt,
            ref.last_rtt,
            ref.tail_lost,
        )
    # merging around a hole, out of time order, is rejected rather than miscounted
    with pytest.raises(ValueError):
        merge_buckets(merge_buckets(parts[0], parts[2]), parts[1])


def test_merge_rejects_overlap() -> None:
    a = bucket_samples([ans(T0 + 10, 4.0)])[0]
    with pytest.raises(ValueError):
        merge_buckets(a, a)


def test_bucket_dict_round_trip_and_damage() -> None:
    b = bucket_samples(
        [ans(T0 + 10, 4.0), lost(T0 + 20), gap(T0 + 30), ans(T0 + 40, 6.5)]
    )[0]
    data = b.to_dict()
    assert all(isinstance(k, str) for k in data)
    assert Bucket.from_dict(data) == b
    assert Bucket.from_dict(empty_bucket(T0, HOUR_S).to_dict()) == empty_bucket(
        T0, HOUR_S
    )
    with pytest.raises(ValueError):
        Bucket.from_dict({**data, "answered": -1})
    with pytest.raises(ValueError):
        Bucket.from_dict({**data, "start": "x"})
    with pytest.raises(ValueError):
        Bucket.from_dict({"start": T0})
    with pytest.raises(TypeError):
        Bucket.from_dict("nope")  # type: ignore[arg-type]


def _hour_samples(
    day: int, hour: int, rtt: float, lost_n: int = 0, gaps: int = 0
) -> list[Sample]:
    base = T0 + day * DAY_S + hour * HOUR_S
    out = [ans(base + i * R, rtt) for i in range(12 - lost_n - gaps)]
    out += [lost(base + (12 - lost_n - gaps + i) * R) for i in range(lost_n)]
    out += [gap(base + (12 - gaps + i) * R) for i in range(gaps)]
    return out


def test_case_26_historical_aggregation() -> None:
    # 1) samples -> hour buckets, 3 days x 24 hours, 12 rounds an hour
    samples: list[Sample] = []
    for day in range(3):
        for hour in range(24):
            samples += _hour_samples(
                day,
                hour,
                rtt=10.0 + day,
                lost_n=1 if hour == 5 else 0,
                gaps=1 if hour == 6 else 0,
            )
    hours = bucket_samples(samples, span=HOUR_S)
    assert len(hours) == 72
    assert all(h.end - h.start == HOUR_S for h in hours)

    # 2) hour -> day folding is exact against the raw samples
    days = fold_into_days(hours)
    assert len(days) == 3
    for day_index, day in enumerate(days):
        raw = summarize(
            [
                s
                for s in samples
                if T0 + day_index * DAY_S <= s.ts < T0 + (day_index + 1) * DAY_S
            ]
        )
        folded = bucket_summary(day)
        assert folded.answered == raw.answered == 12 * 24 - 2
        assert folded.lost == raw.lost == 1 and folded.gaps == raw.gaps == 1
        assert folded.mean_ms == pytest.approx(raw.mean_ms)
        assert folded.jitter_ms == pytest.approx(raw.jitter_ms)
        assert folded.loss_pct == pytest.approx(raw.loss_pct)
        assert folded.coverage == pytest.approx(raw.coverage)

    # incremental folding (hour by hour, as a store would do) gives the same days
    inc: tuple[Bucket, ...] = ()
    for h in hours:
        inc = fold_into_days([h], inc)
    assert inc == days
    # folding an hour twice would double count: rejected
    with pytest.raises(ValueError):
        fold_into_days(hours[:1], days)

    # 3) the four windows
    assert set(WINDOWS) == {"1h", "24h", "7d", "30d"}
    now = T0 + 3 * DAY_S - 1  # last second of day 3
    win = window_summaries(hours, days, now=now)
    # a bucket counts when it overlaps the window: 1 s of hour 22 is inside
    assert win["1h"].answered == 24
    assert win["24h"].answered == 12 + (12 * 24 - 2)  # day 1 hour 23 overlaps
    assert win["7d"].answered == 3 * (12 * 24 - 2)
    assert win["30d"].answered == 3 * (12 * 24 - 2)
    assert win["7d"].mean_ms == pytest.approx(11.0)
    assert win["30d"].mean_ms == pytest.approx(win["7d"].mean_ms)
    assert win["30d"].jitter_ms == pytest.approx(win["7d"].jitter_ms)
    # 30d also counts hours not folded yet (current day still open)
    open_hour = bucket_samples(_hour_samples(3, 0, rtt=50.0))[0]
    win2 = window_summaries((*hours, open_hour), days, now=T0 + 3 * DAY_S + 1800)
    assert win2["30d"].answered == 3 * (12 * 24 - 2) + 12
    # 1h: day 2 hour 23 (12 x 12 ms) overlaps, plus the open hour (12 x 50 ms)
    assert win2["1h"].mean_ms == pytest.approx(31.0)
    # no data in a window is unknown, not healthy
    far = window_summaries(hours, days, now=T0 + 60 * DAY_S)
    assert far["1h"].coverage == 0.0 and far["1h"].loss_pct is None
    assert far["30d"].mean_ms is None
    assert window_bucket(hours, now=T0 + 60 * DAY_S, window_s=HOUR_S) is None

    # 4) pruning keeps memory bounded: hours 7 days, days 30 days by default
    assert HOUR_RETENTION_S == 7 * DAY_S and DAY_RETENTION_S == 30 * DAY_S
    kept_h, kept_d = prune_history(hours, days, now=T0 + 9 * DAY_S)
    assert len(kept_h) == 24  # only day 2 ends less than 7 days ago
    assert all(h.start >= T0 + 2 * DAY_S for h in kept_h)
    kept_h, kept_d = prune_history(hours, days, now=T0 + 10 * DAY_S)
    assert kept_h == ()  # all hours are older than 7 days by now
    assert kept_d == days  # days are still within 30 days
    kept_h, kept_d = prune_history(hours, days, now=T0 + 32 * DAY_S)
    assert kept_d == days[2:]  # day 0 and 1 are older than 30 days
    # retention is a parameter
    assert len(prune_buckets(hours, now=T0 + 3 * DAY_S, retention_s=DAY_S)) == 24
    with pytest.raises(ValueError):
        prune_buckets(hours, now=T0, retention_s=0)


def test_fold_rejects_hour_spanning_two_days() -> None:
    wide = empty_bucket(T0 + DAY_S - HOUR_S, 2 * HOUR_S)
    with pytest.raises(ValueError):
        fold_into_days([wide])


def test_bucket_samples_counts_outliers_per_bucket() -> None:
    samples = [ans(T0 + i * R, 10.0) for i in range(11)] + [ans(T0 + 11 * R, 90.0)]
    (hour,) = bucket_samples(samples)
    assert hour.outliers == 1


# --- review M6: windows right after a full hour, coverage from the interval ---


def test_m6_one_hour_window_right_after_the_hour() -> None:
    # two clean hours, then the first probe of the new hour is lost
    samples = [ans(T0 + i * R, 10.0) for i in range(24)] + [lost(T0 + 2 * HOUR_S + 1)]
    hours = bucket_samples(samples)
    win = window_summaries(hours, (), now=T0 + 2 * HOUR_S + 5, interval_s=R)
    one = win["1h"]
    # the previous hour overlaps the window and is included: no 100 % loss
    assert one.answered == 12 and one.lost == 1
    assert one.loss_pct == pytest.approx(100 / 13)
    assert one.coverage == 1.0


def test_m6_window_coverage_follows_the_probe_interval() -> None:
    # one probe every 5 minutes was planned, only 3 ran in the last hour
    hours = bucket_samples([ans(T0 + HOUR_S + i * R, 10.0) for i in range(3)])
    now = T0 + 2 * HOUR_S - 1
    win = window_summaries(hours, (), now=now, interval_s=R)
    # the window [now - 1 h, now] overlaps the hour bucket starting at T0 by
    # one second, so it is extended to T0: up to 2 h of buckets, 24 rounds
    assert win["1h"].expected == 24
    assert win["1h"].coverage == pytest.approx(3 / 24)
    # 24 h window: the window start is extended to its bucket border
    assert win["24h"].expected == math.ceil((now - (T0 - 23 * HOUR_S)) / R)
    assert win["24h"].coverage == pytest.approx(3 / win["24h"].expected)
    # monitoring started at T0 + 1 h: earlier time is not expected
    since = window_summaries(hours, (), now=now, interval_s=R, since=T0 + HOUR_S)
    assert since["1h"].expected == since["24h"].expected == 12
    assert since["7d"].coverage == pytest.approx(0.25)
    # several probes a round
    three = window_summaries(hours, (), now=now, interval_s=R, probes_per_round=3)
    assert three["1h"].expected == 72
    # nothing measured stays coverage 0, never healthy
    empty = window_summaries((), (), now=now, interval_s=R)
    assert empty["1h"].coverage == 0.0 and empty["1h"].expected == 24
    with pytest.raises(ValueError):
        window_summaries(hours, (), now=now, interval_s=0)
    with pytest.raises(ValueError):
        window_summaries(hours, (), now=now, interval_s=R, probes_per_round=0)


# --- review L1: damaged bucket data is rejected -------------------------------


def test_l1_from_dict_rejects_inconsistent_buckets() -> None:
    good = bucket_samples([ans(T0 + 10, 5.0), ans(T0 + 20, 15.0)])[0].to_dict()
    assert Bucket.from_dict(good).answered == 2
    damage = (
        {"rtt_min": 500.0, "rtt_max": 1.0},
        {"rtt_min": 20.0},  # above the max
        {"outliers": 3},  # more outliers than answers
        {"tail_lost": True},  # newest probe lost, but nothing was lost
        {"first_rtt": 900.0},  # outside min..max
        {"last_rtt": 0.5},
        {"rtt_sum": 1000.0},  # mean above max
        {"rtt_sum": 1.0},  # mean below min
        {"diff_sum": 999.0},  # more than (n - 1) * (max - min)
        {"last_ts": None},  # samples without a newest time
    )
    for bad in damage:
        with pytest.raises(ValueError):
            Bucket.from_dict({**good, **bad})
    single = bucket_samples([ans(T0 + 10, 5.0)])[0].to_dict()
    with pytest.raises(ValueError):
        Bucket.from_dict(
            {**single, "rtt_max": 9.0, "rtt_sum": 5.0}
        )  # one rtt, two values
    with pytest.raises(ValueError):
        Bucket.from_dict({**single, "diff_sum": 1.0})  # one rtt has no difference
    empty = empty_bucket(T0, HOUR_S).to_dict()
    with pytest.raises(ValueError):
        Bucket.from_dict({**empty, "last_ts": T0 + 5})  # a time without samples
