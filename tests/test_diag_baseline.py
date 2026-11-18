"""Tests for the per-key baselines with hysteresis: diag_baseline.py.

Pure logic: no network, no Home Assistant, no wall clock.
"""

from __future__ import annotations

import ast
import dataclasses
from pathlib import Path

import pytest

from custom_components.openwrt_router import diag_baseline as db
from custom_components.openwrt_router.diag_baseline import (
    JITTER_CONFIG,
    LATENCY_CONFIG,
    LOSS_CONFIG,
    METRIC_JITTER,
    METRIC_LATENCY,
    METRIC_LOSS,
    PHASE_DEGRADED,
    PHASE_LEARNING,
    PHASE_NORMAL,
    BaselineConfig,
    BaselineState,
    bucket_metric,
    detect_drift,
    new_baseline,
    observe,
    on_restart,
    relearn,
    thresholds,
)
from custom_components.openwrt_router.diag_stats import (
    DAY_S,
    HOUR_S,
    Bucket,
    Sample,
    SeriesKey,
    bucket_samples,
    fold_into_days,
    summarize,
)

T0 = 20834 * DAY_S
R = 300.0
KEY = SeriesKey("ha", "gateway", "tcp", "ipv4")
KEY6 = SeriesKey("ha", "gateway", "tcp", "ipv6")


def feed(
    state: BaselineState,
    values: list[float | None],
    config: BaselineConfig,
    start: float,
) -> tuple[BaselineState, list]:
    obs = []
    for i, v in enumerate(values):
        o = observe(state, v, ts=start + i * R, config=config)
        obs.append(o)
        state = o.state
    return state, obs


def learned(
    config: BaselineConfig = LATENCY_CONFIG, value: float = 10.0, key: SeriesKey = KEY
) -> BaselineState:
    state, _ = feed(new_baseline(key, config), [value] * config.min_samples, config, T0)
    assert state.phase == PHASE_NORMAL
    return state


def next_ts(state: BaselineState) -> float:
    assert state.last_ts is not None
    return state.last_ts + R


# --- module hygiene -----------------------------------------------------------


def test_module_is_pure() -> None:
    src = Path(db.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level:
                assert node.module == "diag_stats", (
                    "only imports from its own stats module"
                )
            else:
                assert node.module in {
                    "__future__",
                    "dataclasses",
                    "collections.abc",
                    "typing",
                }
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name in {"itertools", "logging", "math"}
    assert "homeassistant" not in src
    assert "time.time" not in src and "datetime.now" not in src
    assert "_LOGGER = logging.getLogger(__name__)" in src


# --- config -------------------------------------------------------------------


def test_config_validation() -> None:
    with pytest.raises(ValueError):
        dataclasses.replace(LATENCY_CONFIG, exit_abs=LATENCY_CONFIG.enter_abs)
    with pytest.raises(ValueError):
        dataclasses.replace(LATENCY_CONFIG, exit_rel=LATENCY_CONFIG.enter_rel + 1)
    with pytest.raises(ValueError):
        dataclasses.replace(LATENCY_CONFIG, enter_rounds=0)
    with pytest.raises(ValueError):
        dataclasses.replace(LATENCY_CONFIG, alpha=0.0)
    with pytest.raises(ValueError):
        dataclasses.replace(LATENCY_CONFIG, degraded_learn_factor=1.5)
    assert {LATENCY_CONFIG.metric, LOSS_CONFIG.metric, JITTER_CONFIG.metric} == {
        METRIC_LATENCY,
        METRIC_LOSS,
        METRIC_JITTER,
    }


# --- learning -----------------------------------------------------------------


def test_no_verdict_before_min_samples() -> None:
    state = new_baseline(KEY, LATENCY_CONFIG)
    assert state.phase == PHASE_LEARNING and state.mean is None
    assert thresholds(state, LATENCY_CONFIG) is None
    # even huge values while learning give no outlier and no degraded state
    state, obs = feed(
        state, [10.0] * (LATENCY_CONFIG.min_samples - 2) + [500.0], LATENCY_CONFIG, T0
    )
    assert state.phase == PHASE_LEARNING
    assert not any(o.outlier for o in obs)
    assert all(o.transition is None for o in obs)
    state, obs = feed(state, [10.0], LATENCY_CONFIG, next_ts(state))
    assert state.phase == PHASE_NORMAL and obs[-1].transition == PHASE_NORMAL


def test_gap_round_changes_nothing() -> None:
    state = learned()
    o = observe(state, None, ts=next_ts(state), config=LATENCY_CONFIG)
    assert o.state == state and not o.outlier and o.transition is None


def test_observe_rejects_bad_input() -> None:
    state = learned()
    with pytest.raises(ValueError):
        observe(state, float("nan"), ts=next_ts(state), config=LATENCY_CONFIG)
    with pytest.raises(ValueError):
        observe(state, -1.0, ts=next_ts(state), config=LATENCY_CONFIG)
    with pytest.raises(ValueError):
        observe(state, 10.0, ts=T0 - 1, config=LATENCY_CONFIG)  # older than last round
    with pytest.raises(ValueError):
        observe(state, 10.0, ts=next_ts(state), config=LOSS_CONFIG)  # other metric


# --- thresholds ---------------------------------------------------------------


def test_absolute_floor_prevents_lan_false_alarm() -> None:
    state = learned(value=2.0)
    enter, leave = thresholds(state, LATENCY_CONFIG)
    assert leave < enter
    assert enter >= 2.0 + LATENCY_CONFIG.enter_abs
    # 2 ms -> 4 ms doubles but is far below the floor: no outlier, no alarm
    state, obs = feed(state, [4.0] * 10, LATENCY_CONFIG, next_ts(state))
    assert state.phase == PHASE_NORMAL and not any(o.outlier for o in obs)


def test_relative_threshold_on_slow_link() -> None:
    state = learned(value=100.0)
    enter, leave = thresholds(state, LATENCY_CONFIG)
    assert enter == pytest.approx(200.0)  # +100 % beats the 20 ms floor
    assert leave == pytest.approx(150.0)


# --- hysteresis ---------------------------------------------------------------


def test_single_outlier_does_not_flip_state() -> None:
    state = learned()
    o = observe(state, 90.0, ts=next_ts(state), config=LATENCY_CONFIG)
    assert o.outlier and o.transition is None
    assert o.state.phase == PHASE_NORMAL
    assert o.state.outliers == 1 and o.state.last_outlier_ts == next_ts(state)
    assert o.state.mean == state.mean  # the outlier is not learned
    # a normal round breaks the streak; two more spikes still do not flip
    state, _ = feed(
        o.state, [10.0, 90.0, 90.0, 10.0, 90.0], LATENCY_CONFIG, next_ts(o.state)
    )
    assert state.phase == PHASE_NORMAL
    assert state.outliers == 4


def test_case_08_increased_latency() -> None:
    cfg = LATENCY_CONFIG
    # stats: latency rises from ~10 ms to ~60 ms
    before = summarize([Sample.answered(T0 + i * R, 10.0 + (i % 2)) for i in range(12)])
    after = summarize(
        [Sample.answered(T0 + (12 + i) * R, 60.0 + (i % 2)) for i in range(12)]
    )
    assert before.mean_ms == pytest.approx(10.5)
    assert after.mean_ms == pytest.approx(60.5)
    assert after.jitter_ms == pytest.approx(before.jitter_ms) == pytest.approx(1.0)
    assert after.loss_pct == 0.0

    state, _ = feed(
        new_baseline(KEY, cfg), [10.0, 11.0] * (cfg.min_samples // 2), cfg, T0
    )
    assert state.phase == PHASE_NORMAL
    base_mean = state.mean
    enter, leave = thresholds(state, cfg)
    assert 30.0 <= enter < 60.0

    # N-1 rounds above: outliers, still normal
    state, obs = feed(state, [60.0] * (cfg.enter_rounds - 1), cfg, next_ts(state))
    assert state.phase == PHASE_NORMAL and all(o.outlier for o in obs)
    # N-th consecutive round: degraded
    state, obs = feed(state, [60.0], cfg, next_ts(state))
    assert state.phase == PHASE_DEGRADED and obs[-1].transition == PHASE_DEGRADED
    assert state.mean == base_mean

    # recovery needs M consecutive rounds below the lower exit threshold
    state, _ = feed(state, [10.0] * (cfg.exit_rounds - 1), cfg, next_ts(state))
    assert state.phase == PHASE_DEGRADED
    # a value inside the band (below enter, above exit) resets the recovery
    band = (enter + leave) / 2
    state, _ = feed(state, [band], cfg, next_ts(state))
    state, _ = feed(state, [10.0] * (cfg.exit_rounds - 1), cfg, next_ts(state))
    assert state.phase == PHASE_DEGRADED
    state, obs = feed(state, [10.0], cfg, next_ts(state))
    assert state.phase == PHASE_NORMAL and obs[-1].transition == PHASE_NORMAL
    assert state.mean == base_mean
    assert state.above == 0 and state.below == 0


def test_degraded_samples_do_not_shift_baseline() -> None:
    cfg = LATENCY_CONFIG
    assert cfg.degraded_learn_factor == 0.0
    state = learned()
    state, _ = feed(state, [80.0] * cfg.enter_rounds, cfg, next_ts(state))
    assert state.phase == PHASE_DEGRADED
    frozen = (state.mean, state.dev)
    state, _ = feed(
        state, [80.0, 120.0, 95.0] * 50, cfg, next_ts(state)
    )  # a long fault
    assert (state.mean, state.dev) == frozen
    assert state.phase == PHASE_DEGRADED


def test_damped_learning_when_configured() -> None:
    cfg = dataclasses.replace(LATENCY_CONFIG, degraded_learn_factor=0.1)
    state = learned(cfg)
    state, _ = feed(state, [80.0] * cfg.enter_rounds, cfg, next_ts(state))
    before = state.mean
    state, _ = feed(state, [80.0], cfg, next_ts(state))
    # damped step: alpha * factor of the distance
    assert state.mean == pytest.approx(before + cfg.alpha * 0.1 * (80.0 - before))


def test_case_07_packet_loss() -> None:
    cfg = LOSS_CONFIG
    # stats: 3 probes a round; one lost probe in 4 rounds -> 1/12 lost
    samples = []
    for rnd in range(4):
        for p in range(3):
            ts = T0 + rnd * R + p
            samples.append(
                Sample.lost(ts) if (rnd, p) == (2, 1) else Sample.answered(ts, 10.0)
            )
    s = summarize(samples)
    assert s.lost == 1 and s.answered == 11
    assert s.loss_pct == pytest.approx(100 / 12)
    assert s.coverage == 1.0

    # baseline on the round loss %: clean link learns 0 %
    state = learned(cfg, value=0.0)
    assert state.mean == 0.0
    # one round with 1/3 lost: outlier, not degraded
    state, obs = feed(state, [100 / 3], cfg, next_ts(state))
    assert obs[0].outlier and state.phase == PHASE_NORMAL
    state, _ = feed(state, [0.0], cfg, next_ts(state))
    assert state.above == 0 and state.mean == 0.0
    # sustained loss: N consecutive lossy rounds flip to degraded
    state, obs = feed(state, [100 / 3, 200 / 3, 100 / 3], cfg, next_ts(state))
    assert state.phase == PHASE_DEGRADED
    assert [o.transition for o in obs] == [None, None, PHASE_DEGRADED]
    # recovery: M clean rounds
    state, obs = feed(state, [0.0] * cfg.exit_rounds, cfg, next_ts(state))
    assert state.phase == PHASE_NORMAL and state.mean == 0.0


def test_case_18_restart_keeps_baseline_and_restarts_counters() -> None:
    cfg = LATENCY_CONFIG
    state = learned()
    state, _ = feed(state, [90.0] * (cfg.enter_rounds - 1), cfg, next_ts(state))
    assert state.above == cfg.enter_rounds - 1
    mean, dev = state.mean, state.dev
    restarted = on_restart(state, ts=next_ts(state))
    assert restarted.above == 0 and restarted.below == 0
    assert (restarted.mean, restarted.dev) == (mean, dev)
    assert restarted.phase == PHASE_NORMAL
    # gap rounds while the router reboots: nothing changes
    after_gap, _ = feed(restarted, [None, None], cfg, next_ts(restarted))
    assert after_gap == restarted
    # one more high round would have flipped without the restart; now it does not
    after, obs = feed(after_gap, [90.0], cfg, next_ts(restarted) + 2 * R)
    assert after.phase == PHASE_NORMAL and obs[0].outlier
    # degraded stays degraded across a restart, but the recovery count restarts
    deg, _ = feed(learned(), [90.0] * cfg.enter_rounds, cfg, T0 + 100 * R)
    deg, _ = feed(deg, [10.0] * (cfg.exit_rounds - 1), cfg, next_ts(deg))
    deg = on_restart(deg, ts=next_ts(deg))
    assert deg.phase == PHASE_DEGRADED and deg.below == 0
    with pytest.raises(ValueError):
        on_restart(deg, ts=T0)


def test_relearn_starts_over_with_same_key() -> None:
    state = learned()
    fresh = relearn(state)
    assert fresh.key == KEY and fresh.phase == PHASE_LEARNING and fresh.mean is None


# --- rule 3: compare like with like --------------------------------------------


def test_keys_never_merge() -> None:
    cfg = LATENCY_CONFIG
    books = {KEY: learned(value=10.0, key=KEY), KEY6: learned(value=40.0, key=KEY6)}
    assert books[KEY].mean == pytest.approx(10.0)
    assert books[KEY6].mean == pytest.approx(40.0)
    # a value observed with a key guard for a different key is rejected
    with pytest.raises(ValueError):
        observe(books[KEY], 10.0, ts=next_ts(books[KEY]), config=cfg, key=KEY6)
    o = observe(books[KEY], 10.0, ts=next_ts(books[KEY]), config=cfg, key=KEY)
    assert o.state.key == KEY
    assert new_baseline(KEY, cfg) != new_baseline(KEY6, cfg)


# --- drift --------------------------------------------------------------------


def _merged_day(samples: list[Sample]) -> tuple[Bucket, ...]:
    return fold_into_days(bucket_samples(samples))


def _day(day: int, rtt: float, n: int = 24) -> Bucket:
    base = T0 + day * DAY_S
    (bucket,) = _merged_day([Sample.answered(base + i * HOUR_S, rtt) for i in range(n)])
    return bucket


def test_drift_needs_consecutive_days_above() -> None:
    cfg = LATENCY_CONFIG
    state = learned()  # baseline 10 ms; drift threshold 10 + max(2.5, 5) = 15
    days = [_day(d, 18.0) for d in range(cfg.drift_days)]
    now = T0 + (cfg.drift_days - 1) * DAY_S + 3600
    drift = detect_drift(state, days, config=cfg, now=now)
    assert drift.drifting and drift.days_above == cfg.drift_days
    assert drift.threshold == pytest.approx(15.0)
    # one day back to normal in the middle breaks the run
    broken = [*days[:-2], _day(cfg.drift_days - 2, 10.0), days[-1]]
    assert not detect_drift(state, broken, config=cfg, now=now).drifting
    # a missing day breaks the run too (no data is not drift and not healthy)
    holes = [days[0], days[-1]]
    assert detect_drift(state, holes, config=cfg, now=now).days_above == 1
    # a stale run (newest day long ago) is not current drift
    assert not detect_drift(state, days, config=cfg, now=now + 10 * DAY_S).drifting
    # thin days (too few answers) do not count
    thin = [_day(d, 18.0, n=2) for d in range(cfg.drift_days)]
    assert not detect_drift(state, thin, config=cfg, now=now).drifting
    # no verdict while learning
    assert (
        detect_drift(new_baseline(KEY, cfg), days, config=cfg, now=now).threshold
        is None
    )


def test_short_outliers_are_not_drift() -> None:
    cfg = LATENCY_CONFIG
    state = learned()
    # each day has one 60 ms spike among 10 ms values: day mean stays low
    days = []
    for d in range(cfg.drift_days):
        base = T0 + d * DAY_S
        samples = [
            Sample.answered(base + i * HOUR_S, 60.0 if i == 3 else 10.0)
            for i in range(24)
        ]
        days.append(_merged_day(samples)[0])
    now = T0 + (cfg.drift_days - 1) * DAY_S
    assert not detect_drift(state, days, config=cfg, now=now).drifting


def test_bucket_metric() -> None:
    samples = [
        Sample.answered(T0, 10.0),
        Sample.answered(T0 + R, 14.0),
        Sample.lost(T0 + 2 * R),
        Sample.answered(T0 + 3 * R, 12.0),
    ]
    (b,) = bucket_samples(samples)
    assert bucket_metric(b, METRIC_LATENCY) == pytest.approx(12.0)
    assert bucket_metric(b, METRIC_JITTER) == pytest.approx(3.0)
    assert bucket_metric(b, METRIC_LOSS) == pytest.approx(25.0)
    with pytest.raises(ValueError):
        bucket_metric(b, "bogus")


# --- review H4: a lasting fault is never learned --------------------------------


def _ceiling(config: BaselineConfig, reference: float) -> float:
    return reference + max(config.drift_rel * reference, config.drift_abs)


def test_h4_sustained_moderate_loss_degrades() -> None:
    cfg = LOSS_CONFIG
    state = learned(cfg, value=0.0)
    state, obs = feed(state, [15.0] * 300, cfg, next_ts(state))
    assert obs[cfg.enter_rounds - 1].transition == PHASE_DEGRADED
    assert state.phase == PHASE_DEGRADED
    assert state.mean == 0.0 and state.reference == 0.0
    # a few lost points (below the floor) on a clean link are no alarm
    calm, obs = feed(learned(cfg, value=0.0), [2.0] * 50, cfg, T0 + 100 * R)
    assert calm.phase == PHASE_NORMAL and not any(o.outlier for o in obs)


def test_h4_band_values_are_neither_learned_nor_recovery() -> None:
    cfg = LATENCY_CONFIG
    state = learned()
    enter, leave = thresholds(state, cfg)
    band = (enter + leave) / 2
    after, obs = feed(state, [band] * 50, cfg, next_ts(state))
    assert (after.mean, after.dev) == (state.mean, state.dev)
    assert after.phase == PHASE_NORMAL and not any(o.outlier for o in obs)
    # values below exit are learned as before
    lower, _ = feed(state, [leave - 1.0] * 5, cfg, next_ts(state))
    assert lower.mean > state.mean


def test_h4_latency_creep_cannot_move_the_baseline() -> None:
    cfg = LATENCY_CONFIG
    for share, pick in ((0.95, 0), (0.99, 1)):  # just under enter, just under exit
        state = learned()
        ceiling = _ceiling(cfg, 10.0)
        for _step in range(40):
            level = min(thresholds(state, cfg)[pick] * share, 120.0)
            state, _ = feed(state, [level] * 30, cfg, next_ts(state))
            assert state.mean <= ceiling + 1e-9
        assert state.reference == pytest.approx(10.0)
        enter, _leave = thresholds(state, cfg)
        assert enter < 120.0
        # the real fault still flips to degraded
        state, obs = feed(state, [120.0] * cfg.enter_rounds, cfg, next_ts(state))
        assert all(o.outlier for o in obs)
        assert state.phase == PHASE_DEGRADED


def test_h4_drift_is_judged_against_the_frozen_reference() -> None:
    cfg = LATENCY_CONFIG
    state = learned()
    # the live mean may wander a little (values below exit are learned) ...
    state, _ = feed(state, [19.0] * 200, cfg, next_ts(state))
    assert state.mean > 14.0
    # ... but drift is measured from the learning result, not the live mean
    assert state.reference == pytest.approx(10.0)
    days = [_day(d, 16.0) for d in range(cfg.drift_days)]
    now = T0 + (cfg.drift_days - 1) * DAY_S
    drift = detect_drift(state, days, config=cfg, now=now)
    assert drift.threshold == pytest.approx(15.0)
    assert drift.drifting


def _loss_day(day: int, every: int) -> Bucket:
    base = T0 + day * DAY_S
    samples = [
        Sample.lost(base + i * 60)
        if i % every == 0
        else Sample.answered(base + i * 60, 10.0)
        for i in range(200)
    ]
    return _merged_day(samples)[0]


def test_h4_lasting_loss_is_drift_and_only_relearn_accepts_it() -> None:
    cfg = LOSS_CONFIG
    state = learned(cfg, value=0.0)
    state, _ = feed(state, [15.0] * 300, cfg, next_ts(state))
    days = [_loss_day(d, 7) for d in range(4)]  # 29 of 200 lost = 14.5 %
    now = T0 + 3 * DAY_S + 60
    drift = detect_drift(state, days, config=cfg, now=now)
    assert drift.threshold == pytest.approx(cfg.drift_abs)
    assert drift.drifting and drift.days_above == 4
    # only an explicit relearn makes 15 % the new normal
    fresh, _ = feed(relearn(state), [15.0] * cfg.min_samples, cfg, next_ts(state))
    assert fresh.phase == PHASE_NORMAL and fresh.reference == pytest.approx(15.0)
    assert not detect_drift(fresh, days, config=cfg, now=now).drifting


def test_h4_reference_is_set_once_per_learning() -> None:
    cfg = LATENCY_CONFIG
    state = new_baseline(KEY, cfg)
    assert state.reference is None
    state = learned()
    ref = state.reference
    state, _ = feed(state, [12.0] * 100, cfg, next_ts(state))
    state, _ = feed(
        state, [90.0] * cfg.enter_rounds + [10.0] * cfg.exit_rounds, cfg, next_ts(state)
    )
    state = on_restart(state, ts=next_ts(state))
    assert state.reference == ref
    assert relearn(state).reference is None
