"""Active network diagnostics: per-series baselines with hysteresis.

Pure module: standard library plus :mod:`.diag_stats`, no Home Assistant, no
I/O, no clock. Round timestamps are passed in.

Method
------
One :class:`BaselineState` per series key (``diag_stats.SeriesKey``) and
metric. It is fed one value per probe round (for example the mean rtt of the
round, or the round's loss %). The baseline is an EWMA of the value plus an
EWMA of the absolute deviation, the RFC 6298 SRTT/RTTVAR pair::

    dev  = (1 - beta)  * dev  + beta  * |mean - value|
    mean = (1 - alpha) * mean + alpha * value

with ``alpha = 1/8`` and ``beta = 1/4``. The first value sets ``mean = value``
and ``dev = value / 2``. When learning ends, the mean is kept as the
``reference``; only :func:`relearn` replaces it. The live mean may never rise
above the drift threshold of the reference
(``reference + max(drift_rel * reference, drift_abs)``), so slow creep cannot
drag the baseline along. It may fall freely (a link that gets better).

Thresholds (relative part, absolute floor, deviation part; the largest wins)::

    enter = mean + max(enter_rel * mean, enter_abs, enter_dev_k * dev)
    exit  = mean + max(exit_rel  * mean, exit_abs,  exit_dev_k  * dev)

The absolute floor keeps 2 ms -> 4 ms on a LAN from being an alarm. ``exit``
is always below ``enter`` (checked in :class:`BaselineConfig`).

States
------
* ``learning`` -- until ``min_samples`` values were seen. No outliers and no
  verdict; every value is learned.
* ``normal`` -- a value above ``enter`` is an outlier: counted, not learned,
  and it raises the ``above`` streak. ``enter_rounds`` consecutive outliers
  switch to ``degraded``. Any value at or below ``enter`` ends the streak.
  Only values below ``exit`` are learned; values between ``exit`` and
  ``enter`` are neither learned nor outliers (a fault just under ``enter``
  must not become the baseline).
* ``degraded`` -- the baseline is frozen (``degraded_learn_factor`` 0.0; a
  value between 0 and 1 learns with ``alpha * factor`` and ``beta * factor``
  instead) so the fault is never learned. ``exit_rounds`` consecutive values
  below ``exit`` switch back to ``normal``; any other value ends that streak.

A round without a value (``None``: gap, or no answer for an rtt metric) does
not change anything: it neither confirms nor breaks a streak. A restart of a
router or of Home Assistant, signalled with :func:`on_restart`, restarts both
streak counters and keeps the baseline and the state. A lasting change of the
link (new provider) never becomes the new normal by itself: it stays
``degraded`` or, if it sits between the thresholds, shows as long-term drift,
until the caller calls :func:`relearn`.

``exit_dev_k`` is at most 1: with a larger factor, values just below ``exit``
would grow ``dev`` (and with it both thresholds) without bound.

Drift
-----
Short-term outliers come from :func:`observe`. Long-term drift is judged on
UTC day buckets: :func:`detect_drift` counts the newest consecutive days whose
day value is above :func:`drift_threshold` of the frozen ``reference`` (not
the live mean, which the fault could have moved). Days with
fewer than ``drift_min_samples`` measured probes, or missing days, end the
run (no data is neither drift nor healthy). ``drift_days`` days in a row,
ending today or yesterday, are drift.

Default configs
---------------

=========== ===== ====== ===== ====== ===== ===== ====== ===== ===== ====
metric      e_rel e_abs  e_dev x_rel  x_abs x_dev rounds learn drift d_abs
=========== ===== ====== ===== ====== ===== ===== ====== ===== ===== ====
latency_ms  1.0   20 ms  4     0.5    10 ms 1     3 / 4  12    0.25  5 ms
loss_pct    1.0   5 pp   4     0.5    2 pp  1     3 / 4  12    0.5   1 pp
jitter_ms   1.0   10 ms  4     0.5    5 ms  1     3 / 4  12    0.5   3 ms
=========== ===== ====== ===== ====== ===== ===== ====== ===== ===== ====

``rounds`` = ``enter_rounds / exit_rounds``; ``learn`` = ``min_samples``
rounds (one hour at one round per 5 minutes); drift needs 3 days in a row
with at least 12 measured probes each.

Loss is fed as the loss % of a round. With few probes a round (3 probes:
0 / 33 / 67 / 100 %) moderate loss arrives as scattered single-loss rounds
that do not form ``enter_rounds`` in a row; it is then caught as drift on the
day buckets, or the caller feeds the loss over several rounds.
"""

from __future__ import annotations

import logging
import math
from collections.abc import Sequence
from dataclasses import dataclass, replace

from .diag_stats import DAY_S, Bucket, SeriesKey, align, bucket_summary

_LOGGER = logging.getLogger(__name__)

# --- Constants ---------------------------------------------------------------

PHASE_LEARNING = "learning"
PHASE_NORMAL = "normal"
PHASE_DEGRADED = "degraded"

METRIC_LATENCY = "latency_ms"
METRIC_LOSS = "loss_pct"
METRIC_JITTER = "jitter_ms"
METRICS = frozenset({METRIC_LATENCY, METRIC_LOSS, METRIC_JITTER})

ALPHA = 0.125
BETA = 0.25
MIN_SAMPLES = 12
ENTER_ROUNDS = 3
EXIT_ROUNDS = 4
DRIFT_DAYS = 3
DRIFT_MIN_SAMPLES = 12


@dataclass(frozen=True, slots=True)
class BaselineConfig:
    """Tuning of one metric's baseline; see the module docstring."""

    metric: str
    enter_rel: float
    enter_abs: float
    exit_rel: float
    exit_abs: float
    drift_rel: float
    drift_abs: float
    enter_dev_k: float = 4.0
    exit_dev_k: float = 1.0
    alpha: float = ALPHA
    beta: float = BETA
    min_samples: int = MIN_SAMPLES
    enter_rounds: int = ENTER_ROUNDS
    exit_rounds: int = EXIT_ROUNDS
    degraded_learn_factor: float = 0.0
    drift_days: int = DRIFT_DAYS
    drift_min_samples: int = DRIFT_MIN_SAMPLES

    def __post_init__(self) -> None:
        if self.metric not in METRICS:
            raise ValueError(f"unknown metric {self.metric!r}")
        for name in ("alpha", "beta"):
            if not 0.0 < getattr(self, name) <= 1.0:
                raise ValueError(f"{name} must be in (0, 1]")
        if not 0.0 <= self.degraded_learn_factor <= 1.0:
            raise ValueError("degraded_learn_factor must be in [0, 1]")
        for name in ("min_samples", "enter_rounds", "exit_rounds", "drift_days"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        for name in (
            "enter_rel",
            "enter_abs",
            "exit_rel",
            "exit_abs",
            "drift_rel",
            "drift_abs",
            "enter_dev_k",
            "exit_dev_k",
        ):
            value = getattr(self, name)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and not negative")
        if not (
            self.exit_abs < self.enter_abs
            and self.exit_rel <= self.enter_rel
            and self.exit_dev_k <= self.enter_dev_k
        ):
            raise ValueError("exit thresholds must lie below the enter thresholds")
        if self.exit_dev_k > 1.0:
            raise ValueError("exit_dev_k above 1 lets dev grow without bound")


LATENCY_CONFIG = BaselineConfig(
    metric=METRIC_LATENCY,
    enter_rel=1.0,
    enter_abs=20.0,
    exit_rel=0.5,
    exit_abs=10.0,
    drift_rel=0.25,
    drift_abs=5.0,
)
LOSS_CONFIG = BaselineConfig(
    metric=METRIC_LOSS,
    enter_rel=1.0,
    enter_abs=5.0,
    exit_rel=0.5,
    exit_abs=2.0,
    drift_rel=0.5,
    drift_abs=1.0,
)
JITTER_CONFIG = BaselineConfig(
    metric=METRIC_JITTER,
    enter_rel=1.0,
    enter_abs=10.0,
    exit_rel=0.5,
    exit_abs=5.0,
    drift_rel=0.5,
    drift_abs=3.0,
)


# --- State -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class BaselineState:
    """Baseline and hysteresis state of one (series key, metric)."""

    key: SeriesKey
    metric: str
    phase: str = PHASE_LEARNING
    mean: float | None = None
    dev: float | None = None
    learned: int = 0
    above: int = 0  # consecutive rounds above enter (normal phase)
    below: int = 0  # consecutive rounds below exit (degraded phase)
    outliers: int = 0
    last_outlier_ts: float | None = None
    phase_since: float | None = None
    last_ts: float | None = None
    reference: float | None = None  # mean at the end of learning


@dataclass(frozen=True, slots=True)
class Observation:
    """Result of one round: new state, outlier flag, phase change if any."""

    state: BaselineState
    outlier: bool
    transition: str | None


def new_baseline(key: SeriesKey, config: BaselineConfig) -> BaselineState:
    """A fresh baseline in the learning state."""
    if not isinstance(key, SeriesKey):
        raise TypeError("key must be a SeriesKey")
    return BaselineState(key=key, metric=config.metric)


def relearn(state: BaselineState) -> BaselineState:
    """Start learning anew for the same key (caller's explicit decision)."""
    return BaselineState(key=state.key, metric=state.metric, last_ts=state.last_ts)


def thresholds(
    state: BaselineState, config: BaselineConfig
) -> tuple[float, float] | None:
    """``(enter, exit)`` limits, or ``None`` while learning."""
    if state.phase == PHASE_LEARNING or state.mean is None or state.dev is None:
        return None
    mean, dev = state.mean, state.dev
    enter = mean + max(
        config.enter_rel * mean, config.enter_abs, config.enter_dev_k * dev
    )
    leave = mean + max(config.exit_rel * mean, config.exit_abs, config.exit_dev_k * dev)
    return enter, leave


def drift_threshold(reference: float, config: BaselineConfig) -> float:
    """Drift limit above the reference; also the ceiling of the live mean."""
    return reference + max(config.drift_rel * reference, config.drift_abs)


def _learn(
    state: BaselineState,
    value: float,
    config: BaselineConfig,
    factor: float = 1.0,
) -> BaselineState:
    if state.mean is None or state.dev is None:
        return replace(state, mean=value, dev=value / 2.0, learned=state.learned + 1)
    alpha, beta = config.alpha * factor, config.beta * factor
    dev = (1.0 - beta) * state.dev + beta * abs(state.mean - value)
    mean = (1.0 - alpha) * state.mean + alpha * value
    if state.reference is not None:
        mean = min(mean, drift_threshold(state.reference, config))
    return replace(state, mean=mean, dev=dev, learned=state.learned + 1)


def _check_round(
    state: BaselineState,
    value: float | None,
    ts: float,
    config: BaselineConfig,
    key: SeriesKey | None,
) -> None:
    if config.metric != state.metric:
        raise ValueError("config metric differs from the baseline metric")
    if key is not None and key != state.key:
        raise ValueError("value belongs to another series key")
    if not math.isfinite(ts):
        raise ValueError("timestamp must be finite")
    if state.last_ts is not None and ts < state.last_ts:
        raise ValueError("round older than the last one")
    if value is not None and (not math.isfinite(value) or value < 0):
        raise ValueError("value must be finite and not negative")


def observe(
    state: BaselineState,
    value: float | None,
    *,
    ts: float,
    config: BaselineConfig,
    key: SeriesKey | None = None,
) -> Observation:
    """Feed one round. ``value`` ``None`` = no value this round (no change).

    ``key``, when given, must equal the state's key (guard against mixing
    series, binding rule 3).
    """
    _check_round(state, value, ts, config, key)
    if value is None:
        return Observation(state, False, None)
    stamped = replace(state, last_ts=ts)
    if state.phase == PHASE_LEARNING:
        return _observe_learning(stamped, value, ts, config)
    if state.phase == PHASE_NORMAL:
        return _observe_normal(stamped, value, ts, config)
    return _observe_degraded(stamped, value, ts, config)


def _observe_learning(
    state: BaselineState, value: float, ts: float, config: BaselineConfig
) -> Observation:
    learned = _learn(state, value, config)
    if learned.learned < config.min_samples:
        return Observation(learned, False, None)
    done = replace(learned, phase=PHASE_NORMAL, phase_since=ts, reference=learned.mean)
    return Observation(done, False, PHASE_NORMAL)


def _outlier(state: BaselineState, ts: float) -> BaselineState:
    return replace(state, outliers=state.outliers + 1, last_outlier_ts=ts)


def _observe_normal(
    state: BaselineState, value: float, ts: float, config: BaselineConfig
) -> Observation:
    enter, leave = thresholds(state, config)  # type: ignore[misc]
    if value < leave:
        calm = replace(state, above=0)
        return Observation(_learn(calm, value, config), False, None)
    if value <= enter:
        return Observation(replace(state, above=0), False, None)
    marked = replace(_outlier(state, ts), above=state.above + 1)
    if marked.above < config.enter_rounds:
        return Observation(marked, True, None)
    flipped = replace(marked, phase=PHASE_DEGRADED, phase_since=ts, above=0, below=0)
    return Observation(flipped, True, PHASE_DEGRADED)


def _observe_degraded(
    state: BaselineState, value: float, ts: float, config: BaselineConfig
) -> Observation:
    enter, leave = thresholds(state, config)  # type: ignore[misc]
    is_outlier = value > enter
    marked = _outlier(state, ts) if is_outlier else state
    factor = config.degraded_learn_factor
    if factor > 0.0:
        marked = _learn(marked, value, config, factor)
        marked = replace(marked, learned=state.learned)
    if value >= leave:
        return Observation(replace(marked, below=0), is_outlier, None)
    below = state.below + 1
    if below < config.exit_rounds:
        return Observation(replace(marked, below=below), is_outlier, None)
    back = replace(marked, phase=PHASE_NORMAL, phase_since=ts, above=0, below=0)
    return Observation(back, is_outlier, PHASE_NORMAL)


def on_restart(state: BaselineState, *, ts: float) -> BaselineState:
    """A router or Home Assistant restart: streaks restart, baseline stays."""
    if not math.isfinite(ts):
        raise ValueError("timestamp must be finite")
    if state.last_ts is not None and ts < state.last_ts:
        raise ValueError("restart older than the last round")
    return replace(state, above=0, below=0, last_ts=ts)


# --- Drift -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Drift:
    """Long-term drift verdict over day buckets."""

    drifting: bool
    days_above: int
    threshold: float | None


def bucket_metric(bucket: Bucket, metric: str) -> float | None:
    """Value of ``metric`` for a bucket (mean rtt, jitter or loss %)."""
    summary = bucket_summary(bucket)
    if metric == METRIC_LATENCY:
        return summary.mean_ms
    if metric == METRIC_JITTER:
        return summary.jitter_ms
    if metric == METRIC_LOSS:
        return summary.loss_pct
    raise ValueError(f"unknown metric {metric!r}")


def _measured(bucket: Bucket, metric: str) -> int:
    return bucket.answered + bucket.lost if metric == METRIC_LOSS else bucket.answered


def detect_drift(
    state: BaselineState,
    days: Sequence[Bucket],
    *,
    config: BaselineConfig,
    now: float,
) -> Drift:
    """Count the newest consecutive UTC days above the drift threshold."""
    if state.phase == PHASE_LEARNING or state.reference is None:
        return Drift(False, 0, None)
    threshold = drift_threshold(state.reference, config)
    by_day = {int(align(day.start, DAY_S) // DAY_S): day for day in days}
    today = int(align(now, DAY_S) // DAY_S)
    newest = max((d for d in by_day if d <= today), default=None)
    if newest is None or newest < today - 1:
        return Drift(False, 0, threshold)
    count = 0
    index = newest
    while index in by_day:
        day = by_day[index]
        value = bucket_metric(day, config.metric)
        if _measured(day, config.metric) < config.drift_min_samples:
            break
        if value is None or value <= threshold:
            break
        count += 1
        index -= 1
    return Drift(count >= config.drift_days, count, threshold)
