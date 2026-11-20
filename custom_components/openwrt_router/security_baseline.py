"""Adaptive baselines and thresholds of the Security Center (stage 2, pure).

One baseline per key (a device, or router + metric + zone). No clock: ``now``
is a parameter. Keys are opaque strings composed by the caller; they may
contain identities, so a :class:`Verdict` hides its key in ``repr`` and
nothing here logs a key.

Why EWMA + exponentially weighted variance (not hour-of-day buckets):

* O(1) memory per key (a handful of floats), so thousands of keys fit;
  24 or 168 buckets per key would cost 24-168 times more for the same cap;
* it follows slow drift (a PC that is used more over weeks) without a
  retraining step;
* robustness comes from two guards: a value outside ``clip_sigma`` standard
  deviations only moves the baseline by its clipped value (one outlier
  cannot poison it), and ``min_std`` / ``min_rel_std`` stop a flat series
  from turning every small change into an anomaly.

Limit: daily seasonality is not modelled; a device busy only at night will
widen its variance instead. Plan 3.1 ("unusual connection times") needs the
Client Stability hour buckets and is not part of this module.

Rules:

* ``learning`` until ``min_samples`` samples and ``min_age_s`` observed
  time; a learning baseline never reports an anomaly;
* a missing value (None, NaN, inf) is ``no_data``: it is neither 0 nor
  normal and does not update the baseline;
* a gap longer than ``max_gap_s`` between samples (HA or router restart,
  outage) is not counted as observed time, and the next ``settle_samples``
  samples after a gap or an explicit :meth:`BaselineBook.mark_gap` are
  skipped (status ``gap``: no anomaly, no update);
* fair share when full (review M1): keys belong to a *group* (e.g. router +
  detector). A new key evicts from the group that holds the most keys,
  a learning key before a ready one, least recently used first. So a flood
  of new keys (forged DNS clients) evicts its own group's keys and never a
  ready baseline of a smaller group. Evictions are counted per group
  (:meth:`BaselineBook.pop_evictions`) so the detector can report them.
"""

from __future__ import annotations

import logging
import math
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any, Final

_LOGGER = logging.getLogger(__name__)

STORE_VERSION: Final = 1
DEFAULT_ALPHA: Final = 0.1
DEFAULT_MIN_SAMPLES: Final = 12
DEFAULT_MIN_AGE_S: Final = 6 * 3600.0
DEFAULT_Z_THRESHOLD: Final = 4.0
DEFAULT_MIN_STD: Final = 1.0
DEFAULT_MIN_REL_STD: Final = 0.1
DEFAULT_CLIP_SIGMA: Final = 3.0
DEFAULT_MAX_GAP_S: Final = 1800.0
DEFAULT_SETTLE_SAMPLES: Final = 1
DEFAULT_MAX_KEYS: Final = 4096
MAX_KEY_LEN: Final = 200
NO_GROUP: Final = ""  # keys observed without a group share this one


class BaselineStatus(StrEnum):
    """Outcome of one sample."""

    LEARNING = "learning"
    READY = "ready"
    NO_DATA = "no_data"
    GAP = "gap"


@dataclass(frozen=True, kw_only=True, slots=True)
class BaselineState:
    """Statistics of one key."""

    mean: float = 0.0
    var: float = 0.0
    samples: int = 0
    observed_s: float = 0.0
    last_ts: float | None = None
    settle: int = 0

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe form."""
        return {
            "mean": self.mean,
            "var": self.var,
            "samples": self.samples,
            "observed_s": self.observed_s,
            "last_ts": self.last_ts,
            "settle": self.settle,
        }

    @classmethod
    def from_dict(cls, data: Any) -> BaselineState | None:
        """Lenient inverse of :meth:`to_dict`; None if unusable."""
        if not isinstance(data, Mapping):
            return None
        mean, var = _num(data.get("mean")), _num(data.get("var"))
        samples, settle = data.get("samples"), data.get("settle", 0)
        if mean is None or var is None or var < 0 or not _count(samples):
            return None
        return cls(
            mean=mean,
            var=var,
            samples=samples,
            observed_s=max(0.0, _num(data.get("observed_s")) or 0.0),
            last_ts=_num(data.get("last_ts")),
            settle=settle if _count(settle) else 0,
        )


@dataclass(frozen=True, kw_only=True, slots=True)
class Verdict:
    """Result of checking one value against its baseline (key hidden)."""

    key: str = field(repr=False)
    status: BaselineStatus
    value: float | None
    mean: float | None = None
    std: float | None = None
    z: float | None = None
    anomalous: bool = False
    samples: int = 0


def _num(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class BaselineBook:
    """Baselines for at most ``max_keys`` keys (fair share by group when full)."""

    def __init__(
        self,
        *,
        alpha: float = DEFAULT_ALPHA,
        min_samples: int = DEFAULT_MIN_SAMPLES,
        min_age_s: float = DEFAULT_MIN_AGE_S,
        z_threshold: float = DEFAULT_Z_THRESHOLD,
        min_std: float = DEFAULT_MIN_STD,
        min_rel_std: float = DEFAULT_MIN_REL_STD,
        clip_sigma: float = DEFAULT_CLIP_SIGMA,
        max_gap_s: float = DEFAULT_MAX_GAP_S,
        settle_samples: int = DEFAULT_SETTLE_SAMPLES,
        max_keys: int = DEFAULT_MAX_KEYS,
        two_sided: bool = False,
    ) -> None:
        """Create an empty book; every threshold is a parameter."""
        self.alpha = min(1.0, max(0.001, float(alpha)))
        self.min_samples = max(2, int(min_samples))
        self.min_age_s = max(0.0, float(min_age_s))
        self.z_threshold = float(z_threshold)
        self.min_std = max(1e-9, float(min_std))
        self.min_rel_std = max(0.0, float(min_rel_std))
        self.clip_sigma = max(1.0, float(clip_sigma))
        self.max_gap_s = float(max_gap_s)
        self.settle_samples = max(0, int(settle_samples))
        self.max_keys = max(1, int(max_keys))
        self.two_sided = bool(two_sided)
        self.evicted = 0
        self._states: OrderedDict[str, BaselineState] = OrderedDict()
        self._group_of: dict[str, str] = {}
        self._groups: dict[str, OrderedDict[str, None]] = {}  # LRU per group
        self._pending: OrderedDict[str, int] = OrderedDict()  # evictions

    def __len__(self) -> int:
        """Number of keys."""
        return len(self._states)

    def __repr__(self) -> str:
        """Counts only, no keys."""
        return f"BaselineBook(keys={len(self._states)}, max={self.max_keys})"

    def get(self, key: str) -> BaselineState | None:
        """State of ``key`` or None."""
        return self._states.get(key)

    def is_ready(self, state: BaselineState | None) -> bool:
        """True once enough samples and observed time are collected."""
        return (
            state is not None
            and state.samples >= self.min_samples
            and state.observed_s >= self.min_age_s
        )

    def _std(self, state: BaselineState) -> float:
        return max(
            math.sqrt(state.var), self.min_std, self.min_rel_std * abs(state.mean)
        )

    def check(self, key: str, value: Any, now: float) -> Verdict:
        """Judge ``value`` without updating the baseline."""
        state = self._states.get(key)
        return self._judge(key, state, _num(value), now)

    def observe(
        self, key: str, value: Any, now: float, *, group: str | None = None
    ) -> Verdict:
        """Judge ``value`` against the baseline, then learn from it.

        ``group`` (e.g. ``"<router>|<detector>"``) only matters when the book
        is full: see the module notes on fair share.
        """
        key = str(key)[:MAX_KEY_LEN]
        number = _num(value)
        state = self._states.get(key)
        verdict = self._judge(key, state, number, now)
        if number is None:
            return verdict  # missing is not 0 and not normal: no update
        if state is None:
            if len(self._states) >= self.max_keys:
                self._evict()
            state = BaselineState()
            self._join(key, NO_GROUP if group is None else str(group))
        self._states[key] = self._update(state, number, now, verdict)
        self._states.move_to_end(key)
        self._groups[self._group_of[key]].move_to_end(key)
        return verdict

    def pop_evictions(self, group: str) -> int:
        """Keys of ``group`` evicted since the last call (then reset to 0)."""
        return self._pending.pop(group, 0)

    def _join(self, key: str, group: str) -> None:
        self._leave(key)
        self._group_of[key] = group
        self._groups.setdefault(group, OrderedDict())[key] = None

    def _leave(self, key: str) -> str | None:
        group = self._group_of.pop(key, None)
        members = self._groups.get(group) if group is not None else None
        if members is not None:
            members.pop(key, None)
            if not members:
                del self._groups[group]  # type: ignore[arg-type]
        return group

    def _evict(self) -> None:
        """Drop one key of the largest group (learning before ready, LRU)."""
        if not self._groups:
            self._states.popitem(last=False)
            self.evicted += 1
            return
        members = max(self._groups.values(), key=len)
        victim = next(
            (k for k in members if not self.is_ready(self._states.get(k))),
            next(iter(members)),
        )
        del self._states[victim]
        group = self._leave(victim)
        self.evicted += 1
        if group is not None:
            self._pending[group] = self._pending.pop(group, 0) + 1
            if len(self._pending) > self.max_keys:
                self._pending.popitem(last=False)

    def _judge(
        self, key: str, state: BaselineState | None, number: float | None, now: float
    ) -> Verdict:
        if number is None:
            return Verdict(
                key=key,
                status=BaselineStatus.NO_DATA,
                value=None,
                samples=state.samples if state else 0,
            )
        if state is None:
            return Verdict(key=key, status=BaselineStatus.LEARNING, value=number)
        if state.settle > 0 or self._is_gap(state, now):
            return Verdict(
                key=key, status=BaselineStatus.GAP, value=number, samples=state.samples
            )
        std = self._std(state)
        z = (number - state.mean) / std
        if not self.is_ready(state):
            return Verdict(
                key=key,
                status=BaselineStatus.LEARNING,
                value=number,
                mean=state.mean,
                std=std,
                z=z,
                samples=state.samples,
            )
        score = abs(z) if self.two_sided else z
        return Verdict(
            key=key,
            status=BaselineStatus.READY,
            value=number,
            mean=state.mean,
            std=std,
            z=z,
            anomalous=score >= self.z_threshold,
            samples=state.samples,
        )

    def _is_gap(self, state: BaselineState, now: float) -> bool:
        return state.last_ts is not None and (
            now - state.last_ts > self.max_gap_s or now < state.last_ts
        )

    def _update(
        self, state: BaselineState, value: float, now: float, verdict: Verdict
    ) -> BaselineState:
        if verdict.status is BaselineStatus.GAP:
            # Skip the sample; the gap itself is no observed time.
            settle = state.settle - 1 if state.settle > 0 else self.settle_samples - 1
            return replace(state, last_ts=now, settle=max(0, settle))
        span = 0.0 if state.last_ts is None else max(0.0, now - state.last_ts)
        if state.samples == 0:
            return replace(state, mean=value, var=0.0, samples=1, last_ts=now)
        x = value
        if self.is_ready(state):
            limit = self.clip_sigma * self._std(state)
            x = min(state.mean + limit, max(state.mean - limit, value))
        # Early samples: cumulative mean, then the fixed EW factor.
        alpha = max(self.alpha, 1.0 / (state.samples + 1))
        diff = x - state.mean
        incr = alpha * diff
        return replace(
            state,
            mean=state.mean + incr,
            var=(1.0 - alpha) * (state.var + diff * incr),
            samples=state.samples + 1,
            observed_s=state.observed_s + span,
            last_ts=now,
        )

    def mark_gap(self, *, key: str | None = None, prefix: str | None = None) -> int:
        """Mark a restart/outage: the next samples of the keys are skipped.

        ``key`` marks one key, ``prefix`` every key starting with it, neither
        marks all keys. Returns the number of keys marked.
        """
        marked = 0
        for name, state in list(self._states.items()):
            if key is not None and name != key:
                continue
            if prefix is not None and not name.startswith(prefix):
                continue
            self._states[name] = replace(
                state, last_ts=None, settle=max(1, self.settle_samples)
            )
            marked += 1
        return marked

    def reset(self, key: str) -> None:
        """Forget ``key`` (it starts learning again)."""
        self._states.pop(key, None)
        self._leave(key)

    def forget(self, prefix: str) -> int:
        """Drop every key and eviction count starting with ``prefix``.

        For a forgotten router (``"<router>|"``). Returns the keys dropped.
        """
        names = [name for name in self._states if name.startswith(prefix)]
        for name in names:
            self.reset(name)
        for group in [g for g in self._pending if g.startswith(prefix)]:
            del self._pending[group]
        return len(names)

    def to_dict(self) -> dict[str, Any]:
        """Store form (keys may hold identities: never log it)."""
        return {
            "v": STORE_VERSION,
            "keys": {key: state.to_dict() for key, state in self._states.items()},
        }

    @classmethod
    def from_dict(cls, data: Any, **params: Any) -> BaselineBook:
        """Rebuild from :meth:`to_dict`; damaged entries are skipped."""
        book = cls(**params)
        keys = data.get("keys") if isinstance(data, Mapping) else None
        for key, row in (keys if isinstance(keys, Mapping) else {}).items():
            state = BaselineState.from_dict(row)
            if state is None or not isinstance(key, str):
                continue
            if len(book._states) >= book.max_keys:
                book.evicted += 1
                continue
            book._states[key[:MAX_KEY_LEN]] = state
            book._join(key[:MAX_KEY_LEN], _stored_group(key))
        return book


def _stored_group(key: str) -> str:
    """Group of a stored key: ``"<router>|<detector>"`` of a detector key."""
    parts = key.split("|", 2)
    return "|".join(parts[:2]) if len(parts) == 3 else NO_GROUP
