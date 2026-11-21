"""Tests for security_baseline (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json
import math

from custom_components.openwrt_router.security_baseline import (
    BaselineBook,
    BaselineStatus,
)

T0 = 1_700_000_000.0
STEP = 300.0
KEY = "rtr_x|dns_rate|aa:bb:cc:dd:ee:ff"


def _train(
    book: BaselineBook, key: str = KEY, n: int = 80, base: float = 100.0
) -> float:
    """Feed ``n`` steady samples (±5 %), return the next timestamp."""
    ts = T0
    for i in range(n):
        book.observe(key, base * (1 + 0.05 * math.sin(i)), ts)
        ts += STEP
    return ts


def test_case14_anomaly_baselines_learn_then_detect() -> None:
    book = BaselineBook()
    first = book.observe(KEY, 100.0, T0)
    assert first.status is BaselineStatus.LEARNING and not first.anomalous
    # enough samples but not enough observed time → still learning
    quick = BaselineBook(min_samples=5, min_age_s=6 * 3600)
    for i in range(10):
        verdict = quick.observe(KEY, 1000.0 if i == 9 else 10.0, T0 + i * 60)
    assert verdict.status is BaselineStatus.LEARNING and not verdict.anomalous
    ts = _train(book)
    normal = book.observe(KEY, 104.0, ts)
    assert normal.status is BaselineStatus.READY and not normal.anomalous
    spike = book.observe(KEY, 600.0, ts + STEP)
    assert spike.status is BaselineStatus.READY and spike.anomalous
    assert spike.z is not None and spike.z > 4
    # one-sided by default: a drop is not an attack indicator
    assert not book.check(KEY, 0.0, ts + 2 * STEP).anomalous
    assert BaselineBook(two_sided=True).two_sided


def test_case14_outliers_do_not_poison_the_baseline() -> None:
    book = BaselineBook()
    ts = _train(book)
    mean_before = book.get(KEY).mean  # type: ignore[union-attr]
    for i in range(5):
        assert book.observe(KEY, 5000.0, ts + i * STEP).anomalous
    state = book.get(KEY)
    assert state is not None
    assert state.mean < mean_before * 1.5  # clipped, not dragged to 5000
    assert book.check(KEY, 600.0, ts + 6 * STEP).anomalous


def test_case14_missing_value_is_neither_zero_nor_normal() -> None:
    book = BaselineBook()
    ts = _train(book)
    before = book.get(KEY)
    for missing in (None, float("nan"), float("inf"), "12", True):
        verdict = book.observe(KEY, missing, ts)
        assert verdict.status is BaselineStatus.NO_DATA
        assert verdict.value is None and not verdict.anomalous
    assert book.get(KEY) == before  # no update
    assert book.observe("other", None, ts).status is BaselineStatus.NO_DATA
    assert book.get("other") is None


def test_case14_restart_gaps_are_skipped() -> None:
    book = BaselineBook(max_gap_s=1800)
    ts = _train(book)
    state = book.get(KEY)
    assert state is not None
    later = ts + 4 * 3600  # outage / HA restart
    gap = book.observe(KEY, 900.0, later)
    assert gap.status is BaselineStatus.GAP and not gap.anomalous
    after = book.get(KEY)
    assert after is not None
    assert after.samples == state.samples and after.observed_s == state.observed_s
    assert after.mean == state.mean
    assert book.observe(KEY, 101.0, later + STEP).status is BaselineStatus.READY
    # clock going backwards is a gap as well
    assert book.observe(KEY, 100.0, later - 10 * STEP).status is BaselineStatus.GAP


def test_case14_keys_are_per_device_and_bounded() -> None:
    book = BaselineBook(max_keys=3)
    for i in range(5):
        book.observe(f"dev{i}", 1.0, T0)
    assert len(book) == 3
    assert book.evicted == 2
    assert book.get("dev0") is None and book.get("dev4") is not None
    a, b = BaselineBook(), BaselineBook()
    ts = _train(a, "busy", base=1000.0)
    _train(a, "quiet", base=5.0)
    assert not a.check("busy", 1100.0, ts).anomalous
    assert a.check("quiet", 1100.0, ts).anomalous
    assert repr(b) == "BaselineBook(keys=0, max=4096)"


def test_mark_gap_by_prefix_and_reset() -> None:
    book = BaselineBook()
    ts = _train(book, "r1|fw|wan")
    _train(book, "r2|fw|wan")
    assert book.mark_gap(prefix="r1|") == 1
    assert book.observe("r1|fw|wan", 9999.0, ts).status is BaselineStatus.GAP
    assert book.observe("r2|fw|wan", 9999.0, ts).anomalous
    book.reset("r2|fw|wan")
    assert book.get("r2|fw|wan") is None
    assert book.mark_gap() == 1


def test_case18_ha_restart_baseline_roundtrip() -> None:
    book = BaselineBook()
    ts = _train(book)
    data = json.loads(json.dumps(book.to_dict()))
    restored = BaselineBook.from_dict(data)
    assert restored.get(KEY) == book.get(KEY)
    assert (
        restored.check(KEY, 600.0, ts).anomalous == book.check(KEY, 600.0, ts).anomalous
    )
    damaged = BaselineBook.from_dict(
        {
            "keys": {
                "a": {"mean": "x"},
                "b": None,
                "c": {"mean": 1, "var": -1, "samples": 1},
            }
        }
    )
    assert len(damaged) == 0
    assert len(BaselineBook.from_dict(None)) == 0
    capped = BaselineBook.from_dict(
        data | {"keys": {**data["keys"], "z": data["keys"][KEY]}}, max_keys=1
    )
    assert len(capped) == 1 and capped.evicted == 1


def test_verdict_repr_hides_key() -> None:
    verdict = BaselineBook().observe(KEY, 1.0, T0)
    assert "aa:bb" not in repr(verdict)
