"""Every Security Center output survives the core's output masking.

``core_masking.mask_for_output`` hides the value of a name that holds a
secret word (``auth``, ``key``, ``token`` …), counters included (contract
19.1 #110). Our output names must therefore never contain one: no number
may vanish when an output structure goes through the core masking.
"""

from __future__ import annotations

import dataclasses
import re
from collections.abc import Iterator
from typing import Any

from custom_components.openwrt_router.core_masking import mask_for_output
from custom_components.openwrt_router.core_models import derive_module_key
from custom_components.openwrt_router.security_logsrc import (
    Deduper,
    DedupStats,
    SourceStats,
)
from custom_components.openwrt_router.security_model import (
    IDENTITY_KEY_PURPOSE,
    MODULE_SOURCE,
    DataSource,
    SecurityEvent,
    source_status,
)
from custom_components.openwrt_router.security_rules import (
    DRIFT_KIND,
    DetectorResult,
    WifiSignal,
    default_detectors,
)
from custom_components.openwrt_router.security_score import (
    DEFAULT_RULES,
    compute_score,
)
from custom_components.openwrt_router.security_trust import TrustBook

T0 = 1_795_000_000.0
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32
KEY = derive_module_key(b"i" * 32, MODULE_SOURCE, IDENTITY_KEY_PURPOSE)
_NUMBER_IN_TEXT = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.])")


def _numbers(obj: Any, path: str = "") -> Iterator[tuple[str, Any]]:
    """Every number of ``obj``, also those written into ``name=value`` text."""
    if isinstance(obj, bool) or obj is None:
        return
    if isinstance(obj, int | float):
        yield path, obj
    elif isinstance(obj, str):
        for match in _NUMBER_IN_TEXT.finditer(obj):
            yield f"{path}~", match.group(0)
    elif isinstance(obj, dict):
        for key, value in obj.items():
            yield from _numbers(value, f"{path}.{key}")
    elif isinstance(obj, list | tuple):
        for index, value in enumerate(obj):
            yield from _numbers(value, f"{path}[{index}]")


def _assert_numbers_survive(name: str, obj: Any) -> None:
    before = sorted(map(str, _numbers(obj)))
    after = sorted(map(str, _numbers(mask_for_output(obj))))
    assert after == before, (name, sorted(set(before) - set(after)))


def _events() -> list[tuple[str, SecurityEvent]]:
    """Real findings of most detectors (one per detector)."""
    dset = default_detectors()
    signals = []
    for router in (R1, R2):
        for i in range(12):
            mac = f"aa:bb:cc:00:00:{i:02x}"
            kinds = ("wifi.psk_mismatch",) * 4 + ("wifi.connected",) * 6
            for kind in (*kinds, "wifi.deauth", "wifi.deauth", "wifi.deauth"):
                signals.append(
                    WifiSignal(
                        ts=T0 + i, router_id=router, kind=kind, client=mac, ap="wlan0"
                    )
                )
    dset.feed_wifi(signals)
    records = []
    for i in range(40):
        for fields in (
            {"zone": "guest", "dpt": 1000 + i, "src": "192.0.2.10"},
            {"zone": "guest", "dpt": 22, "src": "192.0.2.11", "dir": "input"},
            {
                "dir": "forward",
                "zone": "guest",
                "dest_zone": "lan",
                "src": "192.0.2.10",
            },
        ):
            records.append(
                {"router": R1, "ts": T0 + i, "kind": "fw.drop", "fields": fields}
            )
        records.append(
            {
                "router": R1,
                "ts": T0 + i,
                "kind": "dns.reply",
                "fields": {"client": "192.0.2.10", "name": f"h{i}.org", "rcode": "3"},
            }
        )
    dset.feed_records(records)
    dset.feed_drift(
        [
            {
                "router": R1,
                "ts": T0,
                "kind": DRIFT_KIND,
                "fields": {"drift_id": "d1", "areas": ["firewall"], "critical": True},
            }
        ]
    )
    statuses = {
        r: {s: source_status(s, now=T0 + 40, last_ok=T0 + 40) for s in DataSource}
        for r in (R1, R2)
    }
    out: dict[str, SecurityEvent] = {}
    results: list[DetectorResult] = []
    for step in range(3):
        for result in dset.evaluate(T0 + 40 + step, statuses):
            results.append(result)
            for event in result.events:
                out.setdefault(result.detector_id, event)
    for result in results:
        plain = dataclasses.asdict(dataclasses.replace(result, events=()))
        _assert_numbers_survive(f"result {result.detector_id}", plain)
    _assert_numbers_survive("detector set", {"invalid_router": dset.invalid_router})
    return sorted(out.items())


def test_findings_keep_every_number_through_core_masking() -> None:
    events = _events()
    assert {"wifi_multi_ap_auth", "wifi_auth_many_clients"} <= {n for n, _ in events}
    for name, event in events:
        _assert_numbers_survive(f"{name} evidence", list(event.evidence))
        _assert_numbers_survive(f"{name} redacted", event.redacted())
        core = event.to_core_event(module_key=KEY)
        _assert_numbers_survive(f"{name} core", core.to_dict())


def test_counters_and_stats_keep_every_number() -> None:
    source = SourceStats(
        **{f.name: i + 1 for i, f in enumerate(dataclasses.fields(SourceStats))}
    )
    dedup = DedupStats(
        **{f.name: i + 1 for i, f in enumerate(dataclasses.fields(DedupStats))}
    )
    _assert_numbers_survive("source stats", source.to_dict())
    _assert_numbers_survive("dedup stats", dedup.to_dict())
    _assert_numbers_survive("dedup footprint", Deduper().footprint())
    status = source_status(DataSource.FIREWALL_LOG, now=T0, last_ok=T0 - 5)
    _assert_numbers_survive("source status", status.to_dict())


def test_score_and_trust_outputs_keep_every_number() -> None:
    values = {rule.id: 1 for rule in DEFAULT_RULES}
    statuses = {s: source_status(s, now=T0, last_ok=T0) for s in DataSource}
    score = compute_score(values, statuses)
    _assert_numbers_survive("score values", values)  # keyed by factor id
    _assert_numbers_survive("score", score.to_dict())
    assert all("auth" not in rule.id for rule in DEFAULT_RULES)
    book = TrustBook()
    _assert_numbers_survive("trust counts", book.counts(T0))
    _assert_numbers_survive("trust repr", {"overflow": book.capacity_overflow})
