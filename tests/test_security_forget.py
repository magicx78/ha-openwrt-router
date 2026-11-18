"""Forgetting a router (core event ``router.forgotten``) in the Security Center.

All per-router state of the pure Security Center modules goes; other
routers keep theirs. The trust book is fleet-wide and is not a holder.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Mapping
from typing import Any

import pytest

from custom_components.openwrt_router.security_logsrc import (
    Deduper,
    KeyAssigner,
    Liveness,
    SecLogRecord,
    second_token,
)
from custom_components.openwrt_router.security_model import (
    DataSource,
    LogPath,
    forget_router,
    source_status,
)
from custom_components.openwrt_router.security_rules import (
    DetectorSet,
    WifiSignal,
    default_detectors,
)

T0 = 1_795_000_000.0
R1 = "rtr_" + "1" * 32
R2 = "rtr_" + "2" * 32


def _mentions(obj: Any, needle: str, seen: set[int] | None = None) -> int:
    """How often ``needle`` occurs anywhere in the object graph of ``obj``."""
    seen = set() if seen is None else seen
    if isinstance(obj, str):
        return obj.count(needle)
    if obj is None or isinstance(obj, int | float | bytes):
        return 0
    if id(obj) in seen:
        return 0
    seen.add(id(obj))
    if isinstance(obj, Mapping):
        items: list[Any] = [*obj.keys(), *obj.values()]
    elif isinstance(obj, list | tuple | set | frozenset | deque):
        items = list(obj)
    else:
        items = list(vars(obj).values()) if hasattr(obj, "__dict__") else []
        for cls in type(obj).__mro__:
            for name in getattr(cls, "__slots__", ()):
                if hasattr(obj, name):
                    items.append(getattr(obj, name))
    return sum(_mentions(item, needle, seen) for item in items)


def _wifi(router: str, ts: float, kind: str, mac: str, ap: str) -> WifiSignal:
    return WifiSignal(ts=ts, router_id=router, kind=kind, client=mac, ap=ap)


def _log(router: str, ts: float, kind: str, **fields: Any) -> dict[str, Any]:
    return {"router": router, "ts": ts, "kind": kind, "fields": fields}


def _feed_router(dset: DetectorSet, router: str) -> None:
    signals = []
    for i in range(12):
        mac = f"aa:bb:cc:00:00:{i:02x}"
        for kind in ("wifi.psk_mismatch", "wifi.connected", "wifi.deauth"):
            signals.append(_wifi(router, T0 + i, kind, mac, f"wlan{i % 2}"))
    dset.feed_wifi(signals)
    records = []
    for i in range(30):
        records.append(_log(router, T0 + i, "fw.drop", zone="guest", dpt=1000 + i))
        records.append(
            _log(
                router,
                T0 + i,
                "fw.drop",
                dir="forward",
                zone="guest",
                dest_zone="lan",
                src="192.0.2.10",
            )
        )
        records.append(
            _log(router, T0 + i, "dns.query", client="192.0.2.10", name=f"h{i}.org")
        )
    dset.feed_records(records)
    dset.feed_drift([_log(router, T0, "config.drift", area="firewall.zone")])
    dset.note_uptime(router, 1000.0)


def _statuses(*routers: str, now: float) -> dict[str, dict[str, Any]]:
    return {
        r: {s: source_status(s, now=now, last_ok=now) for s in DataSource}
        for r in routers
    }


def test_detector_set_forgets_one_router_and_keeps_the_other() -> None:
    dset = default_detectors()
    for router in (R1, R2):
        _feed_router(dset, router)
    for step in range(3):  # baselines sample on evaluation
        dset.evaluate(T0 + 40 + 300 * step, _statuses(R1, R2, now=T0 + 40))
    assert _mentions(dset, R1) > 0
    assert dset.baseline.get(f"{R1}|fw_blocked|guest") is not None
    r2_before = _mentions(dset, R2)

    dset.forget_router(R1)

    assert _mentions(dset, R1) == 0
    assert _mentions(dset, R2) == r2_before
    assert dset.baseline.get(f"{R2}|fw_blocked|guest") is not None
    assert dset.baseline.pop_evictions(f"{R1}|fw_blocked") == 0


def test_forget_needs_a_contract_router_id() -> None:
    dset = default_detectors()
    with pytest.raises(ValueError):
        dset.forget_router("rtr_1|")


def _record(assigner: KeyAssigner, router: str, ts: float, msg: str) -> SecLogRecord:
    second = second_token(ts, estimated=False, local_wall=None)
    return SecLogRecord(
        router=router,
        ts=ts,
        recv=ts + 0.2,
        path=LogPath.SYSLOG.value,
        pri=85,
        proc="kernel",
        pid=None,
        msg=msg,
        kind="fw.drop",
        fields={"zone": "guest"},
        key=assigner.assign(router, second, "kernel", msg),
    )


def test_log_path_state_forgets_one_router_and_keeps_the_other() -> None:
    assigner = KeyAssigner()
    deduper = Deduper()
    live = Liveness()
    for router in (R1, R2):
        records = [_record(assigner, router, T0 + i, f"line {i}") for i in range(20)]
        live.observe(deduper.filter(records, T0 + 30))
    holders = (assigner, deduper, live)
    assert all(_mentions(h, R1) > 0 for h in holders)
    before = [_mentions(h, R2) for h in holders]
    r2_mark = deduper.hwm(R2)

    assert forget_router(R1, holders) == 3

    assert [_mentions(h, R1) for h in holders] == [0, 0, 0]
    assert [_mentions(h, R2) for h in holders] == before
    assert deduper.hwm(R1) is None and deduper.hwm(R2) == r2_mark
    assert live.last_ok(R1, DataSource.FIREWALL_LOG) is None
    assert live.last_ok(R2, DataSource.FIREWALL_LOG) is not None
    # forgetting an unknown router changes nothing
    forget_router(R1, holders)
    assert [_mentions(h, R2) for h in holders] == before


def test_records_with_a_foreign_router_id_are_counted_not_stored() -> None:
    dset = default_detectors()
    dset.feed_records([_log("r1", T0, "fw.drop", zone="guest")])
    dset.feed_drift([_log("entry-1", T0, "config.drift", area="firewall.zone")])
    assert dset.feed_wifi([{"router": "r1", "ts": T0, "kind": "wifi.deauth"}]) == 0
    assert dset.invalid_router == 3
    assert dset.state_size() == 0
