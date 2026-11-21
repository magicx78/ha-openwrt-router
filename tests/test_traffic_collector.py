"""Intake of the optional external traffic collector (plan §8, Phase K).

Schema ``traffic.collector.v1``, strict validation with fixed limits, all
or nothing, bounded store, rate limit and a budgeted security event for
refused authorisations. The HTTP route is covered in test_traffic_views.
Pure functions and a FlowStore; no router, no Home Assistant, no network.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from custom_components.openwrt_router import traffic_collector as tc
from custom_components.openwrt_router.traffic_const import FEED_COLLECTOR
from custom_components.openwrt_router.traffic_flows import FlowStore

NOW = 1_800_000_000.0
KEY = bytes(range(32))
RID = "rtr_" + "1" * 32
MAC = "02:00:5e:30:00:01"


def record(**over: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "kind": "flow",
        "router_id": RID,
        "window": {"start": NOW - 60, "end": NOW},
        "direction": "orig",
        "proto": "tcp",
        "src": "192.0.2.10",
        "dst": "198.51.100.5",
        "src_port": 50000,
        "dst_port": 443,
        "client_mac": MAC,
        "bytes": 1200,
        "packets": 10,
        "observation": "observed",
    }
    raw.update(over)
    return raw


def body(*records: Any, **over: Any) -> bytes:
    data: dict[str, Any] = {
        "schema": tc.SCHEMA_V1,
        "collector": "edge-1",
        "sent_at": NOW,
        "records": list(records) if records else [record()],
    }
    data.update(over)
    return json.dumps(data).encode()


def refused(raw: bytes, **kw: Any) -> tc.CollectorRejected:
    with pytest.raises(tc.CollectorRejected) as err:
        tc.CollectorIntake().ingest(
            raw, now_wall=NOW, module_key=KEY, flows=kw.get("flows") or FlowStore()
        )
    return err.value


# --- schema and limits ----------------------------------------------------------------


def test_valid_call_is_kept_completely() -> None:
    intake, flows = tc.CollectorIntake(), FlowStore()
    answer = intake.ingest(
        body(record(), record(dst_port=80)), now_wall=NOW, module_key=KEY, flows=flows
    )
    assert answer == {"v": 1, "schema": tc.SCHEMA_V1, "accepted": 2, "rejected": []}
    assert len(flows) == 2
    assert intake.counters["accepted_calls"] == 1
    assert intake.counters["accepted_records"] == 2
    assert intake.last_accepted_wall == NOW


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b"{nope", "not_json"),
        (b"[1, 2]", "not_an_object"),
        (body(extra=1), "unknown_key"),
        (body(schema=None), "schema_missing"),
        (body(schema="traffic.collector.v2"), "schema_unsupported"),
        (body(schema="traffic.collector.v1.1"), "schema_unsupported"),
        (body(collector="x" * 33), "invalid_collector_name"),
        (body(collector="a\nb"), "invalid_collector_name"),
        (body(sent_at="now"), "invalid_sent_at"),
        (body(sent_at=NOW + 3600), "invalid_sent_at"),
        (body(sent_at=NOW - 2 * 86400), "invalid_sent_at"),
        (body(sent_at=True), "invalid_sent_at"),
        (body(records={"a": 1}), "records_missing"),
        (body(*[record()] * 501), "too_many_records"),
        (body(record(src="x" * 65)), "string_too_long"),
        (body(record(window={"start": {"deep": [1]}, "end": NOW})), "too_deep"),
    ],
)
def test_invalid_envelope_is_refused_with_a_fixed_reason(
    raw: bytes, reason: str
) -> None:
    err = refused(raw)
    assert err.status == 400 and err.reason == reason


def test_one_bad_record_rejects_the_whole_call() -> None:
    flows = FlowStore()
    err = refused(
        body(record(), record(proto="gre"), record(), {"kind": "client_aggregate"}),
        flows=flows,
    )
    assert err.reason == "records_rejected"
    assert err.rejected == [(1, "invalid_field"), (3, "kind_not_supported")]
    assert len(flows) == 0
    out = tc.rejected_body(err)
    assert out["accepted"] == 0 and out["rejected_total"] == 2
    assert out["rejected"][1] == {"index": 3, "reason": "kind_not_supported"}


def test_rejected_list_is_capped() -> None:
    err = refused(body(*[record(proto="gre")] * 120))
    out = tc.rejected_body(err)
    assert len(out["rejected"]) == tc.MAX_REJECTED_LISTED
    assert out["rejected_total"] == 120


def test_aggregate_kinds_are_part_of_the_schema_but_not_taken() -> None:
    for kind in sorted(tc.AGGREGATE_KINDS):
        err = refused(body({"kind": kind}))
        assert err.rejected == [(0, "kind_not_supported")]


def test_records_with_a_mac_need_the_module_key() -> None:
    with pytest.raises(tc.CollectorRejected) as err:
        tc.CollectorIntake().ingest(
            body(), now_wall=NOW, module_key=None, flows=FlowStore()
        )
    assert err.value.rejected == [(0, "module_key_missing")]


def test_a_call_that_does_not_fit_is_refused_as_a_whole() -> None:
    flows = FlowStore(max_total=3, max_per_feed=500)
    intake = tc.CollectorIntake()
    intake.ingest(body(record(), record()), now_wall=NOW, module_key=KEY, flows=flows)
    with pytest.raises(tc.CollectorRejected) as err:
        intake.ingest(  # another call (sent_at), not a repeat of the first
            body(record(), record(), sent_at=NOW + 1),
            now_wall=NOW,
            module_key=KEY,
            flows=flows,
        )
    assert err.value.status == 503 and err.value.reason == "store_full"
    assert len(flows) == 2  # nothing of the second call
    assert intake.counters["rejected_store_full"] == 1
    assert intake.counters["rejected_records"] == 2


def test_a_full_feed_replacing_its_own_oldest_is_no_refusal() -> None:
    flows = FlowStore(max_total=10, max_per_feed=2)
    recs = [record(dst_port=p) for p in (1, 2, 3)]
    parsed = tc.validate_records(recs, now=NOW, module_key=KEY)
    assert flows.can_take(parsed, origin=FEED_COLLECTOR, now=NOW)


def test_limits_are_fixed() -> None:
    limits = tc.limits()
    assert limits["body_max_bytes"] == 256 * 1024
    assert limits["max_records"] == 500
    assert limits["max_depth"] == 4
    assert limits["max_string"] == 64
    assert limits["min_interval_s"] == 10.0


# --- rate, events, state --------------------------------------------------------------


def test_rate_limit_answers_429_with_retry_after() -> None:
    intake = tc.CollectorIntake()
    intake.check_rate(100.0)
    with pytest.raises(tc.CollectorRejected) as err:
        intake.check_rate(103.0)
    assert err.value.status == 429 and err.value.retry_after == 7
    intake.check_rate(110.0)
    assert intake.counters["rejected_rate_limited"] == 1


def test_refused_authorisation_is_a_budgeted_security_event() -> None:
    sent: list[tuple[str, dict[str, Any]]] = []
    intake = tc.CollectorIntake()
    intake.emit = lambda event, **kw: sent.append((event, kw))
    for i in range(15):
        intake.auth_refused("authorization_denied", NOW + i)
    assert len(sent) == tc.EVENT_BUDGET_PER_HOUR
    event, kw = sent[0]
    assert event == tc.EVENT_REJECTED
    assert kw["security_relevant"] is True
    assert kw["data"] == {"reason": "authorization_denied"}
    assert intake.counters["events_over_budget"] == 5
    intake.auth_refused("collector_off", NOW + 3700)  # an hour later: again
    assert len(sent) == tc.EVENT_BUDGET_PER_HOUR + 1


def test_without_the_core_events_are_counted_not_published() -> None:
    intake = tc.CollectorIntake()
    intake.auth_refused("insecure_transport", NOW)
    assert intake.counters["events_not_published"] == 1
    assert intake.counters["rejected_insecure_transport"] == 1


def test_a_failing_emit_never_breaks_the_intake() -> None:
    intake = tc.CollectorIntake()

    def boom(*_a: Any, **_kw: Any) -> None:
        raise RuntimeError("core gone")

    intake.emit = boom
    intake.auth_refused("authorization_denied", NOW)
    assert intake.counters["events_failed"] == 1


def test_states() -> None:
    intake = tc.CollectorIntake()
    assert intake.state(enabled=False, now_wall=NOW, ttl_s=900) == "off"
    assert intake.state(enabled=True, now_wall=NOW, ttl_s=900) == "waiting"
    intake.ingest(body(), now_wall=NOW, module_key=KEY, flows=FlowStore())
    assert intake.state(enabled=True, now_wall=NOW + 60, ttl_s=900) == "receiving"
    assert intake.state(enabled=True, now_wall=NOW + 901, ttl_s=900) == "silent"
    intake.clear()
    assert intake.state(enabled=True, now_wall=NOW, ttl_s=900) == "waiting"


def test_nothing_of_a_record_reaches_the_log_or_the_summary(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    intake = tc.CollectorIntake()
    with pytest.raises(tc.CollectorRejected):
        intake.ingest(
            body(record(proto="gre")), now_wall=NOW, module_key=KEY, flows=FlowStore()
        )
    intake.ingest(body(), now_wall=NOW, module_key=KEY, flows=FlowStore())
    text = caplog.text + json.dumps(intake.summary())
    for needle in (MAC, "192.0.2.10", "198.51.100.5", "edge-1"):
        assert needle not in text
    assert intake.summary()["schema"] == tc.SCHEMA_V1
