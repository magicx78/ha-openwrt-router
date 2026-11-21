"""Flows (test areas 16 missing flow data, 17 conntrack snapshot evaluation).

traffic_flows.py and traffic_protocols.py: collector records validated,
RAM-only store with hard limits and visible drops, no flow source is not
"no traffic", snapshots are not a flow history, NAT and offload lower the
coverage, addresses only as pseudonyms and never in logs, protocol labels
are heuristic. Documentation address ranges only; no router, no network.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.traffic_const import (
    ACCURACY_MEDIUM,
    ACCURACY_NONE,
    FEED_COLLECTOR,
    FLOW_STATE_NO_SOURCE,
    FLOW_STATE_NOT_READY,
    FLOW_STATE_READY,
    FLOW_STATE_SILENT,
    NOTE_PORT_IS_NO_PROOF,
    NOTE_TLS_NOT_ATTRIBUTED,
    REASON_ACCT_OFF,
    REASON_EMPTY_IS_NOT_NO_TRAFFIC,
    REASON_NAT_SEEN,
    REASON_SNAPSHOT_NOT_HISTORY,
    REASON_SNAPSHOT_TRUNCATED,
    REJECT_BAD_FIELD,
    REJECT_FUTURE,
    REJECT_KEY_MISSING,
    REJECT_NOT_FLOW,
    REJECT_SPAN,
    REJECT_TOO_OLD,
    REJECT_UNKNOWN_FIELD,
)
from custom_components.openwrt_router.traffic_flows import (
    FlowRejected,
    FlowStore,
    evaluate_snapshot,
    normalise_collector_flow,
    parse_conntrack,
)
from custom_components.openwrt_router.traffic_model import (
    Coverage,
    FlowDirection,
    FlowKind,
)
from custom_components.openwrt_router.traffic_protocols import classify

RID = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
KEY = bytes(range(32))
NOW = 1_800_000_000.0
MAC = "02:00:5e:30:00:01"
CLIENT_IP = "192.0.2.10"
SERVER_IP = "198.51.100.5"
WAN_IP = "203.0.113.2"


def flow(**over: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "kind": "flow",
        "router_id": RID,
        "window": {"start": NOW - 60, "end": NOW},
        "direction": "orig",
        "proto": "tcp",
        "src": CLIENT_IP,
        "dst": SERVER_IP,
        "src_port": 50000,
        "dst_port": 443,
        "client_mac": MAC,
        "vlan_id": 10,
        "bytes": 1200,
        "packets": 10,
        "observation": "observed",
    }
    raw.update(over)
    return raw


# --- area 16: missing flow data ------------------------------------------------------


def test_without_flow_source_state_is_no_source_not_no_traffic() -> None:
    store = FlowStore()
    state = store.source_state(NOW, module_key=KEY)
    assert state.state == FLOW_STATE_NO_SOURCE
    assert state.reason == "needs_flow_source"
    result = store.query(NOW, module_key=KEY)
    assert result.rows == () and result.complete is False
    assert REASON_EMPTY_IS_NOT_NO_TRAFFIC in result.notes
    assert result.source.state == FLOW_STATE_NO_SOURCE


def test_silent_source_is_not_no_traffic_either() -> None:
    store = FlowStore(ttl_s=60)
    store.add(
        normalise_collector_flow(flow(), now=NOW, module_key=KEY),
        origin=FEED_COLLECTOR,
        now=NOW,
    )
    later = store.source_state(NOW + 3600, module_key=KEY)
    assert later.state == FLOW_STATE_SILENT and later.records == 0
    assert store.query(NOW + 3600, module_key=KEY).rows == ()


def test_without_module_key_nothing_is_shown_or_taken() -> None:
    store = FlowStore()
    accepted, rejected = store.add_collector([flow()], now=NOW, module_key=None)
    assert (accepted, rejected) == (0, [(0, REJECT_KEY_MISSING)])
    accepted, _ = store.add_collector([flow(client_mac=None)], now=NOW, module_key=None)
    assert accepted == 1
    state = store.source_state(NOW, module_key=None)
    assert state.state == FLOW_STATE_NOT_READY
    assert store.query(NOW, module_key=None).rows == ()


def test_collector_record_becomes_a_pseudonymised_row() -> None:
    store = FlowStore()
    accepted, rejected = store.add_collector([flow()], now=NOW, module_key=KEY)
    assert (accepted, rejected) == (1, [])
    result = store.query(NOW, module_key=KEY)
    assert result.source.state == FLOW_STATE_READY
    (row,) = result.rows
    assert row["client_ref"] == pseudonymise_identifier("client", MAC, KEY)
    assert row["src"] == pseudonymise_identifier("ip", CLIENT_IP, KEY)
    assert row["dst"].startswith("ipa_")
    assert row["kind"] == "observed" and row["snapshot"] is False
    assert row["protocol"]["heuristic"] is True
    text = json.dumps(result.to_dict())
    for raw in (MAC, CLIENT_IP, SERVER_IP):
        assert raw not in text


@pytest.mark.parametrize(
    ("over", "reason"),
    [
        ({"extra": 1}, REJECT_UNKNOWN_FIELD),
        ({"kind": "client_aggregate"}, REJECT_NOT_FLOW),
        ({"proto": "quic"}, REJECT_BAD_FIELD),
        ({"src": "not-an-ip"}, REJECT_BAD_FIELD),
        ({"dst_port": 70000}, REJECT_BAD_FIELD),
        ({"bytes": -1}, REJECT_BAD_FIELD),
        ({"bytes": True}, REJECT_BAD_FIELD),
        ({"vlan_id": 0}, REJECT_BAD_FIELD),
        ({"router_id": "router1"}, REJECT_BAD_FIELD),
        ({"direction": "sideways"}, REJECT_BAD_FIELD),
        ({"observation": "guessed"}, REJECT_BAD_FIELD),
        ({"window": {"start": NOW, "end": NOW + 301}}, REJECT_FUTURE),
        ({"window": {"start": NOW - 90_000, "end": NOW - 86_500}}, REJECT_TOO_OLD),
        ({"window": {"start": NOW - 4000, "end": NOW}}, REJECT_SPAN),
        ({"window": {"start": NOW, "end": NOW - 1}}, REJECT_BAD_FIELD),
        ({"client_mac": "x" * 65}, REJECT_BAD_FIELD),
    ],
)
def test_invalid_collector_records_are_rejected(
    over: dict[str, Any], reason: str
) -> None:
    with pytest.raises(FlowRejected) as err:
        normalise_collector_flow(flow(**over), now=NOW, module_key=KEY)
    assert err.value.reason == reason


def test_kinds_are_kept_apart() -> None:
    kinds = {
        "observed": FlowKind.OBSERVED,
        "aggregated": FlowKind.AGGREGATED,
        "estimated_category": FlowKind.ESTIMATED_CATEGORY,
        None: FlowKind.UNKNOWN,
    }
    for observation, kind in kinds.items():
        record = normalise_collector_flow(
            flow(observation=observation), now=NOW, module_key=KEY
        )
        assert record.kind is kind


def test_store_limits_drop_only_within_the_same_feed() -> None:
    store = FlowStore(max_total=6, max_per_feed=4)
    for i in range(6):
        store.add_collector([flow(src_port=40000 + i)], now=NOW + i, module_key=KEY)
    assert len(store) == 4  # feed of RID full: its own oldest fell
    assert store.counters["dropped_flows_feed_full"] == 2
    for i in range(3):
        store.add_collector([flow(router_id=RID2)], now=NOW + 10 + i, module_key=KEY)
    assert len(store) == 6
    assert store.counters["dropped_flows_store_full"] == 1  # never displaces RID
    rows = store.query(NOW + 20, module_key=KEY, router_id=RID).rows
    assert len(rows) == 4
    assert [r["src_port"] for r in rows] == [40005, 40004, 40003, 40002]


def test_retention_is_configurable_and_bounded() -> None:
    store = FlowStore()
    assert store.set_ttl(5, NOW) == 60.0
    assert store.set_ttl(10**9, NOW) == 86400.0
    assert store.set_ttl("x", NOW) == 3600.0
    store.set_ttl(120, NOW)
    store.add_collector([flow()], now=NOW, module_key=KEY)
    assert store.prune(NOW + 121) == 1 and len(store) == 0
    assert store.counters["expired_flows"] == 1


def test_only_anonymised_aggregates_are_offered_for_storage() -> None:
    store = FlowStore()
    store.add_collector(
        [flow(), flow(src_port=50001, bytes=800)], now=NOW, module_key=KEY
    )
    (agg,) = store.aggregates()
    assert agg["flows"] == 2 and agg["bytes"] == 2000
    assert agg["class"] == "https_tls" and agg["heuristic"] is True
    text = json.dumps(store.aggregates()) + json.dumps(store.summary())
    for raw in (MAC, CLIENT_IP, SERVER_IP, "ipa_"):
        assert raw not in text


def test_addresses_never_reach_the_log(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    store = FlowStore()
    store.add_collector([flow(), flow(src="bad"), "junk"], now=NOW, module_key=KEY)
    parse_conntrack(f"tcp 6 10 ESTABLISHED src={CLIENT_IP} dst=bad")
    for raw in (MAC, CLIENT_IP, SERVER_IP):
        assert raw not in caplog.text


# --- area 17: conntrack snapshot evaluation -------------------------------------------


NAT_LINE = (
    f"ipv4     2 tcp      6 431999 ESTABLISHED src={CLIENT_IP} dst={SERVER_IP} "
    f"sport=50000 dport=443 packets=10 bytes=1200 src={SERVER_IP} dst={WAN_IP} "
    "sport=443 dport=50000 packets=8 bytes=9000 [ASSURED] mark=0 zone=0 use=2"
)
PLAIN_LINE = (
    "udp      17 29 src=192.0.2.11 dst=192.0.2.1 sport=40000 dport=53 "
    "src=192.0.2.1 dst=192.0.2.11 sport=53 dport=40000 mark=0 use=1"
)
OFFLOAD_LINE = (
    "tcp      6 src=192.0.2.12 dst=198.51.100.7 sport=50001 dport=80 packets=3 "
    "bytes=300 src=198.51.100.7 dst=203.0.113.2 sport=80 dport=50001 packets=3 "
    "bytes=900 [OFFLOAD] mark=0 use=2"
)


def test_snapshot_lines_are_parsed_with_both_directions() -> None:
    snap = parse_conntrack(f"{NAT_LINE}\n{PLAIN_LINE}\ngarbage line\n")
    assert len(snap.entries) == 2 and snap.invalid_lines == 1
    nat, plain = snap.entries
    assert (nat.proto, nat.state, nat.orig.dport, nat.reply.bytes) == (
        "tcp",
        "ESTABLISHED",
        443,
        9000,
    )
    assert nat.nat_seen is True and plain.nat_seen is False
    assert plain.orig.bytes is None  # no accounting: unknown, not 0


def test_snapshot_is_not_a_history_and_nat_offload_lower_coverage() -> None:
    snap = parse_conntrack([NAT_LINE, PLAIN_LINE, OFFLOAD_LINE])
    refs = {CLIENT_IP: "cli_" + "a" * 16}
    ev = evaluate_snapshot(
        snap, router_id=RID, captured_at=NOW, client_ref_of_ip=refs.get
    )
    assert ev.complete_history is False
    assert ev.coverage is Coverage.PARTIAL
    assert set(ev.coverage_reasons) == {
        REASON_SNAPSHOT_NOT_HISTORY,
        REASON_NAT_SEEN,
        "hw_offload_on",
        REASON_ACCT_OFF,
    }
    assert (ev.nat_seen, ev.offloaded, ev.without_accounting) == (2, 1, 1)
    assert ev.unattributed == 2
    assert len(ev.records) == 6  # orig + reply per entry
    orig, reply = ev.records[0], ev.records[1]
    assert orig.direction is FlowDirection.ORIG and orig.bytes == 1200
    assert reply.direction is FlowDirection.REPLY and reply.bytes == 9000
    assert reply.src == CLIENT_IP  # original tuple: the client's view
    assert orig.client_ref == "cli_" + "a" * 16 and orig.nat_seen is True
    assert orig.start == orig.end == NOW


def test_connections_not_listed_are_unknown_never_absent() -> None:
    ev = evaluate_snapshot(parse_conntrack([NAT_LINE]), router_id=RID, captured_at=NOW)
    assert ev.connection_seen("tcp", CLIENT_IP, SERVER_IP, 50000, 443) is True
    assert ev.connection_seen("tcp", CLIENT_IP, SERVER_IP, 50001, 443) is None
    assert ev.connection_seen("tcp", "bad", SERVER_IP, 1, 2) is None
    assert ev.summary()["not_listed_means"] == "not_seen_is_unknown_not_absent"


def test_snapshot_is_bounded_and_marked_truncated() -> None:
    snap = parse_conntrack([PLAIN_LINE] * 10, max_entries=4)
    assert len(snap.entries) == 4 and snap.truncated
    ev = evaluate_snapshot(snap, router_id=RID, captured_at=NOW)
    assert REASON_SNAPSHOT_TRUNCATED in ev.coverage_reasons
    assert parse_conntrack(["tcp 6 " + "x" * 600]).invalid_lines == 1
    empty = evaluate_snapshot(parse_conntrack(""), router_id=RID, captured_at=NOW)
    assert empty.coverage is Coverage.UNKNOWN and empty.records == ()


def test_snapshot_records_go_to_their_own_feed() -> None:
    store = FlowStore(max_per_feed=4)
    store.add_collector([flow()], now=NOW, module_key=KEY)
    ev = evaluate_snapshot(
        parse_conntrack([PLAIN_LINE] * 5), router_id=RID, captured_at=NOW
    )
    assert store.add_snapshot(ev, now=NOW) == 10
    assert store.counters["dropped_flows_feed_full"] == 6
    rows = store.query(NOW, module_key=KEY).rows
    assert sum(r["snapshot"] for r in rows) == 4
    assert sum(not r["snapshot"] for r in rows) == 1  # collector feed untouched
    assert store.summary()["snapshots"] == 1


# --- protocol visibility (task §9) ----------------------------------------------------


@pytest.mark.parametrize(
    ("proto", "sport", "dport", "label"),
    [
        ("udp", 40000, 53, "dns"),
        ("udp", 123, 40000, "ntp"),  # reply direction
        ("tcp", 50000, 80, "http"),
        ("tcp", 50000, 443, "https_tls"),
        ("tcp", 50000, 1883, "mqtt"),
        ("tcp", 50000, 22, "ssh"),
        ("tcp", 50000, 554, "rtsp"),
        ("tcp", 50000, 50001, "unknown"),
        ("icmp", None, None, "icmp"),
        ("other", None, None, "unknown"),
    ],
)
def test_protocol_labels(proto: str, sport: Any, dport: Any, label: str) -> None:
    guess = classify(proto, sport, dport)
    assert guess.label == label
    assert guess.heuristic is True
    assert guess.accuracy in ("low", "medium", "none")


def test_port_is_no_proof_and_tls_is_never_an_application() -> None:
    https = classify("tcp", 50000, 443)
    assert https.accuracy == "low"
    assert NOTE_PORT_IS_NO_PROOF in https.notes
    assert NOTE_TLS_NOT_ATTRIBUTED in https.notes
    assert classify("tcp", 1, 22).accuracy == ACCURACY_MEDIUM
    unknown = classify("tcp", 40000, 40001)
    assert unknown.accuracy == ACCURACY_NONE and unknown.port is None
    assert classify(None, True, 99999).label == "unknown"
