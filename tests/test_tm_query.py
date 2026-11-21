"""Network Time Machine, Phase A: query, merge, rights and paging (tm_query).

Query checks and the merge rules on marks built by ``tm_sources.make_mark``;
paging end to end over the real Network Intelligence engine of the AK1
scenario (``test_tm_sources.ak1``). No router, no HA instance.
"""

from __future__ import annotations

from typing import Any

import pytest
from test_net_correlation import (
    T0,
    clock,  # noqa: F401 - fixture
    fleet,  # noqa: F401 - fixture
)
from test_tm_sources import NI_ROUTERS, ak1

from custom_components.openwrt_router import tm_query as tq
from custom_components.openwrt_router import tm_sources as src
from custom_components.openwrt_router.tm_query import Query, QueryError, parse_query
from custom_components.openwrt_router.tm_sources import RouterMap, SourceResult

NOW = 1_795_000_000.4
RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
ROUTERS = RouterMap({"e1": RID1}, {RID1: "Router e1"})


def mark(
    n: int,
    ts: float,
    *,
    source: str = "ni_events",
    kind: str = "router_down",
    severity: str = "info",
    router_id: str | None = RID1,
) -> dict[str, Any]:
    return src.make_mark(
        source=source,
        source_id=str(n),
        ts=ts,
        kind=kind,
        severity=severity,
        router_id=router_id,
        routers=ROUTERS,
        fleet=router_id is None,
        code="x",
        ref=src.ref_of("network_intelligence", "event"),
    )


def result(source: str, marks: list[dict[str, Any]], **kw: Any) -> SourceResult:
    marks = sorted(marks, key=lambda m: (-m["ts"], m["id"]))
    return SourceResult(
        source,
        kw.pop("state", src.STATE_OK if marks else src.STATE_EMPTY),
        kw.pop("reason", None),
        marks,
        kw.pop("omitted", 0),
        kw.pop("truncated", False),
        marks[-1]["ts"] if marks else None,
    )


def q(**kw: Any) -> Query:
    return Query(kw.pop("since", NOW - 86_400), kw.pop("until", NOW + 1), **kw)


# --- query ------------------------------------------------------------------------------


def test_defaults_are_24_hours_up_to_now_and_every_source() -> None:
    query = parse_query({}, NOW)
    assert query.until == 1_795_000_001.0
    assert query.until - query.since == 86_400
    assert query.sources == src.ALL_SOURCE_IDS
    assert (query.router_id, query.kind, query.min_severity) == (None, None, None)
    assert query.limit == 200


def test_explicit_values_are_taken() -> None:
    query = parse_query(
        {
            "from": "1794900000",
            "until": "1794990000.5",
            "source": "security_timeline,core_audit",
            "router_id": RID1,
            "kind": "config_drift",
            "min_severity": "warning",
            "limit": "500",
        },
        NOW,
    )
    assert (query.since, query.until) == (1_794_900_000.0, 1_794_990_000.5)
    assert query.sources == ("core_audit", "security_timeline")  # fixed order
    assert (query.router_id, query.kind, query.min_severity, query.limit) == (
        RID1,
        "config_drift",
        "warning",
        500,
    )
    only_until = parse_query({"until": "1794990000"}, NOW)
    assert only_until.since == 1_794_990_000 - 86_400


@pytest.mark.parametrize(
    ("query", "field", "reason"),
    [
        ({"from": "yesterday"}, "from", "invalid"),
        ({"from": "-5"}, "from", "invalid"),
        ({"until": "1e9"}, "until", "invalid"),
        ({"until": "9999999999"}, "until", "out_of_range"),
        ({"from": str(NOW + 10)}, "window", "empty"),
        ({"from": "100", "until": "100"}, "window", "empty"),
        ({"from": str(NOW - 15 * 86_400)}, "window", "too_large"),
        ({"source": "core_audit,recorder"}, "source", "unknown"),
        ({"source": ""}, "source", "unknown"),
        ({"source": "ni_events,ni_events"}, "source", "repeated"),
        ({"router_id": "rtr_XYZ"}, "router_id", "invalid"),
        ({"router_id": "e1"}, "router_id", "invalid"),
        ({"kind": "client_secret"}, "kind", "unknown"),
        ({"min_severity": "high"}, "min_severity", "unknown"),
        ({"limit": "0"}, "limit", "out_of_range"),
        ({"limit": "501"}, "limit", "out_of_range"),
        ({"limit": "ten"}, "limit", "out_of_range"),
        ({"mac": "02:00:5e:10:00:01"}, "query", "unknown_key"),
        ({"kind": "x" * 97}, "kind", "too_long"),
    ],
)
def test_bad_queries_name_field_and_reason_only(
    query: dict[str, str], field: str, reason: str
) -> None:
    with pytest.raises(QueryError) as err:
        parse_query(query, NOW)
    assert (err.value.field, err.value.reason) == (field, reason)
    for value in query.values():
        if len(value) > 3:
            assert value not in str(err.value)


def test_every_kind_and_severity_is_accepted() -> None:
    for kind in src.KINDS:
        assert parse_query({"kind": kind}, NOW).kind == kind
    for severity in src.SEVERITIES:
        assert parse_query({"min_severity": severity}, NOW).min_severity == severity


# --- merge ------------------------------------------------------------------------------


def test_merge_sorts_newest_first_and_counts_per_source() -> None:
    a = result("ni_events", [mark(1, NOW - 50), mark(2, NOW - 10)], omitted=2)
    b = result(
        "ni_incidents",
        [mark(3, NOW - 30, source="ni_incidents", kind="incident_opened")],
        omitted=1,
    )
    body = tq.merge([a, b], q(), admin=True, now=NOW)
    assert [m["ts"] for m in body["marks"]] == [NOW - 10, NOW - 30, NOW - 50]
    assert body["status"] == "ok" and body["v"] == 1
    assert body["omitted_client_marks"] == 3
    assert body["truncated"] is False and body["next_until"] is None
    assert body["window"] == {"from": NOW - 86_400, "until": NOW + 1}
    assert [(s["id"], s["state"], s["count"]) for s in body["sources"]] == [
        ("ni_events", "ok", 2),
        ("ni_incidents", "ok", 1),
    ]
    assert set(body) == {
        "v",
        "status",
        "generated_at",
        "window",
        "marks",
        "sources",
        "omitted_client_marks",
        "truncated",
        "next_until",
    }


def test_only_administrators_get_the_count_of_left_out_client_entries() -> None:
    """1.50.0: a non-admin gets 0, also when client entries were left out."""
    a = result("ni_events", [mark(1, NOW - 50)], omitted=2)
    b = result("ni_incidents", [], omitted=1)
    admin = tq.merge([a, b], q(), admin=True, now=NOW)
    plain = tq.merge([a, b], q(), admin=False, now=NOW)
    assert admin["omitted_client_marks"] == 3
    assert plain["omitted_client_marks"] == 0
    assert set(plain) == set(admin)


def test_ties_are_ordered_by_mark_id() -> None:
    marks = [mark(n, NOW - 5) for n in range(6)]
    body = tq.merge([result("ni_events", marks)], q(), admin=True, now=NOW)
    ids = [m["id"] for m in body["marks"]]
    assert ids == sorted(ids)


def test_non_admins_see_infrastructure_and_disruptions_only() -> None:
    kinds = ("router_down", "rf_event", "uplink_changed", "incident_opened")
    hidden = ("config_version", "config_drift", "security_event", "core_event")
    marks = [mark(n, NOW - n, kind=k) for n, k in enumerate(kinds + hidden)]
    admin = tq.merge([result("ni_events", marks)], q(), admin=True, now=NOW)
    plain = tq.merge([result("ni_events", marks)], q(), admin=False, now=NOW)
    assert {m["kind"] for m in admin["marks"]} == set(kinds + hidden)
    assert {m["kind"] for m in plain["marks"]} == set(kinds)


def test_filters_router_kind_and_severity() -> None:
    marks = [
        mark(1, NOW - 1, severity="critical"),
        mark(2, NOW - 2, severity="warning", router_id=RID2),
        mark(3, NOW - 3, severity="info", kind="wan_event"),
        mark(4, NOW - 4, severity="warning", router_id=None),
    ]
    res = [result("ni_events", marks)]

    def ids(**kw: Any) -> list[str]:
        body = tq.merge(res, q(**kw), admin=True, now=NOW)
        return [m["id"] for m in body["marks"]]

    by_id = {m["ts"]: m["id"] for m in marks}
    assert ids(router_id=RID1) == [by_id[NOW - 1], by_id[NOW - 3]]
    assert ids(kind="wan_event") == [by_id[NOW - 3]]
    assert ids(min_severity="warning") == [
        by_id[NOW - 1],
        by_id[NOW - 2],
        by_id[NOW - 4],
    ]
    assert ids(min_severity="critical") == [by_id[NOW - 1]]


def test_a_page_never_splits_one_second() -> None:
    marks = [mark(1, NOW - 1), mark(2, NOW - 2), mark(3, NOW - 3), mark(4, NOW - 3)]
    body = tq.merge([result("ni_events", marks)], q(limit=3), admin=True, now=NOW)
    assert [m["ts"] for m in body["marks"]] == [NOW - 1, NOW - 2]
    assert body["next_until"] == NOW - 2 and body["truncated"] is True
    rest = [m for m in marks if m["ts"] < body["next_until"]]
    second = tq.merge(
        [result("ni_events", rest)],
        q(until=body["next_until"], limit=3),
        admin=True,
        now=NOW,
    )
    assert [m["ts"] for m in second["marks"]] == [NOW - 3, NOW - 3]
    assert second["next_until"] is None and second["truncated"] is False


def test_one_second_larger_than_the_page_is_cut_and_flagged() -> None:
    marks = [mark(n, NOW - 1) for n in range(5)]
    body = tq.merge([result("ni_events", marks)], q(limit=3), admin=True, now=NOW)
    assert len(body["marks"]) == 3
    assert body["truncated"] is True and body["next_until"] == NOW - 1


def test_a_cut_source_bounds_the_page() -> None:
    audit = result(
        "core_audit",
        [mark(1, NOW - 100, source="core_audit", kind="config_event")],
        truncated=True,
    )
    events = result("ni_events", [mark(2, NOW - 50), mark(3, NOW - 500)])
    body = tq.merge([audit, events], q(), admin=True, now=NOW)
    # the edge's millisecond goes whole to the next page (review K4)
    assert [m["ts"] for m in body["marks"]] == [NOW - 50]
    assert body["next_until"] == src.ms_next(NOW - 100)
    assert body["truncated"] is True
    by_source = {s["id"]: s for s in body["sources"]}
    assert by_source["core_audit"]["truncated"] is True
    assert by_source["core_audit"]["cut"] == "next_page"
    assert by_source["core_audit"]["state"] == "ok"  # cut, not quiet
    assert by_source["ni_events"]["count"] == 1


def test_an_unreadable_source_makes_the_answer_partial() -> None:
    bad = SourceResult("security_timeline", src.STATE_UNREADABLE, src.REASON_TIMEOUT)
    good = result("ni_events", [mark(1, NOW - 1)])
    body = tq.merge([good, bad], q(), admin=True, now=NOW)
    assert body["status"] == "partial"
    assert len(body["marks"]) == 1
    assert body["sources"][1] == {
        "id": "security_timeline",
        "state": "unreadable",
        "reason": "timeout",
        "count": 0,
        "oldest": None,
        "truncated": False,
        "cut": None,
        "duplicates": 0,
    }


def test_off_body_has_the_same_keys_and_nothing_in_them() -> None:
    off = tq.off_body(NOW)
    on = tq.merge([], q(), admin=True, now=NOW)
    assert set(off) == set(on)
    assert off["status"] == "off" and off["marks"] == [] and off["sources"] == []
    assert off["window"] == {"from": None, "until": None}


# --- paging over the real engine --------------------------------------------------------


async def test_paging_walks_the_whole_window_without_gaps_or_doubles(
    fleet,  # noqa: F811
) -> None:
    intel = ak1(fleet)
    hass = intel.hass
    full_query = Query(T0 - 10, T0 + 700, ("ni_events", "ni_incidents"))
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(tq, "build_router_map", lambda _hass: NI_ROUTERS)
        full = await tq.async_timeline(hass, full_query, admin=True, now=T0 + 700)
        assert full["next_until"] is None and len(full["marks"]) >= 5
        seen: list[str] = []
        until = T0 + 700
        for _ in range(20):
            page = await tq.async_timeline(
                hass,
                # three marks share one second in AK1: a page of 3 holds them
                Query(T0 - 10, until, ("ni_events", "ni_incidents"), limit=3),
                admin=True,
                now=T0 + 700,
            )
            assert page["marks"], "a page with next_until is never empty"
            seen += [m["id"] for m in page["marks"]]
            if page["next_until"] is None:
                break
            until = page["next_until"]
    assert seen == [m["id"] for m in full["marks"]]
