"""P7: network intelligence API routes of the topology panel.

Access like the snapshot (403 for non-admins unless the panel is open to
all users, 410 after the last unload), writing routes admin only (also when
the panel is open to all), 404 for an unknown incident, 400 for bad filters,
limits and settings (bounds of ``merge_settings``), 503 without a loaded
engine. Filters, limits and the cursor of the timeline; the derived
``cause_level``; the warning symbols in the snapshot. Router names are
roles, MACs locally administered test values.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.components.http import KEY_HASS_USER
from homeassistant.helpers.http import KEY_HASS
from test_net_correlation import Clock, level
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_p6 import reconnects

from custom_components.openwrt_router import net_engine, topology_panel
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    EventRing,
    IncidentStatus,
    NetEvent,
    Severity,
)
from custom_components.openwrt_router.net_query import router_badges
from custom_components.openwrt_router.net_rules import (
    DEFAULT_SETTINGS,
    SETTINGS_LIST_MAX,
    WIFI_RECONNECT_KIND,
    AlarmMachine,
    CauseLevel,
    cause_level,
    settings_errors,
)
from custom_components.openwrt_router.topology_mesh import _intelligence
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
    OpenWrtIntelEventsView,
    OpenWrtIntelIncidentsView,
    OpenWrtIntelIncidentView,
    OpenWrtIntelSettingsView,
    OpenWrtIntelSummaryView,
    _api_views,
)

T0 = 1_763_280_000.0
G, A = "gw", "ap1"
MAC = "02:00:5E:10:00:01"
MAC2 = "02:00:5E:10:00:02"


class Req(dict):
    """aiohttp-like request: user, app, query and a JSON body."""

    def __init__(
        self,
        hass: Any,
        *,
        admin: bool = True,
        query: dict[str, str] | None = None,
        body: Any = None,
        bad_json: bool = False,
    ) -> None:
        super().__init__()
        self.app = {KEY_HASS: hass}
        self[KEY_HASS_USER] = SimpleNamespace(is_admin=admin)
        self.query = query or {}
        self._body = body
        self._bad_json = bad_json

    async def json(self) -> Any:
        if self._bad_json:
            raise json.JSONDecodeError("bad", "x", 0)
        return self._body


def body(response: Any) -> Any:
    return json.loads(response.body)


@pytest.fixture
async def intel() -> NetIntelligence:
    clock = Clock()
    disk = FakeDisk()
    with (
        patch.object(net_engine, "time", clock),
        patch.object(topology_panel, "time", clock),
        patch.object(net_engine, "async_call_later", lambda *a: lambda: None),
        patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)),
    ):
        engine = NetIntelligence(make_hass())
        await engine.async_load()
        engine.hass.config_entries.async_get_entry.side_effect = lambda i: (
            SimpleNamespace(title={G: "Gateway", A: "AP Flur"}.get(i))
        )
        for router in (G, A):
            engine.register(router)
        # stored events: 5 reconnects of MAC on the AP, one of MAC2, a
        # system event on the gateway; the reconnects are the evidence
        for i in range(5):
            engine.ring.add(
                NetEvent(
                    id=f"{A}:{i}",
                    ts=T0 + i,
                    router=A,
                    category=Category.WIFI,
                    kind=WIFI_RECONNECT_KIND,
                    subject={"mac": MAC},
                    severity=Severity.WARNING,
                )
            )
        engine.ring.add(
            NetEvent(
                id=f"{A}:9",
                ts=T0 + 9,
                router=A,
                category=Category.WIFI,
                kind=WIFI_RECONNECT_KIND,
                subject={"mac": MAC2},
            )
        )
        engine.ring.add(
            NetEvent(
                id=f"{G}:1",
                ts=T0 + 10,
                router=G,
                category=Category.SYSTEM,
                kind="system.reboot",
                severity=Severity.CRITICAL,
            )
        )
        clock.now = T0 + 20
        engine._run_machine(T0 + 20, [*reconnects(5), level("wan_down", G)])
        engine.hass.data[net_engine._DATA_KEY] = engine
        yield engine


def incident(engine: NetIntelligence, type_: str) -> Any:
    return next(i for i in engine.machine.incidents() if i.type == type_)


# --- access -----------------------------------------------------------------


def _get_views() -> list[tuple[Any, dict[str, Any]]]:
    return [
        (OpenWrtIntelSummaryView(), {}),
        (OpenWrtIntelEventsView(), {}),
        (OpenWrtIntelIncidentsView(), {}),
        (OpenWrtIntelIncidentView(), {"incident_id": "x"}),
        (OpenWrtIntelSettingsView(), {}),
    ]


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_are_admin_only_by_default(
    intel: NetIntelligence, view: Any, kwargs: dict[str, Any]
) -> None:
    response = await view.get(Req(intel.hass, admin=False), **kwargs)
    assert response.status == 403


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_follow_the_all_users_option(
    intel: NetIntelligence, view: Any, kwargs: dict[str, Any]
) -> None:
    intel.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    if kwargs:
        kwargs = {"incident_id": incident(intel, "wan_down").id}
    response = await view.get(Req(intel.hass, admin=False), **kwargs)
    assert response.status == 200


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_gone_after_last_unload(
    intel: NetIntelligence, view: Any, kwargs: dict[str, Any]
) -> None:
    intel.hass.data[_PANEL_VIEW_DISABLED_KEY] = True
    response = await view.get(Req(intel.hass), **kwargs)
    assert response.status == 410


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_routes_without_engine_answer_503(
    intel: NetIntelligence, view: Any, kwargs: dict[str, Any]
) -> None:
    del intel.hass.data[net_engine._DATA_KEY]
    response = await view.get(Req(intel.hass), **kwargs)
    assert response.status == 503


async def test_post_routes_are_admin_only_even_when_open_to_all(
    intel: NetIntelligence,
) -> None:
    intel.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    wan = incident(intel, "wan_down")
    response = await OpenWrtIntelIncidentView().post(
        Req(intel.hass, admin=False, body={"status": "acknowledged"}), wan.id
    )
    assert response.status == 403
    assert incident(intel, "wan_down").status is IncidentStatus.ACTIVE
    before = json.dumps(intel.settings, sort_keys=True)
    response = await OpenWrtIntelSettingsView().post(
        Req(intel.hass, admin=False, body={"retention_days": 7})
    )
    assert response.status == 403
    assert json.dumps(intel.settings, sort_keys=True) == before


def test_views_have_unique_names_under_the_panel_api() -> None:
    views = _api_views()
    # 6 network intelligence views + 4 client stability views (B5)
    assert len({v.name for v in views}) == len(views) == 10
    assert all(v.url.startswith("/api/openwrt_topology/") for v in views)
    assert all(v.requires_auth for v in views)


# --- summary -------------------------------------------------------------------


async def test_summary_scores_incidents_and_counts(intel: NetIntelligence) -> None:
    data = body(await OpenWrtIntelSummaryView().get(Req(intel.hass)))
    assert data["loaded"] is True
    assert {r["id"]: r["name"] for r in data["routers"]} == {
        A: "AP Flur",
        G: "Gateway",
    }
    assert data["incidents"]["critical"] == 1  # wan_down
    assert data["incidents_open_total"] == 2
    gw = next(r for r in data["routers"] if r["id"] == G)
    assert gw["incidents"]["critical"] == 1
    assert data["events_24h"]["wifi"] == 6
    top = data["wifi"]["top_clients"]
    assert top[0]["mac"] == MAC
    assert top[0]["reconnects"] == 5
    assert top[0]["router_name"] == "AP Flur"
    assert "fleet" in data and "maintenance_until" in data["fleet"]


# --- events --------------------------------------------------------------------


async def events(intel: NetIntelligence, **query: str) -> Any:
    return await OpenWrtIntelEventsView().get(Req(intel.hass, query=query))


async def test_events_newest_first_with_filters(intel: NetIntelligence) -> None:
    data = body(await events(intel))
    assert [e["id"] for e in data["events"]][:2] == [f"{G}:1", f"{A}:9"]
    assert data["events"][0]["router_name"] == "Gateway"
    assert body(await events(intel, router=G))["events"][0]["kind"] == "system.reboot"
    assert len(body(await events(intel, category="wifi"))["events"]) == 6
    assert len(body(await events(intel, severity="warning"))["events"]) == 5
    assert len(body(await events(intel, mac=MAC2.lower()))["events"]) == 1
    window = body(await events(intel, since=str(T0 + 1), until=str(T0 + 3)))
    assert [e["id"] for e in window["events"]] == [f"{A}:2", f"{A}:1"]
    assert body(await events(intel, kind="nope"))["events"] == []


async def test_events_cursor_pages_without_overlap(intel: NetIntelligence) -> None:
    first = body(await events(intel, limit="3"))
    assert len(first["events"]) == 3
    assert first["next_before"] == first["events"][-1]["id"]
    second = body(await events(intel, limit="3", before=first["next_before"]))
    third = body(await events(intel, limit="3", before=second["next_before"]))
    ids = [e["id"] for e in first["events"] + second["events"] + third["events"]]
    assert len(ids) == len(set(ids)) == 7
    assert third["next_before"] is None
    gone = body(await events(intel, before="no-longer-stored"))
    assert gone == {"events": [], "next_before": None, "limit": 100}


@pytest.mark.parametrize(
    "query",
    [
        {"limit": "501"},
        {"limit": "0"},
        {"limit": "ten"},
        {"category": "weather"},
        {"severity": "loud"},
        {"since": "yesterday"},
        {"since": "nan"},
        {"since": "10", "until": "5"},
        {"router": "x" * 200},
    ],
)
async def test_events_reject_bad_filters(
    intel: NetIntelligence, query: dict[str, str]
) -> None:
    response = await events(intel, **query)
    assert response.status == 400


async def test_events_limit_upper_bound_is_accepted(intel: NetIntelligence) -> None:
    assert (await events(intel, limit="500")).status == 200


# --- incidents -----------------------------------------------------------------


async def incidents(intel: NetIntelligence, **query: str) -> Any:
    return await OpenWrtIntelIncidentsView().get(Req(intel.hass, query=query))


async def test_incident_list_order_filters_and_fields(intel: NetIntelligence) -> None:
    data = body(await incidents(intel))
    assert data["total"] == 2
    first = data["incidents"][0]
    assert first["type"] == "wan_down"  # active and critical first
    assert first["router_names"] == ["Gateway"]
    assert first["cause_level"] in {lv.value for lv in CauseLevel}
    assert first["evidence_count"] >= 1
    assert "evidence" not in first
    assert first["duration_s"] >= 0
    assert first["child"] is False
    assert body(await incidents(intel, router=A))["incidents"][0]["type"] == (
        "wifi_reconnect_storm"
    )
    assert body(await incidents(intel, severity="critical"))["total"] == 1
    assert body(await incidents(intel, status="resolved"))["total"] == 0
    assert body(await incidents(intel, status="active,resolved"))["total"] == 2
    assert body(await incidents(intel, limit="1"))["incidents"][0]["type"] == (
        "wan_down"
    )


@pytest.mark.parametrize(
    "query",
    [{"limit": "201"}, {"status": "open"}, {"severity": "major"}],
)
async def test_incident_list_rejects_bad_filters(
    intel: NetIntelligence, query: dict[str, str]
) -> None:
    assert (await incidents(intel, **query)).status == 400


async def test_incident_detail_evidence_children_chain(intel: NetIntelligence) -> None:
    storm = incident(intel, "wifi_reconnect_storm")
    wan = incident(intel, "wan_down")
    # make the storm a child of the WAN outage and link a follow-up event
    intel.machine._incidents[storm.id].parent_id = wan.id
    intel.ring.set_parents({f"{A}:9": wan.id})
    view = OpenWrtIntelIncidentView()
    data = body(await view.get(Req(intel.hass), wan.id))
    assert data["incident"]["id"] == wan.id
    assert [c["id"] for c in data["children"]] == [storm.id]
    assert data["children"][0]["child"] is True
    assert [e["id"] for e in data["chain"]] == [f"{A}:9"]
    assert data["chain"][0]["role"] == "follow_up"
    child = body(await view.get(Req(intel.hass), storm.id))
    assert child["parent"]["id"] == wan.id
    joined = [e for e in child["incident"]["evidence"] if e["event"]]
    assert {e["event"]["id"] for e in joined} == {f"{A}:{i}" for i in range(5)}
    assert all(e["role"] == "evidence" for e in child["chain"])
    # a child does not count: no badge, the root's list entry marks it
    assert router_badges(intel.machine.peek()).get(A) is None


async def test_incident_detail_unknown_is_404(intel: NetIntelligence) -> None:
    response = await OpenWrtIntelIncidentView().get(Req(intel.hass), "nope")
    assert response.status == 404


# --- incident status (POST) -------------------------------------------------------


async def post_status(intel: NetIntelligence, inc_id: str, payload: Any) -> Any:
    return await OpenWrtIntelIncidentView().post(Req(intel.hass, body=payload), inc_id)


async def test_acknowledge_ignore_and_reactivate(intel: NetIntelligence) -> None:
    wan = incident(intel, "wan_down")
    response = await post_status(intel, wan.id, {"status": "acknowledged"})
    assert response.status == 200
    assert body(response)["incident"]["status"] == "acknowledged"
    assert intel._save_pending
    again = await post_status(intel, wan.id, {"status": "acknowledged"})
    assert again.status == 409
    back = await post_status(intel, wan.id, {"status": "active"})
    assert body(back)["incident"]["status"] == "active"
    ignored = await post_status(intel, wan.id, {"status": "ignored", "ignore_days": 2})
    data = body(ignored)["incident"]
    assert data["status"] == "ignored"
    assert data["ignore_until"] == intel.machine.last_now + 2 * 86400
    # wan_down still measured (track live): back to active, not resolved
    back = await post_status(intel, wan.id, {"status": "active"})
    assert body(back)["incident"]["status"] == "active"
    assert body(back)["incident"]["ignore_until"] is None


async def test_status_unknown_incident_is_404(intel: NetIntelligence) -> None:
    response = await post_status(intel, "nope", {"status": "acknowledged"})
    assert response.status == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"status": "resolved"},
        {"status": "acknowledged", "ignore_days": 1},
        {"status": "ignored", "ignore_days": 0},
        {"status": "ignored", "ignore_days": 366},
        {"status": "ignored", "ignore_days": True},
        {"status": "ignored", "extra": 1},
        ["acknowledged"],
    ],
)
async def test_status_rejects_bad_bodies(intel: NetIntelligence, payload: Any) -> None:
    wan = incident(intel, "wan_down")
    response = await post_status(intel, wan.id, payload)
    assert response.status == 400
    assert incident(intel, "wan_down").status is IncidentStatus.ACTIVE


async def test_status_rejects_non_json(intel: NetIntelligence) -> None:
    wan = incident(intel, "wan_down")
    response = await OpenWrtIntelIncidentView().post(
        Req(intel.hass, bad_json=True), wan.id
    )
    assert response.status == 400


def test_reactivate_resolves_an_ignored_incident_without_live_track() -> None:
    machine = AlarmMachine()
    machine.update(T0, [level("wan_down", G)])
    inc = machine.incidents()[0]
    assert machine.ignore(inc.id, T0)
    machine._tracks.clear()
    assert machine.reactivate(inc.id, T0 + 5)
    assert machine.get(inc.id).status is IncidentStatus.RESOLVED
    assert machine.get(inc.id).resolved_at == T0 + 5
    assert not machine.reactivate(inc.id, T0 + 6)  # resolved: nothing to undo
    assert not machine.reactivate("nope", T0)


# --- settings ------------------------------------------------------------------


async def test_settings_get_shows_defaults_routers_and_rights(
    intel: NetIntelligence,
) -> None:
    intel.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    data = body(await OpenWrtIntelSettingsView().get(Req(intel.hass, admin=False)))
    assert data["can_edit"] is False
    assert data["settings"]["retention_days"] == 30
    assert (
        data["defaults"]["thresholds"].keys() == DEFAULT_SETTINGS["thresholds"].keys()
    )
    assert {r["id"]: r["name"] for r in data["routers"]} == {
        A: "AP Flur",
        G: "Gateway",
    }
    admin = body(await OpenWrtIntelSettingsView().get(Req(intel.hass)))
    assert admin["can_edit"] is True


async def test_settings_post_applies_a_partial_change(intel: NetIntelligence) -> None:
    patch_ = {
        "max_events": 4,
        "thresholds": {"wifi_reconnect_storm": {"count": 8, "severity": "critical"}},
        "exclusions": {"macs": [MAC2.lower()], "routers": [A]},
        "maintenance": {"fleet_until": T0 + 3600},
    }
    response = await OpenWrtIntelSettingsView().post(Req(intel.hass, body=patch_))
    assert response.status == 200
    data = body(response)
    rule = data["settings"]["thresholds"]["wifi_reconnect_storm"]
    assert rule["count"] == 8
    assert rule["severity"] == "critical"
    assert rule["window"] == 600  # untouched keys keep their value
    assert data["settings"]["exclusions"]["routers"] == [A]
    assert intel.machine._settings["thresholds"]["wifi_reconnect_storm"]["count"] == 8
    assert intel.ring.max_count == 4
    assert len(intel.ring) == 4  # newest kept
    assert intel._save_pending
    # the fleet maintenance window applies at once (view refreshed)
    assert intel.view.fleet.maintenance == 2
    assert intel.in_maintenance(G)


@pytest.mark.parametrize(
    ("payload", "error"),
    [
        ({"retention_days": 400}, "retention_days"),
        ({"max_events": 0}, "max_events"),
        ({"schema": 2}, "schema: cannot be changed"),
        ({"surprise": 1}, "surprise: unknown key"),
        ({"thresholds": {"wifi_reconnect_storm": {"count": 2.5}}}, "count"),
        ({"thresholds": {"wifi_reconnect_storm": {"mode": "level"}}}, "mode"),
        ({"thresholds": {"wan_down": {"severity": "fatal"}}}, "severity"),
        ({"thresholds": {"no_such_rule": {}}}, "unknown key"),
        ({"score": {"min_coverage": 1.5}}, "min_coverage"),
        ({"exclusions": {"macs": ["not-a-mac"]}}, "not a MAC"),
        ({"exclusions": {"ssids": ["x"] * (SETTINGS_LIST_MAX + 1)}}, "list"),
        ({"exclusions": {"routers": "gw"}}, "list"),
        ({"maintenance": {"fleet_until": "tomorrow"}}, "fleet_until"),
        ({"notify_min_severity": None}, "notify_min_severity"),
        ([], "object expected"),
    ],
)
async def test_settings_post_rejects_invalid_values(
    intel: NetIntelligence, payload: Any, error: str
) -> None:
    before = json.dumps(intel.settings, sort_keys=True)
    response = await OpenWrtIntelSettingsView().post(Req(intel.hass, body=payload))
    assert response.status == 400
    assert any(error in e for e in body(response)["errors"])
    assert json.dumps(intel.settings, sort_keys=True) == before
    assert intel.ring.max_count == 3000


async def test_settings_post_rejects_non_json(intel: NetIntelligence) -> None:
    response = await OpenWrtIntelSettingsView().post(Req(intel.hass, bad_json=True))
    assert response.status == 400


async def test_recursion_error_in_the_parser_is_400(
    intel: NetIntelligence, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deeply nested JSON on every interpreter: the parser's RecursionError
    (raised here on purpose, Python 3.14's parser does not) is a bad body."""

    async def too_deep(_self: Any) -> Any:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(Req, "json", too_deep)
    before = json.dumps(intel.settings, sort_keys=True)
    response = await OpenWrtIntelSettingsView().post(Req(intel.hass))
    assert response.status == 400
    assert json.dumps(intel.settings, sort_keys=True) == before
    wan = incident(intel, "wan_down")
    response = await OpenWrtIntelIncidentView().post(Req(intel.hass), wan.id)
    assert response.status == 400
    assert incident(intel, "wan_down").status is IncidentStatus.ACTIVE


def test_settings_errors_accept_the_full_defaults() -> None:
    """The panel may send back the whole object it read (fixed keys equal)."""
    assert settings_errors(DEFAULT_SETTINGS) == []
    assert settings_errors({"maintenance": {"fleet_until": None}}) == []


# --- cause level, badges, ring -----------------------------------------------------


@pytest.mark.parametrize(
    ("status", "confidence", "expected"),
    [
        (CauseStatus.CONFIRMED, 0.2, CauseLevel.CONFIRMED),
        (CauseStatus.HYPOTHESIS, 0.9, CauseLevel.LIKELY),
        (CauseStatus.HYPOTHESIS, 0.7, CauseLevel.LIKELY),
        (CauseStatus.HYPOTHESIS, 0.6, CauseLevel.POSSIBLE),  # inferred edge cap
        (CauseStatus.HYPOTHESIS, 0.4, CauseLevel.POSSIBLE),
        (CauseStatus.HYPOTHESIS, 0.3, CauseLevel.UNKNOWN),
        (None, 1.0, CauseLevel.UNKNOWN),
    ],
)
def test_cause_level_mapping(
    status: CauseStatus | None, confidence: float, expected: CauseLevel
) -> None:
    """The P7 thresholds, now with two independent source families (RT6;
    one family alone is at most possible: tests/test_net_cause_level.py)."""
    families = frozenset({"log", "poll"})
    assert cause_level("weak_signal", status, confidence, families) is expected


async def test_snapshot_badges_and_fleet_meta(intel: NetIntelligence) -> None:
    badges, meta = _intelligence(intel.hass)
    assert badges[G] == {"critical": 1, "warning": 0, "info": 0}
    assert sum(badges[A].values()) == 1
    assert meta == {
        "fleet_score": intel.view.fleet.score,
        "coverage": intel.view.fleet.coverage,
    }
    # ignored incidents carry no symbol
    wan = incident(intel, "wan_down")
    intel.set_incident_status(wan.id, "ignored")
    badges, _meta = _intelligence(intel.hass)
    assert G not in badges


def test_snapshot_without_engine_has_no_intelligence() -> None:
    assert _intelligence(make_hass()) == ({}, None)


def test_ring_resize_keeps_the_newest() -> None:
    ring = EventRing(max_count=5)
    for i in range(5):
        ring.add(
            NetEvent(id=str(i), ts=T0 + i, router=G, category=Category.WAN, kind="k")
        )
    assert ring.resize(2, 3600) == 3
    assert [e.id for e in ring] == ["3", "4"]
    ring.add(NetEvent(id="5", ts=T0 + 5, router=G, category=Category.WAN, kind="k"))
    assert [e.id for e in ring] == ["4", "5"]
    assert ring.max_age == 3600


async def test_ak5_panel_routes_show_the_store_after_a_restart(
    intel: NetIntelligence,
) -> None:
    """AK5: incidents and stored events come back through the panel routes."""
    before_inc = body(await OpenWrtIntelIncidentsView().get(Req(intel.hass)))
    before_ev = body(await OpenWrtIntelEventsView().get(Req(intel.hass)))
    disk = FakeDisk()
    disk.data = json.loads(json.dumps(intel._payload()))
    clock = Clock()
    clock.now = T0 + 20
    with (
        patch.object(net_engine, "time", clock),
        patch.object(topology_panel, "time", clock),
        patch.object(net_engine, "async_call_later", lambda *a: lambda: None),
        patch.object(net_engine, "Store", lambda *a, **kw: FakeStore(disk, *a, **kw)),
    ):
        restarted = NetIntelligence(make_hass())
        await restarted.async_load()
        restarted.hass.config_entries.async_get_entry = (
            intel.hass.config_entries.async_get_entry
        )
        for router in (G, A):
            restarted.register(router)
        restarted.hass.data[net_engine._DATA_KEY] = restarted
        after_inc = body(await OpenWrtIntelIncidentsView().get(Req(restarted.hass)))
        after_ev = body(await OpenWrtIntelEventsView().get(Req(restarted.hass)))
    assert after_inc["total"] == before_inc["total"] > 0
    assert [i["id"] for i in after_inc["incidents"]] == [
        i["id"] for i in before_inc["incidents"]
    ]
    assert [e["id"] for e in after_ev["events"]] == [
        e["id"] for e in before_ev["events"]
    ]
    assert len(after_ev["events"]) == 7
