"""B5: client stability API routes of the topology panel (client_views.py).

Access like the NI P7 routes (403 for non-admins unless the panel is open
to all users, 410 after the last unload, POST admin only), 503 without a
loaded client stability engine, 400 for bad filters, limits, windows and
settings, 404 for an unknown client. The history is built through the
engine's public poll observer on top of a real ``NetIntelligence`` with the
in-memory store fakes. MACs are locally administered test values, IPs from
the documentation range.
"""

from __future__ import annotations

import logging
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
from test_client_engine import IFACES, client, finding, incident
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_net_panel_api import Req, body

from custom_components.openwrt_router import (
    client_engine,
    client_views,
    net_engine,
    topology_panel,
)
from custom_components.openwrt_router.client_engine import (
    ClientStability,
    async_get_client_stability,
)
from custom_components.openwrt_router.client_views import (
    SERIES_MAX,
    OpenWrtClientApsView,
    OpenWrtClientSettingsView,
    OpenWrtClientsView,
    OpenWrtClientView,
)
from custom_components.openwrt_router.net_engine import (
    PollFacts,
    async_get_net_intelligence,
)
from custom_components.openwrt_router.net_rules import wifi_context
from custom_components.openwrt_router.topology_panel import (
    _PANEL_ACCESS_KEY,
    _PANEL_VIEW_DISABLED_KEY,
    _api_views,
)

T0 = 1_800_000_000.0
STEP = 60.0
POLLS = 180  # 3 hours
M1 = "02:00:5E:10:00:01"  # phone on the gateway, 5 GHz, good signal
M2 = "02:00:5E:10:00:02"  # laptop on the AP, 2.4 GHz, weak signal
M3 = "02:00:5E:10:00:03"  # on the AP, leaves after 2 hours
UNKNOWN = "02:00:5E:10:00:99"
NAMES = {"r1": "Gateway", "r2": "AP Flur"}


def poll(router: str, now: float, *clients: dict[str, Any]) -> PollFacts:
    context = wifi_context(IFACES, list(clients))
    return PollFacts(
        router=router,
        now=now,
        interval=STEP,
        fresh_clients=True,
        context=context,
        log_ok=True,
        log_coverage=1.0,
    )


@pytest.fixture
async def cs() -> ClientStability:
    disks: dict[str, FakeDisk] = {}

    def store(*args: Any, **kw: Any) -> FakeStore:
        return FakeStore(disks.setdefault(args[2], FakeDisk()), *args, **kw)

    with (
        patch.object(net_engine, "Store", store),
        patch.object(client_engine, "Store", store),
        patch.object(net_engine, "async_call_later", lambda *a: lambda: None),
    ):
        hass = make_hass()
        hass.config_entries.async_get_entry.side_effect = lambda i: SimpleNamespace(
            title=NAMES.get(i)
        )
        engine = await async_get_net_intelligence(hass)
        for router in NAMES:
            engine.register(router)
        stability = await async_get_client_stability(hass, engine)
        now = T0
        for i in range(POLLS):
            now = T0 + i * STEP
            stability.on_poll(
                poll(
                    "r1",
                    now,
                    client(M1, signal=-55, hostname="phone", ip="192.0.2.10"),
                )
            )
            on_ap = [client(M2, radio="phy0-ap0", signal=-82, hostname="laptop")]
            if i < POLLS - 60:
                on_ap.append(client(M3, signal=-60))
            stability.on_poll(poll("r2", now, *on_ap))
        wall = SimpleNamespace(time=lambda: now)
        with patch.object(client_views, "time", wall):
            yield stability


# --- access -----------------------------------------------------------------------


def _get_views() -> list[tuple[Any, dict[str, Any]]]:
    return [
        (OpenWrtClientsView(), {}),
        (OpenWrtClientView(), {"mac": M1}),
        (OpenWrtClientApsView(), {}),
        (OpenWrtClientSettingsView(), {}),
    ]


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_are_admin_only_by_default(
    cs: ClientStability, view: Any, kwargs: dict[str, Any]
) -> None:
    response = await view.get(Req(cs.hass, admin=False), **kwargs)
    assert response.status == 403


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_follow_the_all_users_option(
    cs: ClientStability, view: Any, kwargs: dict[str, Any]
) -> None:
    cs.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    response = await view.get(Req(cs.hass, admin=False), **kwargs)
    assert response.status == 200


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_get_routes_gone_after_last_unload(
    cs: ClientStability, view: Any, kwargs: dict[str, Any]
) -> None:
    cs.hass.data[_PANEL_VIEW_DISABLED_KEY] = True
    response = await view.get(Req(cs.hass), **kwargs)
    assert response.status == 410


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_routes_without_client_engine_answer_503(
    cs: ClientStability, view: Any, kwargs: dict[str, Any]
) -> None:
    del cs.hass.data[client_engine._DATA_KEY]
    response = await view.get(Req(cs.hass), **kwargs)
    assert response.status == 503


@pytest.mark.parametrize(("view", "kwargs"), _get_views())
async def test_routes_before_the_store_was_read_answer_503(
    view: Any, kwargs: dict[str, Any]
) -> None:
    hass = make_hass()
    with patch.object(
        client_engine, "Store", lambda *a, **kw: FakeStore(FakeDisk(), *a, **kw)
    ):
        hass.data[client_engine._DATA_KEY] = ClientStability(hass)
    response = await view.get(Req(hass), **kwargs)
    assert response.status == 503


async def test_settings_post_is_admin_only_even_when_open_to_all(
    cs: ClientStability,
) -> None:
    cs.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    response = await OpenWrtClientSettingsView().post(
        Req(cs.hass, admin=False, body={"retention_days": 7})
    )
    assert response.status == 403
    assert cs.settings["retention_days"] == 30


def test_client_views_are_registered_before_the_mac_route() -> None:
    views = _api_views()
    urls = [v.url for v in views]
    base = "/api/openwrt_topology/intelligence/clients"
    assert len({v.name for v in views}) == len(views)
    for url in (base, f"{base}/aps", f"{base}/settings", f"{base}/{{mac}}"):
        assert url in urls
    # aiohttp matches in order: the fixed paths must come before ``{mac}``
    assert urls.index(f"{base}/aps") < urls.index(f"{base}/{{mac}}")
    assert urls.index(f"{base}/settings") < urls.index(f"{base}/{{mac}}")


# --- table ------------------------------------------------------------------------


async def table(cs: ClientStability, **query: str) -> Any:
    return await OpenWrtClientsView().get(Req(cs.hass, query=query))


def macs(data: dict[str, Any]) -> list[str]:
    return [row["mac"] for row in data["clients"]]


async def test_table_worst_first_with_live_fields(cs: ClientStability) -> None:
    data = body(await table(cs))
    assert data["total"] == 3
    assert sorted(macs(data)) == [M1, M2, M3]
    scores = [row["score"] for row in data["clients"]]
    known = [s for s in scores if s is not None]
    assert known == sorted(known)
    assert scores[: len(known)] == known  # unknown scores last
    phone = next(r for r in data["clients"] if r["mac"] == M1)
    assert phone["name"] == "phone"
    assert phone["ip"] == "192.0.2.10"
    assert phone["router"] == "r1"
    assert phone["router_name"] == "Gateway"
    assert phone["band"] == "5g"
    assert phone["ssid"] == "Test"
    assert phone["state"] == "online"
    assert phone["coverage"] > 0.9
    assert phone["availability_24h"] == 1.0
    assert phone["reconnects_24h"] == 0
    for row in data["clients"]:
        # page rows carry the 7-day values and the trend
        assert {"score_7d", "availability_7d", "trend", "class"} <= row.keys()
    gone = next(r for r in data["clients"] if r["mac"] == M3)
    assert gone["state"] == "offline"
    assert gone["last_disconnect"]["ts"] is not None


async def test_table_filters(cs: ClientStability) -> None:
    assert sorted(macs(body(await table(cs, router="r2")))) == [M2, M3]
    assert macs(body(await table(cs, band="2.4g"))) == [M2]
    assert sorted(macs(body(await table(cs, ssid="Test")))) == [M1, M2, M3]
    assert macs(body(await table(cs, ssid="Other"))) == []
    assert macs(body(await table(cs, state="offline"))) == [M3]
    assert macs(body(await table(cs, q="LAP"))) == [M2]
    assert macs(body(await table(cs, q="192.0.2.10"))) == [M1]
    assert macs(body(await table(cs, q=M3.lower()))) == [M3]
    first = body(await table(cs))["clients"][0]
    same = body(await table(cs, **{"class": first["class"]}))
    assert same["clients"]
    assert {row["class"] for row in same["clients"]} == {first["class"]}


async def test_table_sort_by_name_both_ways(cs: ClientStability) -> None:
    up = macs(body(await table(cs, sort="name")))
    assert up == [M3, M2, M1]  # "02:00:..." < "laptop" < "phone"
    assert macs(body(await table(cs, sort="-name"))) == [M1, M2, M3]


async def test_table_cursor_pages_without_overlap(cs: ClientStability) -> None:
    full = macs(body(await table(cs)))
    seen: list[str] = []
    cursor: str | None = None
    for _ in range(5):
        query = {"limit": "1"} | ({"cursor": cursor} if cursor else {})
        data = body(await table(cs, **query))
        seen += macs(data)
        cursor = data["next_cursor"]
        if cursor is None:
            break
    assert seen == full


@pytest.mark.parametrize(
    "query",
    [
        {"limit": "0"},
        {"limit": "501"},
        {"limit": "abc"},
        {"cursor": "-1"},
        {"cursor": "x"},
        {"class": "great"},
        {"state": "asleep"},
        {"band": "7g"},
        {"sort": "colour"},
        {"q": "x" * 200},
    ],
)
async def test_table_rejects_bad_parameters(
    cs: ClientStability, query: dict[str, str]
) -> None:
    response = await table(cs, **query)
    assert response.status == 400


async def test_table_limit_upper_bound_is_accepted(cs: ClientStability) -> None:
    response = await table(cs, limit="500")
    assert response.status == 200


# --- detail -----------------------------------------------------------------------


async def detail(cs: ClientStability, mac: str, **query: str) -> Any:
    return await OpenWrtClientView().get(Req(cs.hass, query=query), mac)


async def test_detail_24h_has_score_series_and_live_state(
    cs: ClientStability,
) -> None:
    data = body(await detail(cs, M1.lower()))
    assert data["mac"] == M1
    assert data["window"] == "24h"
    assert data["live"]["router_name"] == "Gateway"
    assert data["live"]["state"] == "online"
    assert data["live"]["ssid"] == "Test"
    assert data["score"]["class"] in {
        "very_stable",
        "stable",
        "noticeable",
        "unstable",
        "critical",
        "unknown",
    }
    assert set(data["score"]["parts"]) >= {"disconnects", "signal"}
    assert data["stats"]["availability"] == 1.0
    assert data["stats"]["rssi_mean"] == -55.0
    assert 0 < len(data["series"]) <= 24
    assert all(point["rssi_mean"] == -55.0 for point in data["series"])
    assert len(data["score_series"]) <= SERIES_MAX
    assert {"time", "signal", "ap"} <= data["patterns"].keys()
    assert isinstance(data["recommendations"], list)
    assert data["attribution"]["attribution"] == "none"
    assert data["entity"] is False
    assert data["sleepy"] is False


async def test_detail_1h_uses_the_raw_ring(cs: ClientStability) -> None:
    data = body(await detail(cs, M1, window="1h"))
    assert data["window"] == "1h"
    ring = data["rssi"]
    assert 0 < len(ring) <= 120
    assert all(p["rssi"] == -55 for p in ring)
    assert all(p["router"] == "r1" for p in ring)


async def test_detail_shows_the_disconnect_of_a_gone_client(
    cs: ClientStability,
) -> None:
    data = body(await detail(cs, M3))
    assert data["live"]["state"] == "offline"
    kinds = [t["kind"] for t in data["transitions"]]
    assert "start" in kinds and "end" in kinds
    end = next(t for t in data["transitions"] if t["kind"] == "end")
    assert end["router_name"] == "AP Flur"
    timeline = data["timeline"]
    assert timeline and timeline[-1]["state"] == "offline"
    assert data["attribution"]["client"] == 1


@pytest.mark.parametrize("window", ["7d", "30d"])
async def test_detail_long_windows(cs: ClientStability, window: str) -> None:
    data = body(await detail(cs, M2, window=window))
    assert data["window"] == window
    assert len(data["series"]) <= SERIES_MAX
    assert data["stats"]["weak_share"] == 1.0


async def test_detail_errors(cs: ClientStability) -> None:
    response = await detail(cs, UNKNOWN)
    assert response.status == 404
    assert body(response)["message"] == "Unknown client"
    assert (await detail(cs, "not-a-mac")).status == 400
    assert (await detail(cs, M1, window="2h")).status == 400


# --- AP comparison ------------------------------------------------------------------


async def aps(cs: ClientStability, **query: str) -> Any:
    return await OpenWrtClientApsView().get(Req(cs.hass, query=query))


@pytest.mark.parametrize("window", ["24h", "7d", "30d"])
async def test_ap_comparison_windows(cs: ClientStability, window: str) -> None:
    data = body(await aps(cs, window=window))
    assert data["window"] == window
    rows = {row["ap"]: row for row in data["aps"]}
    assert set(rows) == {"r1", "r2"}
    assert rows["r1"]["name"] == "Gateway"
    assert rows["r2"]["clients"] == 2
    assert rows["r1"]["status"] == "insufficient"  # 3 client hours < 10
    assert isinstance(data["recommendations"], list)
    assert data["ranking"] == []


async def test_ap_comparison_rejects_a_bad_window(cs: ClientStability) -> None:
    assert (await aps(cs, window="1h")).status == 400


async def test_port_root_of_the_ap_keeps_infrastructure_likely(
    cs: ClientStability,
) -> None:
    storm = [f"02:00:5E:10:01:{i:02X}" for i in range(3)]
    facts = poll("r1", T0 + POLLS * STEP - 30, *(client(m) for m in storm))
    cs.on_poll(
        replace(
            facts, findings=tuple(finding("wifi.reconnect", m, count=3) for m in storm)
        )
    )

    async def keys(*roots: Any) -> list[str]:
        with patch.object(cs._engine.machine, "peek", return_value=list(roots)):
            data = body(await aps(cs, window="24h"))
        return [rec["key"] for rec in data["recommendations"]]

    # r1's own port towards another AP is down: r1's clients are not behind it
    uplink = incident("u", "lan_uplink_down", ["r1"], scope_key="r1:port:lan1")
    assert "infrastructure_likely" in await keys(uplink)
    # a root on r1 itself explains the reconnects
    assert "infrastructure_likely" not in await keys(
        incident("a", "router_unreachable", ["r1"])
    )


# --- settings -----------------------------------------------------------------------


async def test_settings_get_shows_defaults_and_rights(cs: ClientStability) -> None:
    data = body(await OpenWrtClientSettingsView().get(Req(cs.hass)))
    assert data["can_edit"] is True
    assert data["settings"] == data["defaults"]
    assert data["limits"]["entity_max"] == 25
    assert data["limits"]["retention_days_max"] == 90
    cs.hass.data[_PANEL_ACCESS_KEY] = {"entry": True}
    data = body(await OpenWrtClientSettingsView().get(Req(cs.hass, admin=False)))
    assert data["can_edit"] is False


async def test_settings_post_applies_a_partial_change(cs: ClientStability) -> None:
    response = await OpenWrtClientSettingsView().post(
        Req(cs.hass, body={"entity_macs": [M1.lower()], "retention_days": 14})
    )
    assert response.status == 200
    data = body(response)
    assert data["settings"]["entity_macs"] == [M1]
    assert data["settings"]["retention_days"] == 14
    assert cs.settings["entity_macs"] == [M1]
    assert body(await detail(cs, M1))["entity"] is True


@pytest.mark.parametrize(
    "payload",
    [
        {"retention_days": 0},
        {"retention_days": True},
        {"entity_macs": ["nope"]},
        {"classes": [10, 20, 30, 40]},
        {"weights": {part: 0 for part in client_engine.PARTS}},
        {"bogus": 1},
        [],
        "text",
    ],
)
async def test_settings_post_rejects_invalid_values(
    cs: ClientStability, payload: Any
) -> None:
    before = dict(cs.settings)
    response = await OpenWrtClientSettingsView().post(Req(cs.hass, body=payload))
    assert response.status == 400
    assert body(response)["errors"]
    assert cs.settings == before


async def test_settings_post_rejects_non_json(cs: ClientStability) -> None:
    response = await OpenWrtClientSettingsView().post(Req(cs.hass, bad_json=True))
    assert response.status == 400


async def test_route_errors_name_only_the_exception_type(
    cs: ClientStability, caplog: pytest.LogCaptureFixture
) -> None:
    with patch.object(
        client_views, "clients_table", side_effect=RuntimeError(f"boom {M1}")
    ):
        response = await table(cs)
    assert response.status == 500
    assert M1 not in response.text
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings
    assert all(M1 not in r.getMessage() for r in warnings)


def test_topology_panel_module_is_not_imported_twice() -> None:
    # client_views imports the panel's base view; the panel imports the
    # client views lazily (no import cycle at module level)
    assert client_views._IntelView is topology_panel._IntelView


# --- 1.43: new figures, sorting, last problem, strips --------------------------------


async def test_window_figures_of_1_43(cs: ClientStability) -> None:
    stats = body(await detail(cs, M1))["stats"]
    assert stats["start"] is not None and stats["memory_from"] is None
    # IP known in every sample of the phone; share of the signal samples
    assert stats["ip_visible_share"] == 1.0
    assert stats["notable_events"] == 0
    assert stats["finished_sessions"] == 0 and stats["session_mean_s"] is None
    gone = body(await detail(cs, M3))["stats"]
    assert gone["finished_sessions"] == 1
    assert gone["session_mean_s"] == pytest.approx(120 * STEP, abs=STEP)
    assert gone["ip_visible_share"] == 0.0
    assert gone["notable_events"] == 1  # one disconnect of class unknown
    assert gone["disconnects"]["unknown"] == 1


def test_notable_events_sum() -> None:
    from custom_components.openwrt_router.client_analysis import notable_events
    from custom_components.openwrt_router.client_history import Bucket

    b = Bucket(
        dc_error=1,
        dc_unknown=2,
        dc_inactivity=4,
        dc_leave=8,
        dc_infra=16,
        roam_flaps=32,
        auth_fail=64,
        assoc_fail=128,
        dhcp_fail=256,
        reconnects=512,
    )
    # error + unknown + flaps + auth + assoc + DHCP; not inactivity, leave,
    # infrastructure or reconnects
    assert notable_events(b) == 1 + 2 + 32 + 64 + 128 + 256


async def test_detail_1h_is_the_trailing_hour(cs: ClientStability) -> None:
    data = body(await detail(cs, M1, window="1h"))
    stats = data["stats"]
    now = data["now"]
    assert stats["start"] == now - 3600
    assert stats["window_s"] == 3600
    assert stats["online_s"] == pytest.approx(3600, abs=1)
    assert stats["rssi_n"] == 61
    assert data["timeline"] == [{"start": now - 3600, "end": now, "state": "online"}]


async def test_table_last_problem_includes_failures(cs: ClientStability) -> None:
    now = T0 + (POLLS - 1) * STEP
    facts = poll("r1", now - 30, client(M1, signal=-55, hostname="phone"))
    cs.on_poll(replace(facts, findings=(finding("wifi.no_ip", M1),)))
    rows = {r["mac"]: r for r in body(await table(cs))["clients"]}
    problem = rows[M1]["last_problem"]
    assert problem["kind"] == "dhcp_fail" and problem["ts"] == now - 30
    gone = rows[M3]["last_problem"]
    assert gone["kind"] == "disconnect"
    assert gone["class"] == "unknown"
    assert gone["ts"] == rows[M3]["last_disconnect"]["ts"]
    assert rows[M2]["last_problem"] is None


async def test_table_sorts_by_ap_7d_availability_and_trend(
    cs: ClientStability,
) -> None:
    by_ap = macs(body(await table(cs, sort="router")))
    assert by_ap[0] == M2 or by_ap[0] == M3  # "AP Flur" < "Gateway"
    assert by_ap[-1] == M1
    assert macs(body(await table(cs, sort="-router")))[0] == M1
    week = body(await table(cs, sort="availability_7d"))["clients"]
    values = [r["availability_7d"] for r in week]
    known = [v for v in values if v is not None]
    assert known == sorted(known)
    down = body(await table(cs, sort="-availability"))["clients"]
    known = [r["availability_24h"] for r in down if r["availability_24h"] is not None]
    assert known == sorted(known, reverse=True)
    trend = body(await table(cs, sort="trend"))
    assert trend["total"] == 3
    for row in trend["clients"]:
        assert {"trend", "score_previous_24h", "trend_delta"} <= row.keys()
    assert macs(body(await table(cs, sort="last_problem")))


async def test_detail_series_name_the_main_ap_and_band(cs: ClientStability) -> None:
    data = body(await detail(cs, M2, window="24h"))
    assert data["routers"] == {"r2": "AP Flur"}
    assert all(p["ap"] == "r2" and p["band"] == "2.4g" for p in data["series"])
    phone = body(await detail(cs, M1, window="7d"))
    assert all(p["ap"] == "r1" and p["band"] == "5g" for p in phone["series"])


@pytest.mark.parametrize(
    ("window", "count", "span"), [("7d", 168, 3600), ("30d", 30, 86400)]
)
async def test_long_windows_have_a_coarse_strip(
    cs: ClientStability, window: str, count: int, span: int
) -> None:
    data = body(await detail(cs, M3, window=window))
    strip = data["strip"]
    assert len(strip) == count
    assert all(s["span_s"] == span for s in strip[:-1])
    assert 0 < strip[-1]["span_s"] <= span  # the running bucket ends now
    seen = [s for s in strip if s["online"] or s["offline"] or s["gap"]]
    assert seen
    for s in strip:
        assert s["online"] + s["offline"] + s["gap"] + s["unknown"] == pytest.approx(
            1.0
        )
    assert sum(s["disconnects"] for s in strip) == 1
    # before the first sighting everything is unknown, never offline
    assert strip[0]["unknown"] == 1.0
    assert (await detail(cs, M3, window="24h")).status == 200
    assert body(await detail(cs, M3, window="24h"))["strip"] == []


# --- 1.43: AP figures and the score settings of the panel ----------------------------


async def test_ap_comparison_has_the_figures_of_the_panel(cs: ClientStability) -> None:
    rows = {row["ap"]: row for row in body(await aps(cs, window="24h"))["aps"]}
    for row in rows.values():
        assert {
            "auth_fail_per_100h",
            "roams_in_per_100h",
            "roams_out_per_100h",
            "weak_share",
            "infra_clients",
        } <= row.keys()
        assert isinstance(row["infra_clients"], int)


async def test_settings_limits_name_the_parts_and_classes(cs: ClientStability) -> None:
    data = body(await OpenWrtClientSettingsView().get(Req(cs.hass)))
    assert data["limits"]["parts"] == list(client_engine.PARTS)
    assert set(data["defaults"]["weights"]) == set(client_engine.PARTS)
    assert len(data["defaults"]["classes"]) == len(data["limits"]["classes"]) - 2


async def test_settings_weights_and_classes_round_trip_and_reset(
    cs: ClientStability,
) -> None:
    view = OpenWrtClientSettingsView()
    weights = dict.fromkeys(client_engine.PARTS, 0)
    weights["signal"] = 100
    changed = await view.post(
        Req(cs.hass, body={"weights": weights, "classes": [95, 80, 60, 30]})
    )
    assert changed.status == 200
    data = body(changed)
    assert data["settings"]["weights"]["signal"] == 100
    assert data["settings"]["classes"] == [95, 80, 60, 30]
    defaults = data["defaults"]
    reset = await view.post(
        Req(
            cs.hass,
            body={"weights": defaults["weights"], "classes": defaults["classes"]},
        )
    )
    assert reset.status == 200
    assert body(reset)["settings"] == defaults
