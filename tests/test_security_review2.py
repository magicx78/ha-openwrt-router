"""Security Center: fixes of the second review (release 1.46.0).

One block per finding (H1, M1, M2, M3, N1, N2, N4, N5, N6). Every test
started red against bec5e13. No Home Assistant instance, no router: the
center runs on in-memory stores, the core on FakeDisks.
"""

from __future__ import annotations

import hashlib
import json
import time
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from config_manager_kit import cm_env, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import (
    USER_ID,
    FakeDisks,
    FakeEntry,
    core_of,
    router_data,
    setup_router,
)
from core_testkit import make_hass as core_hass
from homeassistant.helpers import entity_registry as er
from test_net_engine import FakeDisk, FakeStore, make_hass
from test_registry_orphan_bound import _orphan, _plant
from test_security_center import (
    ADMIN,
    M1,
    M2,
    MODULE_KEY,
    NO_SCHEDULE,
    RID1,
    RID2,
    T0,
    _core_center,
    center_for,
    coordinator,
    disks,  # noqa: F401 - fixture
    sec_disk,
)
from test_security_entities import Platform, ours, registry_hass
from test_security_views import http, users

from custom_components.openwrt_router import security_center
from custom_components.openwrt_router import security_views as sv
from custom_components.openwrt_router.const import (
    DOMAIN,
    SEC_INCIDENT_CAP,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry
from custom_components.openwrt_router.router_registry import ORPHAN_RETENTION_DAYS
from custom_components.openwrt_router.security_center import (
    SecurityCenter,
    async_release_security_center,
    async_setup_security_center,
    default_settings,
    merge_settings,
)
from custom_components.openwrt_router.security_entities import (
    SECURITY_UNIQUE_IDS,
    async_entry_unloaded,
    async_setup_security_sensors,
)
from custom_components.openwrt_router.security_model import (
    SecCategory,
    SecurityEvent,
    event_type,
    make_dedup_key,
    make_event_id,
)
from custom_components.openwrt_router.security_rules import WifiAuthRepeatDetector


def _digest(*parts: Any) -> str:
    """The unkeyed incident digest of 1.46.0 before review 2 (attacker view)."""
    text = "\x1f".join("" if p is None else str(p) for p in parts)
    return hashlib.blake2b(text.encode("utf-8"), digest_size=8).hexdigest()


CANDIDATES = [f"02:00:5e:10:00:{n:02x}" for n in range(256)]
MAC = CANDIDATES[1]


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def poll_facts(router: str, now: float) -> Any:
    """What NI hands its poll observers (nothing delivered but the poll)."""
    return SimpleNamespace(
        router=router,
        now=now,
        log_ok=True,
        fresh_clients=False,
        exclude=frozenset(),
        wifi_lines=(),
        stored_events=(),
        context=SimpleNamespace(clients=None),
    )


def fw_event(i: int, ts: float, rid: str = RID1) -> SecurityEvent:
    """A finding with its own scope (as forged port-scan lines would make)."""
    return SecurityEvent(
        event_id=f"evt_{i}",
        ts=ts,
        type=event_type("fw_port_scan_hint"),
        category=SecCategory.FIREWALL,
        router_id=rid,
        dedup_key=f"k{i}",
    )


def auth_event(rid: str, mac: str = MAC, now: float = T0) -> SecurityEvent:
    return WifiAuthRepeatDetector()._event(
        router_id=rid, now=now, key=(rid, mac), client=mac
    )


def unkeyed_ids(rid: str, mac: str, now: float = T0) -> set[str]:
    """Every id an attacker can derive from a candidate MAC without a key."""
    det = WifiAuthRepeatDetector()
    bucket = int(now // det.window_s)
    dedup = make_dedup_key(det.id, mac)
    scope = "|".join((rid, event_type(det.id), dedup))
    return {
        dedup,
        make_event_id(det.id, rid, mac, bucket),
        "sec_" + _digest(scope),
        _digest(scope),
    }


def inc_dict(inc_id: str, rid: str, status: str = "open") -> dict[str, Any]:
    return {
        "id": inc_id,
        "scope": f"{rid}|security_center.x|{inc_id}",
        "first_seen": T0,
        "last_seen": T0,
        "status": status,
        "router_id": rid,
        "type": "sec_x",
        "detector": "x",
        "category": "wifi",
        "severity": "warning",
    }


# --- H1: an unloaded router leaves the fleet ------------------------------------------------


async def _two_routers_one_unloaded(hass: Any) -> SecurityCenter:
    center = SecurityCenter(hass)
    center.router_id_of = {"r1": RID1, "r2": RID2}.get
    hass.data[security_center.DATA_SECURITY_CENTER] = center
    await center.async_load()
    center.add_entry("r1", coordinator())
    center.add_entry("r2", coordinator())
    center.settings = merge_settings(center.settings, {"enabled": True})
    center.active = True
    center._module_key = MODULE_KEY
    center._engine = object()  # NI present (statuses only check "is not None")
    center.on_poll(poll_facts("r1", T0))
    center.on_poll(poll_facts("r2", T0))
    center._record(fw_event(1, T0, RID2), T0)  # a hint of r2
    center.baseline.observe(f"{RID2}|x", 3, T0, group=f"{RID2}|x")
    await async_release_security_center(hass, "r2")
    center.on_router_removed("r2")  # what NI's remove_router calls
    for k in range(1, 40):
        center.on_poll(poll_facts("r1", T0 + 60 * k))
    return center


async def test_review2_h1_unloaded_router_leaves_score_and_coverage(
    disks,  # noqa: F811
) -> None:
    center = await _two_routers_one_unloaded(make_hass())
    control = SecurityCenter(make_hass())
    control.router_id_of = {"r1": RID1}.get
    await control.async_load()
    control.add_entry("r1", coordinator())
    control.settings = merge_settings(control.settings, {"enabled": True})
    control.active = True
    control._module_key = MODULE_KEY
    control._engine = object()
    for k in range(40):
        control.on_poll(poll_facts("r1", T0 + 60 * k))
    view, want = center.fleet_view, control.fleet_view
    assert view is not None and want is not None
    for key in ("routers", "coverage", "stale", "missing"):
        assert view[key] == want[key], key
    assert view["routers"] == 1
    assert RID2 not in center._seen and RID2 not in center._statuses
    overview = center.overview(actor=None, now=T0 + 60 * 39)
    assert overview["score"]["routers"] == 1
    assert RID2 not in center.detections_view(now=T0 + 60 * 39)["sources"]


async def test_review2_h1_hints_and_baselines_of_an_unloaded_router_stay(
    disks,  # noqa: F811
) -> None:
    center = await _two_routers_one_unloaded(make_hass())
    assert [i["router_id"] for i in center.incidents.values()] == [RID2]
    assert center.baseline.get(f"{RID2}|x") is not None
    assert center.counters["routers_forgotten"] == 0


# --- M1: router.forgotten sent before the center listened -----------------------------------


async def _sec_store_with(rids: dict[str, str]) -> FakeDisk:
    sec = FakeDisk()
    sec.path = "/nonexistent/.storage/sec"
    sec.data = {
        "settings": {**default_settings(), "enabled": True},
        "incidents": [inc_dict(f"sec_{n}", rid) for n, rid in rids.items()],
        "timeline": [
            {"ts": T0, "kind": "incident_opened", "router_id": rid, "text": "x"}
            for rid in rids.values()
        ],
        "drifts": [
            {"router_id": rid, "drift_id": f"d{n}", "ts": time.time()}
            for n, rid in rids.items()
        ],
    }
    return sec


async def _start_with_registry(
    store: Any, sec: FakeDisk, orphans: list[dict[str, Any]], **load: Any
) -> tuple[Any, SecurityCenter]:
    """Core start (prune_orphans in core.async_load), then the center."""
    _plant(store, orphans)
    for key, value in load.items():
        setattr(store["openwrt_router.router_registry"], key, value)
    hass = core_hass([FakeEntry("live")])
    coord = await setup_router(hass, hass.entries[0], router_data())
    with patch.object(
        security_center, "Store", lambda *a, **kw: FakeStore(sec, *a, **kw)
    ):
        center = await async_setup_security_center(hass, hass.entries[0], coord)
    return hass, center


async def test_review2_m1_forgotten_before_subscribe_is_forgotten_on_bind(
    core_disks,
) -> None:
    old = _orphan("old", ORPHAN_RETENTION_DAYS + 1)
    young = _orphan("young", ORPHAN_RETENTION_DAYS - 1)
    old_id, young_id = old["identity"]["router_id"], young["identity"]["router_id"]
    live_id = router_id_for_entry("live")
    sec = await _sec_store_with({"a": old_id, "b": young_id, "c": live_id})
    hass, center = await _start_with_registry(core_disks, sec, [old, young])
    # the core really forgot "old" while it loaded, before the center existed
    assert core_of(hass).registry.find(old_id) is None
    assert center.active
    routers = {i["router_id"] for i in center.incidents.values()}
    assert routers == {young_id, live_id}
    assert {t["router_id"] for t in center.timeline} == {young_id, live_id}
    assert {k[0] for k in center.drifts} == {young_id, live_id}
    assert center.counters["routers_forgotten"] == 1
    await async_release_security_center(hass, "live")


async def test_review2_m1_unknown_registry_forgets_nothing(core_disks) -> None:
    gone = router_id_for_entry("gone")
    sec = await _sec_store_with({"a": gone})
    hass, center = await _start_with_registry(
        core_disks, sec, [], load_error=OSError("disk")
    )
    assert core_of(hass).registry.load_failed
    assert [i["router_id"] for i in center.incidents.values()] == [gone]
    assert center.counters["routers_forgotten"] == 0
    await async_release_security_center(hass, "live")


async def test_review2_m1_no_core_forgets_nothing(disks) -> None:  # noqa: F811
    sec_disk(disks).data = {
        "settings": {**default_settings(), "enabled": True},
        "incidents": [inc_dict("sec_a", RID2)],
    }
    center = await center_for(make_hass(), "r1", enabled=False)
    await center.async_activate()
    assert center.active and center.counters["routers_forgotten"] == 0
    assert len(center.incidents) == 1


# --- M2: no id derivable from a candidate MAC -----------------------------------------------


def _texts(*items: Any) -> str:
    return json.dumps(items, default=str, ensure_ascii=False)


async def test_review2_m2_ids_reveal_no_mac_with_the_module_key(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    assert center.module_key_available
    rid = env.rid
    center._record(auth_event(rid), T0)
    view = center.overview(actor=None, now=T0)
    inc = view["incidents"][0]
    stored = center._data_to_save()
    core_events = [
        e.to_dict()
        for e in env.core.audit.events(types=["security_center.wifi_auth_repeat"])
    ]
    assert len(core_events) == 1
    text = _texts(view, stored, core_events)
    for mac in CANDIDATES:
        for derived in unkeyed_ids(rid, mac):
            assert derived not in text, mac
    assert MAC not in text and MAC.upper() not in text
    # the same finding keeps its incident (keyed, deterministic)
    center._record(auth_event(rid, now=T0 + 5), T0 + 5)
    assert len(center.incidents) == 1 and inc["id"] in center.incidents
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


async def test_review2_m2_without_module_key_no_id_is_made(
    disks,  # noqa: F811
) -> None:
    """Review 3, #6 replaced the random key per run: nothing is recorded."""
    center = await center_for(make_hass(), "r1", module_key=None)
    assert not center.module_key_available
    center._record(auth_event(RID1), T0)
    view = center.overview(actor=None, now=T0)
    text = _texts(view, center._data_to_save())
    for mac in CANDIDATES:
        for derived in unkeyed_ids(RID1, mac):
            assert derived not in text, mac
    assert view["incidents"] == [] and view["not_ready_reason"] == "module_key_missing"
    center.close()


async def test_review2_m2_old_store_with_unkeyed_ids_loads(disks) -> None:  # noqa: F811
    scope = "|".join((RID1, event_type("wifi_auth_repeat"), "0" * 16))
    sec_disk(disks).data = {
        "settings": {**default_settings(), "enabled": True},
        "incidents": [{**inc_dict("sec_" + _digest(scope), RID1), "scope": scope}],
    }
    center = await center_for(make_hass(), "r1", enabled=False)
    assert len(center.incidents) == 1
    center.settings = merge_settings(center.settings, {"enabled": True})
    await center.async_activate()
    center._module_key = MODULE_KEY
    center._record(auth_event(RID1), T0)
    assert len(center.incidents) == 2


# --- M3: confirmed and open hints are never evicted -----------------------------------------


async def test_review2_m3_full_store_keeps_confirmed_and_open_hints(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1")
    center._record(auth_event(RID1), T0)
    (confirmed,) = list(center.incidents)
    center.incidents[confirmed]["status"] = "confirmed"
    for i in range(SEC_INCIDENT_CAP - 1):
        center._record(fw_event(i, T0 + 1 + i), T0 + 1 + i)
    assert len(center.incidents) == SEC_INCIDENT_CAP
    before = set(center.incidents)
    for i in range(1000, 1005):
        center._record(fw_event(i, T0 + 200 + i), T0 + 200 + i)
    assert set(center.incidents) == before  # the NEW hints were dropped
    assert center.counters["incidents_cap_dropped"] == 5
    assert center.counters["incidents_dropped"] == 0
    notes = [t for t in center.timeline if t["kind"] == "cap_reached"]
    assert len(notes) == 1 and "Obergrenze erreicht" in notes[0]["text"]
    overview = center.overview(actor=None, now=T0 + 1300)
    assert overview["limits"]["incidents_cap_dropped"] == 5
    assert center.diagnostics()["counters"]["incidents_cap_dropped"] == 5
    # a later window gets one more note
    center._record(fw_event(2000, T0 + 9000), T0 + 9000)
    assert len([t for t in center.timeline if t["kind"] == "cap_reached"]) == 2


async def test_review2_m3_resolved_hints_make_room_oldest_first(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1")
    for i in range(SEC_INCIDENT_CAP):
        center._record(fw_event(i, T0 + i), T0 + i)
    ids = sorted(center.incidents, key=lambda k: center.incidents[k]["last_seen"])
    for inc_id in ids[5:7]:
        center.incidents[inc_id]["status"] = "resolved"
    center._record(fw_event(500, T0 + 600), T0 + 600)
    assert ids[5] not in center.incidents and ids[6] in center.incidents
    assert len(center.incidents) == SEC_INCIDENT_CAP
    assert center.counters["incidents_dropped"] == 1
    assert center.counters["incidents_cap_dropped"] == 0


async def test_review2_m3_core_emits_of_new_hints_are_limited(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    for i in range(30):
        center._record(fw_event(i, T0 + i, env.rid), T0 + i)
    sent = env.core.audit.events(types=["security_center.fw_port_scan_hint"])
    assert len(sent) == 20
    assert center.counters["events_throttled"] == 10
    assert len(center.incidents) == 30  # stored all the same
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


# --- N1: no usable source, no hint count ----------------------------------------------------


async def test_review2_n1_hint_counts_are_unknown_without_any_source(
    disks,  # noqa: F811
) -> None:
    center = await center_for(make_hass(), "r1")
    center._record(fw_event(1, T0), T0)
    center._publish(T0)
    view = center.fleet_view
    assert view["coverage"] == 0 and view["score"] is None
    assert view["hints_active"] is None and view["hints_critical"] is None


# --- N2: the clock never lags behind the wall clock -----------------------------------------


async def test_review2_n2_actions_after_a_restart_use_the_wall_clock(
    disks,  # noqa: F811
) -> None:
    old = time.time() - 5 * 86400
    first = await center_for(make_hass(), "r1")
    first.last_now = old
    await first.async_flush()
    second = await center_for(make_hass(), "r1")
    assert second.last_now == old
    before = time.time()
    assert second._now() >= before
    second._action_done(
        SecurityEvent(
            event_id="evt_x", ts=old, type=event_type("x"), category=SecCategory.DEVICE
        ),
        "confirmed",
        second._now(),
    )
    assert second.timeline[-1]["ts"] >= before
    # a poll clock ahead of the wall clock (tests, skew) is still kept
    second.last_now = before + 3600
    assert second._now() == before + 3600


# --- N4: no MAC in a URL path ---------------------------------------------------------------


def test_review2_n4_no_route_has_a_mac_in_its_path() -> None:
    urls = [v.url for v in sv.SECURITY_VIEWS]
    assert not any("{mac}" in u for u in urls)
    assert f"{sv.BASE_URL}/devices/confirm" in urls
    assert f"{sv.BASE_URL}/devices/name" in urls


async def test_review2_n4_device_routes_take_the_mac_from_the_body(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    center = await _core_center(env, FakeDisk())
    hass = users(env.hass)
    center.trust.observe(SimpleNamespace(mac=M1, private_mac=None), T0)
    async with http(hass) as h:
        resp = await h.post("/devices/confirm", body={"mac": M1.lower(), "name": "L"})
        assert resp.status == 200 and resp.data == {"confirmed": True}
        assert center.trust.get(M1).name == "L"
        resp = await h.post("/devices/name", body={"mac": M1, "name": None})
        assert resp.status == 200 and resp.data == {"named": False}
        for path in ("/devices/confirm", "/devices/name"):
            missing = await h.post(path, body={"name": "x"})
            assert missing.status == 400 and missing.data["details"]["field"] == "mac"
            bad = await h.post(path, body={"mac": "zz:zz", "name": "x"})
            assert bad.status == 400 and bad.data["details"]["field"] == "mac"
        assert (
            await h.post("/devices/name", body={"mac": M2, "name": "x"})
        ).status == 404
        old = await h.post(f"/devices/{M1}/confirm", body={})
        assert old.status in (404, 405)
        with patch.object(sv, "read_body", AsyncMock(side_effect=AssertionError)):
            denied = await h.post("/devices/confirm", user=USER_ID, body={"mac": M1})
        assert denied.status == 403
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


# --- N5: a renamed entity id survives the host change ---------------------------------------


async def test_review2_n5_renamed_entity_id_survives_the_host_change(
    disks,  # noqa: F811
) -> None:
    hass, registry, entries = await registry_hass()
    await center_for(hass, "r1", "r2")
    first = Platform(registry, entries["e1"])
    second = Platform(registry, entries["e2"])
    async_setup_security_sensors(hass, entries["e2"], second)
    async_setup_security_sensors(hass, entries["e1"], first)
    uid = SECURITY_UNIQUE_IDS[0]
    old_id = registry.async_get_entity_id("sensor", DOMAIN, uid)
    registry.async_update_entity(old_id, new_entity_id="sensor.mein_score")
    async_entry_unloaded(hass, "e2", last=False)  # the host leaves
    assert set(ours(registry).values()) == {"e1"}
    assert registry.async_get_entity_id("sensor", DOMAIN, uid) == "sensor.mein_score"


async def test_review2_n5_renamed_entity_id_survives_a_deleted_host(
    disks,  # noqa: F811
) -> None:
    """Entry deleted: HA clears its registry entries after the unload."""
    hass, registry, entries = await registry_hass()
    await center_for(hass, "r1", "r2")
    later: list[Any] = []
    first = Platform(registry, entries["e1"])
    second = Platform(registry, entries["e2"])
    async_setup_security_sensors(hass, entries["e2"], second)
    async_setup_security_sensors(
        hass, entries["e1"], lambda ents, *a: later.append(ents)
    )
    uid = SECURITY_UNIQUE_IDS[0]
    old_id = registry.async_get_entity_id("sensor", DOMAIN, uid)
    registry.async_update_entity(old_id, new_entity_id="sensor.mein_score")
    async_entry_unloaded(hass, "e2", last=False)  # adding is scheduled ...
    registry.async_clear_config_entry("e2")  # ... HA removes e2's entities first
    assert registry.async_get_entity_id("sensor", DOMAIN, uid) is None
    for ents in later:
        first(ents)
    assert registry.async_get_entity_id("sensor", DOMAIN, uid) == "sensor.mein_score"
    assert set(ours(registry).values()) == {"e1"}
    assert er.DATA_REGISTRY in hass.data


# --- N6: a settings change while off creates no installation key ----------------------------


async def test_review2_n6_settings_while_off_create_no_installation_key(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    versions = env.core.versions
    assert versions.existing_installation_key() is None
    center = await _core_center(env, FakeDisk(), enabled=False)
    with patch.object(type(env.api), "async_get_module_key", autospec=True) as get_key:
        await center.async_update_settings({"log_path": "syslog"}, actor=ADMIN)
        assert get_key.call_count == 0
    assert versions.existing_installation_key() is None
    assert not center.module_key_available
    await center.async_update_settings({"enabled": True}, actor=ADMIN)
    assert center.active and center.module_key_available
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)
