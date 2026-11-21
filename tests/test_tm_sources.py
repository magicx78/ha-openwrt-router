"""Network Time Machine, Phase A: the read adapters (tm_sources).

The adapters are tested against the real source classes with data made on
their own write paths: the enterprise core, the configuration manager and
the Security Center of ``config_manager_kit`` / ``test_security_center``
(case 08: a VLAN drift), Network Intelligence with the real fleet outage
tracker of ``test_net_correlation`` (AK1: an AP outage with 20 clients).
No router, no HA instance, no network; MACs are locally administered test
values, IPs from TEST-NET.
"""

from __future__ import annotations

import asyncio
import inspect
import json
from datetime import timedelta
from typing import Any
from unittest.mock import patch

import pytest
from config_manager_kit import cm_env, drain, stop
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import FakeDisks, FakeEntry, make_hass
from test_net_correlation import (
    AP_TRUNK,
    CLIENTS20,
    HOST,
    MAC,
    T0,
    A,
    B,
    G,
    Log,
    client,
    clock,  # noqa: F401 - fixture
    disc,
    dt,
    feed,
    fleet,  # noqa: F401 - fixture
    gw_poll,
    rdata,
)
from test_net_engine import FakeDisk
from test_net_wifi import mic, psk
from test_security_center import (
    ADMIN,
    NO_SCHEDULE,
    AreaProvider,
    _core_center,
    _drifted_poll,
)

from custom_components.openwrt_router import core_audit, net_engine
from custom_components.openwrt_router import tm_sources as src
from custom_components.openwrt_router.config_api import ConfigurationApi
from custom_components.openwrt_router.const import ERROR_TYPE_TIMEOUT
from custom_components.openwrt_router.core_models import (
    OPTION_CONFIG_BACKUP_ENABLED,
    CoreEventType,
)
from custom_components.openwrt_router.enterprise_core import EnterpriseCore
from custom_components.openwrt_router.net_engine import NetIntelligence
from custom_components.openwrt_router.router_registry import RouterRegistry
from custom_components.openwrt_router.security_center import (
    SecurityCenter,
    async_release_security_center,
)
from custom_components.openwrt_router.tm_sources import (
    REASON_ADMIN_ONLY,
    REASON_BAD_FORMAT,
    REASON_ERROR,
    REASON_MODULE_OFF,
    REASON_NOT_LOADED,
    REASON_NOT_RUNNING,
    REASON_TIMEOUT,
    STATE_EMPTY,
    STATE_OFF,
    STATE_OK,
    STATE_UNREADABLE,
    ReadRequest,
    RouterMap,
)

DAY = 86_400.0
MARK_KEYS = {
    "id",
    "ts",
    "source",
    "kind",
    "group",
    "severity",
    "router_id",
    "router_name",
    "fleet",
    "title_key",
    "text",
    "params",
    "ref",
    "derived",
    # additive in 1.51.0 (Phases B/C): None on the Phase A sources
    "code",
    "end",
    "end_state",
    "client",
    "client_name",
    "peers",
    # additive in 1.51.0: False on the Phase A sources
    "spans_in",
}
REF_KEYS = {"module", "type", "id", "version_id"}


@pytest.fixture
def core_disks():
    with FakeDisks().patch() as fake:
        yield fake


def request(
    since: float, until: float, *, admin: bool = True, now: float | None = None
) -> ReadRequest:
    return ReadRequest(since, until, admin, until if now is None else now)


async def read(
    hass: Any, source: str, req: ReadRequest, routers: RouterMap | None = None
) -> src.SourceResult:
    if routers is None:
        routers = src.build_router_map(hass)
    return await src.async_read_source(hass, source, req, routers)


def assert_mark_shape(mark: dict[str, Any]) -> None:
    assert set(mark) == MARK_KEYS
    assert set(mark["ref"]) == REF_KEYS
    assert mark["id"].startswith("tmm_") and len(mark["id"]) == 20
    assert mark["kind"] in src.KINDS
    assert mark["group"] == src.KIND_GROUP[mark["kind"]]
    assert mark["severity"] in src.SEVERITIES
    assert mark["derived"] is False
    assert len(mark["params"]) <= src.PARAMS_MAX
    assert all(isinstance(v, int | float) for v in mark["params"].values())
    assert mark["router_id"] is None or mark["router_id"].startswith("rtr_")


def assert_sorted(marks: list[dict[str, Any]]) -> None:
    keys = [(-m["ts"], m["id"]) for m in marks]
    assert keys == sorted(keys)


# --- vocabulary and helpers -------------------------------------------------------------


def test_vocabulary_is_fixed_and_consistent() -> None:
    assert src.SOURCE_IDS == (
        "core_audit",
        "config_versions",
        "ni_events",
        "ni_incidents",
        "security_timeline",
    )
    assert set(src.READERS) == set(src.ALL_SOURCE_IDS)
    assert src.SEVERITIES == ("info", "warning", "critical")
    assert len(set(src.KINDS)) == len(src.KINDS)
    groups = set(src.KIND_GROUP.values())
    assert src.NON_ADMIN_GROUPS <= groups
    assert not {"configuration", "security", "administration", "clients"} & set(
        src.NON_ADMIN_GROUPS
    )
    for kind in ("client_session", "client_roam", "client_disconnect"):
        assert src.KIND_GROUP[kind] == "clients"


def test_mark_ids_are_stable_and_distinct() -> None:
    one = src.mark_id("ni_events", "e1:5")
    assert one == src.mark_id("ni_events", "e1:5")
    assert one != src.mark_id("ni_events", "e1:6")
    assert one != src.mark_id("core_audit", "e1:5")
    assert one != src.mark_id("ni_events", "e1:5", "x")
    assert one.startswith("tmm_") and len(one) == 20


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Router e1", "Router e1"),
        ("gw-office", "gw-office"),
        ("192.168.1.1", None),
        ("fd00::1", None),
        ("[fd00::1]", None),
        ("02:00:5e:00:00:01", None),
        ("", None),
        ("x" * 65, None),
        (None, None),
    ],
)
def test_display_name_drops_addresses(title: Any, expected: Any) -> None:
    assert src.display_name(title) == expected


def test_params_keep_numbers_only() -> None:
    params = src.params_of(
        {"changes": 3, "flag": True, "name": "lan", "gap_s": 12.34567, "nan": 1e999},
        ("changes", "flag", "name", "gap_s", "nan", "missing"),
    )
    assert params == {"changes": 3, "gap_s": 12.346}
    assert src.params_of({"routers": ["e1", "e2"]}, ("routers",)) == {"routers": 2}
    many = {f"k{i}": i for i in range(20)}
    assert len(src.params_of(many, list(many))) == src.PARAMS_MAX


def test_masked_text_hides_identities() -> None:
    text = src.masked_text(
        "Client 02:00:5E:10:00:01 at 192.0.2.10 password=hunter2 seen"
    )
    assert text is not None
    for secret in ("02:00:5E:10:00:01", "02:00:5e:10:00:01", "192.0.2.10", "hunter2"):
        assert secret not in text
    assert src.masked_text("") is None and src.masked_text(None) is None
    assert len(src.masked_text("a" * 500) or "") <= src.TEXT_MAX


# --- contract with the real source classes (public read side only) -----------------------


def test_contract_public_read_side_of_the_source_classes() -> None:
    """The adapters read only these public names; a rename fails here."""
    events = inspect.signature(ConfigurationApi.events).parameters
    assert {"since", "ring", "limit"} <= set(events)
    backups = inspect.signature(ConfigurationApi.async_list_backups).parameters
    assert {"since", "limit"} <= set(backups)
    assert callable(RouterRegistry.router_id_for_entry)
    assert isinstance(inspect.getattr_static(NetIntelligence, "loaded"), property)
    assert isinstance(inspect.getattr_static(SecurityCenter, "enabled"), property)
    assert callable(SecurityCenter.overview)
    init = inspect.getsource(EnterpriseCore.__init__)
    for name in ("self.registry", "self.loaded", "self.closed"):
        assert name in init, name


async def test_router_map_converts_entry_ids_through_the_registry(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, routers=2, options={})
    env.entries[1].title = "192.168.1.2"  # an address is no display name
    routers = src.build_router_map(env.hass)
    assert routers.by_entry == {"e1": env.rids[0], "e2": env.rids[1]}
    assert routers.name_of(env.rids[0]) == "Router e1"
    assert routers.name_of(env.rids[1]) is None
    assert routers.router_of_entry("unknown") is None
    assert routers.router_of_entry(None) is None
    await stop(env)
    assert src.build_router_map(env.hass) == RouterMap()


# --- core audit, configuration versions, security timeline (case 08 scenario) -----------


async def drift_env(core_disks: Any, tmp_path: Any) -> tuple[Any, Any]:
    env = await cm_env(
        core_disks, tmp_path, options=NO_SCHEDULE, provider=AreaProvider()
    )
    center = await _core_center(env, FakeDisk())
    with patch.object(core_audit, "utcnow", env.clock.utc):
        await env.runtime.async_backup_now(env.rid, actor=ADMIN)
        env.coords[env.rid].poll()
        await _drifted_poll(env, 1)
        env.clock.advance(seconds=301)
        await env.tick()
        await drain(env.hass)
    assert env.core.audit.events(types=[CoreEventType.DRIFT_DETECTED.value])
    return env, center


async def close(env: Any) -> None:
    await stop(env)
    await async_release_security_center(env.hass, env.entries[0].entry_id)


def window(env: Any) -> tuple[float, float]:
    now = env.clock.utc().timestamp()
    return now - DAY, now + 1


async def test_core_audit_adapter_reads_real_audit_entries(
    core_disks, tmp_path
) -> None:
    env, _center = await drift_env(core_disks, tmp_path)
    since, until = window(env)
    result = await read(env.hass, "core_audit", request(since, until))
    assert result.state == STATE_OK and result.reason is None
    for mark in result.marks:
        assert_mark_shape(mark)
        assert mark["source"] == "core_audit"
        assert mark["text"] is None and mark["ref"]["module"] == "core_audit"
        assert since <= mark["ts"] < until
    assert_sorted(result.marks)
    by_key = {m["title_key"]: m for m in result.marks}
    drift = by_key["core_audit.configuration.drift_detected"]
    assert drift["kind"] == "config_drift" and drift["group"] == "configuration"
    assert drift["router_id"] == env.rid and drift["router_name"] == "Router e1"
    assert drift["params"]["changes"] >= 1
    baseline = await env.api.async_list_backups(env.rid, limit=5)
    assert drift["ref"]["version_id"] in {r.backup_id for r in baseline}
    assert by_key["core_audit.configuration.backup_created"]["kind"] == "config_event"
    sec = [
        m
        for m in result.marks
        if m["title_key"].startswith("core_audit.security_center.")
    ]
    assert sec and all(m["kind"] == "security_incident" for m in sec)
    assert result.oldest == result.marks[-1]["ts"]
    body = json.dumps(result.marks)
    assert "10.0.1.1" not in body and "192.168.1.1" not in body
    await close(env)


async def test_core_audit_is_newest_first_and_cut_to_the_window(
    core_disks, tmp_path
) -> None:
    """``api.events`` sorts oldest first and has no ``until``: cut here."""
    env = await cm_env(core_disks, tmp_path, options={})
    base = env.clock.utc()
    for i in range(10):
        env.core.audit.emit(
            CoreEventType.ROUTER_CAPABILITIES_CHANGED,
            router_id=env.rid,
            now=base + timedelta(minutes=i),
            dedup_key=f"k{i}",
        )
    raw = env.api.events(since=base, limit=50)
    assert [e.ts for e in raw] == sorted(e.ts for e in raw)  # ascending, see doc
    since = base.timestamp() + 120  # minutes 2..5
    until = base.timestamp() + 360
    result = await read(env.hass, "core_audit", request(since, until))
    caps = [m for m in result.marks if m["kind"] == "registry_event"]
    assert [m["ts"] for m in caps] == [base.timestamp() + 60 * i for i in (5, 4, 3, 2)]
    assert_sorted(result.marks)
    await stop(env)


async def test_core_audit_reads_the_ring_whole_and_omits_client_entries(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    base = env.clock.utc()
    env.api.register_event_prefix("wifi_rf.", module="wifi_rf")
    for i in range(520):  # more than the old read limit of 500
        env.core.audit.emit(
            "wifi_rf.channel_changed",
            source="wifi_rf",
            router_id=env.rid,
            dedup_key=f"c{i}",
            now=base + timedelta(seconds=i),
        )
    for i in range(3):
        env.core.audit.emit(
            "wifi_rf.client_steered",
            source="wifi_rf",
            router_id=env.rid,
            dedup_key=f"s{i}",
            client_ref="cli_" + f"{i:016x}",
            now=base + timedelta(seconds=600 + i),
        )
    since, until = base.timestamp(), base.timestamp() + 3600
    result = await read(env.hass, "core_audit", request(since, until))
    # the ring is read whole (the read limit is above its capacity, 1.50.0
    # review S2): nothing cut, client entries counted, not shown
    assert src.AUDIT_READ_LIMIT > core_audit.AUDIT_MAX_EVENTS
    assert result.truncated is False and result.unreachable is False
    assert result.omitted_client == 3
    assert "cli_" not in json.dumps(result.marks)
    rf = [m for m in result.marks if m["kind"] == "rf_event"]
    assert len(rf) == 520
    # with a read limit below the ring (patched) the read is cut at its
    # oldest entry of the window
    with patch.object(src, "AUDIT_READ_LIMIT", 100):
        cut = await read(env.hass, "core_audit", request(since, until))
    assert cut.truncated is True and cut.edge == min(m["ts"] for m in cut.marks)
    await stop(env)


async def test_config_versions_adapter_reads_real_versions(
    core_disks, tmp_path
) -> None:
    env, _center = await drift_env(core_disks, tmp_path)
    since, until = window(env)
    result = await read(env.hass, "config_versions", request(since, until))
    versions = await env.api.async_list_backups(limit=50)
    assert result.state == STATE_OK
    assert len(result.marks) == len(versions) >= 1
    for mark in result.marks:
        assert_mark_shape(mark)
        assert mark["kind"] == "config_version" and mark["text"] is None
        assert mark["ref"]["version_id"] == mark["ref"]["id"]
        assert mark["router_id"] == env.rid
    assert {m["ref"]["id"] for m in result.marks} == {v.backup_id for v in versions}
    assert result.marks[-1]["title_key"].startswith("config_versions.manual.")
    await close(env)


async def test_config_versions_off_without_backups_and_for_non_admins(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    since, until = window(env)
    off = await read(env.hass, "config_versions", request(since, until))
    assert (off.state, off.reason) == (STATE_OFF, REASON_MODULE_OFF)
    env.entries[0].options[OPTION_CONFIG_BACKUP_ENABLED] = True
    plain = await read(env.hass, "config_versions", request(since, until, admin=False))
    assert (plain.state, plain.reason) == (STATE_OFF, REASON_ADMIN_ONLY)
    audit = await read(env.hass, "core_audit", request(since, until, admin=False))
    assert (audit.state, audit.reason) == (STATE_OFF, REASON_ADMIN_ONLY)
    empty = await read(env.hass, "config_versions", request(since, until))
    assert (empty.state, empty.reason, empty.marks) == (STATE_EMPTY, None, [])
    await stop(env)


async def test_security_timeline_adapter_reads_the_real_center(
    core_disks, tmp_path
) -> None:
    env, center = await drift_env(core_disks, tmp_path)
    assert center.timeline, "the scenario must write the center's timeline"
    since, until = window(env)
    for admin in (True, False):
        result = await read(
            env.hass, "security_timeline", request(since, until, admin=admin)
        )
        assert result.state == STATE_OK
        kinds = {m["kind"] for m in result.marks}
        assert "config_drift" in kinds
        for mark in result.marks:
            assert_mark_shape(mark)
            assert mark["ref"]["module"] == "security_center"
            assert mark["text"] is None or len(mark["text"]) <= src.TEXT_MAX
        assert_sorted(result.marks)
        body = json.dumps(result.marks, ensure_ascii=False)
        assert "10.0.1.1" not in body and "cli_" not in body
    again = await read(env.hass, "security_timeline", request(since, until))
    assert [m["id"] for m in again.marks] == [m["id"] for m in result.marks]
    await close(env)


async def test_security_timeline_off_unreadable_and_client_entries(
    core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options=NO_SCHEDULE)
    since, until = window(env)
    missing = await read(env.hass, "security_timeline", request(since, until))
    assert (missing.state, missing.reason) == (STATE_UNREADABLE, REASON_NOT_RUNNING)
    center = await _core_center(env, FakeDisk(), enabled=False)
    off = await read(env.hass, "security_timeline", request(since, until))
    assert (off.state, off.reason) == (STATE_OFF, REASON_MODULE_OFF)
    await center.async_update_settings({"enabled": True}, actor=ADMIN)
    now = env.clock.utc().timestamp()
    center._timeline(
        now,
        "notice",
        category="device",
        severity="warning",
        router_id=env.rid,
        text="Neues Gerät",
        client="02:00:5E:10:00:01",
    )
    center._timeline(
        now,
        "status",
        category="system",
        severity="info",
        router_id=None,
        text="Status: resolved 192.0.2.7",
    )
    result = await read(env.hass, "security_timeline", request(since, now + 1))
    assert result.omitted_client == 1
    [mark] = [m for m in result.marks if m["title_key"].endswith(".status")]
    assert mark["fleet"] is True and mark["router_id"] is None
    assert mark["kind"] == "security_incident"
    assert "192.0.2.7" not in (mark["text"] or "")
    with patch.object(center, "overview", return_value={"timeline": "x"}):
        bad = await read(env.hass, "security_timeline", request(since, now + 1))
    assert (bad.state, bad.reason) == (STATE_UNREADABLE, REASON_BAD_FORMAT)
    await close(env)


# --- network intelligence (AK1 scenario with the real outage tracker) ------------------


GUEST = "02:00:5E:30:00:01"
RID_OF = {G: "rtr_" + "a" * 32, A: "rtr_" + "b" * 32, B: "rtr_" + "c" * 32}
NI_ROUTERS = RouterMap(dict(RID_OF), {RID_OF[G]: "Gateway", RID_OF[A]: None})


def ak1(f: Any) -> NetIntelligence:
    """AP A loses 20 clients, its uplink port and then itself; it returns."""
    log = Log()
    clients = [client(mac) for mac in CLIENTS20]
    for n in range(3):
        gw_poll(f, T0 + 60 * n)
        feed(f, A, T0 + 60 * n + 20, rdata(A, clients=clients, trunk=AP_TRUNK))
        feed(f, B, T0 + 60 * n + 40, rdata(B, clients=[], trunk=AP_TRUNK))
    # a client with a wrong key on B: client events, a client incident
    for k in range(3):  # three wrong-key attempts: a client incident
        at = 165 + 30 * k
        wrong = log.lines((at, mic(GUEST)), (at + 0.2, psk(GUEST)))
        feed(
            f,
            B,
            T0 + at + 20,
            rdata(B, events=wrong, clients=[client(GUEST)], trunk=AP_TRUNK),
        )
    lines = log.lines(*((200 + i / 10, disc(mac)) for i, mac in enumerate(CLIENTS20)))
    feed(f, A, T0 + 200, rdata(A, events=lines, clients=[], trunk=AP_TRUNK))
    gw_poll(f, T0 + 240, lan3=False)
    f.clock.now = T0 + 380
    f.h.tracker.report_down(A, ERROR_TYPE_TIMEOUT, dt(T0 + 260))
    gw_poll(f, T0 + 420, lan3=False)
    f.clock.now = T0 + 470
    f.h.fire_timer()
    f.clock.now = T0 + 600
    f.h.tracker.report_up(A)
    intel: NetIntelligence = f.intel
    intel.hass.data[net_engine._DATA_KEY] = intel  # what async_get_engine reads
    return intel


SECRETS = (
    *CLIENTS20,
    *(m.lower() for m in CLIENTS20),
    GUEST,
    GUEST.lower(),
    *HOST.values(),
    *MAC.values(),
)


def assert_private(marks: list[dict[str, Any]]) -> None:
    body = json.dumps(marks)
    for needle in (*SECRETS, "phy0", "phy1", '"gw"', '"ap1"', "ap1:", "gw:"):
        assert needle not in body, needle


async def test_ni_events_adapter_reads_the_real_engine(fleet) -> None:  # noqa: F811
    intel = ak1(fleet)
    req = request(T0 - 10, T0 + 700)
    result = await read(intel.hass, "ni_events", req, NI_ROUTERS)
    assert result.state == STATE_OK
    kinds = {m["kind"] for m in result.marks}
    assert {"router_down", "router_up"} <= kinds
    for mark in result.marks:
        assert_mark_shape(mark)
        assert mark["ref"] == {
            "module": "network_intelligence",
            "type": "event",
            "id": None,
            "version_id": None,
        }
    down = next(m for m in result.marks if m["kind"] == "router_down")
    assert down["router_id"] == RID_OF[A] and down["router_name"] is None
    assert down["title_key"] == "ni_events.system.router_unreachable"
    # client events (one per station) are left out and counted
    with_mac = [
        e for e in intel.ring if "mac" in e.subject and req.since <= e.ts < req.until
    ]
    assert result.omitted_client == len(with_mac) > 0
    assert_sorted(result.marks)
    assert_private(result.marks)


async def test_ni_incidents_adapter_marks_open_and_resolve(fleet) -> None:  # noqa: F811
    intel = ak1(fleet)
    result = await read(
        intel.hass, "ni_incidents", request(T0 - 10, T0 + 700), NI_ROUTERS
    )
    assert result.state == STATE_OK
    outage = [
        m for m in result.marks if m["title_key"] == "ni_incidents.router_unreachable"
    ]
    assert [m["kind"] for m in outage] == ["incident_resolved", "incident_opened"]
    assert outage[1]["ts"] == T0 + 260 and outage[0]["ts"] == T0 + 600
    assert all(m["router_id"] == RID_OF[A] for m in outage)
    assert outage[0]["ref"]["id"] == outage[1]["ref"]["id"]
    assert outage[0]["ref"]["id"].startswith("inc-")
    # the wrong-key incident is about a client: left out, counted
    assert result.omitted_client == 1
    assert not [m for m in result.marks if "auth_failures" in m["title_key"]]
    mass = [
        m for m in result.marks if m["title_key"] == "ni_incidents.wifi_mass_disconnect"
    ]
    assert mass and mass[0]["params"].get("affected") == 20
    for mark in result.marks:
        assert_mark_shape(mark)
    assert_private(result.marks)
    # a window before the outage holds none of its marks
    early = await read(
        intel.hass, "ni_incidents", request(T0 - 10, T0 + 100), NI_ROUTERS
    )
    assert early.state == STATE_EMPTY and early.marks == []


async def test_ni_sources_not_running_and_not_loaded() -> None:
    hass = make_hass()
    req = request(T0, T0 + 60)
    for source in ("ni_events", "ni_incidents"):
        result = await read(hass, source, req, RouterMap())
        assert (result.state, result.reason) == (STATE_UNREADABLE, REASON_NOT_RUNNING)
    engine = NetIntelligence(hass)
    hass.data[net_engine._DATA_KEY] = engine
    assert not engine.loaded
    result = await read(hass, "ni_events", req, RouterMap())
    assert (result.state, result.reason) == (STATE_UNREADABLE, REASON_NOT_LOADED)


# --- failures stay inside their source -----------------------------------------------


async def test_a_raising_slow_or_odd_reader_is_unreadable(caplog) -> None:
    hass = make_hass()
    req = request(T0, T0 + 60)

    async def boom(*_a: Any) -> Any:
        raise RuntimeError("02:00:5E:10:00:01 secret")

    async def slow(*_a: Any) -> Any:
        await asyncio.sleep(5)

    async def odd(*_a: Any) -> Any:
        return {"marks": []}

    async def other(*_a: Any) -> Any:
        return src.SourceResult("ni_events", STATE_OK)

    readers = {
        "core_audit": boom,
        "ni_events": slow,
        "ni_incidents": odd,
        "config_versions": other,
    }
    expected = {
        "core_audit": REASON_ERROR,
        "ni_events": REASON_TIMEOUT,
        "ni_incidents": REASON_BAD_FORMAT,
        "config_versions": REASON_BAD_FORMAT,
    }
    with caplog.at_level("DEBUG"):
        for source, reason in expected.items():
            result = await src.async_read_source(
                hass, source, req, RouterMap(), budget=0.05, readers=readers
            )
            assert (result.source, result.state, result.reason) == (
                source,
                STATE_UNREADABLE,
                reason,
            )
    assert "RuntimeError" in caplog.text and "secret" not in caplog.text
    assert "02:00:5E" not in caplog.text


async def test_the_deadline_also_stops_a_loop_without_awaits(fleet) -> None:  # noqa: F811
    intel = ak1(fleet)
    result = await src.async_read_source(
        intel.hass, "ni_events", request(T0 - 10, T0 + 700), NI_ROUTERS, budget=-1
    )
    assert (result.state, result.reason) == (STATE_UNREADABLE, REASON_TIMEOUT)


async def test_core_sources_unreadable_without_a_core() -> None:
    hass = make_hass([FakeEntry("e1", options={OPTION_CONFIG_BACKUP_ENABLED: True})])
    req = request(T0, T0 + 60)
    for source in ("core_audit", "config_versions"):
        result = await read(hass, source, req, RouterMap())
        assert (result.state, result.reason) == (STATE_UNREADABLE, REASON_NOT_RUNNING)
