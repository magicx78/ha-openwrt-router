"""Network diagnostics run time and store (release 1.47.0, part 1).

diag_runtime.py (life cycle, passive poll evaluation, guarded HA probes) and
diag_store.py (bounded history). Mocks only: the store runs on the in-memory
fakes of ``test_net_engine``, the enterprise core on FakeDisks
(``config_manager_kit``). Probes go to loopback servers through a test
``DiagTransport``; the conftest network guard stays in force. Addresses are
documentation / test values.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncIterator
from dataclasses import replace
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from config_manager_kit import cm_env, drain, stop
from core_test_provider import short_tmp_path  # noqa: F401 - short tmp_path
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, make_hass, user_actor
from test_client_engine import data as ni_data
from test_client_engine import setup as ni_setup
from test_diag_scheduler import Env, Stubborn, diag_tasks
from test_net_engine import FakeDisk, FakeStore

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import (
    client_engine,
    dhcp_health,
    diag_runtime,
    diag_store,
    net_engine,
)
from custom_components.openwrt_router.api import DiagTransport, diag_interface_facts
from custom_components.openwrt_router.const import (
    DATA_NET_DIAGNOSTICS,
    DIAG_SAVE_DELAY_SECONDS,
)
from custom_components.openwrt_router.core_errors import (
    ConfigApiError,
    ErrorClass,
    SafetyRefusedError,
)
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.diag_baseline import (
    METRIC_LATENCY,
    METRIC_LOSS,
)
from custom_components.openwrt_router.diag_core import (
    ACTION_RUN_MANUAL,
    EVENT_FINDING,
    EVENT_GATEWAY_CHANGED,
    EVENT_MANUAL_RUN,
    new_correlation_id,
    series_key,
)
from custom_components.openwrt_router.diag_model import (
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Stage,
)
from custom_components.openwrt_router.diag_runtime import (
    JOB_MANUAL,
    JOB_PERIODIC,
    WAN_KIND,
    WAN_TARGET,
    DiagSettingsError,
    NetDiagnostics,
    async_get_net_diagnostics,
    async_release_net_diagnostics,
    async_setup_net_diagnostics,
    default_settings,
    merge_settings,
    parse_settings,
    probe_sample,
)
from custom_components.openwrt_router.diag_scheduler import (
    DiagJob,
    Outcome,
    RequestStatus,
)
from custom_components.openwrt_router.diag_stats import Sample, SeriesKey
from custom_components.openwrt_router.diag_store import (
    GAP_HA_RESTART,
    GAP_ROUTER_RESTART,
    DiagHistory,
)

T0 = 1_800_000_000.0
RID1 = "rtr_" + "1" * 32
RID2 = "rtr_" + "2" * 32
RIDS = {"r1": RID1, "r2": RID2}
MODULE_KEY = bytes(range(32))
ADMIN = user_actor(ADMIN_ID)
PLAIN = user_actor(USER_ID)
GLOBAL_IP = "9.9.9.9"
SECRETS = ("192.0.2.", "203.0.113.", GLOBAL_IP, "example.org")


# --- helpers -----------------------------------------------------------------------


class Clock:
    def __init__(self, now: float = T0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def disk() -> Any:
    """The diagnostics store 'file'; the scheduler loop as a plain task."""
    found = FakeDisk()
    found.path = "/nonexistent/.storage/openwrt_router.net_diagnostics"
    with (
        patch.object(diag_store, "Store", lambda *a, **kw: FakeStore(found, *a, **kw)),
        patch.object(diag_runtime, "_default_task_factory", lambda hass: None),
    ):
        yield found


@pytest.fixture
def ni_disks() -> Any:
    found: dict[str, FakeDisk] = {}

    def store(*args: Any, **kw: Any) -> FakeStore:
        return FakeStore(found.setdefault(args[2], FakeDisk()), *args, **kw)

    with (
        patch.object(net_engine, "Store", store),
        patch.object(client_engine, "Store", store),
    ):
        yield found


@pytest.fixture
def core_disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def run_delayed(found: FakeDisk) -> None:
    """What Home Assistant does once the save delay passed."""
    func, delay = found.delayed[-1]
    assert delay == DIAG_SAVE_DELAY_SECONDS
    found.delayed.clear()
    found.data = json.loads(json.dumps(func()))
    found.saves.append(found.data)


def dump(*, wan_up: bool = True, gw: str = "192.0.2.1") -> list[dict[str, Any]]:
    return [
        {
            "interface": "lan",
            "up": True,
            "proto": "static",
            "dns-server": ["192.0.2.54"],
        },
        {
            "interface": "wan",
            "up": wan_up,
            "proto": "dhcp",
            "route": [{"target": "0.0.0.0", "mask": 0, "nexthop": gw}],
            "dns-server": ["192.0.2.53"],
        },
    ]


def wan_status(
    *, connected: bool = True, facts: bool = True, gw: str = "192.0.2.1"
) -> dict[str, Any]:
    status: dict[str, Any] = {
        "connected": connected,
        "interface": "wan",
        "ipv4": "203.0.113.7",
        "uptime": 100,
        "proto": "dhcp",
        "wan_found": True,
    }
    if facts:
        interfaces = dump(wan_up=connected, gw=gw)
        status["diag_facts"] = diag_interface_facts(interfaces, interfaces[1])
    return status


POOLS = [
    {"name": "lan", "interface": "lan", "size": 150, "leases": 12, "usage_pct": 8.0},
    {
        "name": "guest",
        "interface": "guest",
        "size": 50,
        "leases": 45,
        "usage_pct": 90.0,
    },
]


class Coord:
    def __init__(self) -> None:
        self.data = SimpleNamespace(uptime=5000, wan_status=wan_status(), dhcp_pools=[])
        self.last_update_success = True


async def make_diag(
    hass: Any,
    *entries: str,
    clock: Clock | None = None,
    enabled: bool | None = True,
    settings: dict[str, Any] | None = None,
    activate: bool = True,
) -> NetDiagnostics:
    """A module with the router ids of RIDS (no core needed for them).

    ``enabled`` None keeps the stored settings.
    """
    clock = clock or Clock()
    diag = NetDiagnostics(hass)
    diag.router_id_of = RIDS.get
    diag.clock = clock
    diag.store.clock = clock
    hass.data[DATA_NET_DIAGNOSTICS] = diag
    await diag.async_load()
    for entry in entries:
        diag.add_entry(entry, Coord())
    update = dict(settings or {})
    if enabled is not None:
        update["enabled"] = enabled
    if update:
        diag.store.settings = merge_settings(diag.settings, update)
        diag._rebuild_registry()
    if activate and diag.enabled:
        await diag.async_activate()
    return diag


def poll(
    diag: NetDiagnostics,
    entry: str,
    now: float,
    *,
    uptime: int | None = None,
    success: bool = True,
    interval: float = 60.0,
    **data: Any,
) -> None:
    coord = diag._entries[entry]
    coord.last_update_success = success
    if uptime is not None:
        coord.data.uptime = uptime
    for name, value in data.items():
        setattr(coord.data, name, value)
    diag.on_poll(SimpleNamespace(router=entry, now=now, interval=interval))


def wan_key(rid: str = RID1) -> SeriesKey:
    return series_key(rid, WAN_TARGET, WAN_KIND, "ipv4")


def target(tid: str, kind: str, port: int | None, **kw: Any) -> dict[str, Any]:
    return {
        "id": tid,
        "kind": kind,
        "scope": "external",
        "host": GLOBAL_IP,
        "port": port,
        "confirmed": True,
        **kw,
    }


@contextlib.asynccontextmanager
async def tcp_server(reply: bytes | None = None) -> AsyncIterator[int]:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        if reply is not None:
            with contextlib.suppress(Exception):
                await reader.readuntil(b"\r\n\r\n")
                writer.write(reply)
                await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1]
    finally:
        server.close()
        await server.wait_closed()


def loopback(ports: dict[int, int], seen: list[Any]) -> DiagTransport:
    async def open_connection(host: str, port: int, **kw: Any) -> Any:
        seen.append((host, port))
        if port not in ports:
            raise TimeoutError  # no answer (without waiting for it)
        return await asyncio.open_connection("127.0.0.1", ports[port])

    return DiagTransport(open_connection=open_connection, getaddrinfo=AsyncMock())


# --- settings -------------------------------------------------------------------------


def test_defaults_are_off_and_settings_are_strict_or_tolerant() -> None:
    settings = default_settings()
    assert settings["enabled"] is False and settings["periodic"] is False
    assert settings["targets"] == [] and settings["interval_s"] == 300
    for bad in (
        {"enabled": "yes"},
        {"interval_s": 59},
        {"interval_s": True},
        {"unknown": 1},
        {"http_path": "http://x/"},
        {"targets": [target("t1", "tcp", None)]},  # TCP needs a port
        {"targets": [target("t1", "tcp", 1), target("t1", "tcp", 2)]},
        {"targets": [{**target("t1", "tcp", 1), "host": "127.0.0.1"}]},
        {"internal_networks": ["not a net"]},
    ):
        with pytest.raises(DiagSettingsError):
            merge_settings(default_settings(), bad)
    stored = parse_settings(
        {"enabled": "yes", "periodic": True, "interval_s": 5, "targets": "x"}
    )
    assert stored["enabled"] is False  # a broken value is off, never on
    assert stored["periodic"] is True and stored["interval_s"] == 300
    assert stored["targets"] == []


# --- default off ------------------------------------------------------------------------


async def test_module_off_zero_jobs_and_zero_probe_calls(disk, ni_disks) -> None:
    hass = make_hass()
    engine, _cs = await ni_setup(hass, "r1")
    entry = SimpleNamespace(entry_id="r1")
    probe = AsyncMock()
    with (
        patch.object(diag_runtime, "async_diag_probe", probe),
        patch.object(diag_runtime, "async_diag_resolve", probe),
    ):
        diag = await async_setup_net_diagnostics(hass, entry, Coord())
        assert async_get_net_diagnostics(hass) is diag
        assert not diag.active and diag.scheduler is None
        assert diag not in engine._poll_observers
        for k in range(5):
            engine.ingest("r1", ni_data([]), T0 + 60 * k, interval=60.0)
        with pytest.raises(ConfigApiError) as off:
            await diag.async_run_manual(actor=ADMIN)
        assert off.value.error_class is ErrorClass.NOT_AVAILABLE
        status = diag.status()
        await async_release_net_diagnostics(hass, "r1")
    probe.assert_not_called()
    assert diag.counters["polls"] == 0 and diag.counters["probes"] == 0
    assert status["state"] == "off" and status["reasons"] == ["disabled"]
    assert status["load"]["ha"]["packets_per_day"] == 0
    assert status["router_probes"]["state"] == "not_available"
    assert disk.saves == [] and disk.delayed == []  # off: nothing written
    assert async_get_net_diagnostics(hass) is None


async def test_enabled_without_periodic_or_confirmed_target_has_no_periodic_job(
    disk,
) -> None:
    hass = make_hass()
    unconfirmed = {**target("t1", "tcp", 443), "confirmed": False}
    diag = await make_diag(
        hass, "r1", settings={"periodic": True, "targets": [unconfirmed]}
    )
    assert diag.scheduler is not None and diag.scheduler.running
    assert diag.scheduler.job_status(JOB_MANUAL) is not None  # on demand only
    assert diag.scheduler.job_status(JOB_PERIODIC) is None
    load = diag.load()["ha"]
    assert load["rounds_per_day"] == 0 and load["packets_per_day"] == 0
    assert diag.load()["router"] == {"extra_calls_per_poll": 0, "packets_per_round": 0}
    await diag.async_close()


async def test_periodic_job_needs_confirmed_targets_and_reports_its_load(
    disk,
) -> None:
    hass = make_hass()
    diag = await make_diag(
        hass,
        "r1",
        settings={
            "periodic": True,
            "interval_s": 300,
            "targets": [target("t1", "tcp", 443), target("h1", "http", 80)],
        },
    )
    job = diag.scheduler.job_status(JOB_PERIODIC)
    assert job is not None and job.effective_interval == 300
    load = diag.load()["ha"]
    assert load["probes_per_round"] == 2 and load["packets_per_round"] == 7 + 11
    assert load["rounds_per_day"] == 288 and load["packets_per_day"] == 18 * 288
    assert load["resolver_queries_per_round"] == 0  # IP literals
    diag.store.settings = merge_settings(diag.settings, {"periodic": False})
    await diag._async_sync_jobs()
    assert diag.scheduler.job_status(JOB_PERIODIC) is None
    await diag.async_close()


# --- passive poll evaluation -----------------------------------------------------------


async def test_passive_poll_gives_states_with_reasons_never_ok_by_default(
    disk,
) -> None:
    hass = make_hass()
    clock = Clock()
    diag = await make_diag(hass, "r1", "r2", clock=clock)
    poll(diag, "r1", T0)
    poll(diag, "r2", T0, wan_status=wan_status(facts=False))
    status = diag.status()
    assert status["state"] == "not_ready"
    assert {"core_unavailable", "module_key_missing"} <= set(status["reasons"])
    r1, r2 = status["routers"][RID1], status["routers"][RID2]
    assert r1["state"] == "partial"  # healthy facts only: partially measured
    assert r1["finding"]["classification"] == "partially_measured"
    assert r2 == {**r2, "state": "unknown", "reason": "interface_dump_missing"}
    poll(diag, "r1", T0 + 60, success=False)
    assert diag.status()["routers"][RID1]["reason"] == "poll_failed"
    clock.now = T0 + 4000
    assert diag.status()["routers"][RID2]["reason"] == "stale"
    assert status["ha"]["state"] == "unknown"
    assert status["ha"]["reason"] == "no_confirmed_target"
    assert json.dumps(status).count("192.0.2") == 0
    await diag.async_close()


async def test_wan_down_is_a_problem_but_no_event_without_the_module_key(
    disk,
) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    poll(diag, "r1", T0, wan_status=wan_status(connected=False))
    view = diag.status()["routers"][RID1]
    assert view["state"] == "problem"
    assert view["finding"]["classification"] == "wan_problem"
    assert diag.counters["events_not_ready"] == 1 and diag.counters["events"] == 0
    await diag.async_close()


async def test_case_10_dhcp_pool_usage(disk) -> None:
    """The pool usage of the poll is taken over as is: no second calculation."""
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    with patch.object(dhcp_health, "pool_usage", MagicMock()) as pool_usage:
        poll(diag, "r1", T0, dhcp_pools=[dict(p) for p in POOLS])
    pool_usage.assert_not_called()
    assert diag.status()["routers"][RID1]["dhcp_pools"] == POOLS
    poll(diag, "r1", T0 + 60, dhcp_pools=None)
    assert diag.status()["routers"][RID1]["dhcp_pools"] == []
    await diag.async_close()


async def test_loss_baseline_is_fed_over_the_last_three_rounds(disk) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    seen: list[tuple[str, float]] = []
    real = diag_runtime.observe

    def spy(state: Any, value: Any, **kw: Any) -> Any:
        seen.append((state.metric, value))
        return real(state, value, **kw)

    with patch.object(diag_runtime, "observe", spy):
        for k, up in enumerate((True, False, True, True, True)):
            poll(diag, "r1", T0 + 60 * k, wan_status=wan_status(connected=up))
    losses = [round(v, 1) for m, v in seen if m == METRIC_LOSS]
    assert losses == [0.0, 50.0, 33.3, 33.3, 0.0]
    assert [m for m, _ in seen if m == METRIC_LATENCY] == []  # passive: no rtt
    assert diag.store.history.baseline(wan_key(), METRIC_LOSS) is not None
    await diag.async_close()


async def test_a_failing_stage_or_probe_does_not_break_a_poll(
    disk, caplog: pytest.LogCaptureFixture
) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1", settings={"targets": [target("t1", "tcp", 443)]})
    caplog.set_level(logging.WARNING)
    with patch.object(
        diag_runtime, "evaluate_chain", side_effect=RuntimeError("192.0.2.1")
    ):
        poll(diag, "r1", T0, dhcp_pools=[dict(POOLS[0])])
    assert diag.counters["errors"] == 1 and diag.counters["polls"] == 1
    assert diag.store.history.series[wan_key()].hours  # the WAN stage still ran
    assert diag.status()["routers"][RID1]["dhcp_pools"] == [POOLS[0]]
    # a probe that raises fails its round, never the next poll
    with patch.object(
        diag_runtime, "async_diag_probe", AsyncMock(side_effect=OSError(GLOBAL_IP))
    ):
        diag._manual_plan = (("t1",), new_correlation_id())
        request = diag.scheduler.request_run(JOB_MANUAL)
        result = await request.completion
    assert result.outcome is Outcome.FAILURE and result.error == "OSError"
    poll(diag, "r1", T0 + 60)
    assert diag.counters["polls"] == 2
    assert diag.status()["routers"][RID1]["state"] == "partial"
    for record in caplog.records:
        for secret in SECRETS:
            assert secret not in record.getMessage()
    await diag.async_close()


async def test_an_observer_call_never_raises(disk) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    with patch.object(diag, "_on_poll", side_effect=RuntimeError("x")):
        diag.on_poll(SimpleNamespace(router="r1", now=T0, interval=60.0))
    diag.on_poll(object())  # not even a PollFacts
    assert diag.counters["errors"] == 2
    await diag.async_close()


# --- restarts -------------------------------------------------------------------------


async def test_case_18_router_restart_runtime(disk) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    for k, uptime in enumerate((5000, 5060, 5120)):
        poll(diag, "r1", T0 + 60 * k, uptime=uptime)
    history = diag.store.history
    loss = history.baseline(wan_key(), METRIC_LOSS)
    history.set_baseline(replace(loss, above=2, below=1))
    # the router rebooted: uptime went down
    poll(diag, "r1", T0 + 180, uptime=30)
    gaps = [g for g in history.gaps if g["reason"] == GAP_ROUTER_RESTART]
    assert gaps == [
        {
            "start": T0 + 120,
            "end": T0 + 180,
            "reason": GAP_ROUTER_RESTART,
            "point": RID1,
        }
    ]
    assert history.router_memory(RID1)["restarts"] == 1
    after = history.baseline(wan_key(), METRIC_LOSS)
    assert (after.above, after.below) == (0, 0)  # streaks restart
    assert after.mean == loss.mean == 0.0  # the learned baseline is kept
    assert after.learned == loss.learned + 1
    summary = history.summaries(wan_key(), now=T0 + 180)["1h"]
    assert summary.gaps == 1 and summary.lost == 0  # a gap, not a loss
    # the WAN is still coming up while the router settles: no problem event
    poll(diag, "r1", T0 + 240, uptime=90, wan_status=wan_status(connected=False))
    view = diag.status()["routers"][RID1]
    assert view["state"] == "settling" and view["settling"] is True
    assert view["finding"]["classification"] == "wan_problem"
    assert view["restarts_24h"] == 1
    assert view["score"] is not None
    assert diag.counters["events_not_ready"] == 0
    poll(diag, "r1", T0 + 600, uptime=450)
    assert diag.status()["routers"][RID1]["settling"] is False
    await diag.async_close()


async def test_case_19_home_assistant_restart(disk) -> None:
    hass = make_hass()
    clock = Clock()
    diag = await make_diag(hass, "r1", clock=clock)
    for k in range(4):
        poll(diag, "r1", T0 + 60 * k, uptime=5000 + 60 * k)
    history = diag.store.history
    loss = history.baseline(wan_key(), METRIC_LOSS)
    history.set_baseline(replace(loss, above=2, below=1))
    before = history.summaries(wan_key(), now=T0 + 180)["1h"]
    clock.now = T0 + 200
    await async_release_net_diagnostics(hass, "r1")  # HA stops: final flush
    assert disk.saves and disk.saves[-1]["saved_at"] == T0 + 200
    # HA is down for 10 minutes, then starts again on the same store
    clock.now = T0 + 800
    diag2 = await make_diag(hass, "r1", clock=clock, enabled=None, activate=False)
    assert diag2.enabled  # the stored settings keep it on
    await diag2.async_activate()
    history2 = diag2.store.history
    assert set(history2.series) == {wan_key()}  # history restored
    assert history2.router_memory(RID1)["last_uptime"] == 5180
    gaps = [g for g in history2.gaps if g["reason"] == GAP_HA_RESTART]
    assert gaps == [
        {"start": T0 + 200, "end": T0 + 800, "reason": GAP_HA_RESTART, "point": None}
    ]
    restored = history2.baseline(wan_key(), METRIC_LOSS)
    assert (restored.above, restored.below) == (0, 0)  # counters restart
    assert restored.mean == loss.mean and restored.learned == loss.learned
    after = history2.summaries(wan_key(), now=T0 + 800)["1h"]
    assert after.gaps == before.gaps + 1 and after.lost == before.lost
    # one gap per restart, not per activation
    await diag2.async_deactivate()
    await diag2.async_activate()
    assert len([g for g in history2.gaps if g["reason"] == GAP_HA_RESTART]) == 1
    poll(diag2, "r1", T0 + 860, uptime=5900)
    assert history2.router_memory(RID1)["restarts"] == 0  # uptime went up
    await diag2.async_close()


async def test_damaged_store_starts_empty_and_counts(disk) -> None:
    disk.data = {
        "settings": {"enabled": True},
        "history": {
            "series": [{"key": ["ha"], "since": "x"}, 7],
            "baselines": [{"key": "bad"}],
            "routers": {RID1: "bad"},
            "gaps": [{"reason": "nope"}],
        },
        "saved_at": T0,
    }
    hass = make_hass()
    diag = await make_diag(hass, "r1", enabled=None, activate=False)
    counters = diag.store.history.counters
    assert diag.enabled and diag.store.loaded and not diag.store.load_failed
    assert counters["series_damaged"] == 2
    assert counters["baselines_damaged"] == 1 and counters["routers_damaged"] == 1
    assert diag.store.history.series == {} and diag.store.history.gaps == []
    disk.data = None
    disk.load_error = ValueError("broken")
    other = NetDiagnostics(make_hass())
    await other.async_load()
    assert other.store.load_failed and not other.enabled
    await diag.async_close()


# --- store bounds -----------------------------------------------------------------------


def test_store_quota_and_eviction_counted() -> None:
    history = DiagHistory(
        max_points=1, max_series_ha=2, max_series_router=1, max_hours=2, max_gaps=2
    )

    def key(point: str, tid: str) -> SeriesKey:
        return SeriesKey(point, tid, "tcp", "ipv4")

    assert history.record(key(RID1, "a"), Sample.answered(T0, 5.0))
    # a full router point refuses NEW series of that point only
    assert not history.record(key(RID1, "b"), Sample.answered(T0, 5.0))
    assert history.point_refusals == {RID1: 1}
    # a further router point is refused, the known one is never evicted
    assert not history.record(key(RID2, "a"), Sample.answered(T0, 5.0))
    assert history.counters["points_refused"] == 1
    # the HA point has its own quota
    assert history.record(key("ha", "a"), Sample.answered(T0, 5.0))
    assert history.record(key("ha", "b"), Sample.answered(T0, 5.0))
    assert not history.record(key("ha", "c"), Sample.answered(T0, 5.0))
    assert history.series_count("ha") == 2 and history.series_count(RID1) == 1
    assert history.counters["series_refused"] == 2
    # the existing series keep recording
    assert history.record(key(RID1, "a"), Sample.lost(T0 + 60))
    # out of order: dropped and counted
    assert not history.record(key(RID1, "a"), Sample.answered(T0 + 30, 5.0))
    assert history.counters["samples_out_of_order"] == 1
    # hour cap (normally 7 days): the oldest hour is folded, then dropped
    for hour in range(1, 4):
        history.record(key(RID1, "a"), Sample.answered(T0 + 3600 * hour, 5.0))
    assert len(history.series[key(RID1, "a")].hours) == 2
    assert history.counters["hours_dropped"] == 2
    # restart gap records are bounded
    for n in range(3):
        history.mark_restart(start=T0 + n, end=T0 + 4 * 3600 + n, reason=GAP_HA_RESTART)
    assert len(history.gaps) == 2 and history.counters["gaps_dropped"] == 1
    status = history.status()
    assert status["series_refused_per_point"] == {RID1: 1, "ha": 1}
    assert status["counters"]["points_refused"] == 1
    # plain data round trip keeps everything, counters included
    copy = DiagHistory(max_points=1, max_series_ha=2, max_series_router=1)
    copy.restore(json.loads(json.dumps(history.to_dict())))
    assert copy.to_dict() == history.to_dict()


async def test_store_writes_delayed_only_while_on_and_once_at_unload(disk) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    poll(diag, "r1", T0)
    poll(diag, "r1", T0 + 60)
    assert len(disk.delayed) == 1  # one pending delayed write, not one per poll
    run_delayed(disk)
    assert disk.saves[-1]["history"]["series"]
    poll(diag, "r1", T0 + 120)
    await async_release_net_diagnostics(hass, "r1")
    assert len(disk.saves) == 2  # the final flush
    assert json.dumps(disk.saves).count("192.0.2") == 0


# --- forgetting ---------------------------------------------------------------------------


async def test_router_forgotten_applies_the_forget_plan(disk) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1", "r2")
    for k in range(2):
        poll(diag, "r1", T0 + 60 * k, uptime=5000 - 4000 * k)  # with a restart gap
        poll(diag, "r2", T0 + 60 * k)
    ha = series_key(None, "t1", "tcp", "ipv4")
    diag.store.history.record(ha, Sample.answered(T0, 4.0))
    event = {"type": CoreEventType.ROUTER_FORGOTTEN.value, "router_id": RID1}
    diag._on_core_event(event)
    history = diag.store.history
    assert {k.point for k in history.series} == {RID2, "ha"}
    assert all(state.key.point != RID1 for state in history.baselines.values())
    assert RID1 not in history.routers and RID2 in history.routers
    assert all(g["point"] != RID1 for g in history.gaps)
    assert RID1 not in diag.status()["routers"]
    assert history.counters["routers_forgotten"] == 1
    await diag.async_close()


# --- probe samples ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("outcome", "rtt", "reason", "expected"),
    [
        (ProbeOutcome.OK, 5.0, None, "answered"),
        (ProbeOutcome.NXDOMAIN, 5.0, None, "answered"),
        (ProbeOutcome.TIMEOUT, None, "timeout", "lost"),
        (ProbeOutcome.REFUSED, None, "connection_refused", "lost"),
        (ProbeOutcome.SKIPPED, None, "no_query_name", "gap"),
        (ProbeOutcome.ERROR, None, "internal_error", "gap"),
    ],
)
def test_probe_samples(outcome, rtt, reason, expected) -> None:
    dns = outcome is ProbeOutcome.NXDOMAIN
    probe = ProbeResult(
        point=MeasurementPoint.ha(),
        target_id="t1",
        kind=ProbeKind.DNS if dns else ProbeKind.TCP,
        stage=Stage.DNS if dns else Stage.INTERNET,
        family=None,
        outcome=outcome,
        timestamp=T0,
        rtt_ms=rtt,
        evidence={} if reason is None else {"reason": reason},
    )
    assert probe_sample(probe).outcome == expected


# --- wiring in __init__ ----------------------------------------------------------------


async def test_setup_and_unload_survive_a_broken_module(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    entry = SimpleNamespace(
        entry_id="e1", title="router 192.0.2.1", runtime_data=SimpleNamespace()
    )
    with (
        patch.object(
            integration, "_async_setup_entry_sc", AsyncMock(return_value=True)
        ),
        patch.object(
            integration, "_async_unload_entry_sc", AsyncMock(return_value=True)
        ),
        patch.object(
            diag_runtime,
            "async_setup_net_diagnostics",
            AsyncMock(side_effect=RuntimeError("boom 192.0.2.1")),
        ),
        patch.object(
            diag_runtime,
            "async_release_net_diagnostics",
            AsyncMock(side_effect=OSError("disk 192.0.2.1")),
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert await integration.async_setup_entry(hass, entry) is True
        assert await integration.async_unload_entry(hass, entry) is True
    assert "Network diagnostics setup failed (RuntimeError)" in caplog.text
    assert "Network diagnostics release failed (OSError)" in caplog.text
    assert "192.0.2.1" not in caplog.text


async def test_failed_base_setup_does_not_start_the_module() -> None:
    hass = make_hass()
    entry = SimpleNamespace(entry_id="e1", runtime_data=SimpleNamespace())
    setup_mock = AsyncMock()
    release_mock = AsyncMock()
    with (
        patch.object(
            integration, "_async_setup_entry_sc", AsyncMock(return_value=False)
        ),
        patch.object(
            integration, "_async_unload_entry_sc", AsyncMock(return_value=False)
        ),
        patch.object(diag_runtime, "async_setup_net_diagnostics", setup_mock),
        patch.object(diag_runtime, "async_release_net_diagnostics", release_mock),
    ):
        assert await integration.async_setup_entry(hass, entry) is False
        assert await integration.async_unload_entry(hass, entry) is False
    setup_mock.assert_not_called()
    release_mock.assert_not_called()


# --- with the enterprise core -----------------------------------------------------------


async def core_diag(env: Any, *, enabled: bool = False) -> NetDiagnostics:
    """Set the module up for every entry like ``__init__`` does."""
    diag = None
    for entry, coord in zip(env.entries, env.coords.values(), strict=True):
        diag = await async_setup_net_diagnostics(env.hass, entry, coord)
    assert diag is not None
    if enabled:
        await diag.async_update_settings({"enabled": True}, actor=ADMIN)
    return diag


async def release_all(env: Any) -> None:
    for entry in env.entries:
        await async_release_net_diagnostics(env.hass, entry.entry_id)
    await drain(env.hass)
    await stop(env)


def facts(env: Any, now: float) -> Any:
    return SimpleNamespace(router=env.entries[0].entry_id, now=now, interval=60.0)


async def test_off_module_registers_nothing_with_the_core(
    disk, core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    listeners = env.core.audit.listener_count
    diag = await core_diag(env)
    assert not diag.active
    assert env.core.audit.listener_count == listeners
    assert "net_diagnostics" not in env.core.audit.registered_modules()
    await release_all(env)


async def test_settings_need_a_verified_admin(disk, core_disks, tmp_path) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    diag = await core_diag(env)
    listeners = env.core.audit.listener_count
    with pytest.raises(ConfigApiError):
        await diag.async_update_settings({"enabled": True}, actor=PLAIN)
    assert not diag.enabled and not diag.active
    assert env.core.audit.listener_count == listeners  # nothing left bound
    with pytest.raises(ConfigApiError) as bad:
        await diag.async_update_settings({"interval_s": 1}, actor=ADMIN)
    assert bad.value.error_class is ErrorClass.INVALID
    view = await diag.async_update_settings(
        {"enabled": True, "targets": [target("t1", "tcp", 443)]}, actor=ADMIN
    )
    assert diag.active and view["targets"][0] == {
        "id": "t1",
        "kind": "tcp",
        "scope": "external",
        "port": 443,
        "confirmed": True,
        "stage": None,
    }
    assert diag.module_key_available
    status = diag.status()
    assert status["state"] == "not_ready"
    assert status["reasons"] == ["engine_unavailable"]  # no NI in this env
    await diag.async_update_settings({"enabled": False}, actor=ADMIN)
    assert not diag.active and diag.scheduler is None
    await release_all(env)
    assert disk.saves[-1]["settings"]["enabled"] is False


async def test_no_confirmed_external_target_is_a_safety_refusal(
    disk, core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    diag = await core_diag(env, enabled=True)
    probe = AsyncMock()
    with (
        patch.object(diag_runtime, "async_diag_probe", probe),
        patch.object(diag_runtime, "async_diag_resolve", probe),
    ):
        with pytest.raises(SafetyRefusedError) as none:
            await diag.async_run_manual(actor=ADMIN)
        assert none.value.reason == "target.not_confirmed"
        unconfirmed = {**target("t1", "tcp", 443), "confirmed": False}
        await diag.async_update_settings({"targets": [unconfirmed]}, actor=ADMIN)
        with pytest.raises(SafetyRefusedError) as refused:
            await diag.async_run_manual(actor=ADMIN, target_ids=["t1"])
        assert refused.value.reason == "target.not_confirmed"
    probe.assert_not_called()
    runs = env.core.audit.events(types=[EVENT_MANUAL_RUN])
    assert [e.data["status"] for e in runs] == ["refused_target", "refused_target"]
    assert diag.counters["manual_refused"] == 2
    assert diag.scheduler.job_status(JOB_PERIODIC) is None
    await release_all(env)


async def test_e2e_manual_diagnosis_runtime_core_probe(
    disk, core_disks, tmp_path
) -> None:
    """Runtime -> core guard, audit and events -> real api.py probes."""
    env = await cm_env(core_disks, tmp_path, options={})
    diag = await core_diag(env, enabled=True)
    await diag.async_update_settings(
        {"targets": [target("t1", "tcp", 443), target("h1", "http", 80)]},
        actor=ADMIN,
    )
    seen: list[Any] = []
    async with (
        tcp_server() as tcp_port,
        tcp_server(b"HTTP/1.1 204 No Content\r\n\r\n") as http_port,
    ):
        diag.transport = loopback({443: tcp_port, 80: http_port}, seen)
        # a plain user is refused by the guard before any packet
        with pytest.raises(ConfigApiError):
            await diag.async_run_manual(actor=PLAIN)
        assert seen == []
        result = await diag.async_run_manual(actor=ADMIN)
    assert result["status"] == Outcome.SUCCESS.value
    assert [r["outcome"] for r in result["results"]] == ["ok", "ok"]
    assert sorted(seen) == [(GLOBAL_IP, 80), (GLOBAL_IP, 443)]
    assert diag.counters["probes"] == 2 and diag.counters["probe_packets"] == 18
    # audit: refused + accepted manual runs, the guard's grant of the action
    runs = env.core.audit.events(types=[EVENT_MANUAL_RUN])
    assert [e.data["status"] for e in runs] == ["denied", "accepted"]
    assert runs[-1].correlation_id == result["correlation_id"]
    granted = env.core.audit.events(types=["core.active_action_granted"])
    assert any(e.data.get("action") == ACTION_RUN_MANUAL.name for e in granted)
    # HA history: one answered sample per series, latency and loss baselines
    history = diag.store.history
    for tid, kind in (("t1", "tcp"), ("h1", "http")):
        key = series_key(None, tid, kind, "ipv4")
        assert key in history.series
        assert history.baseline(key, METRIC_LATENCY) is not None
        assert history.baseline(key, METRIC_LOSS) is not None
    ha = diag.status()["ha"]
    assert ha["state"] in ("ok", "partial") and len(ha["series"]) == 2
    # a failing round: problem finding -> one pseudonymous core event
    diag.transport = loopback({}, seen)
    failed = await diag.async_run_manual(actor=ADMIN, target_ids=["t1"])
    assert [r["outcome"] for r in failed["results"]] == ["timeout"]
    findings = env.core.audit.events(types=[EVENT_FINDING])
    assert len(findings) == 1 and findings[0].source == "net_diagnostics"
    stored = json.dumps([e.to_dict() for e in env.core.audit.events()], default=str)
    for secret in SECRETS:
        assert secret not in stored
    await release_all(env)


async def test_passive_events_go_through_the_core_with_pseudonyms(
    disk, core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    diag = await core_diag(env, enabled=True)
    coord = env.coords[env.rid]
    coord.data.uptime = 5000
    coord.data.wan_status = wan_status()
    diag.on_poll(facts(env, T0))
    coord.data.wan_status = wan_status(gw="192.0.2.2")
    diag.on_poll(facts(env, T0 + 60))
    changes = env.core.audit.events(types=[EVENT_GATEWAY_CHANGED])
    assert len(changes) == 1
    assert changes[0].data["current_gateway"].startswith("ipa_")
    coord.data.wan_status = wan_status(connected=False, gw="192.0.2.2")
    diag.on_poll(facts(env, T0 + 120))
    diag.on_poll(facts(env, T0 + 180))  # same finding: no second event
    findings = env.core.audit.events(types=[EVENT_FINDING])
    assert len(findings) == 1 and findings[0].router_id == env.rid
    stored = json.dumps([e.to_dict() for e in env.core.audit.events()], default=str)
    for secret in SECRETS:
        assert secret not in stored
    assert env.router_calls() == []  # passive: no router call
    await release_all(env)


async def test_manual_runs_are_rate_limited_by_the_guard(
    disk, core_disks, tmp_path
) -> None:
    env = await cm_env(core_disks, tmp_path, options={})
    diag = await core_diag(env, enabled=True)
    await diag.async_update_settings(
        {"targets": [target("t1", "tcp", 443)]}, actor=ADMIN
    )
    diag.transport = loopback({}, [])
    limit = diag.scheduler_config.rate_limit.max_runs
    for _ in range(limit):
        await diag.async_run_manual(actor=ADMIN)
    with pytest.raises(ConfigApiError) as limited:
        await diag.async_run_manual(actor=ADMIN)
    assert limited.value.error_class is ErrorClass.RATE_LIMITED
    assert diag.counters["probes"] == limit
    await release_all(env)


async def test_ni_poll_observer_feeds_the_module(disk, ni_disks) -> None:
    hass = make_hass()
    engine, _cs = await ni_setup(hass, "r1")
    diag = await make_diag(hass, "r1")
    assert diag in engine._poll_observers
    engine.ingest("r1", ni_data([]), T0, interval=60.0)
    assert diag.counters["polls"] == 1
    assert diag.status()["routers"][RID1]["state"] == "partial"
    await async_release_net_diagnostics(hass, "r1")
    assert diag not in engine._poll_observers


# --- scheduler and diag_core changes ---------------------------------------------------


async def test_an_orphan_holds_a_concurrency_slot_until_it_ends() -> None:
    virtual = Env()  # virtual time of test_diag_scheduler
    s = virtual.scheduler(max_concurrent=1)
    stubborn = Stubborn(virtual)
    after = virtual.body("after")
    s.add_job(DiagJob("stub", "ping", stubborn, router_key="a", timeout=5.0))
    s.add_job(DiagJob("after", "ping", after, router_key="b", timeout=5.0))
    s.start()
    s.request_run("stub")
    await virtual.vt.advance(10.0)  # timeout + cancel grace: orphaned
    assert s.orphaned_tasks == 1
    follow = s.request_run("after")
    assert follow.status is RequestStatus.ACCEPTED
    await virtual.vt.advance(5.0)
    assert after.calls == 0  # the orphan still runs and holds the only slot
    stubborn.release.set()
    await virtual.settle()
    await virtual.vt.advance(1.0)
    assert s.orphaned_tasks == 0 and after.calls == 1
    stopping = asyncio.get_running_loop().create_task(s.async_stop())
    assert await virtual.vt.run_until_done(stopping, 120)
    assert diag_tasks() == []


def test_diag_events_carry_the_classification_code() -> None:
    from custom_components.openwrt_router.diag_causes import correlate
    from custom_components.openwrt_router.diag_chain import classify, evaluate_chain
    from custom_components.openwrt_router.diag_core import (
        correlation_events,
        new_correlation_id,
    )

    probe = ProbeResult(
        point=MeasurementPoint.ha(),
        target_id="t1",
        kind=ProbeKind.TCP,
        stage=Stage.INTERNET,
        family=None,
        outcome=ProbeOutcome.TIMEOUT,
        timestamp=T0,
    )
    finding = classify(evaluate_chain(MeasurementPoint.ha(), [probe]))
    events = correlation_events(
        correlate((finding,), {}), correlation_id=new_correlation_id(), key=MODULE_KEY
    )
    assert events
    for event in events:
        kwargs = event.emit_kwargs()
        assert kwargs["classification"] == event.classification
        assert event.classification is not None
