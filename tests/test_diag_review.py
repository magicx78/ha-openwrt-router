"""Regression tests of the independent review (release 1.47.0, part 5).

One test (or more) per finding: H1, H2, M1, M2, M4, L2 to L6 (M3 extends
``test_case_18`` in ``test_diag_runtime``, L1 replaces the engine test in
``test_diag_incidents``). Mocks, in-memory stores and loopback servers only;
the conftest network guard stays in force. Addresses are documentation /
test values.
"""

from __future__ import annotations

import asyncio
import json
import socket
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from config_manager_kit import cm_env
from core_test_provider import short_tmp_path  # noqa: F401 - short tmp_path
from core_testkit import make_hass
from test_client_engine import data as ni_data
from test_client_engine import setup as ni_setup
from test_diag_runtime import (
    ADMIN,
    GLOBAL_IP,
    RID1,
    RID2,
    SECRETS,
    T0,
    Clock,
    core_diag,
    core_disks,  # noqa: F401 - fixture
    disk,  # noqa: F401 - fixture
    make_diag,
    ni_disks,  # noqa: F401 - fixture
    poll,
    release_all,
    target,
    tcp_server,
    wan_status,
)

from custom_components.openwrt_router.api import DiagTransport
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.diag_context import SourceState
from custom_components.openwrt_router.diag_core import (
    EVENT_FINDING,
    EVENT_GATEWAY_CHANGED,
    series_key,
)
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    MeasurementPoint,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Stage,
)
from custom_components.openwrt_router.diag_runtime import (
    RUN_TIMEOUT_SECONDS,
    async_release_net_diagnostics,
    probe_sample,
)
from custom_components.openwrt_router.diag_stats import Sample, SeriesKey
from custom_components.openwrt_router.diag_store import DiagHistory

CID = "c" * 32


def ha_probe(
    tid: str,
    kind: ProbeKind = ProbeKind.TCP,
    stage: Stage = Stage.INTERNET,
    outcome: ProbeOutcome = ProbeOutcome.OK,
    *,
    ts: float = T0,
    rtt: float | None = 5.0,
    received: int | None = 1,
) -> ProbeResult:
    return ProbeResult(
        point=MeasurementPoint.ha(),
        target_id=tid,
        kind=kind,
        stage=stage,
        family=AddressFamily.IPV4,
        outcome=outcome,
        timestamp=ts,
        rtt_ms=rtt,
        sent=1,
        received=received,
    )


def failing(tid: str, ts: float = T0) -> ProbeResult:
    return ha_probe(tid, outcome=ProbeOutcome.TIMEOUT, ts=ts, rtt=None, received=0)


def host_target(tid: str, host: str, **kw: Any) -> dict[str, Any]:
    return {
        "id": tid,
        "kind": "tcp",
        "scope": "external",
        "host": host,
        "port": 443,
        "confirmed": True,
        **kw,
    }


class FakeCoordinator:
    """What the module reads of a DataUpdateCoordinator, with listeners."""

    def __init__(self, data: Any) -> None:
        self.data = data
        self.last_update_success = True
        self.listeners: list[Any] = []

    def async_add_listener(self, listener: Any) -> Any:
        self.listeners.append(listener)
        return lambda: self.listeners.remove(listener)

    def notify(self) -> None:
        for listener in list(self.listeners):
            listener()


# --- H1: a failed poll makes the router unknown, chain and finding hidden ----------------


async def test_h1_failed_poll_through_the_engine_hides_chain_and_finding(
    disk,  # noqa: F811
    ni_disks,  # noqa: F811
) -> None:
    hass = make_hass()
    engine, _cs = await ni_setup(hass, "r1")
    clock = Clock()
    diag = await make_diag(hass, "r1", clock=clock)
    data = ni_data([], uptime=5000, wan_status=wan_status())
    coord = FakeCoordinator(data)
    diag.add_entry("r1", coord)  # the module listens to the coordinator
    engine.ingest("r1", data, T0, interval=60.0)
    before = diag.overview()["routers"][RID1]
    assert before["state"] != "unknown" and before["chain"]
    # the router goes offline: HA keeps the data and notifies again with it
    coord.last_update_success = False
    for k in range(1, 4):
        engine.ingest("r1", data, T0 + 60 * k, interval=60.0)  # NI: a repeat
        coord.notify()
    assert diag.counters["polls"] == 1  # the failed polls never reach on_poll
    clock.now = T0 + 180
    view = diag.status()["routers"][RID1]
    assert (view["state"], view["reason"]) == ("unknown", "poll_failed")
    assert view["finding"] is None
    overview = diag.overview()["routers"][RID1]
    assert overview["state"] == "unknown"
    assert overview["chain"] is None and overview["finding"] is None
    # the entity view was rebuilt by the listener (no poll needed)
    assert diag.view["routers_unknown"] == 1
    assert diag.view["gateways"][RID1]["state"] is None
    detail = await diag.async_detail(RID1, actor=None, admin=False)
    assert detail["finding"] is None and detail["context"] is None
    # stale (no poll for long) is unknown as well, never the old chain
    coord.last_update_success = True
    clock.now = T0 + 4000
    stale = diag.overview()["routers"][RID1]
    assert (stale["state"], stale["chain"], stale["finding"]) == ("unknown", None, None)
    # back online with new data: known again
    fresh = ni_data([], uptime=9000, wan_status=wan_status())
    coord.data = fresh
    engine.ingest("r1", fresh, T0 + 4000, interval=60.0)
    assert diag.overview()["routers"][RID1]["chain"]
    diag.remove_entry("r1")
    assert coord.listeners == []
    await diag.async_close()


# --- H2: resolver outage with host-name targets -------------------------------------------


def _failing_resolver() -> DiagTransport:
    return DiagTransport(
        getaddrinfo=AsyncMock(side_effect=socket.gaierror(-3, "x")),
        open_connection=AsyncMock(side_effect=AssertionError("no connect")),
    )


async def test_h2_resolver_outage_is_a_dns_observation_never_the_old_state(
    disk,  # noqa: F811
) -> None:
    clock = Clock()
    diag = await make_diag(
        make_hass(),
        "r1",
        clock=clock,
        settings={
            "targets": [
                host_target("web", "one.example.net"),
                host_target("api", "two.example.net"),
            ]
        },
    )
    diag._apply_ha_round([ha_probe("web"), ha_probe("api")], CID)
    before = diag.status()["ha"]
    assert before["finding"]["classification"] != "dns_problem"
    diag.transport = _failing_resolver()
    clock.now = T0 + 600
    result = await diag._async_round(("web", "api"), "d" * 32)
    assert result["probes"] == 0 and result["lookups_failed"] == 2
    after = diag.status()["ha"]
    assert after["state"] == "problem"
    assert after["finding"]["classification"] == "dns_problem"
    assert after["finding"]["stage"] == "dns"
    assert after["finding"]["severity"] == "warning"
    assert after["last_round"]["ts"] == T0 + 600
    assert diag.counters["resolutions_failed"] == 2
    # no sample: a failed lookup is no packet loss of the series
    for tid in ("web", "api"):
        summary = diag.store.history.summaries(
            series_key(None, tid, "tcp", "ipv4"), now=clock.now
        )["1h"]
        assert summary.lost == 0
    await diag.async_close()


async def test_h2_one_failed_lookup_among_answered_ones_is_no_dns_failure(
    disk,  # noqa: F811
) -> None:
    seen: list[Any] = []

    async def getaddrinfo(host: str, port: int) -> list[Any]:
        if host == "two.example.net":
            raise socket.gaierror(-2, "x")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (GLOBAL_IP, 0))]

    diag = await make_diag(
        make_hass(),
        "r1",
        settings={
            "targets": [
                host_target("web", "one.example.net"),
                host_target("api", "two.example.net"),
            ]
        },
    )
    async with tcp_server() as port:

        async def open_connection(host: str, p: int, **kw: Any) -> Any:
            seen.append((host, p))
            return await asyncio.open_connection("127.0.0.1", port)

        diag.transport = DiagTransport(
            getaddrinfo=getaddrinfo, open_connection=open_connection
        )
        result = await diag._async_round(("web", "api"), CID)
    assert result["probes"] == 1 and result["lookups_failed"] == 1
    assert seen == [(GLOBAL_IP, 443)]
    chain = diag._ha_finding.chain
    assert chain.stage(Stage.DNS, AddressFamily.IPV4).state.value == "degraded"
    # one name not resolved among answered ones: an info note, no failure
    assert diag._ha_finding.severity.value == "info"
    await diag.async_close()


async def test_h2_a_round_without_any_measurement_makes_ha_unknown(
    disk,  # noqa: F811
) -> None:
    clock = Clock()
    diag = await make_diag(make_hass(), "r1", clock=clock)
    diag._apply_ha_round([ha_probe("t1"), ha_probe("t2")], CID)
    assert diag.status()["ha"]["finding"] is not None
    clock.now = T0 + 600
    result = await diag._async_round(("gone",), "d" * 32)  # unknown id: refused
    assert result["probes"] == 0 and result["lookups_failed"] == 0
    ha = diag.status()["ha"]
    assert ha["state"] == "unknown" and ha["finding"] is None
    assert diag._ha_finding is None  # the manual-run response has none either
    await diag.async_close()


# --- M1: HA state ages ------------------------------------------------------------------


async def test_m1_ha_state_finding_and_count_go_unknown_when_old(
    disk,  # noqa: F811
) -> None:
    clock = Clock()
    diag = await make_diag(make_hass(), "r1", clock=clock)
    diag._apply_ha_round([failing("t1"), failing("t2")], CID)  # internet down
    assert diag.status()["ha"]["state"] == "problem"
    assert diag.view["findings_active"] >= 1
    problems = diag.view["findings_active"]
    clock.now = T0 + 3500  # within an hour: still the finding
    diag._publish()
    assert diag.status()["ha"]["state"] == "problem"
    clock.now = T0 + 3700  # older than max(1 h, 3 x interval)
    diag._publish()
    ha = diag.status()["ha"]
    assert (ha["state"], ha["reason"], ha["finding"]) == ("unknown", "stale", None)
    assert diag.view["ha_state"] == "unknown"
    assert diag.view["findings_active"] in (None, problems - 1)
    overview = diag.overview()["ha"]
    assert overview["finding"] is None and overview["chain"] is None
    detail = await diag.async_detail(None, actor=None, admin=False)
    assert detail["finding"] is None
    await diag.async_close()


# --- M2: quota slots come back --------------------------------------------------------------


def test_m2_series_without_buckets_free_their_quota_slot() -> None:
    history = DiagHistory(max_series_ha=2)
    for tid in ("old1", "old2"):
        key = SeriesKey("ha", tid, "tcp", "ipv4")
        assert history.record(key, Sample.answered(T0, 5.0))
    later = T0 + 40 * 86400
    history.fold(later)
    assert history.series == {}
    assert history.counters["series_expired"] == 2
    assert history.record(
        SeriesKey("ha", "new", "tcp", "ipv4"), Sample.answered(later, 5.0)
    )


async def test_m2_removed_targets_drop_their_series_baselines_and_rounds(
    disk,  # noqa: F811
) -> None:
    diag = await make_diag(
        make_hass(),
        "r1",
        settings={"targets": [target("t1", "tcp", 443), target("t2", "tcp", 443)]},
    )
    diag._apply_ha_round([ha_probe("t1"), ha_probe("t2")], CID)
    keys = {k.target for k in diag.store.history.series if k.point == "ha"}
    assert keys == {"t1", "t2"}
    diag._async_authorize_settings = AsyncMock()  # the guard (tested elsewhere)
    await diag.async_update_settings(
        {"targets": [target("t1", "tcp", 443)]}, actor=ADMIN
    )
    history = diag.store.history
    assert {k.target for k in history.series if k.point == "ha"} == {"t1"}
    assert all(s.key.target != "t2" for s in history.baselines.values())
    assert all(k.target != "t2" for k in diag._rounds)
    assert history.counters["series_removed"] == 1
    assert diag.status()["store"]["history"]["counters"]["series_removed"] == 1
    await diag.async_close()


# --- M4: drift notes per router ------------------------------------------------------------


async def test_m4_drift_notes_are_capped_per_router_counted_and_partial(
    disk,  # noqa: F811
) -> None:
    hass = make_hass()
    diag = await make_diag(hass, "r1", "r2")
    diag.config_runtime_of = lambda: SimpleNamespace(
        drift_check_enabled=lambda rid: True
    )
    diag._binding.api = MagicMock()
    diag._config_since = T0 - 7200

    async def no_areas(note: Any) -> None:
        return None

    diag.drift_areas_of = no_areas

    def drift(rid: str, n: int) -> None:
        diag._config_event(
            SimpleNamespace(
                type=CoreEventType.DRIFT_DETECTED.value,
                router_id=rid,
                data={"drift_id": f"drift_{n}", "baseline_version_id": "bk"},
                ts=T0 - 1000 + n,
            )
        )

    for n in range(2):
        drift(RID2, n)
    for n in range(20):
        drift(RID1, n)
    await asyncio.gather(*hass.tasks)
    per_router = {}
    for rid, _ref in diag._config_notes:
        per_router[rid] = per_router.get(rid, 0) + 1
    assert per_router == {RID1: 16, RID2: 2}  # r2 keeps all of its notes
    assert diag.counters["config_notes_dropped"] == 4
    limits = diag.status()["limits"]
    assert limits["config_notes_dropped"] == 4
    assert limits["routers_with_dropped_notes"] == 1
    view = diag._config_view(RID1)
    assert view.state is SourceState.PARTIAL
    assert view.reason == "config_notes_dropped" and len(view.items) == 16
    assert diag._config_view(RID2).state is SourceState.READY
    diag._binding.api = None
    await diag.async_close()


# --- L2: passive end to end -----------------------------------------------------------------


async def test_l2_passive_engine_runtime_core_pseudonymised_event(
    disk,  # noqa: F811
    ni_disks,  # noqa: F811
    core_disks,  # noqa: F811
    tmp_path,
) -> None:
    """NI ingest -> run time -> real core (module key) -> pseudonymised event."""
    env = await cm_env(core_disks, tmp_path, options={})
    entry_id = env.entries[0].entry_id
    engine, _cs = await ni_setup(env.hass, entry_id)
    diag = await core_diag(env, enabled=True)
    assert diag.module_key_available
    coord = env.coords[env.rid]

    def ingest(gw: str, at: float, *, connected: bool = True) -> None:
        coord.data = ni_data(
            [],
            uptime=5000 + int(at - T0),
            wan_status=wan_status(gw=gw, connected=connected),
        )
        engine.ingest(entry_id, coord.data, at, interval=60.0)

    ingest("192.0.2.1", T0)
    ingest("192.0.2.2", T0 + 60)
    changes = env.core.audit.events(types=[EVENT_GATEWAY_CHANGED])
    assert len(changes) == 1
    assert changes[0].data["current_gateway"].startswith("ipa_")
    ingest("192.0.2.2", T0 + 120, connected=False)
    findings = env.core.audit.events(types=[EVENT_FINDING])
    assert len(findings) == 1 and findings[0].router_id == env.rid
    stored = json.dumps([e.to_dict() for e in env.core.audit.events()], default=str)
    for secret in SECRETS:
        assert secret not in stored
    assert env.router_calls() == []
    await release_all(env)


# --- L3: internal host names without the internal resolver ------------------------------


async def test_l3_internal_host_name_is_unusable_without_the_internal_resolver(
    disk,  # noqa: F811
) -> None:
    nas = {
        "id": "nas",
        "kind": "tcp",
        "scope": "internal",
        "host": "nas.home.arpa",
        "port": 443,
    }
    diag = await make_diag(
        make_hass(),
        "r1",
        settings={"targets": [nas], "local_domains": ["home.arpa"]},
    )
    [row] = diag.status()["targets"]
    assert row["usable"] is False and row["reason"] == "target.internal_name"
    ha = diag.status()["ha"]
    assert ha["reason"] == "no_confirmed_target"
    diag.store.settings = {**diag.settings, "ha_resolver_internal": True}
    [row] = diag.status()["targets"]
    assert row["usable"] is True and row["reason"] == "ok"
    await diag.async_close()


# --- L4: a reply is no packet loss ----------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "stage", "outcome", "rtt", "received", "expected"),
    [
        (ProbeKind.TCP, Stage.INTERNET, ProbeOutcome.REFUSED, None, 1, "answered"),
        (ProbeKind.DNS, Stage.DNS, ProbeOutcome.SERVFAIL, 7.0, 1, "answered"),
        (ProbeKind.DNS, Stage.DNS, ProbeOutcome.REFUSED, 7.0, 1, "answered"),
        (ProbeKind.HTTP, Stage.INTERNET, ProbeOutcome.FAILED, 9.0, 1, "answered"),
        (ProbeKind.HTTP, Stage.INTERNET, ProbeOutcome.FAILED, 9.0, 0, "lost"),
        (ProbeKind.TCP, Stage.INTERNET, ProbeOutcome.TIMEOUT, None, 0, "lost"),
    ],
)
def test_l4_replies_are_answered_samples(
    kind: ProbeKind,
    stage: Stage,
    outcome: ProbeOutcome,
    rtt: float | None,
    received: int,
    expected: str,
) -> None:
    probe = ProbeResult(
        point=MeasurementPoint.ha(),
        target_id="t1",
        kind=kind,
        stage=stage,
        family=AddressFamily.IPV4,
        outcome=outcome,
        timestamp=T0,
        duration_ms=4.0,
        rtt_ms=rtt,
        sent=1,
        received=received,
    )
    sample = probe_sample(probe)
    assert sample.outcome == expected
    if expected == "answered":
        assert sample.rtt_ms == (rtt if rtt is not None else 4.0)


async def test_l4_loss_sensor_counts_only_missing_answers(disk) -> None:  # noqa: F811
    diag = await make_diag(make_hass(), "r1")
    refused = [
        ha_probe(t, kind=ProbeKind.HTTP, outcome=ProbeOutcome.FAILED, rtt=9.0)
        for t in ("h1", "h2")
    ]
    diag._apply_ha_round(refused, CID)
    assert diag.view["ha_loss_pct"] == 0.0  # the hosts answered
    # the stage evaluation still sees the failed replies
    assert diag._ha_finding.is_problem
    diag._apply_ha_round([failing("h1", T0 + 60), failing("h2", T0 + 60)], CID)
    assert diag.view["ha_loss_pct"] == 50.0
    await diag.async_close()


# --- L5: emitted events are remembered per event ------------------------------------------


async def test_l5_a_failing_emit_never_resends_what_went_out(disk) -> None:  # noqa: F811
    diag = await make_diag(make_hass(), "r1")
    sent: list[str] = []
    fail_next = {"on": False}

    def emit(**kw: Any) -> None:
        if fail_next["on"] and kw["event_type"] != EVENT_FINDING:
            raise RuntimeError(f"core write failed {GLOBAL_IP}")
        sent.append(kw["event_type"])

    diag._binding.api = SimpleNamespace(emit=emit)
    diag._binding.events_ok = True
    diag._module_key = bytes(range(32))
    poll(diag, "r1", T0, uptime=5000)
    # WAN down and a new next hop in one poll; the change event fails
    fail_next["on"] = True
    poll(
        diag,
        "r1",
        T0 + 60,
        uptime=5060,
        wan_status=wan_status(connected=False, gw="192.0.2.2"),
    )
    assert sent.count(EVENT_FINDING) == 1
    assert diag.counters["events_failed"] == 1
    fail_next["on"] = False
    poll(
        diag,
        "r1",
        T0 + 120,
        uptime=5120,
        wan_status=wan_status(connected=False, gw="192.0.2.2"),
    )
    assert sent.count(EVENT_FINDING) == 1  # the finding is not sent again
    diag._binding.api = None
    await diag.async_close()


# --- L6: the round timeout keeps what was measured -------------------------------------------


def test_l6_run_timeout_covers_the_worst_case() -> None:
    # 16 host-name targets: resolve 3 s + HTTP 5 s + close 1 s each
    assert RUN_TIMEOUT_SECONDS >= 16 * (3 + 5 + 1)


async def test_l6_a_timeout_keeps_the_finished_targets(disk) -> None:  # noqa: F811
    diag = await make_diag(
        make_hass(),
        "r1",
        settings={"targets": [target("t1", "tcp", 443), target("t2", "tcp", 8443)]},
    )
    hang = asyncio.Event()
    async with tcp_server() as port:

        async def open_connection(host: str, p: int, **kw: Any) -> Any:
            if p == 8443:
                await hang.wait()  # never answers
            return await asyncio.open_connection("127.0.0.1", port)

        diag.transport = DiagTransport(
            open_connection=open_connection, getaddrinfo=AsyncMock()
        )
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(diag._async_round(("t1", "t2"), CID), timeout=0.5)
    assert diag.counters["rounds_partial"] == 1
    assert diag._ha_last["probes"] == 1
    assert [p["target_id"] for p in diag._ha_probes] == ["t1"]
    assert series_key(None, "t1", "tcp", "ipv4") in diag.store.history.series
    assert series_key(None, "t2", "tcp", "ipv4") not in diag.store.history.series
    assert diag._ha_finding is not None  # t2 unmeasured: partial, never ok
    assert diag._ha_finding.classification.value != "no_fault_detected"
    await diag.async_close()


async def test_release_drops_the_coordinator_listener(disk) -> None:  # noqa: F811
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    coord = FakeCoordinator(SimpleNamespace(uptime=5000, wan_status=wan_status()))
    diag.add_entry("r2", coord)
    assert len(coord.listeners) == 1
    diag.add_entry("r2", coord)  # added again: still one
    assert len(coord.listeners) == 1
    await async_release_net_diagnostics(hass, "r2")
    assert coord.listeners == []
    await async_release_net_diagnostics(hass, "r1")


async def test_coordinator_listener_only_while_active(disk) -> None:  # noqa: F811
    """Off means no work: no listener on a coordinator while inactive."""
    hass = make_hass()
    diag = await make_diag(hass, "r1")
    coord = FakeCoordinator(SimpleNamespace(uptime=5000, wan_status=wan_status()))
    await diag.async_deactivate()
    diag.add_entry("r2", coord)
    assert coord.listeners == []
    assert diag.enabled  # still enabled, only deactivated
    await diag.async_activate()
    assert len(coord.listeners) == 1
    await diag.async_deactivate()
    assert coord.listeners == []
    await diag.async_close()
    assert coord.listeners == []
