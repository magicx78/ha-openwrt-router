"""WiFi RF Intelligence center (rf_center + rf_evaluate, 1.48.0 part 1).

Fake coordinators with poll data from the synthetic RF fixtures and a
stand-in for ``api.async_rf_read``; the real-API end-to-end paths live in
``test_rf_center_e2e.py``. No router, no Home Assistant, no network.
"""

from __future__ import annotations

import json
import logging
import random
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from rf_center_kit import (
    KEY,
    MAC_A,
    MAC_B,
    RID1,
    RID2,
    FakeCoordinator,
    ap,
    client,
    entry,
    load,
    new_center,
    options,
    poll,
    poll_data,
    rf_disk,
    rf_hass,
)

import custom_components.openwrt_router as integration
from custom_components.openwrt_router import diagnostics
from custom_components.openwrt_router import rf_center as rc
from custom_components.openwrt_router.api import RfReadError
from custom_components.openwrt_router.const import DIAGNOSTICS_REDACTED
from custom_components.openwrt_router.core_models import CoreEventType
from custom_components.openwrt_router.rf_center import (
    ROUTER_OK,
    ROUTER_UNREACHABLE,
    STATUS_NOT_READY,
    STATUS_OFF,
    STATUS_READY,
    _Binding,
    async_get_rf_center,
    async_release_rf_center,
    async_setup_rf_center,
)
from custom_components.openwrt_router.rf_identity import RadioRef
from custom_components.openwrt_router.rf_models import CapabilityState

R1 = RadioRef(RID1, "radio1")
STATUS_A = load("hostapd_get_status_mt76_a.json")
STATUS_B = load("hostapd_get_status_mt76_b.json")
ASSOC = load("iwinfo_assoclist_mt76.json")


@pytest.fixture
def disk() -> Any:
    with rf_disk() as fake:
        yield fake


def _assoc_later(packets: int, retries: int) -> dict[str, Any]:
    """The mt76 assoclist one read later: both clients sent more."""
    later = json.loads(json.dumps(ASSOC))
    for station in later["results"]:
        station["tx"]["packets"] += packets
        station["tx"]["retries"] += retries
    return later


async def _one_router(opts: dict[str, Any], **kw: Any) -> Any:
    coordinator = FakeCoordinator()
    center, clock, reader = await new_center(
        rf_hass(), (entry("e1", opts), coordinator), **kw
    )
    return center, clock, reader, coordinator


# --- off / existing data -----------------------------------------------------------------


async def test_off_by_default_makes_no_read_and_no_evaluation(disk) -> None:
    center, clock, reader, coord = await _one_router({})
    for _ in range(3):
        await poll(center, coord, poll_data(uptime=clock()))
        clock.advance(60)
    assert reader.calls == []
    assert center.results == {} and center.status == STATUS_OFF
    assert center.counters["polls_off"] == 3 and center.counters["polls"] == 0
    assert disk.delayed == []  # not even a history write


async def test_on_with_existing_data_only(disk) -> None:
    center, _clock, reader, coord = await _one_router(options())
    await poll(center, coord, poll_data(uptime=1000))
    assert reader.calls == []  # no extra read switched on
    result = center.results[R1]
    assert result.radio.radio_id_source == "uci"
    metrics = result.metrics
    assert metrics["noise"].value == -92 and metrics["noise"].is_measured
    assert metrics["txpower"].value == 20
    assert metrics["utilization"] is None  # not assessed, not 0
    assert metrics["retry_rate"] is None
    assert metrics["signal_quality"].is_measured
    caps = result.caps
    assert caps.state("utilization") is None and caps.state("retries") is None
    assert caps.state("scan") is CapabilityState.UNSUPPORTED
    assert caps.state("noise") is CapabilityState.MEASURED
    # existing data alone covers too little for a rating
    assert center.status == STATUS_READY
    assert center.fleet.health[R1].score is None
    assert center.fleet.health[R1].grade == "unknown"


# --- extra reads -------------------------------------------------------------------------


async def test_get_status_gives_utilization_over_two_polls(disk) -> None:
    center, clock, reader, coord = await _one_router(options("get_status"))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    await poll(center, coord, poll_data(uptime=1000))
    first = center.results[R1].metrics["utilization"]
    assert first.state is CapabilityState.NO_DATA and first.value is None
    assert center.results[R1].utilization.reason.value == "no_previous"

    reader.answers[("get_status", "phy1-ap0")] = STATUS_B
    clock.advance(300)
    await poll(center, coord, poll_data(uptime=1300))
    util = center.results[R1].metrics["utilization"]
    # (60_022_800 - 60_000_000) / (200_060_000 - 200_000_000): 38 %, not the
    # utilization byte (255 then 0)
    assert util.is_measured and util.value == pytest.approx(38.0)
    assert util.source == "hostapd.get_status"
    assert reader.calls == [("get_status", "phy1-ap0")] * 2
    assert center.results[R1].caps.state("busy_time") is CapabilityState.MEASURED


async def test_reads_respect_cadence_and_floor(disk) -> None:
    center, clock, reader, coord = await _one_router(options("get_status", every=5))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    for i in range(10):
        await poll(center, coord, poll_data(uptime=1000 + 60 * i))
        clock.advance(60)
    # first poll at once, then every 5th poll (300 s): 2 reads in 10 polls
    assert len(reader.calls) == 2


async def test_assoclist_gives_the_retry_rate(disk) -> None:
    center, clock, reader, coord = await _one_router(options("assoclist"))
    clients = [client(MAC_A), client(MAC_B)]
    reader.answers[("assoclist", "phy1-ap0")] = ASSOC
    await poll(center, coord, poll_data(uptime=1000, clients=clients))
    retry = center.results[R1].metrics["retry_rate"]
    assert retry.state is CapabilityState.NO_DATA  # one read: no delta yet

    reader.answers[("assoclist", "phy1-ap0")] = _assoc_later(1000, 100)
    clock.advance(300)
    await poll(center, coord, poll_data(uptime=1300, clients=clients))
    result = center.results[R1]
    retry = result.metrics["retry_rate"]
    assert retry.is_measured
    # both clients sent 1000 packets with 100 retries: 0.1 per packet
    assert retry.value == pytest.approx(0.1)
    assert result.caps.state("retries") is CapabilityState.MEASURED
    assert result.store_values["retry_rate"] == pytest.approx(0.1)


async def test_zero_retries_of_an_unknown_driver_stay_unknown(disk) -> None:
    center, clock, reader, coord = await _one_router(options("assoclist"))
    reader.answers[("assoclist", "phy1-ap0")] = ASSOC
    await poll(center, coord, poll_data(uptime=1000, clients=[client(MAC_B)]))
    reader.answers[("assoclist", "phy1-ap0")] = _assoc_later(5000, 0)
    clock.advance(300)
    await poll(center, coord, poll_data(uptime=1300, clients=[client(MAC_B)]))
    # mt76 with WED counts no retries at all: 0 is no perfect link
    assert not center.results[R1].metrics["retry_rate"].is_measured


async def test_missing_right_is_unsupported_with_a_reason_not_a_poll_error(
    disk,
) -> None:
    center, clock, reader, coord = await _one_router(options("get_status", "survey"))
    reader.answers[("get_status", "phy1-ap0")] = RfReadError(
        "permission_denied", unsupported=True
    )
    await poll(center, coord, poll_data(uptime=1000))
    result = center.results[R1]
    util = result.metrics["utilization"]
    assert util.state is CapabilityState.UNSUPPORTED and util.value is None
    assert result.sources["get_status"] == {
        "state": "unsupported",
        "reason": "permission_denied",
    }
    # survey needs the Core's rf.survey (ACL fact): not asked at all
    assert ("survey", "phy1-ap0") not in reader.calls
    assert result.sources["survey"]["reason"] == "capability_unavailable:not_detected"
    assert center.routers["e1"].status == ROUTER_OK
    assert center.fleet.health[R1].score is None
    # backed off: the next polls do not ask again (no retry storm)
    for _ in range(5):
        clock.advance(300)
        await poll(center, coord, poll_data(uptime=clock() - 1_794_999_000))
    assert reader.calls.count(("get_status", "phy1-ap0")) == 1


async def test_router_restart_makes_the_utilization_unknown(disk) -> None:
    center, clock, reader, coord = await _one_router(options("get_status"))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    await poll(center, coord, poll_data(uptime=5000))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_B
    clock.advance(300)
    await poll(center, coord, poll_data(uptime=120))  # rebooted in between
    result = center.results[R1]
    assert result.metrics["utilization"].state is CapabilityState.NO_DATA
    assert result.utilization.reason.value == "router_restart"
    assert center.routers["e1"].reason == "router_restart"
    assert result.store_values["utilization"] is None  # a gap, never 0


async def test_collector_error_keeps_the_poll_green_and_marks_unreachable(
    disk,
) -> None:
    center, _clock, reader, coord = await _one_router(options("get_status"))
    reader.answers[("get_status", "phy1-ap0")] = RuntimeError("driver bug")
    coord.poll(poll_data(uptime=1000))  # the listener itself never raises
    await center.async_wait_rounds()
    state = center.routers["e1"]
    assert state.status == ROUTER_UNREACHABLE
    assert state.reason == "collector_error"
    assert center.counters["errors"] >= 1
    assert R1 in center.results  # the poll data is still evaluated
    assert not state.collector.busy


async def test_unreachable_reads_mark_the_router(disk) -> None:
    center, _clock, reader, coord = await _one_router(options("get_status"))
    reader.answers[("get_status", "phy1-ap0")] = RfReadError(
        "timeout", unsupported=False
    )
    await poll(center, coord, poll_data(uptime=1000))
    assert center.routers["e1"].status == ROUTER_UNREACHABLE
    assert center.routers["e1"].reason == "timeout"
    util = center.results[R1].metrics["utilization"]
    assert util.state is CapabilityState.UNREACHABLE


async def test_paused_coordinator_makes_no_reads(disk) -> None:
    coordinator = FakeCoordinator(interval_s=300)  # SSH fallback interval
    center, _clock, reader = await new_center(
        rf_hass(), (entry("e1", options("get_status")), coordinator)
    )
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    await poll(center, coordinator, poll_data(uptime=1000))
    assert reader.calls == []
    assert R1 in center.results


# --- readiness ------------------------------------------------------------------------------


async def test_without_key_not_ready_and_no_rating(disk) -> None:
    center, _clock, reader, coord = await _one_router(
        options("get_status", "assoclist"), key=None
    )
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    reader.answers[("assoclist", "phy1-ap0")] = ASSOC
    await poll(center, coord, poll_data(uptime=1000))
    assert center.status == STATUS_NOT_READY
    assert center.not_ready_reasons() == ["module_key_missing"]
    func, _delay = disk.delayed[-1]
    radios = func()["radios"]
    assert all("health" not in r["h"] for r in radios.values())


async def test_without_router_id_not_ready(disk) -> None:
    center, _clock, _reader, coord = await _one_router(options(), rids={})
    await poll(center, coord, poll_data(uptime=1000))
    assert center.status == STATUS_NOT_READY
    assert "router_id_missing" in center.not_ready_reasons()
    assert center.results == {}


# --- life cycle ----------------------------------------------------------------------------


async def test_setup_listens_and_release_flushes_the_history(disk) -> None:
    hass = rf_hass()
    coordinator = FakeCoordinator()
    config_entry = entry("e1", options())
    center = await async_setup_rf_center(hass, config_entry, coordinator)
    assert async_get_rf_center(hass) is center
    center.auto_bind = False
    center.router_id_of = {"e1": RID1}.get
    center.module_key = KEY
    assert len(coordinator.listeners) == 1
    await poll(center, coordinator, poll_data(uptime=1000))
    assert center.store.dirty
    await async_release_rf_center(hass, "e1")
    assert coordinator.listeners == []
    assert async_get_rf_center(hass) is None and center.closed
    assert disk.saves and "rtr_" in json.dumps(disk.saves[-1])


async def test_a_second_entry_shares_the_center(disk) -> None:
    hass = rf_hass()
    c1, c2 = FakeCoordinator(), FakeCoordinator()
    center = await async_setup_rf_center(hass, entry("e1", options()), c1)
    assert await async_setup_rf_center(hass, entry("e2", options()), c2) is center
    await async_release_rf_center(hass, "e1")
    assert async_get_rf_center(hass) is center and not center.closed
    await async_release_rf_center(hass, "e2")
    assert center.closed


async def test_router_forgotten_drops_every_rf_datum(disk) -> None:
    c1, c2 = FakeCoordinator(), FakeCoordinator()
    center, _clock, _reader = await new_center(
        rf_hass(), (entry("e1", options()), c1), (entry("e2", options()), c2)
    )
    await poll(center, c1, poll_data(uptime=1000))
    await poll(center, c2, poll_data(uptime=1000, clients=[client(MAC_B)]))
    assert {r.router_id for r in center.results} == {RID1, RID2}
    center._on_core_event(
        SimpleNamespace(type=CoreEventType.ROUTER_FORGOTTEN, router_id=RID1)
    )
    assert {r.router_id for r in center.results} == {RID2}
    assert center.store.routers() == {RID2}
    assert center.routers["e1"].radios == {}
    assert center.counters["forgotten_routers"] == 1


async def test_roaming_between_routers_is_counted_with_client_refs_only(
    disk,
) -> None:
    c1, c2 = FakeCoordinator(), FakeCoordinator()
    center, clock, _reader = await new_center(
        rf_hass(), (entry("e1", options()), c1), (entry("e2", options()), c2)
    )
    await poll(center, c1, poll_data(uptime=1000, clients=[client(MAC_A)]))
    clock.advance(60)
    await poll(center, c1, poll_data(uptime=1060, clients=[]))
    await poll(center, c2, poll_data(uptime=1060, clients=[client(MAC_A)]))
    r2 = RadioRef(RID2, "radio1")
    assert center.roam_count(r2, clock()) == 1
    (roam,) = center.roams
    assert roam["client_ref"].startswith("cli_")
    assert MAC_A not in json.dumps(list(center.roams))
    assert roam["from"]["router_id"] == RID1 and roam["to"]["router_id"] == RID2


# --- events --------------------------------------------------------------------------------


def _bind(center: Any) -> MagicMock:
    api = MagicMock()
    center._binding = _Binding(api=api, events_ok=True)
    return api


async def test_sustained_utilization_is_one_event_while_it_lasts(disk) -> None:
    center, clock, reader, coord = await _one_router(options("get_status"))
    api = _bind(center)
    busy = {"time": 200_000_000, "time_busy": 60_000_000}

    def status() -> dict[str, Any]:
        busy["time"] += 300_000
        busy["time_busy"] += 270_000  # 90 % busy
        return {**STATUS_A, "airtime": {**STATUS_A["airtime"], **busy}}

    reader.answers[("get_status", "phy1-ap0")] = status
    # one hour at 300 s expects 12 points; 0.75 coverage needs 9 valid ones
    for i in range(8):
        await poll(center, coord, poll_data(uptime=1000 + 300 * i))
        clock.advance(300)
    early = [c.args[0] for c in api.emit.call_args_list]
    assert "wifi_rf.channel_utilization_high" not in early  # too few points
    for i in range(8, 16):
        await poll(center, coord, poll_data(uptime=1000 + 300 * i))
        clock.advance(300)
    types = [c.args[0] for c in api.emit.call_args_list]
    assert types.count("wifi_rf.channel_utilization_high") == 1
    call = next(
        c for c in api.emit.call_args_list if c.args[0].endswith("utilization_high")
    )
    assert call.kwargs["source"] == "wifi_rf"
    assert call.kwargs["router_id"] == RID1 and call.kwargs["radio_id"] == "radio1"
    assert "security_relevant" not in call.kwargs  # general ring


async def test_recommendations_after_a_start_are_the_baseline(disk) -> None:
    c1, c2 = FakeCoordinator(), FakeCoordinator()
    center, _clock, _reader = await new_center(
        rf_hass(), (entry("e1", options()), c1), (entry("e2", options()), c2)
    )
    api = _bind(center)
    wide = ap(
        "phy0-ap0", phy="phy0", channel=6, frequency=2437, htmode="HT40", center=4
    )
    data = poll_data(uptime=1000, aps=[wide], clients=[], radio_names={})
    await poll(center, c1, data)
    await poll(center, c2, data)
    assert center.fleet.recommendations  # 40 MHz on 2.4 GHz
    # an evaluation with a router seen first since the start is a baseline
    # (routers poll one by one after a start; a newcomer changes the
    # recommendations of its co-channel neighbours too)
    types = [c.args[0] for c in api.emit.call_args_list]
    assert not [t for t in types if t.startswith("wifi_rf.recommendation")]
    await poll(center, c1, poll_data(uptime=1060, clients=[]))  # now 5 GHz
    types = [c.args[0] for c in api.emit.call_args_list]
    assert "wifi_rf.recommendation_resolved" in types
    assert "wifi_rf.recommendation_new" not in types


async def test_no_events_while_not_ready(disk) -> None:
    center, _clock, _reader, coord = await _one_router(options(), key=None)
    api = _bind(center)
    await poll(center, coord, poll_data(uptime=1000))
    assert api.emit.call_count == 0


# --- property: a confirming source never makes things look better ---------------------


@pytest.mark.parametrize("seed", range(12))
async def test_a_confirming_source_never_lowers_a_rating_or_invents_health(
    disk, seed: int
) -> None:
    """Adding a read that only confirms known figures (here: survey on a
    radio that already reads get_status) never lowers the score, never turns
    an unknown score into a known one, and coverage rises or stays."""
    rng = random.Random(seed)
    busy_share = rng.uniform(0.05, 0.95)
    clients = [client(MAC_A, signal=rng.randint(-85, -45))]
    base_reads = rng.choice([("get_status",), ("get_status", "assoclist")])

    async def run(extra: tuple[str, ...]) -> tuple[Any, float]:
        center, clock, reader, coord = await _one_router(options(*base_reads, *extra))
        center.capability_of = lambda _rid, _name: (True, None)
        counters = {"time": 1_000_000, "busy": 100_000}

        def status() -> dict[str, Any]:
            counters["time"] += 300_000
            counters["busy"] += int(300_000 * busy_share)
            airtime = {"time": counters["time"], "time_busy": counters["busy"]}
            return {**STATUS_A, "airtime": airtime}

        def survey() -> dict[str, Any]:
            return {
                "results": [
                    {
                        "mhz": 5180,
                        "active_time": counters["time"],
                        "busy_time": counters["busy"],
                        "noise": 164,
                    }
                ]
            }

        reader.answers[("get_status", "phy1-ap0")] = status
        reader.answers[("survey", "phy1-ap0")] = survey
        reader.answers[("assoclist", "phy1-ap0")] = lambda: _assoc_later(
            1000 * len(reader.calls), 10 * len(reader.calls)
        )
        for i in range(4):
            await poll(center, coord, poll_data(uptime=1000 + 300 * i, clients=clients))
            clock.advance(300)
        return center.fleet.health[R1], center.fleet.coverage

    base, base_cov = await run(())
    more, more_cov = await run(("survey",))
    assert more_cov >= base_cov
    if base.score is None:
        assert more.score is None or more.coverage > base.coverage
    else:
        assert more.score is not None and more.score >= base.score
    assert (more.score is None) == (more.grade == "unknown")


# --- diagnostics -------------------------------------------------------------------------------


async def test_diagnostics_hold_no_identity(disk) -> None:
    center, _clock, reader, coord = await _one_router(options("get_status"))
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    await poll(center, coord, poll_data(uptime=1000))
    text = json.dumps(center.diagnostics())
    for needle in (RID1, MAC_A, "phy1-ap0", "radio1", "example-ssid", KEY.hex()):
        assert needle not in text
    assert center.diagnostics()["counters"]["rounds_started"] == 1


def test_center_module_reads_through_api_only() -> None:
    import inspect

    source = inspect.getsource(rc)
    for needle in ("aiohttp", "asyncssh", "_call(", "session.post"):
        assert needle not in source


# --- wiring: __init__ and diagnostics ------------------------------------------------


async def test_entry_setup_and_unload_add_and_release_the_center(disk) -> None:
    hass = rf_hass()
    coordinator = FakeCoordinator()
    config_entry = SimpleNamespace(
        entry_id="e1", options={}, runtime_data=SimpleNamespace(coordinator=coordinator)
    )
    with (
        patch.object(
            integration, "_async_setup_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(
            integration, "_async_unload_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(integration, "_security_center", None),
    ):
        assert await integration.async_setup_entry(hass, config_entry) is True
        center = async_get_rf_center(hass)
        assert center is not None and len(coordinator.listeners) == 1
        assert await integration.async_unload_entry(hass, config_entry) is True
    assert async_get_rf_center(hass) is None and coordinator.listeners == []


async def test_entry_setup_and_unload_survive_a_broken_center(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = rf_hass()
    config_entry = SimpleNamespace(
        entry_id="e1", title=f"router {MAC_A}", runtime_data=SimpleNamespace()
    )
    with (
        patch.object(
            integration, "_async_setup_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(
            integration, "_async_unload_entry_base", AsyncMock(return_value=True)
        ),
        patch.object(integration, "_security_center", None),
        patch.object(
            rc, "async_setup_rf_center", AsyncMock(side_effect=RuntimeError(MAC_A))
        ),
        patch.object(
            rc, "async_release_rf_center", AsyncMock(side_effect=OSError(MAC_A))
        ),
        caplog.at_level(logging.WARNING),
    ):
        assert await integration.async_setup_entry(hass, config_entry) is True
        assert await integration.async_unload_entry(hass, config_entry) is True
    assert "WiFi RF setup failed (RuntimeError)" in caplog.text
    assert "WiFi RF release failed (OSError)" in caplog.text
    assert MAC_A not in caplog.text


async def test_failed_base_setup_does_not_start_the_center() -> None:
    hass = rf_hass()
    setup_mock = AsyncMock()
    with (
        patch.object(
            integration, "_async_setup_entry_base", AsyncMock(return_value=False)
        ),
        patch.object(integration, "_security_center", None),
        patch.object(rc, "async_setup_rf_center", setup_mock),
    ):
        entry_ = SimpleNamespace(entry_id="e1", runtime_data=SimpleNamespace())
        assert await integration.async_setup_entry(hass, entry_) is False
    setup_mock.assert_not_called()


async def test_diagnostics_block_is_redacted_and_never_fails(disk) -> None:
    center, _clock, reader, coord = await _one_router(options("get_status"))
    hass = center.hass
    assert diagnostics._wifi_rf_summary(hass) == {"loaded": False}
    hass.data[rc.DATA_WIFI_RF_CENTER] = center
    reader.answers[("get_status", "phy1-ap0")] = STATUS_A
    await poll(center, coord, poll_data(uptime=1000))
    base = AsyncMock(return_value={"integration": "openwrt_router"})
    with (
        patch.object(diagnostics, "_async_get_config_entry_diagnostics_base", base),
        patch.object(diagnostics, "_security_center_summary", lambda _h: {}),
    ):
        result = await diagnostics.async_get_config_entry_diagnostics(
            hass, SimpleNamespace(entry_id="e1")
        )
    block = result["wifi_rf"]
    assert block["status"] == STATUS_READY and block["radios"] == 1
    assert block["pseudonyms_ready"] is True
    assert block["routers"][0]["options"]["reads"] == ["get_status"]
    text = json.dumps(result, default=str)
    for needle in (RID1, MAC_A, "phy1-ap0", "radio1", "example-ssid", "rtr_"):
        assert needle not in text, needle
    assert DIAGNOSTICS_REDACTED not in json.dumps(block)  # nothing key-like left
    with patch.object(type(center), "diagnostics", side_effect=RuntimeError(MAC_A)):
        assert diagnostics._wifi_rf_summary(hass) == {"loaded": False, "error": True}
