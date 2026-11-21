"""Extra RF reads (api.py block) and their schedule (rf_collector, 1.48.0).

Mocks only: ``OpenWrtAPI._call`` is replaced, no router is contacted.
"""

from __future__ import annotations

import asyncio
import itertools
from typing import Any

import pytest

from custom_components.openwrt_router import api as api_module
from custom_components.openwrt_router.api import (
    RF_KIND_ASSOCLIST,
    RF_KIND_FREQLIST,
    RF_KIND_GET_STATUS,
    RF_KIND_SURVEY,
    RF_KIND_TXPOWERLIST,
    RF_MAX_LIST_ENTRIES,
    OpenWrtAPI,
    OpenWrtConnectionError,
    OpenWrtMethodNotFoundError,
    OpenWrtResponseError,
    OpenWrtTimeoutError,
    RfReadError,
    async_rf_read,
)
from custom_components.openwrt_router.const import (
    OPTION_WIFI_RF_ASSOCLIST,
    OPTION_WIFI_RF_ENABLED,
    OPTION_WIFI_RF_EVERY_N_POLLS,
    OPTION_WIFI_RF_GET_STATUS,
    OPTION_WIFI_RF_LISTS,
    OPTION_WIFI_RF_SURVEY,
)
from custom_components.openwrt_router.rf_collector import (
    RadioPlanInput,
    RfCollector,
    Target,
    options_from_entry,
)
from custom_components.openwrt_router.rf_models import CapabilityState


class FakeApi:
    """Stands in for OpenWrtAPI: records calls, answers from a table."""

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None) -> None:
        self.calls: list[tuple[str, str, dict]] = []
        self.answers = answers or {}

    async def _call(self, obj: str, method: str, params: dict) -> Any:
        self.calls.append((obj, method, dict(params)))
        answer = self.answers.get((obj, method), {})
        if isinstance(answer, BaseException):
            raise answer
        return answer


# --- api.py block ---------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "call"),
    [
        (RF_KIND_GET_STATUS, ("hostapd.phy0-ap0", "get_status", {})),
        (RF_KIND_ASSOCLIST, ("iwinfo", "assoclist", {"device": "phy0-ap0"})),
        (RF_KIND_FREQLIST, ("iwinfo", "freqlist", {"device": "phy0-ap0"})),
        (RF_KIND_TXPOWERLIST, ("iwinfo", "txpowerlist", {"device": "phy0-ap0"})),
        (RF_KIND_SURVEY, ("iwinfo", "survey", {"device": "phy0-ap0"})),
    ],
)
async def test_each_kind_is_one_call_with_the_device(kind, call):
    api = FakeApi()
    await async_rf_read(api, kind, "phy0-ap0")  # type: ignore[arg-type]
    assert api.calls == [call]


async def test_there_is_no_scan_and_no_other_kind():
    api = FakeApi()
    for kind in ("scan", "info", "devices", ""):
        with pytest.raises(ValueError):
            await async_rf_read(api, kind, "phy0-ap0")  # type: ignore[arg-type]
    assert api.calls == []


@pytest.mark.parametrize("device", ["", "a/b", "x" * 33, "phy0 ap0", None, 5])
async def test_a_bad_device_is_refused_without_a_call(device):
    api = FakeApi()
    with pytest.raises(RfReadError) as err:
        await async_rf_read(api, RF_KIND_ASSOCLIST, device)  # type: ignore[arg-type]
    assert err.value.reason == "invalid_device" and err.value.unsupported
    assert api.calls == []


@pytest.mark.parametrize(
    ("error", "reason", "unsupported"),
    [
        (
            OpenWrtMethodNotFoundError("ubus object or method not found"),
            "method_not_found",
            True,
        ),
        (
            OpenWrtMethodNotFoundError(
                "rpcd ACL blocks iwinfo/survey (cached this session)"
            ),
            "permission_denied",
            True,
        ),
        (
            OpenWrtResponseError("ubus error 2 for iwinfo/survey"),
            "invalid_argument",
            True,
        ),
        (
            OpenWrtResponseError("ubus error 7 for iwinfo/survey"),
            "response_error",
            False,
        ),
        (OpenWrtTimeoutError("slow"), "timeout", False),
        (OpenWrtConnectionError("down"), "unreachable", False),
    ],
)
async def test_errors_are_classified(error, reason, unsupported):
    api = FakeApi({("iwinfo", "survey"): error})
    with pytest.raises(RfReadError) as err:
        await async_rf_read(api, RF_KIND_SURVEY, "phy0-ap0")  # type: ignore[arg-type]
    assert (err.value.reason, err.value.unsupported) == (reason, unsupported)
    assert "phy0" not in str(err.value)


async def test_long_lists_are_cut_and_the_cut_is_reported():
    entries = [{"mac": f"02:00:00:00:{i // 256:02x}:{i % 256:02x}"} for i in range(300)]
    api = FakeApi({("iwinfo", "assoclist"): {"results": entries}})
    answer = await async_rf_read(api, RF_KIND_ASSOCLIST, "phy0-ap0")  # type: ignore[arg-type]
    assert len(answer["results"]) == RF_MAX_LIST_ENTRIES
    assert answer["_truncated"] == 300 - RF_MAX_LIST_ENTRIES


async def test_permission_denied_through_the_real_call_path():
    """A real _call: status 6 twice -> one re-login, then cached, no storm."""
    api = OpenWrtAPI(
        host="192.0.2.1", port=80, username="root", password="pw", session=None
    )
    api._token = "a" * 32
    api._token_expires_at = float("inf")
    calls: list[str] = []

    async def raw(payload: dict) -> Any:
        calls.append(payload["params"][2])
        raise api_module.OpenWrtAuthError("ubus permission denied (status=6)")

    async def login() -> None:
        calls.append("login")

    api._raw_call = raw  # type: ignore[method-assign]
    api.login = login  # type: ignore[method-assign]
    api._ensure_fresh_token = _noop  # type: ignore[method-assign]
    for _ in range(3):
        with pytest.raises(RfReadError) as err:
            await async_rf_read(api, RF_KIND_SURVEY, "phy0-ap0")
        assert err.value.reason == "permission_denied"
    assert calls == ["survey", "login", "survey"]  # later attempts: cached


async def _noop() -> None:
    return None


# --- options ------------------------------------------------------------------------------


def test_options_default_off_and_only_true_switches_on():
    assert options_from_entry({}).enabled is False
    assert options_from_entry(None).kinds == frozenset()
    opts = options_from_entry(
        {
            OPTION_WIFI_RF_ENABLED: True,
            OPTION_WIFI_RF_GET_STATUS: True,
            OPTION_WIFI_RF_ASSOCLIST: "yes",
            OPTION_WIFI_RF_EVERY_N_POLLS: 0,
        }
    )
    assert opts.kinds == {RF_KIND_GET_STATUS}
    assert opts.every_n_polls == 5
    off = options_from_entry({OPTION_WIFI_RF_GET_STATUS: True})
    assert off.enabled is False and off.kinds == frozenset()


# --- schedule -----------------------------------------------------------------------------


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


RADIO = RadioPlanInput("radio1", ("phy1-ap0", "phy1-ap1"), (36, "DE"))


def _opts(*options: str, every: int = 5) -> Any:
    return options_from_entry(
        {OPTION_WIFI_RF_ENABLED: True, OPTION_WIFI_RF_EVERY_N_POLLS: every}
        | dict.fromkeys(options, True)
    )


def _yes(_name: str) -> tuple[bool, str | None]:
    return True, None


def _no(_name: str) -> tuple[bool, str | None]:
    return False, "permission_denied"


def test_off_plans_nothing():
    collector = RfCollector()
    assert (
        collector.plan(options_from_entry({}), [RADIO], paused=False, capability=_yes)
        == []
    )
    assert collector.plan(_opts(), [RADIO], paused=False, capability=_yes) == []


def test_periodic_reads_every_n_polls_and_never_below_the_floor():
    clock = Clock()
    collector = RfCollector(clock=clock)
    opts = _opts(OPTION_WIFI_RF_GET_STATUS, OPTION_WIFI_RF_ASSOCLIST)
    planned = []
    for _poll in range(11):
        targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
        for t in targets:
            collector.targets.setdefault((t.kind, t.device), _state()).last_at = clock.t
        planned.append(sorted((t.kind, t.device) for t in targets))
        clock.t += 60.0
    first = [
        ("assoclist", "phy1-ap0"),
        ("assoclist", "phy1-ap1"),
        ("get_status", "phy1-ap0"),
    ]
    assert planned[0] == first  # start probe
    assert planned[5] == first and planned[10] == first
    assert all(planned[i] == [] for i in (1, 2, 3, 4, 6, 7, 8, 9))
    # N=1 is still held to the 300 s floor per target.
    collector = RfCollector(clock=clock)
    opts = _opts(OPTION_WIFI_RF_GET_STATUS, every=1)
    hits = 0
    for _poll in range(10):
        for t in collector.plan(opts, [RADIO], paused=False, capability=_yes):
            collector.targets.setdefault((t.kind, t.device), _state()).last_at = clock.t
            hits += 1
        clock.t += 60.0
    assert hits == 2  # t=0 and t=300 of 600 s


def _state() -> Any:
    from custom_components.openwrt_router.rf_collector import TargetState

    return TargetState()


def test_paused_polls_read_nothing():
    collector = RfCollector(clock=Clock())
    opts = _opts(OPTION_WIFI_RF_GET_STATUS)
    assert collector.plan(opts, [RADIO], paused=True, capability=_yes) == []
    assert collector.counters["polls_paused"] == 1


async def test_setup_lists_once_and_again_after_a_channel_change():
    clock = Clock()
    collector = RfCollector(clock=clock)
    opts = _opts(OPTION_WIFI_RF_LISTS)

    async def read(kind: str, device: str) -> dict:
        return {"results": []}

    targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
    assert sorted(t.kind for t in targets) == ["freqlist", "txpowerlist"]
    await collector.async_run(targets, read, list_keys={"radio1": RADIO.list_key})
    for _ in range(10):
        clock.t += 60
        assert collector.plan(opts, [RADIO], paused=False, capability=_yes) == []
    moved = RadioPlanInput("radio1", RADIO.devices, (100, "DE"))
    again = collector.plan(opts, [moved], paused=False, capability=_yes)
    assert sorted(t.kind for t in again) == ["freqlist", "txpowerlist"]


def test_survey_and_txpowerlist_need_the_core_capability():
    collector = RfCollector(clock=Clock())
    opts = _opts(OPTION_WIFI_RF_SURVEY, OPTION_WIFI_RF_LISTS)
    targets = collector.plan(opts, [RADIO], paused=False, capability=_no)
    assert [t.kind for t in targets] == ["freqlist"]
    state, reason = collector.kind_state("survey", "phy1-ap0")
    assert state is CapabilityState.UNSUPPORTED
    assert reason == "capability_unavailable:permission_denied"


async def test_unsupported_answers_back_off_without_a_storm():
    clock = Clock()
    collector = RfCollector(clock=clock)
    opts = _opts(OPTION_WIFI_RF_SURVEY, every=1)
    calls = []

    async def read(kind: str, device: str) -> dict:
        calls.append(kind)
        raise RfReadError("method_not_found", unsupported=True)

    for _ in range(30):  # 30 polls of 60 s
        targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
        await collector.async_run(targets, read)
        clock.t += 60
    assert calls == ["survey"]  # asked once, then the 1 h backoff
    state, reason = collector.kind_state("survey", "phy1-ap0")
    assert (state, reason) == (CapabilityState.UNSUPPORTED, "method_not_found")


async def test_transient_errors_back_off_exponentially():
    clock = Clock()
    collector = RfCollector(clock=clock)
    opts = _opts(OPTION_WIFI_RF_GET_STATUS, every=1)
    times = []

    async def read(kind: str, device: str) -> dict:
        times.append(clock.t)
        raise RfReadError("timeout", unsupported=False)

    for _ in range(60):
        targets = collector.plan(opts, [RADIO], paused=False, capability=_yes)
        await collector.async_run(targets, read)
        clock.t += 60
    gaps = [b - a for a, b in itertools.pairwise(times)]
    assert gaps[:3] == [300.0, 600.0, 1200.0]
    assert (
        collector.kind_state("get_status", "phy1-ap0")[0] is CapabilityState.UNREACHABLE
    )


async def test_round_time_limit_marks_the_rest():
    collector = RfCollector(round_timeout_s=0.05)

    async def read(kind: str, device: str) -> dict:
        await asyncio.sleep(1)
        return {}

    targets = [
        Target("get_status", "phy1-ap0", "radio1"),
        Target("assoclist", "phy1-ap0", "radio1"),
    ]
    result = await collector.async_run(targets, read)
    assert result.timed_out
    assert set(result.errors.values()) == {"round_timeout"}
    assert collector.counters["rounds_timed_out"] == 1
