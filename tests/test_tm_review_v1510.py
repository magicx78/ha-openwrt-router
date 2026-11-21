"""Network Time Machine 1.51.0: fixes of the review before the merge.

One test (or more) per finding, each red without its fix (checked against
``40e269c``), over the real write paths: the real outage tracker, the real
Client Stability transitions into the recorder, the timeline and sessions
routes over HTTP. Kits: ``tm_index_kit`` (store on ``core_testkit.FakeDisks``)
and the helpers of ``test_tm_clients_v1510``.
"""

# ruff: noqa: F811  (pytest fixtures imported from test_client_engine)
from __future__ import annotations

import json
import os
import random
import shutil
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from core_testkit import ADMIN_ID, FakeDisks, add_users
from homeassistant.exceptions import ServiceValidationError
from test_client_engine import M1, M2, client, data, disk, setup  # noqa: F401
from test_tm_clients_v1510 import clients_world, get, step
from tm_index_kit import RID, T0, world

from custom_components.openwrt_router import (
    core_store,
    tm_clients,
    tm_engine,
    tm_query,
    tm_sources,
    tm_store,
)
from custom_components.openwrt_router.client_history import Transition
from custom_components.openwrt_router.tm_engine import (
    async_apply_time_machine_options,
)
from custom_components.openwrt_router.tm_marks import QUOTAS
from custom_components.openwrt_router.tm_sources import (
    SourceResult,
    build_router_map,
    make_mark,
)
from custom_components.openwrt_router.tm_store import STOP_DISABLED

R1, R2, R3 = RID["r1"], RID["r2"], RID["r3"]


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def sessions_of(w: Any) -> list[Any]:
    return w.marks("client_session")


def mac_of(i: int) -> str:
    return f"02:00:5e:{(i >> 8) & 255:02x}:{i & 255:02x}:01"


# --- S2: open intervals are evicted last ----------------------------------------------


async def test_s2_an_open_outage_outlives_a_full_infrastructure_quota(disks) -> None:
    with world(disks, routers=3) as w:
        engine = await w.start()
        w.down("r1")
        [down] = w.marks("router_down")
        cycles = QUOTAS["infrastructure"] // 2 + 100
        for _ in range(cycles):  # r2 goes down and up: two marks each time
            w.clock.advance(60)
            w.down("r2")
            w.clock.advance(60)
            w.up("r2")
        stats = engine.index.stats()
        assert stats["evicted_infrastructure"] > 0 and stats.get("evicted_open", 0) == 0
        assert engine.index.get(down.seq) is down and down.is_open
        w.clock.advance(60)
        w.up("r1")
        assert down.end_state == "closed"
        [up] = [m for m in w.marks("router_up") if m.router == R1]
        assert up.params["duration_s"] == pytest.approx(w.clock.t - down.ts, abs=1)


async def test_s2_an_open_outage_evicted_after_all_still_books_its_end(disks) -> None:
    """Only open intervals left in the quota: the end is booked honestly."""
    with world(disks, routers=3) as w:
        engine = await w.start()
        engine.index.quotas["infrastructure"] = 1
        w.down("r1")
        w.clock.advance(60)
        w.down("r2")  # evicts r1's open outage: nothing else is left
        assert engine.index.stats().get("evicted_open") == 1
        w.clock.advance(60)
        w.up("r1")
        [up] = [m for m in w.marks("router_up") if m.router == R1]
        assert "duration_s" not in up.params  # its start is gone: no duration


async def test_s2_an_open_session_outlives_a_client_storm(disks, disk) -> None:
    async with clients_world(disks, disk) as w:
        step(w, [M1], [])  # the long session of M1 on r1
        recorder = w.engine.recorder
        [long] = [m for m in w.marks("client_session") if m.is_open]
        # 60 other clients connect and leave 100 times each (2 marks a cycle,
        # under the daily cap of 200): more than the client quota
        t = w.clock.t
        for cycle in range(100):
            for i in range(60):
                mac = mac_of(i)
                t += 0.01
                recorder.transition(mac, Transition(t, "start", "r2"), "5g")
                recorder.transition(mac, Transition(t + 0.005, "end", "r2"), "5g")
        stats = w.engine.index.stats()
        assert stats["evicted_clients"] > 0 and stats.get("evicted_open", 0) == 0
        assert w.engine.index.get(long.seq) is long and long.is_open
        recorder.transition(M1, Transition(w.clock.t + 1, "end", "r1"), "5g")
        assert long.end_state == "closed"


# --- S1: an NI event is a double only of the same mark of the same router -----------


def ni_event(w: Any, kind: str, ts: float, router: str | None) -> dict[str, Any]:
    """An NI event as ``read_ni_events`` turns it into a mark."""
    return make_mark(
        source="ni_events",
        source_id=f"ev_{kind}_{ts}",
        ts=ts,
        kind=tm_sources.ni_kind(kind),
        severity="warning",
        router_id=router,
        routers=build_router_map(w.hass),
        fleet=False,
        code=kind,
        ref=tm_sources.ref_of("network_intelligence", "event"),
    )


async def timeline_with(w: Any, ni: list[dict[str, Any]], now: float) -> dict:
    """The own index read by its real adapter, merged with these NI events."""
    query = tm_query.Query(now - 86400, now + 1)
    req = tm_sources.ReadRequest(query.since, query.until, True, now)
    index = await tm_sources.async_read_source(
        w.hass, "tm_index", req, build_router_map(w.hass)
    )
    assert index.state == "ok"
    ni_result = SourceResult("ni_events", "ok", marks=ni)
    return tm_query.merge([ni_result, index], query, admin=True, now=now)


def shown(body: dict) -> list[tuple[str, str, str | None]]:
    return [(m["source"], m["kind"], m["code"]) for m in body["marks"]]


def duplicates(body: dict) -> int:
    return {s["id"]: s["duplicates"] for s in body["sources"]}["ni_events"]


async def test_s1_an_ni_uplink_port_event_without_an_own_mark_stays(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.clock.advance(600)
        now = w.clock.t
        body = await timeline_with(w, [ni_event(w, "lan.uplink", now - 60, R1)], now)
        assert ("ni_events", "uplink_changed", "lan.uplink") in shown(body)
        assert duplicates(body) == 0


async def test_s1_the_outage_of_another_router_is_no_double(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.clock.advance(60)
        w.down("r1")
        [down] = w.marks("router_down")
        w.clock.advance(600)
        now = w.clock.t
        # NI reports r2 unreachable while r1 is down: r2 has no own mark
        body = await timeline_with(
            w, [ni_event(w, "system.router_unreachable", down.ts + 150, R2)], now
        )
        assert ("ni_events", "router_down", "system.router_unreachable") in shown(body)
        assert duplicates(body) == 0


async def test_s1_a_real_double_is_shown_once_and_counted(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.clock.advance(60)
        w.down("r1")
        [down] = w.marks("router_down")
        w.clock.advance(900)
        w.up("r1")
        up_at = w.clock.t
        w.clock.advance(600)
        now = w.clock.t
        ni = [
            # NI reports after the threshold and its settle delay
            ni_event(w, "system.router_unreachable", down.ts + 150, R1),
            ni_event(w, "system.router_reachable", up_at + 5, R1),
            # later NI has an outage the own index has not: it stays
            ni_event(w, "system.router_unreachable", now - 30, R1),
        ]
        body = await timeline_with(w, ni, now)
        assert duplicates(body) == 2
        kinds = shown(body)
        assert (
            kinds.count(("ni_events", "router_down", "system.router_unreachable")) == 1
        )
        assert [m["ts"] for m in body["marks"] if m["source"] == "ni_events"] == [
            now - 30
        ]
        assert ("tm_index", "router_down", "timeout") in kinds
        assert any(k[:2] == ("tm_index", "router_up") for k in kinds)


# --- S3: a cursor pages through one millisecond -------------------------------------


async def walk_route(w: Any, path: str, window: dict[str, str]) -> list[list[str]]:
    """All pages over HTTP with ``cursor``; the ids of each page."""
    pages: list[list[str]] = []
    params = {**window, "limit": "200"}
    while True:
        status, body = await get(w.hass, path, ADMIN_ID, params)
        assert status == 200, body
        items = body["sessions"] if path == "/sessions" else body["marks"]
        pages.append([item["id"] for item in items])
        assert len(pages) < 10
        if body["next_cursor"] is None:
            assert body["next_until"] is None
            return pages
        params = {**window, "limit": "200", "cursor": body["next_cursor"]}


async def test_s3_250_resumed_sessions_of_one_start_page_without_loss(
    disks, disk
) -> None:
    async with clients_world(disks, disk, clients=False) as w:
        add_users(w.hass)
        w.hass.is_stopping = False
        many = [mac_of(i) for i in range(250)]
        for _ in range(2):
            step(w, many, [])  # connected while the client switch is off
        await async_apply_time_machine_options(w.hass, on=True, clients=True)
        resumed = sessions_of(w)
        assert len(resumed) == 250 and len({m.ts for m in resumed}) == 1
        for group in range(3):  # 30 more, ten per poll, on r2
            step(w, many, [mac_of(1000 + 10 * group + i) for i in range(10)])
        assert len(sessions_of(w)) == 280
        window = {"from": str(int(T0 - 60)), "until": str(int(w.t + 60))}
        for path, extra in (("/sessions", {}), ("/timeline", {"source": "tm_clients"})):
            pages = await walk_route(w, path, {**window, **extra})
            ids = [i for page in pages for i in page]
            wanted = [m for m in w.engine.index if m.kind == "client_session"]
            if path == "/timeline":  # the timeline holds the roams etc. too
                wanted = [m for m in w.engine.index if m.client is not None]
            assert len(ids) == len(set(ids)) == len(wanted), path
            assert max(len(page) for page in pages) == 200  # inside one ms
        # an old client (``next_until`` only) is told the page is cut
        _status, body = await get(
            w.hass, "/sessions", ADMIN_ID, {**window, "limit": "200"}
        )
        assert body["truncated"] is True and body["next_until"] is not None


async def test_s3_resumed_sessions_keep_the_start_client_stability_knows(
    disks, disk
) -> None:
    async with clients_world(disks, disk, clients=False) as w:
        step(w, [M1, M2], [])
        for _ in range(12):  # both leave: Client Stability sees them offline
            step(w, [], [])
        connects = [w.t, w.t + 60]
        step(w, [M1], [])  # each comes back: a connect it observed
        step(w, [M1, M2], [])
        w.clock.advance(300)
        await async_apply_time_machine_options(w.hass, on=True, clients=True)
        starts = sorted(m.ts for m in sessions_of(w))
        assert starts == connects  # their connects, not the switching on


# --- S4: intervals that reach into the window come apart, on request ----------------


async def test_s4_an_old_open_outage_comes_with_spans_on_the_first_page(disks) -> None:
    with world(disks, routers=3) as w:
        add_users(w.hass)
        w.hass.is_stopping = False
        for entry in w.entries:
            entry.options["time_machine_enabled"] = True
        await w.start()
        w.down("r1")  # two days before the window, still down
        [down] = w.marks("router_down")
        w.clock.advance(2 * 86400)
        since = w.clock.t
        for _ in range(225):  # 450 marks inside the window
            w.clock.advance(60)
            w.down("r2")
            w.clock.advance(60)
            w.up("r2")
        w.clock.advance(60)
        window = {"from": str(int(since)), "until": str(int(w.clock.t + 1))}
        window["source"] = "tm_index"
        status, first = await get(
            w.hass, "/timeline", ADMIN_ID, {**window, "spans": "1"}
        )
        assert status == 200 and first["truncated"] is True
        [spanning] = first["spanning"]
        assert (spanning["ts"], spanning["end_state"]) == (down.ts, "open")
        assert spanning["spans_in"] is True and first["spanning_truncated"] is False
        # the walk without ``spans``: the outage is on no page, the rest once
        seen: list[str] = [m["id"] for m in first["marks"]]
        params = {**window, "cursor": first["next_cursor"]}
        while True:
            status, body = await get(w.hass, "/timeline", ADMIN_ID, params)
            assert status == 200 and body["spanning"] == []
            seen += [m["id"] for m in body["marks"]]
            if body["next_cursor"] is None:
                break
            params = {**window, "cursor": body["next_cursor"]}
        assert len(seen) == len(set(seen)) == 450
        assert spanning["id"] not in seen
        # without ``spans`` the first page has no ``spanning`` either
        status, plain = await get(w.hass, "/timeline", ADMIN_ID, window)
        assert plain["spanning"] == [] and spanning["id"] not in {
            m["id"] for m in plain["marks"]
        }


# --- K1: writes are bundled for five minutes ----------------------------------------


async def test_k1_a_change_arms_one_write_in_five_minutes(disks) -> None:
    with world(disks) as w:
        await w.start()
        w.flush()
        w.down("r1")
        assert tm_store.SAVE_DELAY_S == 300.0
        assert [delay for _f, delay in w.disk.delayed] == [300.0]


# --- K2 / K5: forget by pseudonym; a connected client is recorded again --------------


def forget_schema(hass: Any) -> Any:
    """The schema the forget action is registered with."""
    found: dict[str, Any] = {}

    def register(_hass, _domain, service, _handler, schema=None, **_kw) -> None:
        found[service] = schema

    hass.services.has_service = MagicMock(return_value=False)
    with patch("homeassistant.helpers.service.async_register_admin_service", register):
        tm_engine.async_register_time_machine_services(hass)
    return found["time_machine_forget_client"]


async def test_k2_forget_takes_the_pseudonym_and_exactly_one_of_both(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        for _ in range(3):
            step(w, [M1, M2], [])
        tmc1 = "tmc_" + w.engine.recorder.pseudonym(M1)
        schema = forget_schema(w.hass)
        # both pass the schema: the function answers in the user's language
        assert schema({"mac": M1, "client": tmc1}) == {"mac": M1, "client": tmc1}
        assert schema({"client": tmc1}) == {"client": tmc1}
        for bad in ({}, {"mac": M1, "client": tmc1}):
            with pytest.raises(ServiceValidationError) as err:
                await tm_engine.async_forget_client(w.hass, **bad)
            assert err.value.translation_key == "time_machine_mac_or_client"
        with pytest.raises(ServiceValidationError) as err:
            await tm_engine.async_forget_client(w.hass, client="tmc_" + "x" * 16)
        assert err.value.translation_key == "time_machine_invalid_client"
        answer = await tm_engine.async_forget_client(w.hass, client=tmc1)
        assert answer["deleted"] == 1
        assert {m.client for m in sessions_of(w)} == {w.engine.recorder.pseudonym(M2)}
        assert all(m.client != tmc1[4:] for m in w.engine.index)
        # K5: M1 is still connected; it is recorded again from its next move
        step(w, [M2], [M1])
        [again] = [m for m in sessions_of(w) if m.client == tmc1[4:]]
        assert again.is_open and again.router == R2


async def test_kc_forget_over_the_real_action_answers_translated(tmp_path) -> None:
    """Review K-c: a real HA service call; neither or both is the translated
    error ``time_machine_mac_or_client``, the input is never repeated."""
    from homeassistant.core import HomeAssistant

    from custom_components.openwrt_router.core_masking import (
        pseudonymise_identifier,
    )
    from custom_components.openwrt_router.tm_marks import MarkIndex

    hass = HomeAssistant(str(tmp_path))
    index = MarkIndex()
    key = b"k" * 32
    mine = pseudonymise_identifier("client", M1, key)[4:]
    index.add(ts=T0, kind="client_roam", router=R1, client=mine, code="roam")
    engine = SimpleNamespace(
        loaded=True,
        recorder=None,
        index=index,
        clock=lambda: T0 + 60,
        emit=MagicMock(),
        store=SimpleNamespace(
            schedule=MagicMock(), async_remove_copies=AsyncMock(return_value=0)
        ),
    )

    async def module_key() -> bytes:
        return key

    engine.async_module_key = module_key
    try:
        tm_engine.async_register_time_machine_services(hass)

        async def call(data: dict[str, Any]) -> Any:
            return await hass.services.async_call(
                "openwrt_router",
                "time_machine_forget_client",
                data,
                blocking=True,
                return_response=True,
            )

        with patch.object(tm_engine, "async_get_time_machine", lambda _h: engine):
            for data in ({}, {"mac": M1, "client": "tmc_" + mine}, {"mac": ""}):
                with pytest.raises(ServiceValidationError) as err:
                    await call(data)
                assert err.value.translation_key == "time_machine_mac_or_client"
                assert M1 not in f"{err.value} {err.value.args!r}"
            with pytest.raises(ServiceValidationError) as err:
                await call({"client": "tmc_not_a_pseudonym"})
            assert err.value.translation_key == "time_machine_invalid_client"
            assert "not_a_pseudonym" not in f"{err.value} {err.value.args!r}"
            assert (await call({"mac": M1}))["deleted"] == 1
            index.add(ts=T0, kind="client_roam", router=R1, client=mine, code="roam")
            assert (await call({"client": "tmc_" + mine}))["deleted"] == 1
        assert len(index) == 2  # the two tm_forgot_client marks, no client
    finally:
        await hass.async_stop(force=True)


async def test_k2_the_texts_say_mac_or_pseudonym_and_the_recorder() -> None:
    root = Path(tm_engine.__file__).parent
    services = (root / "services.yaml").read_text()
    assert (
        "    client:" in services
        and "required: true"
        not in services.split("time_machine_forget_client:")[1].split(
            "time_machine_clear_history:"
        )[0]
    )
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((root / name).read_text())
        fields = data["services"]["time_machine_forget_client"]["fields"]
        assert set(fields) == {"mac", "client"}
        assert "Recorder" in fields["mac"]["description"] or (
            "recorder" in fields["mac"]["description"]
        )
        assert "time_machine_mac_or_client" in data["exceptions"]


# --- K3: the option texts agree on host names ---------------------------------------


def test_k3_no_option_text_promises_host_names_are_never_shown() -> None:
    root = Path(tm_engine.__file__).parent
    for name in ("strings.json", "translations/en.json", "translations/de.json"):
        data = json.loads((root / name).read_text())
        text = data["options"]["step"]["init"]["data_description"]
        both = text["time_machine_enabled"] + text["time_machine_clients"]
        assert "never stored or shown" not in both
        assert "nie gespeichert oder angezeigt" not in both
        assert ("administrators" in both) or ("Administratoren" in both)


# --- K4: deleted client data leaves no old copy; a removed router its marks ----------


async def test_k4_purge_deletes_the_old_copies_of_a_real_file(tmp_path) -> None:
    from homeassistant.core import HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    try:
        store = tm_store.TimeMachineStore(hass)
        await store.async_load()
        now = time.time()
        store.index.add(
            ts=now, kind="client_roam", router=R1, client="ab" * 8, code="roam"
        )
        store.index.add(
            ts=now, kind="router_down", router=R1, code="timeout", end_state="open"
        )
        await store.async_flush(STOP_DISABLED)
        path = store._store.path
        assert os.path.isfile(path)
        for copy in (".bak", ".corrupt.2026-11-21T10-00-00"):
            shutil.copyfile(path, path + copy)
        assert await tm_engine.async_purge_clients(hass) == 1
        assert sorted(os.listdir(os.path.dirname(path))) == [os.path.basename(path)]
        rows = json.loads(Path(path).read_text(encoding="utf-8"))["data"]["marks"]
        assert len(rows) == 1 and "|router_down|" in rows[0]
    finally:
        await hass.async_stop(force=True)


@pytest.mark.parametrize("how", ["switch_off", "forget", "clear", "tm_off"])
async def test_k4_every_client_delete_removes_the_copies(disks, disk, how) -> None:
    removed: list[Any] = []
    with patch.object(core_store, "_remove_copies", removed.append):
        async with clients_world(disks, disk) as w:
            for _ in range(3):
                step(w, [M1], [])
            if how == "switch_off":
                await async_apply_time_machine_options(w.hass, on=True, clients=False)
            elif how == "forget":
                await tm_engine.async_forget_client(w.hass, M1)
            elif how == "clear":
                await tm_engine.async_clear_history(w.hass, True)
            else:
                await async_apply_time_machine_options(w.hass, on=False, clients=True)
            assert removed == [w.disk.path]


async def test_k4_removing_a_router_removes_its_marks(disks) -> None:
    removed: list[Any] = []
    with (
        world(disks, routers=3) as w,
        patch.object(core_store, "_remove_copies", removed.append),
    ):
        engine = await w.start()
        w.down("r1")
        w.down("r2")
        assert await tm_engine.async_remove_router(w.hass, R1) == 1
        assert {m.router for m in engine.index} >= {R2}
        assert R1 not in {m.router for m in engine.index}
        # no engine (the last router is gone): the file is edited
        w.flush()
        await engine.async_stop("unloaded")
        w.hass.data.pop(tm_engine.DATA_TIME_MACHINE_ENGINE, None)
        assert await tm_engine.async_remove_router(w.hass, R2) >= 1
        assert not [r for r in w.stored["marks"] if "|router_down|" in r]
        # review K-b: the old copies stay (router ids are no personal data)
        assert removed == []


async def test_kb_removing_a_router_keeps_the_copy_of_a_newer_file(tmp_path) -> None:
    """A downgrade left the newer file as a copy: removing a router must not
    delete the other routers' history in it (review K-b)."""
    from homeassistant.core import HomeAssistant

    hass = HomeAssistant(str(tmp_path))
    try:
        store = tm_store.TimeMachineStore(hass)
        await store.async_load()
        now = time.time()
        for router in (R1, R2):
            store.index.add(
                ts=now,
                kind="router_down",
                router=router,
                code="timeout",
                end_state="open",
            )
        await store.async_flush(STOP_DISABLED)
        path = store._store.path
        shutil.copyfile(path, path + ".bak")
        assert await tm_engine.async_remove_router(hass, R1) == 1
        assert os.path.isfile(path + ".bak")
        copy = json.loads(Path(path + ".bak").read_text(encoding="utf-8"))
        assert len(copy["data"]["marks"]) == 2  # R2's history is still there
    finally:
        await hass.async_stop(force=True)


async def test_k4_async_remove_entry_hands_the_router_to_the_time_machine(
    disks,
) -> None:
    import custom_components.openwrt_router as integration

    with world(disks, routers=2) as w:
        engine = await w.start()
        w.down("r1")
        entry = SimpleNamespace(entry_id="r1", title="Router 1")
        core = SimpleNamespace(async_remove_entry_core=AsyncMock(return_value=R1))
        with (
            patch.object(integration, "_enterprise_core", core),
            patch.object(integration, "async_remove_router_data", AsyncMock()),
        ):
            await integration.async_remove_entry(w.hass, entry)
        assert R1 not in {m.router for m in engine.index}


# --- K9: the pseudonym -> MAC table stays bounded ------------------------------------


async def test_k9_the_mac_table_keeps_open_clients_and_a_bounded_rest(
    disks, disk
) -> None:
    async with clients_world(disks, disk) as w:
        step(w, [M1], [])
        recorder = w.engine.recorder
        t = w.clock.t
        for i in range(3000):  # many short visitors
            mac = mac_of(i)
            recorder.transition(mac, Transition(t, "start", "r2"), "5g")
            recorder.transition(mac, Transition(t + 1, "end", "r2"), "5g")
        assert len(recorder._macs) <= tm_clients.MACS_RECENT_MAX + len(recorder._open)
        assert recorder.pseudonym(M1) in recorder._macs  # open: kept
        assert recorder.pseudonym(mac_of(2999)) in recorder._macs  # recent
        assert recorder.pseudonym(mac_of(0)) not in recorder._macs


# --- K10: routers unreachable at HA's start are no HA gap ----------------------------


async def test_k10_an_late_first_router_splits_the_ha_gap(disks) -> None:
    with world(disks) as w:
        await w.start()
        await w.ha_stop_and_write()
        stopped = w.clock.t
        w.clock.advance(300)
        w.hass.data[tm_engine.DATA_HA_STARTED] = w.clock.t  # HA runs again
        ha_started = w.clock.t
        w.clock.advance(3600)  # every router unreachable: none loads
        await w.start()
        [gap] = w.marks("ha_gap")
        assert (gap.ts, gap.end) == (pytest.approx(stopped), pytest.approx(ha_started))
        assert gap.params["gap_s"] == 300
        [unloaded] = [m for m in w.marks("observation_gap") if m.code == "unloaded"]
        assert (unloaded.ts, unloaded.end) == (ha_started, pytest.approx(w.clock.t))


async def test_k10_a_quick_start_keeps_one_ha_gap(disks) -> None:
    with world(disks) as w:
        await w.start()
        await w.ha_stop_and_write()
        w.clock.advance(300)
        w.hass.data[tm_engine.DATA_HA_STARTED] = w.clock.t
        w.clock.advance(20)
        await w.start()
        [gap] = w.marks("ha_gap")
        assert gap.end == pytest.approx(w.clock.t)
        assert not w.marks("observation_gap")


# --- K6: a full source is turned into marks in slices -------------------------------


async def test_k6_a_full_client_quota_yields_to_the_event_loop(disks) -> None:
    with world(disks) as w:
        engine = await w.start(clients=True)
        engine.clients_wanted = True
        for i in range(2500):
            engine.index.add(
                ts=w.clock.t - 3600 + i,
                kind="client_session",
                router=R1,
                client=f"{i:016x}",
                end=w.clock.t - 3000 + i,
                end_state="closed",
                params={"band": 5},
            )
        now = w.clock.t + 1
        req = tm_sources.ReadRequest(now - 86400, now, True, now)
        sleeps: list[float] = []
        real_sleep = tm_sources.asyncio.sleep

        async def counting_sleep(delay: float, *args: Any) -> Any:
            sleeps.append(delay)
            return await real_sleep(delay, *args)

        with patch.object(tm_sources.asyncio, "sleep", counting_sleep):
            result = await tm_sources.async_read_source(
                w.hass, "tm_clients", req, build_router_map(w.hass)
            )
        assert result.state == "ok" and len(result.marks) == 2500
        assert len(sleeps) >= 2  # one slice of 1000 marks at a time


# --- M1: the double test is the old rule, in O(log n) -------------------------------


def linear_rule(mark: dict[str, Any], own: list[dict[str, Any]]) -> bool:
    """The rule of f0a1930 (linear scan), kept here as the reference."""
    match = tm_query.NI_MATCH_S
    spans: dict[tuple[str, Any], list[tuple[float, float | None]]] = {}
    for m in own:
        if m["kind"] in tm_query.COVERED_NI_KINDS:
            end = m["end"] if m["end_state"] != "open" else None
            spans.setdefault((m["kind"], m["router_id"]), []).append((m["ts"], end))
    kind, router, ts = mark["kind"], mark["router_id"], mark["ts"]
    if kind not in tm_query.COVERED_NI_KINDS or (router is None and not mark["fleet"]):
        return False
    if kind in ("router_down", "lan_down"):
        return any(
            start - match <= ts <= (float("inf") if end is None else end + match)
            for start, end in spans.get((kind, router), ())
        )
    if any(abs(start - ts) <= match for start, _e in spans.get((kind, router), ())):
        return True
    down = {"router_up": "router_down", "lan_up": "lan_down"}.get(kind)
    return down is not None and any(
        end is not None and abs(end - ts) <= match
        for _s, end in spans.get((down, router), ())
    )


def own_mark(kind: str, router: str | None, ts: float, end: float | None) -> dict:
    return {
        "kind": kind,
        "router_id": router,
        "ts": ts,
        "end": end,
        "end_state": "open" if end is None else "closed",
    }


def ni_mark(kind: str, router: str | None, ts: float) -> dict:
    return {"kind": kind, "router_id": router, "ts": ts, "fleet": router is None}


KINDS = ("router_down", "router_up", "lan_down", "lan_up", "channel_changed")


@pytest.mark.parametrize("seed", range(40))
def test_m1_the_fast_rule_decides_like_the_linear_one(seed: int) -> None:
    rnd = random.Random(seed)
    routers = [R1, R2, R3, None]
    base = 1_800_000_000.0
    own: list[dict[str, Any]] = []
    for _ in range(rnd.choice([0, 1, 5, 60, 300])):
        kind = rnd.choice(KINDS)
        router = None if kind.startswith("lan") else rnd.choice(routers[:3])
        ts = base + round(rnd.uniform(0, 20000), 3)
        end = None
        if kind.endswith("down") and rnd.random() > 0.15:  # some stay open
            end = ts + round(rnd.choice([0, 1, 60, 179.999, 180, 900]), 3)
        own.append(own_mark(kind, router, ts, end))
    probes = []
    for _ in range(400):
        kind = rnd.choice((*KINDS, "uplink_changed", "wan_event"))
        router = rnd.choice(routers)
        if own and rnd.random() < 0.7:  # right at the borders of own marks
            o = rnd.choice(own)
            point = (
                o["end"] if (o["end"] is not None and rnd.random() < 0.5) else o["ts"]
            )
            ts = point + rnd.choice(
                [-180.001, -180, -179.999, 0, 179.999, 180, 180.001]
            )
        else:
            ts = base + round(rnd.uniform(-500, 21000), 3)
        probes.append(ni_mark(kind, router, ts))
    fast = tm_query._OwnSpans(own)
    for probe in probes:
        assert fast.holds(probe) == linear_rule(probe, own), (probe, seed)


def test_m1_overlapping_and_open_intervals_of_one_router() -> None:
    base = 1_800_000_000.0
    own = [
        own_mark("router_down", R1, base, None),  # open, then a later one
        own_mark("router_down", R1, base + 5000, base + 5060),
        own_mark("router_down", R2, base, base + 10000),
        own_mark("router_down", R2, base + 100, base + 200),  # inside the first
    ]
    fast = tm_query._OwnSpans(own)
    for router, ts in ((R1, base + 9000), (R2, base + 9000), (R2, base + 10180)):
        probe = ni_mark("router_down", router, ts)
        assert fast.holds(probe) is True is linear_rule(probe, own)
    probe = ni_mark("router_down", R2, base + 10180.001)
    assert fast.holds(probe) is False is linear_rule(probe, own)


def test_m1_a_flapping_router_costs_log_n_comparisons_per_event() -> None:
    """3000 own marks of one router, 3000 NI events: counted, not timed."""
    base = 1_800_000_000.0
    own = []
    for i in range(1500):
        start = base + i * 800
        own.append(own_mark("router_down", R1, start, start + 60))
        own.append(own_mark("router_up", R1, start + 60, None))
    events = [
        ni_mark(
            "router_down" if i % 2 == 0 else "router_up",
            R1,
            base + (i // 2) * 800 + (400 if i % 4 < 2 else 30),
        )
        for i in range(3000)
    ]
    fast = tm_query._OwnSpans(own)
    decided = [fast.holds(e) for e in events]
    assert decided[:300] == [linear_rule(e, own) for e in events[:300]]
    assert sum(decided) == 1500  # the 30 s ones are doubles, the 400 s ones not
    # at most four values compared per event (two neighbours, two lists);
    # the linear scan compared up to 1500 per event
    assert fast.checks <= 4 * 2 * len(events)


async def test_m1_drop_duplicates_uses_the_fast_index(disks) -> None:
    with world(disks, routers=2) as w:
        await w.start()
        w.clock.advance(60)
        w.down("r1")
        w.clock.advance(600)
        w.up("r1")
        now = w.clock.t + 1
        [down] = w.marks("router_down")
        made: list[Any] = []
        real = tm_query._OwnSpans

        def spy(marks: Any) -> Any:
            made.append(real(marks))
            return made[-1]

        with patch.object(tm_query, "_OwnSpans", spy):
            body = await timeline_with(
                w, [ni_event(w, "system.router_unreachable", down.ts + 150, R1)], now
            )
        assert duplicates(body) == 1 and len(made) == 1 and made[0].checks == 1


# --- K-a: a channel change never shows twice across a page boundary -----------------


def ni_reader(events: list[dict[str, Any]]) -> Any:
    async def read(_hass: Any, req: Any, _routers: Any, _deadline: float) -> Any:
        marks = [m for m in events if req.since <= m["ts"] < req.until]
        return tm_sources._finish("ni_events", marks, 0, False)

    return read


async def walk_pages(w: Any, params: dict[str, str], now: float, readers: Any) -> list:
    seen: list[tuple[str, str, float]] = []
    page = dict(params)
    for _ in range(20):
        query = tm_query.parse_query(page, now)
        body = await tm_query.async_timeline(
            w.hass, query, admin=True, now=now, readers=readers
        )
        seen += [(m["source"], m["kind"], m["ts"]) for m in body["marks"]]
        if body["next_cursor"] is None:
            return seen
        page = {**params, "cursor": body["next_cursor"]}
    raise AssertionError("no end")


@pytest.mark.parametrize("kind", ["dfs.new_channel", "system.router_reachable"])
async def test_ka_a_double_split_by_a_page_boundary_is_shown_once(disks, kind) -> None:
    with world(disks, routers=2) as w:
        engine = await w.start()
        w.clock.advance(3600)
        now = w.clock.t
        t_ni = now - 1000
        own = "channel_changed" if kind.startswith("dfs") else "router_up"
        code = "channel" if own == "channel_changed" else "reachable"
        engine.index.add(ts=t_ni + 60, kind=own, router=R1, code=code)
        for offset in (50, 30, -30):  # other marks: a page of 3 ends between
            engine.index.add(ts=t_ni + offset, kind="router_up", router=R2, code=code)
        readers = {
            "ni_events": ni_reader([ni_event(w, kind, t_ni, R1)])  # NI is older
        }
        params = {
            "from": str(int(now - 3000)),
            "until": str(int(now + 1)),
            "source": "ni_events,tm_index",
        }
        whole = await walk_pages(w, {**params, "limit": "500"}, now, readers)
        paged = await walk_pages(w, {**params, "limit": "3"}, now, readers)
        assert sorted(paged) == sorted(whole)
        r1 = [s for s in paged if s[2] in (t_ni, t_ni + 60)]
        assert r1 == [("tm_index", own, t_ni + 60)]  # once, the own mark
