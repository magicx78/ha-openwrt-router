"""Tests for net_explain.py: the optional local-AI annotation seam (RT8)."""

from __future__ import annotations

import asyncio
import dataclasses
import json
from types import SimpleNamespace
from typing import Any

import pytest

from custom_components.openwrt_router.const import DOMAIN
from custom_components.openwrt_router.net_events import (
    Category,
    CauseStatus,
    Incident,
    NetEvent,
    Origin,
    Scope,
    Severity,
)
from custom_components.openwrt_router.net_explain import (
    MAX_TEXT,
    ExplainResult,
    IncidentExplainer,
    async_annotate,
    async_register_explainer,
    build_snapshot,
    get_explainer,
)

MAC = "aa:bb:cc:dd:ee:ff"
HOST = "secret-laptop"


def _hass() -> Any:
    return SimpleNamespace(data={})


def _incident() -> Incident:
    return Incident(
        id="inc-1",
        type="wifi_mass_disconnect",
        scope=Scope.ROUTER,
        scope_key=f"ap1:{MAC}",
        severity=Severity.WARNING,
        confidence=0.7,
        origin=Origin.OBSERVED,
        cause="weak_signal",
        cause_status=CauseStatus.HYPOTHESIS,
        evidence=[{"kind": "disassoc", "ts": 100.0, "source": "log", "id": "ap1-1"}],
        routers=["ap1"],
        children=1,
        affected=2,
        first_seen=100.0,
        last_seen=160.0,
        occurrences=3,
    )


def _events() -> list[NetEvent]:
    return [
        NetEvent(
            id="ap1-1",
            ts=100.0,
            router="ap1",
            category=Category.WIFI,
            kind="disassoc",
            subject={"mac": MAC, "hostname": HOST, "ip": "10.0.0.5"},
            parent_id="inc-1",
        )
    ]


class _Fake:
    def __init__(self, result: Any = None, delay: float = 0.0, exc: Any = None):
        self.result = result
        self.delay = delay
        self.exc = exc
        self.seen: list[dict[str, Any]] = []

    async def explain(self, snapshot: dict[str, Any]) -> ExplainResult | None:
        self.seen.append(snapshot)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.result


async def test_no_explainer_returns_none() -> None:
    hass = _hass()
    assert get_explainer(hass) is None
    assert await async_annotate(hass, _incident(), _events()) is None


async def test_fake_explainer_gives_annotation() -> None:
    hass = _hass()
    fake = _Fake(ExplainResult("  Probably the antenna.  ", "weak_signal", ("e1",)))
    await async_register_explainer(hass, fake)
    assert isinstance(fake, IncidentExplainer)
    out = await async_annotate(hass, _incident(), _events())
    assert out is not None
    assert out["ai_note"] == "Probably the antenna."
    assert out["ai_suggested_cause"] == "weak_signal"
    assert out["ai_references"] == ["e1"]
    assert out["origin"] == "inferred"
    assert out["source"] == "ai"
    assert isinstance(out["ts"], float)
    json.dumps(out)


async def test_incident_is_unchanged() -> None:
    hass = _hass()
    inc = _incident()
    before = inc.to_dict()
    events = _events()
    events_before = [e.to_dict() for e in events]
    await async_register_explainer(
        hass, _Fake(ExplainResult("note", "router_crash", ("x",)))
    )
    out = await async_annotate(hass, inc, events)
    assert out is not None
    assert inc.to_dict() == before
    assert [e.to_dict() for e in events] == events_before
    assert inc.cause == "weak_signal"
    assert inc.cause_status is CauseStatus.HYPOTHESIS
    assert inc.severity is Severity.WARNING
    assert inc.confidence == 0.7
    with pytest.raises(dataclasses.FrozenInstanceError):
        events[0].cause = "x"  # type: ignore[misc]


async def test_timeout_respected() -> None:
    hass = _hass()
    await async_register_explainer(hass, _Fake(ExplainResult("late"), delay=5))
    loop = asyncio.get_running_loop()
    start = loop.time()
    assert await async_annotate(hass, _incident(), _events(), timeout=0.05) is None
    assert loop.time() - start < 1.0


async def test_raising_explainer_returns_none() -> None:
    hass = _hass()
    await async_register_explainer(hass, _Fake(exc=RuntimeError("boom")))
    assert await async_annotate(hass, _incident(), _events()) is None


async def test_empty_or_wrong_result_returns_none() -> None:
    hass = _hass()
    await async_register_explainer(hass, _Fake(ExplainResult("   ")))
    assert await async_annotate(hass, _incident(), _events()) is None
    await async_register_explainer(hass, _Fake("not a result"))
    assert await async_annotate(hass, _incident(), _events()) is None


async def test_second_registration_replaces_and_unregister_works(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = _hass()
    first, second = _Fake(ExplainResult("a")), _Fake(ExplainResult("b"))
    unreg1 = await async_register_explainer(hass, first)
    assert hass.data[DOMAIN]["explainer"] is first
    unreg2 = await async_register_explainer(hass, second)
    assert get_explainer(hass) is second
    assert "Replacing" in caplog.text
    unreg1()  # stale handle must not remove the newer one
    assert get_explainer(hass) is second
    unreg2()
    assert get_explainer(hass) is None
    assert await async_annotate(hass, _incident(), _events()) is None


async def test_register_tolerates_foreign_domain_data() -> None:
    hass = _hass()
    hass.data[DOMAIN] = "something else"
    assert get_explainer(hass) is None
    fake = _Fake()
    await async_register_explainer(hass, fake)
    assert get_explainer(hass) is fake


def test_snapshot_redacts_and_serialises() -> None:
    snap = build_snapshot(_incident(), _events())
    dumped = json.dumps(snap)
    assert MAC not in dumped
    assert "aa:bb" not in dumped
    assert HOST not in dumped
    assert "10.0.0.5" not in dumped
    assert "ap1" not in dumped
    assert snap["events"][0]["subject"] == {"mac": "..:dd:ee:ff"}
    assert snap["cause"] == "weak_signal"
    assert snap["cause_status"] == "hypothesis"
    assert snap["confidence"] == 0.7
    assert snap["origin"] == "observed"
    assert snap["severity"] == "warning"
    assert snap["scope"] == "router"
    assert snap["router_count"] == 1
    assert snap["first_seen"] == 100.0 and snap["last_seen"] == 160.0
    assert snap["evidence"] == [{"kind": "disassoc", "ts": 100.0, "source": "log"}]
    assert snap["children_refs"] == [snap["events"][0]["ref"]]


def test_snapshot_allow_hostnames() -> None:
    snap = build_snapshot(_incident(), _events(), allow_hostnames=True)
    assert snap["events"][0]["subject"]["hostname"] == HOST
    assert snap["routers"] == ["ap1"]
    assert MAC not in json.dumps(snap)
    assert "10.0.0.5" not in json.dumps(snap)


async def test_text_is_capped_and_snapshot_reaches_explainer() -> None:
    hass = _hass()
    fake = _Fake(
        ExplainResult(
            "x" * (MAX_TEXT * 3), "c" * 500, tuple("r" * 100 for _ in range(50))
        )
    )
    await async_register_explainer(hass, fake)
    out = await async_annotate(hass, _incident(), _events())
    assert out is not None
    assert len(out["ai_note"]) == MAX_TEXT
    assert len(out["ai_suggested_cause"]) <= 100
    assert len(out["ai_references"]) <= 20
    assert fake.seen and fake.seen[0]["cause"] == "weak_signal"
