"""1.50.0: the sample answers of the "Zeitreise" tab are real route answers.

The frontend tests (``frontend/topology/src/enterprise/timemachine``) read
``tmFixture.json``. It is not written by hand: this test builds the world of
``test_tm_views`` (enterprise core, configuration manager, Security Center
with a VLAN drift, Network Intelligence with WAN flaps and one client with a
wrong key), asks the real route ``GET .../timemachine/timeline`` as an
administrator and as a user, with a failing source, an empty window, a
second page, a refused query and while switched off, and compares the
answers with the checked-in file.

Ids and keys are made repeatable (``uuid.uuid4`` counts, ``secrets.token_bytes``
is fixed, the route's clock is fixed); everything else is what the route
answers. All values are invented (locally administered MACs, TEST-NET
addresses, the router "Router e1"); the route's privacy check runs on every
body.

Regenerate after a deliberate change of the answer::

    TM_WRITE_FIXTURE=1 python -m pytest tests/test_tm_panel_fixture_v1500.py
"""

from __future__ import annotations

import itertools
import json
import os
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
)
from core_testkit import USER_ID, FakeDisks
from test_tm_views import around, close, full_env, http

from custom_components.openwrt_router import tm_views
from custom_components.openwrt_router.const import OPTION_TIME_MACHINE_ENABLED
from custom_components.openwrt_router.topology_panel import _PANEL_ACCESS_KEY

FIXTURE = (
    Path(__file__).parents[1]
    / "custom_components/openwrt_router/frontend/topology/src/enterprise/timemachine"
    / "tmFixture.json"
)
PAGE = 6  # small page: the first one is cut and has a next_until


@pytest.fixture
def disks() -> Any:
    with FakeDisks().patch() as fake:
        yield fake


def _answer(resp: Any) -> dict[str, Any]:
    return {"status": resp.status, "body": resp.data}


async def build(disks: Any, tmp_path: Any) -> dict[str, Any]:
    """Every answer the tab's tests need, from the real route."""
    seq = itertools.count(1)
    with (
        patch("uuid.uuid4", side_effect=lambda: uuid.UUID(int=next(seq))),
        patch("secrets.token_bytes", side_effect=lambda n=32: bytes(range(n))),
    ):
        world = await full_env(disks, tmp_path)
    hass = world.env.hass
    window = around(world)
    past = {
        "from": str(int(world.start - 10 * 86_400)),
        "until": str(int(world.start - 9 * 86_400)),
    }
    out: dict[str, Any] = {}
    with patch.object(tm_views.time, "time", return_value=world.start + 7200):
        async with http(hass) as h:
            out["admin"] = _answer(await h.get(params=window))
            page1 = await h.get(params={**window, "limit": str(PAGE)})
            out["admin_page1"] = _answer(page1)
            until = page1.data["next_until"]
            assert until is not None
            out["admin_page2"] = _answer(
                await h.get(params={**window, "limit": str(PAGE), "until": str(until)})
            )
            out["empty"] = _answer(await h.get(params=past))
            with patch.object(world.center, "overview", side_effect=RuntimeError):
                out["partial"] = _answer(await h.get(params=window))
                out["partial_empty"] = _answer(await h.get(params=past))
            out["bad_request"] = _answer(await h.get(params={"kind": "nope"}))
            hass.data[_PANEL_ACCESS_KEY] = {"e1": True}
            out["user"] = _answer(await h.get(user=USER_ID, params=window))
            hass.data.pop(_PANEL_ACCESS_KEY)
            world.env.entries[0].options[OPTION_TIME_MACHINE_ENABLED] = False
            out["off"] = _answer(await h.get(params=window))
            h.assert_private()
    await close(world)
    return out


def _dump(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=1, ensure_ascii=False) + "\n"


async def test_the_tab_fixture_is_the_real_route_answer(disks, tmp_path) -> None:
    doc = await build(disks, tmp_path)
    # the scenarios the frontend tests rely on
    assert doc["admin"]["body"]["status"] == "ok"
    assert doc["admin"]["body"]["omitted_client_marks"] >= 1
    assert doc["admin_page1"]["body"]["truncated"] is True
    assert doc["partial"]["body"]["status"] == "partial"
    assert doc["partial_empty"]["body"]["marks"] == []
    assert doc["empty"]["body"]["marks"] == []
    assert doc["bad_request"]["status"] == 400
    assert doc["off"]["body"]["status"] == "off"
    user = {s["id"]: s for s in doc["user"]["body"]["sources"]}
    assert user["core_audit"]["reason"] == "admin_only"
    assert doc["user"]["body"]["omitted_client_marks"] == 0
    text = _dump(doc)
    if os.environ.get("TM_WRITE_FIXTURE") == "1":
        FIXTURE.write_text(text, encoding="utf-8")
    assert FIXTURE.read_text(encoding="utf-8") == text, (
        "tmFixture.json differs from the route's answer; regenerate it with "
        "TM_WRITE_FIXTURE=1 (see the module docstring)"
    )
