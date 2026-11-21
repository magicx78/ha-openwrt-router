"""Traffic Analytics quality checks of Phase L (plan 2026-11-20 §20, §23).

* No ``lambda`` is handed to ``async_dispatcher_connect`` in any traffic
  module (HA would run it as an executor job, off the loop; the 1.47.1 fix).
* Nothing that identifies a device or a person reaches the log, at DEBUG
  level, while the reference fleet polls, every read route answers, the
  settings are written and the collector pushes: no MAC, no IP, no AP
  netdev name, no HA user id, no token.

Mocks only; no router, no Home Assistant instance, no network.
"""

from __future__ import annotations

import ast
import json
import logging
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from core_testkit import FakeDisks
from core_testkit import make_hass as core_make_hass
from test_traffic_engine import _reset_pending  # noqa: F401 - autouse fixture
from test_traffic_performance import fleet, run_rounds
from test_traffic_views import (
    COLLECTOR_ID,
    collector_users,
    envelope,
    http,
    ingest,
    users,
)

from custom_components.openwrt_router import traffic_output as out
from custom_components.openwrt_router.traffic_model import Scope

COMPONENT = Path(__file__).parent.parent / "custom_components" / "openwrt_router"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.test-token-value"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def test_no_lambda_is_handed_to_the_dispatcher() -> None:
    files = sorted(COMPONENT.glob("traffic_*.py"))
    assert len(files) > 15
    found = 0
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "async_dispatcher_connect":
                continue
            found += 1
            target = node.args[2] if len(node.args) > 2 else None
            assert target is not None, (path.name, node.lineno)
            assert not isinstance(target, ast.Lambda), (path.name, node.lineno)
    assert found >= 2  # the entities and the platform receiver


async def test_nothing_identifying_reaches_the_log(disks, caplog: Any) -> None:
    caplog.set_level(logging.DEBUG, logger="custom_components.openwrt_router")
    hass = users(core_make_hass())
    engine, coords = await fleet(hass)
    await run_rounds(engine, coords, hass, 1, 12)
    collector_users(hass)
    wan = next(p for p in engine.series.points() if p.scope is Scope.WAN)
    async with http(hass) as h:
        for path in (
            "/overview",
            "/points",
            "/talkers",
            "/clients",
            "/vlans",
            "/capacity",
            "/anomalies",
            "/recommendations",
            "/flows",
            "/settings",
            "/collector/users",
        ):
            assert (await h.get(path)).status == 200, path
        series = await h.get(
            "/series", params={"point_id": wan.point_id, "window": "24h"}
        )
        assert series.status == 200
        resp = await h.call(
            "post",
            "/settings",
            json={"collector": {"enabled": True, "user_id": COLLECTOR_ID}},
        )
        assert resp.status == 200
        ok = await ingest(h, envelope(engine.wall()))
        assert ok.status == 200, ok.data
        # refused: a wrong user with a token-like header, plain HTTP, bad body
        await h.call(
            "post",
            "/collector/ingest",
            headers={"Authorization": f"Bearer {TOKEN}", "X-Test-Https": "1"},
            json=envelope(engine.wall()),
        )
        await ingest(h, envelope(engine.wall()), https=False)
        await ingest(h, b'{"schema": "traffic.collector.v1", "records": [1]}')
        # a failing builder whose message carries a MAC: only the type is logged
        # at WARNING (the DEBUG traceback is HA's exc_info, kept off this check)
        boom = MagicMock(side_effect=ValueError("02:00:5e:99:99:99 at 192.0.2.99"))
        with patch.object(out, "capacity", boom):
            assert (await h.get("/capacity")).status == 500
    await run_rounds(engine, coords, hass, 13, 3)
    warned = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("ValueError" in r.getMessage() for r in warned)
    text = "\n".join(r.getMessage() for r in caplog.records).lower()
    text += json.dumps(engine.summary(), default=str).lower()
    for needle in (
        "02:00:5e:",  # every MAC of the fleet and the collector record
        "192.0.2.",
        "198.51.100.",
        "phy0-ap0",
        "phy1-ap0",
        COLLECTOR_ID,
        TOKEN.lower(),
        "gw-office",  # the host name of the test routers
    ):
        assert needle not in text, needle
