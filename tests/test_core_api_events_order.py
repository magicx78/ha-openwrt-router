"""``api.events`` returns audit entries oldest first; ``limit`` keeps the newest.

The behaviour is unchanged (callers depend on it); the docstrings said
"newest first" and now say what the code does. This test pins both.
"""

from __future__ import annotations

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks

from custom_components.openwrt_router.config_api import ConfigurationApi
from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_models import ConfigurationApiProtocol

MODULE = "order_probe"
TYPE = f"{MODULE}.sample"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def test_docstrings_name_the_real_order() -> None:
    for doc in (
        ConfigurationApi.events.__doc__,
        ConfigurationApiProtocol.events.__doc__,
        AuditLog.events.__doc__,
    ):
        assert doc is not None
        assert "oldest first" in doc
        assert "newest first" not in doc


async def test_api_events_oldest_first_limit_keeps_newest(disks, tmp_path) -> None:
    env = await start_env(disks, tmp_path)
    try:
        env.api.register_event_prefix(f"{MODULE}.", module=MODULE)
        for i in range(5):
            env.api.emit(TYPE, source=MODULE, router_id=env.rid, data={"i": i})
        events = env.api.events(types=[TYPE])
        assert [e.data["i"] for e in events] == [0, 1, 2, 3, 4]
        stamps = [e.ts for e in events]
        assert stamps == sorted(stamps)
        newest = env.api.events(types=[TYPE], limit=2)
        assert [e.data["i"] for e in newest] == [3, 4]
    finally:
        await stop_env(env)
