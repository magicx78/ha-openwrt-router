"""The diagnostics update signal runs its receivers on the event loop (1.47.1).

Home Assistant's dispatcher classifies every connected target with
``HassJob``: a sync function without ``@callback`` (a lambda, too) is an
executor job and runs in a worker thread. The module's receiver then called
``hass.async_create_task`` off the loop (RuntimeError after a restart), the
late gateway sensor was never added and ``syncing`` stayed True.

Here the signal goes through the real dispatcher of a real (not started)
``HomeAssistant``; the entity platforms and the device registry are fakes.
No network, no router.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from core_testkit import fake_device_registry, make_hass
from homeassistant.core import HassJob, HassJobType, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import frame
from homeassistant.helpers.dispatcher import DATA_DISPATCHER, async_dispatcher_send
from test_diag_entities import Host, gateways, module
from test_diag_runtime import disk  # noqa: F401 - fixture

from custom_components.openwrt_router import diag_entities as de
from custom_components.openwrt_router.const import (
    DATA_DIAG_ENTITIES,
    DIAG_GATEWAY_UID_SUFFIX,
    SIGNAL_NET_DIAGNOSTICS,
)
from custom_components.openwrt_router.diag_runtime import (
    async_release_net_diagnostics,
)


def _receivers(hass: Any) -> list[Any]:
    """The targets connected to the diagnostics signal (as HA stores them)."""
    return list(hass.data.get(DATA_DISPATCHER, {}).get(SIGNAL_NET_DIAGNOSTICS, {}))


async def test_the_signal_adds_a_late_gateway_sensor_on_the_event_loop(
    tmp_path,
    disk,  # noqa: F811
) -> None:
    hass = HomeAssistant(str(tmp_path))
    found = Host(hass)
    hass.devices = {"r1": "dev-r1"}  # r2's device appears later
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    threads: list[int] = []
    original = de._on_update

    def recording(hass_: Any) -> None:
        threads.append(threading.get_ident())
        original(hass_)

    try:
        with (
            patch.object(de, "platforms_of", found),
            patch.object(de, "_on_update", recording),
            # HA's thread check reports as in production (restored after)
            patch.object(frame._hass, "hass", hass),
        ):
            # connected exactly as the integration does (async_sync_diag_entities)
            diag = await module(found, "r1", "r2", devices=("r1",))
            assert set(gateways(found)) == {"r1" + DIAG_GATEWAY_UID_SUFFIX}
            [receiver] = _receivers(hass)
            hass.devices["r2"] = "dev-r2"
            assert de.router_waiting(hass, diag)
            async_dispatcher_send(hass, SIGNAL_NET_DIAGNOSTICS)
            await hass.async_block_till_done()
            assert threads == [threading.get_ident()]  # the loop, no worker
            assert set(gateways(found)) == {
                "r1" + DIAG_GATEWAY_UID_SUFFIX,
                "r2" + DIAG_GATEWAY_UID_SUFFIX,
            }
            assert hass.data[DATA_DIAG_ENTITIES].syncing is False
            assert not de.router_waiting(hass, diag)
            # the reason: HA classifies the connected object itself
            assert HassJob(receiver).job_type is HassJobType.Callback
            for entry in ("r1", "r2"):
                await async_release_net_diagnostics(hass, entry)
    finally:
        await hass.async_stop(force=True)


async def test_the_entity_receiver_is_a_callback(host_hass, disk) -> None:  # noqa: F811
    hass, found = host_hass
    await module(found, "r1", devices=("r1",))
    for entity in found.entities():
        assert HassJob(entity._handle_update).job_type is HassJobType.Callback
    await async_release_net_diagnostics(hass, "r1")


async def test_a_task_that_cannot_start_never_leaves_syncing_stuck(
    host_hass,
    disk,  # noqa: F811
) -> None:
    hass, found = host_hass
    diag = await module(found, "r1", "r2", devices=("r1",))
    hass.devices["r2"] = "dev-r2"
    create = hass.async_create_task
    hass.async_create_task = MagicMock(side_effect=RuntimeError("not the loop"))
    with pytest.raises(RuntimeError):
        de._on_update(hass)
    assert hass.data[DATA_DIAG_ENTITIES].syncing is False
    # the next signal tries again
    hass.async_create_task = create
    de._on_update(hass)
    for task in list(hass.tasks):
        await task
    assert not de.router_waiting(hass, diag)
    for entry in ("r1", "r2"):
        await async_release_net_diagnostics(hass, entry)


@pytest.fixture
def host_hass() -> Any:
    hass = make_hass()
    found = Host(hass)
    with patch.object(de, "platforms_of", found):
        yield hass, found
