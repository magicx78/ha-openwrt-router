"""The WiFi RF update signal runs its receivers on the event loop (1.48.0).

Same defect as 1.47.1 in the network diagnostics: Home Assistant's
dispatcher classifies every connected target with ``HassJob``; a sync
function without ``@callback`` (a lambda, too) is an executor job and runs
in a worker thread. The module receiver then called ``hass.async_create_task``
off the loop, the set of a router whose device appeared later was never
added and ``syncing`` stayed True.

Here the signal goes through the real dispatcher of a real (not started)
``HomeAssistant``; the entity platforms, the device registry and the RF
reads are fakes. No network, no router.
"""

from __future__ import annotations

import threading
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from core_testkit import fake_device_registry
from homeassistant.core import HassJob, HassJobType, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import frame
from homeassistant.helpers.dispatcher import DATA_DISPATCHER, async_dispatcher_send
from rf_center_kit import options
from test_diag_entities import Host
from test_wifi_rf_entities import (
    _router,
    _settle,
    _setup,
    disk,  # noqa: F401 - fixture
    host,  # noqa: F401 - fixture
)

from custom_components.openwrt_router import wifi_rf_entities as we
from custom_components.openwrt_router.const import (
    DATA_WIFI_RF_ENTITIES,
    SIGNAL_WIFI_RF,
)


def _receivers(hass: Any) -> list[Any]:
    """The targets connected to the WiFi RF signal (as HA stores them)."""
    return list(hass.data.get(DATA_DISPATCHER, {}).get(SIGNAL_WIFI_RF, {}))


async def test_the_signal_adds_a_late_router_set_on_the_event_loop(
    tmp_path,
    disk,  # noqa: F811
) -> None:
    hass = HomeAssistant(str(tmp_path))
    found = Host(hass)
    hass.devices = {}
    hass.data[dr.DATA_REGISTRY] = fake_device_registry(hass.devices)
    threads: list[int] = []
    original = we._on_update

    def recording(hass_: Any) -> None:
        threads.append(threading.get_ident())
        original(hass_)

    try:
        with (
            patch.object(we, "platforms_of", found),
            patch.object(we, "_on_update", recording),
            # HA's thread check reports as in production (restored after)
            patch.object(frame._hass, "hass", hass),
        ):
            # connected exactly as the integration does (async_sync_rf_entities)
            await _setup(
                found, {"gw": options("get_status"), "ap2": options("get_status")}
            )
            assert _router(found, "ap2") == {}
            receivers = [
                r for r in _receivers(hass) if getattr(r, "__self__", None) is None
            ]
            assert len(receivers) == 1  # the module receiver (not an entity)
            hass.devices["ap2"] = "dev-ap2"
            async_dispatcher_send(hass, SIGNAL_WIFI_RF)
            await hass.async_block_till_done()
            assert threads and set(threads) == {threading.get_ident()}  # the loop
            assert len(_router(found, "ap2")) == 7
            assert hass.data[DATA_WIFI_RF_ENTITIES].syncing is False
            # the reason: HA classifies the connected object itself
            for receiver in _receivers(hass):
                assert HassJob(receiver).job_type is HassJobType.Callback
    finally:
        await hass.async_stop(force=True)


async def test_the_entity_receiver_is_a_callback(host, disk) -> None:  # noqa: F811
    await _setup(host, {"gw": options("get_status")})
    assert host.entities()
    for entity in host.entities():
        assert HassJob(entity._handle_update).job_type is HassJobType.Callback


async def test_a_task_that_cannot_start_never_leaves_syncing_stuck(
    host,  # noqa: F811
    disk,  # noqa: F811
) -> None:
    await _setup(host, {"gw": options("get_status"), "ap2": options("get_status")})
    hass = host.hass
    hass.devices["ap2"] = "dev-ap2"
    create = hass.async_create_task
    hass.async_create_task = MagicMock(side_effect=RuntimeError("not the loop"))
    with pytest.raises(RuntimeError):
        we._on_update(hass)
    assert hass.data[DATA_WIFI_RF_ENTITIES].syncing is False
    # the next signal tries again
    hass.async_create_task = create
    we._on_update(hass)
    await _settle(hass)
    assert len(_router(host, "ap2")) == 7
