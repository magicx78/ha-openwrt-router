"""Module keys and the caller (follow-up to B1): today by name only.

``api.async_get_module_key(module, purpose)`` checks that ``module`` has
registered its event prefix in this core run, not WHO asks: the one shared
``ConfigurationApi`` object carries no caller identity, and
``register_event_prefix`` hands back only a remover. So any module (or any
code holding the api object) gets the key of another registered module by
naming it, and can recompute that module's client pseudonyms.

A clean check needs a registration handle that the module passes when it
asks for its key; that changes the callers in the module files
(security_center, net_diagnostics, wifi_rf, traffic_analytics,
config_manager). Until then the first test documents today's state and the
second, a strict xfail, pins the expected behaviour.
"""

from __future__ import annotations

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks, core_of

from custom_components.openwrt_router.core_errors import ConfigApiError
from custom_components.openwrt_router.core_models import derive_module_key

OWNER = "security_center"
OTHER = "net_diagnostics"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def test_today_any_caller_gets_a_registered_modules_key(disks, tmp_path) -> None:
    env = await start_env(disks, tmp_path)
    try:
        env.api.register_event_prefix(f"{OWNER}.", module=OWNER)
        env.api.register_event_prefix(f"{OTHER}.", module=OTHER)
        installation = await env.api.async_get_installation_key()
        # the call names the module; nothing says which module is asking
        key = await env.api.async_get_module_key(OWNER, "pseudonyms")
        assert key == derive_module_key(installation, OWNER, "pseudonyms")
        assert core_of(env.hass).manager.stats["module_keys_refused"] == 0
    finally:
        await stop_env(env)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "Core 1.49.4: async_get_module_key checks only that the named module "
        "registered its event prefix, not who asks; there is no caller "
        "identity on the shared api object. Expected: a key only against the "
        "module's own registration handle, refused (module_keys_refused, "
        "reason module_not_owner) otherwise. Needs the module callers changed. "
        "Strict: turns red once the core is fixed."
    ),
)
async def test_other_module_does_not_get_the_key(disks, tmp_path) -> None:
    env = await start_env(disks, tmp_path)
    try:
        env.api.register_event_prefix(f"{OWNER}.", module=OWNER)
        # net_diagnostics holds only its own registration ...
        env.api.register_event_prefix(f"{OTHER}.", module=OTHER)
        # ... and asks for the key of security_center
        with pytest.raises(ConfigApiError) as err:
            await env.api.async_get_module_key(OWNER, "pseudonyms")
        assert err.value.details["reason"] == "module_not_owner"
        assert core_of(env.hass).manager.stats["module_keys_refused"] == 1
    finally:
        await stop_env(env)
