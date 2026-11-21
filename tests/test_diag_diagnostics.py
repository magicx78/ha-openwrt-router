"""Diagnostics download and the network diagnostics (release 1.47.0, part 2).

The new address fields of the poll (``wan_status.diag_facts``: next hop,
DNS servers) and the module's own block ("network_diagnostics") carry no
address, host or domain. The shared redaction list is unchanged; the block
in ``diagnostics.py`` adds its own pass. No network, no Home Assistant.
"""

from __future__ import annotations

import json
from typing import Any

from core_testkit import make_hass
from test_diag_runtime import (
    GLOBAL_IP,
    T0,
    disk,  # noqa: F401 - fixture
    make_diag,
    poll,
    target,
    wan_status,
)

from custom_components.openwrt_router import diagnostics
from custom_components.openwrt_router.const import (
    DIAGNOSTICS_REDACTED,
    DIAGNOSTICS_TO_REDACT,
)
from custom_components.openwrt_router.diag_runtime import (
    async_release_net_diagnostics,
)
from custom_components.openwrt_router.diagnostics import (
    DIAG_REDACT_KEYS,
    async_get_config_entry_diagnostics,
)

SECRETS = ("192.0.2.", "203.0.113.", GLOBAL_IP, "example.org", "generate_204")


async def module(hass: Any) -> Any:
    """A module with targets, networks and domains in its settings."""
    diag = await make_diag(
        hass,
        "r1",
        settings={
            "targets": [target("t1", "tcp", 443)],
            "internal_networks": ["192.0.2.0/24"],
            "local_domains": ["example.org"],
            "dns_query_name": "example.org",
        },
    )
    poll(diag, "r1", T0, uptime=5000, wan_status=wan_status(connected=False))
    return diag


async def test_new_address_fields_and_the_block_are_redacted(
    mock_config_entry_with_runtime,
    disk,  # noqa: F811
) -> None:
    hass = make_hass()
    diag = await module(hass)
    entry = mock_config_entry_with_runtime
    entry.runtime_data.coordinator.data.wan_status = wan_status()
    result = await async_get_config_entry_diagnostics(hass, entry)

    facts = result["coordinator"]["data"]["wan_status"]["diag_facts"]
    assert facts["ipv4_gateway"] == DIAGNOSTICS_REDACTED
    assert facts["dns_servers"] == DIAGNOSTICS_REDACTED
    # the troubleshooting facts stay
    assert facts["interfaces"] == 2 and facts["ipv4_default_route"] is True

    block = result["network_diagnostics"]
    assert block["state"] in ("ok", "partial", "not_ready")
    assert "ha" not in block
    dumped = json.dumps(result, default=str)
    for secret in SECRETS:
        assert secret not in dumped, secret
    assert diag.settings["internal_networks"] == ["192.0.2.0/24"]  # untouched
    await async_release_net_diagnostics(hass, "r1")


async def test_a_broken_module_never_fails_the_download(
    mock_config_entry_with_runtime,
    disk,  # noqa: F811
) -> None:
    hass = make_hass()
    diag = await module(hass)

    def boom() -> Any:
        raise RuntimeError(f"boom {GLOBAL_IP}")

    diag.status = boom
    result = await async_get_config_entry_diagnostics(
        hass, mock_config_entry_with_runtime
    )
    assert result["network_diagnostics"] == {"loaded": False, "error": True}
    assert GLOBAL_IP not in json.dumps(result, default=str)
    await async_release_net_diagnostics(hass, "r1")
    # no module at all
    result = await async_get_config_entry_diagnostics(
        make_hass(), mock_config_entry_with_runtime
    )
    assert result["network_diagnostics"] == {"loaded": False}


def test_the_shared_redaction_list_is_unchanged_and_the_own_one_additive() -> None:
    # the block's own keys come on top; the shared list keeps its keys
    assert "address" in DIAGNOSTICS_TO_REDACT
    assert {"ipv4_gateway", "dns_servers", "internal_networks"} <= DIAG_REDACT_KEYS
    assert diagnostics.async_get_config_entry_diagnostics.__wrapped__ is not None
