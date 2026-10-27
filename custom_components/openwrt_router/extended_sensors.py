"""Bulk enable/disable of the extended Wi-Fi sensors (radio / AP / port).

These sensors are disabled by default (``entity_registry_enabled_default``)
because they multiply with radios, SSIDs and ports. The options-flow switch
toggles them in one go instead of one click per entity:

- on:  enable every matching sensor the *integration* disabled and remember
       which ones were already enabled before;
- off: disable again what the switch enabled; sensors the user had enabled
       before the switch was turned on stay on.

Sensors disabled by the user (``disabled_by=USER``) are never touched. This
runs only when the option changes in the options flow — never from
``async_setup_entry`` (re-disabling on every setup was the v1.28.3 bug).
"""

from __future__ import annotations

import re

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er


def _extended_pattern(entry_id: str) -> re.Pattern[str]:
    # Anchored: a bare substring match would also hit unrelated unique_ids
    # that merely contain "_ap_" or "_port_".
    return re.compile(rf"^{re.escape(entry_id)}_(radio|ap|port)_")


@callback
def async_apply_extended_wifi_sensors(
    hass: HomeAssistant,
    entry: ConfigEntry,
    enabled: bool,
    preexisting: list[str],
) -> list[str]:
    """Toggle the extended sensors of ``entry``.

    Returns the unique_ids to store as the new "preexisting" list: the
    sensors that were enabled before switching on, or ``[]`` after switching off.
    """
    ent_reg = er.async_get(hass)
    pattern = _extended_pattern(entry.entry_id)
    matching = [
        ent
        for ent in er.async_entries_for_config_entry(ent_reg, entry.entry_id)
        if ent.domain == "sensor" and pattern.match(ent.unique_id)
    ]
    if enabled:
        already_on = sorted(
            ent.unique_id for ent in matching if ent.disabled_by is None
        )
        for ent in matching:
            if ent.disabled_by == er.RegistryEntryDisabler.INTEGRATION:
                ent_reg.async_update_entity(ent.entity_id, disabled_by=None)
        return already_on

    keep = set(preexisting)
    for ent in matching:
        if ent.disabled_by is None and ent.unique_id not in keep:
            ent_reg.async_update_entity(
                ent.entity_id, disabled_by=er.RegistryEntryDisabler.INTEGRATION
            )
    return []
