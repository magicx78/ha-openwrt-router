"""Remove the duplicate Wi-Fi entities that 1.48.0-1.49.1 registered (1.49.2).

From 1.48.0 to 1.49.1 ``get_wifi_status`` asked ``iwinfo info`` per device.
That call succeeds on real routers, where the old ``iwinfo info {}`` had
failed and the UCI fallback had run. The radios then came without a UCI
section, so every Wi-Fi switch got the kernel ifname as its unique_id key
(``<entry_id>_wifi_ssid_phy1-ap0`` instead of ``<entry_id>_wifi_ssid_lan_5g``)
and Home Assistant registered it next to the user's old switch; the iwinfo
radios also carried noise/signal, which added ``<entry_id>_radio_<ifname>_*``
sensors that 1.47.1 never made on such a router.

1.49.2 makes the 1.47.1 call again, so the old switches come back. This
module removes the leftovers once, at setup, before the platforms add their
entities. A registry entry is removed only when ALL of this holds:

* it belongs to this integration (platform) and to this config entry, and
  is a switch ``<entry_id>_wifi_ssid_<key>`` or a radio sensor
  ``<entry_id>_radio_<key>_noise|signal``;
* ``<key>`` looks like a kernel netdev name (``phy0-ap0``, ``phy1-sta0``,
  ``wlan0``, ``wlan0-1``, ...);
* the Wi-Fi read of this setup succeeded and every radio has a UCI section
  (the router is on the section-keyed path again); an empty or failed read
  removes nothing;
* ``<key>`` is not the unique_id key of a switch of this poll, not a UCI
  section of this router (a section may be named like an ifname) and not
  the ifname of a radio of this poll;
* for a switch: the registry still has a switch of this entry keyed by one
  of this router's UCI sections on the same device (the original that
  returns); otherwise the duplicate is kept;
* it was created on or after :data:`REGRESSION_START` (2026-11-21 00:00 UTC;
  the code that made such entries did not exist before 02:25 UTC that day).
  Entities of routers that had ifname keys already before 1.48.0
  (network.wireless or iwinfo path) are therefore never touched.

Idempotent: once removed, nothing matches any more.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, RADIO_KEY_IFNAME, RADIO_KEY_UCI_SECTION

_LOGGER = logging.getLogger(__name__)

# No entry created before this instant can stem from the 1.48.0 change
# (commit fddb6cf, 2026-11-21 02:25 UTC; release 1.48.0 07:30 UTC).
REGRESSION_START = datetime(2026, 11, 21, 0, 0, tzinfo=UTC)

# Kernel netdev names of OpenWrt Wi-Fi interfaces: phy<N>-ap<M>,
# phy<N>-sta<M>, phy<N>-mesh<M>, wlan<N>, wlan<N>-<M>, wlan<N>-ap<M> ...
_NETDEV_RE = re.compile(
    r"^(?:phy\d+-(?:ap|sta|mesh|mon|wds)\d+|wlan\d+(?:-(?:ap|sta|mesh)?\d+)?)$"
)
_RADIO_METRIC_RE = re.compile(r"^(?P<key>.+)_(?:noise|signal)$")


def looks_like_netdev(key: str) -> bool:
    """True if ``key`` has the form of a kernel Wi-Fi interface name."""
    return bool(_NETDEV_RE.match(key))


def _dicts(items: Any) -> list[dict[str, Any]]:
    return [i for i in items or [] if isinstance(i, dict)]


def duplicate_entity_ids(
    entry_id: str,
    radios: Any,
    entries: Iterable[er.RegistryEntry],
) -> list[str]:
    """Entity ids of the 1.48.0-1.49.1 duplicates; see the module docstring.

    ``radios`` is ``coordinator.data.wifi_radios`` of this setup and
    ``entries`` the registry entries of the config entry.
    """
    current = _dicts(radios)
    sections = {str(r.get(RADIO_KEY_UCI_SECTION) or "") for r in current}
    if not current or "" in sections:
        # Failed/empty read, or a radio without section (ifname-keyed path):
        # nothing can be told apart safely.
        return []
    ifnames = {str(r.get(RADIO_KEY_IFNAME) or "") for r in current} - {""}
    protected = sections | ifnames

    switch_prefix = f"{entry_id}_wifi_ssid_"
    radio_prefix = f"{entry_id}_radio_"
    own = [
        e
        for e in entries
        if e.platform == DOMAIN and e.config_entry_id == entry_id and e.unique_id
    ]
    # Devices that still have their original, section-keyed switch.
    original_devices = {
        e.device_id
        for e in own
        if e.domain == "switch"
        and e.unique_id.startswith(switch_prefix)
        and e.unique_id[len(switch_prefix) :] in sections
    }

    result: list[str] = []
    for e in own:
        created = getattr(e, "created_at", None)
        if not isinstance(created, datetime) or created < REGRESSION_START:
            continue
        if e.domain == "switch" and e.unique_id.startswith(switch_prefix):
            key = e.unique_id[len(switch_prefix) :]
            if e.device_id not in original_devices:
                continue
        elif e.domain == "sensor" and e.unique_id.startswith(radio_prefix):
            match = _RADIO_METRIC_RE.match(e.unique_id[len(radio_prefix) :])
            if match is None:
                continue
            key = match.group("key")
        else:
            continue
        if key in protected or not looks_like_netdev(key):
            continue
        result.append(e.entity_id)
    return result


def async_remove_duplicate_wifi_entities(
    hass: HomeAssistant, entry_id: str, radios: Any
) -> int:
    """Remove the duplicates of this entry from the registry; return the count."""
    ent_reg = er.async_get(hass)
    entries = er.async_entries_for_config_entry(ent_reg, entry_id)
    removed = duplicate_entity_ids(entry_id, radios, entries)
    for entity_id in removed:
        ent_reg.async_remove(entity_id)
    if removed:
        _LOGGER.info(
            "Removed %d duplicate Wi-Fi entities registered by 1.48.0-1.49.1 "
            "(ifname-based unique_ids); the original switches are used again",
            len(removed),
        )
    return len(removed)
