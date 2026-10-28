"""MAC address helpers (pure, no HA).

Phones, tablets and laptops use a randomised, *locally administered* MAC per
network ("private Wi-Fi address"). Such an address has bit 0x02 of the first
octet set and no manufacturer behind it: an OUI lookup would only produce
wrong vendors.
"""

from __future__ import annotations

import re

# aa:bb:cc:dd:ee:ff, aa-bb-cc-dd-ee-ff, aabb.ccdd.eeff (Cisco), aabbccddeeff
_MAC_RE = re.compile(
    r"^(?:[0-9a-f]{2}(?::[0-9a-f]{2}){5}|[0-9a-f]{2}(?:-[0-9a-f]{2}){5}"
    r"|[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}|[0-9a-f]{12})$"
)


def is_mac(value: object) -> bool:
    """Return True if ``value`` is a full 48-bit MAC in one of the forms above."""
    return isinstance(value, str) and bool(_MAC_RE.fullmatch(value.strip().lower()))


def is_locally_administered(mac: str | None) -> bool:
    """Return True for a locally administered (randomised) unicast MAC.

    Accepts ``aa:bb:..``, ``aa-bb-..`` and bare hex; anything that is not a
    full 48-bit MAC is False. Multicast addresses (bit 0x01) are not client
    addresses and also return False.
    """
    if not isinstance(mac, str):
        return False
    mac = mac.strip().lower()
    if not _MAC_RE.fullmatch(mac):
        return False
    first = int(mac[:2], 16)
    return bool(first & 0x02) and not first & 0x01
