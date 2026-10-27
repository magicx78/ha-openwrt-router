"""MAC address helpers (pure, no HA).

Phones, tablets and laptops use a randomised, *locally administered* MAC per
network ("private Wi-Fi address"). Such an address has bit 0x02 of the first
octet set and no manufacturer behind it: an OUI lookup would only produce
wrong vendors.
"""

from __future__ import annotations

_HEX = "0123456789abcdef"


def is_locally_administered(mac: str | None) -> bool:
    """Return True for a locally administered (randomised) unicast MAC.

    Accepts ``aa:bb:..``, ``aa-bb-..`` and bare hex; anything that is not a
    full 48-bit MAC is False. Multicast addresses (bit 0x01) are not client
    addresses and also return False.
    """
    if not isinstance(mac, str):
        return False
    digits = "".join(c for c in mac.lower() if c in _HEX)
    if len(digits) != 12 or len(mac.strip()) not in (12, 14, 17):
        return False
    first = int(digits[:2], 16)
    return bool(first & 0x02) and not first & 0x01
