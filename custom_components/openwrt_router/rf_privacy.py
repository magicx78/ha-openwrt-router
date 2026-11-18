"""The one output step for RF results: Core pseudonyms, then Core masking.

``as_dict`` stays the internal, complete form. Anything that leaves RF
(diagnostics, panel, logs) goes through :func:`mask_rf_output`:

1. objects with ``as_dict`` become plain dicts, all the way down;
2. values under :data:`RF_IDENTIFIER_FIELDS` (``mac``, ``bssid``, ``ssid``,
   ``ssids``, ``client_mac``, ``hostname``, ``ip``) become the Core pseudonym
   ``core_masking.pseudonymise_identifier(kind, value, key)``; a value that
   is not of its kind becomes ``core_masking.IDENTIFIER_INVALID``;
3. MAC addresses inside other strings (evidence codes, notes) become the
   Core pseudonym of kind ``mac``;
4. ``core_masking.mask_for_output`` (secret names, free-text redaction), with
   the other ``const.DIAGNOSTICS_TO_REDACT`` names as extra secret keys.

The key is the ``wifi_rf`` module key (:func:`rf_key_request`). Without a
key (installation key lost) every identifier becomes ``core_masking.MASK``;
the raw value never leaves.

What this does beyond the Core (why it is kept): the Core's
``pseudonymise_fields`` walks mappings and lists only (an RF object passes
it unchanged, MACs included), never looks into free text, and is not
idempotent (a second pass turns a pseudonym into ``IDENTIFIER_INVALID``).
Steps 1 and 3 and the "already a pseudonym of this kind stays" rule of
step 2 close exactly those three gaps, plus the keyless fallback; every
pseudonym itself is the Core's.

RF names no field ``*_key`` and no counter with a secret word any more
(contract #108, #110): the Core masks such names, so the former RF
exception for ``router_key``/``radio_key``/``key``/``worst_key`` is gone.

Foreign SSIDs/BSSIDs never reach this point in clear text: the scan path
keeps them only as Core pseudonyms (:func:`.rf_scan_policy.sanitize_neighbors`).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Mapping
from typing import Any, Final, Protocol

from .const import DIAGNOSTICS_TO_REDACT
from .core_masking import (
    IDENTIFIER_INVALID,
    IDENTIFIER_PSEUDONYM_HEX_LENGTH,
    IDENTIFIER_PSEUDONYM_PREFIXES,
    MASK,
    mask_for_output,
    pseudonymise_identifier,
)
from .rf_capabilities import RF_MODULE

_LOGGER = logging.getLogger(__name__)

# Purpose of the one wifi_rf module key (contract §11.5). One key for all
# RF pseudonyms: the Core keeps the kinds apart, and an own BSSID shown on
# output equals its pseudonym in a neighbor list.
RF_PSEUDONYM_PURPOSE: Final = "pseudonym"

# RF field name -> Core identifier kind (pseudonymise_identifier).
RF_IDENTIFIER_FIELDS: Final[Mapping[str, str]] = {
    "mac": "mac",
    "bssid": "bssid",
    "ssid": "ssid",
    "ssids": "ssid",
    "client_mac": "client",
    "hostname": "hostname",
    "ip": "ip",
}
# Identifying names without a Core kind: masked like secrets on output.
MASKED_FIELDS: Final = frozenset(DIAGNOSTICS_TO_REDACT - set(RF_IDENTIFIER_FIELDS))

# Same forms as mac_utils.is_mac (colon, dash, Cisco dots, bare 12 hex),
# found inside text. The hex lookarounds keep longer hex runs (Core ids,
# pseudonyms, digests, checksums) intact.
_MAC_IN_TEXT: Final = re.compile(
    r"(?<![0-9A-Fa-f])(?:"
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"
    r"|[0-9A-Fa-f]{12}"
    r")(?![0-9A-Fa-f])"
)
_PSEUDONYM: Final = {
    kind: re.compile(
        re.escape(prefix) + f"[0-9a-f]{{{IDENTIFIER_PSEUDONYM_HEX_LENGTH}}}"
    )
    for kind, prefix in IDENTIFIER_PSEUDONYM_PREFIXES.items()
}
_MAX_DEPTH: Final = 32


class ModuleKeySource(Protocol):
    """What RF needs from the Core configuration API (contract §11.5)."""

    def async_get_module_key(self, module: str, purpose: str = "") -> Awaitable[bytes]:
        """Return the module key (``ConfigurationApiProtocol``)."""


def rf_key_request(api: ModuleKeySource) -> Awaitable[bytes]:
    """Return the Core call that yields RF's pseudonym key (not awaited).

    ``await rf_key_request(api)`` is ``api.async_get_module_key("wifi_rf",
    "pseudonym")``: 32 bytes derived by the Core from the installation key
    (contract §11.5). It is the ``key`` of
    :func:`.rf_scan_policy.sanitize_neighbors` and :func:`mask_rf_output`.
    The Core gives it only after ``register_event_prefix("wifi_rf.",
    module="wifi_rf")`` in the same run; a lost installation key raises
    ``InstallationKeyLostError`` and RF substitutes nothing. RF never makes
    or stores a key itself; after an installation key reset all RF
    pseudonyms change.
    """
    return api.async_get_module_key(RF_MODULE, RF_PSEUDONYM_PURPOSE)


def client_ref(mac: str, key: bytes) -> str:
    """Return ``CoreEvent.client_ref`` of a client (Core pseudonym ``cli_<16 hex>``).

    Equal to what :func:`mask_rf_output` shows under ``client_mac``.
    ValueError for a value that is not a MAC or a key under 16 bytes.
    """
    return pseudonymise_identifier("client", mac, key)


def _pseudonym(kind: str, value: Any, key: bytes | None) -> Any:
    if value is None:
        return None
    if isinstance(value, list | tuple):
        return [_pseudonym(kind, v, key) for v in value]
    if isinstance(value, str) and _PSEUDONYM[kind].fullmatch(value):
        return value  # already the Core pseudonym of this kind
    if key is None:
        return MASK
    try:
        return pseudonymise_identifier(kind, value, key)
    except (TypeError, ValueError):
        return IDENTIFIER_INVALID


def _text(value: str, key: bytes | None) -> str:
    if key is None:
        return _MAC_IN_TEXT.sub(MASK, value)
    return _MAC_IN_TEXT.sub(
        lambda m: pseudonymise_identifier("mac", m.group(0), key), value
    )


def _walk(value: Any, key: bytes | None, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("RF output nested too deeply")
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    if isinstance(value, Mapping):
        return {
            k: (
                _pseudonym(RF_IDENTIFIER_FIELDS[k], v, key)
                if k in RF_IDENTIFIER_FIELDS
                else _walk(v, key, depth + 1)
            )
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [_walk(v, key, depth + 1) for v in value]
    if isinstance(value, str):
        return _text(value, key)
    if value is None or isinstance(value, bool | int | float):
        return value
    raise TypeError(f"cannot mask RF output of type {type(value).__name__}")


def mask_rf_output(data: Any, *, key: bytes | None) -> Any:
    """Return a pseudonymised, masked plain copy of an RF result.

    ``key`` is the ``wifi_rf`` module key (:func:`rf_key_request`), or None
    when the Core has none (identifiers then become ``MASK``). The input is
    not changed; masking twice gives the same result.
    """
    return mask_for_output(_walk(data, key, 0), extra_keys=MASKED_FIELDS)
