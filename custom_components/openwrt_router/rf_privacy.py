"""The one masking step for every RF output form (pure, no I/O).

``as_dict`` stays the internal, complete form. Anything that leaves RF
(diagnostics, panel, logs, events) goes through :func:`mask_rf_output`,
which uses the Core's rules and placeholder:

- values under identifier keys (``const.DIAGNOSTICS_TO_REDACT``: ``ssid``,
  ``bssid``, ``mac``, ``hostname``, ``ip``, …, plus RF's ``client_key``)
  become ``core_masking.MASK``;
- other keys the Core calls secret (``core_masking.is_secret_key``) become
  ``MASK`` too, except RF's reference keys (``router_key``, ``radio_key``,
  ``key``, ``worst_key``), whose values are ids, radio names or digests;
- every string loses MAC addresses (replaced by ``MASK``) and then passes
  ``core_masking.redact_text``.

Why RF masks SSID/BSSID/MAC itself: ``core_masking.mask_for_output`` does
not detect them (keys or values), and it treats every ``*_key`` name as a
secret, which would wipe ``router_key``/``radio_key``. Both gaps are
reported in the plan document, section 9; tests pin them so a Core change
shows up.

Foreign SSIDs/BSSIDs never reach this point in clear text: the scan path
keeps them only as Core digests (:func:`.rf_scan_policy.sanitize_neighbors`).
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from typing import Any, Final

from .const import DIAGNOSTICS_TO_REDACT
from .core_masking import MASK, is_secret_key, redact_text

_LOGGER = logging.getLogger(__name__)

# Keys whose values identify a person, a device or a network.
IDENTIFIER_KEYS: Final = frozenset(DIAGNOSTICS_TO_REDACT | {"client_key"})
# RF keys whose values are Core router ids, UCI radio names, RadioRef
# strings or Core digests; MACs inside them are still masked.
REFERENCE_KEYS: Final = frozenset({"router_key", "radio_key", "key", "worst_key"})

# Same forms as mac_utils.is_mac (colon, dash, Cisco dots, bare 12 hex),
# found inside text. The hex lookarounds keep longer hex runs (Core ids,
# digests, checksums) intact.
_MAC_IN_TEXT: Final = re.compile(
    r"(?<![0-9A-Fa-f])(?:"
    r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5}"
    r"|[0-9A-Fa-f]{4}(?:\.[0-9A-Fa-f]{4}){2}"
    r"|[0-9A-Fa-f]{12}"
    r")(?![0-9A-Fa-f])"
)
_MAX_DEPTH: Final = 32


def _text(value: str) -> str:
    return redact_text(_MAC_IN_TEXT.sub(MASK, value))


def _key_value(key: Any, value: Any, depth: int) -> Any:
    name = str(key)
    if name in IDENTIFIER_KEYS:
        return MASK
    if name not in REFERENCE_KEYS and is_secret_key(name):
        return MASK
    return _walk(value, depth + 1)


def _walk(value: Any, depth: int) -> Any:
    if depth > _MAX_DEPTH:
        raise ValueError("RF output nested too deeply")
    if hasattr(value, "as_dict"):
        value = value.as_dict()
    if isinstance(value, Mapping):
        return {k: _key_value(k, v, depth) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_walk(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _text(value)
    if value is None or isinstance(value, bool | int | float):
        return value
    raise TypeError(f"cannot mask RF output of type {type(value).__name__}")


def mask_rf_output(data: Any) -> Any:
    """Return a masked plain copy of an RF result (object, dict or list).

    Objects with ``as_dict`` are turned into dicts first. The input is not
    changed; masking twice gives the same result.
    """
    return _walk(data, 0)
