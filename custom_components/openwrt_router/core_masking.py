"""Central secret masking for the enterprise core (plan 2026-11-17).

Pure functions, no HA import. Used for the audit log, the HA event bus,
``to_dict()`` of every core type and diagnostics.

Masking is key-name based: a mapping key whose name contains a secret word
(``password``, ``psk``, ``key``, ``token`` …) has its value replaced by
:data:`MASK`, recursively through mappings, lists, tuples and sets. A key is
split into words at ``_``, ``-``, ``.``, spaces and camelCase boundaries, and
trailing digits are dropped (UCI WEP keys are ``key1`` … ``key4``), so
``monkey`` or ``author`` stay readable while ``wpa_psk``, ``PrivateKey`` and
``key1`` are masked. Over-masking is preferred to a leak.

Values that are not reached through a key (for example a UCI option name in
a diff) must be checked with :func:`is_secret_key` by the caller.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Mapping
from typing import Any, Final

from .const import DIAGNOSTICS_REDACT_KEYS, DIAGNOSTICS_REDACTED

_LOGGER = logging.getLogger(__name__)

MASK: Final = DIAGNOSTICS_REDACTED
TRUNCATED: Final = "**TRUNCATED**"
MAX_DEPTH: Final = 32

# Whole words that mark a secret.
SECRET_WORDS: Final = frozenset(
    {
        "apikey",
        "auth",
        "credential",
        "credentials",
        "key",
        "passphrase",
        "passwd",
        "password",
        "pin",
        "private",
        "privkey",
        "psk",
        "pwd",
        "sae",
        "secret",
        "token",
        "wpa",
    }
)
# Substrings that mark a secret wherever they appear in the key.
SECRET_SUBSTRINGS: Final = ("password", "passwd", "passphrase", "secret", "token")
# Exact key names (lower case) that are secrets but contain no secret word.
SECRET_EXACT_KEYS: Final = frozenset(
    {k.lower() for k in DIAGNOSTICS_REDACT_KEYS} | {"ubus_rpc_session", "session"}
)
# Core metadata flags that contain a secret word but are never secret.
SAFE_KEYS: Final = frozenset({"contains_secrets"})

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_TRAILING_DIGITS = re.compile(r"\d+$")


def _words(name: str) -> list[str]:
    """Split ``name`` into lower-case words without trailing digits."""
    spaced = _CAMEL.sub(" ", name)
    return [
        _TRAILING_DIGITS.sub("", part.lower()) for part in _SPLIT.split(spaced) if part
    ]


def is_secret_key(name: object, extra_keys: Iterable[str] = ()) -> bool:
    """Return True if a mapping key or option ``name`` names a secret."""
    if not isinstance(name, str) or not name:
        return False
    lowered = name.lower()
    if lowered in SAFE_KEYS:
        return False
    if lowered in SECRET_EXACT_KEYS or lowered in {k.lower() for k in extra_keys}:
        return True
    if any(sub in lowered for sub in SECRET_SUBSTRINGS):
        return True
    words = _words(name)
    if any(word in SECRET_WORDS for word in words):
        return True
    # "api-key" / "api_key" written as two words
    return "".join(words) in SECRET_WORDS


def mask_value(value: Any) -> Any:
    """Mask one secret value; ``None`` stays ``None`` (absence is no secret)."""
    return None if value is None else MASK


def mask_secrets(data: Any, *, extra_keys: Iterable[str] = (), _depth: int = 0) -> Any:
    """Return a masked copy of ``data``; the input is never modified.

    Mappings become ``dict``, lists stay lists, tuples stay tuples, sets and
    frozensets become sorted lists (JSON-safe). Scalars are returned as is.
    Nesting deeper than :data:`MAX_DEPTH` is replaced by :data:`TRUNCATED`.
    """
    if _depth > MAX_DEPTH:
        return TRUNCATED
    extra = tuple(extra_keys)
    nxt = _depth + 1
    if isinstance(data, Mapping):
        return {
            key: (
                mask_value(value)
                if is_secret_key(key, extra)
                else mask_secrets(value, extra_keys=extra, _depth=nxt)
            )
            for key, value in data.items()
        }
    if isinstance(data, list):
        return [mask_secrets(v, extra_keys=extra, _depth=nxt) for v in data]
    if isinstance(data, tuple):
        return tuple(mask_secrets(v, extra_keys=extra, _depth=nxt) for v in data)
    if isinstance(data, set | frozenset):
        return sorted(
            (mask_secrets(v, extra_keys=extra, _depth=nxt) for v in data), key=str
        )
    return data
