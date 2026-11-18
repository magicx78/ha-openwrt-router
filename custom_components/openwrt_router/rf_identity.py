"""RF identities on top of the Core router id (pure, no I/O, not wired up yet).

``router_id`` in every RF type holds the Core router id
(``rtr_<32 hex>``, ``core_models.ROUTER_ID_PREFIX``). RF never derives it
from a config entry: after an adoption the router keeps its old id, so the
id must come from the router registry (``RouterRecord.router_id``).

The Core has no radio registry (``AccessPointInfo`` / ``InterfaceInfo``
describe interfaces, not radios). ``radio_id`` is therefore the UCI radio
section name (``radio0``, ``radio1``; ``phy0`` in ``channel_plan``), which
is only unique together with the router id (:class:`RadioRef`). It is the
value RF puts into the typed ``CoreEvent.radio_id`` (contract §12.1, #107),
so :func:`require_radio_id` uses the Core's token rule for that field.

Names: ``router_id``/``radio_id``, never ``router_key``/``radio_key`` --
the Core masks every ``*_key`` name again (contract #108), so a ``*_key``
field would lose its value in every output.

The dataclasses keep plain ``str`` fields (no check in ``__post_init__``) so
the pure analysis stays cheap and its tests can use short names; the
boundary into RF validates with :func:`require_router_id` /
:func:`radio_ref`.

Importing ``core_models`` pulls in ``homeassistant.exceptions`` through
``core_errors`` (transitive, reported in the plan document, section 9).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from .core_models import ROUTER_ID_PREFIX, check_token, is_valid_id

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RadioRef:
    """Identity of a radio: Core router id and UCI radio name together."""

    router_id: str
    radio_id: str

    def __str__(self) -> str:
        return f"{self.router_id}/{self.radio_id}"

    def as_dict(self) -> dict[str, str]:
        """Return the reference as a plain dict."""
        return {"router_id": self.router_id, "radio_id": self.radio_id}


def require_router_id(value: object) -> str:
    """Return ``value`` if it is a Core router id, else raise ValueError."""
    if not isinstance(value, str) or not is_valid_id(value, ROUTER_ID_PREFIX):
        raise ValueError("router id must be a Core router id (rtr_<32 hex>)")
    return value


def require_radio_id(value: object) -> str:
    """Return ``value`` if it is a usable UCI radio name, else raise ValueError.

    The Core's token rule of ``CoreEvent.radio_id`` (``check_token``: 1-128
    characters ``[A-Za-z0-9._:@-]``, no ``..``). That also refuses ``/``,
    which :class:`RadioRef` uses as separator (``router/radio``), and
    blanks. DECIDED: stricter than before (any non-blank text without
    ``/``) so every RF radio id can go into the typed event field.
    """
    if not isinstance(value, str) or not _is_token(value):
        raise ValueError("radio id must be a UCI radio name")
    return value


def _is_token(value: str) -> bool:
    try:
        check_token("radio_id", value)
    except ValueError:
        return False
    return True


def radio_ref(router_id: object, radio_id: object) -> RadioRef:
    """Return a validated :class:`RadioRef` (Core router id + UCI radio name)."""
    return RadioRef(require_router_id(router_id), require_radio_id(radio_id))
