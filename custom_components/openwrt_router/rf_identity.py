"""RF identities on top of the Core router id (pure, no I/O, not wired up yet).

``router_key`` in every RF type holds the Core router id
(``rtr_<32 hex>``, ``core_models.ROUTER_ID_PREFIX``). RF never derives it
from a config entry: after an adoption the router keeps its old id, so the
id must come from the router registry (``RouterRecord.router_id``).

The Core has no radio identifier (``AccessPointInfo`` / ``InterfaceInfo``
describe interfaces, not radios). ``radio_key`` is therefore the UCI radio
section name (``radio0``, ``radio1``; ``phy0`` in ``channel_plan``), which
is only unique together with the router id (:class:`RadioRef`).

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

from .core_models import ROUTER_ID_PREFIX, is_valid_id

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class RadioRef:
    """Identity of a radio: Core router id and UCI radio name together."""

    router_key: str
    radio_key: str

    def __str__(self) -> str:
        return f"{self.router_key}/{self.radio_key}"

    def as_dict(self) -> dict[str, str]:
        """Return the reference as a plain dict."""
        return {"router_key": self.router_key, "radio_key": self.radio_key}


def require_router_id(value: object) -> str:
    """Return ``value`` if it is a Core router id, else raise ValueError."""
    if not isinstance(value, str) or not is_valid_id(value, ROUTER_ID_PREFIX):
        raise ValueError("router id must be a Core router id (rtr_<32 hex>)")
    return value


def require_radio_key(value: object) -> str:
    """Return ``value`` if it is a usable UCI radio name, else raise ValueError.

    ``/`` is refused because :class:`RadioRef` prints as ``router/radio``.
    """
    if not isinstance(value, str) or not value.strip() or "/" in value:
        raise ValueError("radio key must be a non-empty UCI radio name")
    return value


def radio_ref(router_id: object, radio_key: object) -> RadioRef:
    """Return a validated :class:`RadioRef` (Core router id + UCI radio name)."""
    return RadioRef(require_router_id(router_id), require_radio_key(radio_key))
