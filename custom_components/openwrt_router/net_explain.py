"""Optional seam for a local AI that annotates incidents (RT8).

Rules (non-negotiable):

* Annotation only. The result is a note (``ai_note``) next to an incident.
  It never changes ``cause``, ``cause_status``, ``cause_level``,
  ``severity`` or ``confidence``: the deterministic root cause stays
  authoritative. ``async_annotate`` does not touch the incident it is given.
* Never authoritative. The annotation is marked ``origin="inferred"`` and
  ``source="ai"``; ``suggested_cause`` is a suggestion for a human.
* Local only. This module makes no network call, ships no model file and
  adds no requirement. Whatever registers an explainer is responsible for
  keeping the data on the machine.
* Redacted input. The explainer sees ``build_snapshot`` output: MACs
  shortened, no hostnames (unless the user allows it), no IPs, no SSIDs.
* Failure is silent. A timeout (default 5 s) or an exception gives ``None``
  and a log line; it never reaches the caller.

How a future add-on or another integration registers::

    from custom_components.openwrt_router.net_explain import (
        ExplainResult,
        async_register_explainer,
    )


    class MyExplainer:
        async def explain(self, snapshot):
            return ExplainResult(text="...", suggested_cause=None, references=())


    unregister = await async_register_explainer(hass, MyExplainer())
    # later: unregister()

Only one explainer is active; registering another replaces the first.

Wiring into ``net_engine.py`` is deferred until the engine files are free
(planned after RT5). This module only provides the seam.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .const import DOMAIN
from .net_events import Incident, NetEvent, redact_event, redact_incident

if TYPE_CHECKING:
    from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)

MAX_TEXT = 2000
MAX_REFERENCES = 20
MAX_SNAPSHOT_EVENTS = 50
DEFAULT_TIMEOUT = 5.0
_EXPLAINER_KEY = "explainer"
_HOSTNAME_KEYS = ("hostname", "name")


@dataclass(frozen=True)
class ExplainResult:
    """What an explainer returns. All fields are advisory."""

    text: str
    suggested_cause: str | None = None
    references: tuple[str, ...] = ()


@runtime_checkable
class IncidentExplainer(Protocol):
    """A local AI (add-on or integration) that comments on an incident."""

    async def explain(self, snapshot: dict[str, Any]) -> ExplainResult | None:
        """Return an annotation for the redacted ``snapshot``, or ``None``."""
        ...


# --- Snapshot ---------------------------------------------------------------


def _ref(value: str) -> str:
    """Short opaque reference; event ids carry router ids, so hash them."""
    return hashlib.sha1(value.encode(), usedforsecurity=False).hexdigest()[:8]


def _short_mac(mac: Any) -> str | None:
    """Last three octets only (``..:aa:bb:cc``), same spirit as diagnostics."""
    if not isinstance(mac, str):
        return None
    parts = mac.replace("-", ":").split(":")
    if len(parts) < 4:
        return "..:??"
    return "..:" + ":".join(p.lower() for p in parts[-3:])


def _event_view(event: NetEvent, allow_hostnames: bool) -> dict[str, Any]:
    view = redact_event(event.to_dict())
    view["ref"] = _ref(event.id)
    if event.parent_id:
        view["parent_ref"] = _ref(event.parent_id)
    subject: dict[str, Any] = {}
    mac = _short_mac(event.subject.get("mac"))
    if mac:
        subject["mac"] = mac
    if allow_hostnames:
        for key in _HOSTNAME_KEYS:
            value = event.subject.get(key)
            if isinstance(value, str):
                subject[key] = value[:64]
    if subject:
        view["subject"] = subject
    return view


def build_snapshot(
    incident: Incident,
    events: Iterable[NetEvent],
    *,
    allow_hostnames: bool = False,
) -> dict[str, Any]:
    """Redacted, JSON-serialisable view of an incident and its events."""
    # RT8 decision: reuse net_events.redact_incident (drops scope_key, router
    # names, evidence ids); router ids come back only with allow_hostnames
    # because they are host names.
    base = redact_incident(incident.to_dict())
    evidence: list[dict[str, Any]] = []
    for raw in incident.evidence:
        item = {k: raw[k] for k in ("kind", "ts", "source") if k in raw}
        evidence.append(item)
    base["evidence"] = evidence
    base["scope"] = incident.scope.value
    base["incident_type"] = incident.type
    base["incident_ref"] = _ref(incident.id)
    if allow_hostnames:
        base["routers"] = list(incident.routers)

    views = [_event_view(e, allow_hostnames) for e in list(events)]
    # RT8 decision: cap the event list so a huge incident cannot bloat a prompt.
    views = views[-MAX_SNAPSHOT_EVENTS:]
    base["events"] = views
    base["children_refs"] = [
        v["ref"] for v in views if v.get("parent_ref") == base["incident_ref"]
    ]
    return base


# --- Registry ---------------------------------------------------------------


def _store(hass: HomeAssistant) -> dict[str, Any]:
    # RT8 decision: hass.data[DOMAIN] is not used by the rest of the
    # integration (it uses private top-level keys and runtime_data), so
    # create it defensively here and tolerate a foreign non-dict value.
    data = hass.data.get(DOMAIN)
    if not isinstance(data, dict):
        data = {}
        hass.data[DOMAIN] = data
    return data


def get_explainer(hass: HomeAssistant) -> IncidentExplainer | None:
    """The active explainer, or ``None``."""
    data = hass.data.get(DOMAIN)
    if not isinstance(data, dict):
        return None
    return data.get(_EXPLAINER_KEY)


async def async_register_explainer(
    hass: HomeAssistant, explainer: IncidentExplainer
) -> Callable[[], None]:
    """Make ``explainer`` the active one; returns the unregister function."""
    data = _store(hass)
    previous = data.get(_EXPLAINER_KEY)
    if previous is not None and previous is not explainer:
        _LOGGER.warning("Replacing the registered incident explainer")
    data[_EXPLAINER_KEY] = explainer

    def _unregister() -> None:
        current = hass.data.get(DOMAIN)
        # Only remove our own registration, not a later replacement.
        if isinstance(current, dict) and current.get(_EXPLAINER_KEY) is explainer:
            current[_EXPLAINER_KEY] = None

    return _unregister


# --- Annotation -------------------------------------------------------------


def _clean_text(value: Any) -> str:
    text = value if isinstance(value, str) else str(value)
    return text.strip()[:MAX_TEXT].strip()


async def async_annotate(
    hass: HomeAssistant,
    incident: Incident,
    events: Iterable[NetEvent],
    *,
    timeout: float = DEFAULT_TIMEOUT,
    allow_hostnames: bool = False,
) -> dict[str, Any] | None:
    """Ask the explainer for a note. Never raises, never mutates ``incident``."""
    explainer = get_explainer(hass)
    if explainer is None:
        return None
    try:
        snapshot = build_snapshot(incident, events, allow_hostnames=allow_hostnames)
        async with asyncio.timeout(timeout):
            result = await explainer.explain(snapshot)
    except TimeoutError:
        _LOGGER.debug("Incident explainer timed out after %.1f s", timeout)
        return None
    except Exception as err:  # noqa: BLE001 - a foreign plug-in must not break us
        _LOGGER.warning("Incident explainer failed: %s", err)
        return None
    if not isinstance(result, ExplainResult):
        return None
    text = _clean_text(result.text)
    if not text:
        return None
    cause = result.suggested_cause
    return {
        "ai_note": text,
        "ai_suggested_cause": cause[:100] if isinstance(cause, str) else None,
        "ai_references": [str(r)[:64] for r in result.references][:MAX_REFERENCES],
        "origin": "inferred",
        "source": "ai",
        "ts": time.time(),
    }
