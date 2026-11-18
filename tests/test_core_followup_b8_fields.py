"""Follow-up B8: typed optional CoreEvent fields for modules.

``client_ref`` (a ``cli_<16 hex>`` pseudonym, never a raw MAC),
``confidence`` (finite number 0..1, stored as float), ``classification``
(machine code, ``EVENT_CLASSIFICATION_PATTERN``), ``incident_ref`` and
``radio_id`` (bounded tokens). All default None, are part of ``to_dict`` /
``from_dict`` and the bus payload, never part of the dedup scope. Entries
stored before B8 read unchanged; an older core ignores the new keys
(``from_dict`` reads named keys only), so no store version.
"""

from __future__ import annotations

import math

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks, bus_events, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_masking import pseudonymise_identifier
from custom_components.openwrt_router.core_models import (
    EVENT_CLASSIFICATION_PATTERN,
    CoreEvent,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
MOD = "security_center"
PREFIX = "security_center."
CLIENT = pseudonymise_identifier("client", "aa:bb:cc:dd:ee:01", b"\x01" * 32)
TS = "2026-11-18T10:00:00+00:00"
FIELDS = {
    "client_ref": CLIENT,
    "confidence": 0.75,
    "classification": "port_scan",
    "incident_ref": "inc-2026-0042",
    "radio_id": "radio1",
}


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _event(**kwargs) -> CoreEvent:
    from datetime import datetime

    return CoreEvent(
        event_id="evt_" + "0" * 32,
        ts=datetime.fromisoformat(TS),
        type=f"{PREFIX}finding",
        source=MOD,
        **kwargs,
    )


def test_defaults_and_round_trip():
    plain = _event()
    for name in FIELDS:
        assert getattr(plain, name) is None
        assert plain.to_dict()[name] is None
    full = _event(**FIELDS)
    data = full.to_dict()
    for name, value in FIELDS.items():
        assert data[name] == value
    assert CoreEvent.from_dict(data) == full


def test_old_dict_reads():
    event = CoreEvent.from_dict(
        {"event_id": "evt_" + "0" * 32, "ts": TS, "type": "x.y", "source": MOD}
    )
    assert all(getattr(event, name) is None for name in FIELDS)


def test_confidence_int_is_float():
    assert _event(confidence=1).confidence == 1.0
    assert isinstance(_event(confidence=0).confidence, float)


@pytest.mark.parametrize(
    ("name", "bad"),
    [
        ("client_ref", "aa:bb:cc:dd:ee:01"),  # raw MAC: never
        ("client_ref", "mac_0123456789abcdef"),  # wrong kind
        ("client_ref", "cli_0123"),
        ("client_ref", 5),
        ("confidence", 1.5),
        ("confidence", -0.1),
        ("confidence", math.nan),
        ("confidence", math.inf),
        ("confidence", True),
        ("confidence", "0.5"),
        ("classification", "Port Scan"),
        ("classification", ""),
        ("classification", "x" * 65),
        ("incident_ref", "../etc"),
        ("incident_ref", "a/b"),
        ("incident_ref", "x" * 129),
        ("radio_id", ""),
        ("radio_id", "radio 0"),
        ("radio_id", 0),
    ],
)
def test_validation(name, bad):
    with pytest.raises((TypeError, ValueError)):
        _event(**{name: bad})


def test_pattern_constant():
    assert EVENT_CLASSIFICATION_PATTERN.fullmatch("rogue_ap.suspected")
    assert not EVENT_CLASSIFICATION_PATTERN.fullmatch("Rogue")


async def test_emit_persist_and_bus(disks):
    hass = make_hass()
    log = AuditLog(hass)
    await log.async_load()
    log.register_event_prefix(PREFIX, module=MOD)
    res = log.emit(f"{PREFIX}finding", source=MOD, router_id=R1, **FIELDS)
    assert res.published
    payload = bus_events(hass, f"{PREFIX}finding")[0]
    for name, value in FIELDS.items():
        assert payload[name] == value, name
    await log.async_flush()
    again = AuditLog(hass)
    await again.async_load()
    (stored,) = again.events()
    for name, value in FIELDS.items():
        assert getattr(stored, name) == value


async def test_not_in_dedup_scope(disks):
    log = AuditLog(make_hass())
    await log.async_load()
    log.register_event_prefix(PREFIX, module=MOD)
    log.emit(f"{PREFIX}finding", source=MOD, dedup_key="k", confidence=0.2)
    second = log.emit(f"{PREFIX}finding", source=MOD, dedup_key="k", confidence=0.9)
    assert second.deduplicated


async def test_api_surface(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.api.register_event_prefix(PREFIX, module=MOD)
    res = env.api.emit(f"{PREFIX}finding", source=MOD, router_id=env.rid, **FIELDS)
    assert res.event.client_ref == CLIENT and res.event.confidence == 0.75
    await stop_env(env)
