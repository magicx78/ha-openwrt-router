"""The core bus event carries a user pseudonym, never the HA user id.

Review finding 7 of PR #55: ``openwrt_router_core_event`` lands in the
recorder and the logbook. Its ``actor.user_id`` (and any other ``user_id``
in the payload) is now the pseudonym the diagnostics use
(``usr_<12 hex>``, HMAC-SHA256 with a salt), made by ONE shared helper in
``core_masking``. The bus salt lives in memory per audit log (same user,
same pseudonym while the core runs); the audit store and the in-process
listeners keep the real id.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from core_testkit import ADMIN_ID, USER_ID, FakeDisks, bus_events, make_hass, user_actor

from custom_components.openwrt_router import core_masking
from custom_components.openwrt_router import diagnostics as diag_mod
from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_models import EVENT_CORE, CoreEventType
from custom_components.openwrt_router.logbook import async_describe_events
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("e1")
ADOPTED = CoreEventType.ROUTER_ADOPTED
COMP = Path(diag_mod.__file__).resolve().parent


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass) -> AuditLog:
    log = AuditLog(hass)
    await log.async_load()
    return log


def _is_pseudonym(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.startswith(core_masking.ACTOR_PSEUDONYM_PREFIX)
        and len(value) == len("usr_") + 12
        and all(c in "0123456789abcdef" for c in value[4:])
    )


async def test_bus_actor_is_pseudonym(disks):
    hass = make_hass()
    log = await _log(hass)
    seen = []
    log.subscribe(seen.append)
    log.emit(ADOPTED, router_id=R1, actor=user_actor(ADMIN_ID))
    log.emit(ADOPTED, router_id=R1, actor=user_actor(ADMIN_ID))
    log.emit(ADOPTED, router_id=R1, actor=user_actor(USER_ID))
    payloads = bus_events(hass, ADOPTED.value)
    assert len(payloads) == 3
    ids = [p["actor"]["user_id"] for p in payloads]
    assert all(_is_pseudonym(i) for i in ids), ids
    assert ids[0] == ids[1]  # same user, same pseudonym in one run
    assert ids[0] != ids[2]
    raw = json.dumps(payloads)
    assert ADMIN_ID not in raw and USER_ID not in raw
    # the audit store and in-process listeners keep the real id
    assert [e.actor.user_id for e in log.events()].count(ADMIN_ID) == 2
    assert seen[0].actor.user_id == ADMIN_ID
    # the rest of the actor is unchanged
    assert payloads[0]["actor"]["kind"] == "user"


async def test_bus_nested_user_id(disks):
    hass = make_hass()
    log = await _log(hass)
    log.emit(
        ADOPTED,
        router_id=R1,
        data={"requested_by": {"kind": "user", "user_id": ADMIN_ID}},
    )
    (payload,) = bus_events(hass, ADOPTED.value)
    assert _is_pseudonym(payload["data"]["requested_by"]["user_id"])
    assert ADMIN_ID not in json.dumps(payload)


async def test_bus_salt_differs_per_log(disks):
    hass = make_hass()
    first, second = await _log(hass), await _log(hass)
    first.emit(ADOPTED, router_id=R1, actor=user_actor(ADMIN_ID))
    second.emit(ADOPTED, router_id=R1, actor=user_actor(ADMIN_ID))
    a, b = (p["actor"]["user_id"] for p in bus_events(hass, ADOPTED.value))
    assert a != b  # random salt, never a stable HA-wide user handle


def test_helper_is_shared():
    salt = b"\x01" * 16
    entry = {"actor": {"kind": "user", "user_id": ADMIN_ID}, "type": "x"}
    expected = core_masking.pseudonymise_user_ids(entry, salt)
    assert diag_mod._pseudonymise_actors([entry], salt) == [expected]
    assert _is_pseudonym(expected["actor"]["user_id"])
    assert entry["actor"]["user_id"] == ADMIN_ID  # input not changed
    assert diag_mod.ACTOR_PSEUDONYM_PREFIX == core_masking.ACTOR_PSEUDONYM_PREFIX
    # one implementation: no second HMAC over user ids
    assert "hmac.new" not in (COMP / "diagnostics.py").read_text(encoding="utf-8")
    assert "hmac.new" not in (COMP / "core_audit.py").read_text(encoding="utf-8")


def test_helper_leaves_other_values():
    salt = b"\x02" * 16
    data = {"user_id": None, "count": 3, "items": [{"user_id": "u"}], "s": "u"}
    out = core_masking.pseudonymise_user_ids(data, salt)
    assert out["user_id"] is None and out["count"] == 3 and out["s"] == "u"
    assert _is_pseudonym(out["items"][0]["user_id"])
    assert core_masking.pseudonymise_user_id("u", salt) == out["items"][0]["user_id"]


async def test_logbook_renders_pseudonymised(disks):
    hass = make_hass()
    log = await _log(hass)
    log.emit(ADOPTED, router_id=R1, actor=user_actor(ADMIN_ID), result="success")
    (payload,) = bus_events(hass, ADOPTED.value)
    registered = {}
    async_describe_events(hass, lambda d, e, fn: registered.setdefault(e, fn))
    described = registered[EVENT_CORE](MagicMock(data=payload))
    assert described == {"name": "OpenWrt Router", "message": "router.adopted: success"}
    assert ADMIN_ID not in json.dumps(described)
