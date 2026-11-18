"""Follow-up B7: the contract says what the code does.

1. §6.3: a READ action that goes through ``authorize`` is granted with a
   minted authorization and audited (``security.authorization_granted``,
   security ring). The core's own read operations do not call ``authorize``.
2. §17: module names are ``security_center`` / ``net_diagnostics`` (not the
   repo names with a hyphen); a module has ONE detector with ONE prefix, so
   ``diag.`` and ``log.`` are alternatives, not both.
3. §3.1: a table of all reserved prefixes and namespaces; every constant in
   the code appears in it.
4. ``FLEET_ROUTER_ID`` ("-"): one constant (``core_models``, re-exported by
   ``core_guard``), ``is_fleet_router_id``; the registry never treats it as a
   router (``get`` refuses with ``details.fleet``, ``find`` None,
   ``has_capability`` False); ``AuditLog.events(router_id="-")`` returns the
   entries stored with "-" only (not those without a router).
"""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime

import pytest
from core_test_provider import (
    short_tmp_path,  # noqa: F401 - short tmp_path (Windows path limit)
    start_env,
    stop_env,
)
from core_testkit import FakeDisks, make_hass

from custom_components.openwrt_router import core_guard, core_models
from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import RouterNotFoundError
from custom_components.openwrt_router.core_masking import (
    ACTOR_PSEUDONYM_PREFIX,
    IDENTIFIER_PSEUDONYM_PREFIXES,
)
from custom_components.openwrt_router.core_models import (
    CORE_CAPABILITY_NAMESPACES,
    CORE_EVENT_NAMESPACES,
    FLEET_ROUTER_ID,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    RESERVED_NAMESPACES,
    ActionClass,
    Actor,
    AuditRing,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEventType,
    is_fleet_router_id,
)

DOC = pathlib.Path(__file__).resolve().parents[1] / "docs/dev/configuration-api-v1.md"


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def _section(title: str) -> str:
    text = DOC.read_text(encoding="utf-8")
    start = text.index(title)
    ends = [text.find("\n## ", start + len(title))]
    if title.startswith("### "):  # a subsection ends at the next one, too
        ends.append(text.find("\n### ", start + len(title)))
    cut = min((x for x in ends if x != -1), default=len(text))
    return text[start:cut]


# -- 1. read grants -------------------------------------------------------------------


async def test_read_authorize_mints_and_audits(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    guard = env.api.guard
    guard.register_action(
        "net_diagnostics.status", ActionClass.READ, module="net_diagnostics"
    )
    module = await guard.async_verify_actor(Actor.for_module("net_diagnostics"))
    decision = guard.authorize("net_diagnostics.status", env.rid, module)
    assert decision.approved and decision.authorization is not None
    granted = [
        e
        for e in env.core.audit.events(ring=AuditRing.SECURITY)
        if e.type == CoreEventType.AUTHORIZATION_GRANTED.value
    ]
    assert granted and granted[-1].data["action"] == "net_diagnostics.status"
    section = _section("### 6.3 Aktionen")
    assert "keine Autorisierung" not in section
    assert "`security.authorization_granted`" in section
    await stop_env(env)


# -- 2. module names and detector prefixes ---------------------------------------------


def _status(name: str) -> CapabilityStatus:
    return CapabilityStatus(
        capability=name,
        state=CapabilityState.AVAILABLE,
        reason=CapabilityReason.OK,
        source="module:test",
        detected_at=datetime(2026, 11, 18, tzinfo=UTC),
    )


async def test_section17_module_names(disks, tmp_path):
    section = _section("## 17. Erweiterungspunkte")
    # the repo names with a hyphen are not module names (table rows)
    assert "(`net-diagnostics`)" not in section
    assert "(`security-center`)" not in section
    for module in MODULE_EVENT_PREFIXES:
        assert f"`{module}`" in section, module
    env = await start_env(disks, tmp_path)
    reg = env.api.register_capability_detector
    with pytest.raises(ValueError):  # the hyphen name is not the module
        reg("net-diagnostics", lambda r, d: {}, prefix="diag.")
    remove = reg(
        "net_diagnostics",
        lambda r, d: {
            "diag.traceroute": _status("diag.traceroute"),
            "log.syslog": _status("log.syslog"),  # outside the one prefix
        },
        prefix="diag.",
    )
    env.coords[env.rid].poll()
    caps = env.api.registry.capabilities(env.rid)
    assert caps["diag.traceroute"].available
    assert "log.syslog" not in caps
    with pytest.raises(ValueError):  # one detector per module
        reg("net_diagnostics", lambda r, d: {}, prefix="log.")
    remove()
    reg("net_diagnostics", lambda r, d: {}, prefix="log.")  # log. instead
    await stop_env(env)


# -- 3. reserved prefixes table --------------------------------------------------------


def test_reserved_prefix_table_lists_every_constant():
    section = _section("### 3.1 Reservierte Präfixe und Namensräume")
    expected = {
        *RESERVED_NAMESPACES,
        *CORE_CAPABILITY_NAMESPACES,
        core_models.CONFIG_CAPABILITY_NAMESPACE,
        *CORE_EVENT_NAMESPACES,
        *MODULE_EVENT_PREFIXES.values(),
        *MODULE_CAPABILITY_NAMESPACES.values(),
        core_models.ROUTER_ID_PREFIX,
        core_models.BACKUP_ID_PREFIX,
        core_models.EVENT_ID_PREFIX,
        core_models.APPROVAL_ID_PREFIX,
        core_models.PLAN_ID_PREFIX,
        core_models.AUTHORIZATION_ID_PREFIX,
        core_models.VERIFICATION_ID_PREFIX,
        core_models.CORRELATION_ID_PREFIX,
        ACTOR_PSEUDONYM_PREFIX,
        *IDENTIFIER_PSEUDONYM_PREFIXES.values(),
        core_models.CORE_KEY_OWNER,
        FLEET_ROUTER_ID,
    }
    missing = sorted(p for p in expected if f"`{p}`" not in section)
    assert missing == []


# -- 4. FLEET_ROUTER_ID ---------------------------------------------------------------


def test_fleet_constant_is_one():
    assert FLEET_ROUTER_ID == "-"
    assert core_guard.FLEET_ROUTER_ID is FLEET_ROUTER_ID
    assert is_fleet_router_id("-") and not is_fleet_router_id(None)
    assert not is_fleet_router_id("rtr_" + "0" * 32) and not is_fleet_router_id(3)


async def test_registry_never_treats_fleet_as_router(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    registry = env.api.registry
    with pytest.raises(RouterNotFoundError) as err:
        registry.get(FLEET_ROUTER_ID)
    assert err.value.details == {"reason": "invalid_router_id", "fleet": True}
    assert err.value.router_id is None
    with pytest.raises(RouterNotFoundError) as other:
        registry.get("garbage")
    assert "fleet" not in other.value.details
    assert registry.find(FLEET_ROUTER_ID) is None
    assert registry.has_capability(FLEET_ROUTER_ID, "transport.ubus") is False
    await stop_env(env)


async def test_audit_fleet_filter(disks):
    log = AuditLog(make_hass())
    await log.async_load()
    log.emit(CoreEventType.STORE_RECOVERED, router_id=None, data={"store": "x"})
    log.emit(CoreEventType.INSTALLATION_KEY_RESET, router_id=FLEET_ROUTER_ID, data={})
    fleet = log.events(router_id=FLEET_ROUTER_ID)
    assert [e.type for e in fleet] == [CoreEventType.INSTALLATION_KEY_RESET.value]
    assert len(log.events()) == 2
    section = _section("### 4.1 Flotten-Kennung")
    assert '`events(router_id="-")`' in section
