"""Follow-up B1: per-module keys and a stable bus pseudonym.

``api.async_get_module_key(module, purpose)`` derives a 32-byte key from the
installation key with HKDF-SHA256 (RFC 5869, stdlib hmac/hashlib) and a
fixed, versioned info string that names the module and the purpose. Only a
module that registered its event prefix in this core run gets a key, and
only its own (the name is the derivation input; ``core`` is never a module).
A lost key raises ``InstallationKeyLostError``; nothing is substituted.

The user pseudonym on the core bus (``usr_<12 hex>``) is derived from
HKDF(``core`` / ``bus_pseudonym``) when the installation key exists at core
load, so it stays the same across restarts. Without a key the salt is
random per run; that is counted (``bus_salt_ephemeral``) and logged once.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest
from core_test_provider import restart, start_env, stop_env
from core_testkit import ADMIN_ID, FakeDisks, bus_events, core_of, user_actor

from custom_components.openwrt_router import version_store as version_store_module
from custom_components.openwrt_router.core_errors import (
    ConfigApiError,
    InstallationKeyLostError,
)
from custom_components.openwrt_router.core_models import (
    INSTALLATION_KEY_STORE_KEY,
    MODULE_KEY_INFO_PREFIX,
    BackupReason,
    CoreEventType,
    derive_module_key,
    hkdf_sha256,
)

ADMIN = user_actor(ADMIN_ID)
ADOPTED = CoreEventType.ROUTER_ADOPTED


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


def test_hkdf_rfc5869_case1():
    """RFC 5869 appendix A.1."""
    okm = hkdf_sha256(
        bytes.fromhex("0b" * 22),
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_rfc5869_case3():
    """RFC 5869 appendix A.3 (empty salt and info)."""
    okm = hkdf_sha256(bytes.fromhex("0b" * 22), salt=b"", info=b"", length=42)
    assert okm.hex() == (
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_derive_is_separated():
    key = b"\x11" * 32
    a = derive_module_key(key, "security_center")
    assert len(a) == 32
    assert a == derive_module_key(key, "security_center")
    assert a != derive_module_key(key, "security_center", "pseudonyms")
    assert a != derive_module_key(key, "net_diagnostics")
    assert a != derive_module_key(b"\x12" * 32, "security_center")
    assert a != key
    assert MODULE_KEY_INFO_PREFIX.endswith(b"/v1")
    for module, purpose in (("", ""), ("core", ""), ("a.b", ""), ("m", "x/y")):
        with pytest.raises(ValueError):
            derive_module_key(key, module, purpose)


async def test_module_key_needs_prefix(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    with pytest.raises(ConfigApiError) as err:
        await env.api.async_get_module_key("security_center")
    assert err.value.details["reason"] == "module_not_registered"
    env.api.register_event_prefix("security_center.", module="security_center")
    key = await env.api.async_get_module_key("security_center")
    assert len(key) == 32
    installation = await env.api.async_get_installation_key()
    assert key == derive_module_key(installation, "security_center")
    assert key != installation
    other = await env.api.async_get_module_key("security_center", "pseudonyms")
    assert other == derive_module_key(installation, "security_center", "pseudonyms")
    # another module's key is refused until that module registered itself
    with pytest.raises(ConfigApiError) as err:
        await env.api.async_get_module_key("net_diagnostics")
    assert err.value.details["reason"] == "module_not_registered"
    for bad in ("core", "", "a.b", None):
        with pytest.raises(ConfigApiError) as err:
            await env.api.async_get_module_key(bad)  # type: ignore[arg-type]
        assert err.value.details["reason"] in ("invalid_module", "reserved_module")
    with pytest.raises(ConfigApiError) as err:
        await env.api.async_get_module_key("security_center", "../x")
    assert err.value.details["reason"] == "invalid_purpose"
    stats = core_of(env.hass).manager.stats
    assert stats["module_keys_issued"] == 2
    assert stats["module_keys_refused"] >= 6
    await stop_env(env)


async def test_module_key_stable(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    env.api.register_event_prefix("security_center.", module="security_center")
    first = await env.api.async_get_module_key("security_center")
    env = await restart(env)
    env.api.register_event_prefix("security_center.", module="security_center")
    assert await env.api.async_get_module_key("security_center") == first
    await stop_env(env)


async def test_module_key_lost(disks, tmp_path):
    env = await start_env(disks, tmp_path)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    await stop_env(env)
    disks[INSTALLATION_KEY_STORE_KEY].data = None
    with patch.object(version_store_module, "async_raise_issue"):
        env = await restart(env)
    env.api.register_event_prefix("security_center.", module="security_center")
    with pytest.raises(InstallationKeyLostError):
        await env.api.async_get_module_key("security_center")
    assert disks[INSTALLATION_KEY_STORE_KEY].data is None  # nothing substituted
    await stop_env(env)


async def test_module_key_not_leaked(disks, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    env = await start_env(disks, tmp_path)
    env.api.register_event_prefix("security_center.", module="security_center")
    key = await env.api.async_get_module_key("security_center")
    core = core_of(env.hass)
    texts = [
        caplog.text,
        repr(core.summary()),
        repr(env.api),
        repr(core.manager),
        repr([e.to_dict() for e in env.api.events()]),
        repr(bus_events(env.hass)),
    ]
    for text in texts:
        assert key.hex() not in text
        assert repr(key) not in text
    await stop_env(env)


def _bus_user(env) -> str:
    core_of(env.hass).audit.emit(ADOPTED, router_id=env.rid, actor=ADMIN)
    return bus_events(env.hass, ADOPTED.value)[-1]["actor"]["user_id"]


async def test_bus_pseudonym_stable(disks, tmp_path, caplog):
    caplog.set_level(logging.INFO)
    env = await start_env(disks, tmp_path)
    await env.api.async_get_installation_key()  # the first use creates it
    # this run started without a key: random salt, visible
    assert core_of(env.hass).audit.stats["bus_salt_ephemeral"] == 1
    assert "bus pseudonyms are random for this run" in caplog.text
    first_run = _bus_user(env)
    env = await restart(env)
    assert core_of(env.hass).audit.stats["bus_salt_ephemeral"] == 0
    second_run = _bus_user(env)
    env = await restart(env)
    third_run = _bus_user(env)
    assert second_run == third_run != first_run
    assert ADMIN_ID not in second_run
    await stop_env(env)


async def test_bus_pseudonym_lost_key(disks, tmp_path, caplog):
    """A lost key never fails emission: the run gets a random salt."""
    caplog.set_level(logging.INFO)
    env = await start_env(disks, tmp_path)
    await env.api.async_create_backup(env.rid, reason=BackupReason.MANUAL, actor=ADMIN)
    env = await restart(env)
    stable = _bus_user(env)
    await stop_env(env)
    disks[INSTALLATION_KEY_STORE_KEY].data = None
    caplog.clear()
    with patch.object(version_store_module, "async_raise_issue"):
        env = await restart(env)
    lost = _bus_user(env)
    assert lost != stable
    assert core_of(env.hass).audit.stats["bus_salt_ephemeral"] == 1
    assert caplog.text.count("bus pseudonyms are random for this run") == 1
    await stop_env(env)
