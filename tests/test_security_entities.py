"""Fleet sensors and diagnostics of the Security Center (release 1.46.0 part 2).

The center runs on in-memory stores (``test_security_center``); the entity
registry is HA's real one, loaded like HA 2026.11 does it
(``loaded_registry`` of ``test_net_entities``). No Home Assistant instance,
no router. MACs are locally administered test values.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.helpers import entity_registry as er
from test_client_engine import setup
from test_net_engine import make_hass
from test_net_entities import loaded_registry
from test_security_center import (
    M1,
    M2,
    RID1,
    T0,
    center_for,
    coordinator,
    disks,  # noqa: F401 - fixture
    scenario_polls,
    sec_disk,
    security_event,
)

from custom_components.openwrt_router import (
    _LEGACY_DYNAMIC_PATTERNS,
    diagnostics,
    security_entities,
    sensor,
)
from custom_components.openwrt_router.const import (
    DATA_SECURITY_ENTITIES,
    DIAGNOSTICS_REDACTED,
    DOMAIN,
    FLEET_UID_PREFIX,
)
from custom_components.openwrt_router.security_center import (
    async_release_security_center,
    async_setup_security_center,
    default_settings,
    merge_settings,
)
from custom_components.openwrt_router.security_entities import (
    SECURITY_UNIQUE_IDS,
    SENSORS,
    SecurityFleetSensor,
    async_entry_unloaded,
    async_setup_security_sensors,
    async_sync_security_entities,
)
from custom_components.openwrt_router.security_syslog import SyslogReceiver

COMPONENT = Path(__file__).parent.parent / "custom_components" / DOMAIN
IDENTITIES = (M1, M2, M1.lower(), M2.lower(), "192.0.2.10", "Laptop", '"pc"')


def entry(entry_id: str) -> MagicMock:
    e = MagicMock()
    e.entry_id = entry_id
    e.domain = DOMAIN
    e.disabled_by = None
    e.pref_disable_new_entities = False
    return e


class Platform:
    """An entry's sensor platform: adds what it gets to the registry."""

    def __init__(self, registry: er.EntityRegistry, config_entry: Any) -> None:
        self.registry = registry
        self.entry = config_entry
        self.added: list[SecurityFleetSensor] = []

    def __call__(self, entities: list[Any], *_args: Any) -> None:
        for entity in entities:
            self.registry.async_get_or_create(
                "sensor", DOMAIN, entity.unique_id, config_entry=self.entry
            )
            self.added.append(entity)


async def registry_hass() -> tuple[Any, er.EntityRegistry, dict[str, Any]]:
    hass = make_hass()
    registry = await loaded_registry(hass)
    hass.data[er.DATA_REGISTRY] = registry
    entries = {eid: entry(eid) for eid in ("e1", "e2")}
    hass.config_entries.async_get_entry.side_effect = entries.get
    return hass, registry, entries


def ours(registry: er.EntityRegistry) -> dict[str, str | None]:
    """unique_id -> config entry of the fleet sensors in the registry."""
    return {
        e.unique_id: e.config_entry_id
        for e in registry.entities.values()
        if e.unique_id in SECURITY_UNIQUE_IDS
    }


def sensor_of(hass: Any, key: str) -> SecurityFleetSensor:
    entity = SecurityFleetSensor(next(d for d in SENSORS if d.key == key))
    entity.hass = hass
    return entity


# --- descriptions and strings ----------------------------------------------------------


def test_seven_fleet_sensors_with_stable_unique_ids() -> None:
    assert len(SENSORS) == len(set(SECURITY_UNIQUE_IDS)) == 7
    for description in SENSORS:
        uid = description.unique_id
        assert uid.startswith(f"{FLEET_UID_PREFIX}security_")
        assert not any(p in uid for p in _LEGACY_DYNAMIC_PATTERNS), uid
        assert description.translation_key
        assert not isinstance(description.name, str)  # translated, no hard name
    # HA reads the unrecorded attributes per class, not per instance
    combined = SecurityFleetSensor._Entity__combined_unrecorded_attributes  # type: ignore[attr-defined]
    assert {"states", "missing", "reason"} <= combined


@pytest.mark.parametrize(
    "path", ["strings.json", "translations/en.json", "translations/de.json"]
)
def test_every_sensor_has_a_name_in_every_language(path: str) -> None:
    data = json.loads((COMPONENT / path).read_text("utf-8"))
    names = data["entity"]["sensor"]
    for description in SENSORS:
        name = names[description.translation_key]["name"]
        assert name and "angriff" not in name.lower() and "attack" not in name.lower()


# --- values: unknown is None, never 0 ------------------------------------------------------


async def test_sensors_are_unknown_without_a_source(disks) -> None:  # noqa: F811
    hass = make_hass()
    center = await center_for(hass, enabled=False)
    for description in SENSORS:
        entity = sensor_of(hass, description.key)
        assert entity.available is False and entity.native_value is None
    center.settings = merge_settings(center.settings, {"enabled": True})
    await center.async_activate()
    center._publish(T0)
    assert center.fleet_view is None  # no router: no view at all
    center.add_entry("r1", coordinator())
    center._publish(T0)
    view = center.fleet_view
    assert view is not None and view["routers"] == 1
    for key in (
        "score",
        "unknown_devices",
        "firewall_events_1h",
        "wifi_auth_failures_1h",
    ):
        assert view[key] is None, key
        entity = sensor_of(hass, f"security_{key}")
        assert entity.available and entity.native_value is None, key
    assert sensor_of(hass, "security_coverage").native_value == 0
    assert sensor_of(hass, "security_coverage").extra_state_attributes["missing"]


async def test_sensors_count_once_sources_deliver(disks) -> None:  # noqa: F811
    hass = make_hass()
    engine, _cs = await setup(hass, "r1")
    center = await center_for(hass, "r1")
    for payload, now in scenario_polls():
        engine.ingest("r1", payload, now, interval=60.0)
    center._record(security_event("wifi_assoc_burst", T0 + 600), T0 + 600)
    center._publish(T0 + 600)
    view = center.fleet_view
    assert view is not None
    assert sensor_of(hass, "security_unknown_devices").native_value == 3
    attrs = sensor_of(hass, "security_unknown_devices").extra_state_attributes
    assert attrs["states"]  # counts per trust state only
    assert sensor_of(hass, "security_hints_active").native_value >= 1
    assert isinstance(sensor_of(hass, "security_hints_critical").native_value, int)
    assert isinstance(sensor_of(hass, "security_coverage").native_value, int)
    failures = sensor_of(hass, "security_wifi_auth_failures_1h").native_value
    assert failures is None or failures >= 1  # PSK failures of the scenario
    # no syslog receiver: firewall events stay unknown, never 0
    assert sensor_of(hass, "security_firewall_events_1h").native_value is None
    text = json.dumps(
        [sensor_of(hass, d.key).extra_state_attributes for d in SENSORS],
        default=str,
    )
    for secret in IDENTITIES:
        assert secret not in text, secret
    center.deactivate()
    assert center.fleet_view is None
    assert sensor_of(hass, "security_score").available is False


# --- creation and removal ------------------------------------------------------------------


async def test_off_creates_nothing_and_on_creates_the_set(disks) -> None:  # noqa: F811
    hass, registry, entries = await registry_hass()
    center = await center_for(hass, "r1", enabled=False)
    platform = Platform(registry, entries["e1"])
    async_setup_security_sensors(hass, entries["e1"], platform)
    assert platform.added == [] and ours(registry) == {}

    center.settings = merge_settings(center.settings, {"enabled": True})
    await center.async_activate()
    center._sync_entities()
    assert len(platform.added) == 7
    assert set(ours(registry)) == set(SECURITY_UNIQUE_IDS)
    center._sync_entities()  # idempotent
    assert len(platform.added) == 7

    center.settings = merge_settings(center.settings, {"enabled": False})
    center.deactivate()
    center._sync_entities()
    assert ours(registry) == {}  # off: nothing stays behind


async def test_sensor_setup_before_the_center_keeps_registry_entries(
    disks,  # noqa: F811
) -> None:
    """HA restart: the platform runs before the center; nothing is removed."""
    hass, registry, entries = await registry_hass()
    for uid in SECURITY_UNIQUE_IDS:
        registry.async_get_or_create("sensor", DOMAIN, uid, config_entry=entries["e1"])
    platform = Platform(registry, entries["e1"])
    async_setup_security_sensors(hass, entries["e1"], platform)  # no center yet
    assert len(ours(registry)) == 7 and platform.added == []
    sec_disk(disks).data = {"settings": {**default_settings(), "enabled": True}}
    await async_setup_security_center(hass, entries["e1"], coordinator())
    assert len(platform.added) == 7 and len(ours(registry)) == 7
    await async_release_security_center(hass, "e1")
    assert DATA_SECURITY_ENTITIES not in hass.data
    assert len(ours(registry)) == 7  # kept for the next start


async def test_the_set_moves_when_its_host_unloads(disks) -> None:  # noqa: F811
    hass, registry, entries = await registry_hass()
    await center_for(hass, "r1", "r2")
    first = Platform(registry, entries["e1"])
    second = Platform(registry, entries["e2"])
    async_setup_security_sensors(hass, entries["e2"], second)
    async_setup_security_sensors(hass, entries["e1"], first)
    assert len(second.added) == 7 and first.added == []  # first offer hosts
    async_entry_unloaded(hass, "e1", last=False)  # not the host
    assert len(first.added) == 0
    async_setup_security_sensors(hass, entries["e1"], first)
    async_entry_unloaded(hass, "e2", last=False)  # the host leaves
    assert len(first.added) == 7
    assert set(ours(registry).values()) == {"e1"}  # same entities, new entry
    assert len(ours(registry)) == 7


async def test_sync_without_center_or_registry_never_raises(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    async_sync_security_entities(hass)  # no center
    center = await center_for(hass, enabled=False)
    with patch.object(er, "async_get", side_effect=RuntimeError("no registry")):
        async_sync_security_entities(hass)
    with patch.object(
        security_entities,
        "async_sync_security_entities",
        side_effect=RuntimeError("bug"),
    ):
        center._sync_entities()  # a broken sync never leaves the center
    assert center.counters["errors"] >= 1


async def test_sensor_platform_survives_a_broken_security_module(
    caplog: pytest.LogCaptureFixture,
) -> None:
    hass = make_hass()
    config_entry = SimpleNamespace(entry_id="e1", title=f"router {M1}")
    base = AsyncMock(return_value=None)
    adder = MagicMock()
    with (
        patch.object(sensor, "_async_setup_entry_sensor_base", base),
        patch.object(
            security_entities,
            "async_setup_security_sensors",
            side_effect=RuntimeError(f"bug {M1}"),
        ),
        caplog.at_level(logging.WARNING),
    ):
        await sensor.async_setup_entry(hass, config_entry, adder)
    base.assert_awaited_once_with(hass, config_entry, adder)
    assert "Security Center sensors not set up (RuntimeError)" in caplog.text
    assert M1 not in caplog.text
    assert sensor.async_setup_entry.__wrapped__ is sensor._async_setup_entry_sensor_base


# --- diagnostics --------------------------------------------------------------------------


async def test_diagnostics_block_holds_no_identities(disks) -> None:  # noqa: F811
    hass = make_hass()
    assert diagnostics._security_center_summary(hass) == {"loaded": False}
    center = await center_for(hass, "r1")
    center.trust.observe(
        SimpleNamespace(mac=M1, private_mac=None, ip="192.0.2.10", hostname="pc"),
        T0,
    )
    center.trust.set_name(M1, "Laptop")
    center._record(security_event("wifi_assoc_burst", T0), T0)
    receiver = SyslogReceiver(port=0, host="127.0.0.1")
    receiver.set_senders({"192.0.2.10": RID1})
    receiver.receive(b"<4>Nov 18 12:00:00 pc kernel: drop", ("192.0.2.10", 1))
    center.syslog = receiver
    base = AsyncMock(return_value={"integration": DOMAIN})
    with patch.object(diagnostics, "_async_get_config_entry_diagnostics_base", base):
        result = await diagnostics.async_get_config_entry_diagnostics(
            hass, SimpleNamespace(entry_id="r1")
        )
    block = result["security_center"]
    assert block["enabled"] is True and block["devices"] == 1
    assert block["syslog"]["senders"] == 1 and block["syslog"]["stats"]["received"] == 1
    assert block["module_key"] == DIAGNOSTICS_REDACTED  # key-like names: masked
    text = json.dumps(result, default=str)
    for secret in (*IDENTITIES, "127.0.0.1", "kernel: drop", "rtr_"):
        assert secret not in text, secret
    center.syslog = None


async def test_diagnostics_never_fail_because_of_the_center(
    disks,  # noqa: F811
) -> None:
    hass = make_hass()
    center = await center_for(hass, "r1")
    with patch.object(type(center), "diagnostics", side_effect=RuntimeError(M1)):
        assert diagnostics._security_center_summary(hass) == {
            "loaded": False,
            "error": True,
        }
