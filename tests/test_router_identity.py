"""Enterprise core part 1: router identity (cases 1-4 and the pure functions)."""

from __future__ import annotations

import uuid
from types import SimpleNamespace

import pytest
from core_testkit import (
    LOCAL_MAC,
    MAC_A,
    MAC_B,
    FakeDisks,
    FakeEntry,
    bus_events,
    core_of,
    make_hass,
    repeater_data,
    router_data,
    setup_router,
)

from custom_components.openwrt_router.const import CONF_HOST
from custom_components.openwrt_router.core_models import (
    ROUTER_ID_NAMESPACE,
    CoreEventType,
    HardwareFingerprint,
    IdentityFlag,
    IdentityStatus,
    RecordState,
    RouterRole,
)
from custom_components.openwrt_router.enterprise_core import async_setup_entry_core
from custom_components.openwrt_router.router_identity import (
    alternate_router_id,
    assess,
    candidate_macs,
    derive_role,
    duplicate_groups,
    hardware_matches,
    identity_signature,
    is_factory_default_hostname,
    merge_reference,
    observe,
    router_id_for_entry,
)

ID_CHANGED = CoreEventType.ROUTER_IDENTITY_CHANGED.value
DUPLICATE = CoreEventType.ROUTER_DUPLICATE_SUSPECTED.value


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


# --- pure functions --------------------------------------------------------------


def test_router_id_is_uuid5_of_the_entry_id() -> None:
    rid = router_id_for_entry("01JABCDEF")
    assert rid == "rtr_" + uuid.uuid5(ROUTER_ID_NAMESPACE, "01JABCDEF").hex
    assert router_id_for_entry("01JABCDEF") == rid
    assert router_id_for_entry("other") != rid
    assert alternate_router_id("01JABCDEF", 1) not in (
        rid,
        alternate_router_id("01JABCDEF", 2),
    )


def test_locally_administered_and_sta_upstream_macs_are_not_hardware() -> None:
    data = repeater_data()
    # the STA bssid is the upstream AP (another device), the STA mac is random
    assert MAC_A[1] not in candidate_macs(data)
    obs = observe(data, management_host="192.168.1.40")
    assert LOCAL_MAC not in obs.fingerprint.macs
    assert obs.ignored_local_macs == 1
    assert obs.fingerprint.macs  # the two AP BSSIDs are universal


def test_api_fallbacks_are_not_identity() -> None:
    obs = observe(repeater_data("192.168.1.40"), management_host="192.168.1.40")
    assert obs.model is None  # "OpenWrt Router" is api.py's fallback
    assert obs.hostname is None  # hostname == host is api.py's fallback
    assert obs.board_name is None


def test_hardware_match_prefers_macs_over_model_text() -> None:
    ref = HardwareFingerprint.build(board_name="a,b", model="Old name", macs=MAC_A)
    renamed = HardwareFingerprint.build(
        board_name="a,b", model="New name", macs=MAC_A[:1]
    )
    assert hardware_matches(ref, renamed) is True
    other = HardwareFingerprint.build(board_name="a,b", model="Old name", macs=MAC_B)
    assert hardware_matches(ref, other) is False  # same board, other device
    no_macs = HardwareFingerprint.build(board_name="x,y", model=None, macs=[])
    assert hardware_matches(ref, no_macs) is False  # board differs
    assert hardware_matches(HardwareFingerprint(), no_macs) is None


def test_reference_fingerprint_is_capped_and_counts_drops() -> None:
    many = [f"00:1a:2b:00:{i // 256:02x}:{i % 256:02x}" for i in range(80)]
    ref, dropped = merge_reference(
        HardwareFingerprint(),
        HardwareFingerprint.build(board_name=None, model=None, macs=many),
    )
    assert len(ref.macs) == 64
    assert dropped == 16


def test_duplicate_groups_are_symmetric() -> None:
    groups = duplicate_groups(
        {"r1": frozenset(MAC_A), "r2": frozenset(MAC_A[:1]), "r3": frozenset(MAC_B)}
    )
    assert groups == {"r1": {"r2": 1}, "r2": {"r1": 1}}


def test_role_from_wan_evidence() -> None:
    gateway = router_data()
    assert derive_role(gateway, "192.168.1.1", RouterRole.UNKNOWN) is RouterRole.GATEWAY
    ap = router_data(wan={"wan_found": False})
    assert derive_role(ap, "192.168.1.2", RouterRole.UNKNOWN) is RouterRole.ACCESS_POINT
    outage = router_data(
        wan={"wan_found": True, "interface": "wan", "proto": "dhcp", "connected": False}
    )
    # weak evidence keeps what was known
    assert derive_role(outage, "192.168.1.1", RouterRole.GATEWAY) is RouterRole.GATEWAY
    assert (
        derive_role(SimpleNamespace(wan_status={}), "h", RouterRole.UNKNOWN)
        is RouterRole.UNKNOWN
    )


def test_signature_ignores_volatile_data() -> None:
    a, b = router_data(), router_data()
    b.uptime, b.clients, b.cpu_load = 999, [{"mac": "x"}], 50.0
    assert identity_signature(a, "h") == identity_signature(b, "h")
    b.router_info["hostname"] = "new"
    assert identity_signature(a, "h") != identity_signature(b, "h")


def test_assess_clears_unverified_with_the_first_data() -> None:
    obs = observe(router_data(), management_host="192.168.1.1")
    result = assess(
        flags={IdentityFlag.UNVERIFIED},
        reference=HardwareFingerprint(),
        previous_hostname=None,
        previous_version=None,
        previous_host=None,
        observation=obs,
        management_host="192.168.1.1",
    )
    assert result.flags == frozenset()
    assert result.update_reference


def test_factory_default_hostname() -> None:
    assert is_factory_default_hostname("OpenWrt")
    assert is_factory_default_hostname("openwrt")
    assert not is_factory_default_hostname("OpenWrt-AP")
    assert not is_factory_default_hostname(None)


# --- case 1: IP change --------------------------------------------------------------


async def test_case01_router_id_stable_on_ip_change(disks: FakeDisks) -> None:
    entry = FakeEntry("e1", host="192.168.1.1")
    hass = make_hass()
    coord = await setup_router(hass, entry, router_data())
    rid = core_of(hass).registry.get_by_entry("e1").router_id
    assert rid == router_id_for_entry("e1")

    entry.data[CONF_HOST] = "10.0.0.1"  # reconfigured: reload runs setup again
    await async_setup_entry_core(hass, entry)
    coord.poll()
    record = core_of(hass).registry.get_by_entry("e1")
    assert record.router_id == rid
    assert record.identity.management_host == "10.0.0.1"
    assert record.connection.host == "10.0.0.1"
    assert record.identity.status is IdentityStatus.CONFIRMED
    changed = bus_events(hass, ID_CHANGED)
    assert changed[-1]["data"]["changed_fields"] == ["management_host"]
    assert changed[-1]["router_id"] == rid
    assert len(core_of(hass).registry.list()) == 1


# --- case 2: hostname change --------------------------------------------------------


async def test_case02_identity_stable_on_hostname_change(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data(hostname="gw-old"))
    rid = core_of(hass).registry.get_by_entry("e1").router_id
    coord.poll(data=router_data(hostname="gw-new"))
    record = core_of(hass).registry.get_by_entry("e1")
    assert record.router_id == rid
    assert record.identity.hostname == "gw-new"
    assert record.identity.status is IdentityStatus.CONFIRMED
    event = bus_events(hass, ID_CHANGED)[-1]
    assert event["data"]["changed_fields"] == ["hostname"]
    assert event["data"]["factory_reset_suspected"] is False
    assert event["severity"] == "info"


# --- case 3: duplicates -------------------------------------------------------------


async def test_case03_duplicate_identities_flagged_not_merged(disks: FakeDisks) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1", host="192.168.1.1"), router_data())
    await setup_router(
        hass, FakeEntry("e2", host="192.168.1.2"), router_data(hostname="same-box")
    )
    registry = core_of(hass).registry
    r1, r2 = registry.get_by_entry("e1"), registry.get_by_entry("e2")
    assert r1.router_id != r2.router_id  # never merged
    assert len(registry.list()) == 2
    for record in (r1, r2):
        assert IdentityFlag.DUPLICATE_SUSPECTED in record.identity.identity_flags
        assert record.identity.status is IdentityStatus.DUPLICATE_SUSPECTED
        assert record.state is RecordState.ACTIVE
    events = bus_events(hass, DUPLICATE)
    assert {e["router_id"] for e in events} == {r1.router_id, r2.router_id}
    assert all(e["severity"] == "warning" for e in events)
    assert events[0]["data"]["shared_mac_count"] == len(MAC_A)


async def test_case03_duplicate_clears_when_the_overlap_is_gone(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    await setup_router(hass, FakeEntry("e1"), router_data())
    c2 = await setup_router(hass, FakeEntry("e2", host="192.168.1.2"), router_data())
    c2.poll(data=router_data(macs=MAC_B, board="other,board", model="Other"))
    registry = core_of(hass).registry
    r1 = registry.get_by_entry("e1")
    assert IdentityFlag.DUPLICATE_SUSPECTED not in r1.identity.identity_flags
    cleared = [
        e
        for e in bus_events(hass, ID_CHANGED)
        if e["data"].get("change") == "duplicate_cleared"
    ]
    assert {e["router_id"] for e in cleared} >= {r1.router_id}


# --- case 4: factory reset / hardware swap ---------------------------------------------


async def test_case04_factory_reset_same_hardware_keeps_id(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data(hostname="gw-office"))
    rid = core_of(hass).registry.get_by_entry("e1").router_id
    coord.poll(data=router_data(hostname="OpenWrt", version="24.10.0"))
    record = core_of(hass).registry.get_by_entry("e1")
    assert record.router_id == rid
    assert record.identity.status is IdentityStatus.CONFIRMED
    event = bus_events(hass, ID_CHANGED)[-1]
    assert event["severity"] == "info"
    assert event["data"]["factory_reset_suspected"] is True
    assert set(event["data"]["changed_fields"]) == {"hostname", "openwrt_version"}


async def test_case04_hardware_swap_flags_changed_keeps_id(disks: FakeDisks) -> None:
    hass = make_hass()
    coord = await setup_router(hass, FakeEntry("e1"), router_data())
    rid = core_of(hass).registry.get_by_entry("e1").router_id
    coord.poll(data=router_data(macs=MAC_B, board="cudy,wr3000", model="Cudy WR3000"))
    record = core_of(hass).registry.get_by_entry("e1")
    assert record.router_id == rid
    assert record.identity.identity_flags == {IdentityFlag.CHANGED}
    assert record.identity.status is IdentityStatus.CHANGED
    # the reference stays the original device while the flag is set
    assert record.identity.fingerprint.macs == frozenset(MAC_A)
    swap = [
        e
        for e in bus_events(hass, ID_CHANGED)
        if e["data"].get("change") == "hardware_changed"
    ]
    assert len(swap) == 1 and swap[0]["severity"] == "warning"
    assert swap[0]["data"]["board_changed"] is True

    # the original device comes back: flag cleared, info event
    coord.poll(data=router_data())
    record = core_of(hass).registry.get_by_entry("e1")
    assert record.identity.status is IdentityStatus.CONFIRMED
    restored = [
        e
        for e in bus_events(hass, ID_CHANGED)
        if e["data"].get("change") == "hardware_restored"
    ]
    assert len(restored) == 1


async def test_case04_swap_that_also_duplicates_sets_both_flags(
    disks: FakeDisks,
) -> None:
    hass = make_hass()
    c1 = await setup_router(hass, FakeEntry("e1"), router_data())
    await setup_router(
        hass,
        FakeEntry("e2", host="192.168.1.2"),
        router_data(macs=MAC_B, board="cudy,wr3000", model="Cudy"),
    )
    # e1's address now answers with e2's device
    c1.poll(data=router_data(macs=MAC_B, board="cudy,wr3000", model="Cudy"))
    registry = core_of(hass).registry
    r1, r2 = registry.get_by_entry("e1"), registry.get_by_entry("e2")
    assert r1.identity.identity_flags == {
        IdentityFlag.CHANGED,
        IdentityFlag.DUPLICATE_SUSPECTED,
    }
    assert r1.identity.status is IdentityStatus.CHANGED  # changed outranks duplicate
    assert IdentityFlag.DUPLICATE_SUSPECTED in r2.identity.identity_flags
    assert r1.router_id != r2.router_id
    swap = [
        e
        for e in bus_events(hass, ID_CHANGED)
        if e["data"].get("change") == "hardware_changed"
    ]
    assert [e["router_id"] for e in swap] == [r1.router_id]
    dup = bus_events(hass, DUPLICATE)
    assert {e["router_id"] for e in dup} == {r1.router_id, r2.router_id}
