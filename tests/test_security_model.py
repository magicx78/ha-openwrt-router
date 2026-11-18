"""Tests for security_model (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime

import pytest

from custom_components.openwrt_router.core_masking import (
    MASK,
    pseudonymise_identifier,
    pseudonymise_user_id,
    pseudonymise_user_ids,
    secret_digest_factory,
)
from custom_components.openwrt_router.core_models import (
    CLIENT_REF_PATTERN,
    CORE_OWNED_MODULE_CAPABILITIES,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    MODULE_KEY_BYTES,
    MODULE_KEY_PURPOSE_PATTERN,
    Actor,
    ActorKind,
    AuditRing,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    CoreEventType,
    default_router_id,
    derive_core_key,
    derive_module_key,
    is_core_event_type,
)
from custom_components.openwrt_router.security_model import (
    CAPABILITY_PREFIX,
    EVENT_PREFIX,
    IDENTITY_KEY_PURPOSE,
    MASK_DOMAIN,
    MASK_IP,
    MASK_MAC,
    MAX_EVIDENCE,
    MAX_EVIDENCE_LEN,
    MAX_LINKED_INCIDENTS,
    MODULE_SOURCE,
    Assessment,
    Availability,
    DataSource,
    Endpoint,
    LogPath,
    SecCategory,
    SecurityEvent,
    Severity,
    SourceStatus,
    assess,
    can_confirm,
    check_module_key,
    clean_text,
    event_actor,
    event_type,
    forget_router,
    forgotten_router_id,
    log_path_capability,
    make_correlation_id,
    make_event_id,
    mask_identities,
    missing_status,
    source_status,
    status_from_capability,
    valid_router_id,
    zone_ref,
)

ROUTER = "rtr_" + "a" * 32
MAC = "AA:BB:CC:11:22:33"
MAC_NORM = "aa:bb:cc:11:22:33"
IP4 = "192.168.40.17"
IP6 = "fe80::1234:5678:9abc:def0"
DOMAIN = "evil-tracker.example.com"
HOST = "kids-tablet"
IDENTITIES = (MAC, MAC_NORM, IP4, IP6, DOMAIN, HOST)
HA_USER = "0d5a2f3b9c8e4a71b6f0e2d4c6a8b0f1"  # Home Assistant user id form
INSTALLATION_KEY = b"i" * 32
# What api.async_get_module_key(MODULE_SOURCE, purpose=IDENTITY_KEY_PURPOSE)
# returns (core derivation, contract 11.5).
KEY = derive_module_key(INSTALLATION_KEY, MODULE_SOURCE, IDENTITY_KEY_PURPOSE)
_CODE = r"[a-z0-9][a-z0-9_.:-]*"


def _event(**kw: object) -> SecurityEvent:
    base: dict[str, object] = {
        "event_id": make_event_id("t", 1),
        "ts": 1_700_000_000.0,
        "type": event_type("fw_port_scan_hint"),
        "router_id": ROUTER,
        "category": SecCategory.FIREWALL,
        "severity": Severity.WARNING,
        "data_source": DataSource.FIREWALL_LOG,
        "assessment": Assessment.NOTICEABLE,
        "client": MAC,
        "src": Endpoint(addr=IP4, port=51234, zone="guest"),
        "dst": Endpoint(addr=IP6, port=22, zone="lan"),
        "evidence": (f"host={HOST}", f"query {DOMAIN} from {IP4}"),
    }
    base.update(kw)
    return SecurityEvent(**base)  # type: ignore[arg-type]


def _no_identity(text: str) -> None:
    lowered = text.lower()
    for ident in IDENTITIES:
        assert ident.lower() not in lowered, ident


# --- event basics -----------------------------------------------------------


def test_event_roundtrip_is_lossless() -> None:
    event = _event(linked_incident_ids=("inc_1",), count=3, last_ts=1_700_000_100.0)
    data = json.loads(json.dumps(event.to_dict()))
    assert SecurityEvent.from_dict(data) == event


def test_event_from_dict_is_tolerant() -> None:
    assert SecurityEvent.from_dict(None) is None
    assert SecurityEvent.from_dict({"event_id": "evt_x"}) is None
    assert SecurityEvent.from_dict({**_event().to_dict(), "ts": "soon"}) is None
    loose = {
        **_event().to_dict(),
        "unknown_future_key": 1,
        "confidence": "high",
        "count": "many",
        "src": "not-a-mapping",
    }
    event = SecurityEvent.from_dict(loose)
    assert event is not None
    assert event.count == 1
    assert event.src is None


def test_dedup_key_is_discriminator_and_scope_matches_core() -> None:
    event = _event()
    assert event.dedup_key is not None and len(event.dedup_key) == 16
    _no_identity(event.dedup_key)
    assert event.dedup_scope == (ROUTER, event.type, event.dedup_key)
    assert event.to_core_event().dedup_scope == event.dedup_scope


def test_dedup_key_differs_per_zone_client_and_router() -> None:
    base = _event(client=None, src=None, dst=Endpoint(zone="lan"))
    keys = {
        base.dedup_scope,
        _event(client=None, src=None, dst=Endpoint(zone="iot")).dedup_scope,
        _event(
            client=None, src=None, dst=Endpoint(zone="lan"), router_id="rtr_" + "b" * 32
        ).dedup_scope,
        _event(
            client="aa:bb:cc:00:00:01", src=None, dst=Endpoint(zone="lan")
        ).dedup_scope,
        _event(
            client=None, src=None, dst=Endpoint(zone="lan"), type=event_type("other")
        ).dedup_scope,
    }
    assert len(keys) == 5


def test_event_rejects_bad_values() -> None:
    with pytest.raises(ValueError):
        _event(ts=float("nan"))
    with pytest.raises(ValueError):
        _event(event_id="")
    with pytest.raises(ValueError):
        _event(category="nope")
    with pytest.raises(TypeError):
        _event(src={"addr": IP4})


def test_evidence_caps_and_control_characters() -> None:
    long = "x" * (MAX_EVIDENCE_LEN * 3)
    event = _event(
        evidence=["a\x00b\x1b[31mc\u202e", long, *[f"e{i}" for i in range(50)]],
        linked_incident_ids=[f"inc_{i}" for i in range(100)],
    )
    assert len(event.evidence) == MAX_EVIDENCE
    assert event.evidence[0] == "ab[31mc"
    assert len(event.evidence[1]) <= MAX_EVIDENCE_LEN
    assert len(event.linked_incident_ids) == MAX_LINKED_INCIDENTS
    assert clean_text("ok\r\nnext\ttab") == "oknexttab"


def test_confirmed_needs_explicit_proof_never_logs_or_counters_alone() -> None:
    with pytest.raises(ValueError):
        _event(assessment=Assessment.CONFIRMED, proof=False)
    # syslog alone: even with a proof flag, log text is forgeable
    with pytest.raises(ValueError):
        _event(
            assessment=Assessment.CONFIRMED,
            proof=True,
            data_source=DataSource.ROUTER_LOG,
        )
    # counters alone (no proof)
    with pytest.raises(ValueError):
        _event(assessment=Assessment.CONFIRMED, data_source=DataSource.NFT_COUNTERS)
    assert assess(10, data_source=DataSource.NFT_COUNTERS) is Assessment.SUSPICIOUS
    assert (
        assess(10, proof=True, data_source=DataSource.FIREWALL_LOG)
        is Assessment.SUSPICIOUS
    )
    assert can_confirm(DataSource.HOSTAPD_CLIENTS, True)
    ok = _event(
        assessment=Assessment.CONFIRMED,
        proof=True,
        data_source=DataSource.HOSTAPD_CLIENTS,
    )
    assert ok.assessment is Assessment.CONFIRMED


def test_stored_confirmed_without_proof_is_downgraded() -> None:
    data = {**_event().to_dict(), "assessment": "confirmed", "proof": False}
    event = SecurityEvent.from_dict(data)
    assert event is not None
    assert event.assessment is Assessment.SUSPICIOUS


def test_assess_levels() -> None:
    assert assess(0) is Assessment.NORMAL
    assert assess(1) is Assessment.NOTICEABLE
    assert assess(2) is Assessment.SUSPICIOUS
    assert [a.rank for a in Assessment] == [0, 1, 2, 3]


def test_merged_with_counts_and_keeps_strongest() -> None:
    a = _event(ts=100.0, severity=Severity.INFO, evidence=("a",))
    b = _event(
        ts=50.0,
        severity=Severity.WARNING,
        evidence=("b",),
        linked_incident_ids=("inc_9",),
    )
    merged = a.merged_with(b)
    assert merged.count == 2
    assert merged.ts == 50.0
    assert merged.last_ts == 100.0
    assert merged.severity is Severity.WARNING
    assert set(merged.evidence) == {"a", "b"}
    assert merged.linked_incident_ids == ("inc_9",)


# --- core contract ----------------------------------------------------------


def test_to_core_event_aligns_with_contract() -> None:
    event = _event(correlation_id=make_correlation_id("x"))
    core = event.to_core_event()
    assert isinstance(core, CoreEvent)
    assert core.type.startswith(EVENT_PREFIX)
    assert core.event_id.startswith("evt_")
    assert core.correlation_id is not None and core.correlation_id.startswith("cor_")
    assert core.ts == datetime.fromtimestamp(event.ts, UTC)
    assert core.router_id == ROUTER
    assert core.severity is Severity.WARNING
    assert core.data["incident_type"] == "sec_fw_port_scan_hint"
    assert core.data["dst_port"] == 22
    # typed core fields instead of data (contract 19.1 #107, #103)
    assert core.confidence == event.confidence
    assert core.classification == Assessment.NOTICEABLE.value
    assert core.security_relevant is True
    assert core.audit_ring is AuditRing.SECURITY
    for name in ("confidence", "assessment", "client_ref", "linked_incident_ids"):
        assert name not in core.data
    # without the module key no reference at all
    assert core.client_ref is None
    for name in ("src_ref", "dst_ref", "src_zone_ref", "dst_zone_ref"):
        assert name not in core.data
    _no_identity(json.dumps(dict(core.data), default=str))


def test_to_core_event_identities_only_as_core_pseudonyms() -> None:
    core = _event().to_core_event(module_key=KEY)
    assert core.client_ref == pseudonymise_identifier("client", MAC, KEY)
    assert CLIENT_REF_PATTERN.fullmatch(core.client_ref)
    assert core.data["src_ref"] == pseudonymise_identifier("ip", IP4, KEY)
    assert core.data["dst_ref"] == pseudonymise_identifier("ip", IP6, KEY)
    assert core.data["src_zone_ref"] == zone_ref("guest", KEY)
    assert core.data["dst_zone_ref"] == zone_ref("lan", KEY)
    assert zone_ref("guest", KEY) != zone_ref("lan", KEY)
    # the same client in another spelling gets the same reference
    other = _event(client=MAC_NORM).to_core_event(module_key=KEY)
    assert other.client_ref == core.client_ref
    # a client known by its IP only (DNS logs) is no cli_ reference
    dns = _event(client=IP4).to_core_event(module_key=KEY)
    assert dns.client_ref is None
    assert dns.data["client_ip_ref"] == pseudonymise_identifier("ip", IP4, KEY)
    _no_identity(json.dumps(core.to_dict(), default=str))


def test_core_event_data_holds_only_ids_and_counters() -> None:
    # contract 12.1: data carries ids and counters, never configuration
    # values; evidence text stays in the SecurityEvent (our own store) and
    # the core event points to it by the shared event id.
    event = _event(
        evidence=("zone=guest", f"host={HOST}", "attempts=4"),
        linked_incident_ids=("inc_1", "inc 2"),
        correlation_id=make_correlation_id("x"),
    )
    core = event.to_core_event(module_key=KEY)
    assert core.event_id == event.event_id
    assert core.data["evidence_count"] == 3
    assert core.incident_ref == "inc_1"
    assert core.data["linked_incidents"] == 2
    for name, value in core.data.items():
        assert value is None or isinstance(value, bool | int | float | str), name
        if isinstance(value, str):
            assert re.fullmatch(_CODE, value), (name, value)
            assert value not in ("guest", "lan"), name
    text = json.dumps(dict(core.data))
    for item in ("guest", "lan", "attempts", "host=", 'evidence"', HOST):
        assert item not in text
    _no_identity(json.dumps(core.to_dict(), default=str))


def test_module_key_follows_the_core_derivation() -> None:
    assert MODULE_KEY_PURPOSE_PATTERN.fullmatch(IDENTITY_KEY_PURPOSE)
    assert check_module_key(KEY) == KEY and len(KEY) == MODULE_KEY_BYTES
    for bad in (b"k" * 16, b"k" * 31, b"k" * 33, b""):
        with pytest.raises(ValueError):
            check_module_key(bad)
    with pytest.raises(TypeError):
        check_module_key("k" * 32)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        _event().to_core_event(module_key=b"short")


def test_fleet_event_has_no_router_id() -> None:
    event = _event(router_id=None)
    assert event.to_core_event().router_id is None
    assert event.dedup_scope[0] == "-"


# --- data sources -----------------------------------------------------------


def test_data_sources_reuse_core_capability_names() -> None:
    assert DataSource.ROUTER_LOG == Capability.DATA_LOGS.value
    assert DataSource.CONFIG_DRIFT == Capability.CONFIG_DRIFT.value
    own = [s for s in DataSource if not s.startswith(("data.", "config."))]
    assert all(s.startswith("security.center.") for s in own)
    assert log_path_capability(LogPath.SYSLOG) == "security.center.log_path.syslog"


def test_source_status_states() -> None:
    src = DataSource.DNS_QUERY_LOG
    assert (
        source_status(src, now=1000, last_ok=None).availability
        is Availability.NOT_AVAILABLE
    )
    assert source_status(src, now=1000, last_ok=990).usable
    stale = source_status(src, now=10_000, last_ok=1000, stale_after_s=900)
    assert stale.availability is Availability.STALE and not stale.usable
    off = source_status(src, now=1000, last_ok=990, enabled=False)
    assert off.availability is Availability.NOT_AVAILABLE
    assert missing_status(src).reason == "not_reported"
    assert SourceStatus.from_dict(stale.to_dict()) == stale
    assert SourceStatus.from_dict({"source": src, "availability": "maybe"}) is None


def test_status_from_capability_uses_core_status() -> None:
    def cap(state: CapabilityState, reason: str) -> CapabilityStatus:
        return CapabilityStatus(
            capability=Capability.DATA_LOGS.value,
            state=state,
            reason=reason,
            source="test",
            detected_at=datetime(2026, 11, 17, tzinfo=UTC),
        )

    off = status_from_capability(
        cap(CapabilityState.UNAVAILABLE, "disabled"), now=100.0, last_ok=90.0
    )
    assert off.availability is Availability.NOT_AVAILABLE
    assert off.reason == "disabled"
    on = status_from_capability(
        cap(CapabilityState.AVAILABLE, "ok"), now=100.0, last_ok=90.0
    )
    assert on.usable and on.source == DataSource.ROUTER_LOG
    never = status_from_capability(
        cap(CapabilityState.AVAILABLE, "ok"), now=100.0, last_ok=None
    )
    assert not never.usable


# --- case 21: privacy -------------------------------------------------------


def test_case21_privacy_repr_mask_and_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    event = _event()
    _no_identity(repr(event))
    _no_identity(repr(event.src))
    _no_identity(repr(event.dst))
    _no_identity(json.dumps(event.redacted()))
    masked = mask_identities(
        f"client {MAC} ip {IP4} v6 {IP6} asked {DOMAIN} host={HOST}"
        " kind wifi.roam id 12:34"
    )
    _no_identity(masked)  # host=… masked as key=value
    assert MASK_MAC in masked and MASK_IP in masked and MASK_DOMAIN in masked
    assert "wifi.roam" in masked  # own vocabulary stays readable
    nested = mask_identities({"hostname": HOST, "rows": [{"mac": MAC, "x": IP4}]})
    _no_identity(json.dumps(nested))
    SecurityEvent.from_dict({**event.to_dict(), "category": "bad"})
    logging.getLogger("custom_components.openwrt_router.security_model").warning(
        "event %r", event
    )
    for record in caplog.records:
        _no_identity(record.getMessage())


# --- revised core contract (00b3d1f) ----------------------------------------


def test_event_type_outside_core_namespaces() -> None:
    assert EVENT_PREFIX == "security_center."
    assert not is_core_event_type(event_type("port_scan"))
    with pytest.raises(ValueError):
        _event(type="security.center.port_scan")  # core namespace "security."
    with pytest.raises(ValueError):
        _event(type="configuration.drift_detected")


def test_merged_duplicates_map_to_core_repeat_fields() -> None:
    single = _event().to_core_event()
    assert single.repeat_count == 0 and single.last_repeat_at is None
    merged = (
        _event(ts=100.0).merged_with(_event(ts=160.0)).merged_with(_event(ts=220.0))
    )
    core = merged.to_core_event()
    assert core.repeat_count == 2
    assert core.last_repeat_at == datetime.fromtimestamp(220.0, UTC)
    assert "count" not in core.data and "last_ts" not in core.data
    assert core.data["linked_incidents"] == 0


def test_log_path_off() -> None:
    assert LogPath("off") is LogPath.OFF
    assert log_path_capability("collector") == "security.center.log_path.collector"
    with pytest.raises(ValueError):
        log_path_capability(LogPath.OFF)


def test_mask_identities_also_applies_core_secret_masking() -> None:
    masked = mask_identities(
        {"note": "from aa:bb:cc:11:22:33 login password=hunter2", "psk": "x", "n": 3}
    )
    assert "hunter2" not in json.dumps(masked)
    assert masked["psk"] != "x" and masked["n"] == 3
    assert masked["note"] == f"from {MASK_MAC} login password={MASK}"


def test_secret_value_masked_by_core_swallows_a_following_identity() -> None:
    # The core masks a secret value up to the end of the line on purpose
    # (core_masking._VALUE_RE "over-masking on purpose"): a MAC behind it is
    # inside the masked span. It must not survive in any form.
    masked = mask_identities({"note": "login password=hunter2 from " + MAC})
    assert masked == {"note": f"login password={MASK}"}
    _no_identity(json.dumps(masked))


def test_core_masks_before_the_text_is_cut() -> None:
    # A token cut by the 200-character cap first is too short for the core
    # to recognise; the core must see the uncut text.
    token = "Zx9" + "q7Lm2Vb8Nc4Xs1Kd6Fg3Hj5" * 3
    for pad in range(150, 200, 5):
        text = "a " * (pad // 2) + "session token " + token + " end"
        masked = mask_identities({"n": text})["n"]
        assert token[:8] not in masked, pad


def test_valid_router_id_uses_core_format() -> None:
    assert valid_router_id(ROUTER) == ROUTER
    assert valid_router_id(default_router_id("entry-1")) == default_router_id("entry-1")
    for bad in (None, "", "r1", "rtr_" + "A" * 32, ROUTER + "|x", 5):
        assert valid_router_id(bad) is None
    with pytest.raises(ValueError):
        _event(router_id="r1")
    assert SecurityEvent.from_dict({**_event().to_dict(), "router_id": "r1"}) is None


def test_zone_refs_use_the_core_digest_with_the_module_key() -> None:
    # The core has no identifier kind for a firewall zone: the zone name is
    # an HMAC under the module key (core_masking.secret_digest_factory).
    assert zone_ref("guest", KEY) == secret_digest_factory(KEY)(
        "security_center/zone/guest"
    )
    assert zone_ref("Guest ", KEY) == zone_ref("guest", KEY)
    assert zone_ref(None, KEY) is None and zone_ref("", KEY) is None


def test_actor_reaches_the_core_unchanged_and_never_our_store() -> None:
    raw = Actor(kind=ActorKind.USER, user_id=HA_USER, context_id="ctx-1", is_admin=True)
    with pytest.raises(ValueError):
        _event(actor=raw)  # context ids are dropped first (event_actor)
    actor = event_actor(raw)
    assert actor is not None
    assert actor.user_id == HA_USER and actor.is_admin is True
    assert actor.context_id is None and actor.parent_context_id is None
    assert event_actor(None) is None
    event = _event(actor=actor)
    core = event.to_core_event(module_key=KEY)
    # The core keeps the user id in its audit store and pseudonymises it on
    # the bus with its stable salt: the Security Center pseudonym IS the core
    # bus pseudonym, linkable with every other event of that user.
    assert core.actor == actor
    bus_salt = derive_core_key(INSTALLATION_KEY, "bus_pseudonym")
    bus = pseudonymise_user_ids(core.to_dict(), bus_salt)
    assert bus["actor"]["user_id"] == pseudonymise_user_id(HA_USER, bus_salt)
    assert HA_USER not in json.dumps(bus)
    # our own forms never hold the Home Assistant user id
    for text in (
        json.dumps(event.to_dict()),
        json.dumps(event.redacted()),
        repr(event),
    ):
        assert HA_USER not in text and "ctx-1" not in text
    stored = SecurityEvent.from_dict(json.loads(json.dumps(event.to_dict())))
    assert stored is not None and stored.actor is not None
    assert stored.actor.user_id is None and stored.actor.kind is ActorKind.USER
    assert SecurityEvent.from_dict({**event.to_dict(), "actor": "x"}).actor is None  # type: ignore[union-attr]


def test_module_prefixes_come_from_the_core() -> None:
    assert EVENT_PREFIX == MODULE_EVENT_PREFIXES[MODULE_SOURCE]
    assert CAPABILITY_PREFIX.startswith(MODULE_CAPABILITY_NAMESPACES[MODULE_SOURCE])
    core_names = {c.value for c in Capability}
    for source in DataSource:
        assert source in core_names or source.startswith(CAPABILITY_PREFIX), source
        assert source not in CORE_OWNED_MODULE_CAPABILITIES


def test_capability_determined_on_first_use_is_judged_by_delivery() -> None:
    def cap(reason: str) -> CapabilityStatus:
        return CapabilityStatus(
            capability=Capability.CONFIG_DRIFT.value,
            state=CapabilityState.UNKNOWN,
            reason=reason,
            source="test",
            detected_at=datetime(2026, 11, 18, tzinfo=UTC),
        )

    first_use = cap(CapabilityReason.DETERMINED_ON_FIRST_USE)
    assert status_from_capability(first_use, now=100.0, last_ok=90.0).usable
    assert not status_from_capability(first_use, now=100.0, last_ok=None).usable
    pending = status_from_capability(
        cap(CapabilityReason.NO_DATA_YET), now=100.0, last_ok=90.0
    )
    assert pending.availability is Availability.NOT_AVAILABLE
    assert pending.reason == CapabilityReason.NO_DATA_YET


def test_forgotten_router_id_reads_the_core_event() -> None:
    def core_event(event_type: str, router_id: str | None) -> CoreEvent:
        return CoreEvent(
            event_id="evt_" + "0" * 32,
            ts=datetime(2026, 11, 18, tzinfo=UTC),
            type=event_type,
            source="core",
            router_id=router_id,
        )

    assert forgotten_router_id(core_event(CoreEventType.ROUTER_FORGOTTEN, ROUTER)) == (
        ROUTER
    )
    assert (
        forgotten_router_id(core_event(CoreEventType.ROUTER_ORPHANED, ROUTER)) is None
    )
    assert forgotten_router_id(core_event(CoreEventType.ROUTER_FORGOTTEN, None)) is None


def test_forget_router_asks_every_holder_and_checks_the_id() -> None:
    seen: list[str] = []

    class Holder:
        def forget_router(self, router_id: str) -> None:
            seen.append(router_id)

    assert forget_router(ROUTER, [Holder(), Holder()]) == 2
    assert seen == [ROUTER, ROUTER]
    with pytest.raises(ValueError):
        forget_router("rtr_x|", [Holder()])
