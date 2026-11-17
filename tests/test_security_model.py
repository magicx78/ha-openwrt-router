"""Tests for security_model (Security Center stage 2, pure logic)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime

import pytest

from custom_components.openwrt_router.core_models import (
    Capability,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    is_core_event_type,
)
from custom_components.openwrt_router.security_model import (
    EVENT_PREFIX,
    MASK_DOMAIN,
    MASK_IP,
    MASK_MAC,
    MAX_EVIDENCE,
    MAX_EVIDENCE_LEN,
    MAX_LINKED_INCIDENTS,
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
    clean_text,
    event_type,
    log_path_capability,
    make_correlation_id,
    make_event_id,
    mask_identities,
    missing_status,
    source_status,
    status_from_capability,
)

ROUTER = "rtr_" + "a" * 32
MAC = "AA:BB:CC:11:22:33"
MAC_NORM = "aa:bb:cc:11:22:33"
IP4 = "192.168.40.17"
IP6 = "fe80::1234:5678:9abc:def0"
DOMAIN = "evil-tracker.example.com"
HOST = "kids-tablet"
IDENTITIES = (MAC, MAC_NORM, IP4, IP6, DOMAIN, HOST)


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
    assert "client_ref" not in core.data
    _no_identity(json.dumps(dict(core.data), default=str))


def test_to_core_event_identity_only_as_digest() -> None:
    core = _event().to_core_event(identity_digest=lambda v: "ref-" + str(len(v)))
    assert core.data["client_ref"] == "ref-17"
    assert core.data["src_ref"] == "ref-13"
    _no_identity(json.dumps(dict(core.data), default=str))


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


def test_log_path_off() -> None:
    assert LogPath("off") is LogPath.OFF
    assert log_path_capability("collector") == "security.center.log_path.collector"
    with pytest.raises(ValueError):
        log_path_capability(LogPath.OFF)


def test_mask_identities_also_applies_core_secret_masking() -> None:
    masked = mask_identities(
        {"note": "login password=hunter2 from aa:bb:cc:11:22:33", "psk": "x", "n": 3}
    )
    assert "hunter2" not in json.dumps(masked)
    assert masked["psk"] != "x" and masked["n"] == 3
    assert MASK_MAC in masked["note"]
