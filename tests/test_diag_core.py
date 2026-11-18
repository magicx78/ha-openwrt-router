"""Adapter between the pure diag modules and the enterprise core (diag_core).

Every value here is invented: router ids come from made-up entry ids,
addresses are documentation ranges (RFC 5737 / RFC 3849) and hostnames use
the reserved ``.invalid`` top-level domain. Nothing talks to a network.
"""

from __future__ import annotations

import json
import logging
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any

import pytest
from core_testkit import (
    ADMIN_ID,
    USER_ID,
    FakeDisks,
    add_users,
    bus_events,
    make_hass,
    user_actor,
)

from custom_components.openwrt_router import diag_core
from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_guard import ActionGuard
from custom_components.openwrt_router.core_masking import (
    ACTOR_PSEUDONYM_PREFIX,
    MASK,
)
from custom_components.openwrt_router.core_models import (
    CORE_OWNED_MODULE_CAPABILITIES,
    CORRELATION_ID_PREFIX,
    MODULE_CAPABILITY_NAMESPACES,
    MODULE_EVENT_PREFIXES,
    ActionClass,
    Actor,
    ActorKind,
    AuditRing,
    Capability,
    CapabilityReason,
    CapabilityState,
    CapabilityStatus,
    CoreEvent,
    CoreEventType,
    DecisionState,
    EventResult,
    FirmwareInfo,
    RouterIdentity,
    RouterRecord,
    is_core_event_type,
    is_valid_id,
    new_id,
)
from custom_components.openwrt_router.core_models import (
    Severity as CoreSeverity,
)
from custom_components.openwrt_router.diag_baseline import (
    LATENCY_CONFIG,
    LOSS_CONFIG,
    new_baseline,
)
from custom_components.openwrt_router.diag_causes import (
    RouterDependencies,
    correlate,
)
from custom_components.openwrt_router.diag_chain import (
    dns_server_change,
    gateway_change,
)
from custom_components.openwrt_router.diag_model import (
    AddressFamily,
    Basis,
    CauseClass,
    ChainResult,
    Classification,
    Finding,
    LocationKind,
    MeasurementPoint,
    PointKind,
    ProbeKind,
    ProbeOutcome,
    ProbeResult,
    Severity,
    Stage,
    StageResult,
    StageState,
)
from custom_components.openwrt_router.diag_scheduler import DiagJob, RequestStatus
from custom_components.openwrt_router.diag_stats import SeriesKey
from custom_components.openwrt_router.diag_targets import (
    PendingTarget,
    Refusal,
    ScopePolicy,
    TargetRegistry,
    check_resolved,
    make_target,
)
from custom_components.openwrt_router.router_identity import router_id_for_entry

R1 = router_id_for_entry("entry-diag-one")
R2 = router_id_for_entry("entry-diag-two")
T0 = datetime(2026, 11, 18, 9, 0, tzinfo=UTC)

# invented sensitive values that must never leave the adapter unmasked
GW_OLD = "192.0.2.1"
GW_NEW = "192.0.2.254"
DNS_OLD = ("198.51.100.53",)
DNS_NEW = ("2001:db8::53", "198.51.100.54")
RAW_ADDR = "203.0.113.77"
RAW_HOST = "nas-cellar.example.invalid"
SENSITIVE = (GW_OLD, GW_NEW, *DNS_OLD, *DNS_NEW, RAW_ADDR, RAW_HOST)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _log(hass: Any = None) -> AuditLog:
    log = AuditLog(hass or make_hass())
    await log.async_load()
    return log


def _dump(value: Any) -> str:
    return json.dumps(value, default=str, sort_keys=True)


def _assert_clean(value: Any) -> None:
    text = _dump(value)
    for needle in SENSITIVE:
        assert needle not in text, needle


def _problem(
    router_id: str | None,
    classification: Classification = Classification.WAN_PROBLEM,
    severity: Severity = Severity.CRITICAL,
    *,
    family: AddressFamily | None = AddressFamily.IPV4,
    stage: Stage | None = Stage.WAN,
    chain: ChainResult | None = None,
) -> Finding:
    return Finding(
        point=diag_core.point_for(router_id),
        classification=classification,
        severity=severity,
        summary_key=classification.value,
        recommendation_key=f"check_{classification.value}",
        cause_class=CauseClass.PROBABLE,
        cause_stage=stage,
        family=family,
        reasons=("invented_reason",),
        unmeasured=("ipv6:dns",),
        chain=chain,
    )


def _leaky_chain(router_id: str) -> ChainResult:
    """A chain whose excluded probe carries raw addresses in its evidence."""
    stray = ProbeResult(
        point=MeasurementPoint.ha(),
        target_id="gw-probe",
        kind=ProbeKind.TCP,
        stage=Stage.GATEWAY,
        family=AddressFamily.IPV4,
        outcome=ProbeOutcome.OK,
        timestamp=1.0,
        subject=R2,
        evidence={"address": RAW_ADDR, "hostname": RAW_HOST, "note": RAW_HOST},
    )
    stage = StageResult(
        stage=Stage.WAN,
        family=AddressFamily.IPV4,
        state=StageState.FAILED,
        basis=Basis.DIRECT,
        reasons=("invented",),
        failed_targets=("wan-probe",),
    )
    return ChainResult(
        point=diag_core.point_for(router_id), stages=(stage,), excluded=(stray,)
    )


def _status(name: str, state: CapabilityState = CapabilityState.AVAILABLE):
    return CapabilityStatus(
        capability=name,
        state=state,
        reason=CapabilityReason.OK
        if state is CapabilityState.AVAILABLE
        else CapabilityReason.NOT_DETECTED,
        source="test",
        detected_at=T0,
    )


FULL_FACTS = diag_core.DiagRouterFacts(
    interface_dump=True,
    odhcpd_methods=frozenset({"ipv6leases", "ipv6ra", "ipv4leases"}),
    dnsmasq_ubus=True,
    dnsmasq_metric_keys=frozenset({"dns_queries", "dns_cache_inserted"}),
    dhcp_config=True,
    exec_permitted=True,
    tools=frozenset({"ping", "nslookup", "traceroute"}),
    mem_available_kb=96_000,
)
RELAY_FACTS = diag_core.DiagRouterFacts(
    interface_dump=True,
    odhcpd_methods=frozenset({"ipv6ra"}),
    dnsmasq_ubus=False,
    dnsmasq_metric_keys=frozenset(),
    dhcp_config=True,
    exec_permitted=True,
    tools=frozenset({"ping", "nslookup"}),
    mem_available_kb=21_000,
)
UBUS_OK = _status(Capability.TRANSPORT_UBUS)


def _record(router_id: str, *, model: str, version: str) -> RouterRecord:
    return RouterRecord(
        identity=RouterIdentity(
            router_id=router_id, entry_id="entry-x", model=model, board_name=model
        ),
        firmware=FirmwareInfo(version=version, board_name=model),
        capabilities={Capability.TRANSPORT_UBUS: UBUS_OK},
    )


# --- identity ------------------------------------------------------------------


def test_identity_round_trips_router_and_ha() -> None:
    assert diag_core.point_for(None) == MeasurementPoint.ha()
    point = diag_core.point_for(R1)
    assert point == MeasurementPoint.router(R1)
    assert diag_core.router_id_for(point) == R1
    assert diag_core.router_id_for(MeasurementPoint.ha()) is None
    key = diag_core.series_key(R1, "gw-probe", ProbeKind.ICMP, AddressFamily.IPV4)
    assert key == SeriesKey(R1, "gw-probe", "icmp", "ipv4")
    assert diag_core.router_id_for_series(key) == R1
    ha_key = diag_core.series_key(None, "gw-probe", "icmp", "ipv6")
    assert ha_key.point == diag_core.HA_POINT_KEY
    assert diag_core.router_id_for_series(ha_key) is None
    assert diag_core.scheduler_key(R1) == R1
    assert diag_core.scheduler_key(None) is None


def test_ha_point_cannot_collide_with_a_router_id() -> None:
    assert diag_core.HA_POINT_KEY == PointKind.HA.value
    assert not is_valid_id(diag_core.HA_POINT_KEY, "rtr_")
    for router_id in (R1, R2, router_id_for_entry("ha"), new_id("rtr_")):
        assert diag_core.series_point(router_id) != diag_core.HA_POINT_KEY
        assert diag_core.point_for(router_id).label != diag_core.HA_POINT_KEY
    # a router keyed "ha" would read as the HA point: the adapter refuses it
    for bad in ("ha", "HA", "", "rtr_short", "router-1", 7):
        with pytest.raises(ValueError):
            diag_core.point_for(bad)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            diag_core.series_point(bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        diag_core.router_id_for(MeasurementPoint.router("ha"))
    with pytest.raises(ValueError):
        diag_core.router_id_for_series(SeriesKey("router-1", "t", "icmp", "ipv4"))


def test_dependencies_are_keyed_by_core_router_ids() -> None:
    deps = diag_core.dependencies_by_router(
        {R1: RouterDependencies(gateway=R2, wan="wan-main"), R2: RouterDependencies()}
    )
    assert set(deps) == {R1, R2}
    with pytest.raises(ValueError):
        diag_core.dependencies_by_router({"ha": RouterDependencies()})
    with pytest.raises(ValueError):
        diag_core.dependencies_by_router({R1: RouterDependencies(gateway="gw-x")})
    with pytest.raises(ValueError):
        diag_core.dependencies_by_router(
            {R1: RouterDependencies(upstream=frozenset({"ha"}))}
        )


# --- events --------------------------------------------------------------------


def test_module_names_follow_the_core_tables() -> None:
    assert diag_core.MODULE == "net_diagnostics"
    assert diag_core.EVENT_PREFIX == MODULE_EVENT_PREFIXES[diag_core.MODULE]
    assert diag_core.CAPABILITY_PREFIX == MODULE_CAPABILITY_NAMESPACES[diag_core.MODULE]
    for event_type in diag_core.DIAG_EVENT_TYPES:
        assert event_type.startswith(diag_core.EVENT_PREFIX)
        assert not is_core_event_type(event_type)
    assert diag_core.AUDIT_DUTY_EVENT_TYPES <= diag_core.DIAG_EVENT_TYPES
    assert diag_core.EVENT_MANUAL_RUN in diag_core.AUDIT_DUTY_EVENT_TYPES
    assert diag_core.EVENT_ROUTER_PROBES_CHANGED in diag_core.AUDIT_DUTY_EVENT_TYPES


def test_no_incidents_are_created() -> None:
    names = [n for n in dir(diag_core) if "incident" in n.lower()]
    assert names == []
    assert all("incident" not in t for t in diag_core.DIAG_EVENT_TYPES)


async def test_event_prefix_registration_and_reserved_diag_prefix(disks) -> None:
    log = await _log()
    diag_core.register_event_prefix(log)
    diag_core.register_event_prefix(log)  # idempotent
    with pytest.raises(ValueError):  # the capability namespace is no event prefix
        log.register_event_prefix("diag.", module=diag_core.MODULE)


def test_severity_mapping() -> None:
    assert diag_core.core_severity(Severity.OK) is CoreSeverity.INFO
    assert diag_core.core_severity(Severity.INFO) is CoreSeverity.INFO
    assert diag_core.core_severity(Severity.WARNING) is CoreSeverity.WARNING
    assert diag_core.core_severity(Severity.CRITICAL) is CoreSeverity.CRITICAL


def test_finding_event_mapping() -> None:
    cor = diag_core.new_correlation_id()
    event = diag_core.finding_event(_problem(R1), correlation_id=cor)
    assert event is not None
    assert event.event_type == diag_core.EVENT_FINDING
    assert event.severity is CoreSeverity.CRITICAL
    assert event.result is EventResult.FAILURE
    assert event.router_id == R1
    assert event.correlation_id == cor
    assert event.dedup_key == "wan_problem:ipv4:wan"
    assert event.actor is None
    assert event.data["classification"] == "wan_problem"
    assert event.data["point_kind"] == "router"
    assert event.data["unmeasured_count"] == 1
    kwargs = event.emit_kwargs()
    assert kwargs["source"] == diag_core.MODULE
    assert kwargs["event_type"] == diag_core.EVENT_FINDING
    # the HA point maps to the fleet scope (router_id None)
    ha_event = diag_core.finding_event(_problem(None, family=None, stage=None))
    assert ha_event is not None and ha_event.router_id is None
    assert ha_event.dedup_key == "wan_problem:any:none"


def test_non_problems_make_no_event() -> None:
    for classification in (
        Classification.NO_FAULT_DETECTED,
        Classification.INSUFFICIENT_DATA,
        Classification.PARTIALLY_MEASURED,
    ):
        assert diag_core.finding_event(_problem(R1, classification)) is None
    assert diag_core.finding_event(_problem(R1, severity=Severity.OK)) is None


def test_change_findings_have_own_types_and_no_values() -> None:
    gw = gateway_change(diag_core.point_for(R1), GW_OLD, GW_NEW)
    dns = dns_server_change(diag_core.point_for(R1), DNS_OLD, DNS_NEW)
    assert gw is not None and dns is not None
    gw_event = diag_core.finding_event(gw)
    dns_event = diag_core.finding_event(dns)
    assert gw_event is not None and dns_event is not None
    assert gw_event.event_type == diag_core.EVENT_GATEWAY_CHANGED
    assert dns_event.event_type == diag_core.EVENT_DNS_SERVER_CHANGED
    for event in (gw_event, dns_event):
        assert event.severity is CoreSeverity.INFO
        assert event.result is EventResult.INFO
        assert event.dedup_key is None  # every observed change is kept
        _assert_clean(event.data)
        _assert_clean(event.emit_kwargs())
    assert dns_event.data["previous_count"] == 1
    assert dns_event.data["current_count"] == 2


def test_correlation_id_is_checked() -> None:
    cor = diag_core.new_correlation_id()
    assert is_valid_id(cor, CORRELATION_ID_PREFIX)
    with pytest.raises(ValueError):
        diag_core.finding_event(_problem(R1), correlation_id="cor_nothex")
    with pytest.raises(ValueError):
        diag_core.correlation_events(correlate([], {}), correlation_id="x")


def test_cause_and_link_mapping() -> None:
    findings = [_problem(R1), _problem(None, Classification.DNS_PROBLEM)]
    result = correlate(findings, diag_core.dependencies_by_router({}))
    cor = diag_core.new_correlation_id()
    events = diag_core.correlation_events(result, correlation_id=cor)
    finding_events = [e for e in events if e.event_type == diag_core.EVENT_FINDING]
    cause_events = [e for e in events if e.event_type == diag_core.EVENT_CAUSE]
    assert len(finding_events) == 2 and len(cause_events) == 2
    assert all(e.correlation_id == cor for e in events)
    by_router = {e.router_id: e for e in cause_events}
    assert by_router[R1].data["location_kind"] == LocationKind.ROUTER.value
    assert by_router[R1].data["router_ids"] == [R1]
    assert by_router[None].data["location_kind"] == LocationKind.HA.value
    assert by_router[None].data["router_ids"] == []
    assert by_router[R1].data["link_count"] == 1
    assert by_router[R1].dedup_key == "router:local_finding:ipv4:probable"
    for event in finding_events:
        assert event.data["link_count"] == 1
        assert event.data["link_rules"] == ["local_finding"]
    for event in events:
        assert "cause_id" not in event.data


async def test_events_round_trip_through_the_audit_log(disks) -> None:
    hass = make_hass()
    log = await _log(hass)
    diag_core.register_event_prefix(log)
    event = diag_core.finding_event(_problem(R1), correlation_id=new_id("cor_"))
    assert event is not None
    first = log.emit(**event.emit_kwargs(), now=T0)
    again = log.emit(**event.emit_kwargs(), now=T0)
    assert first.published and again.deduplicated
    stored = log.events()[0]
    assert stored.type == diag_core.EVENT_FINDING
    assert stored.router_id == R1
    assert stored.severity is CoreSeverity.CRITICAL
    assert stored.correlation_id == event.correlation_id
    assert stored.to_dict()["data"] == dict(event.data)
    copy = CoreEvent.from_dict(stored.to_dict())
    assert copy.to_dict() == stored.to_dict()
    assert stored.audit_ring is AuditRing.GENERAL
    # the same finding at the HA point is a different scope
    ha_event = diag_core.finding_event(_problem(None))
    assert ha_event is not None
    assert log.emit(**ha_event.emit_kwargs(), now=T0).published
    assert len(bus_events(hass)) == 2


# --- masking -------------------------------------------------------------------


async def test_no_address_or_hostname_in_events_or_audit(disks) -> None:
    hass = make_hass()
    log = await _log(hass)
    diag_core.register_event_prefix(log)
    findings = [
        _problem(R1, chain=_leaky_chain(R1)),
        gateway_change(diag_core.point_for(R1), GW_OLD, GW_NEW),
        dns_server_change(diag_core.point_for(None), DNS_OLD, DNS_NEW),
    ]
    result = correlate(findings, {})
    events = diag_core.correlation_events(result)
    assert {e.event_type for e in events} >= {
        diag_core.EVENT_FINDING,
        diag_core.EVENT_GATEWAY_CHANGED,
        diag_core.EVENT_DNS_SERVER_CHANGED,
        diag_core.EVENT_CAUSE,
    }
    salt = b"0123456789abcdef"
    for event in events:
        _assert_clean(event.data)
        _assert_clean(diag_core.event_output(event, salt))
        log.emit(**event.emit_kwargs(), now=T0)
    _assert_clean([e.to_dict() for e in log.events(limit=100)])
    _assert_clean(bus_events(hass))


def test_outputs_mask_change_values_and_raw_evidence() -> None:
    finding = _problem(R1, chain=_leaky_chain(R1))
    change = gateway_change(diag_core.point_for(R1), GW_OLD, GW_NEW)
    assert change is not None
    for item in (finding, change):
        out = diag_core.finding_output(item, admin=True)
        _assert_clean(out)
    assert diag_core.finding_output(change, admin=True)["change"] == MASK
    detail = diag_core.finding_output(finding, admin=True)
    assert detail["chain"]["excluded"] == MASK
    probe = finding.chain.excluded[0]  # type: ignore[union-attr]
    probe_out = diag_core.probe_output(probe)
    assert probe_out["evidence"] == MASK
    assert probe_out["target_id"] == "gw-probe"
    _assert_clean(probe_out)
    result = correlate([finding, change], {})
    _assert_clean(diag_core.correlation_output(result, admin=True))
    _assert_clean(diag_core.log_safe({"finding": finding.to_dict()}))


def test_outputs_keep_i18n_keys_readable() -> None:
    """Core masking treats ``*_key`` names as secret; the adapter renames them."""
    out = diag_core.finding_output(_problem(R1), admin=True)
    assert out["summary"] == "wan_problem"
    assert out["recommendation"] == "check_wan_problem"
    assert out["router_id"] == R1
    assert "summary_key" not in out and "router_key" not in out
    result = correlate([_problem(R1)], {})
    cause_out = diag_core.correlation_output(result, admin=True)["causes"][0]
    assert cause_out["router_ids"] == [R1]
    assert cause_out["summary"] == "wan_problem"


def test_sensitive_reads_need_an_admin() -> None:
    finding = _problem(R1, chain=_leaky_chain(R1))
    brief = diag_core.finding_output(finding, admin=False)
    assert "chain" not in brief and "evidence" not in brief
    assert "change" not in brief and "reasons" not in brief
    assert brief["classification"] == "wan_problem"
    assert brief["router_id"] == R1
    brief_result = diag_core.correlation_output(correlate([finding], {}), admin=False)
    assert all("evidence" not in c for c in brief_result["causes"])
    assert set(diag_core.SENSITIVE_READS) >= {"chain", "evidence", "probe"}


async def test_sensitive_reads_follow_the_verified_admin_flag(disks) -> None:
    hass = make_hass()
    add_users(hass)
    guard = ActionGuard(hass, await _log(hass))
    admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
    plain = await guard.async_verify_actor(user_actor(USER_ID, claims_admin=True))
    module = await guard.async_verify_actor(Actor.for_module(diag_core.MODULE))
    assert diag_core.may_read_sensitive(admin)
    assert not diag_core.may_read_sensitive(plain)
    # like the core's content reads: non-user actors read without admin rights
    assert diag_core.may_read_sensitive(module)
    assert not diag_core.may_read_sensitive(admin, now=T0.replace(year=2099))
    assert not diag_core.may_read_sensitive(None)
    assert not diag_core.may_read_sensitive(user_actor(ADMIN_ID, claims_admin=True))


async def test_no_raw_user_id_in_audit_payloads(disks) -> None:
    hass = make_hass()
    add_users(hass)
    log = await _log(hass)
    diag_core.register_event_prefix(log)
    guard = ActionGuard(hass, log)
    verified = await guard.async_verify_actor(user_actor(ADMIN_ID))
    event = diag_core.manual_run_event(
        R1,
        actor=verified.actor,
        status=RequestStatus.ACCEPTED,
        kinds=[diag_core.KIND_HA_TCP],
    )
    assert event.actor is not None and event.actor.user_id == ADMIN_ID
    assert ADMIN_ID not in _dump(event.data)
    salt = b"fedcba9876543210"
    out = diag_core.event_output(event, salt)
    assert ADMIN_ID not in _dump(out)
    assert out["actor"]["user_id"].startswith(ACTOR_PSEUDONYM_PREFIX)
    assert ADMIN_ID not in _dump(diag_core.actor_output(verified.actor, salt))
    log.emit(**event.emit_kwargs(), now=T0)
    (payload,) = bus_events(hass, diag_core.EVENT_MANUAL_RUN)
    assert ADMIN_ID not in _dump(payload)
    stored = log.events(types=[diag_core.EVENT_MANUAL_RUN])[0]
    assert ADMIN_ID not in _dump(dict(stored.data))


async def test_manual_runs_are_all_audited(disks) -> None:
    log = await _log()
    diag_core.register_event_prefix(log)
    actor = user_actor(ADMIN_ID)
    accepted = diag_core.manual_run_event(
        R1, actor=actor, status=RequestStatus.ACCEPTED, kinds=["diag.probe.ha_dns"]
    )
    refused = diag_core.manual_run_event(
        R1,
        actor=actor,
        status=RequestStatus.REFUSED_RATE_LIMIT,
        kinds=["diag.probe.ha_dns"],
    )
    denied = diag_core.manual_run_event(
        None, actor=actor, status="denied", kinds=["diag.probe.ha_tcp"]
    )
    assert accepted.result is EventResult.SUCCESS
    assert refused.result is EventResult.DENIED
    assert denied.result is EventResult.DENIED and denied.router_id is None
    for event in (accepted, accepted, refused, denied):
        assert event.dedup_key is None
        assert log.emit(**event.emit_kwargs(), now=T0).published
    assert len(log.events(types=[diag_core.EVENT_MANUAL_RUN])) == 4
    with pytest.raises(ValueError):
        diag_core.manual_run_event(R1, actor=actor, status="accepted", kinds=["x"])
    with pytest.raises(ValueError):
        diag_core.manual_run_event(R1, actor=actor, status="accepted", kinds=[])


def test_router_probe_change_event() -> None:
    actor = user_actor(ADMIN_ID)
    event = diag_core.router_probes_event(
        R1,
        actor=actor,
        kinds=[diag_core.KIND_EXEC_TRACEROUTE, diag_core.KIND_EXEC_PING],
        result=EventResult.SUCCESS,
    )
    assert event.event_type == diag_core.EVENT_ROUTER_PROBES_CHANGED
    assert event.severity is CoreSeverity.WARNING
    assert event.dedup_key is None
    assert event.data["enabled_kinds"] == ["diag.exec.ping", "diag.exec.traceroute"]
    with pytest.raises(ValueError):
        diag_core.router_probes_event(
            R1, actor=actor, kinds=["diag.probe.ha_tcp"], result=EventResult.SUCCESS
        )
    with pytest.raises(ValueError):
        diag_core.router_probes_event(
            None, actor=actor, kinds=[], result=EventResult.SUCCESS
        )


# --- capabilities --------------------------------------------------------------


def test_capability_names() -> None:
    assert diag_core.DATA_KINDS == (
        "diag.data.interface_dump",
        "diag.data.odhcpd",
        "diag.data.dnsmasq_metrics",
        "diag.data.dhcp_config",
    )
    assert diag_core.HA_PROBE_KINDS == (
        "diag.probe.ha_tcp",
        "diag.probe.ha_dns",
        "diag.probe.ha_http",
    )
    assert diag_core.EXEC_KINDS == (
        "diag.exec.ping",
        "diag.exec.nslookup",
        "diag.exec.traceroute",
    )
    for name in diag_core.ALL_KINDS:
        assert name.startswith(diag_core.CAPABILITY_PREFIX)
        assert name not in CORE_OWNED_MODULE_CAPABILITIES


def test_full_router_capabilities() -> None:
    caps = diag_core.detect_capabilities(FULL_FACTS, transport=UBUS_OK, now=T0)
    assert set(caps) == set(diag_core.DATA_KINDS) | set(diag_core.EXEC_KINDS)
    for name, status in caps.items():
        assert status.capability == name
        assert status.state is CapabilityState.AVAILABLE, name
        assert status.detected_at == T0
    odhcpd = caps[diag_core.KIND_DATA_ODHCPD]
    assert dict(odhcpd.detail) == {"ipv6leases": True, "ipv6ra": True}


def test_relay_ap_without_dnsmasq() -> None:
    caps = diag_core.detect_capabilities(RELAY_FACTS, transport=UBUS_OK, now=T0)
    dnsmasq = caps[diag_core.KIND_DATA_DNSMASQ]
    assert dnsmasq.state is CapabilityState.UNAVAILABLE
    assert dnsmasq.reason == CapabilityReason.NOT_DETECTED
    assert caps[diag_core.KIND_DATA_ODHCPD].available
    assert caps[diag_core.KIND_EXEC_TRACEROUTE].state is CapabilityState.UNAVAILABLE
    kinds = diag_core.available_kinds(caps, RELAY_FACTS)
    assert diag_core.KIND_DATA_DNSMASQ not in kinds
    assert diag_core.KIND_DATA_INTERFACE_DUMP in kinds
    assert set(diag_core.HA_PROBE_KINDS) <= kinds
    assert not kinds & set(diag_core.EXEC_KINDS)


def test_odhcpd_needs_ipv6_methods_never_ipv4leases() -> None:
    only_v4 = diag_core.DiagRouterFacts(odhcpd_methods=frozenset({"ipv4leases"}))
    caps = diag_core.detect_capabilities(only_v4, transport=UBUS_OK, now=T0)
    status = caps[diag_core.KIND_DATA_ODHCPD]
    assert status.state is CapabilityState.UNAVAILABLE
    assert "ipv4leases" not in dict(status.detail)
    leases = diag_core.DiagRouterFacts(odhcpd_methods=frozenset({"ipv6leases"}))
    status = diag_core.detect_capabilities(leases, transport=UBUS_OK, now=T0)[
        diag_core.KIND_DATA_ODHCPD
    ]
    assert status.available
    assert dict(status.detail) == {"ipv6leases": True, "ipv6ra": False}


def test_exec_kinds_are_off_by_default() -> None:
    caps = diag_core.detect_capabilities(FULL_FACTS, transport=UBUS_OK, now=T0)
    reasons = diag_core.kind_availability(caps, FULL_FACTS)
    for kind in diag_core.EXEC_KINDS:
        assert reasons[kind] == diag_core.REASON_NOT_ENABLED
    assert not diag_core.available_kinds(caps, FULL_FACTS) & set(diag_core.EXEC_KINDS)
    assert diag_core.DiagSettings().enabled_exec == frozenset()


def test_exec_needs_enable_capability_and_free_memory() -> None:
    caps = diag_core.detect_capabilities(FULL_FACTS, transport=UBUS_OK, now=T0)
    on = diag_core.DiagSettings(enabled_exec=frozenset(diag_core.EXEC_KINDS))
    kinds = diag_core.available_kinds(caps, FULL_FACTS, on)
    assert set(diag_core.EXEC_KINDS) <= kinds
    # enabled, but the tool is missing on the router
    relay_caps = diag_core.detect_capabilities(RELAY_FACTS, transport=UBUS_OK, now=T0)
    reasons = diag_core.kind_availability(relay_caps, RELAY_FACTS, on)
    assert reasons[diag_core.KIND_EXEC_TRACEROUTE] == (
        diag_core.REASON_CAPABILITY_UNAVAILABLE
    )
    assert reasons[diag_core.KIND_EXEC_PING] == diag_core.REASON_OK
    # enabled and present, but too little free memory, or none known
    low = replace(FULL_FACTS, mem_available_kb=on.exec_min_free_kb - 1)
    unknown = replace(FULL_FACTS, mem_available_kb=None)
    assert diag_core.kind_availability(caps, low, on)[diag_core.KIND_EXEC_PING] == (
        diag_core.REASON_MEMORY_LOW
    )
    assert diag_core.kind_availability(caps, unknown, on)[diag_core.KIND_EXEC_PING] == (
        diag_core.REASON_MEMORY_UNKNOWN
    )
    # an exec name that is no exec kind cannot be enabled
    with pytest.raises(ValueError):
        diag_core.DiagSettings(enabled_exec=frozenset({"diag.data.odhcpd"}))


def test_exec_refused_without_rpcd_exec_permission() -> None:
    facts = replace(FULL_FACTS, exec_permitted=False)
    caps = diag_core.detect_capabilities(facts, transport=UBUS_OK, now=T0)
    for kind in diag_core.EXEC_KINDS:
        assert caps[kind].state is CapabilityState.UNAVAILABLE
        assert caps[kind].reason == CapabilityReason.PERMISSION_DENIED


def test_capabilities_without_transport_or_facts() -> None:
    down = _status(Capability.TRANSPORT_UBUS, CapabilityState.UNAVAILABLE)
    caps = diag_core.detect_capabilities(FULL_FACTS, transport=down, now=T0)
    assert all(
        s.reason == CapabilityReason.TRANSPORT_UNSUPPORTED for s in caps.values()
    )
    assert all(s.state is CapabilityState.UNAVAILABLE for s in caps.values())
    unknown = diag_core.detect_capabilities(None, transport=UBUS_OK, now=T0)
    assert all(s.state is CapabilityState.UNKNOWN for s in unknown.values())
    assert all(s.reason == CapabilityReason.NO_DATA_YET for s in unknown.values())
    not_checked = diag_core.detect_capabilities(
        diag_core.DiagRouterFacts(), transport=UBUS_OK, now=T0
    )
    assert all(s.reason == CapabilityReason.NOT_CHECKED for s in not_checked.values())
    reasons = diag_core.kind_availability({}, None)
    assert reasons[diag_core.KIND_DATA_ODHCPD] == diag_core.REASON_CAPABILITY_UNKNOWN


def test_ha_probes_follow_their_setting() -> None:
    kinds = diag_core.available_kinds({}, None)
    assert kinds == frozenset(diag_core.HA_PROBE_KINDS)
    off = diag_core.DiagSettings(ha_probes=False)
    reasons = diag_core.kind_availability({}, None, off)
    assert {reasons[k] for k in diag_core.HA_PROBE_KINDS} == {diag_core.REASON_DISABLED}


def test_detector_ignores_device_type_and_version() -> None:
    detector = diag_core.make_detector(lambda data: data, clock=lambda: T0)
    a = detector(_record(R1, model="Relay-ish AP", version="21.02.0"), FULL_FACTS)
    b = detector(_record(R2, model="Big Gateway", version="25.12.0"), FULL_FACTS)
    assert {k: v.to_dict() for k, v in a.items()} == {
        k: v.to_dict() for k, v in b.items()
    }
    relay = detector(_record(R1, model="Big Gateway", version="25.12.0"), RELAY_FACTS)
    assert not relay[diag_core.KIND_DATA_DNSMASQ].available
    no_transport = RouterRecord(
        identity=RouterIdentity(router_id=R1, entry_id="entry-x"), capabilities={}
    )
    assert all(
        s.reason == CapabilityReason.NO_DATA_YET
        for s in detector(no_transport, FULL_FACTS).values()
    )
    signature = diag_core.make_signature(lambda data: data)
    assert signature(FULL_FACTS) == signature(FULL_FACTS)
    assert signature(FULL_FACTS) != signature(RELAY_FACTS)
    # memory is a run-time precondition, not a capability: it never re-runs it
    other_mem = replace(FULL_FACTS, mem_available_kb=1)
    assert signature(other_mem) == signature(FULL_FACTS)


# --- guard ---------------------------------------------------------------------


def test_guard_declarations() -> None:
    run = diag_core.ACTION_RUN_MANUAL
    enable = diag_core.ACTION_ENABLE_ROUTER_PROBES
    assert run.name == "net_diagnostics.run_manual"
    assert run.agreed_name == "diag.run_manual"
    assert run.action_class is ActionClass.READ and run.admin_user_only
    assert enable.name == "net_diagnostics.enable_router_probes"
    assert enable.agreed_name == "diag.enable_router_probes"
    assert enable.action_class is ActionClass.CRITICAL and enable.admin_user_only
    assert diag_core.DIAG_ACTIONS == (run, enable)


async def test_actions_register_only_on_request(disks) -> None:
    hass = make_hass()
    add_users(hass)
    guard = ActionGuard(hass, await _log(hass))
    assert guard.action_class(diag_core.ACTION_RUN_MANUAL.name) is None
    names = diag_core.register_actions(guard)
    assert names == (
        "net_diagnostics.run_manual",
        "net_diagnostics.enable_router_probes",
    )
    assert diag_core.register_actions(guard) == names  # idempotent
    assert guard.action_class(names[0]) is ActionClass.READ
    with pytest.raises(ValueError):  # the agreed name breaks <module>.<action>
        guard.register_action(
            "diag.run_manual", ActionClass.READ, module=diag_core.MODULE
        )


async def test_run_manual_is_for_verified_admin_users_only(disks) -> None:
    hass = make_hass()
    add_users(hass)
    guard = ActionGuard(hass, await _log(hass))
    diag_core.register_actions(guard)
    name = diag_core.ACTION_RUN_MANUAL.name
    admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
    plain = await guard.async_verify_actor(user_actor(USER_ID, claims_admin=True))
    module = await guard.async_verify_actor(Actor.for_module(diag_core.MODULE))
    automation = await guard.async_verify_actor(
        Actor(kind=ActorKind.AUTOMATION, parent_context_id="ctx-invented")
    )
    system = await guard.async_verify_actor(Actor.system())
    assert guard.authorize(name, R1, admin).state is DecisionState.APPROVED
    for actor in (plain, module, automation, system):
        decision = guard.authorize(name, R1, actor)
        assert decision.state is DecisionState.DENIED
        assert decision.reason == "not_admin"


async def test_enable_router_probes_needs_an_approval(disks) -> None:
    hass = make_hass()
    add_users(hass)
    guard = ActionGuard(hass, await _log(hass))
    diag_core.register_actions(guard)
    name = diag_core.ACTION_ENABLE_ROUTER_PROBES.name
    checksum = diag_core.enable_probes_checksum(R1, [diag_core.KIND_EXEC_PING])
    admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
    module = await guard.async_verify_actor(Actor.for_module(diag_core.MODULE))
    pending = guard.authorize(name, R1, admin, checksum=checksum)
    assert pending.state is DecisionState.PENDING
    assert guard.authorize(name, R1, module, checksum=checksum).reason == "not_admin"


def test_enable_probes_checksum_binds_router_and_kinds() -> None:
    one = diag_core.enable_probes_checksum(R1, ["diag.exec.ping", "diag.exec.nslookup"])
    same = diag_core.enable_probes_checksum(
        R1, ["diag.exec.nslookup", "diag.exec.ping"]
    )
    assert one == same
    assert one != diag_core.enable_probes_checksum(R2, ["diag.exec.ping"])
    assert one != diag_core.enable_probes_checksum(R1, ["diag.exec.ping"])
    with pytest.raises(ValueError):
        diag_core.enable_probes_checksum(R1, ["diag.probe.ha_tcp"])
    with pytest.raises(ValueError):
        diag_core.enable_probes_checksum("ha", ["diag.exec.ping"])


def test_register_with_core_wires_all_three_hooks() -> None:
    calls: list[tuple[str, Any]] = []

    class FakeGuard:
        def register_action(self, name, action_class, *, module, admin_user_only):
            calls.append(("action", (name, action_class, module, admin_user_only)))

    class FakeApi:
        guard = FakeGuard()

        def register_event_prefix(self, prefix, *, module):
            calls.append(("prefix", (prefix, module)))

        def register_capability_detector(self, module, detector, *, prefix, signature):
            calls.append(("detector", (module, prefix, callable(signature))))
            return lambda: calls.append(("removed", module))

    remove = diag_core.register_with_core(FakeApi(), lambda data: None)
    kinds = [kind for kind, _ in calls]
    assert kinds == ["prefix", "action", "action", "detector"]
    assert calls[0][1] == ("net_diagnostics.", "net_diagnostics")
    assert calls[-1][1] == ("net_diagnostics", "diag.", True)
    remove()
    assert calls[-1] == ("removed", "net_diagnostics")


# --- router.forgotten ------------------------------------------------------------


async def _noop() -> None:
    return None


def test_forget_plan_drops_only_that_router() -> None:
    k1 = diag_core.series_key(R1, "gw-probe", "icmp", "ipv4")
    k1b = diag_core.series_key(R1, "dns-probe", "dns", "ipv6")
    k2 = diag_core.series_key(R2, "gw-probe", "icmp", "ipv4")
    kha = diag_core.series_key(None, "gw-probe", "icmp", "ipv4")
    baselines = [
        new_baseline(k1, LATENCY_CONFIG),
        new_baseline(k1, LOSS_CONFIG),
        new_baseline(k2, LATENCY_CONFIG),
        new_baseline(kha, LATENCY_CONFIG),
    ]
    jobs = [
        DiagJob("r1-gw", "icmp", _noop, router_key=diag_core.scheduler_key(R1)),
        DiagJob("r2-gw", "icmp", _noop, router_key=diag_core.scheduler_key(R2)),
        DiagJob("ha-gw", "tcp", _noop, router_key=diag_core.scheduler_key(None)),
    ]
    plan = diag_core.forget_plan(
        R1, series_keys=[k1, k1b, k2, kha], baselines=baselines, jobs=jobs
    )
    assert plan.router_id == R1
    assert plan.scheduler_key == R1
    assert plan.series_keys == frozenset({k1, k1b})
    assert plan.baselines == frozenset({(k1, "latency_ms"), (k1, "loss_pct")})
    assert plan.job_ids == frozenset({"r1-gw"})
    assert not plan.is_empty
    empty = diag_core.forget_plan(R2)
    assert empty.is_empty and empty.scheduler_key == R2
    with pytest.raises(ValueError):
        diag_core.forget_plan("ha", series_keys=[kha])


def test_forgotten_router_id_from_core_event() -> None:
    forgotten = CoreEvent(
        event_id=new_id("evt_"),
        ts=T0,
        type=CoreEventType.ROUTER_FORGOTTEN,
        source="core",
        router_id=R1,
        data={"reason": "aged"},
    )
    assert diag_core.forgotten_router_id(forgotten) == R1
    assert diag_core.forgotten_router_id(forgotten.to_dict()) == R1
    other = CoreEvent(
        event_id=new_id("evt_"),
        ts=T0,
        type=CoreEventType.ROUTER_REGISTERED,
        source="core",
        router_id=R1,
    )
    assert diag_core.forgotten_router_id(other) is None
    broken = {"type": CoreEventType.ROUTER_FORGOTTEN.value, "router_id": "ha"}
    assert diag_core.forgotten_router_id(broken) is None
    assert diag_core.forgotten_router_id("router.forgotten") is None


# --- diag module clean-up --------------------------------------------------------


def test_diag_targets_debug_logs_never_echo_raw_input(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Hosts and addresses stay out of every log level (core logging rule)."""
    import socket

    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("network I/O attempted")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    caplog.set_level(
        logging.DEBUG, logger="custom_components.openwrt_router.diag_targets"
    )
    secret = "198.51.100.77"
    assert isinstance(
        make_target("t1", "icmp", "external", f"http://{secret}/"), Refusal
    )

    pol = ScopePolicy.from_config(["192.168.1.0/24"], local_domains=[])
    reg = TargetRegistry(pol)
    reg.resolve("../" + secret)
    made = make_target("p", "icmp", "external", "probe.example.com", confirmed=True)
    reg2 = reg.with_target(made)  # type: ignore[arg-type]
    assert isinstance(reg2, TargetRegistry)
    issued = reg2.resolve("p")
    assert isinstance(issued, PendingTarget)
    check_resolved(issued, ["192.168.1.9"], pol)
    assert caplog.records, "the refusals above log at debug level"
    for record in caplog.records:
        assert secret not in record.getMessage()
        assert "192.168.1.9" not in record.getMessage()
        assert "probe.example.com" not in record.getMessage()
