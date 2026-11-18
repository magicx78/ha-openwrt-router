"""RF events built as Core events (rf_events.py); nothing is sent."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from core_testkit import FakeDisks, bus_events, make_hass

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_masking import mask_for_output
from custom_components.openwrt_router.core_models import (
    EVENT_ID_PREFIX,
    MODULE_EVENT_PREFIXES,
    Actor,
    ActorKind,
    AuditRing,
    CoreEvent,
    CoreEventType,
    EventResult,
    Severity,
    default_router_id,
    is_core_event_type,
    is_valid_id,
)
from custom_components.openwrt_router.rf_conflicts import (
    ConflictKind,
    RadioRef,
    RadioView,
    detect_conflicts,
)
from custom_components.openwrt_router.rf_events import (
    ALL_EVENT_TYPES,
    EVENT_CHANNEL_CONFLICT,
    EVENT_PREFIX,
    EVENT_RECOMMENDATION_NEW,
    EVENT_RECOMMENDATION_RESOLVED,
    EVENT_SCAN_EXECUTED,
    EVENT_SCAN_REFUSED,
    EVENT_SCAN_REQUESTED,
    EVENT_UTILIZATION_HIGH,
    RF_MODULE,
    channel_conflict_event,
    channel_utilization_event,
    emit_kwargs,
    forget_router,
    forgotten_router_id,
    recommendation_events,
    recommendation_key,
    scan_executed_event,
    scan_refused_event,
    scan_requested_event,
)
from custom_components.openwrt_router.rf_models import (
    SOURCE_HOSTAPD_STATUS,
    metric_measured,
)
from custom_components.openwrt_router.rf_recommend import Recommendation
from custom_components.openwrt_router.rf_scan_policy import ScanDecision, ScanReason
from custom_components.openwrt_router.rf_utilization import (
    OverloadPhase,
    UtilizationSummary,
)

R1 = default_router_id("e1")
R2 = default_router_id("e2")
T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
MAC = "aa:bb:cc:dd:ee:01"
USER = "8f1c2e9a0b7d4c3e9f1a2b3c4d5e6f70"  # looks like an HA user id
ADMIN = Actor(kind=ActorKind.USER, user_id=USER, is_admin=True)


def _view(router, radio="radio0", util=None, channel=6):
    return RadioView(
        router_key=router,
        radio_key=radio,
        band="2.4g",
        channel=channel,
        width_mhz=20,
        utilization=None
        if util is None
        else metric_measured(util, SOURCE_HOSTAPD_STATUS, measured_at=1.0),
    )


def _conflict(util=78.0, same_router=False):
    other = _view(R1, "radio1") if same_router else _view(R2)
    (conflict,) = detect_conflicts([_view(R1, util=util), other])
    return conflict


def _summary(sustained=True):
    return UtilizationSummary(
        current=82.0,
        mean=76.5,
        peak=91.0,
        valid_count=12,
        invalid_count=1,
        coverage=0.92,
        phases=(OverloadPhase(start=0.0, end=600.0, peak=91.0, points=6),),
        sustained_overload=sustained,
    )


def _rec(target=None, kind="channel", action="change_channel", **kw):
    base = {
        "kind": kind,
        "target": RadioRef(R1, "radio0") if target is None else target,
        "problem": "co_channel",
        "evidence": (f"client:{MAC}",),
        "action": action,
        "action_params": {"channel": 1},
        "expected_effect": "less_contention",
        "confidence": 0.6,
        "risk": ("clients_reconnect_on_change",),
    }
    base.update(kw)
    return Recommendation(**base)


def _all_events():
    rec = _rec()
    return [
        channel_conflict_event(_conflict(), now=T0),
        channel_utilization_event(RadioRef(R1, "radio0"), _summary(), now=T0),
        *recommendation_events([], [rec], now=T0),
        *recommendation_events([rec], [], now=T0),
        scan_requested_event(R1, "radio0", actor=ADMIN, now=T0),
        scan_refused_event(
            R1,
            "radio0",
            ScanDecision(False, ScanReason.UPLINK_RADIO),
            actor=ADMIN,
            now=T0,
        ),
        scan_executed_event(
            R1, "radio0", actor=ADMIN, now=T0, neighbor_count=7, own_count=2
        ),
    ]


class TestNaming:
    def test_prefix_is_the_core_assigned_module_prefix(self):
        assert MODULE_EVENT_PREFIXES[RF_MODULE] == EVENT_PREFIX == "wifi_rf."

    def test_all_types_are_below_the_prefix_and_not_core_types(self):
        assert len(ALL_EVENT_TYPES) == 7
        for event_type in ALL_EVENT_TYPES:
            assert event_type.startswith(EVENT_PREFIX)
            assert not is_core_event_type(event_type)
            assert event_type == event_type.lower()
            assert event_type.count(".") == 1

    def test_module_events_land_in_the_general_ring(self):
        for event in _all_events():
            assert event.audit_ring is AuditRing.GENERAL


class TestEveryEvent:
    def test_shape(self):
        for event in _all_events():
            assert isinstance(event, CoreEvent)
            assert event.type in ALL_EVENT_TYPES
            assert event.source == RF_MODULE
            assert event.ts == T0
            assert is_valid_id(event.event_id, EVENT_ID_PREFIX)
            assert event.router_id is None or is_valid_id(event.router_id, "rtr_")

    def test_data_is_unchanged_by_core_masking(self):
        # The core masks data again on emit; RF data must survive that intact.
        for event in _all_events():
            data = _plain(event.data)
            assert mask_for_output(data) == data, event.type

    def test_no_user_id_mac_or_ssid_in_data(self):
        for event in _all_events():
            text = repr(_plain(dict(event.data)))
            assert USER not in text
            assert "user_id" not in text
            assert MAC not in text
            assert "ssid" not in text

    def test_actor_is_the_core_actor_record(self):
        for event in _all_events():
            if event.type.startswith("wifi_rf.scan_"):
                assert event.actor == ADMIN
            else:
                assert event.actor is None


def _plain(value):
    """Thaw the read-only event data into dicts and lists."""
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(v) for v in value]
    return value


class TestConflictEvent:
    def test_measured_conflict(self):
        event = channel_conflict_event(_conflict(), now=T0)
        assert event.type == EVENT_CHANNEL_CONFLICT
        assert event.severity is Severity.WARNING
        assert event.router_id is None  # spans two routers
        data = _plain(dict(event.data))
        assert data["kind"] == ConflictKind.CO_CHANNEL
        assert data["status"] == "measured"
        assert data["members"] == sorted(
            [
                {"router_id": R1, "radio": "radio0"},
                {"router_id": R2, "radio": "radio0"},
            ],
            key=lambda m: (m["router_id"], m["radio"]),
        )
        assert "utilization" in data["evidence_codes"]
        assert event.dedup_key

    def test_one_router_conflict_names_the_router(self):
        event = channel_conflict_event(_conflict(same_router=True), now=T0)
        assert event.router_id == R1

    def test_only_measured_conflicts_make_an_event(self):
        assert channel_conflict_event(_conflict(util=None), now=T0) is None

    def test_dedup_key_is_stable_and_member_bound(self):
        a = channel_conflict_event(_conflict(), now=T0)
        b = channel_conflict_event(_conflict(), now=T0)
        c = channel_conflict_event(_conflict(same_router=True), now=T0)
        assert a.dedup_key == b.dedup_key != c.dedup_key
        assert a.event_id != b.event_id


class TestUtilizationEvent:
    def test_sustained_overload(self):
        event = channel_utilization_event(RadioRef(R1, "radio0"), _summary(), now=T0)
        assert event.type == EVENT_UTILIZATION_HIGH
        assert event.router_id == R1
        assert event.severity is Severity.WARNING
        data = _plain(dict(event.data))
        assert data == {
            "radio": "radio0",
            "current_pct": 82.0,
            "mean_pct": 76.5,
            "peak_pct": 91.0,
            "phase_count": 1,
            "valid_count": 12,
            "coverage": 0.92,
        }

    @pytest.mark.parametrize("sustained", [False, None])
    def test_no_event_without_sustained_overload(self, sustained):
        summary = _summary(sustained)
        assert (
            channel_utilization_event(RadioRef(R1, "radio0"), summary, now=T0) is None
        )

    def test_router_must_be_a_core_id(self):
        with pytest.raises(ValueError):
            channel_utilization_event(RadioRef("e1", "radio0"), _summary(), now=T0)


class TestRecommendationEvents:
    def test_new_and_resolved(self):
        keep, gone, new = _rec(), _rec(action="reduce_width"), _rec(kind="tx_power")
        events = recommendation_events([keep, gone], [keep, new], now=T0)
        assert [(e.type, e.dedup_key) for e in events] == [
            (EVENT_RECOMMENDATION_NEW, recommendation_key(new)),
            (EVENT_RECOMMENDATION_RESOLVED, recommendation_key(gone)),
        ]
        assert all(e.router_id == R1 for e in events)

    def test_changed_parameters_are_the_same_recommendation(self):
        a = _rec(action_params={"channel": 1})
        b = _rec(action_params={"channel": 11}, confidence=0.9)
        assert recommendation_key(a) == recommendation_key(b)
        assert recommendation_events([a], [b], now=T0) == []

    def test_data_carries_codes_not_parameters(self):
        (event,) = recommendation_events([], [_rec()], now=T0)
        data = _plain(dict(event.data))
        assert data == {
            "kind": "channel",
            "problem": "co_channel",
            "action": "change_channel",
            "scope": "radio",
            "target": {"router_id": R1, "radio": "radio0"},
            "priority": "normal",
            "confidence": 0.6,
            "risk": ["clients_reconnect_on_change"],
        }

    def test_router_and_network_targets(self):
        (router,) = recommendation_events([], [_rec(target=R2)], now=T0)
        assert router.router_id == R2
        assert _plain(dict(router.data))["target"] == {"router_id": R2}
        (network,) = recommendation_events([], [replace(_rec(), target=None)], now=T0)
        assert network.router_id is None
        assert _plain(dict(network.data))["target"] is None

    def test_key_has_no_identifier_beyond_router_and_radio(self):
        key = recommendation_key(_rec())
        assert MAC not in key


class TestScanEvents:
    def test_requested(self):
        event = scan_requested_event(
            R1, "radio0", actor=ADMIN, now=T0, correlation_id="cor_" + "1" * 32
        )
        assert event.type == EVENT_SCAN_REQUESTED
        assert event.result is EventResult.PENDING
        assert event.router_id == R1
        assert event.correlation_id == "cor_" + "1" * 32
        assert _plain(dict(event.data)) == {
            "radio": "radio0",
            "action": "wifi_rf.scan",
        }

    @pytest.mark.parametrize("reason", [r for r in ScanReason if r.value != "allowed"])
    def test_refused_carries_the_scan_reason(self, reason):
        decision = ScanDecision(False, reason, 30.0 if "rate" in reason else None)
        event = scan_refused_event(R1, "radio0", decision, actor=ADMIN, now=T0)
        assert event.type == EVENT_SCAN_REFUSED
        assert event.result is EventResult.DENIED
        data = _plain(dict(event.data))
        assert data["reason"] == reason.value
        assert data["retry_after_s"] == decision.retry_after_s

    def test_an_allowed_decision_is_no_refusal(self):
        with pytest.raises(ValueError):
            scan_refused_event(
                R1,
                "radio0",
                ScanDecision(True, ScanReason.ALLOWED),
                actor=ADMIN,
                now=T0,
            )

    def test_executed_counts_only(self):
        event = scan_executed_event(
            R1, "radio0", actor=ADMIN, now=T0, neighbor_count=7, own_count=2
        )
        assert event.type == EVENT_SCAN_EXECUTED
        assert event.result is EventResult.SUCCESS
        assert _plain(dict(event.data)) == {
            "radio": "radio0",
            "action": "wifi_rf.scan",
            "neighbor_count": 7,
            "own_count": 2,
        }

    def test_only_core_actors_are_accepted(self):
        class FakeVerified:
            actor = ADMIN

        # Anything that is not a Core Actor is refused: no ad-hoc user ids.
        with pytest.raises(TypeError):
            scan_requested_event(R1, "radio0", actor=FakeVerified(), now=T0)
        with pytest.raises(TypeError):
            scan_requested_event(R1, "radio0", actor=USER, now=T0)

    def test_router_must_be_a_core_id(self):
        with pytest.raises(ValueError):
            scan_requested_event("e1", "radio0", actor=ADMIN, now=T0)

    def test_naive_time_is_refused(self):
        with pytest.raises(ValueError):
            scan_requested_event(R1, "radio0", actor=ADMIN, now=datetime(2026, 1, 1))


class TestEmitThroughTheCore:
    @pytest.fixture
    def disks(self):
        with FakeDisks().patch() as fake:
            yield fake

    async def test_core_audit_accepts_every_rf_event(self, disks):
        hass = make_hass()
        log = AuditLog(hass)
        await log.async_load()
        log.register_event_prefix(EVENT_PREFIX, module=RF_MODULE)
        for event in _all_events():
            result = log.emit(**emit_kwargs(event))
            assert result.event.type == event.type
            assert _plain(dict(result.event.data)) == _plain(dict(event.data))
        assert len(log.events(ring=AuditRing.GENERAL)) == len(_all_events())
        # On the bus the core replaces the user id by a pseudonym.
        payloads = bus_events(hass)
        assert payloads
        assert USER not in repr(payloads)


class TestForgetRouter:
    def test_drops_every_state_of_the_router(self):
        state = {
            R1: 1,
            R2: 2,
            RadioRef(R1, "radio0"): 3,
            RadioRef(R2, "radio0"): 4,
            (R1, "radio1"): 5,
            (RadioRef(R1, "radio0"), "x"): 6,
            (RadioRef(R2, "radio1"), MAC): 7,
        }
        assert forget_router(state, R1) == {
            R2: 2,
            RadioRef(R2, "radio0"): 4,
            (RadioRef(R2, "radio1"), MAC): 7,
        }
        assert R1 in state  # input untouched

    def test_validates_the_router_id(self):
        with pytest.raises(ValueError):
            forget_router({}, "e1")

    def test_reacts_to_the_core_router_forgotten_event(self):
        event = CoreEvent(
            event_id="evt_" + "a" * 32,
            ts=T0,
            type=CoreEventType.ROUTER_FORGOTTEN,
            source="core",
            router_id=R1,
            data={"reason": "aged"},
        )
        assert forgotten_router_id(event) == R1
        state = {RadioRef(R1, "radio0"): 1, RadioRef(R2, "radio0"): 2}
        assert forget_router(state, forgotten_router_id(event)) == {
            RadioRef(R2, "radio0"): 2
        }

    def test_other_events_forget_nothing(self):
        other = CoreEvent(
            event_id="evt_" + "b" * 32,
            ts=T0,
            type=CoreEventType.ROUTER_ORPHANED,
            source="core",
            router_id=R1,
        )
        assert forgotten_router_id(other) is None
        broken = CoreEvent(
            event_id="evt_" + "c" * 32,
            ts=T0,
            type=CoreEventType.ROUTER_FORGOTTEN,
            source="core",
            router_id=None,
        )
        assert forgotten_router_id(broken) is None
