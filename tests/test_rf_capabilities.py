"""RF capability matrix mapped onto the Core capability model (rf_capabilities.py)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from custom_components.openwrt_router.core_models import (
    CORE_OWNED_MODULE_CAPABILITIES,
    MODULE_CAPABILITY_NAMESPACES,
    Capability,
    CapabilityReason,
    CapabilityStatus,
    default_router_id,
)
from custom_components.openwrt_router.core_models import (
    CapabilityState as CoreState,
)
from custom_components.openwrt_router.rf_capabilities import (
    CAPABILITY_PREFIX,
    METRIC_CAPABILITY_PREFIX,
    RF_CAPABILITY_SOURCE,
    capability_detector,
    capability_name,
    from_core_capabilities,
    scan_capability,
    to_core_capabilities,
)
from custom_components.openwrt_router.rf_models import (
    ALL_METRICS,
    METRIC_NOISE,
    METRIC_SCAN,
    METRIC_UTILIZATION,
    CapabilityState,
    RadioCapabilities,
)

C = CapabilityState
R1 = default_router_id("e1")
R2 = default_router_id("e2")
T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def _caps(radio, states, excluded=(), router=R1):
    return RadioCapabilities(router, radio, states, frozenset(excluded))


def _one(states, metric):
    return to_core_capabilities([_caps("radio0", states)], router_id=R1, now=T0)[
        capability_name(metric)
    ]


class TestNaming:
    def test_prefix_is_the_one_the_core_assigns_to_wifi_rf(self):
        assert MODULE_CAPABILITY_NAMESPACES["wifi_rf"] == CAPABILITY_PREFIX == "rf."
        assert METRIC_CAPABILITY_PREFIX == "rf.metric."

    def test_every_metric_has_a_name_below_the_prefix(self):
        names = {capability_name(m) for m in ALL_METRICS}
        assert len(names) == len(ALL_METRICS)
        assert all(n.startswith(METRIC_CAPABILITY_PREFIX) for n in names)

    def test_no_name_collides_with_core_owned_rf_names(self):
        # rf.scan / rf.survey / rf.txpowerlist belong to the core (ACL);
        # a detector reporting them is refused.
        names = {capability_name(m) for m in ALL_METRICS}
        assert not names & {str(c) for c in CORE_OWNED_MODULE_CAPABILITIES}
        assert capability_name(METRIC_SCAN) != Capability.RF_SCAN

    def test_unknown_metric_is_refused(self):
        with pytest.raises(ValueError):
            capability_name("ssid")


class TestStateMapping:
    @pytest.mark.parametrize(
        ("rf_state", "core_state", "reason"),
        [
            (C.MEASURED, CoreState.AVAILABLE, CapabilityReason.OK),
            (C.UNSUPPORTED, CoreState.UNAVAILABLE, CapabilityReason.NOT_DETECTED),
            (C.NO_DATA, CoreState.UNKNOWN, CapabilityReason.NO_DATA_YET),
            (C.STALE, CoreState.UNKNOWN, CapabilityReason.NO_DATA_YET),
            (C.UNREACHABLE, CoreState.UNKNOWN, CapabilityReason.NOT_CHECKED),
        ],
    )
    def test_single_radio(self, rf_state, core_state, reason):
        status = _one({METRIC_NOISE: rf_state}, METRIC_NOISE)
        assert isinstance(status, CapabilityStatus)
        assert status.state is core_state
        assert status.reason == reason
        assert status.capability == capability_name(METRIC_NOISE)
        assert status.source == RF_CAPABILITY_SOURCE
        assert status.detected_at == T0

    def test_not_assessed_is_unknown_not_checked(self):
        status = _one({}, METRIC_NOISE)
        assert status.state is CoreState.UNKNOWN
        assert status.reason == CapabilityReason.NOT_CHECKED

    def test_scan_not_assessed_stays_unsupported(self):
        # Until a scan is proven on a radio it is "nicht unterstützt".
        status = _one({}, METRIC_SCAN)
        assert status.state is CoreState.UNAVAILABLE
        assert status.reason == CapabilityReason.NOT_DETECTED

    def test_stale_and_no_data_never_turn_a_known_state_unknown_hard(self):
        # Mapped to UNKNOWN: the core's merge keeps the last known state,
        # so a poll gap is not reported as a capability change.
        for rf_state in (C.NO_DATA, C.STALE, C.UNREACHABLE):
            assert _one({METRIC_NOISE: rf_state}, METRIC_NOISE).state is (
                CoreState.UNKNOWN
            )


class TestAggregation:
    def test_any_measured_radio_makes_the_router_available(self):
        caps = [
            _caps("radio0", {METRIC_UTILIZATION: C.UNSUPPORTED}),
            _caps("radio1", {METRIC_UTILIZATION: C.MEASURED}),
        ]
        status = to_core_capabilities(caps, router_id=R1, now=T0)[
            capability_name(METRIC_UTILIZATION)
        ]
        assert status.state is CoreState.AVAILABLE
        assert dict(status.detail["radios"]) == {
            "radio0": {"state": "unsupported", "excluded": False},
            "radio1": {"state": "measured", "excluded": False},
        }

    def test_all_unsupported_is_unavailable(self):
        caps = [
            _caps("radio0", {METRIC_UTILIZATION: C.UNSUPPORTED}),
            _caps("radio1", {METRIC_UTILIZATION: C.UNSUPPORTED}),
        ]
        status = to_core_capabilities(caps, router_id=R1, now=T0)[
            capability_name(METRIC_UTILIZATION)
        ]
        assert status.state is CoreState.UNAVAILABLE

    def test_mixed_unsupported_and_no_data_is_unknown(self):
        caps = [
            _caps("radio0", {METRIC_UTILIZATION: C.UNSUPPORTED}),
            _caps("radio1", {METRIC_UTILIZATION: C.NO_DATA}),
        ]
        status = to_core_capabilities(caps, router_id=R1, now=T0)[
            capability_name(METRIC_UTILIZATION)
        ]
        assert status.state is CoreState.UNKNOWN

    def test_excluded_radios_do_not_count(self):
        caps = [
            _caps("radio0", {}, excluded={METRIC_UTILIZATION}),
            _caps("radio1", {METRIC_UTILIZATION: C.UNSUPPORTED}),
        ]
        status = to_core_capabilities(caps, router_id=R1, now=T0)[
            capability_name(METRIC_UTILIZATION)
        ]
        assert status.state is CoreState.UNAVAILABLE

    def test_all_excluded_is_unavailable_disabled(self):
        caps = [_caps("radio0", {}, excluded={METRIC_UTILIZATION})]
        status = to_core_capabilities(caps, router_id=R1, now=T0)[
            capability_name(METRIC_UTILIZATION)
        ]
        assert status.state is CoreState.UNAVAILABLE
        assert status.reason == CapabilityReason.DISABLED

    def test_one_status_per_metric(self):
        result = to_core_capabilities(
            [_caps("radio0", {METRIC_NOISE: C.MEASURED})], router_id=R1, now=T0
        )
        assert set(result) == {capability_name(m) for m in ALL_METRICS}
        assert all(name == s.capability for name, s in result.items())


class TestLossless:
    def test_round_trip_restores_every_radio_exactly(self):
        caps = [
            _caps(
                "radio0",
                {m: s for m, s in zip(ALL_METRICS, list(C) * 4, strict=False)},
                excluded={METRIC_SCAN},
            ),
            _caps("radio1", {METRIC_NOISE: C.STALE, METRIC_SCAN: C.MEASURED}),
            _caps("radio2", {}),
        ]
        statuses = to_core_capabilities(caps, router_id=R1, now=T0)
        back = from_core_capabilities(statuses, router_id=R1)
        assert sorted(back, key=lambda c: c.radio_id) == caps

    def test_metric_both_measured_and_excluded_survives(self):
        caps = [_caps("radio0", {METRIC_NOISE: C.MEASURED}, excluded={METRIC_NOISE})]
        statuses = to_core_capabilities(caps, router_id=R1, now=T0)
        assert from_core_capabilities(statuses, router_id=R1) == caps

    def test_round_trip_through_to_dict(self):
        caps = [_caps("radio0", {METRIC_NOISE: C.UNREACHABLE})]
        statuses = to_core_capabilities(caps, router_id=R1, now=T0)
        dumped = {name: s.to_dict() for name, s in statuses.items()}
        rebuilt = {
            name: CapabilityStatus(
                capability=d["capability"],
                state=d["state"],
                reason=d["reason"],
                source=d["source"],
                detected_at=T0,
                detail=d["detail"],
            )
            for name, d in dumped.items()
        }
        assert from_core_capabilities(rebuilt, router_id=R1) == caps

    def test_foreign_entries_are_ignored(self):
        statuses = to_core_capabilities(
            [_caps("radio0", {METRIC_NOISE: C.MEASURED})], router_id=R1, now=T0
        )
        other = CapabilityStatus(
            capability="rf.txpowerlist",
            state=CoreState.AVAILABLE,
            reason=CapabilityReason.OK,
            source="acl",
            detected_at=T0,
        )
        mixed = {**statuses, "rf.txpowerlist": other}
        assert from_core_capabilities(mixed, router_id=R1) == (
            from_core_capabilities(statuses, router_id=R1)
        )


class TestValidation:
    def test_router_id_must_be_a_core_id(self):
        with pytest.raises(ValueError):
            to_core_capabilities([], router_id="e1", now=T0)

    def test_all_radios_must_belong_to_the_router(self):
        with pytest.raises(ValueError):
            to_core_capabilities([_caps("radio0", {}, router=R2)], router_id=R1, now=T0)

    def test_duplicate_radio_is_refused(self):
        with pytest.raises(ValueError):
            to_core_capabilities(
                [_caps("radio0", {}), _caps("radio0", {})], router_id=R1, now=T0
            )

    def test_naive_time_is_refused(self):
        with pytest.raises(ValueError):
            to_core_capabilities(
                [_caps("radio0", {})], router_id=R1, now=datetime(2026, 11, 17)
            )


def _acl_status(state):
    return CapabilityStatus(
        capability=Capability.RF_SCAN,
        state=state,
        reason=CapabilityReason.OK,
        source="acl",
        detected_at=T0,
    )


class TestScanCapability:
    def test_default_is_unsupported(self):
        assert scan_capability(None, None) is C.UNSUPPORTED
        assert scan_capability(_acl_status(CoreState.AVAILABLE), None) is (
            C.UNSUPPORTED
        )

    def test_proven_but_acl_missing_is_unreachable(self):
        assert scan_capability(None, C.MEASURED) is C.UNREACHABLE
        assert scan_capability(_acl_status(CoreState.UNKNOWN), C.MEASURED) is (
            C.UNREACHABLE
        )
        assert scan_capability(_acl_status(CoreState.UNAVAILABLE), C.MEASURED) is (
            C.UNREACHABLE
        )

    def test_proven_and_acl_available_keeps_the_proven_state(self):
        acl = _acl_status(CoreState.AVAILABLE)
        for proven in (C.MEASURED, C.NO_DATA, C.STALE, C.UNSUPPORTED):
            assert scan_capability(acl, proven) is proven

    def test_acl_status_must_be_the_core_rf_scan(self):
        wrong = CapabilityStatus(
            capability="rf.survey",
            state=CoreState.AVAILABLE,
            reason=CapabilityReason.OK,
            source="acl",
            detected_at=T0,
        )
        with pytest.raises(ValueError):
            scan_capability(wrong, C.MEASURED)


class TestDetector:
    def test_detector_reads_data_only_and_reports_below_the_prefix(self):
        seen = []

        def extract(data):
            seen.append(data)
            return data["caps"]

        detect = capability_detector(extract, clock=lambda: T0)
        record = SimpleNamespace(router_id=R1)
        caps = [_caps("radio0", {METRIC_NOISE: C.MEASURED})]
        result = detect(record, {"caps": caps})
        assert seen == [{"caps": caps}]
        assert all(name.startswith(CAPABILITY_PREFIX) for name in result)
        assert not set(result) & {str(c) for c in CORE_OWNED_MODULE_CAPABILITIES}
        assert result[capability_name(METRIC_NOISE)].state is CoreState.AVAILABLE

    def test_detector_without_rf_data_reports_nothing(self):
        detect = capability_detector(lambda data: None, clock=lambda: T0)
        assert detect(SimpleNamespace(router_id=R1), {}) == {}

    def test_detector_is_synchronous(self):
        import inspect

        detect = capability_detector(lambda data: [], clock=lambda: T0)
        assert not inspect.iscoroutinefunction(detect)
