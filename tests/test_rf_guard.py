"""How a scan request passes the Core guard (rf_guard.py); never scans."""

from __future__ import annotations

from datetime import timedelta

import pytest
from core_testkit import (
    ADMIN_ID,
    USER_ID,
    FakeDisks,
    add_users,
    make_hass,
    user_actor,
)

from custom_components.openwrt_router.core_audit import AuditLog
from custom_components.openwrt_router.core_errors import (
    AuthorizationError,
    CapabilityUnavailableError,
    ConfigApiError,
    RateLimitedError,
    SafetyRefusedError,
)
from custom_components.openwrt_router.core_guard import ActionGuard
from custom_components.openwrt_router.core_models import (
    ActionClass,
    Actor,
    DecisionState,
    async_verify_actor,
    binding_checksum,
    default_router_id,
    utcnow,
)
from custom_components.openwrt_router.rf_capabilities import capability_name
from custom_components.openwrt_router.rf_guard import (
    RF_ACTIONS,
    SCAN_ACTION,
    SENSITIVE_READ_ACTIONS,
    register_rf_actions,
    scan_guard_request,
    scan_policy_denial,
    scan_refusal_error,
    scan_request_from_actor,
)
from custom_components.openwrt_router.rf_models import METRIC_SCAN, CapabilityState
from custom_components.openwrt_router.rf_scan_policy import (
    ScanDecision,
    ScanPolicy,
    ScanReason,
    ScanState,
    decide_scan,
)

R1 = default_router_id("e1")
EMPTY = ScanState(last_scan_at={}, last_router_scan_at=None)


@pytest.fixture
def disks():
    with FakeDisks().patch() as fake:
        yield fake


async def _verified(hass, actor):
    return await async_verify_actor(hass, actor)


def _hass():
    hass = make_hass()
    add_users(hass)
    return hass


class TestActionRegistration:
    def test_scan_is_a_critical_admin_only_module_action(self):
        assert SCAN_ACTION.name == "wifi_rf.scan"
        assert SCAN_ACTION.module == "wifi_rf"
        assert SCAN_ACTION.action_class is ActionClass.CRITICAL
        assert SCAN_ACTION.admin_user_only is True
        assert SCAN_ACTION.critical is True
        assert RF_ACTIONS == (SCAN_ACTION, *SENSITIVE_READ_ACTIONS)

    async def test_the_core_guard_accepts_the_registration(self, disks):
        hass = _hass()
        audit = AuditLog(hass)
        await audit.async_load()
        guard = ActionGuard(hass, audit)
        register_rf_actions(guard)
        register_rf_actions(guard)  # same definition again is a no-op
        assert guard.action_class(SCAN_ACTION.name) is ActionClass.CRITICAL
        for action in SENSITIVE_READ_ACTIONS:
            assert guard.action_class(action.name) is ActionClass.READ

    def test_registration_is_plain_data_passed_to_register_action(self):
        calls = []

        class Recorder:
            def register_action(
                self,
                name,
                action_class,
                *,
                module,
                admin_user_only,
                sensitive_read,
                rate_limit,
            ):
                calls.append(
                    (
                        name,
                        action_class,
                        module,
                        admin_user_only,
                        sensitive_read,
                        rate_limit,
                    )
                )

        register_rf_actions(Recorder())
        read = ActionClass.READ
        assert calls == [
            ("wifi_rf.scan", ActionClass.CRITICAL, "wifi_rf", True, False, None),
            ("wifi_rf.neighbor_list", read, "wifi_rf", False, True, None),
            ("wifi_rf.client_rf", read, "wifi_rf", False, True, None),
            ("wifi_rf.client_roam_history", read, "wifi_rf", False, True, None),
        ]


class TestPolicy:
    async def test_only_a_verified_admin_user_may_request(self):
        hass = _hass()
        admin = await _verified(hass, user_actor(ADMIN_ID))
        plain = await _verified(hass, user_actor(USER_ID, claims_admin=True))
        module = await _verified(hass, Actor.for_module("wifi_rf"))
        system = await _verified(hass, Actor.system())
        assert scan_policy_denial(admin) is None
        assert scan_policy_denial(plain) == "not_admin"
        assert scan_policy_denial(module) == "not_admin"
        assert scan_policy_denial(system) == "not_admin"
        assert scan_policy_denial(user_actor(ADMIN_ID)) == "unverified_actor"

    async def test_expired_verification_is_refused(self):
        hass = _hass()
        admin = await _verified(hass, user_actor(ADMIN_ID))
        later = utcnow() + timedelta(minutes=5)
        assert scan_policy_denial(admin, now=later) == "actor_verification_expired"


class TestScanRequest:
    async def test_is_admin_comes_from_the_verified_actor(self):
        hass = _hass()
        admin = await _verified(hass, user_actor(ADMIN_ID))
        plain = await _verified(hass, user_actor(USER_ID, claims_admin=True))
        assert scan_request_from_actor(admin, "radio0", requested_at=1.0).is_admin
        request = scan_request_from_actor(plain, "radio0", requested_at=1.0)
        assert request.is_admin is False
        assert request.manual is True
        decision = decide_scan(
            request,
            capability=CapabilityState.MEASURED,
            uplink=False,
            cac_active=False,
            state=EMPTY,
            policy=ScanPolicy(),
        )
        assert decision.reason is ScanReason.NOT_ADMIN

    def test_unverified_actor_is_refused(self):
        with pytest.raises(TypeError):
            scan_request_from_actor(
                user_actor(ADMIN_ID, claims_admin=True), "radio0", requested_at=1.0
            )

    def test_guard_request_binds_router_and_radio(self):
        request = scan_guard_request(R1, "radio0")
        assert request == {
            "action": "wifi_rf.scan",
            "router_id": R1,
            "subject_id": "radio0",
            "checksum": binding_checksum("wifi_rf.scan", R1, "radio0"),
        }
        assert scan_guard_request(R1, "radio1")["checksum"] != request["checksum"]

    def test_guard_request_validates_ids(self):
        with pytest.raises(ValueError):
            scan_guard_request("e1", "radio0")
        with pytest.raises(ValueError):
            scan_guard_request(R1, "")


class TestFullFlowWithTheCoreGuard:
    """request -> pending -> admin approval -> redeem -> consume. No scan."""

    async def test_admin_scan_needs_an_approval_and_is_bound(self, disks):
        hass = _hass()
        audit = AuditLog(hass)
        await audit.async_load()
        guard = ActionGuard(hass, audit)
        register_rf_actions(guard)
        admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
        binding = scan_guard_request(R1, "radio0")

        first = guard.authorize(actor=admin, **binding)
        assert first.state is DecisionState.PENDING
        approval_id = first.approval_request.approval_id
        guard.approve(approval_id, actor=admin)

        granted = guard.authorize(actor=admin, approval_id=approval_id, **binding)
        assert granted.state is DecisionState.APPROVED
        # The wiring would start the scan right after this consume.
        guard.consume(
            granted.authorization,
            action=binding["action"],
            router_id=R1,
            checksum=binding["checksum"],
        )
        with pytest.raises(AuthorizationError):  # used once
            guard.consume(
                granted.authorization,
                action=binding["action"],
                router_id=R1,
                checksum=binding["checksum"],
            )

    async def test_plain_user_is_denied_before_any_approval(self, disks):
        hass = _hass()
        audit = AuditLog(hass)
        await audit.async_load()
        guard = ActionGuard(hass, audit)
        register_rf_actions(guard)
        plain = await guard.async_verify_actor(user_actor(USER_ID))
        decision = guard.authorize(actor=plain, **scan_guard_request(R1, "radio0"))
        assert decision.state is DecisionState.DENIED
        assert decision.reason == "not_admin"
        assert guard.pending_approvals() == ()

    async def test_approval_for_one_radio_does_not_scan_another(self, disks):
        hass = _hass()
        audit = AuditLog(hass)
        await audit.async_load()
        guard = ActionGuard(hass, audit)
        register_rf_actions(guard)
        admin = await guard.async_verify_actor(user_actor(ADMIN_ID))
        first = guard.authorize(actor=admin, **scan_guard_request(R1, "radio0"))
        approval_id = first.approval_request.approval_id
        guard.approve(approval_id, actor=admin)
        other = guard.authorize(
            actor=admin, approval_id=approval_id, **scan_guard_request(R1, "radio1")
        )
        assert other.state is DecisionState.DENIED
        assert other.reason == "checksum_mismatch"


class TestRefusalErrors:
    @pytest.mark.parametrize(
        ("reason", "error", "retryable"),
        [
            (ScanReason.SCAN_UNSUPPORTED, CapabilityUnavailableError, False),
            (ScanReason.SCAN_UNAVAILABLE, CapabilityUnavailableError, False),
            (ScanReason.NOT_ADMIN, AuthorizationError, False),
            (ScanReason.AUTO_DISABLED, AuthorizationError, False),
            (ScanReason.UPLINK_RADIO, SafetyRefusedError, False),
            (ScanReason.UPLINK_UNKNOWN, SafetyRefusedError, False),
            (ScanReason.CAC_UNKNOWN, SafetyRefusedError, False),
            (ScanReason.CAC_ACTIVE, SafetyRefusedError, False),
            (ScanReason.RATE_LIMIT_RADIO, RateLimitedError, True),
            (ScanReason.RATE_LIMIT_ROUTER, RateLimitedError, True),
        ],
    )
    def test_every_refusal_maps_to_a_core_error(self, reason, error, retryable):
        decision = ScanDecision(False, reason, 12.0 if "rate" in reason else None)
        err = scan_refusal_error(decision, router_id=R1)
        assert type(err) is error
        assert isinstance(err, ConfigApiError)
        assert err.retryable is retryable
        assert err.router_id == R1
        assert err.details["reason"] == reason.value
        assert err.to_dict()["details"]["reason"] == reason.value

    def test_capability_errors_name_the_rf_capability(self):
        err = scan_refusal_error(
            ScanDecision(False, ScanReason.SCAN_UNSUPPORTED), router_id=R1
        )
        assert err.capability == capability_name(METRIC_SCAN)

    def test_rate_limit_carries_the_wait(self):
        err = scan_refusal_error(
            ScanDecision(False, ScanReason.RATE_LIMIT_ROUTER, 42.0), router_id=R1
        )
        assert err.retry_after == 42.0
        assert err.details["retry_after"] == 42.0
        assert err.to_dict()["retry_after"] == 42.0

    @pytest.mark.parametrize("wait", [float("nan"), float("inf"), -1.0])
    def test_an_unusable_wait_takes_the_full_interval(self, wait):
        err = scan_refusal_error(
            ScanDecision(False, ScanReason.RATE_LIMIT_ROUTER, wait), router_id=R1
        )
        assert err.retry_after == 300.0

    def test_safety_refusals_carry_the_core_reason(self):
        err = scan_refusal_error(
            ScanDecision(False, ScanReason.UPLINK_RADIO), router_id=R1
        )
        assert err.reason == "uplink_radio"
        assert err.to_dict()["details"]["action"] == "wifi_rf.scan"

    def test_every_reason_is_covered(self):
        for reason in ScanReason:
            if reason is ScanReason.ALLOWED:
                continue
            assert isinstance(
                scan_refusal_error(ScanDecision(False, reason), router_id=R1),
                ConfigApiError,
            )

    def test_allowed_is_no_error(self):
        with pytest.raises(ValueError):
            scan_refusal_error(ScanDecision(True, ScanReason.ALLOWED), router_id=R1)


def test_sensitive_reads_are_listed():
    names = {a.name for a in SENSITIVE_READ_ACTIONS}
    assert {"wifi_rf.neighbor_list", "wifi_rf.client_rf"} <= names
    for action in SENSITIVE_READ_ACTIONS:
        assert action.sensitive_read and action.module == "wifi_rf"
